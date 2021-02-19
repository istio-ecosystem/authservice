#include "oidc_filter.h"

#include <algorithm>
#include <boost/beast.hpp>
#include <sstream>

#include "absl/strings/str_join.h"
#include "google/rpc/code.pb.h"
#include "spdlog/spdlog.h"
#include "src/common/http/headers.h"
#include "src/common/http/http.h"
#include "src/common/utilities/time_service.h"

namespace beast = boost::beast;    // from <boost/beast.hpp>
namespace http = beast::http;      // from <boost/beast/http.hpp>
namespace net = boost::asio;       // from <boost/asio.hpp>
using tcp = boost::asio::ip::tcp;  // from <boost/asio/ip/tcp.hpp>

namespace authservice {
namespace filters {
namespace oidc {

namespace {
const char *filter_name_ = "oidc";
const char *mandatory_scope_ = "openid";
const char *https_scheme_ = "https";
const int64_t NO_TIMEOUT = -1;

const std::map<const char *, const char *> standard_headers = {
    {common::http::headers::CacheControl,
     common::http::headers::CacheControlDirectives::NoCache},
    {common::http::headers::Pragma,
     common::http::headers::PragmaDirectives::NoCache},
};
}  // namespace

OidcFilter::OidcFilter(
    common::http::ptr_t http_ptr, const config::oidc::OIDCConfig &idp_config,
    TokenResponseParserPtr parser,
    common::session::SessionStringGeneratorPtr session_string_generator,
    SessionStorePtr session_store)
    : http_ptr_(http_ptr),
      idp_config_(idp_config),
      parser_(parser),
      session_string_generator_(session_string_generator),
      session_store_(session_store) {
  spdlog::trace("{}", __func__);
}

google::rpc::Code OidcFilter::Process(
    const ::envoy::service::auth::v3::CheckRequest *request,
    ::envoy::service::auth::v3::CheckResponse *response,
    boost::asio::io_context &ioc, boost::asio::yield_context yield) {
  spdlog::trace("{}", __func__);
  spdlog::debug(
      "Call from {}@{} to {}@{}", request->attributes().source().principal(),
      request->attributes().source().address().socket_address().address(),
      request->attributes().destination().principal(),
      request->attributes().destination().address().socket_address().address());

  if (!request->attributes().request().has_http()) {
    spdlog::info("{}: missing http in request", __func__);
    SetStandardResponseHeaders(response);
    return google::rpc::Code::INVALID_ARGUMENT;
  }

  // Verify the request was via a secure scheme.
  /* TODO: Reinstate
  if (request->attributes().request().http().scheme() != https_scheme_) {
    spdlog::info("invalid request scheme, wanted {}, got {}", https_scheme_,
                 request->attributes().request().http().scheme());
    return google::rpc::Code::INVALID_ARGUMENT;
  }
  */

  auto httpRequest = request->attributes().request().http();
  auto headers = httpRequest.headers();
  auto session_id_optional = GetSessionIdFromCookie(headers);

  // If the request is for the configured logout path,
  // then logout and redirect to the configured logout redirect uri.
  if (MatchesLogoutRequest(request)) {
    spdlog::info("{}: Handling logout", __func__);
    if (session_id_optional.has_value()) {
      spdlog::info("{}: Removing session info from session store during logout",
                   __func__);
      try {
        session_store_->RemoveSession(session_id_optional.value());
      } catch (SessionError &err) {
        spdlog::error("{}: Session error in RemoveSession: {}", __func__,
                      err.what());
        return SessionErrorResponse(response, err);
      }
    }
    SetLogoutHeaders(response);
    spdlog::info("{}: Logout complete. Sending user to re-authenticate.",
                 __func__);
    return google::rpc::Code::UNAUTHENTICATED;
  }

  // If the id_token header already exists,
  // then let request continue.
  // (It is up to the downstream system to validate the header is valid.)
  if (headers.contains(idp_config_.id_token().header())) {
    spdlog::info(
        "{}: ID Token header already present. Allowing request to proceed "
        "without adding any additional headers.",
        __func__);
    return google::rpc::Code::OK;
  }

  // If the request does not have a session_id cookie,
  // then generate a session id, put it in a header, and redirect for login.
  if (!session_id_optional.has_value()) {
    spdlog::info(
        "{}: No session cookie detected. Generating new session and sending "
        "user to re-authenticate.",
        __func__);
    return RedirectToIdp(response, httpRequest);
  }

  auto session_id = session_id_optional.value();

  // If the request path is the callback for receiving the authorization code,
  // has a session id then exchange it for tokens and redirects end-user back to
  // their originally requested URL.
  if (MatchesCallbackRequest(request)) {
    return RetrieveToken(request, response, session_id, ioc, yield);
  }

  spdlog::trace("{}: attempting session retrieval", __func__);
  std::shared_ptr<TokenResponse> token_response_ptr;
  try {
    token_response_ptr = session_store_->GetTokenResponse(session_id);
  } catch (SessionError &err) {
    spdlog::error("{}: Session error in GetTokenResponse: {}", __func__,
                  err.what());
    return SessionErrorResponse(response, err);
  }

  spdlog::trace("{}: checking retrieved token response for expected tokens",
                __func__);
  // If the user has a session_id cookie but there are no required tokens in the
  // session store associated with it, then redirect for login.
  if (!RequiredTokensPresent(token_response_ptr)) {
    spdlog::info(
        "{}: Required tokens are not present. Sending user to re-authenticate.",
        __func__);
    return RedirectToIdp(response, httpRequest, session_id);
  }

  auto token_response = *token_response_ptr;

  // If both ID & Access token are still unexpired,
  // then allow the request to proceed (no need to intervene).
  spdlog::trace("{}: checking token expiration", __func__);
  if (!RequiredTokensExpired(token_response)) {
    AddTokensToRequestHeaders(response, token_response);
    spdlog::info("{}: Tokens not expired. Allowing request to proceed.",
                 __func__);
    return google::rpc::Code::OK;
  }

  // If there is no refresh token,
  // then direct the request to the identity provider for authentication
  auto refresh_token_optional = token_response.RefreshToken();
  if (!refresh_token_optional.has_value()) {
    spdlog::info(
        "{}: A token was expired, but session did not contain a refresh token. "
        "Sending user to re-authenticate.",
        __func__);
    return RedirectToIdp(response, httpRequest, session_id);
  }

  // If the user has an unexpired refresh token then use it to request a fresh
  // token_response. If successful, allow the request to proceed. If
  // unsuccessful, redirect for login.
  spdlog::trace("{}: attempting to refresh token", __func__);
  auto refreshed_token_response =
      RefreshToken(token_response, refresh_token_optional.value(), ioc, yield);
  if (refreshed_token_response) {
    try {
      spdlog::trace("{}: storing refreshed token", __func__);
      session_store_->SetTokenResponse(session_id, refreshed_token_response);
    } catch (SessionError &err) {
      spdlog::error("{}: Session error in SetTokenResponse: {}", __func__,
                    err.what());
      return SessionErrorResponse(response, err);
    }
    spdlog::info(
        "{}: Updated session store with newly refreshed access token. Allowing "
        "request to proceed.",
        __func__);
    AddTokensToRequestHeaders(response, *refreshed_token_response);
    return google::rpc::Code::OK;
  } else {
    spdlog::info(
        "{}: Attempt to refresh access token did not yield refreshed token. "
        "Sending user to re-authenticate.",
        __func__);
    return RedirectToIdp(response, httpRequest, session_id);
  }
}

google::rpc::Code OidcFilter::SessionErrorResponse(
    envoy::service::auth::v3::CheckResponse *response,
    const SessionError &err) {
  response->mutable_denied_response()->mutable_status()->set_code(
      envoy::type::v3::Unauthorized);
  response->mutable_denied_response()->mutable_body()->append(
      "There was an error accessing your session data. Try again later.");
  return google::rpc::UNAUTHENTICATED;
}

google::rpc::Code OidcFilter::RedirectToIdp(
    envoy::service::auth::v3::CheckResponse *response,
    const ::envoy::service::auth::v3::AttributeContext_HttpRequest &httpRequest,
    absl::optional<std::string> old_session_id) {
  if (old_session_id.has_value()) {
    try {
      // remove old session and regenerate session_id to prevent session
      // fixation attacks
      session_store_->RemoveSession(old_session_id.value());
    } catch (SessionError &err) {
      spdlog::error("{}: Session error in RemoveSession: {}", __func__,
                    err.what());
      return SessionErrorResponse(response, err);
    }
  }

  auto session_id = session_string_generator_->GenerateSessionId();
  auto state = session_string_generator_->GenerateState();
  auto nonce = session_string_generator_->GenerateNonce();

  std::set<absl::string_view> scopes = {mandatory_scope_};
  for (const auto &scope : idp_config_.scopes()) {
    scopes.insert(scope);
  }

  auto encoded_scopes = absl::StrJoin(scopes, " ");
  std::multimap<absl::string_view, absl::string_view> params = {
      {"response_type", "code"},
      {"scope", encoded_scopes},
      {"client_id", idp_config_.client_id()},
      {"nonce", nonce},
      {"state", state},
      {"redirect_uri", idp_config_.callback_uri()}};
  auto query = common::http::Http::EncodeQueryData(params);

  SetStandardResponseHeaders(response);

  auto redirect_location =
      absl::StrJoin({idp_config_.authorization_uri(), query}, "?");
  SetRedirectHeaders(redirect_location, response);

  try {
    session_store_->SetAuthorizationState(
        session_id.data(), std::make_shared<AuthorizationState>(
                               state, nonce, GetRequestUrl(httpRequest)));
  } catch (SessionError &err) {
    spdlog::error("{}: Session error in SetAuthorizationState: {}", __func__,
                  err.what());
    return SessionErrorResponse(response, err);
  }

  SetSessionIdCookie(response, session_id.data());

  return google::rpc::UNAUTHENTICATED;
}

std::string OidcFilter::GetRequestUrl(
    const ::envoy::service::auth::v3::AttributeContext_HttpRequest
        &http_request) {
  auto request_without_query = std::string(https_scheme_) + "://" +
                               http_request.host() + http_request.path();

  if (http_request.query().empty()) {
    return request_without_query;
  }

  return absl::StrJoin({request_without_query, http_request.query()}, "?");
}

void OidcFilter::SetHeader(
    ::google::protobuf::RepeatedPtrField<
        ::envoy::config::core::v3::HeaderValueOption> *headers,
    absl::string_view name, absl::string_view value) {
  auto header_value_option = headers->Add();
  auto header = header_value_option->mutable_header();
  header->set_key(name.data());
  header->set_value(value.data());
}

void OidcFilter::SetStandardResponseHeaders(
    ::envoy::service::auth::v3::CheckResponse *response) {
  for (auto to_add : standard_headers) {
    SetHeader(response->mutable_denied_response()->mutable_headers(),
              to_add.first, to_add.second);
  }
}

void OidcFilter::SetRedirectHeaders(
    absl::string_view redirect_url,
    ::envoy::service::auth::v3::CheckResponse *response) {
  response->mutable_denied_response()->mutable_status()->set_code(
      envoy::type::v3::Found);
  SetHeader(response->mutable_denied_response()->mutable_headers(),
            common::http::headers::Location, redirect_url.data());
}

std::string OidcFilter::EncodeCookieTimeoutDirective(int64_t timeout) {
  return std::string(common::http::headers::SetCookieDirectives::MaxAge) + "=" +
         std::to_string(timeout);
}

std::string OidcFilter::GetCookieName(const std::string &cookie) const {
  if (idp_config_.cookie_name_prefix() == "") {
    return "__Host-authservice-" + cookie + "-cookie";
  }
  return "__Host-" + idp_config_.cookie_name_prefix() + "-authservice-" +
         cookie + "-cookie";
}

std::string OidcFilter::GetSessionIdCookieName() const {
  return GetCookieName("session-id");
}

std::string OidcFilter::EncodeHeaderValue(const std::string &preamble,
                                          const std::string &value) {
  if (preamble != "") {
    return preamble + " " + value;
  }
  return value;
}

void OidcFilter::SetCookie(
    ::google::protobuf::RepeatedPtrField<
        ::envoy::config::core::v3::HeaderValueOption> *responseHeaders,
    const std::string &cookie_name, absl::string_view value, int64_t timeout) {
  std::set<std::string> cookie_directives = GetCookieDirectives(timeout);
  std::set<absl::string_view> cookie_directives_string_view(
      cookie_directives.begin(), cookie_directives.end());
  auto cookie_header = common::http::Http::EncodeSetCookie(
      cookie_name, value, cookie_directives_string_view);
  SetHeader(responseHeaders, common::http::headers::SetCookie, cookie_header);
}

void OidcFilter::DeleteCookie(
    ::google::protobuf::RepeatedPtrField<
        ::envoy::config::core::v3::HeaderValueOption> *responseHeaders,
    const std::string &cookieName) {
  SetCookie(responseHeaders, cookieName, "deleted", 0);
}

std::set<std::string> OidcFilter::GetCookieDirectives(int64_t timeout) {
  std::set<std::string> token_set_cookie_header_directives = {
      common::http::headers::SetCookieDirectives::HttpOnly,
      common::http::headers::SetCookieDirectives::SameSiteLax,
      common::http::headers::SetCookieDirectives::Secure, "Path=/"};

  if (timeout != NO_TIMEOUT) {
    std::string timeoutDirective = EncodeCookieTimeoutDirective(timeout);
    token_set_cookie_header_directives.insert(timeoutDirective);
  }
  return token_set_cookie_header_directives;
}

absl::optional<std::string> OidcFilter::CookieFromHeaders(
    const ::google::protobuf::Map<::std::string, ::std::string> &headers,
    const std::string &cookie) {
  const auto &cookie_header_value = headers.find(common::http::headers::Cookie);
  if (cookie_header_value == headers.cend()) {
    return absl::nullopt;
  }
  auto cookies = common::http::Http::DecodeCookies(cookie_header_value->second);
  if (!cookies.has_value()) {
    return absl::nullopt;
  }
  const auto &iter = cookies->find(cookie);
  if (iter != cookies->cend()) {
    return iter->second;
  }
  return absl::nullopt;
}

void OidcFilter::SetLogoutHeaders(
    envoy::service::auth::v3::CheckResponse *response) {
  SetRedirectHeaders(idp_config_.logout().redirect_uri(), response);
  SetStandardResponseHeaders(response);
  auto responseHeaders = response->mutable_denied_response()->mutable_headers();
  DeleteCookie(responseHeaders, GetSessionIdCookieName());
}

void OidcFilter::AddTokensToRequestHeaders(
    envoy::service::auth::v3::CheckResponse *response,
    TokenResponse &tokenResponse) {
  auto id_token = tokenResponse.IDToken().jwt_;
  SetIdTokenHeader(response, id_token);
  if (idp_config_.has_access_token() &&
      tokenResponse.AccessToken().has_value()) {
    SetAccessTokenHeader(response, tokenResponse.AccessToken().value());
  }
}

bool OidcFilter::RequiredTokensPresent(
    std::shared_ptr<TokenResponse> token_response) {
  return token_response && (!idp_config_.has_access_token() ||
                            token_response->AccessToken().has_value());
}

bool OidcFilter::RequiredTokensExpired(TokenResponse &token_response) {
  common::utilities::TimeService timeService;
  int64_t now_seconds = timeService.GetCurrentTimeInSecondsSinceEpoch();

  if (token_response.GetIDTokenExpiry() < now_seconds) {
    return true;
  }

  // Don't require expires_in. Rely on presence of field to determine if check
  // should be made.
  //  The oauth spec does not require a expires_in
  //  https://tools.ietf.org/html/rfc6749#section-5.1
  const absl::optional<int64_t> &accessTokenExpiry =
      token_response.GetAccessTokenExpiry();
  return idp_config_.has_access_token() && accessTokenExpiry.has_value() &&
         accessTokenExpiry.value() < now_seconds;
}

bool OidcFilter::MatchesLogoutRequest(
    const ::envoy::service::auth::v3::CheckRequest *request) {
  return idp_config_.has_logout() &&
         RequestPath(request) == idp_config_.logout().path();
}

std::string OidcFilter::RequestPath(
    const envoy::service::auth::v3::CheckRequest *request) {
  return common::http::PathQueryFragment(
             request->attributes().request().http().path())
      .Path();
}

std::string OidcFilter::RequestQueryString(
    const envoy::service::auth::v3::CheckRequest *request) {
  return common::http::PathQueryFragment(
             request->attributes().request().http().path())
      .Query();
}

bool OidcFilter::MatchesCallbackRequest(
    const ::envoy::service::auth::v3::CheckRequest *request) {
  auto path = request->attributes().request().http().path();
  auto request_host = request->attributes().request().http().host();
  auto scheme = request->attributes().request().http().scheme();
  spdlog::trace("{}: checking handler for {}://{}{}", __func__, scheme,
                request_host, path);

  auto request_path_parts = common::http::PathQueryFragment(path);
  auto configured_uri = idp_config_.callback_uri();
  auto parsed_uri = common::http::Uri(configured_uri);
  auto configured_port = parsed_uri.GetPort();
  auto configured_hostname = parsed_uri.GetHost();
  auto configured_scheme = parsed_uri.GetScheme();
  auto configured_path = parsed_uri.GetPathQueryFragment();

  std::stringstream buf;
  buf << configured_hostname << ':' << std::dec << configured_port;

  std::string configured_callback_host_with_port = buf.str();

  bool path_matches = request_path_parts.Path() == configured_path;

  bool host_matches = request_host == configured_callback_host_with_port ||
                      (configured_scheme == "https" && configured_port == 443 &&
                       request_host == configured_hostname);

  auto matches_callback = path_matches && host_matches;

  spdlog::trace("{}: matches_callback: {} ", __func__, matches_callback);

  return matches_callback;
}

absl::optional<std::string> OidcFilter::GetSessionIdFromCookie(
    const ::google::protobuf::Map<::std::string, ::std::string> &headers) {
  auto cookie_name = GetSessionIdCookieName();
  auto cookie = CookieFromHeaders(headers, cookie_name);
  if (cookie.has_value()) {
    return cookie.value();
  } else {
    spdlog::info("{}: {} session id cookie missing", __func__, cookie_name);
    return absl::nullopt;
  }
}

void OidcFilter::SetAccessTokenHeader(
    ::envoy::service::auth::v3::CheckResponse *response,
    const std::string &access_token) {
  auto value =
      EncodeHeaderValue(idp_config_.access_token().preamble(), access_token);
  SetHeader(response->mutable_ok_response()->mutable_headers(),
            idp_config_.access_token().header(), value);
}

void OidcFilter::SetIdTokenHeader(
    ::envoy::service::auth::v3::CheckResponse *response,
    const std::string &id_token) {
  auto value = EncodeHeaderValue(idp_config_.id_token().preamble(), id_token);
  SetHeader(response->mutable_ok_response()->mutable_headers(),
            idp_config_.id_token().header(), value);
}

void OidcFilter::SetSessionIdCookie(
    ::envoy::service::auth::v3::CheckResponse *response,
    std::string session_id) {
  SetCookie(response->mutable_denied_response()->mutable_headers(),
            GetSessionIdCookieName(), session_id, NO_TIMEOUT);
}

// https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokens
std::shared_ptr<TokenResponse> OidcFilter::RefreshToken(
    const TokenResponse &existing_token_response,
    const std::string &refresh_token, boost::asio::io_context &ioc,
    boost::asio::yield_context yield) {
  std::map<absl::string_view, absl::string_view> headers = {
      {common::http::headers::ContentType,
       common::http::headers::ContentTypeDirectives::FormUrlEncoded},
  };

  std::multimap<absl::string_view, absl::string_view> params = {
      {"client_id", idp_config_.client_id()},
      {"client_secret", idp_config_.client_secret()},
      {"grant_type", "refresh_token"},
      {"refresh_token", refresh_token},
      // according to this link, omitting the `scope` param should return new
      // tokens with the previously requested `scope`
      // https://www.oauth.com/oauth2-servers/access-tokens/refreshing-access-tokens/
  };

  spdlog::info("{}: POSTing to refresh access token", __func__);
  auto retrieved_token_response =
      http_ptr_->Post(idp_config_.token_uri(), headers,
                      common::http::Http::EncodeFormData(params),
                      idp_config_.trusted_certificate_authority(),
                      idp_config_.proxy_uri(), ioc, yield);

  if (retrieved_token_response == nullptr) {
    spdlog::warn(
        "{}: Received null pointer as response from identity provider.",
        __func__);
    return nullptr;
  }

  http::status status = retrieved_token_response->result();
  if (status != boost::beast::http::status::ok) {
    spdlog::warn(
        "{}: Received (non-OK) status {} from identity provider when "
        "refreshing the access token.",
        __func__, std::to_string(static_cast<unsigned>(status)));
    return nullptr;
  }

  return parser_->ParseRefreshTokenResponse(existing_token_response,
                                            retrieved_token_response->body());
}

// Performs an HTTP POST and prints the response
google::rpc::Code OidcFilter::RetrieveToken(
    const ::envoy::service::auth::v3::CheckRequest *request,
    ::envoy::service::auth::v3::CheckResponse *response,
    absl::string_view session_id, boost::asio::io_context &ioc,
    boost::asio::yield_context yield) {
  spdlog::trace("{}", __func__);

  SetStandardResponseHeaders(response);

  // Extract expected state and authorization code from request
  auto query = RequestQueryString(request);
  auto query_data = common::http::Http::DecodeQueryData(query);
  if (!query_data.has_value()) {
    spdlog::info("{}: form data is invalid", __func__);
    return google::rpc::Code::INVALID_ARGUMENT;
  }
  const auto state_from_request = query_data->find("state");
  const auto code_from_request = query_data->find("code");
  if (state_from_request == query_data->end() ||
      code_from_request == query_data->end()) {
    spdlog::info(
        "{}: form data does not contain expected state and code parameters",
        __func__);
    return google::rpc::Code::INVALID_ARGUMENT;
  }

  std::shared_ptr<AuthorizationState> authorization_state;
  try {
    authorization_state = session_store_->GetAuthorizationState(session_id);
  } catch (SessionError &err) {
    spdlog::error("{}: Session error in GetAuthorizationState: {}", __func__,
                  err.what());
    return SessionErrorResponse(response, err);
  }

  if (!authorization_state) {
    spdlog::info(
        "{}: Missing state, nonce, and original url requested by the user. "
        "Cannot redirect.",
        __func__);
    response->mutable_denied_response()->mutable_status()->set_code(
        envoy::type::v3::BadRequest);
    response->mutable_denied_response()->set_body(
        "Oops, your session has expired. Please try again.");
    return google::rpc::Code::UNAUTHENTICATED;
  }

  // Compare state from request and session
  if (state_from_request->second != authorization_state->GetState()) {
    spdlog::info("{}: mismatch state", __func__);
    return google::rpc::Code::INVALID_ARGUMENT;
  }

  // Build headers
  auto authorization = common::http::Http::EncodeBasicAuth(
      idp_config_.client_id(), idp_config_.client_secret());
  std::map<absl::string_view, absl::string_view> headers = {
      {common::http::headers::ContentType,
       common::http::headers::ContentTypeDirectives::FormUrlEncoded},
      {common::http::headers::Authorization, authorization},
  };

  // Build body
  std::multimap<absl::string_view, absl::string_view> params = {
      {"code", code_from_request->second},
      {"redirect_uri", idp_config_.callback_uri()},
      {"grant_type", "authorization_code"},
  };

  auto retrieve_token_response =
      http_ptr_->Post(idp_config_.token_uri(), headers,
                      common::http::Http::EncodeFormData(params),
                      idp_config_.trusted_certificate_authority(),
                      idp_config_.proxy_uri(), ioc, yield);
  if (retrieve_token_response == nullptr) {
    spdlog::info("{}: HTTP error encountered: {}", __func__,
                 "IdP connection error");
    return google::rpc::Code::INTERNAL;
  }
  if (retrieve_token_response->result() != boost::beast::http::status::ok) {
    spdlog::info("{}: HTTP token response error: {}", __func__,
                 retrieve_token_response->result_int());
    return google::rpc::Code::UNKNOWN;
  } else {
    auto nonce = authorization_state->GetNonce();
    auto token_response = parser_->Parse(idp_config_.client_id(), nonce,
                                         retrieve_token_response->body());
    if (!token_response) {
      spdlog::info("{}: Invalid token response", __func__);
      return google::rpc::Code::INVALID_ARGUMENT;
    }

    // If access_token forwarding is configured but there is not an access token
    // in the token response then there is a problem
    if (idp_config_.has_access_token()) {
      auto access_token = token_response->AccessToken();
      if (!access_token.has_value()) {
        spdlog::info("{}: Missing expected access_token", __func__);
        return google::rpc::Code::INVALID_ARGUMENT;
      }
    }

    try {
      session_store_->ClearAuthorizationState(session_id);
    } catch (SessionError &err) {
      spdlog::error("{}: Session error in ClearAuthorizationState: {}",
                    __func__, err.what());
      return SessionErrorResponse(response, err);
    }

    spdlog::info("{}: Saving token response to session store", __func__);
    try {
      session_store_->SetTokenResponse(session_id, token_response);
    } catch (SessionError &err) {
      spdlog::error("{}: Session error in SetTokenResponse: {}", __func__,
                    err.what());
      return SessionErrorResponse(response, err);
    }

    SetRedirectHeaders(authorization_state->GetRequestedUrl(), response);
    return google::rpc::Code::UNAUTHENTICATED;
  }
}

absl::string_view OidcFilter::Name() const { return filter_name_; }

}  // namespace oidc
}  // namespace filters
}  // namespace authservice
