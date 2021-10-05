#ifndef AUTHSERVICE_SRC_FILTERS_OIDC_OIDC_FILTER_H_
#define AUTHSERVICE_SRC_FILTERS_OIDC_OIDC_FILTER_H_

#include <ctime>

#include "boost/asio/io_context.hpp"
#include "config/oidc/config.pb.h"
#include "google/rpc/code.pb.h"
#include "src/common/http/http.h"
#include "src/common/session/session_string_generator.h"
#include "src/common/utilities/random.h"
#include "src/filters/filter.h"
#include "src/filters/filter_factory.h"
#include "src/filters/oidc/jwks_resolver.h"
#include "src/filters/oidc/session_store.h"
#include "src/filters/oidc/token_response.h"

namespace authservice {
namespace filters {
namespace oidc {

/** @brief An implementation of an OpenID Connect token acquisition filter.
 *
 * An implementation of an OpenID Connect token acquisition filter which
 * performs agent redirection and token acquisition
 * using the Authorization Code flow. See
 * https://openid.net/specs/openid-connect-core-1_0.html.
 */

class OidcFilter final : public filters::Filter {
 private:
  common::http::ptr_t http_ptr_;
  const config::oidc::OIDCConfig idp_config_;
  TokenResponseParserPtr parser_;
  common::session::SessionStringGeneratorPtr session_string_generator_;
  SessionStorePtr session_store_;

  /**
   * Set HTTP header helper in a response.
   * @param headers the response headers in which to add the header
   * @param name the name of the header
   * @param value the header value
   */
  static void SetHeader(
      ::google::protobuf::RepeatedPtrField<
          ::envoy::config::core::v3::HeaderValueOption> *headers,
      absl::string_view name, absl::string_view value);

  /** @brief Set standard reply headers.
   *
   * Set standard reply headers. For example cache-control headers.
   * @param response The response to be augmented.
   */
  static void SetStandardResponseHeaders(
      ::envoy::service::auth::v3::CheckResponse *response);

  /** @brief Set redirect headers.
   *
   * @param redirect_url The url to redirect to.
   * @param response The response to be augmented.
   */
  static void SetRedirectHeaders(
      absl::string_view redirect_url,
      ::envoy::service::auth::v3::CheckResponse *response);

  void SetLogoutHeaders(envoy::service::auth::v3::CheckResponse *response);

  google::rpc::Code SessionErrorResponse(
      envoy::service::auth::v3::CheckResponse *response,
      const SessionError &err);

  /** @brief Encode the given timeout as a cookie Max-Age directive.
   *
   * @param timeout the time out in seconds.
   * @return the encoded cookie directive.
   */
  static std::string EncodeCookieTimeoutDirective(int64_t timeout);

  /** @brief Set cookie.
   *
   * @param responseHeaders The headers to add to.
   * @param cookie_name The key name of the cookie to be set.
   * @param value The value of the cookie.
   * @param timeout The lifetime in seconds the cookie is valid for before
   * browsers should not honor this cookie.
   */
  void SetCookie(
      ::google::protobuf::RepeatedPtrField<
          ::envoy::config::core::v3::HeaderValueOption> *responseHeaders,
      const std::string &cookie_name, absl::string_view value, int64_t timeout);

  /** @brief Extract the requested cookie from the given headers
   *
   * @param headers the headers to extract the cookies from
   * @param cookie the name of the cookie to extract
   * @return the extracted cookie value
   */
  static absl::optional<std::string> CookieFromHeaders(
      const ::google::protobuf::Map<::std::string, ::std::string> &headers,
      const std::string &cookie);

  google::rpc::Code RedirectToIdp(
      envoy::service::auth::v3::CheckResponse *response,
      const ::envoy::service::auth::v3::AttributeContext_HttpRequest
          &httpRequest,
      absl::optional<std::string> old_session_id = absl::nullopt);

  /** @brief Retrieve tokens from OIDC token endpoint */
  google::rpc::Code RetrieveToken(
      const ::envoy::service::auth::v3::CheckRequest *request,
      ::envoy::service::auth::v3::CheckResponse *response,
      absl::string_view session_id, boost::asio::io_context &ioc,
      boost::asio::yield_context yield);

  /** @brief Refresh tokens from OIDC token endpoint */
  std::shared_ptr<TokenResponse> RefreshToken(
      const TokenResponse &existing_token_response,
      const std::string &refresh_token, boost::asio::io_context &ioc,
      boost::asio::yield_context yield);

  /** @brief Get a cookie name. */
  std::string GetCookieName(const std::string &cookie) const;

  /** @brief Encode a cookie value with optional preamble. */
  std::string EncodeHeaderValue(const std::string &premable,
                                const std::string &value);

  /**
   * @brief Given an ID token, put it in a request header for the application to
   * consume
   *
   * @param response the outgoing response
   * @param id_token the ID token
   */
  void SetIdTokenHeader(::envoy::service::auth::v3::CheckResponse *response,
                        const std::string &id_token);

  /**
   * @brief Given an access token, put it in a request header for the
   * application to consume
   *
   * @param response the outgoing response
   * @param access_token the access token
   */
  void SetAccessTokenHeader(::envoy::service::auth::v3::CheckResponse *response,
                            const std::string &access_token);

  /**
   * @brief Given a session id, put it in a request header for the application
   * to consume
   *
   * @param response the outgoing response
   * @param session_id the session id
   */
  void SetSessionIdCookie(::envoy::service::auth::v3::CheckResponse *response,
                          std::string session_id);

  /**
   * @brief Retrieve and decrypt the sessionId from cookies
   *
   * @param headers The request headers to read the cookie from
   * @return
   */
  absl::optional<std::string> GetSessionIdFromCookie(
      const ::google::protobuf::Map<::std::string, ::std::string> &headers);

  /**
   * @brief Assemble a URL string from a request
   *
   * @param The http request
   * @return The requested Url from the http request as a string
   */
  static std::string GetRequestUrl(
      const ::envoy::service::auth::v3::AttributeContext_HttpRequest
          &http_request);

  /**
   * @brief Get the directives that should be used when setting a cookie
   *
   * @param timeout The value of the Max-Age for the cookie
   * @return The set of directives as strings, e.g. a set of strings like
   * "Max-Age=42"
   */
  std::set<std::string> GetCookieDirectives(int64_t timeout);

  void DeleteCookie(
      ::google::protobuf::RepeatedPtrField<
          ::envoy::config::core::v3::HeaderValueOption> *responseHeaders,
      const std::string &cookieName);

  /** @brief Check if the request appears to be the callback request. */
  bool MatchesCallbackRequest(
      const ::envoy::service::auth::v3::CheckRequest *request);

  /** @brief Check if the request appears to be the logout request. */
  bool MatchesLogoutRequest(
      const ::envoy::service::auth::v3::CheckRequest *request);

  /** @brief get the path from the request sans query string */
  std::string RequestPath(
      const envoy::service::auth::v3::CheckRequest *request);

  /** @brief get the query string from the request sans path */
  std::string RequestQueryString(
      const envoy::service::auth::v3::CheckRequest *request);

  bool RequiredTokensPresent(std::shared_ptr<TokenResponse> token_response);

  bool RequiredTokensExpired(TokenResponse &token_response);

  void AddTokensToRequestHeaders(
      envoy::service::auth::v3::CheckResponse *response,
      TokenResponse &tokenResponse);

 public:
  OidcFilter(
      common::http::ptr_t http_ptr, const config::oidc::OIDCConfig &idp_config,
      TokenResponseParserPtr parser,
      common::session::SessionStringGeneratorPtr session_string_generator,
      SessionStorePtr session_store);

  google::rpc::Code Process(
      const ::envoy::service::auth::v3::CheckRequest *request,
      ::envoy::service::auth::v3::CheckResponse *response,
      boost::asio::io_context &ioc, boost::asio::yield_context yield) override;

  // Required to inherit the 2-argument version of Process from the base class
  using filters::Filter::Process;

  absl::string_view Name() const override;

  /** @brief Get sessionID cookie name */
  std::string GetSessionIdCookieName() const;
};

class FilterFactory : public filters::FilterFactory {
 public:
  FilterFactory(const config::oidc::OIDCConfig &config,
                oidc::SessionStorePtr session_store,
                oidc::JwksResolverCachePtr resolver_cache)
      : config_(config),
        session_store_(session_store),
        resolver_cache_(resolver_cache) {}

  filters::FilterPtr create() override;

 private:
  const config::oidc::OIDCConfig config_;
  oidc::SessionStorePtr session_store_;
  oidc::JwksResolverCachePtr resolver_cache_;
};

}  // namespace oidc
}  // namespace filters
}  // namespace authservice

#endif  // AUTHSERVICE_SRC_FILTERS_OIDC_OIDC_FILTER_H_
