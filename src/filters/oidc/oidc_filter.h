#ifndef AUTHSERVICE_SRC_FILTERS_OIDC_OIDC_FILTER_H_
#define AUTHSERVICE_SRC_FILTERS_OIDC_OIDC_FILTER_H_

#include "config/oidc/config.pb.h"
#include "google/rpc/code.pb.h"
#include "src/common/http/http.h"
#include "src/common/session/token_encryptor.h"
#include "src/filters/filter.h"
#include "src/filters/oidc/token_response.h"
#include "src/common/utilities/random.h"
#include "src/common/session/session_id_generator.h"
#include "src/filters/oidc/session_store.h"
#include <ctime>

namespace authservice {
namespace filters {
namespace oidc {

/*** @brief An implementation of an OpenID Connect token acquisition filter.
 *
 * An implementation of an OpenID Connect token acquisition filter which
 * performs agent redirection and token acquisition
 * using the Authorization Code flow. See
 * https://openid.net/specs/openid-connect-core-1_0.html.
 */
class OidcFilter final : public filters::Filter {
private:
  common::http::ptr_t http_ptr_;
  const authservice::config::oidc::OIDCConfig idp_config_;
  TokenResponseParserPtr parser_;
  common::session::TokenEncryptorPtr cryptor_;
  common::session::SessionIdGeneratorPtr session_id_generator_;
  SessionStorePtr session_store_;

  /**
   * Set HTTP header helper in a response.
   * @param headers the response headers in which to add the header
   * @param name the name of the header
   * @param value the header value
   */
  static void SetHeader(::google::protobuf::RepeatedPtrField<::envoy::api::v2::core::HeaderValueOption> *headers,
                        absl::string_view name, absl::string_view value);

  /** @brief Set standard reply headers.
   *
   * Set standard reply headers. For example cache-control headers.
   * @param response The response to be augmented.
   */
  static void SetStandardResponseHeaders(
      ::envoy::service::auth::v2::CheckResponse *response);

  /** @brief Set redirect headers.
   *
   * @param redirect_url The url to redirect to.
   * @param response The response to be augmented.
   */
  static void SetRedirectHeaders(
      absl::string_view redirect_url,
      ::envoy::service::auth::v2::CheckResponse *response);

  void SetLogoutHeaders(CheckResponse *response);

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
   * @param timeout The lifetime in seconds the cookie is valid for before browsers should not honor this cookie.
   */
  void SetCookie(::google::protobuf::RepeatedPtrField<::envoy::api::v2::core::HeaderValueOption> *responseHeaders,
                 const std::string &cookie_name, absl::string_view value, int64_t timeout);

  /** @brief Set cookie.
   *
   * @param responseHeaders The headers to add to.
   * @param cookie_name The key name of the cookie to be set.
   * @param value_to_be_encrypted The value of the cookie, which will be encrypted in the cookie.
   * @param timeout The lifetime in seconds the cookie is valid for before browsers should not honor this cookie.
   */
  void SetEncryptedCookie(
      ::google::protobuf::RepeatedPtrField<::envoy::api::v2::core::HeaderValueOption> *responseHeaders,
      const std::string &cookie_name, absl::string_view value_to_be_encrypted, int64_t timeout);

  /** @brief Extract the requested cookie from the given headers
   *
   * @param headers the headers to extract the cookies from
   * @param cookie the name of the cookie to extract
   * @return the extracted cookie value
   */
  static absl::optional<std::string> CookieFromHeaders(
      const ::google::protobuf::Map<::std::string, ::std::string> &headers,
      const std::string &cookie);

  /** @brief Set IdP redirect parameters
   *
   * Set IdP redirect parameters so that a requesting agent is forced to
   * authenticate the user.
   */
  void SetRedirectToIdPHeaders(::envoy::service::auth::v2::CheckResponse *response, std::string session_id);

  /** @brief Retrieve tokens from OIDC token endpoint */
  google::rpc::Code RetrieveToken(
      const ::envoy::service::auth::v2::CheckRequest *request,
      ::envoy::service::auth::v2::CheckResponse *response,
      absl::string_view session_id,
      boost::asio::io_context &ioc,
      boost::asio::yield_context yield);

  /** @brief Refresh tokens from OIDC token endpoint */
  absl::optional<TokenResponse> RefreshToken(
      TokenResponse existing_token_response,
      const std::string &refresh_token,
      boost::asio::io_context &ioc,
      boost::asio::yield_context yield);

  /** @brief Get a cookie name. */
  std::string GetCookieName(const std::string &cookie) const;

  /** @brief Encode a cookie value with optional preamble. */
  std::string EncodeHeaderValue(const std::string &premable,
                                const std::string &value);

  /**
   * @brief Given an ID token, put it in a request header for the application to consume
   *
   * @param response the outgoing response
   * @param id_token the ID token
   */
  void SetIdTokenHeader(::envoy::service::auth::v2::CheckResponse *response, const std::string &id_token);

  /**
   * @brief Given an access token, put it in a request header for the application to consume
   *
   * @param response the outgoing response
   * @param access_token the access token
   */
  void SetAccessTokenHeader(::envoy::service::auth::v2::CheckResponse *response, const std::string &access_token);

  /**
   * @brief Given a session id, put it in a request header for the application to consume
   *
   * @param response the outgoing response
   * @param session_id the session id
   */
  void SetSessionIdCookie(::envoy::service::auth::v2::CheckResponse *response, std::string session_id);

  /**
   * @brief Retrieve and decrypt the sessionId from cookies
   *
   * @param headers The request headers to read the cookie from
   * @return
   */
  absl::optional<std::string> GetSessionIdFromCookie(const ::google::protobuf::Map<::std::string,
      ::std::string> &headers);

  /**
   * @brief Get the directives that should be used when setting a cookie
   *
   * @param timeout The value of the Max-Age for the cookie
   * @return The set of directives as strings, e.g. a set of strings like "Max-Age=42"
   */
  std::set<std::string> GetCookieDirectives(int64_t timeout);

  void DeleteCookie(::google::protobuf::RepeatedPtrField<::envoy::api::v2::core::HeaderValueOption> *responseHeaders,
                    const std::string &cookieName);

  /** @brief Check if the request appears to be the callback request. */
  bool MatchesCallbackRequest(const ::envoy::service::auth::v2::CheckRequest *request);

  /** @brief Check if the request appears to be the logout request. */
  bool MatchesLogoutRequest(const ::envoy::service::auth::v2::CheckRequest *request);

  /** @brief get the path from the request sans query string */
  std::string RequestPath(const CheckRequest *request);

  /** @brief get the query string from the request sans path */
  std::string RequestQueryString(const CheckRequest *request);

  bool RequiredTokensPresent(absl::optional<TokenResponse> &token_response);

  bool RequiredTokensExpired(TokenResponse &token_response);

  void AddTokensToRequestHeaders(CheckResponse *response, TokenResponse &tokenResponse);

public:
  OidcFilter(common::http::ptr_t http_ptr,
             const authservice::config::oidc::OIDCConfig &idp_config,
             TokenResponseParserPtr parser,
             common::session::TokenEncryptorPtr cryptor,
             common::session::SessionIdGeneratorPtr session_id_generator,
             SessionStorePtr session_store);

  google::rpc::Code Process(
      const ::envoy::service::auth::v2::CheckRequest *request,
      ::envoy::service::auth::v2::CheckResponse *response,
      boost::asio::io_context &ioc,
      boost::asio::yield_context yield) override;

  // Required to inherit the 2-argument version of Process from the base class
  using filters::Filter::Process;

  absl::string_view Name() const override;

  /** @brief Get state cookie name. */
  std::string GetStateCookieName() const;

  /** @brief Get sessionID cookie name */
  std::string GetSessionIdCookieName() const;
};

}  // namespace oidc
}  // namespace filters
}  // namespace authservice

#endif  // AUTHSERVICE_SRC_FILTERS_OIDC_OIDC_FILTER_H_
