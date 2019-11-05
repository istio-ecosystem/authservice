#ifndef AUTHSERVICE_SRC_FILTERS_OIDC_OIDC_FILTER_H_
#define AUTHSERVICE_SRC_FILTERS_OIDC_OIDC_FILTER_H_
#include "config/oidc/config.pb.h"
#include "external/com_google_googleapis/google/rpc/code.pb.h"
#include "src/common/http/http.h"
#include "src/common/session/token_encryptor.h"
#include "src/filters/filter.h"
#include "src/filters/oidc/token_response.h"

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

  /**
   * Set HTTP header helper in a response.
   * @param headers the response headers in which to add the header
   * @param name the name of the header
   * @param value the header value
   */
  static void SetHeader(::google::protobuf::RepeatedPtrField<
                            ::envoy::api::v2::core::HeaderValueOption> *headers,
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
   *
   * @param response the redirect response
   * @return the call state.
   */
  google::rpc::Code RedirectToIdP(
      ::envoy::service::auth::v2::CheckResponse *response);
  /** @brief Retrieve tokens from OIDC token endpoint
   *
   * @param request the incoming request
   * @param response the outgoing response
   * @param query the request query string
   * @return the call status
   */
  google::rpc::Code RetrieveToken(
      const ::envoy::service::auth::v2::CheckRequest *request,
      ::envoy::service::auth::v2::CheckResponse *response,
      absl::string_view query);

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
   * @brief Retrieve and decrypt the token from the specified cookie
   *
   * @param headers The request headers to read the cookie from
   * @param cookie_name The name of the cookie to read the token from
   * @return
   */
  absl::optional<std::string> GetTokenFromCookie(const ::google::protobuf::Map<::std::string,
      ::std::string> &headers, const std::string &cookie_name);

  /**
   * @brief Get the directives that should be used when setting a cookie
   *
   * @param timeout The value of the Max-Age for the cookie
   * @return The set of directives as strings, e.g. a set of strings like "Max-Age=42"
   */
  std::set<std::string> GetCookieDirectives(int64_t timeout);

public:
  OidcFilter(common::http::ptr_t http_ptr,
             const authservice::config::oidc::OIDCConfig &idp_config,
             TokenResponseParserPtr parser,
             common::session::TokenEncryptorPtr cryptor);

  google::rpc::Code Process(
      const ::envoy::service::auth::v2::CheckRequest *request,
      ::envoy::service::auth::v2::CheckResponse *response) override;
  absl::string_view Name() const override;

  /** @brief Get state cookie name. */
  std::string GetStateCookieName() const;

  /** @brief Get id token cookie name. */
  std::string GetIdTokenCookieName() const;

  /** @brief Get access token cookie name. */
  std::string GetAccessTokenCookieName() const;

  void DeleteCookie(::google::protobuf::RepeatedPtrField<::envoy::api::v2::core::HeaderValueOption> *responseHeaders,
                    const std::string &cookieName);
};

}  // namespace oidc
}  // namespace filters
}  // namespace authservice

#endif  // AUTHSERVICE_SRC_FILTERS_OIDC_OIDC_FILTER_H_
