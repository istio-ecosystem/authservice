#ifndef TRANSPARENT_AUTH_SRC_FILTERS_OIDC_OIDC_FILTER_H_
#define TRANSPARENT_AUTH_SRC_FILTERS_OIDC_OIDC_FILTER_H_
#include "config/oidc/config.pb.h"
#include "external/com_google_googleapis/google/rpc/code.pb.h"
#include "src/common/http/http.h"
#include "src/common/session/token_encryptor.h"
#include "src/filters/filter.h"
#include "src/filters/oidc/token_response.h"

namespace transparent_auth {
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
  const authservice::config::oidc::OIDCConfig &idp_config_;
  TokenResponseParserPtr parser_;
  common::session::TokenEncryptorPtr cryptor_;

  /**
   * Set HTTP header helper in a response.
   * @param response the response to add the header to
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

  /** @brief Set state cookie.
   *
   * @param headers The headers to add to.
   * @param value The value of the state cookie.
   */
  void SetStateCookie(
      ::google::protobuf::RepeatedPtrField<
          ::envoy::api::v2::core::HeaderValueOption> *headers,
      absl::string_view value);

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
  std::string GetStateCookieName();

  /** @brief Get id token cookie name. */
  std::string GetIdTokenCookieName();
};

}  // namespace oidc
}  // namespace filters
}  // namespace transparent_auth

#endif  // TRANSPARENT_AUTH_SRC_FILTERS_OIDC_OIDC_FILTER_H_
