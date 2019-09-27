#ifndef TRANSPARENT_AUTH_SRC_FILTERS_OIDC_OIDC_IDP_CONFIGURATION_H_
#define TRANSPARENT_AUTH_SRC_FILTERS_OIDC_OIDC_IDP_CONFIGURATION_H_
#include <set>
#include <string>
#include "src/common/http/http.h"

namespace transparent_auth {
namespace filters {
namespace oidc {

/*** @brief Configuration for an IdP that support OpenID Connect.
 *
 * Configuration for an IdP that support OpenID Connect Authorization Code flow.
 */
class OidcIdPConfiguration final {
 private:
  common::http::Endpoint authorization_endpoint_;
  common::http::Endpoint token_endpoint_;
  common::http::Endpoint jwks_endpoint_;
  std::string client_id_;
  std::string client_secret_;
  std::set<std::string> scopes_;
  common::http::Endpoint callback_path_;
  std::string landing_page_;

 public:
  /*** @brief Constructor
   *
   * @param authorization_endpoint the authorization endpoint of the IdP.
   * @param token_endpoint the token endpoint of the IdP.
   * @param jwks_endpoint the JWKS endpoint of the IdP.
   * @param client_id the Client ID to connect to the IdP.
   * @param client_secret the shared Client secret to connect to the IdP.
   * @param scopes the scopes request from the IdP.
   * @param callback_path the path used for the local OpenID Connect callback.
   * @param landing_page the relative path the user is redirected to after
   * successful authentication.
   */
  OidcIdPConfiguration(const common::http::Endpoint &authorization_endpoint,
                       const common::http::Endpoint &token_endpoint,
                       const common::http::Endpoint &jwks_endpoint,
                       const std::string &client_id,
                       const std::string &client_secret,
                       const std::set<std::string> &scopes,
                       const common::http::Endpoint &callback_path,
                       const std::string &landing_page);

  /***
   * The authorization endpoint.
   */
  const common::http::Endpoint &AuthorizationEndpoint() const;
  /***
   * The token endpoint.
   */
  const common::http::Endpoint &TokenEndpoint() const;
  /***
   * The JWKS endpoint.
   */
  const common::http::Endpoint &JwksEndpoint() const;
  /***
   * The Client ID.
   */
  const std::string &ClientId() const;
  /***
   * The Client secret.
   */
  const std::string &ClientSecret() const;
  /***
   * The percent-encoded scopes which always includes at least `openid`.
   */
  const std::set<std::string> &Scopes() const;
  /***
   * The callback path.
   */
  const common::http::Endpoint &CallbackPath() const;
  /***
   * The landing page relative path.
   */
  const std::string &LandingPage() const;
};

}  // namespace oidc
}  // namespace filters
}  // namespace transparent_Auth

#endif  // TRANSPARENT_AUTH_SRC_FILTERS_OIDC_OIDC_IDP_CONFIGURATION_H_
