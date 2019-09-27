#include "oidc_idp_configuration.h"

namespace transparent_auth {
namespace filters {
namespace oidc {

namespace {
// The required OpenID Connect scope.
const char *openid_connect_scope_ = "openid";
}

OidcIdPConfiguration::OidcIdPConfiguration(
    const common::http::Endpoint &authorization_endpoint,
    const common::http::Endpoint &token_endpoint,
    const common::http::Endpoint &jwks_endpoint, const std::string &client_id,
    const std::string &client_secret, const std::set<std::string> &scopes,
    const common::http::Endpoint &callback_path,
    const std::string &landing_page)
    : authorization_endpoint_(authorization_endpoint),
      token_endpoint_(token_endpoint),
      jwks_endpoint_(jwks_endpoint),
      client_id_(client_id),
      client_secret_(client_secret),
      callback_path_(callback_path),
      landing_page_(landing_page) {
  scopes_.insert(openid_connect_scope_);
  scopes_.insert(scopes.cbegin(), scopes.cend());
}

const common::http::Endpoint &OidcIdPConfiguration::AuthorizationEndpoint()
    const {
  return authorization_endpoint_;
}

const common::http::Endpoint &OidcIdPConfiguration::TokenEndpoint() const {
  return token_endpoint_;
}

const common::http::Endpoint &OidcIdPConfiguration::JwksEndpoint() const {
  return jwks_endpoint_;
}

const std::string &OidcIdPConfiguration::ClientId() const { return client_id_; }

const std::string &OidcIdPConfiguration::ClientSecret() const {
  return client_secret_;
}

const std::set<std::string> &OidcIdPConfiguration::Scopes() const {
  return scopes_;
}

const common::http::Endpoint &OidcIdPConfiguration::CallbackPath() const {
  return callback_path_;
}

const std::string &OidcIdPConfiguration::LandingPage() const {
  return landing_page_;
}

}  // namespace oidc
}  // namespace filters
}  // namedspace transparent_auth
