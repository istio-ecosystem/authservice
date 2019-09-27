#include "src/filters/oidc/oidc_idp_configuration.h"
#include "gtest/gtest.h"

namespace transparent_auth {
namespace filters {
namespace oidc {
namespace {
const common::http::Endpoint authorization_endpoint = {
    .scheme = "https",
    .hostname = "some-idp.com",
    .port = 443,
    .path = "/authorization",
};
const common::http::Endpoint token_endpoint = {
    .scheme = "https",
    .hostname = "some-idp.com",
    .port = 443,
    .path = "/token",
};
const common::http::Endpoint jwks_endpoint = {
    .scheme = "https", .hostname = "some-idp.com", .port = 443, .path = "/jwks",
};
const std::string client_id = "client_foo";
const std::string client_secret = "super_secret";
const common::http::Endpoint callback_path = {
    .scheme = "https", .hostname = "me.com", .port = 443, .path = "/callback",
};
const std::string landing_page = "/relative-path";
}

TEST(OidcIdPConfigurationTest, ConstructorAndGetters) {
  std::set<std::string> scopes = {"foo", "bar"};
  OidcIdPConfiguration config(authorization_endpoint, token_endpoint,
                              jwks_endpoint, client_id, client_secret, scopes,
                              callback_path, landing_page);
  ASSERT_EQ(config.AuthorizationEndpoint(), authorization_endpoint);
  ASSERT_EQ(config.TokenEndpoint(), token_endpoint);
  ASSERT_EQ(config.JwksEndpoint(), jwks_endpoint);
  ASSERT_EQ(config.ClientId(), client_id);
  ASSERT_EQ(config.ClientSecret(), client_secret);
  ASSERT_EQ(config.LandingPage(), landing_page);
  ASSERT_EQ(config.Scopes().size(), scopes.size() + 1);
  for (auto scope : scopes) {
    ASSERT_NE(config.Scopes().find(scope), config.Scopes().end());
  }
  // Check `openid` scope is added even when not specified.
  ASSERT_NE(config.Scopes().find("openid"), config.Scopes().end());

  ASSERT_EQ(config.CallbackPath(), callback_path);
}

}  // namespace oidc
}  // namespace service
}  // namespace transparent_auth
