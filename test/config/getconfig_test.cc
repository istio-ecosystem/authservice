#include "src/config/getconfig.h"
#include "gtest/gtest.h"

namespace authservice {
namespace config {

TEST(GetConfigTest, ReturnsTheConfig) {
  auto config = GetConfig("test/fixtures/valid-config.json");
  const authservice::config::oidc::OIDCConfig &oidc =
      config->filters().at(0).oidc();

  ASSERT_EQ(config->listen_port(), 10003);
  ASSERT_EQ(config->log_level(), "trace");

  ASSERT_EQ(oidc.authorization().scheme(), "https");
  ASSERT_EQ(oidc.authorization().hostname(), "google3");
  ASSERT_EQ(oidc.authorization().path(), "/path3");
  ASSERT_EQ(oidc.authorization().port(), 443);

  ASSERT_EQ(oidc.token().scheme(), "https");
  ASSERT_EQ(oidc.token().hostname(), "google2");
  ASSERT_EQ(oidc.token().path(), "/path2");
  ASSERT_EQ(oidc.token().port(), 443);

  ASSERT_EQ(oidc.jwks_uri().scheme(), "https");
  ASSERT_EQ(oidc.jwks_uri().hostname(), "google1");
  ASSERT_EQ(oidc.jwks_uri().path(), "/path1");
  ASSERT_EQ(oidc.jwks_uri().port(), 443);

  ASSERT_EQ(oidc.jwks(), "some-jwks");

  ASSERT_EQ(oidc.callback().scheme(), "https");
  ASSERT_EQ(oidc.callback().hostname(), "google4");
  ASSERT_EQ(oidc.callback().path(), "/path4");
  ASSERT_EQ(oidc.callback().port(), 443);

  ASSERT_EQ(oidc.client_id(), "foo");
  ASSERT_EQ(oidc.client_secret(), "bar");

  ASSERT_EQ(oidc.scopes().at(0), "scope");
  ASSERT_EQ(oidc.scopes().size(), 1);

  ASSERT_EQ(oidc.landing_page(), "page");
  ASSERT_EQ(oidc.cryptor_secret(), "some-secret");
  ASSERT_EQ(oidc.cookie_name_prefix(), "my-app");
  ASSERT_EQ(oidc.timeout(), 300);
}

TEST(GetConfigTest, ValidateOidcConfigThrowsForInvalidConfig) {
  ASSERT_THROW(GetConfig("test/fixtures/invalid-config.json"),
               std::runtime_error);
}

TEST(GetConfigTest,
     ValidateOidcConfigThrowsForInvalidConfigForUriNestedProperties) {
  ASSERT_THROW(
      GetConfig("test/fixtures/invalid-config-with-intermediate-nodes.json"),
      std::runtime_error);
}

}  // namespace config
}  // namespace authservice
