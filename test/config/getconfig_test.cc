#include "src/config/getconfig.h"
#include "gtest/gtest.h"

namespace transparent_auth {
namespace config {

class GetConfigTest : public ::testing::Test {
 public:
  constexpr static const char *const expected_error_message =
      "Missing required configuration: "
      "filters.oidc.authorization.scheme, filters.oidc.authorization.hostname, "
      "filters.oidc.authorization.path, filters.oidc.authorization.port, "
      "filters.oidc.token.scheme, filters.oidc.token.hostname, "
      "filters.oidc.token.path, filters.oidc.token.port, "
      "filters.oidc.jwks, "
      "filters.oidc.callback.scheme, filters.oidc.callback.hostname, "
      "filters.oidc.callback.path, filters.oidc.callback.port, "
      "filters.oidc.client_id, filters.oidc.client_secret, "
      "filters.oidc.landing_page, filters.oidc.cryptor_secret";
};

TEST_F(GetConfigTest, ReturnsTheConfig) {
  auto config = GetConfig("test/fixtures/valid-config.json");
  const authservice::config::oidc::OIDCConfig &oidc =
      config->filters().at(0).oidc();

  ASSERT_EQ(config->listen_port(), "10003");
  ASSERT_EQ(config->log_level(), "trace");

  ASSERT_EQ(oidc.authorization().scheme(), "https");
  ASSERT_EQ(oidc.authorization().hostname(), "google3");
  ASSERT_EQ(oidc.authorization().path(), "path3");
  ASSERT_EQ(oidc.authorization().port(), 443);

  ASSERT_EQ(oidc.token().scheme(), "https");
  ASSERT_EQ(oidc.token().hostname(), "google2");
  ASSERT_EQ(oidc.token().path(), "path2");
  ASSERT_EQ(oidc.token().port(), 443);

  ASSERT_EQ(oidc.jwks_uri().scheme(), "https");
  ASSERT_EQ(oidc.jwks_uri().hostname(), "google1");
  ASSERT_EQ(oidc.jwks_uri().path(), "path1");
  ASSERT_EQ(oidc.jwks_uri().port(), 443);

  ASSERT_EQ(oidc.jwks(), "some-jwks");

  ASSERT_EQ(oidc.callback().scheme(), "https");
  ASSERT_EQ(oidc.callback().hostname(), "google4");
  ASSERT_EQ(oidc.callback().path(), "path4");
  ASSERT_EQ(oidc.callback().port(), 443);

  ASSERT_EQ(oidc.client_id(), "foo");
  ASSERT_EQ(oidc.client_secret(), "bar");

  ASSERT_EQ(oidc.scopes().at(0), "scope");
  ASSERT_EQ(oidc.scopes().size(), 1);

  ASSERT_EQ(oidc.landing_page(), "page");
  ASSERT_EQ(oidc.cryptor_secret(), "some-secret");
  ASSERT_EQ(oidc.cookie_name_prefix(), "my-app");
}

TEST_F(GetConfigTest, ValidateOidcConfigThrowsForInvalidConfig) {
  auto invalid_config = GetConfig("test/fixtures/invalid-config.json");
  bool validate_config_threw = false;
  try {
    ValidateOidcConfig(invalid_config->filters().at(0).oidc());
  } catch (const std::exception &e) {
    validate_config_threw = true;
    ASSERT_STREQ(e.what(), expected_error_message);
  }
  ASSERT_TRUE(validate_config_threw);
}

TEST_F(GetConfigTest,
       ValidateOidcConfigThrowsForInvalidConfigForUriNestedProperties) {
  auto invalid_config =
      GetConfig("test/fixtures/invalid-config-with-intermediate-nodes.json");
  bool validate_config_threw = false;
  try {
    ValidateOidcConfig(invalid_config->filters().at(0).oidc());
  } catch (const std::exception &e) {
    validate_config_threw = true;
    ASSERT_STREQ(e.what(), expected_error_message);
  }
  ASSERT_TRUE(validate_config_threw);
}

TEST_F(GetConfigTest, ValidateOidcConfigDoesNotThrowForValidConfig) {
  auto valid_config = GetConfig("test/fixtures/valid-config.json");
  ASSERT_NO_THROW(ValidateOidcConfig(valid_config->filters().at(0).oidc()););
}

}  // namespace config
}  // namespace transparent_auth
