#include <boost/filesystem.hpp>
#include <fstream>

#include "google/protobuf/util/json_util.h"
#include "gtest/gtest.h"
#include "src/config/get_config.h"
#include "test/shared/assertions.h"

namespace authservice {
namespace config {

using test_helpers::ASSERT_THROWS_STD_RUNTIME_ERROR;

class GetConfigTest : public ::testing::Test {
 protected:
  // Note that the json '{' and '}' are doubled to escape them in usages of
  // fmt::format below
  const char *minimal_valid_config = R"JSON(
  {{
    "listen_address": "127.0.0.1",
    "listen_port": "10003",
    "log_level": "trace",
    "threads": 8,
    "chains": [
      {{
        "name": "test-chain",
        "filters": [
          {{
            "oidc":
            {{
              "authorization_uri": "{}",
              "token_uri": "{}",
              "callback_uri": "{}",
              "proxy_uri": "{}",
              "jwks": "fake-jwks",
                "client_id": "fake-client-id",
                "client_secret": "fake-client-secret",
                "id_token": {{
                  "preamble": "Bearer",
                  "header": "authorization"
                }}
            }}
          }}
        ]
      }}
    ]
  }}
  )JSON";

  const char *multiple_chains_valid_config = R"JSON(
  {{
    "listen_address": "127.0.0.1",
    "listen_port": "10003",
    "log_level": "trace",
    "threads": 8,
    "chains": [
      {{
        "name": "test-chain1",
        "filters": [
          {{
            "oidc":
            {{
              "authorization_uri": "{}",
              "token_uri": "{}",
              "callback_uri": "{}",
              "proxy_uri": "{}",
              "jwks": "fake-jwks",
                "client_id": "fake-client-id",
                "client_secret": "fake-client-secret",
                "id_token": {{
                  "preamble": "Bearer",
                  "header": "authorization"
                }}
            }}
          }}
        ]
      }},
      {{
        "name": "test-chain2",
        "filters": [
          {{
            "oidc":
            {{
              "authorization_uri": "{}",
              "token_uri": "{}",
              "callback_uri": "{}",
              "proxy_uri": "{}",
              "jwks": "fake-jwks",
                "client_id": "fake-client-id",
                "client_secret": "fake-client-secret",
                "id_token": {{
                  "preamble": "Bearer",
                  "header": "authorization"
                }}
            }}
          }}
        ]
      }}
    ]
  }}
  )JSON";

  std::string tmp_filename;

  virtual void SetUp() {
    auto pid = ::getpid();
    auto time = ::time(nullptr);
    tmp_filename = "/tmp/test." + std::to_string(pid) + "_" +
                   std::to_string(time) + ".json";
  }

  virtual void TearDown() { std::remove(tmp_filename.c_str()); }

  void write_test_file(const std::string &json_string) {
    std::ofstream stream;
    stream.open(tmp_filename);
    stream << json_string;
    stream.close();
  }
};

TEST_F(GetConfigTest, ReturnsTheConfig) {
  auto config = GetConfig("test/fixtures/valid-config.json");
  const oidc::OIDCConfig &oidc = config->chains().at(0).filters().at(0).oidc();

  ASSERT_EQ(config->listen_port(), 10003);
  ASSERT_EQ(config->log_level(), "trace");
  ASSERT_EQ(config->threads(), 8);

  ASSERT_EQ(config->trigger_rules().size(), 1);
  ASSERT_EQ(config->trigger_rules(0).excluded_paths().size(), 1);
  ASSERT_EQ(config->trigger_rules(0).included_paths().size(), 1);
  ASSERT_EQ(config->trigger_rules(0).excluded_paths(0).exact(),
            "/status/version");
  ASSERT_EQ(config->trigger_rules(0).included_paths(0).prefix(), "/status/");

  ASSERT_EQ(oidc.authorization_uri(), "https://google3/path3");
  ASSERT_EQ(oidc.token_uri(), "https://google2/path2");
  ASSERT_EQ(oidc.callback_uri(), "https://google4/path4");
  ASSERT_EQ(oidc.jwks(), "jwks_placeholder");

  ASSERT_EQ(oidc.client_id(), "foo");
  ASSERT_EQ(oidc.client_secret(), "bar");

  ASSERT_EQ(oidc.scopes().at(0), "scope");
  ASSERT_EQ(oidc.scopes().size(), 1);

  ASSERT_EQ(oidc.cookie_name_prefix(), "my-app");

  ASSERT_EQ(oidc.id_token().preamble(), "Bearer");
  ASSERT_EQ(oidc.id_token().header(), "authorization");

  ASSERT_EQ(oidc.access_token().header(), "x-access-token");

  ASSERT_EQ(oidc.logout().path(), "/logout");
  ASSERT_EQ(oidc.logout().redirect_uri(), "https://logout-redirect");

  ASSERT_EQ(oidc.absolute_session_timeout(), 3600);
  ASSERT_EQ(oidc.idle_session_timeout(), 600);

  ASSERT_EQ(oidc.trusted_certificate_authority(), "ca_placeholder");

  ASSERT_EQ(oidc.proxy_uri(), "http://proxy.example.com");
}

TEST_F(GetConfigTest, ValidateOidcConfigThrowsForInvalidConfig) {
  write_test_file(R"JSON(
    {
      "filters": [
        {
          "oidc":
          {
          }
        }
      ]
    }
  )JSON");

  ASSERT_THROWS_STD_RUNTIME_ERROR([this] { GetConfig(tmp_filename); },
                                  "filters: Cannot find field.");
}

TEST_F(GetConfigTest,
       ValidateOidcConfigThrowsForInvalidConfigForUriNestedProperties) {
  write_test_file(R"JSON(
    {
      "filters": [
        {
          "oidc":
          {
            "authorization_uri": "",
            "token_uri": "",
            "callback_uri": "",
            "jwks": ""
          }
        }
      ]
    }
  )JSON");

  ASSERT_THROWS_STD_RUNTIME_ERROR([this] { GetConfig(tmp_filename); },
                                  "filters: Cannot find field.");
}

TEST_F(GetConfigTest, ValidatesTheUris) {
  write_test_file(fmt::format(minimal_valid_config, "https://foo",
                              "https://bar", "https://baz", "http://proxy"));
  ASSERT_NO_THROW(GetConfig(tmp_filename));

  write_test_file(fmt::format(minimal_valid_config, "https://foo",
                              "https://bar", "https://baz", ""));
  ASSERT_NO_THROW(GetConfig(tmp_filename));

  write_test_file(fmt::format(minimal_valid_config, "invalid", "https://bar",
                              "https://baz", ""));
  ASSERT_THROWS_STD_RUNTIME_ERROR(
      [this] { GetConfig(tmp_filename); },
      "invalid authorization_uri: uri must be https scheme: invalid");

  write_test_file(fmt::format(minimal_valid_config, "https://foo", "invalid",
                              "https://baz", ""));
  ASSERT_THROWS_STD_RUNTIME_ERROR(
      [this] { GetConfig(tmp_filename); },
      "invalid token_uri: uri must be https scheme: invalid");

  write_test_file(fmt::format(minimal_valid_config, "https://foo",
                              "https://bar", "invalid", ""));
  ASSERT_THROWS_STD_RUNTIME_ERROR(
      [this] { GetConfig(tmp_filename); },
      "invalid callback_uri: uri must be https scheme: invalid");

  write_test_file(fmt::format(minimal_valid_config, "https://foo?q=2",
                              "https://bar", "https://baz", ""));
  ASSERT_THROWS_STD_RUNTIME_ERROR([this] { GetConfig(tmp_filename); },
                                  "invalid authorization_uri: query params and "
                                  "fragments not allowed: https://foo?q=2");

  write_test_file(fmt::format(minimal_valid_config, "https://foo#2",
                              "https://bar", "https://baz", ""));
  ASSERT_THROWS_STD_RUNTIME_ERROR([this] { GetConfig(tmp_filename); },
                                  "invalid authorization_uri: query params and "
                                  "fragments not allowed: https://foo#2");

  write_test_file(fmt::format(minimal_valid_config, "https://foo",
                              "https://bar?q=2", "https://baz", ""));
  ASSERT_THROWS_STD_RUNTIME_ERROR([this] { GetConfig(tmp_filename); },
                                  "invalid token_uri: query params and "
                                  "fragments not allowed: https://bar?q=2");

  write_test_file(fmt::format(minimal_valid_config, "https://foo",
                              "https://bar#2", "https://baz", ""));
  ASSERT_THROWS_STD_RUNTIME_ERROR([this] { GetConfig(tmp_filename); },
                                  "invalid token_uri: query params and "
                                  "fragments not allowed: https://bar#2");

  write_test_file(fmt::format(minimal_valid_config, "https://foo",
                              "https://bar", "https://baz?q=2", ""));
  ASSERT_THROWS_STD_RUNTIME_ERROR([this] { GetConfig(tmp_filename); },
                                  "invalid callback_uri: query params and "
                                  "fragments not allowed: https://baz?q=2");

  write_test_file(fmt::format(minimal_valid_config, "https://foo",
                              "https://bar", "https://baz#2", ""));
  ASSERT_THROWS_STD_RUNTIME_ERROR([this] { GetConfig(tmp_filename); },
                                  "invalid callback_uri: query params and "
                                  "fragments not allowed: https://baz#2");

  write_test_file(fmt::format(minimal_valid_config, "https://foo",
                              "https://bar", "https://baz", "https://proxy"));
  ASSERT_THROWS_STD_RUNTIME_ERROR(
      [this] { GetConfig(tmp_filename); },
      "invalid proxy_uri: uri must be http scheme: https://proxy");

  write_test_file(fmt::format(minimal_valid_config, "https://foo",
                              "https://bar", "https://baz", "https://proxy?q"));
  ASSERT_THROWS_STD_RUNTIME_ERROR([this] { GetConfig(tmp_filename); },
                                  "invalid proxy_uri: query params and "
                                  "fragments not allowed: https://proxy?q");
}

TEST_F(GetConfigTest, ValidatesTheUris_WhenThereAreMultipleChains) {
  write_test_file(fmt::format(
      multiple_chains_valid_config, "https://foo1", "https://bar1",
      "https://baz1", "", "https://foo2", "https://bar2", "https://baz2", ""));
  ASSERT_NO_THROW(GetConfig(tmp_filename));

  write_test_file(fmt::format(multiple_chains_valid_config, "https://foo1",
                              "https://bar1", "https://baz1", "http://proxy",
                              "https://foo2", "https://bar2", "https://baz2",
                              "http://proxy"));
  ASSERT_NO_THROW(GetConfig(tmp_filename));

  write_test_file(fmt::format(
      multiple_chains_valid_config, "invalid", "https://bar1", "https://baz1",
      "", "https://foo2", "https://bar2", "https://baz2", ""));
  ASSERT_THROWS_STD_RUNTIME_ERROR(
      [this] { GetConfig(tmp_filename); },
      "invalid authorization_uri: uri must be https scheme: invalid");

  write_test_file(fmt::format(multiple_chains_valid_config, "https://foo1",
                              "https://bar1", "https://baz1", "", "invalid",
                              "https://bar2", "https://baz2", ""));
  ASSERT_THROWS_STD_RUNTIME_ERROR(
      [this] { GetConfig(tmp_filename); },
      "invalid authorization_uri: uri must be https scheme: invalid");

  write_test_file(fmt::format(multiple_chains_valid_config, "https://foo1",
                              "https://bar1", "https://baz1", "",
                              "https://foo2", "invalid", "https://baz2", ""));
  ASSERT_THROWS_STD_RUNTIME_ERROR(
      [this] { GetConfig(tmp_filename); },
      "invalid token_uri: uri must be https scheme: invalid");

  write_test_file(fmt::format(multiple_chains_valid_config, "https://foo1",
                              "https://bar1", "https://baz1", "",
                              "https://foo2", "https://bar2", "invalid", ""));
  ASSERT_THROWS_STD_RUNTIME_ERROR(
      [this] { GetConfig(tmp_filename); },
      "invalid callback_uri: uri must be https scheme: invalid");

  write_test_file(fmt::format(multiple_chains_valid_config, "https://foo1",
                              "https://bar1", "https://baz1", "https://proxy",
                              "https://foo2", "https://bar2", "https://baz2",
                              ""));
  ASSERT_THROWS_STD_RUNTIME_ERROR(
      [this] { GetConfig(tmp_filename); },
      "invalid proxy_uri: uri must be http scheme: https://proxy");

  write_test_file(fmt::format(multiple_chains_valid_config, "https://foo1",
                              "https://bar1", "https://baz1", "",
                              "https://foo2", "https://bar2", "https://baz2",
                              "https://proxy"));
  ASSERT_THROWS_STD_RUNTIME_ERROR(
      [this] { GetConfig(tmp_filename); },
      "invalid proxy_uri: uri must be http scheme: https://proxy");
}

TEST_F(GetConfigTest, OverrideOIDCConfigSuccess) {
  const std::string target_config = R"(
  {
    "listen_address": "127.0.0.1",
    "listen_port": "10003",
    "log_level": "trace",
    "threads": 8,
    "default_oidc_config": {
      "authorization_uri": "https://istio.io/auth/default",
      "token_uri": "https://istio.io/token",
      "jwks": "default_jwk",
      "id_token": {
        "preamble": "Bearer",
        "header": "authorization"
      },
      "client_id": "test-istio",
      "client_secret": "xxxxx-yyyyy-zzzzz"
    },
    "chains": [
      {
        "name": "test-chain",
        "filters": [
          {
            "oidc_override": {
              "jwks": "some-value",
              "callback_uri": "https://ingress/callback",
              "proxy_uri": "http://proxy.io"
            }
          },
          {
            "oidc_override": {
              "jwks": "some-value-2",
              "callback_uri": "https://ingress2/callback",
            }
          },
          {
            "oidc": {
              "authorization_uri": "https://istio.io/auth/default",
              "token_uri": "https://istio.io/token",
              "callback_uri": "https://ingress3/callback",
              "jwks": "default_jwk",
              "id_token": {
                "preamble": "Bearer",
                "header": "Authorization"
              },
              "client_id": "test-istio",
              "client_secret": "xxxxx-yyyyy-zzzzz"
            }
          }
        ]
      }
    ]
  }
  )";
  const std::string expected_config = R"(
  {
    "listen_address": "127.0.0.1",
    "listen_port": "10003",
    "log_level": "trace",
    "threads": 8,
    "chains": [
      {
        "name": "test-chain",
        "filters": [
          {
            "oidc": {
              "authorization_uri": "https://istio.io/auth/default",
              "token_uri": "https://istio.io/token",
              "jwks": "default_jwk",
              "id_token": {
                "preamble": "Bearer",
                "header": "authorization"
              },
              "client_id": "test-istio",
              "client_secret": "xxxxx-yyyyy-zzzzz",
              "jwks": "some-value",
              "callback_uri": "https://ingress/callback",
              "proxy_uri": "http://proxy.io"
            }
          },
          {
            "oidc": {
              "authorization_uri": "https://istio.io/auth/default",
              "token_uri": "https://istio.io/token",
              "jwks": "default_jwk",
              "id_token": {
                "preamble": "Bearer",
                "header": "authorization"
              },
              "client_id": "test-istio",
              "client_secret": "xxxxx-yyyyy-zzzzz",
              "jwks": "some-value-2",
              "callback_uri": "https://ingress2/callback",
            }
          },
          {
            "oidc": {
              "authorization_uri": "https://istio.io/auth/default",
              "token_uri": "https://istio.io/token",
              "callback_uri": "https://ingress3/callback",
              "jwks": "default_jwk",
              "id_token": {
                "preamble": "Bearer",
                "header": "authorization"
              },
              "client_id": "test-istio",
              "client_secret": "xxxxx-yyyyy-zzzzz"
            }
          }
        ]
      }
    ]
  }
  )";

  write_test_file(target_config);
  ASSERT_NO_THROW(GetConfig(tmp_filename));

  config::Config expected_config_msg;
  google::protobuf::util::JsonStringToMessage(expected_config,
                                              &expected_config_msg);
  auto loaded_config = GetConfig(tmp_filename);
  EXPECT_EQ(expected_config_msg.DebugString(), loaded_config->DebugString());
}

TEST_F(GetConfigTest, OverrideOIDCConfigFailedWithInvalidUsage) {
  const std::string target_config = R"(
  {
    "listen_address": "127.0.0.1",
    "listen_port": "10003",
    "log_level": "trace",
    "threads": 8,
    "default_oidc_config": {
      "authorization_uri": "https://istio.io/auth/default",
      "token_uri": "https://istio.io/token",
      "jwks": "default_jwk",
      "id_token": {
        "preamble": "Bearer",
        "header": "authorization"
      },
      "client_id": "test-istio",
      "client_secret": "xxxxx-yyyyy-zzzzz"
    },
    "chains": [
      {
        "name": "test-chain",
        "filters": [
          {
            "oidc": {
              "jwks": "some-value",
              "callback_uri": "https://myself/callback",
              "proxy_uri": "http://proxy.io"
            }
          }
        ]
      }
    ]
  }
  )";

  write_test_file(target_config);
  EXPECT_THROW(GetConfig(tmp_filename), std::runtime_error);
}

TEST_F(GetConfigTest, OverrideOIDCConfigFailedWithMissingRequiredField) {
  const std::string target_config = R"(
  {
    "listen_address": "127.0.0.1",
    "listen_port": "10003",
    "log_level": "trace",
    "threads": 8,
    "default_oidc_config": {
      "authorization_uri": "https://istio.io/auth/default",
      "jwks": "default_jwk",
      "id_token": {
        "preamble": "Bearer",
        "header": "authorization"
      },
      "client_id": "test-istio",
      "client_secret": "xxxxx-yyyyy-zzzzz"
    },
    "chains": [
      {
        "name": "test-chain",
        "filters": [
          {
            "oidc_override": {
              "jwks": "some-value",
              "callback_uri": "https://myself/callback",
              "proxy_uri": "http://proxy.io"
            }
          }
        ]
      }
    ]
  }
  )";

  write_test_file(target_config);
  EXPECT_THROW(GetConfig(tmp_filename), std::runtime_error);
}

}  // namespace config
}  // namespace authservice
