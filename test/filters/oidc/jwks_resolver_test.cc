#include "src/filters/oidc/jwks_resolver.h"

#include <chrono>
#include <memory>
#include <string_view>

#include "gtest/gtest.h"
#include "test/common/http/mocks.h"

namespace authservice {
namespace filters {
namespace oidc {

namespace {
// A valid public JWK key for JWT verification.
const char valid_jwt_public_key_[] = R"(
{
  "keys": [
    {
      "kty": "RSA",
      "alg": "RS256",
      "use": "sig",
      "kid": "62a93512c9ee4c7f8067b5a216dade2763d32a47",
      "n":
      "up97uqrF9MWOPaPkwSaBeuAPLOr9FKcaWGdVEGzQ4f3Zq5WKVZowx9TCBxmImNJ1qmUi13pB8otwM_l5lfY1AFBMxVbQCUXntLovhDaiSvYp4wGDjFzQiYA-pUq8h6MUZBnhleYrkU7XlCBwNVyN8qNMkpLA7KFZYz-486GnV2NIJJx_4BGa3HdKwQGxi2tjuQsQvao5W4xmSVaaEWopBwMy2QmlhSFQuPUpTaywTqUcUq_6SfAHhZ4IDa_FxEd2c2z8gFGtfst9cY3lRYf-c_ZdboY3mqN9Su3-j3z5r2SHWlhB_LNAjyWlBGsvbGPlTqDziYQwZN4aGsqVKQb9Vw",
      "e": "AQAB"
    },
    {
      "kty": "RSA",
      "alg": "RS256",
      "use": "sig",
      "kid": "b3319a147514df7ee5e4bcdee51350cc890cc89e",
      "n":
      "up97uqrF9MWOPaPkwSaBeuAPLOr9FKcaWGdVEGzQ4f3Zq5WKVZowx9TCBxmImNJ1qmUi13pB8otwM_l5lfY1AFBMxVbQCUXntLovhDaiSvYp4wGDjFzQiYA-pUq8h6MUZBnhleYrkU7XlCBwNVyN8qNMkpLA7KFZYz-486GnV2NIJJx_4BGa3HdKwQGxi2tjuQsQvao5W4xmSVaaEWopBwMy2QmlhSFQuPUpTaywTqUcUq_6SfAHhZ4IDa_FxEd2c2z8gFGtfst9cY3lRYf-c_ZdboY3mqN9Su3-j3z5r2SHWlhB_LNAjyWlBGsvbGPlTqDziYQwZN4aGsqVKQb9Vw",
      "e": "AQAB"
    }
  ]
}
)";

const char valid_jwt_public_key2_[] = R"(
{
  "keys": [
    {
      "kty": "RSA",
      "n": "xkgm0jU0J7SgrmmuLypjWO6J9MlF9vpRpsw84sme4EtWMUyAu4zT-X9Ten5wB9W2z0Gft5QOmFL99ueP3MeOqZsXGwW2UWVuQCpkD0bo4qDDqwbt8Cl31Qjb5RHeuvmwYpNQK_1ppb6dwlUCA2Y9AaE7UsZITlR7r5XiBNvOEZh0LTsjPcikCheAs6nPSMBbdIeM28vii1PgPYTU6x6dRBVBAExaRnRDPZZh4acgfKIpbOCMJm2tucqwYhx3Wr5Lhu56oZALK4lvP9SAgOZdG3BA48PKIdLOeiTP-DI_pHJhIn1N5lMCcmcpG3OKMvWo0tFMOGj8Or-mHqB_5I-L4w==",
      "e": "AQAB",
      "use": "sig",
      "alg": "RS256",
      "kid": "6ef4bd908591f697a8a9b893b03e6a77eb04e51f"
    },
    {
      "alg": "RS256",
      "use": "sig",
      "kty": "RSA",
      "kid": "819d1e61429dd3d3caef129c0ac2bae8c6d46fbc",
      "e": "AQAB",
      "n": "qfR12Bcs_hSL0Y1fN5TYZeUQIFmuVRYa210na81BFj91xxwtICJY6ckZCI3Jf0v2tPLOT_iKVk4WBCZ7AVJVvZqHuttkyrdFROMVTe6DwmcjbbkgACMVildTnHy9xy2KuX-OZsEYzgHuRgfe_Y-JN6LoxBYZx6VoBLpgK-F0Q-0O_bRgZhHifVG4ZzARjhgz0PvBb700GtOTHS6mQIfToPErbgqcowKN9k-mJqJr8xpXSHils-Yw97LHjICZmvA5B8EPNW28DwFOE5JrsPcyrFKOAYl4NcSYQgjl-17TWE5_tFdZ8Lz-srjiPMoHlBjZD1C7aO03LI-_9u8lVsktMw=="
    }
  ]
}
)";

const char invalid_jwt_public_key_[] = R"(
  {
      "keys": [
        {
           "kty": "XYZ",
           "crv": "P-256",
           "x": "test",
           "y": "test",
           "alg": "test",
           "kid": "test"
        }
     ]
   }
)";

using testing::_;
using testing::Eq;
using testing::Invoke;

TEST(JwksResolverTest, TestStaticJwksResolver) {
  StaticJwksResolverImpl resolver(valid_jwt_public_key_);
  EXPECT_EQ(google::jwt_verify::Status::Ok, resolver.jwks()->getStatus());

  EXPECT_THROW(
      [] { StaticJwksResolverImpl resolver2(invalid_jwt_public_key_); }(),
      std::runtime_error);
}

void setExpectedRemoteJwks(common::http::HttpMock& mock_http,
                           const char jwks[]) {
  EXPECT_CALL(mock_http, Get(Eq("istio.io"), _, _, _, _, _, _))
      .WillRepeatedly(Invoke([jwks](absl::string_view,
                                    const std::map<absl::string_view,
                                                   absl::string_view>,
                                    absl::string_view,
                                    const common::http::TransportSocketOptions&,
                                    absl::string_view, boost::asio::io_context&,
                                    boost::asio::yield_context) {
        common::http::response_t response =
            std::make_unique<beast::http::response<beast::http::string_body>>();
        response->body() = jwks;
        return response;
      }));
}

TEST(JwksResolverTest, TestDynamicJwksResolver) {
  boost::asio::io_context io_context;
  auto mock_http = std::make_shared<common::http::HttpMock>();
  config::oidc::OIDCConfig::JwksFetcherConfig config;
  config.set_jwks_uri("istio.io");
  config.set_periodic_fetch_interval_sec(1);
  DynamicJwksResolverImpl resolver(config, mock_http, io_context);

  // First flight to extract invalid JWKs.
  setExpectedRemoteJwks(*mock_http, invalid_jwt_public_key_);
  io_context.run_for(std::chrono::seconds(3));
  EXPECT_EQ(nullptr, resolver.jwks());

  // Second flight to extract valid JWKs. It will update existing invalid
  // JWKs
  setExpectedRemoteJwks(*mock_http, valid_jwt_public_key_);
  io_context.run_for(std::chrono::seconds(3));
  EXPECT_EQ(google::jwt_verify::Status::Ok, resolver.jwks()->getStatus());
  EXPECT_EQ(valid_jwt_public_key_, resolver.rawStringJwks());

  // Third flight to extract invalid JWKs. And JWKs not updated.
  setExpectedRemoteJwks(*mock_http, invalid_jwt_public_key_);
  io_context.run_for(std::chrono::seconds(3));
  EXPECT_EQ(google::jwt_verify::Status::Ok, resolver.jwks()->getStatus());
  EXPECT_EQ(valid_jwt_public_key_, resolver.rawStringJwks());

  // Forth flight to update valid JWKs. It will update existing valid JWKS.
  setExpectedRemoteJwks(*mock_http, valid_jwt_public_key2_);
  io_context.run_for(std::chrono::seconds(3));
  EXPECT_EQ(google::jwt_verify::Status::Ok, resolver.jwks()->getStatus());
  EXPECT_EQ(valid_jwt_public_key2_, resolver.rawStringJwks());
}

TEST(JwksResolverTest, TestDynamicJwksResolverWithInvalidHttpStatus) {
  boost::asio::io_context io_context;
  auto mock_http = std::make_shared<common::http::HttpMock>();
  config::oidc::OIDCConfig::JwksFetcherConfig config;
  config.set_jwks_uri("istio.io");
  config.set_periodic_fetch_interval_sec(1);

  DynamicJwksResolverImpl resolver(config, mock_http, io_context);

  // Never initialized with invalid HTTP status.
  EXPECT_CALL(*mock_http, Get(Eq("istio.io"), _, _, _, _, _, _))
      .WillRepeatedly(Invoke([](absl::string_view,
                                const std::map<absl::string_view,
                                               absl::string_view>,
                                absl::string_view,
                                const common::http::TransportSocketOptions&,
                                absl::string_view, boost::asio::io_context&,
                                boost::asio::yield_context) {
        common::http::response_t response =
            std::make_unique<beast::http::response<beast::http::string_body>>();
        response->result(503);
        return response;
      }));
  io_context.run_for(std::chrono::seconds(3));
  EXPECT_EQ(nullptr, resolver.jwks());
}

TEST(JwksResolverTest,
     TestDynamicJwksResolverRequestBy3SecIntervalUntilJwksConfigured) {
  boost::asio::io_context io_context;
  auto mock_http = std::make_shared<common::http::HttpMock>();

  // Configured request interval as 10000 sec. This value is enough to guarantee
  // that second request will not be invoked for 3 sec evloop run.
  config::oidc::OIDCConfig::JwksFetcherConfig config;
  config.set_jwks_uri("istio.io");
  config.set_periodic_fetch_interval_sec(10000);

  DynamicJwksResolverImpl resolver(config, mock_http, io_context);

  // Initially make mock server always return invalid HTTP response as 503.
  EXPECT_CALL(*mock_http, Get(Eq("istio.io"), _, _, _, _, _, _))
      .WillRepeatedly(Invoke([](absl::string_view,
                                const std::map<absl::string_view,
                                               absl::string_view>,
                                absl::string_view,
                                const common::http::TransportSocketOptions&,
                                absl::string_view, boost::asio::io_context&,
                                boost::asio::yield_context) {
        common::http::response_t response =
            std::make_unique<beast::http::response<beast::http::string_body>>();
        response->result(503);
        return response;
      }));

  io_context.run_for(std::chrono::seconds(4));
  EXPECT_EQ(nullptr, resolver.jwks());

  // Called successful request after 4 sec.
  setExpectedRemoteJwks(*mock_http, valid_jwt_public_key_);
  io_context.run_for(std::chrono::seconds(4));
  EXPECT_EQ(google::jwt_verify::Status::Ok, resolver.jwks()->getStatus());
  EXPECT_EQ(valid_jwt_public_key_, resolver.rawStringJwks());
}

}  // namespace
}  // namespace oidc
}  // namespace filters
}  // namespace authservice
