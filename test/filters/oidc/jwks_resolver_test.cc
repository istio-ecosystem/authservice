#include "src/filters/oidc/jwks_resolver.h"

#include <memory>

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

const char *invalid_jwt_public_key_ =
    "MIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSvvkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdV"
    "ha4s38XM/pa/yr47av7+z3VTmvDRyAHcaT92whREFpLv9cj5lTeJSibyr/Mrm/Yt"
    "jCZVWgaOYIhwrXwKLqPr/11inWsAkfIytvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwz"
    "GTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0e+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1"
    "FtGJiJvOwRsIfVChDpYStTcHTCMqtvWbV6L11BWkpAGXSW4Hv43qa+GSYOD2QU68"
    "Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9MwIDAQAB";

using testing::_;
using testing::Eq;
using testing::Invoke;

TEST(JwksResolverTest, TestStaticJwksResolver) {
  StaticJwksResolverImpl storage(valid_jwt_public_key_,
                                 google::jwt_verify::Jwks::JWKS);
  EXPECT_EQ(google::jwt_verify::Status::Ok, storage.jwks()->getStatus());

  StaticJwksResolverImpl storage2(invalid_jwt_public_key_,
                                  google::jwt_verify::Jwks::JWKS);
  EXPECT_NE(google::jwt_verify::Status::Ok, storage2.jwks()->getStatus());
}

TEST(JwksResolverTest, TestDynamicJwksResolver) {
  boost::asio::io_context io_context;
  auto mock_http = std::make_shared<common::http::HttpMock>();
  DynamicJwksResolverImpl storage("istio.io", std::chrono::seconds(1),
                                  mock_http, io_context);
  storage.updateJwks(valid_jwt_public_key_, google::jwt_verify::Jwks::JWKS);
  EXPECT_EQ(google::jwt_verify::Status::Ok, storage.jwks()->getStatus());

  EXPECT_CALL(*mock_http, Get(Eq("istio.io"), _, _, _, _, _, _))
      .Times(5)  // 5 sec to run event loop
      .WillRepeatedly(
          Invoke([](absl::string_view,
                    const std::map<absl::string_view, absl::string_view>,
                    absl::string_view, absl::string_view, absl::string_view,
                    boost::asio::io_context &, boost::asio::yield_context) {
            common::http::response_t response = std::make_unique<
                beast::http::response<beast::http::string_body>>();
            response->body() = invalid_jwt_public_key_;
            return response;
          }));

  // 5 sec is enough to wait 1 sec interval to wait new JWKs.
  io_context.run_for(std::chrono::seconds(5));

  // update key
  EXPECT_NE(google::jwt_verify::Status::Ok, storage.jwks()->getStatus());
}

}  // namespace
}  // namespace oidc
}  // namespace filters
}  // namespace authservice
