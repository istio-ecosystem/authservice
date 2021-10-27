#include "src/service/healthcheck_http_server.h"

#include <memory>

#include "boost/asio/io_context.hpp"
#include "boost/asio/ip/tcp.hpp"
#include "boost/asio/spawn.hpp"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "src/common/http/http.h"
#include "src/config/get_config.h"
#include "src/filters/filter_chain.h"
#include "test/filters/oidc/mocks.h"

namespace authservice {
namespace service {

using testing::_;
using testing::Return;
using testing::ReturnRef;

TEST(TestHealthCheckHttpServer, BasicFlowWithInactiveJwks) {
  boost::asio::io_context io_context;

  auto configuration = std::make_unique<config::FilterChain>();
  auto chain =
      std::make_unique<filters::FilterChainImpl>(io_context, *configuration, 1);

  auto mock_resolver = std::make_shared<filters::oidc::MockJwksResolver>();
  google::jwt_verify::JwksPtr dangling_jwks;
  EXPECT_CALL(*mock_resolver, jwks())
      .Times(2)
      .WillRepeatedly(ReturnRef(dangling_jwks));

  auto resolver_cache =
      std::make_unique<filters::oidc::MockJwksResolverCache>();
  EXPECT_CALL(*resolver_cache, getResolver())
      .Times(2)
      .WillRepeatedly(Return(mock_resolver));

  chain->setJwksResolverCacheForTest(std::move(resolver_cache));
  EXPECT_FALSE(chain->jwksActive());

  std::vector<std::unique_ptr<filters::FilterChain>> chains;
  chains.push_back(std::move(chain));

  HealthcheckAsyncServer server(chains, "0.0.0.0", 0);

  auto http_ptr = common::http::ptr_t(new common::http::HttpImpl);

  boost::asio::spawn(io_context, [&](boost::asio::yield_context yield) {
    auto res = http_ptr->SimpleGet(
        fmt::format("http://0.0.0.0:{}/healthz", server.getPort()), {}, "",
        io_context, yield);
    EXPECT_EQ(res->result(), boost::beast::http::status::not_found);
  });

  io_context.run();
}

TEST(TestHealthCheckHttpServer, BasicFlowWithActiveJwks) {
  boost::asio::io_context io_context;

  auto configuration = std::make_unique<config::FilterChain>();
  auto chain =
      std::make_unique<filters::FilterChainImpl>(io_context, *configuration, 1);

  auto mock_resolver = std::make_shared<filters::oidc::MockJwksResolver>();

  std::string valid_jwks = R"(
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
  auto jwks = google::jwt_verify::Jwks::createFrom(
      valid_jwks, google::jwt_verify::Jwks::JWKS);

  EXPECT_CALL(*mock_resolver, jwks()).Times(2).WillRepeatedly(ReturnRef(jwks));

  auto resolver_cache =
      std::make_unique<filters::oidc::MockJwksResolverCache>();
  EXPECT_CALL(*resolver_cache, getResolver())
      .Times(2)
      .WillRepeatedly(Return(mock_resolver));

  chain->setJwksResolverCacheForTest(std::move(resolver_cache));
  EXPECT_TRUE(chain->jwksActive());

  std::vector<std::unique_ptr<filters::FilterChain>> chains;
  chains.push_back(std::move(chain));

  HealthcheckAsyncServer server(chains, "0.0.0.0", 0);

  auto http_ptr = common::http::ptr_t(new common::http::HttpImpl);

  boost::asio::spawn(io_context, [&](boost::asio::yield_context yield) {
    auto res = http_ptr->SimpleGet(
        fmt::format("http://0.0.0.0:{}/healthz", server.getPort()), {}, "",
        io_context, yield);
    EXPECT_EQ(res->result(), boost::beast::http::status::ok);
  });

  io_context.run();
}

}  // namespace service
}  // namespace authservice
