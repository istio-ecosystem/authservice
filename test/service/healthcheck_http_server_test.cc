#include "src/service/healthcheck_http_server.h"

#include <memory>

#include "boost/asio/io_context.hpp"
#include "boost/asio/ip/tcp.hpp"
#include "boost/asio/spawn.hpp"
#include "config/config.pb.h"
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

class Runner {
 public:
  void addChain(std::unique_ptr<config::FilterChain> config,
                google::jwt_verify::JwksPtr jwks) {
    auto chain = std::make_unique<filters::FilterChainImpl>(ioc_, *config, 1);
    jwks_ = std::move(jwks);
    auto mock_resolver = std::make_shared<filters::oidc::MockJwksResolver>();
    EXPECT_CALL(*mock_resolver, jwks()).WillOnce(ReturnRef(jwks_));

    auto resolver_cache =
        std::make_unique<filters::oidc::MockJwksResolverCache>();
    EXPECT_CALL(*resolver_cache, getResolver()).WillOnce(Return(mock_resolver));

    chain->setJwksResolverCacheForTest(std::move(resolver_cache));
    chains_.push_back(std::move(chain));
  }

  int start() {
    server_ =
        std::make_unique<HealthcheckAsyncServer>(ioc_, chains_, "0.0.0.0", 0);
    server_->startAccept();
    work_ = std::make_unique<boost::asio::io_context::work>(ioc_);
    th_ = std::thread([&] { ioc_.run(); });
    return server_->getPort();
  }

  void stop() {
    work_.reset();
    ioc_.stop();
    server_.reset();
    th_.join();
  }

 private:
  std::thread th_;
  boost::asio::io_context ioc_;
  std::unique_ptr<HealthcheckAsyncServer> server_;
  std::unique_ptr<boost::asio::io_context::work> work_;
  std::vector<std::unique_ptr<filters::FilterChain>> chains_;
  google::jwt_verify::JwksPtr jwks_;
};

TEST(TestHealthCheckHttpServer, BasicFlowWithInactiveJwks) {
  Runner runner;
  runner.addChain(std::make_unique<config::FilterChain>(),
                  google::jwt_verify::JwksPtr());
  const auto port = runner.start();
  auto http_ptr = common::http::ptr_t(new common::http::HttpImpl);

  boost::asio::io_context ioc;
  boost::asio::spawn(ioc, [&](boost::asio::yield_context yield) {
    auto res = http_ptr->SimpleGet(
        fmt::format("http://0.0.0.0:{}/healthz", port), {}, "", ioc, yield);
    EXPECT_EQ(res->result(), boost::beast::http::status::not_found);
  });

  ioc.run();
  runner.stop();
}

TEST(TestHealthCheckHttpServer, BasicFlowWithActiveJwks) {
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

  Runner runner;
  runner.addChain(std::make_unique<config::FilterChain>(), std::move(jwks));
  const auto port = runner.start();
  auto http_ptr = common::http::ptr_t(new common::http::HttpImpl);

  boost::asio::io_context ioc;
  boost::asio::spawn(ioc, [&](boost::asio::yield_context yield) {
    auto res = http_ptr->SimpleGet(
        fmt::format("http://0.0.0.0:{}/healthz", port), {}, "", ioc, yield);
    EXPECT_EQ(res->result(), boost::beast::http::status::ok);
  });

  ioc.run();
  runner.stop();
}

}  // namespace service
}  // namespace authservice
