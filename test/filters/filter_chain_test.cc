#include "src/filters/filter_chain.h"

#include "boost/asio/io_context.hpp"
#include "config/oidc/config.pb.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "src/filters/pipe.h"
#include "test/filters/oidc/mocks.h"

namespace authservice {
namespace filters {

using testing::Return;
using testing::ReturnRef;

boost::asio::io_context io_context;

TEST(FilterChainTest, Name) {
  auto configuration =
      std::unique_ptr<config::FilterChain>(new config::FilterChain);
  configuration->set_name("expected");
  FilterChainImpl chain1(io_context, *configuration, 1);
  ASSERT_EQ(chain1.Name(), "expected");
}

TEST(FilterChainTest, MatchesWithoutMatchField) {
  auto configuration =
      std::unique_ptr<config::FilterChain>(new config::FilterChain);
  ::envoy::service::auth::v3::CheckRequest request1;
  FilterChainImpl chain1(io_context, *configuration, 1);
  ASSERT_TRUE(chain1.Matches(&request1));
}

TEST(FilterChainTest, MatchesPrefix) {
  auto configuration =
      std::unique_ptr<config::FilterChain>(new config::FilterChain);
  configuration->mutable_match()->set_header("x-prefix-header");
  configuration->mutable_match()->set_prefix("prefixed-");

  // invalid prefix case
  ::envoy::service::auth::v3::CheckRequest request1;
  auto headers1 = request1.mutable_attributes()
                      ->mutable_request()
                      ->mutable_http()
                      ->mutable_headers();
  headers1->insert({"x-prefix-header", "not-prefixed-value"});
  FilterChainImpl chain1(io_context, *configuration, 1);
  ASSERT_FALSE(chain1.Matches(&request1));

  // valid prefix case
  ::envoy::service::auth::v3::CheckRequest request2;
  auto headers2 = request2.mutable_attributes()
                      ->mutable_request()
                      ->mutable_http()
                      ->mutable_headers();
  headers2->insert({"x-prefix-header", "prefixed-value"});
  FilterChainImpl chain2(io_context, *configuration, 1);
  ASSERT_TRUE(chain2.Matches(&request2));
}

TEST(FilterChainTest, MatchesEquality) {
  auto configuration =
      std::unique_ptr<config::FilterChain>(new config::FilterChain);
  configuration->mutable_match()->set_header("x-equality-header");
  configuration->mutable_match()->set_equality("exact-value");

  // invalid header value case
  ::envoy::service::auth::v3::CheckRequest request1;
  auto headers1 = request1.mutable_attributes()
                      ->mutable_request()
                      ->mutable_http()
                      ->mutable_headers();
  headers1->insert({"x-equality-header", "not-an-exact-value"});
  FilterChainImpl chain1(io_context, *configuration, 1);
  ASSERT_FALSE(chain1.Matches(&request1));

  // valid header value case
  ::envoy::service::auth::v3::CheckRequest request2;
  auto headers2 = request2.mutable_attributes()
                      ->mutable_request()
                      ->mutable_http()
                      ->mutable_headers();
  headers2->insert({"x-equality-header", "exact-value"});
  FilterChainImpl chain2(io_context, *configuration, 1);
  ASSERT_TRUE(chain2.Matches(&request2));
}

TEST(FilterChainTest, New) {
  auto configuration =
      std::unique_ptr<config::FilterChain>(new config::FilterChain);
  auto filter_config = configuration->mutable_filters()->Add();
  filter_config->mutable_oidc()->set_jwks("some-value");

  FilterChainImpl chain(io_context, *configuration, 1);
  auto instance = chain.New();
  ASSERT_TRUE(dynamic_cast<Pipe *>(instance.get()) != nullptr);
}

TEST(FilterChainTest, MockFilter) {
  auto configuration = std::make_unique<config::FilterChain>();
  auto filter_config = configuration->mutable_filters()->Add();
  filter_config->mutable_mock()->set_allow(true);

  FilterChainImpl chain(io_context, *configuration, 1);
  auto instance = chain.New();
  ASSERT_TRUE(dynamic_cast<Pipe *>(instance.get()) != nullptr);
}

TEST(FilterChainTest, CheckJwks) {
  auto configuration = std::make_unique<config::FilterChain>();
  FilterChainImpl chain(io_context, *configuration, 1);

  auto mock_resolver = std::make_shared<oidc::MockJwksResolver>();
  google::jwt_verify::JwksPtr dangling_jwks;
  EXPECT_CALL(*mock_resolver, jwks()).WillOnce(ReturnRef(dangling_jwks));

  auto resolver_cache = std::make_unique<oidc::MockJwksResolverCache>();
  EXPECT_CALL(*resolver_cache, getResolver()).WillOnce(Return(mock_resolver));

  chain.setJwksResolverCacheForTest(std::move(resolver_cache));
  EXPECT_FALSE(chain.jwksActive());

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
  auto jwks2 = google::jwt_verify::Jwks::createFrom(
      valid_jwks, google::jwt_verify::Jwks::JWKS);
  auto mock_resolver2 = std::make_shared<oidc::MockJwksResolver>();
  EXPECT_CALL(*mock_resolver2, jwks()).WillOnce(ReturnRef(jwks2));

  auto resolver_cache2 = std::make_unique<oidc::MockJwksResolverCache>();
  EXPECT_CALL(*resolver_cache2, getResolver()).WillOnce(Return(mock_resolver2));

  chain.setJwksResolverCacheForTest(std::move(resolver_cache2));
  EXPECT_TRUE(chain.jwksActive());
}

}  // namespace filters
}  // namespace authservice
