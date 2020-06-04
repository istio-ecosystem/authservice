#include "src/filters/filter_chain.h"
#include "gtest/gtest.h"
#include "src/filters/pipe.h"
#include "redis.h"
#include "src/filters/oidc/redis_wrapper.h"

namespace authservice {
namespace filters {

TEST(FilterChainTest, Name) {
  auto configuration = std::unique_ptr<config::FilterChain>(new config::FilterChain);
  configuration->set_name("expected");
  FilterChainImpl chain1(*configuration);
  ASSERT_EQ(chain1.Name(), "expected");
}

TEST(FilterChainTest, MatchesWithoutMatchField) {
  auto configuration = std::unique_ptr<config::FilterChain>(new config::FilterChain);
  ::envoy::service::auth::v2::CheckRequest request1;
  FilterChainImpl chain1(*configuration);
  ASSERT_TRUE(chain1.Matches(&request1));
}

TEST(FilterChainTest, MatchesPrefix) {
  auto configuration = std::unique_ptr<config::FilterChain>(new config::FilterChain);
  configuration->mutable_match()->set_header("x-prefix-header");
  configuration->mutable_match()->set_prefix("prefixed-");

  // invalid prefix case
  ::envoy::service::auth::v2::CheckRequest request1;
  auto headers1 = request1.mutable_attributes()->mutable_request()->mutable_http()->mutable_headers();
  headers1->insert({"x-prefix-header", "not-prefixed-value"});
  FilterChainImpl chain1(*configuration);
  ASSERT_FALSE(chain1.Matches(&request1));

  // valid prefix case
  ::envoy::service::auth::v2::CheckRequest request2;
  auto headers2 = request2.mutable_attributes()->mutable_request()->mutable_http()->mutable_headers();
  headers2->insert({"x-prefix-header", "prefixed-value"});
  FilterChainImpl chain2(*configuration);
  ASSERT_TRUE(chain2.Matches(&request2));
}

TEST(FilterChainTest, MatchesEquality) {
  auto configuration = std::unique_ptr<config::FilterChain>(new config::FilterChain);
  configuration->mutable_match()->set_header("x-equality-header");
  configuration->mutable_match()->set_equality("exact-value");

  // invalid header value case
  ::envoy::service::auth::v2::CheckRequest request1;
  auto headers1 = request1.mutable_attributes()->mutable_request()->mutable_http()->mutable_headers();
  headers1->insert({"x-equality-header", "not-an-exact-value"});
  FilterChainImpl chain1(*configuration);
  ASSERT_FALSE(chain1.Matches(&request1));

  // valid header value case
  ::envoy::service::auth::v2::CheckRequest request2;
  auto headers2 = request2.mutable_attributes()->mutable_request()->mutable_http()->mutable_headers();
  headers2->insert({"x-equality-header", "exact-value"});
  FilterChainImpl chain2(*configuration);
  ASSERT_TRUE(chain2.Matches(&request2));
}

TEST(FilterChainTest, New) {
  auto configuration = std::unique_ptr<config::FilterChain>(new config::FilterChain);
  auto filter_config = configuration->mutable_filters()->Add();
  filter_config->mutable_oidc()->set_jwks("some-value");

  FilterChainImpl chain(*configuration);
  auto instance = chain.New();
  ASSERT_TRUE(dynamic_cast<Pipe *>(instance.get()) != nullptr);
}

TEST(FilterChainTest, RedisPlusPlus) {
  using namespace sw::redis;
  google::jwt_verify::Jwt id_token_jwt;
  auto jwt_status = id_token_jwt.parseFromString(
      "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMiwiYXVkIjpbImNsaWVudDEiXSwibm9uY2UiOiJyYW5kb20ifQ.NQi_VTRjZ8jv5cAp4inpuQ9STfVgCoWfONjLnZEMk8la8s99J9b6QmcKtO2tabTgvcseikVNlPuB6fZztY_fxhdrNE0dBNAl1lhz_AWBz6Yr-D82LLKk5NQ-IKDloF19Pic0Ub9pGCqNLOlmRXRVcfwwq5nISzfP6OdrjepRZ2Jd3rc2HvHYm-6GstH4xkKViABVwCDmwlAOi47bdHPByHkZOOnHSQEElr4tqO_uAQRpj36Yvt-95nPKhWaufZhcpYKk1H7ZRmylJQuG_dhlw4gN1i5iWBMk-Sj_2xyk05Bap1qkKSeHTxyqzhtDAH0LHYZdo_2hU-7YnL4JRhVVwg");
  ASSERT_EQ(jwt_status, google::jwt_verify::Status::Ok);
//  auto redis = Redis("tcp://127.0.0.1:6379");
  auto redis_wrapper = oidc::RedisWrapper(std::make_shared<Redis>("tcp://127.0.0.1:6379"));
  auto token_response = std::make_shared<oidc::TokenResponse>(id_token_jwt);

  redis_wrapper.del("session_id");

  redis_wrapper.hset("session_id", "id_token", std::string(token_response->IDToken().jwt_));
//  redis_wrapper.hset("session_id", "access_token", *token_response->AccessToken());
//  redis_wrapper.hset("session_id", "refresh_token", *token_response->RefreshToken());
//  redis_wrapper.hset("session_id", "access_token_expiry", std::to_string(*token_response->GetAccessTokenExpiry()));
//
//  auto storedAccessToken = redis_wrapper.hget("session_id", "access_token");
//  ASSERT_FALSE(storedAccessToken);
//  //ASSERT_EQ(redis_wrapper.hget("session_id", "refresh_token").value(), sw::redis::OptionalString().value());
//  //ASSERT_EQ(redis_wrapper.hget("session_id", "access_token_expiry").value(), sw::redis::OptionalString().value());
}

}  // namespace filters
}  // namespace authservice