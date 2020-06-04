#include <thread>
#include <include/gmock/gmock-actions.h>
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "src/filters/oidc/redis_session_store.h"
#include "test/common/utilities/mocks.h"
#include "test/filters/oidc/mocks.h"
#include <string>

namespace authservice {
namespace filters {
namespace oidc {

using ::testing::Return;
using ::testing::Eq;

class RedisSessionStoreTest : public ::testing::Test {
protected:
  google::jwt_verify::Jwt id_token_jwt;
  std::shared_ptr<common::utilities::TimeServiceMock> time_service_mock_;
  std::shared_ptr<RedisWrapperMock> redis_wrapper_mock_;

  void SetUp() override {
    auto jwt_status = id_token_jwt.parseFromString(
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMiwiYXVkIjpbImNsaWVudDEiXSwibm9uY2UiOiJyYW5kb20ifQ.NQi_VTRjZ8jv5cAp4inpuQ9STfVgCoWfONjLnZEMk8la8s99J9b6QmcKtO2tabTgvcseikVNlPuB6fZztY_fxhdrNE0dBNAl1lhz_AWBz6Yr-D82LLKk5NQ-IKDloF19Pic0Ub9pGCqNLOlmRXRVcfwwq5nISzfP6OdrjepRZ2Jd3rc2HvHYm-6GstH4xkKViABVwCDmwlAOi47bdHPByHkZOOnHSQEElr4tqO_uAQRpj36Yvt-95nPKhWaufZhcpYKk1H7ZRmylJQuG_dhlw4gN1i5iWBMk-Sj_2xyk05Bap1qkKSeHTxyqzhtDAH0LHYZdo_2hU-7YnL4JRhVVwg");
    ASSERT_EQ(jwt_status, google::jwt_verify::Status::Ok);

    time_service_mock_ = std::make_shared<testing::NiceMock<common::utilities::TimeServiceMock>>();
    redis_wrapper_mock_ = std::make_shared<RedisWrapperMock>();
  }

  std::shared_ptr<TokenResponse> CreateTokenResponse();
};

std::shared_ptr<TokenResponse> RedisSessionStoreTest::CreateTokenResponse() {
  auto token_response = std::make_shared<TokenResponse>(id_token_jwt);
  token_response->SetRefreshToken("fake_refresh_token");
  token_response->SetAccessToken("fake_access_token");
  token_response->SetAccessTokenExpiry(42);
  return token_response;
}

TEST_F(RedisSessionStoreTest, GetTokenResponse_WhenNoTokenResponsePresent) {
  RedisSessionStore redis_session_store(time_service_mock_, 42, 128, redis_wrapper_mock_);
  auto session_id = std::string("fake_session_id");
  auto token_response = CreateTokenResponse();

  EXPECT_CALL(*redis_wrapper_mock_,
              hexists(absl::string_view("fake_session_id"), absl::string_view("id_token"))).WillOnce(Return(false));

  auto result = redis_session_store.GetTokenResponse(session_id);
  ASSERT_FALSE(result);
}

TEST_F(RedisSessionStoreTest, GetTokenResponse_WhenIdTokenCannotBeParsed) {
  RedisSessionStore redis_session_store(time_service_mock_, 42, 128, redis_wrapper_mock_);
  auto session_id = std::string("fake_session_id");
  EXPECT_CALL(*redis_wrapper_mock_,
              hexists(absl::string_view("fake_session_id"), absl::string_view("id_token"))).WillOnce(Return(true));
  EXPECT_CALL(*redis_wrapper_mock_,
              hget(absl::string_view("fake_session_id"), absl::string_view("id_token"))).WillOnce(Return("garbage"));

  auto result = redis_session_store.GetTokenResponse(session_id);
  ASSERT_FALSE(result);
}


TEST_F(RedisSessionStoreTest, GetTokenResponse_WhenOnlyIdTokenIsPresent) {
  int absolute_timeout_in_seconds = 128;
  int idle_timeout_in_seconds = 42;
  RedisSessionStore redis_session_store(time_service_mock_, absolute_timeout_in_seconds,
                                        idle_timeout_in_seconds, redis_wrapper_mock_);
  auto session_id = std::string("fake_session_id");
  auto token_response = std::make_shared<oidc::TokenResponse>(id_token_jwt);

  EXPECT_CALL(*redis_wrapper_mock_,
              hexists(absl::string_view("fake_session_id"), absl::string_view("id_token"))).WillOnce(Return(true));
  EXPECT_CALL(*redis_wrapper_mock_,
              hget(absl::string_view("fake_session_id"), absl::string_view("id_token"))).WillOnce(Return(token_response->IDToken().jwt_));
  EXPECT_CALL(*redis_wrapper_mock_,
              hget(absl::string_view("fake_session_id"), absl::string_view("access_token"))).WillOnce(Return(absl::nullopt));
  EXPECT_CALL(*redis_wrapper_mock_,
              hget(absl::string_view("fake_session_id"), absl::string_view("refresh_token"))).WillOnce(Return(absl::nullopt));
  EXPECT_CALL(*redis_wrapper_mock_,
              hget(absl::string_view("fake_session_id"), absl::string_view("access_token_expiry"))).WillOnce(Return(absl::nullopt));
  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillOnce(Return(1000));
  EXPECT_CALL(*redis_wrapper_mock_,
              hget(absl::string_view("fake_session_id"), absl::string_view("time_added"))).WillOnce(Return("995"));
  EXPECT_CALL(*redis_wrapper_mock_,
              expireat(absl::string_view("fake_session_id"), 1042)).Times(1);


  auto result = redis_session_store.GetTokenResponse(session_id);
  ASSERT_EQ(token_response->IDToken().jwt_, result->IDToken().jwt_);
  ASSERT_FALSE(result->AccessToken());
  ASSERT_FALSE(result->RefreshToken());
  ASSERT_FALSE(result->GetAccessTokenExpiry());
}

TEST_F(RedisSessionStoreTest, GetTokenResponse_WhenTokenResponsePresent) {
  int absolute_timeout_in_seconds = 128;
  int idle_timeout_in_seconds = 42;
  RedisSessionStore redis_session_store(time_service_mock_, absolute_timeout_in_seconds,
                                        idle_timeout_in_seconds, redis_wrapper_mock_);
  auto session_id = std::string("fake_session_id");
  auto token_response = CreateTokenResponse();

  EXPECT_CALL(*redis_wrapper_mock_,
              hexists(absl::string_view("fake_session_id"), absl::string_view("id_token"))).WillOnce(Return(true));
  EXPECT_CALL(*redis_wrapper_mock_,
              hget(absl::string_view("fake_session_id"), absl::string_view("id_token"))).WillOnce(Return(token_response->IDToken().jwt_));
  EXPECT_CALL(*redis_wrapper_mock_,
              hget(absl::string_view("fake_session_id"), absl::string_view("access_token"))).WillOnce(Return(*token_response->AccessToken()));
  EXPECT_CALL(*redis_wrapper_mock_,
              hget(absl::string_view("fake_session_id"), absl::string_view("refresh_token"))).WillOnce(Return(*token_response->RefreshToken()));
  EXPECT_CALL(*redis_wrapper_mock_,
              hget(absl::string_view("fake_session_id"), absl::string_view("access_token_expiry"))).WillOnce(Return(std::to_string(*token_response->GetAccessTokenExpiry())));
  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillOnce(Return(1000));
  EXPECT_CALL(*redis_wrapper_mock_,
              hget(absl::string_view("fake_session_id"), absl::string_view("time_added"))).WillOnce(Return("995"));
  EXPECT_CALL(*redis_wrapper_mock_,
              expireat(absl::string_view("fake_session_id"), 1042)).Times(1);


  auto result = redis_session_store.GetTokenResponse(session_id);
  ASSERT_EQ(token_response->IDToken().jwt_, result->IDToken().jwt_);
  ASSERT_EQ(token_response->AccessToken(), result->AccessToken());
  ASSERT_EQ(token_response->RefreshToken(), result->RefreshToken());
  ASSERT_EQ(token_response->GetAccessTokenExpiry(), result->GetAccessTokenExpiry());
}

TEST_F(RedisSessionStoreTest, SetTokenResponse) {
  int absolute_timeout_in_seconds = 128;
  int idle_timeout_in_seconds = 42;
  RedisSessionStore redis_session_store(time_service_mock_, absolute_timeout_in_seconds,
                                        idle_timeout_in_seconds, redis_wrapper_mock_);
  auto token_response = CreateTokenResponse();
  auto session_id = std::string("fake_session_id");

  EXPECT_CALL(*redis_wrapper_mock_,
              hset(absl::string_view("fake_session_id"), absl::string_view("id_token"), absl::string_view(token_response->IDToken().jwt_))).WillOnce(Return(true));
  EXPECT_CALL(*redis_wrapper_mock_,
              hset(absl::string_view("fake_session_id"), absl::string_view("access_token"), absl::string_view(*token_response->AccessToken()))).WillOnce(Return(true));
  EXPECT_CALL(*redis_wrapper_mock_,
              hset(absl::string_view("fake_session_id"), absl::string_view("refresh_token"), absl::string_view(*token_response->RefreshToken()))).WillOnce(Return(true));
  EXPECT_CALL(*redis_wrapper_mock_,
              hset(absl::string_view("fake_session_id"), absl::string_view("access_token_expiry"), absl::string_view(std::to_string(*token_response->GetAccessTokenExpiry())))).WillOnce(Return(true));
  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillOnce(Return(1000));
  EXPECT_CALL(*redis_wrapper_mock_,
              hget(absl::string_view("fake_session_id"), absl::string_view("time_added"))).WillOnce(Return("995"));
  EXPECT_CALL(*redis_wrapper_mock_,
              expireat(absl::string_view("fake_session_id"), 1042)).Times(1);


  redis_session_store.SetTokenResponse(session_id, token_response);

}
//  // Caution: when you mutate the original, you mutate the same object that is held in the session store's map
//  token_response->SetAccessToken("fake_access_token2");
//
//  result = in_memory_session_store.GetTokenResponse(other_session_id);
//  ASSERT_FALSE(result);
//
//  result = in_memory_session_store.GetTokenResponse(session_id);
//  ASSERT_TRUE(result);
//  ASSERT_EQ(result->IDToken().jwt_, id_token_jwt.jwt_);
//  ASSERT_EQ(result->RefreshToken(), "fake_refresh_token");
//  ASSERT_EQ(result->AccessToken(), "fake_access_token2"); // will be the mutated value, so be careful!
//  ASSERT_EQ(result->GetAccessTokenExpiry(), 42);
//
//  token_response->SetAccessTokenExpiry(99);
//  in_memory_session_store.SetTokenResponse(session_id, token_response); // overwrite
//
//  result = in_memory_session_store.GetTokenResponse(session_id);
//  ASSERT_TRUE(result);
//  ASSERT_EQ(result->IDToken().jwt_, id_token_jwt.jwt_);
//  ASSERT_EQ(result->RefreshToken(), "fake_refresh_token");
//  ASSERT_EQ(result->AccessToken(), "fake_access_token2");
//  ASSERT_EQ(result->GetAccessTokenExpiry(), 99);
//}
//
//TEST_F(RedisSessionStoreTest, SetAuthorizationStateAndClearAuthorizationStateAndGetAuthorizationState) {
//  InMemorySessionStore in_memory_session_store(time_service_mock_, 42, 128);
//  std::string session_id = "fake_session_id";
//  std::string other_session_id = "other_session_id";
//  std::string state = "some-state";
//  std::string original_state(state);
//  std::string nonce = "some-nonce";
//  std::string original_nonce(nonce);
//  std::string requested_url = "https://example.com";
//  std::string original_requested_url(requested_url);
//  auto authorization_state = std::make_shared<AuthorizationState>(state, nonce, requested_url);
//
//  auto result = in_memory_session_store.GetAuthorizationState(session_id);
//  ASSERT_FALSE(result);
//
//  in_memory_session_store.ClearAuthorizationState(session_id); // does not crash
//  ASSERT_FALSE(result);
//
//  in_memory_session_store.SetAuthorizationState(session_id, authorization_state);
//
//  result = in_memory_session_store.GetAuthorizationState(other_session_id);
//  ASSERT_FALSE(result);
//
//  // mutate original strings that were passed to AuthorizationState constructor, make sure it doesn't change AuthorizationState
//  nonce += "-modified";
//  state += "-modified";
//  requested_url += "/modified";
//  result = in_memory_session_store.GetAuthorizationState(session_id);
//  ASSERT_TRUE(result);
//  ASSERT_EQ(result->GetRequestedUrl(), original_requested_url);
//  ASSERT_EQ(result->GetState(), original_state);
//  ASSERT_EQ(result->GetNonce(), original_nonce);
//
//  std::string another_state = "some-other-state";
//  std::string another_nonce = "some-other-nonce";
//  std::string another_requested_url = "https://other.example.com";
//  auto another_authorization_state = std::make_shared<AuthorizationState>(another_state, another_nonce,
//                                                                          another_requested_url);
//  in_memory_session_store.SetAuthorizationState(session_id, another_authorization_state); // overwrite
//
//  result = in_memory_session_store.GetAuthorizationState(session_id);
//  ASSERT_TRUE(result);
//  ASSERT_EQ(result->GetRequestedUrl(), another_requested_url);
//  ASSERT_EQ(result->GetState(), another_state);
//  ASSERT_EQ(result->GetNonce(), another_nonce);
//
//  in_memory_session_store.ClearAuthorizationState(session_id);
//  ASSERT_FALSE(in_memory_session_store.GetAuthorizationState(session_id));
//}
//
//TEST_F(RedisSessionStoreTest, Remove) {
//  InMemorySessionStore in_memory_session_store(time_service_mock_, 42, 128);
//  auto session_id = std::string("fake_session_id");
//  auto token_response = CreateTokenResponse();
//  auto authorization_state = std::make_shared<AuthorizationState>("state", "nonce", "requested_url");
//
//  in_memory_session_store.SetAuthorizationState(session_id, authorization_state);
//  in_memory_session_store.SetTokenResponse(session_id, token_response);
//  ASSERT_TRUE(in_memory_session_store.GetTokenResponse(session_id));
//  ASSERT_TRUE(in_memory_session_store.GetAuthorizationState(session_id));
//
//  in_memory_session_store.RemoveSession(session_id);
//
//  ASSERT_FALSE(in_memory_session_store.GetTokenResponse(session_id));
//  ASSERT_FALSE(in_memory_session_store.GetAuthorizationState(session_id));
//
//  in_memory_session_store.RemoveSession("other-session-id"); // ignore non-existent keys without error
//}
//
//TEST_F(RedisSessionStoreTest, RefreshExpration) {
//
//}
//
//void RedisSessionStoreTest::MockRedisGetAuthorizationState(absl::string_view session_id) {
//
//}
//
//void RedisSessionStoreTest::MockRedisSetAuthorizationState()
//
//void RedisSessionStoreTest::MockRedisGetTokenResponse()
//
//void RedisSessionStoreTest::MockRedisSetTokenResponse()
//
//void RedisSessionStoreTest::MockRedisRefreshExpiration()

}  // namespace oidc
}  // namespace filters
}  // namespace authservice
