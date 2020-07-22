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
  const absl::string_view session_id = absl::string_view("fake_session_id");
  const absl::string_view state_key = absl::string_view("state");
  const std::string state = std::string("fake-state");
  const absl::string_view nonce_key = absl::string_view("nonce");
  const std::string nonce = std::string("fake-nonce");
  const absl::string_view requested_url_key = absl::string_view("requested_url");
  const std::string requested_url = std::string("fake-requested-url");
  const absl::string_view time_added_key = absl::string_view("time_added");
  const absl::string_view id_token_key = absl::string_view("id_token");
  const absl::string_view access_token_key = absl::string_view("access_token");
  const absl::string_view refresh_token_key = absl::string_view("refresh_token");
  const absl::string_view access_token_expiry_key = absl::string_view("access_token_expiry");

  void SetUp() override {
    auto jwt_status = id_token_jwt.parseFromString(
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMiwiYXVkIjpbImNsaWVudDEiXSwibm9uY2UiOiJyYW5kb20ifQ.NQi_VTRjZ8jv5cAp4inpuQ9STfVgCoWfONjLnZEMk8la8s99J9b6QmcKtO2tabTgvcseikVNlPuB6fZztY_fxhdrNE0dBNAl1lhz_AWBz6Yr-D82LLKk5NQ-IKDloF19Pic0Ub9pGCqNLOlmRXRVcfwwq5nISzfP6OdrjepRZ2Jd3rc2HvHYm-6GstH4xkKViABVwCDmwlAOi47bdHPByHkZOOnHSQEElr4tqO_uAQRpj36Yvt-95nPKhWaufZhcpYKk1H7ZRmylJQuG_dhlw4gN1i5iWBMk-Sj_2xyk05Bap1qkKSeHTxyqzhtDAH0LHYZdo_2hU-7YnL4JRhVVwg");
    ASSERT_EQ(jwt_status, google::jwt_verify::Status::Ok);

    time_service_mock_ = std::make_shared<testing::NiceMock<common::utilities::TimeServiceMock>>();
    redis_wrapper_mock_ = std::make_shared<testing::StrictMock<RedisWrapperMock>>();
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

  EXPECT_CALL(*redis_wrapper_mock_, hexists(session_id, id_token_key)).WillOnce(Return(false));

  ASSERT_EQ(nullptr, redis_session_store.GetTokenResponse(session_id));
}

TEST_F(RedisSessionStoreTest, GetTokenResponse_WhenIdTokenCannotBeParsed) {
  RedisSessionStore redis_session_store(time_service_mock_, 42, 128, redis_wrapper_mock_);
  EXPECT_CALL(*redis_wrapper_mock_, hexists(session_id, id_token_key)).WillOnce(Return(true));
  EXPECT_CALL(*redis_wrapper_mock_, hget(session_id, id_token_key)).WillOnce(Return("garbage"));

  ASSERT_EQ(nullptr, redis_session_store.GetTokenResponse(session_id));
}

TEST_F(RedisSessionStoreTest, GetTokenResponse_WhenOnlyIdTokenIsPresent) {
  int absolute_timeout_in_seconds = 128;
  int idle_timeout_in_seconds = 42;
  RedisSessionStore redis_session_store(time_service_mock_, absolute_timeout_in_seconds,
                                        idle_timeout_in_seconds, redis_wrapper_mock_);

  auto token_response = std::make_shared<oidc::TokenResponse>(id_token_jwt);
  auto &id_token_jwt = token_response->IDToken().jwt_;

  EXPECT_CALL(*redis_wrapper_mock_, hexists(session_id, id_token_key)).WillOnce(Return(true));
  EXPECT_CALL(*redis_wrapper_mock_, hget(session_id, id_token_key)).WillOnce(Return(id_token_jwt));
  EXPECT_CALL(*redis_wrapper_mock_, hget(session_id, access_token_key)).WillOnce(Return(absl::nullopt));
  EXPECT_CALL(*redis_wrapper_mock_, hget(session_id, refresh_token_key)).WillOnce(Return(absl::nullopt));
  EXPECT_CALL(*redis_wrapper_mock_, hget(session_id, access_token_expiry_key)).WillOnce(Return(absl::nullopt));

  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillOnce(Return(1000));
  EXPECT_CALL(*redis_wrapper_mock_, hget(session_id, time_added_key)).WillOnce(Return("995"));
  EXPECT_CALL(*redis_wrapper_mock_, expireat(session_id, 1042)).Times(1);

  auto result = redis_session_store.GetTokenResponse(session_id);
  ASSERT_EQ(id_token_jwt, result->IDToken().jwt_);
  ASSERT_FALSE(result->AccessToken().has_value());
  ASSERT_FALSE(result->RefreshToken().has_value());
  ASSERT_FALSE(result->GetAccessTokenExpiry().has_value());
}

TEST_F(RedisSessionStoreTest, GetTokenResponse_WhenTokenResponsePresentWithAllValues) {
  int absolute_timeout_in_seconds = 128;
  int idle_timeout_in_seconds = 42;
  RedisSessionStore redis_session_store(time_service_mock_, absolute_timeout_in_seconds,
                                        idle_timeout_in_seconds, redis_wrapper_mock_);
  auto token_response = CreateTokenResponse();
  auto &id_token_jwt = token_response->IDToken().jwt_;
  auto access_token = token_response->AccessToken();
  auto refresh_token = token_response->RefreshToken();
  auto access_token_expiry = token_response->GetAccessTokenExpiry();

  EXPECT_CALL(*redis_wrapper_mock_, hexists(session_id, id_token_key)).WillOnce(Return(true));
  EXPECT_CALL(*redis_wrapper_mock_, hget(session_id, id_token_key)).WillOnce(Return(id_token_jwt));
  EXPECT_CALL(*redis_wrapper_mock_, hget(session_id, access_token_key)).WillOnce(Return(*access_token));
  EXPECT_CALL(*redis_wrapper_mock_, hget(session_id, refresh_token_key)).WillOnce(Return(*refresh_token));
  EXPECT_CALL(*redis_wrapper_mock_,
              hget(session_id, access_token_expiry_key)).WillOnce(Return(std::to_string(*access_token_expiry)));
  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillOnce(Return(1000));
  EXPECT_CALL(*redis_wrapper_mock_, hget(session_id, time_added_key)).WillOnce(Return("995"));
  EXPECT_CALL(*redis_wrapper_mock_, expireat(session_id, 1042)).Times(1);

  auto result = redis_session_store.GetTokenResponse(session_id);
  ASSERT_EQ(id_token_jwt, result->IDToken().jwt_);
  ASSERT_EQ(access_token, result->AccessToken());
  ASSERT_EQ(refresh_token, result->RefreshToken());
  ASSERT_EQ(access_token_expiry, result->GetAccessTokenExpiry());
}

TEST_F(RedisSessionStoreTest, SetTokenResponse_WithFullyPopulatedTokenResponse) {
  int absolute_timeout_in_seconds = 128;
  int idle_timeout_in_seconds = 42;
  RedisSessionStore redis_session_store(time_service_mock_, absolute_timeout_in_seconds,
                                        idle_timeout_in_seconds, redis_wrapper_mock_);
  auto token_response = CreateTokenResponse();
  auto id_token = absl::string_view(token_response->IDToken().jwt_);
  auto access_token = absl::string_view(*token_response->AccessToken());
  auto refresh_token = absl::string_view(*token_response->RefreshToken());
  auto access_token_expiry = absl::string_view(std::to_string(*token_response->GetAccessTokenExpiry()));

  EXPECT_CALL(*redis_wrapper_mock_, hset(session_id, id_token_key, id_token)).WillOnce(Return(true));
  EXPECT_CALL(*redis_wrapper_mock_, hset(session_id, access_token_key, access_token)).WillOnce(Return(true));
  EXPECT_CALL(*redis_wrapper_mock_, hset(session_id, refresh_token_key, refresh_token)).WillOnce(Return(true));
  EXPECT_CALL(*redis_wrapper_mock_,
              hset(session_id, access_token_expiry_key, access_token_expiry)).WillOnce(Return(true));

  EXPECT_CALL(*redis_wrapper_mock_,
              hsetnx(session_id, time_added_key, absl::string_view("1000"))).WillOnce(Return(true));

  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(1000));
  EXPECT_CALL(*redis_wrapper_mock_, hget(session_id, time_added_key)).WillOnce(Return("995"));
  EXPECT_CALL(*redis_wrapper_mock_, expireat(session_id, 1042)).Times(1);

  redis_session_store.SetTokenResponse(session_id, token_response);
}

TEST_F(RedisSessionStoreTest, SetTokenResponse_WithOnlyIdToken) {
  int absolute_timeout_in_seconds = 128;
  int idle_timeout_in_seconds = 42;
  RedisSessionStore redis_session_store(time_service_mock_, absolute_timeout_in_seconds,
                                        idle_timeout_in_seconds, redis_wrapper_mock_);
  auto token_response = std::make_shared<oidc::TokenResponse>(id_token_jwt);

  const absl::string_view &id_token_string = absl::string_view(token_response->IDToken().jwt_);
  EXPECT_CALL(*redis_wrapper_mock_, hset(session_id, id_token_key, id_token_string)).WillOnce(Return(true));
  EXPECT_CALL(*redis_wrapper_mock_, hdel(session_id, access_token_key)).WillOnce(Return(true));
  EXPECT_CALL(*redis_wrapper_mock_, hdel(session_id, refresh_token_key)).WillOnce(Return(true));
  EXPECT_CALL(*redis_wrapper_mock_, hdel(session_id, access_token_expiry_key)).WillOnce(Return(true));

  EXPECT_CALL(*redis_wrapper_mock_,
              hsetnx(session_id, time_added_key, absl::string_view("1000"))).WillOnce(Return(true));

  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(1000));
  EXPECT_CALL(*redis_wrapper_mock_, hget(session_id, time_added_key)).WillOnce(Return("995"));

  EXPECT_CALL(*redis_wrapper_mock_, expireat(session_id, 1042)).Times(1);

  redis_session_store.SetTokenResponse(std::string("fake_session_id"), token_response);
}

TEST_F(RedisSessionStoreTest, RefreshExpiration_FarFromAbsoluteTimeout_Test) {
  int absolute_timeout_in_seconds = 128;
  int idle_timeout_in_seconds = 42;
  RedisSessionStore redis_session_store(time_service_mock_, absolute_timeout_in_seconds,
                                        idle_timeout_in_seconds, redis_wrapper_mock_);
  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(1000));
  EXPECT_CALL(*redis_wrapper_mock_, hget(session_id, time_added_key)).WillOnce(Return("995"));
  EXPECT_CALL(*redis_wrapper_mock_, expireat(session_id, 1042)).Times(1);
  redis_session_store.RefreshExpiration(session_id);
}

TEST_F(RedisSessionStoreTest, RefreshExpiration_NearToAbsoluteTimeout) {
  int absolute_timeout_in_seconds = 128;
  int idle_timeout_in_seconds = 42;
  RedisSessionStore redis_session_store(time_service_mock_, absolute_timeout_in_seconds,
                                        idle_timeout_in_seconds, redis_wrapper_mock_);
  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(1000));
  EXPECT_CALL(*redis_wrapper_mock_, hget(session_id, time_added_key)).WillOnce(Return("900"));
  EXPECT_CALL(*redis_wrapper_mock_, expireat(session_id, 1028)).Times(1);
  redis_session_store.RefreshExpiration(session_id);
}

TEST_F(RedisSessionStoreTest, RefreshExpiration_WhenTimeAddedIsNull) {
  RedisSessionStore redis_session_store(time_service_mock_, 128, 42, redis_wrapper_mock_);
  EXPECT_CALL(*redis_wrapper_mock_, hget(session_id, time_added_key)).WillOnce(Return(absl::nullopt));
  EXPECT_CALL(*redis_wrapper_mock_, del(session_id));

  redis_session_store.RefreshExpiration(session_id);
}

TEST_F(RedisSessionStoreTest, RemoveSession) {
  RedisSessionStore redis_session_store(time_service_mock_, 128, 42, redis_wrapper_mock_);
  EXPECT_CALL(*redis_wrapper_mock_, del(session_id)).Times(1);
  redis_session_store.RemoveSession(session_id);
}

TEST_F(RedisSessionStoreTest, SetAuthorizationState) {
  int absolute_timeout = 128;
  int idle_timeout = 42;
  RedisSessionStore redis_session_store(time_service_mock_, absolute_timeout, idle_timeout, redis_wrapper_mock_);

  auto requested_url = absl::string_view("fake-requested-url");
  auto nonce = absl::string_view("fake-nonce");
  auto state = absl::string_view("fake-state");

  EXPECT_CALL(*redis_wrapper_mock_, hset(session_id, state_key, state)).WillOnce(Return(true));
  EXPECT_CALL(*redis_wrapper_mock_, hset(session_id, nonce_key, nonce)).WillOnce(Return(true));
  EXPECT_CALL(*redis_wrapper_mock_, hset(session_id, requested_url_key, requested_url)).WillOnce(Return(true));

  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(1000));
  EXPECT_CALL(*redis_wrapper_mock_,
              hsetnx(session_id, time_added_key, absl::string_view("1000"))).WillOnce(Return(true));

  EXPECT_CALL(*redis_wrapper_mock_, expireat(session_id, 1042)).Times(1);
  EXPECT_CALL(*redis_wrapper_mock_, hget(session_id, time_added_key)).WillOnce(Return("995"));

  auto authorization_state = std::make_shared<AuthorizationState>(state, nonce, requested_url);
  redis_session_store.SetAuthorizationState(std::string("fake_session_id"), authorization_state);
}

TEST_F(RedisSessionStoreTest, GetAuthorizationState_WhenNotPresent) {
  RedisSessionStore redis_session_store(time_service_mock_, 128, 42, redis_wrapper_mock_);

  EXPECT_CALL(*redis_wrapper_mock_, hexists(session_id, state_key)).WillOnce(Return(false));

  ASSERT_EQ(nullptr, redis_session_store.GetAuthorizationState(session_id));
}

TEST_F(RedisSessionStoreTest, GetAuthorizationState_WhenValuesPresent) {
  int absolute_timeout = 128;
  int idle_timeout = 42;
  RedisSessionStore redis_session_store(time_service_mock_, absolute_timeout, idle_timeout, redis_wrapper_mock_);

  EXPECT_CALL(*redis_wrapper_mock_, hexists(session_id, state_key)).WillOnce(Return(true));
  EXPECT_CALL(*redis_wrapper_mock_, hget(session_id, state_key)).WillOnce(Return(state));
  EXPECT_CALL(*redis_wrapper_mock_, hget(session_id, nonce_key)).WillOnce(Return(nonce));
  EXPECT_CALL(*redis_wrapper_mock_, hget(session_id, requested_url_key)).WillOnce(Return(requested_url));

  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillOnce(Return(1000));
  EXPECT_CALL(*redis_wrapper_mock_, expireat(session_id, 1042)).Times(1);
  EXPECT_CALL(*redis_wrapper_mock_, hget(session_id, time_added_key)).WillOnce(Return("995"));

  auto result = redis_session_store.GetAuthorizationState(session_id);
  ASSERT_EQ(state, result->GetState());
  ASSERT_EQ(nonce, result->GetNonce());
  ASSERT_EQ(requested_url, result->GetRequestedUrl());
}

TEST_F(RedisSessionStoreTest, ClearAuthorizationState) {
  RedisSessionStore redis_session_store(time_service_mock_, 128, 42, redis_wrapper_mock_);

  EXPECT_CALL(*redis_wrapper_mock_, hdel(session_id, state_key)).WillOnce(Return(true));
  EXPECT_CALL(*redis_wrapper_mock_, hdel(session_id, nonce_key)).WillOnce(Return(true));
  EXPECT_CALL(*redis_wrapper_mock_, hdel(session_id, requested_url_key)).WillOnce(Return(true));

  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillOnce(Return(1000));
  EXPECT_CALL(*redis_wrapper_mock_, expireat(session_id, 1042)).Times(1);
  EXPECT_CALL(*redis_wrapper_mock_, hget(session_id, time_added_key)).WillOnce(Return("995"));

  redis_session_store.ClearAuthorizationState(session_id);
}

TEST_F(RedisSessionStoreTest, RemoveAllExpired_DoesNothing) {
  RedisSessionStore redis_session_store(time_service_mock_, 128, 42, redis_wrapper_mock_);
  redis_session_store.RemoveAllExpired();
}

}  // namespace oidc
}  // namespace filters
}  // namespace authservice
