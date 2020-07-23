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

class RedisSessionStoreWithProtectedMethodsMadePublic : public RedisSessionStore {
 public:

  RedisSessionStoreWithProtectedMethodsMadePublic(
      std::shared_ptr<common::utilities::TimeService> time_service,
      uint32_t absolute_session_timeout_in_seconds,
      uint32_t idle_session_timeout_in_seconds,
      std::shared_ptr<RedisWrapper> redis_wrapper) :
      RedisSessionStore{time_service,
                        absolute_session_timeout_in_seconds,
                        idle_session_timeout_in_seconds,
                        redis_wrapper} {}

  using RedisSessionStore::RefreshExpiration;
};

class RedisSessionStoreTest : public ::testing::Test {
 protected:
  std::shared_ptr<common::utilities::TimeServiceMock> time_service_mock_;
  std::shared_ptr<RedisWrapperMock> redis_wrapper_mock_;
  google::jwt_verify::Jwt id_token_jwt;
  std::shared_ptr<RedisSessionStoreWithProtectedMethodsMadePublic> redis_session_store;

  std::string access_token_expiry_key = "access_token_expiry";
  long long access_token_expiry = 42;
  std::string access_token_key = "access_token";
  std::string access_token = "fake_access_token";
  std::string id_token_key = "id_token";
  std::string id_token =
      "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMiwiYXVkIjpbImNsaWVudDEiXSwibm9uY2UiOiJyYW5kb20ifQ.NQi_VTRjZ8jv5cAp4inpuQ9STfVgCoWfONjLnZEMk8la8s99J9b6QmcKtO2tabTgvcseikVNlPuB6fZztY_fxhdrNE0dBNAl1lhz_AWBz6Yr-D82LLKk5NQ-IKDloF19Pic0Ub9pGCqNLOlmRXRVcfwwq5nISzfP6OdrjepRZ2Jd3rc2HvHYm-6GstH4xkKViABVwCDmwlAOi47bdHPByHkZOOnHSQEElr4tqO_uAQRpj36Yvt-95nPKhWaufZhcpYKk1H7ZRmylJQuG_dhlw4gN1i5iWBMk-Sj_2xyk05Bap1qkKSeHTxyqzhtDAH0LHYZdo_2hU-7YnL4JRhVVwg";
  std::string nonce_key = "nonce";
  std::string nonce = "fake-nonce";
  std::string refresh_token_key = "refresh_token";
  std::string refresh_token = "fake_refresh_token";
  std::string requested_url_key = "requested_url";
  std::string requested_url = "fake-requested-url";
  std::string session_id = "fake_session_id";
  std::string state_key = "state";
  std::string state = "fake-state";
  std::string time_added_key = "time_added";
  std::vector<std::string> list_of_token_response_keys =
      {id_token_key, access_token_key, refresh_token_key, access_token_expiry_key, time_added_key};

  void SetUp() override {
    auto jwt_status = id_token_jwt.parseFromString(id_token);
    ASSERT_EQ(jwt_status, google::jwt_verify::Status::Ok);

    time_service_mock_ = std::make_shared<testing::NiceMock<common::utilities::TimeServiceMock>>();
    redis_wrapper_mock_ = std::make_shared<testing::StrictMock<RedisWrapperMock>>();
    int absolute_timeout = 128;
    int idle_timeout = 42;
    redis_session_store =
        std::make_shared<RedisSessionStoreWithProtectedMethodsMadePublic>(time_service_mock_,
                                                                          absolute_timeout,
                                                                          idle_timeout,
                                                                          redis_wrapper_mock_);
  }
};

TEST_F(RedisSessionStoreTest, GetTokenResponse_WhenNoTokenResponsePresent) {
  std::unordered_map<std::string, absl::optional<std::string>> empty_map = {
      {id_token_key, absl::nullopt},
      {access_token_key, absl::nullopt},
      {refresh_token_key, absl::nullopt},
      {access_token_expiry_key, absl::nullopt},
      {time_added_key, absl::nullopt}
  };

  EXPECT_CALL(*redis_wrapper_mock_, hmget(Eq(session_id), Eq(list_of_token_response_keys))).WillOnce(Return(empty_map));
  ASSERT_EQ(nullptr, redis_session_store->GetTokenResponse(session_id));
}

TEST_F(RedisSessionStoreTest, GetTokenResponse_WhenIdTokenCannotBeParsed) {
  std::unordered_map<std::string, absl::optional<std::string>> token_response_map = {
      {id_token_key, "garbagio"},
      {access_token_key, absl::nullopt},
      {refresh_token_key, absl::nullopt},
      {access_token_expiry_key, absl::nullopt},
      {time_added_key, absl::nullopt}
  };

  EXPECT_CALL(*redis_wrapper_mock_, hmget(Eq(session_id), Eq(list_of_token_response_keys)))
      .WillOnce(Return(token_response_map));

  ASSERT_EQ(nullptr, redis_session_store->GetTokenResponse(session_id));
}

TEST_F(RedisSessionStoreTest, GetTokenResponse_WhenOnlyIdTokenIsPresent) {
  std::unordered_map<std::string, absl::optional<std::string>> token_response_map = {
      {id_token_key, id_token},
      {access_token_key, absl::nullopt},
      {refresh_token_key, absl::nullopt},
      {access_token_expiry_key, absl::nullopt},
      {time_added_key, "995"}
  };

  EXPECT_CALL(*redis_wrapper_mock_, hmget(Eq(session_id), Eq(list_of_token_response_keys)))
      .WillOnce(Return(token_response_map));

  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillOnce(Return(1000));
  EXPECT_CALL(*redis_wrapper_mock_, expireat(Eq(session_id), Eq(1042))).Times(1);

  auto result = redis_session_store->GetTokenResponse(session_id);
  ASSERT_EQ(id_token, result->IDToken().jwt_);
  ASSERT_FALSE(result->AccessToken().has_value());
  ASSERT_FALSE(result->RefreshToken().has_value());
  ASSERT_FALSE(result->GetAccessTokenExpiry().has_value());
}

TEST_F(RedisSessionStoreTest, GetTokenResponse_WhenTokenResponsePresentWithAllValues) {
  std::unordered_map<std::string, absl::optional<std::string>> token_response_map = {
      {id_token_key, id_token},
      {access_token_key, access_token},
      {refresh_token_key, refresh_token},
      {access_token_expiry_key, std::to_string(access_token_expiry)},
      {time_added_key, "995"}
  };

  EXPECT_CALL(*redis_wrapper_mock_, hmget(Eq(session_id), Eq(list_of_token_response_keys)))
      .WillOnce(Return(token_response_map));

  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillOnce(Return(1000));
  EXPECT_CALL(*redis_wrapper_mock_, expireat(Eq(session_id), Eq(1042))).Times(1);

  auto result = redis_session_store->GetTokenResponse(session_id);
  ASSERT_EQ(id_token, result->IDToken().jwt_);
  ASSERT_EQ(access_token, result->AccessToken());
  ASSERT_EQ(refresh_token, result->RefreshToken());
  ASSERT_EQ(access_token_expiry, result->GetAccessTokenExpiry());
}

TEST_F(RedisSessionStoreTest, SetTokenResponse_WithFullyPopulatedTokenResponse) {
  EXPECT_CALL(*redis_wrapper_mock_, hset(Eq(session_id), Eq(id_token_key), Eq(id_token))).WillOnce(Return(true));
  EXPECT_CALL(*redis_wrapper_mock_,
              hset(Eq(session_id), Eq(access_token_key), Eq(access_token))).WillOnce(Return(true));
  EXPECT_CALL(*redis_wrapper_mock_,
              hset(Eq(session_id), Eq(refresh_token_key), Eq(refresh_token))).WillOnce(Return(true));
  EXPECT_CALL(*redis_wrapper_mock_,
              hset(Eq(session_id), Eq(access_token_expiry_key), Eq(std::to_string(access_token_expiry)))).WillOnce(
      Return(true));

  EXPECT_CALL(*redis_wrapper_mock_,
              hsetnx(Eq(session_id), Eq(time_added_key), Eq("1000"))).WillOnce(Return(true));

  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(1000));
  EXPECT_CALL(*redis_wrapper_mock_, hget(Eq(session_id), Eq(time_added_key))).WillOnce(Return("995"));
  EXPECT_CALL(*redis_wrapper_mock_, expireat(Eq(session_id), Eq(1042))).Times(1);

  auto token_response = std::make_shared<TokenResponse>(id_token_jwt);
  token_response->SetRefreshToken(refresh_token);
  token_response->SetAccessToken(access_token);
  token_response->SetAccessTokenExpiry(access_token_expiry);
  redis_session_store->SetTokenResponse(session_id, token_response);
}

TEST_F(RedisSessionStoreTest, SetTokenResponse_WithOnlyIdToken) {
  EXPECT_CALL(*redis_wrapper_mock_, hset(Eq(session_id), Eq(id_token_key), Eq(id_token))).WillOnce(Return(true));
  std::vector<std::string> list_of_token_response_keys_without_id_token =
      {access_token_key, refresh_token_key, access_token_expiry_key};
  EXPECT_CALL(*redis_wrapper_mock_, hdel(Eq(session_id), Eq(list_of_token_response_keys_without_id_token)))
      .WillOnce(Return(true));
  EXPECT_CALL(*redis_wrapper_mock_, hsetnx(Eq(session_id), Eq(time_added_key), Eq("1000"))).WillOnce(Return(true));
  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(1000));
  EXPECT_CALL(*redis_wrapper_mock_, hget(Eq(session_id), Eq(time_added_key))).WillOnce(Return("995"));
  EXPECT_CALL(*redis_wrapper_mock_, expireat(Eq(session_id), Eq(1042))).Times(1);

  redis_session_store->SetTokenResponse(session_id, std::make_shared<oidc::TokenResponse>(id_token_jwt));
}

TEST_F(RedisSessionStoreTest, RefreshExpiration_FarFromAbsoluteTimeout) {
  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(1000));
  EXPECT_CALL(*redis_wrapper_mock_, hget(Eq(session_id), Eq(time_added_key))).WillOnce(Return("995"));
  EXPECT_CALL(*redis_wrapper_mock_, expireat(Eq(session_id), Eq(1042))).Times(1);
  redis_session_store->RefreshExpiration(session_id);
}

TEST_F(RedisSessionStoreTest, RefreshExpiration_NearToAbsoluteTimeout) {
  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(1000));
  EXPECT_CALL(*redis_wrapper_mock_, hget(Eq(session_id), Eq(time_added_key))).WillOnce(Return("900"));
  EXPECT_CALL(*redis_wrapper_mock_, expireat(Eq(session_id), Eq(1028))).Times(1);
  redis_session_store->RefreshExpiration(session_id);
}

TEST_F(RedisSessionStoreTest, RefreshExpiration_WhenTimeAddedIsNull) {
  EXPECT_CALL(*redis_wrapper_mock_, hget(Eq(session_id), Eq(time_added_key))).WillOnce(Return(absl::nullopt));
  EXPECT_CALL(*redis_wrapper_mock_, del(Eq(session_id)));

  redis_session_store->RefreshExpiration(session_id);
}

TEST_F(RedisSessionStoreTest, RemoveSession) {
  EXPECT_CALL(*redis_wrapper_mock_, del(Eq(session_id))).Times(1);
  redis_session_store->RemoveSession(session_id);
}

TEST_F(RedisSessionStoreTest, SetAuthorizationState) {
  std::unordered_map<std::string, std::string> auth_state_map = {
      {state_key, state},
      {nonce_key, nonce},
      {requested_url_key, requested_url}
  };

  EXPECT_CALL(*redis_wrapper_mock_, hmset(Eq(session_id), Eq(auth_state_map))).Times(1);

  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(1000));
  EXPECT_CALL(*redis_wrapper_mock_, hsetnx(Eq(session_id), Eq(time_added_key), Eq("1000"))).WillOnce(Return(true));

  EXPECT_CALL(*redis_wrapper_mock_, expireat(Eq(session_id), Eq(1042))).Times(1);
  EXPECT_CALL(*redis_wrapper_mock_, hget(Eq(session_id), Eq(time_added_key))).WillOnce(Return("995"));

  auto authorization_state = std::make_shared<AuthorizationState>(state, nonce, requested_url);
  redis_session_store->SetAuthorizationState(session_id, authorization_state);
}

TEST_F(RedisSessionStoreTest, GetAuthorizationState_WhenNotPresent) {
  std::unordered_map<std::string, absl::optional<std::string>> auth_state_map = {
      {state_key, absl::nullopt},
      {nonce_key, absl::nullopt},
      {requested_url_key, absl::nullopt},
      {time_added_key, absl::nullopt}
  };
  std::vector<std::string> auth_state_keys({state_key, nonce_key, requested_url_key, time_added_key});
  EXPECT_CALL(*redis_wrapper_mock_, hmget(Eq(session_id), Eq(auth_state_keys))).WillOnce(Return(auth_state_map));

  ASSERT_EQ(nullptr, redis_session_store->GetAuthorizationState(session_id));
}

TEST_F(RedisSessionStoreTest, GetAuthorizationState_WhenOnlyStateNotPresent) {
  std::unordered_map<std::string, absl::optional<std::string>> auth_state_map = {
      {state_key, absl::nullopt},
      {nonce_key, nonce},
      {requested_url_key, requested_url},
      {time_added_key, "995"}
  };
  std::vector<std::string> auth_state_keys({state_key, nonce_key, requested_url_key, time_added_key});
  EXPECT_CALL(*redis_wrapper_mock_, hmget(Eq(session_id), Eq(auth_state_keys))).WillOnce(Return(auth_state_map));

  ASSERT_EQ(nullptr, redis_session_store->GetAuthorizationState(session_id));
}

TEST_F(RedisSessionStoreTest, GetAuthorizationState_WhenOnlyNonceNotPresent) {
  std::unordered_map<std::string, absl::optional<std::string>> auth_state_map = {
      {state_key, state},
      {nonce_key, absl::nullopt},
      {requested_url_key, requested_url},
      {time_added_key, "995"}
  };
  std::vector<std::string> auth_state_keys({state_key, nonce_key, requested_url_key, time_added_key});
  EXPECT_CALL(*redis_wrapper_mock_, hmget(Eq(session_id), Eq(auth_state_keys))).WillOnce(Return(auth_state_map));

  ASSERT_EQ(nullptr, redis_session_store->GetAuthorizationState(session_id));
}

TEST_F(RedisSessionStoreTest, GetAuthorizationState_WhenOnlyRequestedUrlNotPresent) {
  std::unordered_map<std::string, absl::optional<std::string>> auth_state_map = {
      {state_key, state},
      {nonce_key, nonce},
      {requested_url_key, absl::nullopt},
      {time_added_key, "995"}
  };
  std::vector<std::string> auth_state_keys({state_key, nonce_key, requested_url_key, time_added_key});
  EXPECT_CALL(*redis_wrapper_mock_, hmget(Eq(session_id), Eq(auth_state_keys))).WillOnce(Return(auth_state_map));

  ASSERT_EQ(nullptr, redis_session_store->GetAuthorizationState(session_id));
}

TEST_F(RedisSessionStoreTest, GetAuthorizationState_WhenValuesPresent) {
  std::unordered_map<std::string, absl::optional<std::string>> auth_state_map = {
      {state_key, state},
      {nonce_key, nonce},
      {requested_url_key, requested_url},
      {time_added_key, "995"}
  };
  std::vector<std::string> auth_state_keys({state_key, nonce_key, requested_url_key, time_added_key});
  EXPECT_CALL(*redis_wrapper_mock_, hmget(Eq(session_id), Eq(auth_state_keys))).WillOnce(Return(auth_state_map));

  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillOnce(Return(1000));
  EXPECT_CALL(*redis_wrapper_mock_, expireat(Eq(session_id), Eq(1042))).Times(1);

  auto result = redis_session_store->GetAuthorizationState(session_id);
  ASSERT_EQ(state, result->GetState());
  ASSERT_EQ(nonce, result->GetNonce());
  ASSERT_EQ(requested_url, result->GetRequestedUrl());
}

TEST_F(RedisSessionStoreTest, ClearAuthorizationState) {
  EXPECT_CALL(*redis_wrapper_mock_,
              hdel(Eq(session_id), Eq(std::vector<std::string>{state_key, nonce_key, requested_url_key}))).WillOnce(
      Return(true));

  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillOnce(Return(1000));
  EXPECT_CALL(*redis_wrapper_mock_, expireat(Eq(session_id), Eq(1042))).Times(1);
  EXPECT_CALL(*redis_wrapper_mock_, hget(Eq(session_id), Eq(time_added_key))).WillOnce(Return("995"));

  redis_session_store->ClearAuthorizationState(session_id);
}

TEST_F(RedisSessionStoreTest, RemoveAllExpired_DoesNotCallRedis) {
  redis_session_store->RemoveAllExpired();
}

}  // namespace oidc
}  // namespace filters
}  // namespace authservice
