#include <thread>
#include <include/gmock/gmock-actions.h>
#include "gtest/gtest.h"
#include "src/filters/oidc/in_memory_session_store.h"
#include "test/common/utilities/mocks.h"

namespace authservice {
namespace filters {
namespace oidc {

using ::testing::Return;

class InMemorySessionStoreTest : public ::testing::Test {
public:
  InMemorySessionStoreTest();

protected:
  google::jwt_verify::Jwt id_token_jwt;
  std::shared_ptr<common::utilities::TimeServiceMock> time_service_mock_;

  void SetUp() override {
    auto jwt_status = id_token_jwt.parseFromString(
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMiwiYXVkIjpbImNsaWVudDEiXSwibm9uY2UiOiJyYW5kb20ifQ.NQi_VTRjZ8jv5cAp4inpuQ9STfVgCoWfONjLnZEMk8la8s99J9b6QmcKtO2tabTgvcseikVNlPuB6fZztY_fxhdrNE0dBNAl1lhz_AWBz6Yr-D82LLKk5NQ-IKDloF19Pic0Ub9pGCqNLOlmRXRVcfwwq5nISzfP6OdrjepRZ2Jd3rc2HvHYm-6GstH4xkKViABVwCDmwlAOi47bdHPByHkZOOnHSQEElr4tqO_uAQRpj36Yvt-95nPKhWaufZhcpYKk1H7ZRmylJQuG_dhlw4gN1i5iWBMk-Sj_2xyk05Bap1qkKSeHTxyqzhtDAH0LHYZdo_2hU-7YnL4JRhVVwg");
    ASSERT_EQ(jwt_status, google::jwt_verify::Status::Ok);
  }

  std::shared_ptr<TokenResponse> CreateTokenResponse();
};

InMemorySessionStoreTest::InMemorySessionStoreTest()
    : time_service_mock_(std::make_shared<testing::NiceMock<common::utilities::TimeServiceMock>>()) {}

std::shared_ptr<TokenResponse> InMemorySessionStoreTest::CreateTokenResponse() {
  auto token_response = std::make_shared<TokenResponse>(id_token_jwt);
  token_response->SetRefreshToken("fake_refresh_token");
  token_response->SetAccessToken("fake_access_token");
  token_response->SetAccessTokenExpiry(42);
  return token_response;
}

TEST_F(InMemorySessionStoreTest, SetTokenResponseAndGetTokenResponse) {
  InMemorySessionStore in_memory_session_store(time_service_mock_, 42, 128);
  auto session_id = std::string("fake_session_id");
  auto other_session_id = "other_session_id";
  auto token_response = CreateTokenResponse();

  auto result = in_memory_session_store.GetTokenResponse(session_id);
  ASSERT_FALSE(result);

  in_memory_session_store.SetTokenResponse(session_id, token_response);
  // Caution: when you mutate the original, you mutate the same object that is held in the session store's map
  token_response->SetAccessToken("fake_access_token2");

  result = in_memory_session_store.GetTokenResponse(other_session_id);
  ASSERT_FALSE(result);

  result = in_memory_session_store.GetTokenResponse(session_id);
  ASSERT_TRUE(result);
  ASSERT_EQ(result->IDToken().jwt_, id_token_jwt.jwt_);
  ASSERT_EQ(result->RefreshToken(), "fake_refresh_token");
  ASSERT_EQ(result->AccessToken(), "fake_access_token2"); // will be the mutated value, so be careful!
  ASSERT_EQ(result->GetAccessTokenExpiry(), 42);

  token_response->SetAccessTokenExpiry(99);
  in_memory_session_store.SetTokenResponse(session_id, token_response); // overwrite

  result = in_memory_session_store.GetTokenResponse(session_id);
  ASSERT_TRUE(result);
  ASSERT_EQ(result->IDToken().jwt_, id_token_jwt.jwt_);
  ASSERT_EQ(result->RefreshToken(), "fake_refresh_token");
  ASSERT_EQ(result->AccessToken(), "fake_access_token2");
  ASSERT_EQ(result->GetAccessTokenExpiry(), 99);
}

TEST_F(InMemorySessionStoreTest, SetAuthorizationStateAndClearAuthorizationStateAndGetAuthorizationState) {
  InMemorySessionStore in_memory_session_store(time_service_mock_, 42, 128);
  std::string session_id = "fake_session_id";
  std::string other_session_id = "other_session_id";
  std::string state = "some-state";
  std::string original_state(state);
  std::string nonce = "some-nonce";
  std::string original_nonce(nonce);
  std::string requested_url = "https://example.com";
  std::string original_requested_url(requested_url);
  auto authorization_state = std::make_shared<AuthorizationState>(state, nonce, requested_url);

  auto result = in_memory_session_store.GetAuthorizationState(session_id);
  ASSERT_FALSE(result);

  in_memory_session_store.ClearAuthorizationState(session_id); // does not crash
  ASSERT_FALSE(result);

  in_memory_session_store.SetAuthorizationState(session_id, authorization_state);

  result = in_memory_session_store.GetAuthorizationState(other_session_id);
  ASSERT_FALSE(result);

  // mutate original strings that were passed to AuthorizationState constructor, make sure it doesn't change AuthorizationState
  nonce += "-modified";
  state += "-modified";
  requested_url += "/modified";
  result = in_memory_session_store.GetAuthorizationState(session_id);
  ASSERT_TRUE(result);
  ASSERT_EQ(result->GetRequestedUrl(), original_requested_url);
  ASSERT_EQ(result->GetState(), original_state);
  ASSERT_EQ(result->GetNonce(), original_nonce);

  std::string another_state = "some-other-state";
  std::string another_nonce = "some-other-nonce";
  std::string another_requested_url = "https://other.example.com";
  auto another_authorization_state = std::make_shared<AuthorizationState>(another_state, another_nonce,
                                                                          another_requested_url);
  in_memory_session_store.SetAuthorizationState(session_id, another_authorization_state); // overwrite

  result = in_memory_session_store.GetAuthorizationState(session_id);
  ASSERT_TRUE(result);
  ASSERT_EQ(result->GetRequestedUrl(), another_requested_url);
  ASSERT_EQ(result->GetState(), another_state);
  ASSERT_EQ(result->GetNonce(), another_nonce);

  in_memory_session_store.ClearAuthorizationState(session_id);
  ASSERT_FALSE(in_memory_session_store.GetAuthorizationState(session_id));
}

TEST_F(InMemorySessionStoreTest, Remove) {
  InMemorySessionStore in_memory_session_store(time_service_mock_, 42, 128);
  auto session_id = std::string("fake_session_id");
  auto token_response = CreateTokenResponse();
  auto authorization_state = std::make_shared<AuthorizationState>("state", "nonce", "requested_url");

  in_memory_session_store.SetAuthorizationState(session_id, authorization_state);
  in_memory_session_store.SetTokenResponse(session_id, token_response);
  ASSERT_TRUE(in_memory_session_store.GetTokenResponse(session_id));
  ASSERT_TRUE(in_memory_session_store.GetAuthorizationState(session_id));

  in_memory_session_store.RemoveSession(session_id);

  ASSERT_FALSE(in_memory_session_store.GetTokenResponse(session_id));
  ASSERT_FALSE(in_memory_session_store.GetAuthorizationState(session_id));

  in_memory_session_store.RemoveSession("other-session-id"); // ignore non-existent keys without error
}

TEST_F(InMemorySessionStoreTest, RemoveAllExpired_RemovesSessionsWhichHaveExceededTheMaxAbsoluteSessionTimeout) {
  int absolute_session_timeout_in_seconds = 190;
  int idle_session_timeout_in_seconds = 1000;
  InMemorySessionStore in_memory_session_store(time_service_mock_, absolute_session_timeout_in_seconds,
                                               idle_session_timeout_in_seconds);

  // Create session that will expire
  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(5));
  auto session_id_will_expire = std::string("fake_session_id_1");
  auto token_response_will_expire = CreateTokenResponse();
  in_memory_session_store.SetTokenResponse(session_id_will_expire, token_response_will_expire);
  ASSERT_TRUE(in_memory_session_store.GetTokenResponse(session_id_will_expire));

  // Create session that will not expire
  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(20));
  auto session_id_will_not_expire = std::string("fake_session_id_2");
  auto token_response_will_not_expire = CreateTokenResponse();
  in_memory_session_store.SetTokenResponse(session_id_will_not_expire, token_response_will_not_expire);
  ASSERT_TRUE(in_memory_session_store.GetTokenResponse(session_id_will_not_expire));

  // After 30 seconds, neither should have been cleaned up
  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(30));
  in_memory_session_store.RemoveAllExpired();
  ASSERT_TRUE(
      in_memory_session_store.GetTokenResponse(session_id_will_expire)); // has been in for 25 seconds
  ASSERT_TRUE(
      in_memory_session_store.GetTokenResponse(session_id_will_not_expire)); // has been in for 10 seconds

  // After 200 seconds, the older session is cleand up but the younger one is not
  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(200));
  in_memory_session_store.RemoveAllExpired();
  ASSERT_FALSE(
      in_memory_session_store.GetTokenResponse(session_id_will_expire)); // has been in 195 seconds, evicted
  ASSERT_TRUE(
      in_memory_session_store.GetTokenResponse(
          session_id_will_not_expire)); // has been in for 180 seconds, not evicted
}

TEST_F(InMemorySessionStoreTest,
       RemoveAllExpired_DoesNotRemoveSessionsWhenTheMaxAbsoluteSessionTimeoutIsZeroUntilIdleIsReached) {
  InMemorySessionStore in_memory_session_store(time_service_mock_, 0, 1000);
  auto session_id = std::string("fake_session_id");
  auto token_response = CreateTokenResponse();

  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(5));

  in_memory_session_store.SetTokenResponse(session_id, token_response);
  ASSERT_TRUE(in_memory_session_store.GetTokenResponse(session_id));

  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(500));

  in_memory_session_store.RemoveAllExpired();
  ASSERT_TRUE(in_memory_session_store.GetTokenResponse(session_id));

  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(1501));
  in_memory_session_store.RemoveAllExpired();
  ASSERT_FALSE(in_memory_session_store.GetTokenResponse(
      session_id)); // removed due to idle timeout, don't care about time since added
}

TEST_F(InMemorySessionStoreTest,
       RemoveAllExpired_DoesNotRemoveSessionsWhenTheIdleSessionTimeoutIsZeroUntilMaxAbsoluteTimeoutIsReached) {
  InMemorySessionStore in_memory_session_store(time_service_mock_, 1000, 0);
  auto session_id = std::string("fake_session_id");
  auto token_response = CreateTokenResponse();

  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(5));

  in_memory_session_store.SetTokenResponse(session_id, token_response);
  ASSERT_TRUE(in_memory_session_store.GetTokenResponse(session_id));

  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(500));

  in_memory_session_store.RemoveAllExpired();
  ASSERT_TRUE(in_memory_session_store.GetTokenResponse(session_id));

  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(1004));
  ASSERT_TRUE(in_memory_session_store.GetTokenResponse(session_id));

  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(1006));
  in_memory_session_store.RemoveAllExpired();
  ASSERT_FALSE(in_memory_session_store.GetTokenResponse(
      session_id)); // removed due to max absolute timeout, even though it was just accessed
}

TEST_F(InMemorySessionStoreTest, RemoveAllExpired_DoesNotEverRemoveSessionsWhenBothTimeoutsAreZero) {
  InMemorySessionStore in_memory_session_store(time_service_mock_, 0, 0);
  auto session_id = std::string("fake_session_id");
  auto token_response = CreateTokenResponse();

  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(5));

  in_memory_session_store.SetTokenResponse(session_id, token_response);
  ASSERT_TRUE(in_memory_session_store.GetTokenResponse(session_id));

  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(100000000));

  in_memory_session_store.RemoveAllExpired();
  ASSERT_TRUE(in_memory_session_store.GetTokenResponse(session_id));
}

TEST_F(InMemorySessionStoreTest, RemoveAllExpired_RemovesSessionsWhichHaveExceededTheMaxIdleSessionTimeout) {
  InMemorySessionStore in_memory_session_store(time_service_mock_, 500, 50);

  // Create two sessions
  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(5));
  auto session_id_idle = std::string("fake_session_id_idle");
  auto token_response_idle = CreateTokenResponse();
  in_memory_session_store.SetTokenResponse(session_id_idle, token_response_idle);
  ASSERT_TRUE(in_memory_session_store.GetTokenResponse(session_id_idle));
  auto session_id_active = std::string("fake_session_id_active");
  auto token_response_active = CreateTokenResponse();
  in_memory_session_store.SetTokenResponse(session_id_active, token_response_active);
  ASSERT_TRUE(in_memory_session_store.GetTokenResponse(session_id_active));

  // Access both at time 30
  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(30));
  in_memory_session_store.RemoveAllExpired();
  ASSERT_TRUE(in_memory_session_store.GetTokenResponse(session_id_idle)); // last active 25 seconds ago
  ASSERT_TRUE(in_memory_session_store.GetTokenResponse(session_id_active)); // last active 25 seconds ago

  // Access only one of two at time 50
  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(50));
  ASSERT_TRUE(in_memory_session_store.GetTokenResponse(session_id_active)); // accessing at time 50

  // The idle session should be removed at time 90
  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(90));
  in_memory_session_store.RemoveAllExpired();
  ASSERT_FALSE(in_memory_session_store.GetTokenResponse(session_id_idle)); // last active 60 seconds ago
  ASSERT_TRUE(in_memory_session_store.GetTokenResponse(session_id_active)); // last active 40 seconds ago
}

TEST_F(InMemorySessionStoreTest, RemoveAllExpired_UpdatingTokenResponseKeepsSessionActive) {
  InMemorySessionStore in_memory_session_store(time_service_mock_, 500, 50);

  // Create two sessions
  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(5));
  auto session_id_idle = std::string("fake_session_id_idle");
  auto token_response_idle = CreateTokenResponse();
  in_memory_session_store.SetTokenResponse(session_id_idle, token_response_idle);
  ASSERT_TRUE(in_memory_session_store.GetTokenResponse(session_id_idle));
  auto session_id_active = std::string("fake_session_id_active");
  auto token_response_active = CreateTokenResponse();
  in_memory_session_store.SetTokenResponse(session_id_active, token_response_active);
  ASSERT_TRUE(in_memory_session_store.GetTokenResponse(session_id_active));

  // Access both at time 30
  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(30));
  in_memory_session_store.RemoveAllExpired();
  auto updated_token_response = CreateTokenResponse();
  in_memory_session_store.SetTokenResponse(session_id_idle, updated_token_response); // last active 25 seconds ago
  in_memory_session_store.SetTokenResponse(session_id_active, updated_token_response); // last active 25 seconds ago

  // Access only one of two at time 50
  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(50));
  in_memory_session_store.SetTokenResponse(session_id_active, updated_token_response); // accessing at time 50

  // The idle session should be removed at time 90
  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(90));
  in_memory_session_store.RemoveAllExpired();
  ASSERT_FALSE(in_memory_session_store.GetTokenResponse(session_id_idle)); // last active 60 seconds ago
  ASSERT_TRUE(in_memory_session_store.GetTokenResponse(session_id_active)); // last active 40 seconds ago
}

TEST_F(InMemorySessionStoreTest, RemoveAllExpired_UpdatingAuthorizationStateKeepsSessionActive) {
  InMemorySessionStore in_memory_session_store(time_service_mock_, 500, 50);
  auto authorization_state = std::make_shared<AuthorizationState>("state", "nonce", "requested_url");

  // Create two sessions
  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(5));
  auto session_id_idle = std::string("fake_session_id_idle");
  in_memory_session_store.SetAuthorizationState(session_id_idle, authorization_state);
  ASSERT_TRUE(in_memory_session_store.GetAuthorizationState(session_id_idle));
  auto session_id_active = std::string("fake_session_id_active");
  in_memory_session_store.SetAuthorizationState(session_id_active, authorization_state);
  ASSERT_TRUE(in_memory_session_store.GetAuthorizationState(session_id_active));

  // Access both at time 30
  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(30));
  in_memory_session_store.RemoveAllExpired();
  in_memory_session_store.SetAuthorizationState(session_id_idle, authorization_state); // last active 25 seconds ago
  in_memory_session_store.SetAuthorizationState(session_id_active, authorization_state); // last active 25 seconds ago

  // Access only one of two at time 50
  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(50));
  in_memory_session_store.SetAuthorizationState(session_id_active, authorization_state); // accessing at time 50

  // The idle session should be removed at time 90
  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(90));
  in_memory_session_store.RemoveAllExpired();
  ASSERT_FALSE(in_memory_session_store.GetAuthorizationState(session_id_idle)); // last active 60 seconds ago
  ASSERT_TRUE(in_memory_session_store.GetAuthorizationState(session_id_active)); // last active 40 seconds ago
}

TEST_F(InMemorySessionStoreTest, RemoveAllExpired_ClearAuthorizationStateKeepsSessionActive) {
  InMemorySessionStore in_memory_session_store(time_service_mock_, 500, 50);
  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(5));
  auto authorization_state = std::make_shared<AuthorizationState>("state", "nonce", "requested_url");

  // Create a session
  auto session_id_idle = std::string("fake_session_id_idle");
  in_memory_session_store.SetAuthorizationState(session_id_idle, authorization_state);
  auto token_response_idle = CreateTokenResponse();
  in_memory_session_store.SetTokenResponse(session_id_idle, token_response_idle);
  ASSERT_TRUE(in_memory_session_store.GetAuthorizationState(session_id_idle));

  // Create another session
  auto session_id_active = std::string("fake_session_id_active");
  in_memory_session_store.SetAuthorizationState(session_id_active, authorization_state);
  auto token_response_active = CreateTokenResponse();
  in_memory_session_store.SetTokenResponse(session_id_active, token_response_active);
  ASSERT_TRUE(in_memory_session_store.GetAuthorizationState(session_id_active));

  // Access both at time 30
  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(30));
  in_memory_session_store.RemoveAllExpired();
  in_memory_session_store.ClearAuthorizationState(session_id_idle); // last active 25 seconds ago
  in_memory_session_store.ClearAuthorizationState(session_id_active); // last active 25 seconds ago

  // Access only one of two at time 50
  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(50));
  in_memory_session_store.ClearAuthorizationState(session_id_active); // accessing at time 50

  // The idle session should be removed at time 90
  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(90));
  in_memory_session_store.RemoveAllExpired();
  ASSERT_FALSE(in_memory_session_store.GetTokenResponse(session_id_idle)); // last active 60 seconds ago
  ASSERT_TRUE(in_memory_session_store.GetTokenResponse(session_id_active)); // last active 40 seconds ago
}

TEST_F(InMemorySessionStoreTest,
       RemoveAllExpired_RemovesSessionsWhichHaveExceededTheMaxIdleSessionTimeoutEvenIfThatSessionWasNeverAccessed) {
  InMemorySessionStore in_memory_session_store(time_service_mock_, 0, 50);

  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(5));
  auto session_id_idle = std::string("fake_session_id_idle");
  auto token_response_idle = CreateTokenResponse();
  in_memory_session_store.SetTokenResponse(session_id_idle, token_response_idle);

  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(56));
  in_memory_session_store.RemoveAllExpired();
  ASSERT_FALSE(in_memory_session_store.GetTokenResponse(session_id_idle));
}

TEST_F(InMemorySessionStoreTest, RemoveAllExpired_RemovesAuthorizationStatesWhichHaveExceededTheAbsoluteTimeout) {
  int absolute_session_timeout_in_seconds = 190;
  int idle_session_timeout_in_seconds = 0;
  auto authorization_state1 = std::make_shared<AuthorizationState>("state1", "nonce1", "requested_url1");
  auto authorization_state2 = std::make_shared<AuthorizationState>("state2", "nonce2", "requested_url2");
  InMemorySessionStore in_memory_session_store(time_service_mock_, absolute_session_timeout_in_seconds,
                                               idle_session_timeout_in_seconds);

  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(5));
  auto session_id_will_expire = std::string("fake_session_id_1");
  in_memory_session_store.SetAuthorizationState(session_id_will_expire, authorization_state1);
  ASSERT_TRUE(in_memory_session_store.GetAuthorizationState(session_id_will_expire));

  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(20));
  auto session_id_will_not_expire = std::string("fake_session_id_2");
  in_memory_session_store.SetAuthorizationState(session_id_will_not_expire, authorization_state2);
  ASSERT_TRUE(in_memory_session_store.GetAuthorizationState(session_id_will_not_expire));

  // After 30 seconds, neither should have been cleaned up
  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(30));
  in_memory_session_store.RemoveAllExpired();
  ASSERT_TRUE(
      in_memory_session_store.GetAuthorizationState(session_id_will_expire)); // has been in for 25 seconds
  ASSERT_TRUE(
      in_memory_session_store.GetAuthorizationState(session_id_will_not_expire)); // has been in for 10 seconds

  // After 200 seconds, the older session is cleaned up but the younger one is not
  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(200));
  in_memory_session_store.RemoveAllExpired();
  ASSERT_FALSE(in_memory_session_store.GetAuthorizationState(
      session_id_will_expire)); // has been in 195 seconds, evicted
  ASSERT_TRUE(in_memory_session_store.GetAuthorizationState(
      session_id_will_not_expire)); // has been in for 180 seconds, not evicted
}

TEST_F(InMemorySessionStoreTest,
       RemoveAllExpired_RemovesAuthorizationStatesWhichHaveExceededTheMaxIdleSessionTimeout) {
  InMemorySessionStore in_memory_session_store(time_service_mock_, 500, 50);
  auto authorization_state_idle = std::make_shared<AuthorizationState>("state1", "nonce1", "requested_url1");
  auto authorization_state_active = std::make_shared<AuthorizationState>("state2", "nonce2", "requested_url2");

  // Create two sessions
  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(5));
  auto session_id_idle = std::string("fake_session_id_idle");
  in_memory_session_store.SetAuthorizationState(session_id_idle, authorization_state_idle);
  ASSERT_TRUE(in_memory_session_store.GetAuthorizationState(session_id_idle));
  auto session_id_active = std::string("fake_session_id_active");
  in_memory_session_store.SetAuthorizationState(session_id_active, authorization_state_active);
  ASSERT_TRUE(in_memory_session_store.GetAuthorizationState(session_id_active));

  // Access both at time 30
  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(30));
  in_memory_session_store.RemoveAllExpired();
  ASSERT_TRUE(in_memory_session_store.GetAuthorizationState(session_id_idle)); // last active 25 seconds ago
  ASSERT_TRUE(in_memory_session_store.GetAuthorizationState(session_id_active)); // last active 25 seconds ago

  // Access only one of two at time 50
  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(50));
  ASSERT_TRUE(in_memory_session_store.GetAuthorizationState(session_id_active)); // accessing at time 50

  // The idle session should be removed at time 90
  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(90));
  in_memory_session_store.RemoveAllExpired();
  ASSERT_FALSE(in_memory_session_store.GetAuthorizationState(session_id_idle)); // last active 60 seconds ago
  ASSERT_TRUE(in_memory_session_store.GetAuthorizationState(session_id_active)); // last active 40 seconds ago
}

// When the concurrency code is incorrect, this test will occasionally fail.
// If it fails, there is definitely something§ wrong with the concurrency code.
TEST_F(InMemorySessionStoreTest, ThreadSafetyForTokenResponseOperations) {
  InMemorySessionStore in_memory_session_store(time_service_mock_, 0, 0);
  std::vector<std::thread> threads;

  int thread_count = 10;
  int iterations = 5000;

  // Do lots of simultaneous set() and get()
  for (int i = 0; i < thread_count; ++i) {
    threads.emplace_back([iterations, i, &in_memory_session_store, this]() {
      for (int j = 1; j < iterations + 1; ++j) {
        auto token_response = CreateTokenResponse();
        int unique_number = (i * iterations) + j;
        token_response->SetAccessTokenExpiry(unique_number);
        auto key = std::string("session_id_") + std::to_string(unique_number);

        in_memory_session_store.SetTokenResponse(key, token_response);
        auto retrieved_optional_token_response = in_memory_session_store.GetTokenResponse(key);

        ASSERT_TRUE(retrieved_optional_token_response);
        ASSERT_TRUE(retrieved_optional_token_response->GetAccessTokenExpiry().has_value());
        ASSERT_EQ(retrieved_optional_token_response->GetAccessTokenExpiry().value(), unique_number);
      }
    });
  }
  for (auto &t : threads) {
    t.join();
  }

  threads.clear();

  // Do lots of simultaneous get() and remove()
  for (int i = 0; i < thread_count; ++i) {
    threads.emplace_back([iterations, i, &in_memory_session_store]() {
      for (int j = 1; j < iterations + 1; ++j) {
        int unique_number = (i * iterations) + j;
        auto key = std::string("session_id_") + std::to_string(unique_number);

        auto retrieved_token_response = in_memory_session_store.GetTokenResponse(key);
        ASSERT_TRUE(retrieved_token_response);
        ASSERT_EQ(retrieved_token_response->GetAccessTokenExpiry().value(), unique_number);
        in_memory_session_store.RemoveSession(key);
        ASSERT_FALSE(in_memory_session_store.GetTokenResponse(key));
      }
    });
  }
  for (auto &t : threads) {
    t.join();
  }
  threads.clear();
}

// When the concurrency code is incorrect, this test will occasionally fail.
// If it fails, there is definitely something wrong with the concurrency code.
TEST_F(InMemorySessionStoreTest, ThreadSafetyForClearAuthorizationState) {
  InMemorySessionStore in_memory_session_store(time_service_mock_, 0, 0);
  std::vector<std::thread> threads;

  int thread_count = 10;
  int iterations = 5000;

  // Do lots of set() and clear() at the same time that calls to remove() are happening, all on the same session.
  // Eventually clear() will be called on a session that has already been removed and cause a crash,
  // unless clear() is properly synchronized.
  for (int i = 0; i < thread_count; ++i) {
    threads.emplace_back([iterations, &in_memory_session_store]() {
      for (int j = 1; j < iterations + 1; ++j) {
        auto authorization_state = std::make_shared<AuthorizationState>("state", "nonce", "requested_url");
        in_memory_session_store.SetAuthorizationState("session_id", authorization_state);
        in_memory_session_store.ClearAuthorizationState("session_id");
      }
    });
  }
  for (int i = 0; i < thread_count; ++i) {
    threads.emplace_back([iterations, &in_memory_session_store]() {
      for (int j = 1; j < iterations + 1; ++j) {
        in_memory_session_store.RemoveSession("session_id");
      }
    });
  }
  for (auto &t : threads) {
    t.join();
  }
  threads.clear();
}

// When the concurrency code is incorrect, this test will occasionally fail.
// If it fails, there is definitely something wrong with the concurrency code.
TEST_F(InMemorySessionStoreTest, ThreadSafetyForGetAuthorizationState) {
  InMemorySessionStore in_memory_session_store(time_service_mock_, 0, 0);
  std::vector<std::thread> threads;

  int thread_count = 10;
  int iterations = 5000;

  // Do lots of set() and get() at the same time that calls to remove() are happening, all on the same session.
  // Eventually get() will be called on a session that has already been removed and cause a crash,
  // unless get() is properly synchronized.
  for (int i = 0; i < thread_count; ++i) {
    threads.emplace_back([iterations, &in_memory_session_store]() {
      for (int j = 1; j < iterations + 1; ++j) {
        auto authorization_state = std::make_shared<AuthorizationState>("state", "nonce", "requested_url");
        in_memory_session_store.SetAuthorizationState("session_id", authorization_state);
        in_memory_session_store.GetAuthorizationState("session_id");
      }
    });
  }
  for (int i = 0; i < thread_count; ++i) {
    threads.emplace_back([iterations, &in_memory_session_store]() {
      for (int j = 1; j < iterations + 1; ++j) {
        in_memory_session_store.RemoveSession("session_id");
      }
    });
  }
  for (auto &t : threads) {
    t.join();
  }
  threads.clear();
}

// When the concurrency code is incorrect, this test will occasionally fail.
// If it fails, there is definitely something wrong with the concurrency code.
TEST_F(InMemorySessionStoreTest, ThreadSafetyForSetAuthorizationState) {
  InMemorySessionStore in_memory_session_store(time_service_mock_, 0, 0);
  std::vector<std::thread> threads;

  int thread_count = 10;
  int iterations = 5000;

  // Do lots of simultaneous set() and get() on various sessions.
  // Eventually a set() will fail if set() is not properly synchronized.
  for (int i = 0; i < thread_count; ++i) {
    // Each thread has its own instance of URL because otherwise the threads clobber the URL
    threads.emplace_back([iterations, i, &in_memory_session_store]() {
      for (int j = 1; j < iterations + 1; ++j) {
        int unique_number = (i * iterations) + j;
        auto key = std::string("session_id_") + std::to_string(unique_number);
        auto unique_url = std::string("https://example.com") + std::to_string(unique_number);
        auto authorization_state = std::make_shared<AuthorizationState>("state", "nonce", unique_url);

        in_memory_session_store.SetAuthorizationState(key, authorization_state);

        auto retrieved_optional_authorization_state = in_memory_session_store.GetAuthorizationState(key);
        ASSERT_TRUE(retrieved_optional_authorization_state);
        ASSERT_EQ(retrieved_optional_authorization_state->GetRequestedUrl(), unique_url);
      }
    });
  }
  for (auto &t : threads) {
    t.join();
  }
  threads.clear();
}

}  // namespace oidc
}  // namespace filters
}  // namespace authservice
