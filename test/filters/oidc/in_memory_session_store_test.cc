#include <thread>
#include <include/gmock/gmock-actions.h>
#include <spdlog/spdlog.h>
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
  ASSERT_FALSE(result.has_value());

  in_memory_session_store.SetTokenResponse(session_id, *token_response);
  // mutate the original to make sure that on the get() we're getting back a copy of the original made at the time of set()
  token_response->SetAccessToken("fake_access_token2");

  result = in_memory_session_store.GetTokenResponse(other_session_id);
  ASSERT_FALSE(result.has_value());

  result = in_memory_session_store.GetTokenResponse(session_id);
  ASSERT_TRUE(result.has_value());
  ASSERT_EQ(result.value().IDToken().jwt_, id_token_jwt.jwt_);
  ASSERT_EQ(result.value().RefreshToken(), "fake_refresh_token");
  ASSERT_EQ(result.value().AccessToken(), "fake_access_token");
  ASSERT_EQ(result.value().GetAccessTokenExpiry(), 42);

  token_response->SetAccessTokenExpiry(99);
  in_memory_session_store.SetTokenResponse(session_id, *token_response); // overwrite

  result = in_memory_session_store.GetTokenResponse(session_id);
  ASSERT_TRUE(result.has_value());
  ASSERT_EQ(result.value().IDToken().jwt_, id_token_jwt.jwt_);
  ASSERT_EQ(result.value().RefreshToken(), "fake_refresh_token");
  ASSERT_EQ(result.value().AccessToken(), "fake_access_token2");
  ASSERT_EQ(result.value().GetAccessTokenExpiry(), 99);
}

TEST_F(InMemorySessionStoreTest, SetRequestedURLAndGetRequestedURL) {
  InMemorySessionStore in_memory_session_store(time_service_mock_, 42, 128);
  auto session_id = std::string("fake_session_id");
  auto other_session_id = "other_session_id";
  auto requested_url = "https://example.com";

  auto result = in_memory_session_store.GetRequestedURL(session_id);
  ASSERT_FALSE(result.has_value());

  in_memory_session_store.SetRequestedURL(session_id, requested_url);
  // mutate the original to make sure that on the get() we're getting back a copy of the original made at the time of SetRequestedURL()
  requested_url = "https://example2.com";

  result = in_memory_session_store.GetRequestedURL(other_session_id);
  ASSERT_FALSE(result.has_value());

  result = in_memory_session_store.GetRequestedURL(session_id);
  ASSERT_TRUE(result.has_value());
  ASSERT_EQ(result, "https://example.com");

  in_memory_session_store.SetRequestedURL(session_id, requested_url); // overwrite

  result = in_memory_session_store.GetRequestedURL(session_id);
  ASSERT_TRUE(result.has_value());
  ASSERT_EQ(result, "https://example2.com");
}

TEST_F(InMemorySessionStoreTest, Remove) {
  InMemorySessionStore in_memory_session_store(time_service_mock_, 42, 128);
  auto session_id = std::string("fake_session_id");
  auto token_response = CreateTokenResponse();

  in_memory_session_store.SetRequestedURL(session_id, "some-url");
  in_memory_session_store.SetTokenResponse(session_id, *token_response);
  ASSERT_TRUE(in_memory_session_store.GetTokenResponse(session_id).has_value());
  ASSERT_TRUE(in_memory_session_store.GetRequestedURL(session_id).has_value());
  in_memory_session_store.RemoveSession(session_id);
  ASSERT_FALSE(in_memory_session_store.GetTokenResponse(session_id).has_value());
  ASSERT_FALSE(in_memory_session_store.GetRequestedURL(session_id).has_value());

  in_memory_session_store.RemoveSession("other-session-id"); // ignore non-existent keys without error
}

TEST_F(InMemorySessionStoreTest, RemoveAllExpired_RemovesSessionsWhichHaveExceededTheMaxAbsoluteSessionTimeout) {
  int max_absolute_session_timeout_in_seconds = 190;
  int max_session_idle_timeout_in_seconds = 1000;
  InMemorySessionStore in_memory_session_store(time_service_mock_, max_absolute_session_timeout_in_seconds,
                                               max_session_idle_timeout_in_seconds);

  // Create session that will expire
  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(5));
  auto session_id_will_expire = std::string("fake_session_id_1");
  auto token_response_will_expire = CreateTokenResponse();
  in_memory_session_store.SetTokenResponse(session_id_will_expire, *token_response_will_expire);
  ASSERT_TRUE(in_memory_session_store.GetTokenResponse(session_id_will_expire).has_value());

  // Create session that will not expire
  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(20));
  auto session_id_will_not_expire = std::string("fake_session_id_2");
  auto token_response_will_not_expire = CreateTokenResponse();
  in_memory_session_store.SetTokenResponse(session_id_will_not_expire, *token_response_will_not_expire);
  ASSERT_TRUE(in_memory_session_store.GetTokenResponse(session_id_will_not_expire).has_value());

  // After 30 seconds, neither should have been cleaned up
  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(30));
  in_memory_session_store.RemoveAllExpired();
  ASSERT_TRUE(
      in_memory_session_store.GetTokenResponse(session_id_will_expire).has_value()); // has been in for 25 seconds
  ASSERT_TRUE(
      in_memory_session_store.GetTokenResponse(session_id_will_not_expire).has_value()); // has been in for 10 seconds

  // After 200 seconds, the older session is cleand up but the younger one is not
  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(200));
  in_memory_session_store.RemoveAllExpired();
  ASSERT_FALSE(
      in_memory_session_store.GetTokenResponse(session_id_will_expire).has_value()); // has been in 195 seconds, evicted
  ASSERT_TRUE(
      in_memory_session_store.GetTokenResponse(
          session_id_will_not_expire).has_value()); // has been in for 180 seconds, not evicted
}

TEST_F(InMemorySessionStoreTest,
       RemoveAllExpired_DoesNotRemoveSessionsWhenTheMaxAbsoluteSessionTimeoutIsZeroUntilIdleIsReached) {
  InMemorySessionStore in_memory_session_store(time_service_mock_, 0, 1000);
  auto session_id = std::string("fake_session_id");
  auto token_response = CreateTokenResponse();

  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(5));

  in_memory_session_store.SetTokenResponse(session_id, *token_response);
  ASSERT_TRUE(in_memory_session_store.GetTokenResponse(session_id).has_value());

  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(500));

  in_memory_session_store.RemoveAllExpired();
  ASSERT_TRUE(in_memory_session_store.GetTokenResponse(session_id).has_value());

  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(1501));
  in_memory_session_store.RemoveAllExpired();
  ASSERT_FALSE(in_memory_session_store.GetTokenResponse(
      session_id).has_value()); // removed due to idle timeout, don't care about time since added
}

TEST_F(InMemorySessionStoreTest,
       RemoveAllExpired_DoesNotRemoveSessionsWhenTheIdleSessionTimeoutIsZeroUntilMaxAbsoluteTimeoutIsReached) {
  InMemorySessionStore in_memory_session_store(time_service_mock_, 1000, 0);
  auto session_id = std::string("fake_session_id");
  auto token_response = CreateTokenResponse();

  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(5));

  in_memory_session_store.SetTokenResponse(session_id, *token_response);
  ASSERT_TRUE(in_memory_session_store.GetTokenResponse(session_id).has_value());

  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(500));

  in_memory_session_store.RemoveAllExpired();
  ASSERT_TRUE(in_memory_session_store.GetTokenResponse(session_id).has_value());

  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(1004));
  ASSERT_TRUE(in_memory_session_store.GetTokenResponse(session_id).has_value());

  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(1006));
  in_memory_session_store.RemoveAllExpired();
  ASSERT_FALSE(in_memory_session_store.GetTokenResponse(
      session_id).has_value()); // removed due to max absolute timeout, even though it was just accessed
}

TEST_F(InMemorySessionStoreTest, RemoveAllExpired_DoesNotEverRemoveSessionsWhenBothTimeoutsAreZero) {
  InMemorySessionStore in_memory_session_store(time_service_mock_, 0, 0);
  auto session_id = std::string("fake_session_id");
  auto token_response = CreateTokenResponse();

  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(5));

  in_memory_session_store.SetTokenResponse(session_id, *token_response);
  ASSERT_TRUE(in_memory_session_store.GetTokenResponse(session_id).has_value());

  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(100000000));

  in_memory_session_store.RemoveAllExpired();
  ASSERT_TRUE(in_memory_session_store.GetTokenResponse(session_id).has_value());
}

TEST_F(InMemorySessionStoreTest, RemoveAllExpired_RemovesSessionsWhichHaveExceededTheMaxIdleSessionTimeout) {
  InMemorySessionStore in_memory_session_store(time_service_mock_, 500, 50);

  // Create two sessions
  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(5));
  auto session_id_idle = std::string("fake_session_id_idle");
  auto token_response_idle = CreateTokenResponse();
  in_memory_session_store.SetTokenResponse(session_id_idle, *token_response_idle);
  ASSERT_TRUE(in_memory_session_store.GetTokenResponse(session_id_idle).has_value());
  auto session_id_active = std::string("fake_session_id_active");
  auto token_response_active = CreateTokenResponse();
  in_memory_session_store.SetTokenResponse(session_id_active, *token_response_active);
  ASSERT_TRUE(in_memory_session_store.GetTokenResponse(session_id_active).has_value());

  // Access both at time 30
  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(30));
  in_memory_session_store.RemoveAllExpired();
  ASSERT_TRUE(in_memory_session_store.GetTokenResponse(session_id_idle).has_value()); // last active 25 seconds ago
  ASSERT_TRUE(in_memory_session_store.GetTokenResponse(session_id_active).has_value()); // last active 25 seconds ago

  // Access only one of two at time 50
  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(50));
  ASSERT_TRUE(in_memory_session_store.GetTokenResponse(session_id_active).has_value()); // accessing at time 50

  // The idle session should be removed at time 90
  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(90));
  in_memory_session_store.RemoveAllExpired();
  ASSERT_FALSE(in_memory_session_store.GetTokenResponse(session_id_idle).has_value()); // last active 60 seconds ago
  ASSERT_TRUE(in_memory_session_store.GetTokenResponse(session_id_active).has_value()); // last active 40 seconds ago
}

TEST_F(InMemorySessionStoreTest, RemoveAllExpired_UpdatingTokenResponseKeepsSessionActive) {
  InMemorySessionStore in_memory_session_store(time_service_mock_, 500, 50);

  // Create two sessions
  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(5));
  auto session_id_idle = std::string("fake_session_id_idle");
  auto token_response_idle = CreateTokenResponse();
  in_memory_session_store.SetTokenResponse(session_id_idle, *token_response_idle);
  ASSERT_TRUE(in_memory_session_store.GetTokenResponse(session_id_idle).has_value());
  auto session_id_active = std::string("fake_session_id_active");
  auto token_response_active = CreateTokenResponse();
  in_memory_session_store.SetTokenResponse(session_id_active, *token_response_active);
  ASSERT_TRUE(in_memory_session_store.GetTokenResponse(session_id_active).has_value());

  // Access both at time 30
  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(30));
  in_memory_session_store.RemoveAllExpired();
  auto updated_token_response = CreateTokenResponse();
  in_memory_session_store.SetTokenResponse(session_id_idle, *updated_token_response); // last active 25 seconds ago
  in_memory_session_store.SetTokenResponse(session_id_active, *updated_token_response); // last active 25 seconds ago

  // Access only one of two at time 50
  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(50));
  in_memory_session_store.SetTokenResponse(session_id_active, *updated_token_response); // accessing at time 50

  // The idle session should be removed at time 90
  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(90));
  in_memory_session_store.RemoveAllExpired();
  ASSERT_FALSE(in_memory_session_store.GetTokenResponse(session_id_idle).has_value()); // last active 60 seconds ago
  ASSERT_TRUE(in_memory_session_store.GetTokenResponse(session_id_active).has_value()); // last active 40 seconds ago
}

TEST_F(InMemorySessionStoreTest, RemoveAllExpired_UpdatingRequestedUrlKeepsSessionActive) {
  InMemorySessionStore in_memory_session_store(time_service_mock_, 500, 50);

  // Create two sessions
  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(5));
  auto session_id_idle = std::string("fake_session_id_idle");
  in_memory_session_store.SetRequestedURL(session_id_idle, "https://example.com");
  ASSERT_TRUE(in_memory_session_store.GetRequestedURL(session_id_idle).has_value());
  auto session_id_active = std::string("fake_session_id_active");
  in_memory_session_store.SetRequestedURL(session_id_active, "https://example.com");
  ASSERT_TRUE(in_memory_session_store.GetRequestedURL(session_id_active).has_value());

  // Access both at time 30
  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(30));
  in_memory_session_store.RemoveAllExpired();
  in_memory_session_store.SetRequestedURL(session_id_idle, "https://example.com"); // last active 25 seconds ago
  in_memory_session_store.SetRequestedURL(session_id_active, "https://example.com"); // last active 25 seconds ago

  // Access only one of two at time 50
  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(50));
  in_memory_session_store.SetRequestedURL(session_id_active, "https://example.com"); // accessing at time 50

  // The idle session should be removed at time 90
  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(90));
  in_memory_session_store.RemoveAllExpired();
  ASSERT_FALSE(in_memory_session_store.GetRequestedURL(session_id_idle).has_value()); // last active 60 seconds ago
  ASSERT_TRUE(in_memory_session_store.GetRequestedURL(session_id_active).has_value()); // last active 40 seconds ago
}

TEST_F(InMemorySessionStoreTest,
       RemoveAllExpired_RemovesSessionsWhichHaveExceededTheMaxIdleSessionTimeoutEvenIfThatSessionWasNeverAccessed) {
  InMemorySessionStore in_memory_session_store(time_service_mock_, 0, 50);

  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(5));
  auto session_id_idle = std::string("fake_session_id_idle");
  auto token_response_idle = CreateTokenResponse();
  in_memory_session_store.SetTokenResponse(session_id_idle, *token_response_idle);

  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(56));
  in_memory_session_store.RemoveAllExpired();
  ASSERT_FALSE(in_memory_session_store.GetTokenResponse(session_id_idle).has_value());
}

TEST_F(InMemorySessionStoreTest, RemoveAllExpired_RemovesSessionsOfRequestedURLWhichHaveExceededTheAbsoluteTimeout) {
  int max_absolute_session_timeout_in_seconds = 190;
  int max_session_idle_timeout_in_seconds = 0;
  InMemorySessionStore in_memory_session_store(time_service_mock_, max_absolute_session_timeout_in_seconds,
                                               max_session_idle_timeout_in_seconds);

  // Create session of requested URL that will expire
  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(5));
  auto session_id_will_expire = std::string("fake_session_id_1");
  in_memory_session_store.SetRequestedURL(session_id_will_expire, "https://example1.com");
  ASSERT_TRUE(in_memory_session_store.GetRequestedURL(session_id_will_expire).has_value());

  // Create session of requested URL that will not expire
  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(20));
  auto session_id_will_not_expire = std::string("fake_session_id_2");
  in_memory_session_store.SetRequestedURL(session_id_will_not_expire, "https://example2.com");
  ASSERT_TRUE(in_memory_session_store.GetRequestedURL(session_id_will_not_expire).has_value());

  // After 30 seconds, neither should have been cleaned up
  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(30));
  in_memory_session_store.RemoveAllExpired();
  ASSERT_TRUE(
      in_memory_session_store.GetRequestedURL(session_id_will_expire).has_value()); // has been in for 25 seconds
  ASSERT_TRUE(
      in_memory_session_store.GetRequestedURL(session_id_will_not_expire).has_value()); // has been in for 10 seconds

  // After 200 seconds, the older session is cleaned up but the younger one is not
  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(200));
  in_memory_session_store.RemoveAllExpired();
  ASSERT_FALSE(in_memory_session_store.GetRequestedURL(
      session_id_will_expire).has_value()); // has been in 195 seconds, evicted
  ASSERT_TRUE(in_memory_session_store.GetRequestedURL(
      session_id_will_not_expire).has_value()); // has been in for 180 seconds, not evicted
}

TEST_F(InMemorySessionStoreTest,
       RemoveAllExpired_RemovesSessionsOfRequestedUrlsWhichHaveExceededTheMaxIdleSessionTimeout) {
  InMemorySessionStore in_memory_session_store(time_service_mock_, 500, 50);

  // Create two sessions
  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(5));
  auto session_id_idle = std::string("fake_session_id_idle");
  in_memory_session_store.SetRequestedURL(session_id_idle, "https://example.com?1");
  ASSERT_TRUE(in_memory_session_store.GetRequestedURL(session_id_idle).has_value());
  auto session_id_active = std::string("fake_session_id_active");
  in_memory_session_store.SetRequestedURL(session_id_active, "https://example.com?2");
  ASSERT_TRUE(in_memory_session_store.GetRequestedURL(session_id_active).has_value());

  // Access both at time 30
  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(30));
  in_memory_session_store.RemoveAllExpired();
  ASSERT_TRUE(in_memory_session_store.GetRequestedURL(session_id_idle).has_value()); // last active 25 seconds ago
  ASSERT_TRUE(in_memory_session_store.GetRequestedURL(session_id_active).has_value()); // last active 25 seconds ago

  // Access only one of two at time 50
  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(50));
  ASSERT_TRUE(in_memory_session_store.GetRequestedURL(session_id_active).has_value()); // accessing at time 50

  // The idle session should be removed at time 90
  EXPECT_CALL(*time_service_mock_, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(90));
  in_memory_session_store.RemoveAllExpired();
  ASSERT_FALSE(in_memory_session_store.GetRequestedURL(session_id_idle).has_value()); // last active 60 seconds ago
  ASSERT_TRUE(in_memory_session_store.GetRequestedURL(session_id_active).has_value()); // last active 40 seconds ago
}

TEST_F(InMemorySessionStoreTest, ThreadSafetyForTokenResponseOperations) {
  InMemorySessionStore in_memory_session_store(time_service_mock_, 0, 0);
  std::vector<std::thread> threads;

  int thread_count = 10;
  int iterations = 1000;
  // Do lots of simultaneous sets and gets
  for (int i = 0; i < thread_count; ++i) {
    // Each thread has its own instance of token_response because otherwise the threads clobber the token_response
    auto token_response = CreateTokenResponse();
    threads.emplace_back([iterations, i, &in_memory_session_store, token_response]() {
      for (int j = 1; j < iterations + 1; ++j) {
        int unique_number = (i * iterations) + j;
        token_response->SetAccessTokenExpiry(unique_number);
        auto key = std::string("session_id_") + std::to_string(unique_number);

        in_memory_session_store.SetTokenResponse(key, *token_response);
        auto retrieved_optional_token_response = in_memory_session_store.GetTokenResponse(key);

        ASSERT_TRUE(retrieved_optional_token_response.has_value());
        ASSERT_TRUE(retrieved_optional_token_response->GetAccessTokenExpiry().has_value());
        ASSERT_EQ(retrieved_optional_token_response->GetAccessTokenExpiry().value(), unique_number);
      }
    });
  }
  for (auto &t : threads) {
    t.join();
  }

  threads.clear();

  // Do lots of simultaneous gets and removes
  for (int i = 0; i < thread_count; ++i) {
    threads.emplace_back([iterations, i, &in_memory_session_store]() {
      for (int j = 1; j < iterations + 1; ++j) {
        int unique_number = (i * iterations) + j;
        auto key = std::string("session_id_") + std::to_string(unique_number);

        auto retrieved_token_response = in_memory_session_store.GetTokenResponse(key);
        ASSERT_TRUE(retrieved_token_response.has_value());
        ASSERT_EQ(retrieved_token_response->GetAccessTokenExpiry().value(), unique_number);
        in_memory_session_store.RemoveSession(key);
        ASSERT_FALSE(in_memory_session_store.GetTokenResponse(key).has_value());
      }
    });
  }
  for (auto &t : threads) {
    t.join();
  }
  threads.clear();
}

TEST_F(InMemorySessionStoreTest, ThreadSafetyForRequestedURLOperations) {
  InMemorySessionStore in_memory_session_store(time_service_mock_, 0, 0);
  std::vector<std::thread> threads;

  int thread_count = 10;
  int iterations = 1000;

  // Do lots of simultaneous sets and gets
  for (int i = 0; i < thread_count; ++i) {
    // Each thread has its own instance of URL because otherwise the threads clobber the URL
    auto token_response = CreateTokenResponse();
    threads.emplace_back([iterations, i, &in_memory_session_store, token_response]() {
      for (int j = 1; j < iterations + 1; ++j) {
        int unique_number = (i * iterations) + j;
        auto key = std::string("session_id_") + std::to_string(unique_number);
        auto unique_url = std::string("https://example.com") + std::to_string(unique_number);

        in_memory_session_store.SetRequestedURL(key, unique_url);
        auto retrieved_optional_url = in_memory_session_store.GetRequestedURL(key);

        ASSERT_TRUE(retrieved_optional_url.has_value());
        ASSERT_EQ(retrieved_optional_url.value(), unique_url);
      }
    });
  }
  for (auto &t : threads) {
    t.join();
  }
  threads.clear();


  // Do lots of simultaneous gets and removes
  for (int i = 0; i < thread_count; ++i) {
    threads.emplace_back([iterations, i, &in_memory_session_store]() {
      for (int j = 1; j < iterations + 1; ++j) {
        int unique_number = (i * iterations) + j;
        auto key = std::string("session_id_") + std::to_string(unique_number);

        auto retrieved_optional_url = in_memory_session_store.GetRequestedURL(key);
        ASSERT_TRUE(retrieved_optional_url.has_value());
        in_memory_session_store.RemoveSession(key);
        ASSERT_FALSE(in_memory_session_store.GetRequestedURL(key).has_value());
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
