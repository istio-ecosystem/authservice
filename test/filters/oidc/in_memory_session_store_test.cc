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
protected:
  google::jwt_verify::Jwt id_token_jwt;

  void SetUp() override {
    auto jwt_status = id_token_jwt.parseFromString(
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMiwiYXVkIjpbImNsaWVudDEiXSwibm9uY2UiOiJyYW5kb20ifQ.NQi_VTRjZ8jv5cAp4inpuQ9STfVgCoWfONjLnZEMk8la8s99J9b6QmcKtO2tabTgvcseikVNlPuB6fZztY_fxhdrNE0dBNAl1lhz_AWBz6Yr-D82LLKk5NQ-IKDloF19Pic0Ub9pGCqNLOlmRXRVcfwwq5nISzfP6OdrjepRZ2Jd3rc2HvHYm-6GstH4xkKViABVwCDmwlAOi47bdHPByHkZOOnHSQEElr4tqO_uAQRpj36Yvt-95nPKhWaufZhcpYKk1H7ZRmylJQuG_dhlw4gN1i5iWBMk-Sj_2xyk05Bap1qkKSeHTxyqzhtDAH0LHYZdo_2hU-7YnL4JRhVVwg");
    ASSERT_EQ(jwt_status, google::jwt_verify::Status::Ok);
  }

  std::shared_ptr<TokenResponse> CreateTokenResponse();
};

std::shared_ptr<TokenResponse> InMemorySessionStoreTest::CreateTokenResponse() {
  auto token_response = std::make_shared<TokenResponse>(id_token_jwt);
  token_response->SetRefreshToken("fake_refresh_token");
  token_response->SetAccessToken("fake_access_token");
  token_response->SetAccessTokenExpiry(42);
  return token_response;
}


TEST_F(InMemorySessionStoreTest, SetAndGet) {
  InMemorySessionStore in_memory_session_store(std::make_shared<common::utilities::TimeServiceMock>(), 42, 128);
  auto session_id = std::string("fake_session_id");
  auto other_session_id = "other_session_id";
  auto token_response = CreateTokenResponse();

  auto result = in_memory_session_store.Get(session_id);
  ASSERT_FALSE(result.has_value());

  in_memory_session_store.Set(session_id, *token_response);
  // mutate the original to make sure that on the get() we're getting back a copy of the original made at the time of set()
  token_response->SetAccessToken("fake_access_token2");

  result = in_memory_session_store.Get(session_id);
  ASSERT_TRUE(result.has_value());
  ASSERT_EQ(result.value().IDToken().jwt_, id_token_jwt.jwt_);
  ASSERT_EQ(result.value().RefreshToken(), "fake_refresh_token");
  ASSERT_EQ(result.value().AccessToken(), "fake_access_token");
  ASSERT_EQ(result.value().GetAccessTokenExpiry(), 42);

  token_response->SetAccessTokenExpiry(99);
  in_memory_session_store.Set(session_id, *token_response); // overwrite

  result = in_memory_session_store.Get(session_id);
  ASSERT_TRUE(result.has_value());
  ASSERT_EQ(result.value().IDToken().jwt_, id_token_jwt.jwt_);
  ASSERT_EQ(result.value().RefreshToken(), "fake_refresh_token");
  ASSERT_EQ(result.value().AccessToken(), "fake_access_token2");
  ASSERT_EQ(result.value().GetAccessTokenExpiry(), 99);

  result = in_memory_session_store.Get(other_session_id);
  ASSERT_FALSE(result.has_value());
}

TEST_F(InMemorySessionStoreTest, Remove) {
  InMemorySessionStore in_memory_session_store(std::make_shared<common::utilities::TimeServiceMock>(), 42, 128);
  auto session_id = std::string("fake_session_id");
  auto token_response = CreateTokenResponse();

  in_memory_session_store.Set(session_id, *token_response);
  ASSERT_TRUE(in_memory_session_store.Get(session_id).has_value());
  in_memory_session_store.Remove(session_id);
  ASSERT_FALSE(in_memory_session_store.Get(session_id).has_value());

  in_memory_session_store.Remove("other-session-id"); // ignore non-existent keys without error
}

TEST_F(InMemorySessionStoreTest, RemoveAllExpired_RemovesSessionsWhichHaveExceededTheMaxAbsoluteSessionTimeout) {
  const std::shared_ptr<common::utilities::TimeServiceMock> &time_service_mock = std::make_shared<common::utilities::TimeServiceMock>();
  InMemorySessionStore in_memory_session_store(time_service_mock, 190, 1000);
  auto session_id_will_expire = std::string("fake_session_id_1");
  auto token_response_will_expire = CreateTokenResponse();

  auto session_id_will_not_expire = std::string("fake_session_id_2");
  auto token_response_will_not_expire = CreateTokenResponse();

  EXPECT_CALL(*time_service_mock, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(5));

  in_memory_session_store.Set(session_id_will_expire, *token_response_will_expire);
  ASSERT_TRUE(in_memory_session_store.Get(session_id_will_expire).has_value());

  EXPECT_CALL(*time_service_mock, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(20));

  in_memory_session_store.Set(session_id_will_not_expire, *token_response_will_not_expire);
  ASSERT_TRUE(in_memory_session_store.Get(session_id_will_not_expire).has_value());

  EXPECT_CALL(*time_service_mock, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(30));

  in_memory_session_store.RemoveAllExpired();
  ASSERT_TRUE(in_memory_session_store.Get(session_id_will_expire).has_value()); // has been in for 25 seconds
  ASSERT_TRUE(in_memory_session_store.Get(session_id_will_not_expire).has_value()); // has been in for 10 seconds

  EXPECT_CALL(*time_service_mock, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(200));

  in_memory_session_store.RemoveAllExpired();
  ASSERT_FALSE(in_memory_session_store.Get(session_id_will_expire).has_value()); // has been in 195 seconds, evicted
  ASSERT_TRUE(
      in_memory_session_store.Get(session_id_will_not_expire).has_value()); // has been in for 180 seconds, not evicted
}

TEST_F(InMemorySessionStoreTest,
       RemoveAllExpired_DoesNotRemoveSessionsWhenTheMaxAbsoluteSessionTimeoutIsZeroUntilIdleIsReached) {
  const std::shared_ptr<common::utilities::TimeServiceMock> &time_service_mock = std::make_shared<common::utilities::TimeServiceMock>();
  InMemorySessionStore in_memory_session_store(time_service_mock, 0, 1000);
  auto session_id = std::string("fake_session_id");
  auto token_response = CreateTokenResponse();

  EXPECT_CALL(*time_service_mock, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(5));

  in_memory_session_store.Set(session_id, *token_response);
  ASSERT_TRUE(in_memory_session_store.Get(session_id).has_value());

  EXPECT_CALL(*time_service_mock, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(500));

  in_memory_session_store.RemoveAllExpired();
  ASSERT_TRUE(in_memory_session_store.Get(session_id).has_value());

  EXPECT_CALL(*time_service_mock, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(1501));
  in_memory_session_store.RemoveAllExpired();
  ASSERT_FALSE(in_memory_session_store.Get(
      session_id).has_value()); // removed due to idle timeout, don't care about time since added
}

TEST_F(InMemorySessionStoreTest,
       RemoveAllExpired_DoesNotRemoveSessionsWhenTheIdleSessionTimeoutIsZeroUntilMaxAbsoluteTimeoutIsReached) {
  const std::shared_ptr<common::utilities::TimeServiceMock> &time_service_mock = std::make_shared<common::utilities::TimeServiceMock>();
  InMemorySessionStore in_memory_session_store(time_service_mock, 1000, 0);
  auto session_id = std::string("fake_session_id");
  auto token_response = CreateTokenResponse();

  EXPECT_CALL(*time_service_mock, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(5));

  in_memory_session_store.Set(session_id, *token_response);
  ASSERT_TRUE(in_memory_session_store.Get(session_id).has_value());

  EXPECT_CALL(*time_service_mock, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(500));

  in_memory_session_store.RemoveAllExpired();
  ASSERT_TRUE(in_memory_session_store.Get(session_id).has_value());

  EXPECT_CALL(*time_service_mock, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(1004));
  ASSERT_TRUE(in_memory_session_store.Get(session_id).has_value());

  EXPECT_CALL(*time_service_mock, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(1006));
  in_memory_session_store.RemoveAllExpired();
  ASSERT_FALSE(in_memory_session_store.Get(
      session_id).has_value()); // removed due to max absolute timeout, even though it was just accessed
}

TEST_F(InMemorySessionStoreTest, RemoveAllExpired_DoesNotEverRemoveSessionsWhenBothTimeoutsAreZero) {
  const std::shared_ptr<common::utilities::TimeServiceMock> &time_service_mock = std::make_shared<common::utilities::TimeServiceMock>();
  InMemorySessionStore in_memory_session_store(time_service_mock, 0, 0);
  auto session_id = std::string("fake_session_id");
  auto token_response = CreateTokenResponse();

  EXPECT_CALL(*time_service_mock, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(5));

  in_memory_session_store.Set(session_id, *token_response);
  ASSERT_TRUE(in_memory_session_store.Get(session_id).has_value());

  EXPECT_CALL(*time_service_mock, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(100000000));

  in_memory_session_store.RemoveAllExpired();
  ASSERT_TRUE(in_memory_session_store.Get(session_id).has_value());
}

TEST_F(InMemorySessionStoreTest, RemoveAllExpired_RemovesSessionsWhichHaveExceededTheMaxIdleSessionTimeout) {
  const std::shared_ptr<common::utilities::TimeServiceMock> &time_service_mock = std::make_shared<common::utilities::TimeServiceMock>();
  InMemorySessionStore in_memory_session_store(time_service_mock, 500, 50);
  auto session_id_idle = std::string("fake_session_id_idle");
  auto token_response_idle = CreateTokenResponse();

  auto session_id_active = std::string("fake_session_id_active");
  auto token_response_active = CreateTokenResponse();

  EXPECT_CALL(*time_service_mock, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(5));

  in_memory_session_store.Set(session_id_idle, *token_response_idle);
  ASSERT_TRUE(in_memory_session_store.Get(session_id_idle).has_value());

  in_memory_session_store.Set(session_id_active, *token_response_active);
  ASSERT_TRUE(in_memory_session_store.Get(session_id_active).has_value());

  EXPECT_CALL(*time_service_mock, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(30));

  in_memory_session_store.RemoveAllExpired();
  ASSERT_TRUE(in_memory_session_store.Get(session_id_idle).has_value()); // last active 25 seconds ago
  ASSERT_TRUE(in_memory_session_store.Get(session_id_active).has_value()); // last active 25 seconds ago

  EXPECT_CALL(*time_service_mock, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(50));

  ASSERT_TRUE(in_memory_session_store.Get(session_id_active).has_value()); // accessing at time 50

  EXPECT_CALL(*time_service_mock, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(90));

  in_memory_session_store.RemoveAllExpired();
  ASSERT_FALSE(in_memory_session_store.Get(session_id_idle).has_value()); // last active 60 seconds ago
  ASSERT_TRUE(in_memory_session_store.Get(session_id_active).has_value()); // last active 40 seconds ago
}

TEST_F(InMemorySessionStoreTest,
       RemoveAllExpired_RemovesSessionsWhichHaveExceededTheMaxIdleSessionTimeoutEvenIfThatSessionWasNeverAccessed) {
  const std::shared_ptr<common::utilities::TimeServiceMock> &time_service_mock = std::make_shared<common::utilities::TimeServiceMock>();
  InMemorySessionStore in_memory_session_store(time_service_mock, 0, 50);
  auto session_id_idle = std::string("fake_session_id_idle");
  auto token_response_idle = CreateTokenResponse();

  EXPECT_CALL(*time_service_mock, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(5));

  in_memory_session_store.Set(session_id_idle, *token_response_idle);

  EXPECT_CALL(*time_service_mock, GetCurrentTimeInSecondsSinceEpoch()).WillRepeatedly(Return(56));

  in_memory_session_store.RemoveAllExpired();
  ASSERT_FALSE(in_memory_session_store.Get(session_id_idle).has_value());
}

TEST_F(InMemorySessionStoreTest, ThreadSafety) {
  const std::shared_ptr<common::utilities::TimeServiceMock> &time_service_mock = std::make_shared<common::utilities::TimeServiceMock>();
  InMemorySessionStore in_memory_session_store(time_service_mock, 0, 0);
  std::vector<std::thread> threads;
  auto token_response = CreateTokenResponse();

  // Do lots of simultaneous sets and gets
  for (int i = 0; i < 10; ++i) {
    threads.emplace_back([this, i, &in_memory_session_store]() {
      for (int j = 1; j < 101; ++j) {
        int unique_number = (i * 100) + j;
        auto token_response = CreateTokenResponse();
        token_response->SetAccessTokenExpiry(unique_number);

        auto key = std::string("session_id_") + std::to_string(unique_number);
        in_memory_session_store.Set(key, *token_response);
        auto result = in_memory_session_store.Get(key);

        ASSERT_TRUE(result.has_value());
        ASSERT_TRUE(result->GetAccessTokenExpiry().has_value());
        ASSERT_EQ(result->GetAccessTokenExpiry().value(), unique_number);
      }
    });
  }
  for (auto &t : threads) {
    t.join();
  }

  threads.clear();

  // Do lots of simultaneous gets and removes
  for (int i = 0; i < 10; ++i) {
    threads.emplace_back([ i, &in_memory_session_store]() {
      for (int j = 1; j < 101; ++j) {
        int unique_number = (i * 100) + j;
        auto key = std::string("session_id_") + std::to_string(unique_number);

        auto result = in_memory_session_store.Get(key);
        ASSERT_TRUE(result.has_value());
        ASSERT_EQ(result->GetAccessTokenExpiry().value(), unique_number);
        in_memory_session_store.Remove(key);
        ASSERT_FALSE(in_memory_session_store.Get(key).has_value());
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
