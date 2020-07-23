#include <include/gmock/gmock-actions.h>
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "test/filters/oidc/mocks.h"
#include "src/filters/oidc/redis_retry_wrapper.h"
#include <string>

namespace authservice {
namespace filters {
namespace oidc {

using ::testing::Return;
using ::testing::Eq;

class RedisRetryWrapperTest : public ::testing::Test {
 protected:
  std::shared_ptr<RedisWrapperMock> redis_wrapper_mock_;
  std::shared_ptr<RedisRetryWrapper> redis_retry_wrapper;

  std::string session_id = "fake_session_id";

  std::string key_1 = "key_1";
  std::string val_1 = "val_1";
  std::string key_2 = "key_2";
  std::string val_2 = "val_2";

  std::vector<std::string> list_of_keys = {key_1, key_2};

  std::unordered_map<std::string, absl::optional<std::string>> response_map = {
      {key_1, val_1},
      {key_2, val_2},
  };

  std::unordered_map<std::string, std::string> keys_to_vals = {
      {key_1, val_1},
      {key_2, val_2},
  };

  void SetUp() override {
    redis_wrapper_mock_ = std::make_shared<testing::StrictMock<RedisWrapperMock>>();
    redis_retry_wrapper = std::make_shared<RedisRetryWrapper>(redis_wrapper_mock_);
  }
};

ACTION(ThrowRedisClosedError) {
  throw RedisClosedError("redis is closed");
}

ACTION(ThrowRedisIoError) {
  throw RedisIoError("redis timed out");
}

ACTION(ThrowRedisError) {
  throw RedisError("redis problem");
}

// hget hget hget hget hget hget hget hget hget hget hget hget hget hget hget hget hget hget hget hget hget hget hget
TEST_F(RedisRetryWrapperTest, hget_WhenNoErrorsAreThrown) {
  EXPECT_CALL(*redis_wrapper_mock_, hget(Eq(session_id), Eq(key_1))).WillOnce(Return(val_1));
  ASSERT_EQ(val_1, redis_retry_wrapper->hget(session_id, key_1));
}

TEST_F(RedisRetryWrapperTest, hget_WhenRedisWrapperThrowsAClosedException_ItRetries) {
  EXPECT_CALL(*redis_wrapper_mock_, hget(Eq(session_id), Eq(key_1)))
      .WillOnce(ThrowRedisClosedError())
      .WillOnce(ThrowRedisClosedError())
      .WillOnce(ThrowRedisClosedError())
      .WillOnce(Return(val_1));
  ASSERT_EQ(val_1, redis_retry_wrapper->hget(session_id, key_1));
}

TEST_F(RedisRetryWrapperTest, hget_WhenRedisWrapperThrowsMoreThan3RedisClosedExceptions_ItThrowsRedisError) {
  EXPECT_CALL(*redis_wrapper_mock_, hget(Eq(session_id), Eq(key_1)))
      .Times(4).WillRepeatedly(ThrowRedisClosedError());
  ASSERT_THROW(redis_retry_wrapper->hget(session_id, key_1), RedisError);
}

TEST_F(RedisRetryWrapperTest, hget_WhenRedisWrapperThrowsAIoError_ItRetries) {
  EXPECT_CALL(*redis_wrapper_mock_, hget(Eq(session_id), Eq(key_1)))
      .WillOnce(ThrowRedisIoError())
      .WillOnce(ThrowRedisIoError())
      .WillOnce(ThrowRedisIoError())
      .WillOnce(Return(val_1));
  ASSERT_EQ(val_1, redis_retry_wrapper->hget(session_id, key_1));
}

TEST_F(RedisRetryWrapperTest, hget_WhenRedisWrapperThrowsMoreThan3RedisIoError_ItThrowsRedisError) {
  EXPECT_CALL(*redis_wrapper_mock_, hget(Eq(session_id), Eq(key_1)))
      .Times(4).WillRepeatedly(ThrowRedisIoError());
  ASSERT_THROW(redis_retry_wrapper->hget(session_id, key_1), RedisError);
}

TEST_F(RedisRetryWrapperTest, hget_WhenRedisWrapperThrowsRedisError_ItThrowsRedisError) {
  EXPECT_CALL(*redis_wrapper_mock_, hget(Eq(session_id), Eq(key_1))).WillOnce(ThrowRedisError());
  ASSERT_THROW(redis_retry_wrapper->hget(session_id, key_1), RedisError);
}

// hmget hmget hmget hmget hmget hmget hmget hmget hmget hmget hmget hmget hmget hmget hmget hmget hmget hmget hmget
TEST_F(RedisRetryWrapperTest, hmget_WhenNoErrorsAreThrown) {
  EXPECT_CALL(*redis_wrapper_mock_, hmget(Eq(session_id), Eq(list_of_keys))).WillOnce(Return(response_map));
  ASSERT_EQ(response_map, redis_retry_wrapper->hmget(session_id, list_of_keys));
}

TEST_F(RedisRetryWrapperTest, hmget_WhenRedisWrapperThrowsAClosedException_ItRetries) {
  EXPECT_CALL(*redis_wrapper_mock_, hmget(Eq(session_id), Eq(list_of_keys)))
      .WillOnce(ThrowRedisClosedError())
      .WillOnce(ThrowRedisClosedError())
      .WillOnce(ThrowRedisClosedError())
      .WillOnce(Return(response_map));
  ASSERT_EQ(response_map, redis_retry_wrapper->hmget(session_id, list_of_keys));
}

TEST_F(RedisRetryWrapperTest, hmget_WhenRedisWrapperThrowsMoreThan3RedisClosedExceptions_ItThrowsRedisError) {
  EXPECT_CALL(*redis_wrapper_mock_, hmget(Eq(session_id), Eq(list_of_keys)))
      .Times(4).WillRepeatedly(ThrowRedisClosedError());
  ASSERT_THROW(redis_retry_wrapper->hmget(session_id, list_of_keys), RedisError);
}

TEST_F(RedisRetryWrapperTest, hmget_WhenRedisWrapperThrowsAIoError_ItRetries) {
  EXPECT_CALL(*redis_wrapper_mock_, hmget(Eq(session_id), Eq(list_of_keys)))
      .WillOnce(ThrowRedisIoError())
      .WillOnce(ThrowRedisIoError())
      .WillOnce(ThrowRedisIoError())
      .WillOnce(Return(response_map));
  ASSERT_EQ(response_map, redis_retry_wrapper->hmget(session_id, list_of_keys));
}

TEST_F(RedisRetryWrapperTest, hmget_WhenRedisWrapperThrowsMoreThan3RedisIoError_ItThrowsRedisError) {
  EXPECT_CALL(*redis_wrapper_mock_, hmget(Eq(session_id), Eq(list_of_keys)))
      .Times(4).WillRepeatedly(ThrowRedisIoError());
  ASSERT_THROW(redis_retry_wrapper->hmget(session_id, list_of_keys), RedisError);
}

TEST_F(RedisRetryWrapperTest, hmget_WhenRedisWrapperThrowsRedisError_ItThrowsRedisError) {
  EXPECT_CALL(*redis_wrapper_mock_, hmget(Eq(session_id), Eq(list_of_keys))).WillOnce(ThrowRedisError());
  ASSERT_THROW(redis_retry_wrapper->hmget(session_id, list_of_keys), RedisError);
}

// hset hset hset hset hset hset hset hset hset hset hset hset hset hset hset hset hset hset hset hset hset hset hset
TEST_F(RedisRetryWrapperTest, hset_WhenNoErrorsAreThrown) {
  EXPECT_CALL(*redis_wrapper_mock_, hset(Eq(session_id), Eq(key_1), Eq(val_1))).WillOnce(Return(true));
  ASSERT_EQ(true, redis_retry_wrapper->hset(session_id, key_1, val_1));
}

TEST_F(RedisRetryWrapperTest, hset_WhenRedisWrapperThrowsAClosedException_ItRetries) {
  EXPECT_CALL(*redis_wrapper_mock_, hset(Eq(session_id), Eq(key_1), Eq(val_1)))
      .WillOnce(ThrowRedisClosedError())
      .WillOnce(ThrowRedisClosedError())
      .WillOnce(ThrowRedisClosedError())
      .WillOnce(Return(true));
  ASSERT_EQ(true, redis_retry_wrapper->hset(session_id, key_1, val_1));
}

TEST_F(RedisRetryWrapperTest, hset_WhenRedisWrapperThrowsMoreThan3RedisClosedExceptions_ItThrowsRedisError) {
  EXPECT_CALL(*redis_wrapper_mock_, hset(Eq(session_id), Eq(key_1), Eq(val_1)))
      .Times(4).WillRepeatedly(ThrowRedisClosedError());
  ASSERT_THROW(redis_retry_wrapper->hset(session_id, key_1, val_1), RedisError);
}
TEST_F(RedisRetryWrapperTest, hset_WhenRedisWrapperThrowsAIoError_ItRetries) {
  EXPECT_CALL(*redis_wrapper_mock_, hset(Eq(session_id), Eq(key_1), Eq(val_1)))
      .WillOnce(ThrowRedisIoError())
      .WillOnce(ThrowRedisIoError())
      .WillOnce(ThrowRedisIoError())
      .WillOnce(Return(true));
  ASSERT_EQ(true, redis_retry_wrapper->hset(session_id, key_1, val_1));
}

TEST_F(RedisRetryWrapperTest, hset_WhenRedisWrapperThrowsMoreThan3RedisIoError_ItThrowsRedisError) {
  EXPECT_CALL(*redis_wrapper_mock_, hset(Eq(session_id), Eq(key_1), Eq(val_1)))
      .Times(4).WillRepeatedly(ThrowRedisIoError());
  ASSERT_THROW(redis_retry_wrapper->hset(session_id, key_1, val_1), RedisError);
}

TEST_F(RedisRetryWrapperTest, hset_WhenRedisWrapperThrowsRedisError_ItThrowsRedisError) {
  EXPECT_CALL(*redis_wrapper_mock_, hset(Eq(session_id), Eq(key_1), Eq(val_1))).WillOnce(ThrowRedisError());
  ASSERT_THROW(redis_retry_wrapper->hset(session_id, key_1, val_1), RedisError);
}

// hmset hmset hmset hmset hmset hmset hmset hmset hmset hmset hmset hmset hmset hmset hmset hmset hmset hmset hmset
TEST_F(RedisRetryWrapperTest, hmset_WhenNoErrorsAreThrown) {
  EXPECT_CALL(*redis_wrapper_mock_, hmset(Eq(session_id), Eq(keys_to_vals)));
  redis_retry_wrapper->hmset(session_id, keys_to_vals);
}

TEST_F(RedisRetryWrapperTest, hmset_WhenRedisWrapperThrowsAClosedException_ItRetries) {
  EXPECT_CALL(*redis_wrapper_mock_, hmset(Eq(session_id), Eq(keys_to_vals)))
      .WillOnce(ThrowRedisClosedError())
      .WillOnce(ThrowRedisClosedError())
      .WillOnce(ThrowRedisClosedError())
      .WillOnce(Return());
  redis_retry_wrapper->hmset(session_id, keys_to_vals);
}

TEST_F(RedisRetryWrapperTest, hmset_WhenRedisWrapperThrowsMoreThan3RedisClosedExceptions_ItThrowsRedisError) {
  EXPECT_CALL(*redis_wrapper_mock_, hmset(Eq(session_id), Eq(keys_to_vals)))
      .Times(4).WillRepeatedly(ThrowRedisClosedError());
  ASSERT_THROW(redis_retry_wrapper->hmset(session_id, keys_to_vals), RedisError);
}

TEST_F(RedisRetryWrapperTest, hmset_WhenRedisWrapperThrowsAIoError_ItRetries) {
  EXPECT_CALL(*redis_wrapper_mock_, hmset(Eq(session_id), Eq(keys_to_vals)))
      .WillOnce(ThrowRedisIoError())
      .WillOnce(ThrowRedisIoError())
      .WillOnce(ThrowRedisIoError())
      .WillOnce(Return());
  redis_retry_wrapper->hmset(session_id, keys_to_vals);
}

TEST_F(RedisRetryWrapperTest, hmset_WhenRedisWrapperThrowsMoreThan3RedisIoError_ItThrowsRedisError) {
  EXPECT_CALL(*redis_wrapper_mock_, hmset(Eq(session_id), Eq(keys_to_vals)))
      .Times(4).WillRepeatedly(ThrowRedisIoError());
  ASSERT_THROW(redis_retry_wrapper->hmset(session_id, keys_to_vals), RedisError);
}

TEST_F(RedisRetryWrapperTest, hmset_WhenRedisWrapperThrowsRedisError_ItThrowsRedisError) {
  EXPECT_CALL(*redis_wrapper_mock_, hmset(Eq(session_id), Eq(keys_to_vals))).WillOnce(ThrowRedisError());
  ASSERT_THROW(redis_retry_wrapper->hmset(session_id, keys_to_vals), RedisError);
}

// hsetnx hsetnx hsetnx hsetnx hsetnx hsetnx hsetnx hsetnx hsetnx hsetnx hsetnx hsetnx hsetnx hsetnx hsetnx hsetnx
TEST_F(RedisRetryWrapperTest, hsetnx_WhenNoErrorsAreThrown) {
  EXPECT_CALL(*redis_wrapper_mock_, hsetnx(Eq(session_id), Eq(key_1), Eq(val_1))).WillOnce(Return(true));
  ASSERT_TRUE(redis_retry_wrapper->hsetnx(session_id, key_1, val_1));
}

TEST_F(RedisRetryWrapperTest, hsetnx_WhenRedisWrapperThrowsAClosedException_ItRetries) {
  EXPECT_CALL(*redis_wrapper_mock_, hsetnx(Eq(session_id), Eq(key_1), Eq(val_1)))
      .WillOnce(ThrowRedisClosedError())
      .WillOnce(ThrowRedisClosedError())
      .WillOnce(ThrowRedisClosedError())
      .WillOnce(Return(true));
  ASSERT_TRUE(redis_retry_wrapper->hsetnx(session_id, key_1, val_1));
}

TEST_F(RedisRetryWrapperTest, hsetnx_WhenRedisWrapperThrowsMoreThan3RedisClosedExceptions_ItThrowsRedisError) {
  EXPECT_CALL(*redis_wrapper_mock_, hsetnx(Eq(session_id), Eq(key_1), Eq(val_1)))
      .Times(4).WillRepeatedly(ThrowRedisClosedError());
  ASSERT_THROW(redis_retry_wrapper->hsetnx(session_id, key_1, val_1), RedisError);
}

TEST_F(RedisRetryWrapperTest, hsetnx_WhenRedisWrapperThrowsAIoError_ItRetries) {
  EXPECT_CALL(*redis_wrapper_mock_, hsetnx(Eq(session_id), Eq(key_1), Eq(val_1)))
      .WillOnce(ThrowRedisIoError())
      .WillOnce(ThrowRedisIoError())
      .WillOnce(ThrowRedisIoError())
      .WillOnce(Return(true));
  ASSERT_TRUE(redis_retry_wrapper->hsetnx(session_id, key_1, val_1));
}

TEST_F(RedisRetryWrapperTest, hsetnx_WhenRedisWrapperThrowsMoreThan3RedisIoError_ItThrowsRedisError) {
  EXPECT_CALL(*redis_wrapper_mock_, hsetnx(Eq(session_id), Eq(key_1), Eq(val_1)))
      .Times(4).WillRepeatedly(ThrowRedisIoError());
  ASSERT_THROW(redis_retry_wrapper->hsetnx(session_id, key_1, val_1), RedisError);
}

TEST_F(RedisRetryWrapperTest, hsetnx_WhenRedisWrapperThrowsRedisError_ItThrowsRedisError) {
  EXPECT_CALL(*redis_wrapper_mock_, hsetnx(Eq(session_id), Eq(key_1), Eq(val_1))).WillOnce(ThrowRedisError());
  ASSERT_THROW(redis_retry_wrapper->hsetnx(session_id, key_1, val_1), RedisError);
}

// del del del del del del del del del del del del del del del del del del del del del del del del del del del del del
TEST_F(RedisRetryWrapperTest, del_WhenNoErrorsAreThrown) {
  EXPECT_CALL(*redis_wrapper_mock_, del(Eq(session_id))).WillOnce(Return(1));
  ASSERT_EQ(redis_retry_wrapper->del(session_id), 1);
}

TEST_F(RedisRetryWrapperTest, del_WhenRedisWrapperThrowsAClosedException_ItRetries) {
  EXPECT_CALL(*redis_wrapper_mock_, del(Eq(session_id)))
      .WillOnce(ThrowRedisClosedError())
      .WillOnce(ThrowRedisClosedError())
      .WillOnce(ThrowRedisClosedError())
      .WillOnce(Return(1));
  ASSERT_EQ(redis_retry_wrapper->del(session_id), 1);
}

TEST_F(RedisRetryWrapperTest, del_WhenRedisWrapperThrowsMoreThan3RedisClosedExceptions_ItThrowsRedisError) {
  EXPECT_CALL(*redis_wrapper_mock_, del(Eq(session_id))).Times(4).WillRepeatedly(ThrowRedisClosedError());
  ASSERT_THROW(redis_retry_wrapper->del(session_id), RedisError);
}

TEST_F(RedisRetryWrapperTest, del_WhenRedisWrapperThrowsAIoError_ItRetries) {
  EXPECT_CALL(*redis_wrapper_mock_, del(Eq(session_id)))
      .WillOnce(ThrowRedisIoError())
      .WillOnce(ThrowRedisIoError())
      .WillOnce(ThrowRedisIoError())
      .WillOnce(Return(1));
  ASSERT_EQ(redis_retry_wrapper->del(session_id), 1);
}

TEST_F(RedisRetryWrapperTest, del_WhenRedisWrapperThrowsMoreThan3RedisIoError_ItThrowsRedisError) {
  EXPECT_CALL(*redis_wrapper_mock_, del(Eq(session_id)))
      .Times(4).WillRepeatedly(ThrowRedisIoError());
  ASSERT_THROW(redis_retry_wrapper->del(session_id), RedisError);
}

TEST_F(RedisRetryWrapperTest, del_WhenRedisWrapperThrowsRedisError_ItThrowsRedisError) {
  EXPECT_CALL(*redis_wrapper_mock_, del(Eq(session_id))).WillOnce(ThrowRedisError());
  ASSERT_THROW(redis_retry_wrapper->del(session_id), RedisError);
}

// expireat expireat expireat expireat expireat expireat expireat expireat expireat expireat expireat expireat expireat
TEST_F(RedisRetryWrapperTest, expireat_WhenNoErrorsAreThrown) {
  EXPECT_CALL(*redis_wrapper_mock_, expireat(Eq(session_id), Eq(1))).WillOnce(Return(true));
  ASSERT_TRUE(redis_retry_wrapper->expireat(session_id, 1L));
}

TEST_F(RedisRetryWrapperTest, expireat_WhenRedisWrapperThrowsAClosedException_ItRetries) {
  EXPECT_CALL(*redis_wrapper_mock_, expireat(Eq(session_id), Eq(1)))
      .WillOnce(ThrowRedisClosedError())
      .WillOnce(ThrowRedisClosedError())
      .WillOnce(ThrowRedisClosedError())
      .WillOnce(Return(true));
  ASSERT_TRUE(redis_retry_wrapper->expireat(session_id, 1L));
}

TEST_F(RedisRetryWrapperTest, expireat_WhenRedisWrapperThrowsMoreThan3RedisClosedExceptions_ItThrowsRedisError) {
  EXPECT_CALL(*redis_wrapper_mock_, expireat(Eq(session_id), Eq(1))).Times(4).WillRepeatedly(ThrowRedisClosedError());
  ASSERT_THROW(redis_retry_wrapper->expireat(session_id, 1L), RedisError);
}

TEST_F(RedisRetryWrapperTest, expireat_WhenRedisWrapperThrowsAIoError_ItRetries) {
  EXPECT_CALL(*redis_wrapper_mock_, expireat(Eq(session_id), Eq(1)))
      .WillOnce(ThrowRedisIoError())
      .WillOnce(ThrowRedisIoError())
      .WillOnce(ThrowRedisIoError())
      .WillOnce(Return(true));
  ASSERT_TRUE(redis_retry_wrapper->expireat(session_id, 1));
}

TEST_F(RedisRetryWrapperTest, expireat_WhenRedisWrapperThrowsMoreThan3RedisIoError_ItThrowsRedisError) {
  EXPECT_CALL(*redis_wrapper_mock_, expireat(Eq(session_id), Eq(1)))
      .Times(4).WillRepeatedly(ThrowRedisIoError());
  ASSERT_THROW(redis_retry_wrapper->expireat(session_id, 1), RedisError);
}

TEST_F(RedisRetryWrapperTest, expireat_WhenRedisWrapperThrowsRedisError_ItThrowsRedisError) {
  EXPECT_CALL(*redis_wrapper_mock_, expireat(Eq(session_id), Eq(1))).WillOnce(ThrowRedisError());
  ASSERT_THROW(redis_retry_wrapper->expireat(session_id, 1L), RedisError);
}

// hdel hdel hdel hdel hdel hdel hdel hdel hdel hdel hdel hdel hdel hdel hdel hdel hdel hdel hdel hdel hdel hdel hdel
TEST_F(RedisRetryWrapperTest, hdel_WhenNoErrorsAreThrown) {
  EXPECT_CALL(*redis_wrapper_mock_, hdel(Eq(session_id), Eq(list_of_keys))).WillOnce(Return(true));
  ASSERT_TRUE(redis_retry_wrapper->hdel(session_id, list_of_keys));
}

TEST_F(RedisRetryWrapperTest, hdel_WhenRedisWrapperThrowsAClosedException_ItRetries) {
  EXPECT_CALL(*redis_wrapper_mock_, hdel(Eq(session_id), Eq(list_of_keys)))
      .WillOnce(ThrowRedisClosedError())
      .WillOnce(ThrowRedisClosedError())
      .WillOnce(ThrowRedisClosedError())
      .WillOnce(Return(2));
  ASSERT_EQ(redis_retry_wrapper->hdel(session_id, list_of_keys), 2);
}

TEST_F(RedisRetryWrapperTest, hdel_WhenRedisWrapperThrowsMoreThan3RedisClosedExceptions_ItThrowsRedisError) {
  EXPECT_CALL(*redis_wrapper_mock_, hdel(Eq(session_id), Eq(list_of_keys))).Times(4).WillRepeatedly(
      ThrowRedisClosedError());
  ASSERT_THROW(redis_retry_wrapper->hdel(session_id, list_of_keys), RedisError);
}

TEST_F(RedisRetryWrapperTest, hdel_WhenRedisWrapperThrowsAIoError_ItRetries) {
  EXPECT_CALL(*redis_wrapper_mock_, hdel(Eq(session_id), Eq(list_of_keys)))
      .WillOnce(ThrowRedisIoError())
      .WillOnce(ThrowRedisIoError())
      .WillOnce(ThrowRedisIoError())
      .WillOnce(Return(2));
  ASSERT_EQ(redis_retry_wrapper->hdel(session_id, list_of_keys), 2);
}

TEST_F(RedisRetryWrapperTest, hdel_WhenRedisWrapperThrowsMoreThan3RedisIoError_ItThrowsRedisError) {
  EXPECT_CALL(*redis_wrapper_mock_, hdel(Eq(session_id), Eq(list_of_keys)))
      .Times(4).WillRepeatedly(ThrowRedisIoError());
  ASSERT_THROW(redis_retry_wrapper->hdel(session_id, list_of_keys), RedisError);
}

TEST_F(RedisRetryWrapperTest, hdel_WhenRedisWrapperThrowsRedisError_ItThrowsRedisError) {
  EXPECT_CALL(*redis_wrapper_mock_, hdel(Eq(session_id), Eq(list_of_keys))).WillOnce(ThrowRedisError());
  ASSERT_THROW(redis_retry_wrapper->hdel(session_id, list_of_keys), RedisError);
}

}  // namespace oidc
}  // namespace filters
}  // namespace authservice
