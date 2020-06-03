
#include "src/filters/oidc/redis_wrapper.h"

#include <utility>

namespace authservice {
namespace filters {
namespace oidc {

RedisWrapper::RedisWrapper(std::shared_ptr<sw::redis::Redis> redis) : redis_(std::move(redis)) {}

sw::redis::OptionalString oidc::RedisWrapper::hget(const sw::redis::StringView &key, const sw::redis::StringView &value) {
  return redis_->hget(key, value);
}

bool RedisWrapper::hset(const sw::redis::StringView &key, const sw::redis::StringView &field, const sw::redis::StringView &val) {
  return redis_->hset(key, field, val);
}
bool RedisWrapper::hsetnx(const sw::redis::StringView &key, const sw::redis::StringView &field, const sw::redis::StringView &val) {
  return redis_->hsetnx(key, field, val);
}
bool RedisWrapper::hexists(const sw::redis::StringView &key, const sw::redis::StringView &field) {
  return redis_->hexists(key, field);
}
long long RedisWrapper::del(const sw::redis::StringView &key) {
  return redis_->del(key);
}
bool RedisWrapper::expireat(const sw::redis::StringView &key, long long timestamp) {
  return redis_->expireat(key, timestamp);
}
long long RedisWrapper::hdel(const sw::redis::StringView &key, const sw::redis::StringView &field) {
  return redis_->hdel(key, field);
}

} //oidc
} //filters
} //authservice