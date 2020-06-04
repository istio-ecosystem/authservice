
#include "src/filters/oidc/redis_wrapper.h"

#include <utility>

namespace authservice {
namespace filters {
namespace oidc {

RedisWrapper::RedisWrapper(std::shared_ptr<sw::redis::Redis> redis) : redis_(std::move(redis)) {}

absl::optional<std::string> oidc::RedisWrapper::hget(const absl::string_view key, const absl::string_view val) {
  auto hget_value = redis_->hget(sw::redis::StringView(key.data()), sw::redis::StringView(val.data()));
  return hget_value ? absl::optional<std::string>(hget_value->data()) : absl::nullopt;
}

bool RedisWrapper::hset(const absl::string_view key, const absl::string_view field, const absl::string_view val) {
  return redis_->hset(sw::redis::StringView(key.data()), sw::redis::StringView(field.data()), sw::redis::StringView(val.data()));
}
bool RedisWrapper::hsetnx(const absl::string_view key, const absl::string_view field, const absl::string_view val) {
  return redis_->hsetnx(sw::redis::StringView(key.data()), sw::redis::StringView(field.data()), sw::redis::StringView(val.data()));
}
bool RedisWrapper::hexists(const absl::string_view key, const absl::string_view field) {
  return redis_->hexists(sw::redis::StringView(key.data()), sw::redis::StringView(field.data()));
}
long long RedisWrapper::del(const absl::string_view key) {
  return redis_->del(sw::redis::StringView(key.data()));
}
bool RedisWrapper::expireat(const absl::string_view key, long long timestamp) {
  return redis_->expireat(sw::redis::StringView(key.data()), timestamp);
}
long long RedisWrapper::hdel(const absl::string_view key, const absl::string_view field) {
  return redis_->hdel(sw::redis::StringView(key.data()), sw::redis::StringView(field.data()));
}

} //oidc
} //filters
} //authservice