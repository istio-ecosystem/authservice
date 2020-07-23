#ifndef AUTHSERVICE_SRC_FILTERS_OIDC_REDIS_RETRY_WRAPPER_H_
#define AUTHSERVICE_SRC_FILTERS_OIDC_REDIS_RETRY_WRAPPER_H_

#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "redis_wrapper.h"

namespace authservice {
namespace filters {
namespace oidc {

class RedisRetryWrapper {

 private:
  std::shared_ptr<RedisWrapper> redis_wrapper_;

 public:

  explicit RedisRetryWrapper(std::shared_ptr<RedisWrapper> redis_wrapper);

  virtual absl::optional<std::string> hget(const absl::string_view key, const absl::string_view value);

  virtual std::unordered_map<std::string, absl::optional<std::string>>
  hmget(const absl::string_view key, const std::vector<std::string> &fields);

  virtual bool hset(const absl::string_view key, const absl::string_view field, const absl::string_view val);

  virtual void hmset(const absl::string_view key,
                     const std::unordered_map<std::string, std::string> fields_to_values_map);

  virtual bool hsetnx(const absl::string_view key, const absl::string_view field, const absl::string_view val);

  virtual long long del(const absl::string_view key);

  virtual bool expireat(const absl::string_view key, long long timestamp);

  virtual long long hdel(absl::string_view key, std::vector<std::string> &fields);

};

}  // namespace oidc
}  // namespace filters
}  // namespace authservice

#endif //AUTHSERVICE_SRC_FILTERS_OIDC_REDIS_RETRY_WRAPPER_H_
