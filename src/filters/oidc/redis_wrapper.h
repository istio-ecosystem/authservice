#ifndef AUTHSERVICE_TEST_FILTERS_OIDC_REDIS_WRAPPER_H_
#define AUTHSERVICE_TEST_FILTERS_OIDC_REDIS_WRAPPER_H_

#include "redis.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"

namespace authservice {
namespace filters {
namespace oidc {

class RedisWrapper {

 private:

  sw::redis::ConnectionOptions connection_options_;
  sw::redis::ConnectionPoolOptions pool_options_;
  sw::redis::Redis redis_;

  static sw::redis::ConnectionOptions &fillInConnectionOptions(sw::redis::ConnectionOptions &connection_options,
                                                               bool keep_alive,
                                                               int connect_timeout_ms,
                                                               int socket_timeout_ms);

  static sw::redis::ConnectionPoolOptions &fillInPoolOptions(sw::redis::ConnectionPoolOptions &pool_options,
                                                             std::size_t pool_size,
                                                             int wait_timeout_ms,
                                                             int connection_lifetime_ms);

 public:

  explicit RedisWrapper(const absl::string_view redis_sever_uri, unsigned int threads);

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

#endif //AUTHSERVICE_TEST_FILTERS_OIDC_REDIS_WRAPPER_H_
