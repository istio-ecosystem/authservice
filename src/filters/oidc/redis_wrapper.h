#ifndef AUTHSERVICE_TEST_FILTERS_OIDC_REDIS_WRAPPER_H_
#define AUTHSERVICE_TEST_FILTERS_OIDC_REDIS_WRAPPER_H_

#include "redis.h"

namespace authservice {
namespace filters {
namespace oidc {

class RedisWrapper {
 private:
  std::shared_ptr<sw::redis::Redis> redis_;
 public:
  explicit RedisWrapper(std::shared_ptr<sw::redis::Redis> redis);
  virtual sw::redis::OptionalString hget(const sw::redis::StringView &key, const sw::redis::StringView &value);
  virtual bool hset(const sw::redis::StringView &key,
                    const sw::redis::StringView &field,
                    const sw::redis::StringView &val);
  virtual bool hsetnx(const sw::redis::StringView &key,
                      const sw::redis::StringView &field,
                      const sw::redis::StringView &val);
  virtual bool hexists(const sw::redis::StringView &key, const sw::redis::StringView &field);
  virtual long long del(const sw::redis::StringView &key);
  virtual bool expireat(const sw::redis::StringView &key, long long timestamp);
  virtual long long hdel(const sw::redis::StringView &key, const sw::redis::StringView &field);
};

}  // namespace oidc
}  // namespace filters
}  // namespace authservice

#endif //AUTHSERVICE_TEST_FILTERS_OIDC_REDIS_WRAPPER_H_
