#include "src/filters/oidc/redis_retry_wrapper.h"

#include "spdlog/spdlog.h"

namespace authservice {
namespace filters {
namespace oidc {

// redis_sever_uri is of the form: tcp://[[username:]password@]host[:port][/db]
RedisRetryWrapper::RedisRetryWrapper(
    std::shared_ptr<RedisWrapper> redis_wrapper)
    : redis_wrapper_(redis_wrapper) {}

absl::optional<std::string> oidc::RedisRetryWrapper::hget(
    const absl::string_view key, const absl::string_view val) {
  for (int retries = 0;; retries++) {
    try {
      return redis_wrapper_->hget(key, val);
    } catch (const RedisClosedError &err) {
      if (retries < 3) {
        spdlog::trace("{}: redis connection closed error, retrying", __func__);
        continue;
      }
      spdlog::error("{}: redis connection closed error, throwing error",
                    __func__);
      throw RedisError(err.what());
    } catch (const RedisIoError &err) {
      if (retries < 3) {
        spdlog::trace("{}: redis connection timed out, retrying", __func__);
        continue;
      }
      spdlog::error("{}: redis timed out, throwing error", __func__);
      throw RedisError(err.what());
    }
  }
}

std::unordered_map<std::string, absl::optional<std::string>>
oidc::RedisRetryWrapper::hmget(const absl::string_view key,
                               const std::vector<std::string> &fields) {
  for (int retries = 0;; retries++) {
    try {
      return redis_wrapper_->hmget(key, fields);
    } catch (const RedisClosedError &err) {
      if (retries < 3) {
        spdlog::trace("{}: redis connection closed error, retrying", __func__);
        continue;
      }
      spdlog::error("{}: redis connection closed error, throwing error",
                    __func__);
      throw RedisError(err.what());
    } catch (const RedisIoError &err) {
      if (retries < 3) {
        spdlog::trace("{}: redis connection timed out, retrying", __func__);
        continue;
      }
      spdlog::error("{}: redis timed out, throwing error", __func__);
      throw RedisError(err.what());
    }
  }
}

bool RedisRetryWrapper::hset(const absl::string_view key,
                             const absl::string_view field,
                             const absl::string_view val) {
  for (int retries = 0;; retries++) {
    try {
      return redis_wrapper_->hset(key, field, val);
    } catch (const RedisClosedError &err) {
      if (retries < 3) {
        spdlog::trace("{}: redis connection closed error, retrying", __func__);
        continue;
      }
      spdlog::error("{}: redis connection closed error, throwing error",
                    __func__);
      throw RedisError(err.what());
    } catch (const RedisIoError &err) {
      if (retries < 3) {
        spdlog::trace("{}: redis connection timed out, retrying", __func__);
        continue;
      }
      spdlog::error("{}: redis timed out, throwing error", __func__);
      throw RedisError(err.what());
    }
  }
}

void RedisRetryWrapper::hmset(
    const absl::string_view key,
    const std::unordered_map<std::string, std::string> fields_to_values_map) {
  for (int retries = 0;; retries++) {
    try {
      redis_wrapper_->hmset(key, fields_to_values_map);
      break;
    } catch (const RedisClosedError &err) {
      if (retries < 3) {
        spdlog::trace("{}: redis connection closed error, retrying", __func__);
        continue;
      }
      spdlog::error("{}: redis connection closed error, throwing error",
                    __func__);
      throw RedisError(err.what());
    } catch (const RedisIoError &err) {
      if (retries < 3) {
        spdlog::trace("{}: redis connection timed out, retrying", __func__);
        continue;
      }
      spdlog::error("{}: redis timed out, throwing error", __func__);
      throw RedisError(err.what());
    }
  }
}

bool RedisRetryWrapper::hsetnx(const absl::string_view key,
                               const absl::string_view field,
                               const absl::string_view val) {
  for (int retries = 0;; retries++) {
    try {
      return redis_wrapper_->hsetnx(key, field, val);
    } catch (const RedisClosedError &err) {
      if (retries < 3) {
        spdlog::trace("{}: redis connection closed error, retrying", __func__);
        continue;
      }
      spdlog::error("{}: redis connection closed error, throwing error",
                    __func__);
      throw RedisError(err.what());
    } catch (const RedisIoError &err) {
      if (retries < 3) {
        spdlog::trace("{}: redis connection timed out, retrying", __func__);
        continue;
      }
      spdlog::error("{}: redis timed out, throwing error", __func__);
      throw RedisError(err.what());
    }
  }
}

long long RedisRetryWrapper::del(const absl::string_view key) {
  for (int retries = 0;; retries++) {
    try {
      return redis_wrapper_->del(key);
    } catch (const RedisClosedError &err) {
      if (retries < 3) {
        spdlog::trace("{}: redis connection closed error, retrying", __func__);
        continue;
      }
      spdlog::error("{}: redis connection closed error, throwing error",
                    __func__);
      throw RedisError(err.what());
    } catch (const RedisIoError &err) {
      if (retries < 3) {
        spdlog::trace("{}: redis connection timed out, retrying", __func__);
        continue;
      }
      spdlog::error("{}: redis timed out, throwing error", __func__);
      throw RedisError(err.what());
    }
  }
}

bool RedisRetryWrapper::expireat(const absl::string_view key,
                                 long long timestamp) {
  for (int retries = 0;; retries++) {
    try {
      return redis_wrapper_->expireat(key, timestamp);
    } catch (const RedisClosedError &err) {
      if (retries < 3) {
        spdlog::trace("{}: redis connection closed error, retrying", __func__);
        continue;
      }
      spdlog::error("{}: redis connection closed error, throwing error",
                    __func__);
      throw RedisError(err.what());
    } catch (const RedisIoError &err) {
      if (retries < 3) {
        spdlog::trace("{}: redis connection timed out, retrying", __func__);
        continue;
      }
      spdlog::error("{}: redis timed out, throwing error", __func__);
      throw RedisError(err.what());
    }
  }
}

long long RedisRetryWrapper::hdel(absl::string_view key,
                                  std::vector<std::string> &fields) {
  for (int retries = 0;; retries++) {
    try {
      return redis_wrapper_->hdel(key, fields);
    } catch (const RedisClosedError &err) {
      if (retries < 3) {
        spdlog::trace("{}: redis connection closed error, retrying", __func__);
        continue;
      }
      spdlog::error("{}: redis connection closed error, throwing error",
                    __func__);
      throw RedisError(err.what());
    } catch (const RedisIoError &err) {
      if (retries < 3) {
        spdlog::trace("{}: redis connection timed out, retrying", __func__);
        continue;
      }
      spdlog::error("{}: redis timed out, throwing error", __func__);
      throw RedisError(err.what());
    }
  }
}

}  // namespace oidc
}  // namespace filters
}  // namespace authservice
