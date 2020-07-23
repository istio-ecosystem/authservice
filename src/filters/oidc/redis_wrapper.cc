#include "src/filters/oidc/redis_wrapper.h"
#include "src/filters/oidc/session_store.h"
#include <boost/range/combine.hpp>

namespace authservice {
namespace filters {
namespace oidc {

// redis_sever_uri is of the form: tcp://[[username:]password@]host[:port][/db]
RedisWrapper::RedisWrapper(const absl::string_view redis_sever_uri, unsigned int threads)
    : connection_options_(std::string(redis_sever_uri.data())),
      pool_options_(),
      redis_(
          fillInConnectionOptions(connection_options_, false, 10000, 10000),
          fillInPoolOptions(pool_options_, threads, 10000, 0)
      ) {}

sw::redis::ConnectionOptions &RedisWrapper::fillInConnectionOptions(sw::redis::ConnectionOptions &connection_options,
                                                                    bool keep_alive,
                                                                    int connect_timeout_ms,
                                                                    int socket_timeout_ms) {
  connection_options.keep_alive = keep_alive;
  connection_options.connect_timeout = std::chrono::milliseconds(connect_timeout_ms);
  connection_options.socket_timeout = std::chrono::milliseconds(socket_timeout_ms);
  return connection_options;
}

sw::redis::ConnectionPoolOptions &RedisWrapper::fillInPoolOptions(sw::redis::ConnectionPoolOptions &pool_options,
                                                                  std::size_t pool_size,
                                                                  int wait_timeout_ms,
                                                                  int connection_lifetime_ms) {
  pool_options.size = pool_size;
  pool_options.wait_timeout = std::chrono::milliseconds(wait_timeout_ms);
  pool_options.connection_lifetime = std::chrono::milliseconds(connection_lifetime_ms);
  return pool_options;
}

absl::optional<std::string> oidc::RedisWrapper::hget(const absl::string_view key, const absl::string_view val) {
  try {
    auto hget_value = redis_.hget(sw::redis::StringView(key.data()), sw::redis::StringView(val.data()));
    return hget_value ? absl::optional<std::string>(hget_value->data()) : absl::nullopt;
  } catch (const sw::redis::Error &err) {
    throw SessionError(err.what());
  }
}

std::unordered_map<std::string, absl::optional<std::string>>
oidc::RedisWrapper::hmget(const absl::string_view key, const std::vector<std::string> &fields) {
  std::vector<sw::redis::OptionalString> vals;

  try {
    redis_.hmget(key.data(), fields.begin(), fields.end(), std::back_inserter(vals));
  } catch (const sw::redis::Error &err) {
    throw SessionError(err.what());
  }

  std::unordered_map<std::string, absl::optional<std::string>> output_map;

  for (auto tup : boost::combine(fields, vals)) {
    std::string field;
    sw::redis::OptionalString val;
    boost::tie(field, val) = tup;
    if (val) {
      output_map.insert({field, absl::optional<std::string>(val.value())});
    } else {
      output_map.insert({field, absl::nullopt});
    }
  }

  return output_map;
}

bool RedisWrapper::hset(const absl::string_view key, const absl::string_view field, const absl::string_view val) {
  try {
    return redis_.hset(sw::redis::StringView(key.data()),
                       sw::redis::StringView(field.data()),
                       sw::redis::StringView(val.data()));
  } catch (const sw::redis::Error &err) {
    throw SessionError(err.what());
  }
}

void RedisWrapper::hmset(const absl::string_view key,
                         const std::unordered_map<std::string, std::string> fields_to_values_map) {
  try {
    redis_.hmset(sw::redis::StringView(key.data()), fields_to_values_map.begin(), fields_to_values_map.end());
  } catch (const sw::redis::Error &err) {
    throw SessionError(err.what());
  }
}

bool RedisWrapper::hsetnx(const absl::string_view key, const absl::string_view field, const absl::string_view val) {
  try {
    return redis_.hsetnx(sw::redis::StringView(key.data()),
                         sw::redis::StringView(field.data()),
                         sw::redis::StringView(val.data()));
  } catch (const sw::redis::Error &err) {
    throw SessionError(err.what());
  }
}

long long RedisWrapper::del(const absl::string_view key) {
  try {
    return redis_.del(sw::redis::StringView(key.data()));
  } catch (const sw::redis::Error &err) {
    throw SessionError(err.what());
  }
}

bool RedisWrapper::expireat(const absl::string_view key, long long timestamp) {
  try {
    return redis_.expireat(sw::redis::StringView(key.data()), timestamp);
  } catch (const sw::redis::Error &err) {
    throw SessionError(err.what());
  }
}

long long RedisWrapper::hdel(absl::string_view key, std::vector<std::string> &fields) {
  try {
    return redis_.hdel(sw::redis::StringView(key.data()), fields.begin(), fields.end());
  } catch (const sw::redis::Error &err) {
    throw SessionError(err.what());
  }
}

} //oidc
} //filters
} //authservice
