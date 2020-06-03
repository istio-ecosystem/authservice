#ifndef AUTHSERVICE_TEST_FILTERS_OIDC_MOCKS_H_
#define AUTHSERVICE_TEST_FILTERS_OIDC_MOCKS_H_

#include "gmock/gmock.h"
#include "src/filters/oidc/token_response.h"
#include "redis.h"
#include "src/filters/oidc/redis_wrapper.h"

namespace authservice {
namespace filters {
namespace oidc {
class TokenResponseParserMock final : public TokenResponseParser {
 public:
  MOCK_CONST_METHOD3(Parse,
                     std::shared_ptr<TokenResponse>(
                         const std::string &client_id,
                         const std::string &nonce,
                         const std::string &raw));
  MOCK_CONST_METHOD2(ParseRefreshTokenResponse,
                     std::shared_ptr<TokenResponse>(
                         const TokenResponse &existing_token_response,
                         const std::string &raw_response_string));
};

class RedisWrapperMock final : public RedisWrapper {
 public:
  RedisWrapperMock() : RedisWrapper(nullptr) {};
  MOCK_METHOD2(hget, sw::redis::OptionalString(const sw::redis::StringView &, const sw::redis::StringView &));
  MOCK_METHOD3(hset, bool(const sw::redis::StringView &, const sw::redis::StringView &, const sw::redis::StringView &));
  MOCK_METHOD3(hsetnx, bool(const sw::redis::StringView &, const sw::redis::StringView &, const sw::redis::StringView &));
  MOCK_METHOD2(hexists, bool(const sw::redis::StringView &, const sw::redis::StringView &));
  MOCK_METHOD1(del, long long(const sw::redis::StringView &));
  MOCK_METHOD2(hdel, long long(const sw::redis::StringView &, const sw::redis::StringView &));
  MOCK_METHOD2(expireat, bool(const sw::redis::StringView &, long long));
};

}  // namespace oidc
}  // namespace filters
}  // namespace authservice
#endif  // AUTHSERVICE_TEST_FILTERS_OIDC_MOCKS_H_
