#ifndef AUTHSERVICE_TEST_FILTERS_OIDC_MOCKS_H_
#define AUTHSERVICE_TEST_FILTERS_OIDC_MOCKS_H_

#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "gmock/gmock.h"
#include "src/filters/oidc/authorization_state.h"
#include "src/filters/oidc/jwks_resolver.h"
#include "src/filters/oidc/redis_wrapper.h"
#include "src/filters/oidc/session_store.h"
#include "src/filters/oidc/token_response.h"

namespace authservice {
namespace filters {
namespace oidc {

class SessionStoreMock final : public SessionStore {
 public:
  MOCK_METHOD(void, SetTokenResponse,
              (absl::string_view session_id, (std::shared_ptr<TokenResponse>)));

  MOCK_METHOD((std::shared_ptr<TokenResponse>), GetTokenResponse,
              (absl::string_view));

  MOCK_METHOD(void, SetAuthorizationState,
              (absl::string_view, (std::shared_ptr<AuthorizationState>)));

  MOCK_METHOD((std::shared_ptr<AuthorizationState>), GetAuthorizationState,
              (absl::string_view));

  MOCK_METHOD(void, ClearAuthorizationState, (absl::string_view));

  MOCK_METHOD(void, RemoveSession, (absl::string_view));

  MOCK_METHOD(void, RemoveAllExpired, ());
};

class TokenResponseParserMock final : public TokenResponseParser {
 public:
  MOCK_METHOD((std::shared_ptr<TokenResponse>), Parse,
              (const std::string &client_id, const std::string &nonce,
               const std::string &raw),
              (const));

  MOCK_METHOD((std::shared_ptr<TokenResponse>), ParseRefreshTokenResponse,
              (const TokenResponse &, const std::string &), (const));
};

class RedisWrapperMock : public RedisWrapper {
 public:
  // The Redis constructor will parse this url but not open a connection, so
  // this is just enough to satisfy the constructor
  RedisWrapperMock() : RedisWrapper("tcp://127.0.0.1", 6){};

  MOCK_METHOD(absl::optional<std::string>, hget,
              (const absl::string_view, const absl::string_view));

  MOCK_METHOD((std::unordered_map<std::string, absl::optional<std::string>>),
              hmget,
              (const absl::string_view, const std::vector<std::string> &));

  MOCK_METHOD(bool, hset,
              (const absl::string_view, const absl::string_view,
               const absl::string_view));

  MOCK_METHOD(void, hmset,
              (const absl::string_view,
               (const std::unordered_map<std::string, std::string>)));

  MOCK_METHOD(bool, hsetnx,
              (const absl::string_view, const absl::string_view,
               const absl::string_view));

  MOCK_METHOD(long long, del, (const absl::string_view));

  MOCK_METHOD(long long, hdel,
              (const absl::string_view, std::vector<std::string> &));

  MOCK_METHOD(bool, expireat, (const absl::string_view, long long));
};

class MockJwksResolver final : public JwksResolver {
 public:
  MOCK_METHOD((google::jwt_verify::JwksPtr &), jwks, ());
  MOCK_METHOD((const std::string &), rawStringJwks, (), (const));
};

class MockJwksResolverCache : public JwksResolverCache {
 public:
  MOCK_METHOD((std::shared_ptr<authservice::filters::oidc::JwksResolver>),
              getResolver, ());
};

}  // namespace oidc
}  // namespace filters
}  // namespace authservice
#endif  // AUTHSERVICE_TEST_FILTERS_OIDC_MOCKS_H_
