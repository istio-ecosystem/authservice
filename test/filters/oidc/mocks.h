#ifndef AUTHSERVICE_TEST_FILTERS_OIDC_MOCKS_H_
#define AUTHSERVICE_TEST_FILTERS_OIDC_MOCKS_H_

#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "gmock/gmock.h"
#include "src/filters/oidc/authorization_state.h"
#include "src/filters/oidc/redis_wrapper.h"
#include "src/filters/oidc/session_store.h"
#include "src/filters/oidc/token_response.h"

namespace authservice {
namespace filters {
namespace oidc {

class SessionStoreMock final : public SessionStore {
 public:
  MOCK_METHOD2(SetTokenResponse,
               void(absl::string_view session_id,
                    std::shared_ptr<TokenResponse> token_response));

  MOCK_METHOD1(GetTokenResponse,
               std::shared_ptr<TokenResponse>(absl::string_view session_id));

  MOCK_METHOD2(SetAuthorizationState,
               void(absl::string_view session_id,
                    std::shared_ptr<AuthorizationState> authorization_state));

  MOCK_METHOD1(GetAuthorizationState, std::shared_ptr<AuthorizationState>(
                                          absl::string_view session_id));

  MOCK_METHOD1(ClearAuthorizationState, void(absl::string_view session_id));

  MOCK_METHOD1(RemoveSession, void(absl::string_view session_id));

  MOCK_METHOD0(RemoveAllExpired, void());
};

class TokenResponseParserMock final : public TokenResponseParser {
 public:
  MOCK_CONST_METHOD3(
      Parse, std::shared_ptr<TokenResponse>(const std::string &client_id,
                                            const std::string &nonce,
                                            const std::string &raw));

  MOCK_CONST_METHOD2(ParseRefreshTokenResponse,
                     std::shared_ptr<TokenResponse>(
                         const TokenResponse &existing_token_response,
                         const std::string &raw_response_string));
};

class RedisWrapperMock : public RedisWrapper {
 public:
  // The Redis constructor will parse this url but not open a connection, so
  // this is just enough to satisfy the constructor
  RedisWrapperMock() : RedisWrapper("tcp://127.0.0.1", 6){};

  MOCK_METHOD2(hget, absl::optional<std::string>(const absl::string_view,
                                                 const absl::string_view));

  MOCK_METHOD2(hmget,
               std::unordered_map<std::string, absl::optional<std::string>>(
                   const absl::string_view key,
                   const std::vector<std::string> &fields));

  MOCK_METHOD3(hset, bool(const absl::string_view, const absl::string_view,
                          const absl::string_view));

  MOCK_METHOD2(hmset, void(const absl::string_view key,
                           const std::unordered_map<std::string, std::string>
                               fields_to_values_map));

  MOCK_METHOD3(hsetnx, bool(const absl::string_view, const absl::string_view,
                            const absl::string_view));

  MOCK_METHOD1(del, long long(const absl::string_view));

  MOCK_METHOD2(hdel,
               long long(const absl::string_view, std::vector<std::string> &));

  MOCK_METHOD2(expireat, bool(const absl::string_view, long long));
};

}  // namespace oidc
}  // namespace filters
}  // namespace authservice
#endif  // AUTHSERVICE_TEST_FILTERS_OIDC_MOCKS_H_
