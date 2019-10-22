#ifndef TRANSPARENT_AUTH_TEST_FILTERS_OIDC_MOCKS_H_
#define TRANSPARENT_AUTH_TEST_FILTERS_OIDC_MOCKS_H_
#include "gmock/gmock.h"
#include "src/filters/oidc/token_response.h"
namespace transparent_auth {
namespace filters {
namespace oidc {
class TokenResponseParserMock final : public TokenResponseParser {
 public:
  MOCK_CONST_METHOD3(Parse,
                     absl::optional<TokenResponse>(const std::string &client_id,
                         const std::string &nonce,
                         const std::string &raw));
};
}  // namespace oidc
}  // namespace filters
}  // namespace transparent_auth
#endif  // TRANSPARENT_AUTH_TEST_FILTERS_OIDC_MOCKS_H_
