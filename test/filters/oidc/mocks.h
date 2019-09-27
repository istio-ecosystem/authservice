#ifndef TRANSPARENT_AUTH_TEST_FILTERS_OIDC_MOCKS_H_
#define TRANSPARENT_AUTH_TEST_FILTERS_OIDC_MOCKS_H_
#include "gmock/gmock.h"
#include "src/filters/oidc/token_response.h"
namespace transparent_auth {
namespace filters {
namespace oidc {
class TokenResponseParserMock final : public TokenResponseParser {
 public:
  MOCK_CONST_METHOD2(Parse,
                     absl::optional<TokenResponse>(absl::string_view nonce,
                                                   absl::string_view raw));
};
}  // namespace http
}  // namespace common
}  // namespace transparent_auth
#endif  // TRANSPARENT_AUTH_TEST_FILTERS_OIDC_MOCKS_H_
