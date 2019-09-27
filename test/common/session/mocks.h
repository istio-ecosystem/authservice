#ifndef TRANSPARENT_AUTH_TEST_COMMON_SESSION_MOCKS_H_
#define TRANSPARENT_AUTH_TEST_COMMON_SESSION_MOCKS_H_
#include "gmock/gmock.h"
#include "src/common/session/token_encryptor.h"

namespace transparent_auth {
namespace common {
namespace session {
class TokenEncryptorMock final : public TokenEncryptor {
 public:
  MOCK_METHOD1(Encrypt, std::string(const std::string& token));
  MOCK_METHOD1(Decrypt,
               absl::optional<std::string>(const std::string& ciphertext));
};
}  // namespace session
}  // namespace common
}  // namespace transparent_auth

#endif  // TRANSPARENT_AUTH_TEST_COMMON_SESSION_MOCKS_H_
