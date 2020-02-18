#ifndef AUTHSERVICE_TEST_COMMON_SESSION_MOCKS_H_
#define AUTHSERVICE_TEST_COMMON_SESSION_MOCKS_H_

#include "gmock/gmock.h"
#include "src/common/session/token_encryptor.h"
#include "src/common/session/session_id_generator.h"

namespace authservice {
namespace common {
namespace session {

class TokenEncryptorMock final : public TokenEncryptor {
public:
  MOCK_METHOD1(Encrypt, std::string(const absl::string_view token));
  MOCK_METHOD1(Decrypt, absl::optional<std::string>(const std::string &ciphertext));
};

class SessionIdGeneratorMock final : public SessionIdGenerator {
public:
  MOCK_METHOD(std::string, Generate, ());
};

}  // namespace session
}  // namespace common
}  // namespace authservice

#endif  // AUTHSERVICE_TEST_COMMON_SESSION_MOCKS_H_
