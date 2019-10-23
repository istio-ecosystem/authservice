#include "src/common/session/token_encryptor.h"
#include "openssl/rand.h"

#include "gtest/gtest.h"

namespace authservice {
namespace common {
namespace session {

TEST(TokenEncryptorTest, SealAndOpen) {
  unsigned char key[32];
  unsigned char token[256];
  for (auto i = 0; i < 100; i++) {
    ASSERT_EQ(RAND_bytes(key, sizeof(key)), 1);
    ASSERT_EQ(RAND_bytes(token, sizeof(token)), 1);
    auto encryptor = TokenEncryptor::Create(
        std::string(reinterpret_cast<const char *>(key), sizeof(key)));
    auto ciphertext = encryptor->Encrypt(
        std::string(reinterpret_cast<const char *>(token), sizeof(token)));
    auto plaintext = encryptor->Decrypt(ciphertext);
    ASSERT_TRUE(plaintext.has_value());
    ASSERT_EQ(std::string(reinterpret_cast<const char *>(token), sizeof(token)),
              plaintext);
  }
}
}  // namespace session
}  // namespace common
}  // namespace authservice
