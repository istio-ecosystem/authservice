#ifndef AUTHSERVICE_SRC_COMMON_SESSION_TOKEN_ENCRYPTOR_H_
#define AUTHSERVICE_SRC_COMMON_SESSION_TOKEN_ENCRYPTOR_H_
#include <memory>
#include <string>
#include "absl/types/optional.h"
#include "src/common/session/hkdf_deriver.h"
#include "absl/strings/string_view.h"

namespace authservice {
namespace common {
namespace session {

class TokenEncryptor;
typedef std::shared_ptr<TokenEncryptor> TokenEncryptorPtr;

enum class EncryptionAlg {
  AES128GCM,
  AES256GCM,
};

/** Token encryption utility */
class TokenEncryptor {
 public:
  virtual ~TokenEncryptor(){};

  /**
   * Encrypt the given token.
   * @param token the token to encrypt and authenticate.
   * @param nonce the nonce to use during encryption
   * @return base64 string representing the encrypted/authenticated data
   */
  virtual std::string Encrypt(const absl::string_view token) = 0;

  /**
   * Decrypt the given token.
   * @param ciphertext the data (nonce || ciphertext || tag) to be decrypted.
   * @param aad        additional authenticated data.
   * @return plaintext string, or absl::nullopt if verification failed.
   */
  virtual absl::optional<std::string> Decrypt(
      const std::string& ciphertext) = 0;

  /**
   * Create an instance of a TokenEncryptor.
   * @param secret       base64 encoded data of the secret used to derive the
   * encryption key.
   * @param enc_alg      encryption algorithm to be used for
   * encryption/decryption.
   * @param hash_alg     hash algorithm to be used for key derivation.
   * @return an instance of a TokenEncryptor.
   */
  static TokenEncryptorPtr Create(
      const std::string& secret,
      EncryptionAlg enc_alg = EncryptionAlg::AES256GCM,
      HKDFHash hash_alg = HKDFHash::SHA256);
};

}  // namespace session
}  // namespace common
}  // namespace authservice
#endif  // AUTHSERVICE_SRC_COMMON_SESSION_TOKEN_ENCRYPTOR_H_