#ifndef TRANSPARENT_AUTH_SRC_COMMON_SESSION_GCM_ENCRYPTOR_H_
#define TRANSPARENT_AUTH_SRC_COMMON_SESSION_GCM_ENCRYPTOR_H_
#include <memory>
#include <vector>

#include "absl/types/optional.h"
#include "openssl/aead.h"

namespace transparent_auth {
namespace common {
namespace session {

class GcmEncryptor;
typedef std::shared_ptr<GcmEncryptor> GcmEncryptorPtr;

class GcmEncryptor {
 public:
  virtual ~GcmEncryptor(){};

  /**
   * GCM encrypt and authenticate some data.
   * @param plaintext the data to encrypt and authenticate.
   * @param nonce     nonce to be used. If none supplied, one will be randomly
   * generated.
   * @param aad       additional authenticated data.
   * @return bytes representing the encrypted/authenticated data (nonce ||
   * ciphertext || tag).
   */
  virtual std::vector<unsigned char> Seal(
      const std::vector<unsigned char>& plaintext,
      absl::optional<std::vector<unsigned char>> nonce = absl::nullopt,
      const std::vector<unsigned char>& aad = {}) = 0;

  /**
   * GCM decrypt and verify some data.
   * @param ciphertext the data (nonce || ciphertext || tag) to be decrypted.
   * @param aad        additional authenticated data.
   * @return bytes representing the decrypted plaintext, or absl::nullopt if
   * verification failed.
   */
  virtual absl::optional<std::vector<unsigned char>> Open(
      const std::vector<unsigned char>& ciphertext,
      const std::vector<unsigned char>& aad = {}) = 0;

  /**
   * Create an instance of a GcmEncryptor.
   * @param key       data of the key used to encrypt/decrypt.
   * @param tag_len   GCM tag length.
   * @return an instance of a GcmEncryptor.
   */
  static GcmEncryptorPtr Create(const std::vector<unsigned char>& key,
                                size_t tag_len = EVP_AEAD_DEFAULT_TAG_LENGTH);
};

}  // namespace session
}  // namespace common
}  // namespace transparent_auth
#endif  // TRANSPARENT_AUTH_SRC_COMMON_SESSION_GCM_ENCRYPTOR_H_