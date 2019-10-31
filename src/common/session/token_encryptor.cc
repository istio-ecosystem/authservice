#include "src/common/session/token_encryptor.h"
#include "absl/strings/escaping.h"
#include "src/common/session/gcm_encryptor.h"
#include "src/common/utilities/random.h"

namespace authservice {
namespace common {
namespace session {

namespace {
const size_t NONCE_SIZE = 32;
const size_t DERIVED_KEY_SIZE = 32;
}  // namespace

class TokenEncryptorImpl : public TokenEncryptor {
 public:
  TokenEncryptorImpl(const std::string& secret, EncryptionAlg enc_alg,
                     HKDFHash hash_alg);

  std::string Encrypt(const std::string& token) override;
  absl::optional<std::string> Decrypt(const std::string& ciphertext) override;

 private:
  EncryptionAlg enc_alg_;
  HkdfDeriverPtr deriver_;
  utilities::RandomGenerator generator_;

  size_t KeySize() const;

  std::vector<unsigned char> EncryptInternal(
      const std::string& token, const std::vector<unsigned char>& key) const;
};

TokenEncryptorImpl::TokenEncryptorImpl(const std::string& secret,
                                       EncryptionAlg enc_alg, HKDFHash hash_alg)
    : enc_alg_(enc_alg) {
  // Get the secret from the config and use it and the claim nonce to derive a
  // new AES-256 key
  std::vector<unsigned char> secret_vec(secret.begin(), secret.end());
  deriver_ = HkdfDeriver::Create(secret_vec, hash_alg);
}

size_t TokenEncryptorImpl::KeySize() const {
  switch (enc_alg_) {
    case EncryptionAlg::AES128GCM:
      return 16;
    case EncryptionAlg::AES256GCM:
      return 32;
    default:
      throw std::range_error("Unsupported encryption algorithm");
  }
}

std::vector<unsigned char> TokenEncryptorImpl::EncryptInternal(
    const std::string& token, const std::vector<unsigned char>& key) const {
  switch (enc_alg_) {
    case EncryptionAlg::AES128GCM:
    case EncryptionAlg::AES256GCM: {
      // Encrypt the JWT, using the derived key and a random nonce
      // Ouput is: gcm_nonce || ciphertext || tag
      auto encryptor = GcmEncryptor::Create(key);
      std::vector<unsigned char> tokenVec(token.begin(), token.end());
      auto encrypted = encryptor->Seal(tokenVec);
      return encrypted;
    }
    default:
      throw std::range_error("Unsupported encryption algorithm");
  }
}

std::string TokenEncryptorImpl::Encrypt(const std::string& token) {
  auto nonce = generator_.Generate(NONCE_SIZE);
  std::vector<unsigned char> nonce_vec(nonce.Begin(), nonce.End());
  auto derivedKey = deriver_->Derive(KeySize(), nonce_vec);

  auto encrypted = EncryptInternal(token, derivedKey);

  // Concatenate the claim nonce and the ciphertext
  // Result is: derive_nonce || gcm_nonce || ciphertext || tag
  std::vector<unsigned char> output(nonce_vec);
  output.insert(output.end(), encrypted.begin(), encrypted.end());

  // UrlBase64 encode the final encrypted JWT
  return absl::WebSafeBase64Escape(absl::string_view(
      reinterpret_cast<const char*>(output.data()), output.size()));
}

absl::optional<std::string> TokenEncryptorImpl::Decrypt(
    const std::string& ciphertext) {
  // UrlBase64 decode the token
  std::string decoded;
  if (!absl::WebSafeBase64Unescape(ciphertext, &decoded) ||
      decoded.size() < NONCE_SIZE) {
    return absl::nullopt;
  }

  std::vector<unsigned char> nonce_vec(decoded.begin(),
                                       decoded.begin() + NONCE_SIZE);
  auto derivedKey = deriver_->Derive(DERIVED_KEY_SIZE, nonce_vec);

  // Decrypt the JWT
  auto decryptor = GcmEncryptor::Create(derivedKey);
  std::vector<unsigned char> ciphertext_vec(decoded.begin() + NONCE_SIZE,
                                            decoded.end());
  auto decrypted = decryptor->Open(ciphertext_vec);

  if (!decrypted) {
    return absl::nullopt;
  }

  return std::string(decrypted->begin(), decrypted->end());
}

TokenEncryptorPtr TokenEncryptor::Create(const std::string& secret,
                                         EncryptionAlg enc_alg,
                                         HKDFHash hash_alg) {
  return std::make_shared<TokenEncryptorImpl>(secret, enc_alg, hash_alg);
}

}  // namespace session
}  // namespace common
}  // namespace authservice