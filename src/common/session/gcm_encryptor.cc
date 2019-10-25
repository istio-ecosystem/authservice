#include "src/common/session/gcm_encryptor.h"
#include <cassert>

#include "openssl/rand.h"

namespace authservice {
namespace common {
namespace session {

class GcmEncryptorImpl : public GcmEncryptor {
 public:
  GcmEncryptorImpl(const std::vector<unsigned char>& key,
                   size_t tag_len = EVP_AEAD_DEFAULT_TAG_LENGTH);
  virtual ~GcmEncryptorImpl() override;

  virtual std::vector<unsigned char> Seal(
      const std::vector<unsigned char>& plaintext,
      absl::optional<std::vector<unsigned char>> nonce,
      const std::vector<unsigned char>& aad = {}) override;
  virtual absl::optional<std::vector<unsigned char>> Open(
      const std::vector<unsigned char>& ciphertext,
      const std::vector<unsigned char>& aad = {}) override;

 private:
  bssl::UniquePtr<EVP_AEAD_CTX> ctx_;
};

GcmEncryptorImpl::GcmEncryptorImpl(const std::vector<unsigned char>& key,
                                   size_t tag_len) {
  const EVP_AEAD* aead_ = nullptr;
  if (key.size() == EVP_AEAD_key_length(EVP_aead_aes_128_gcm())) {
    aead_ = EVP_aead_aes_128_gcm();
  } else if (key.size() == EVP_AEAD_key_length(EVP_aead_aes_256_gcm())) {
    aead_ = EVP_aead_aes_256_gcm();
  } else {
    throw std::range_error(
        "GCM key is incorrect size, expected 16 or 32 bytes");
  }
  ctx_.reset(EVP_AEAD_CTX_new(aead_, key.data(), key.size(), tag_len));
  assert(ctx_);
}

GcmEncryptorImpl::~GcmEncryptorImpl() {
  EVP_AEAD_CTX_cleanup(ctx_.get());
  ctx_.reset(nullptr);
}

std::vector<unsigned char> GcmEncryptorImpl::Seal(
    const std::vector<unsigned char>& plaintext,
    absl::optional<std::vector<unsigned char>> nonce,
    const std::vector<unsigned char>& aad) {
  auto nonce_len = EVP_AEAD_nonce_length(EVP_AEAD_CTX_aead(ctx_.get()));

  std::vector<unsigned char> actual_nonce;
  if (nonce) {
    if (nonce->size() != nonce_len) {
      throw std::range_error("GCM nonce is incorrect size");
    }
    actual_nonce = *nonce;
  } else {
    // No nonce supplied, so generate a random one
    actual_nonce.resize(nonce_len);
    int rc = RAND_bytes(actual_nonce.data(), nonce_len);
    assert(rc == 1);
  }

  // Create output vector, initially containing the nonce, then reserve maximum
  // required space
  size_t out_len =
      plaintext.size() + EVP_AEAD_max_overhead(EVP_AEAD_CTX_aead(ctx_.get()));
  std::vector<unsigned char> out(actual_nonce);
  out.resize(nonce_len + out_len);

  // Perform the encryption, appending the result to the nonce value
  // Result ciphertext will then contain:
  //     nonce || ciphertext || tag
  auto rc =
      EVP_AEAD_CTX_seal(ctx_.get(), out.data() + nonce_len, &out_len, out_len,
                        actual_nonce.data(), nonce_len, plaintext.data(),
                        plaintext.size(), aad.data(), aad.size());
  assert(rc == 1);

  // Resize down to actual output size
  out.resize(nonce_len + out_len);

  return out;
}

absl::optional<std::vector<unsigned char>> GcmEncryptorImpl::Open(
    const std::vector<unsigned char>& ciphertext,
    const std::vector<unsigned char>& aad) {
  auto nonce_len = EVP_AEAD_nonce_length(EVP_AEAD_CTX_aead(ctx_.get()));

  // Make sure we have at least enough data to not read past the end when we try
  // to access
  // the nonce, and ensure we won't underflow when we do 'ciphertext.size() -
  // nonce_len'
  if (ciphertext.size() < nonce_len) {
    return absl::nullopt;
  }

  size_t out_len = ciphertext.size();
  std::vector<unsigned char> out(out_len);

  auto rc = EVP_AEAD_CTX_open(
      ctx_.get(), out.data(), &out_len, out_len, ciphertext.data(), nonce_len,
      ciphertext.data() + nonce_len, ciphertext.size() - nonce_len, aad.data(),
      aad.size());
  if (rc != 1) {
    // Decryption or validation failed in some way
    return absl::nullopt;
  }

  out.resize(out_len);

  return out;
}

GcmEncryptorPtr GcmEncryptor::Create(const std::vector<unsigned char>& key,
                                     size_t tag_len) {
  return std::make_shared<GcmEncryptorImpl>(key, tag_len);
}

}  // namespace session
}  // namespace common
}  // namespace authservice
