#include "src/common/session/hkdf_deriver.h"
#include <cassert>
#include <exception>
#include "openssl/digest.h"
#include "openssl/hkdf.h"

namespace transparent_auth {
namespace common {
namespace session {

class HkdfDeriverImpl : public HkdfDeriver {
 public:
  HkdfDeriverImpl(std::vector<unsigned char> secret, HKDFHash hash_alg);

  virtual std::vector<unsigned char> Derive(
      size_t out_len, const std::vector<unsigned char>& salt,
      const std::vector<unsigned char>& info = {}) override;

 private:
  std::vector<unsigned char> secret_;
  const EVP_MD* hash_alg_;
};

HkdfDeriverImpl::HkdfDeriverImpl(std::vector<unsigned char> secret,
                                 HKDFHash hash_alg)
    : secret_(std::move(secret)) {
  switch (hash_alg) {
    case HKDFHash::SHA256:
      hash_alg_ = EVP_sha256();
      break;
    case HKDFHash::SHA384:
      hash_alg_ = EVP_sha384();
      break;
    case HKDFHash::SHA512:
      hash_alg_ = EVP_sha512();
      break;
    default:
      throw std::range_error("Unsupport hash algorithm");
  }
}

std::vector<unsigned char> HkdfDeriverImpl::Derive(
    size_t out_len, const std::vector<unsigned char>& salt,
    const std::vector<unsigned char>& info) {
  std::vector<unsigned char> output(out_len);

  auto rc =
      HKDF(output.data(), out_len, hash_alg_, secret_.data(), secret_.size(),
           salt.data(), salt.size(), info.data(), info.size());
  assert(rc == 1);

  return output;
}

HkdfDeriverPtr HkdfDeriver::Create(const std::vector<unsigned char>& secret,
                                   HKDFHash hash_alg) {
  return std::make_shared<HkdfDeriverImpl>(secret, hash_alg);
}
}  // namespace session
}  // namespace common
}  // namespace transparent_auth
