#ifndef TRANSPARENT_AUTH_SRC_COMMON_SESSION_HKDF_DERIVER_H_
#define TRANSPARENT_AUTH_SRC_COMMON_SESSION_HKDF_DERIVER_H_
#include <memory>
#include <vector>

namespace transparent_auth {
namespace common {
namespace session {

class HkdfDeriver;
typedef std::shared_ptr<HkdfDeriver> HkdfDeriverPtr;

enum class HKDFHash {
  SHA256,
  SHA384,
  SHA512,
};

class HkdfDeriver {
 public:
  virtual ~HkdfDeriver(){};

  virtual std::vector<unsigned char> Derive(
      size_t out_len, const std::vector<unsigned char>& salt,
      const std::vector<unsigned char>& info = {}) = 0;

  /**
   * Create an instance of a HkdfDeriver.
   * @return an instance of a HkdfDeriver.
   */
  static HkdfDeriverPtr Create(const std::vector<unsigned char>& secret,
                               HKDFHash hash_alg = HKDFHash::SHA256);
};

}  // namespace session
}  // namespace common
}  // namespace transparent_auth
#endif  // TRANSPARENT_AUTH_SRC_COMMON_SESSION_HKDF_DERIVER_H_