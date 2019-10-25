#include "random.h"
#include <iomanip>
#include <sstream>
#include "absl/strings/escaping.h"
#include "openssl/crypto.h"
#include "openssl/rand.h"

namespace authservice {
namespace common {
namespace utilities {

Random::Random(const uint8_t *randomness, size_t len)
    : internal_buffer_(randomness, randomness + len) {}

bool Random::operator==(const Random &rhs) const {
  auto this_size = Size();
  if (this_size != rhs.Size()) {
    return false;
  }
  return CRYPTO_memcmp(internal_buffer_.data(), rhs.internal_buffer_.data(),
                       this_size) == 0;
}

bool Random::operator!=(const Random &rhs) const { return !(*this == rhs); }

size_t Random::Size() const { return internal_buffer_.size(); }

std::vector<uint8_t>::const_iterator Random::Begin() const {
  return internal_buffer_.cbegin();
}

std::vector<uint8_t>::const_iterator Random::End() const {
  return internal_buffer_.cend();
}

std::string Random::Str() const {
  return absl::WebSafeBase64Escape(
      absl::string_view(reinterpret_cast<const char *>(internal_buffer_.data()),
                        internal_buffer_.size()));
}

absl::optional<Random> Random::FromString(absl::string_view str) {
  std::string tmp;
  if (!absl::WebSafeBase64Unescape(str, &tmp)) {
    return absl::nullopt;
  }
  return Random(reinterpret_cast<const uint8_t *>(tmp.c_str()), tmp.size());
}

Random RandomGenerator::Generate(size_t sz) {
  // boringssl guarantees to return 1 (or abort) but we'll play safe
  // and check and abort() just in case.
  uint8_t tmp[sz];
  if (RAND_bytes(tmp, sz) != 1) {
    abort();
  }
  return Random(tmp, sz);
}
}  // namespace utilities
}  // namespace common
}  // namespace authservice
