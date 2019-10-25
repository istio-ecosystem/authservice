#ifndef AUTHSERVICE_SRC_COMMON_UTILITIES_RANDOM_H_
#define AUTHSERVICE_SRC_COMMON_UTILITIES_RANDOM_H_
#include <memory>
#include <string>
#include <vector>
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"

namespace authservice {
namespace common {
namespace utilities {
class Random {
 private:
  std::vector<uint8_t> internal_buffer_;

 public:
  /**
   * Construct a Random object from the given randomness.
   * @param randomness Random data.
   * @param len the length of randomness.
   */
  explicit Random(const uint8_t *randomness, size_t len);

  /**
   * Compare the contents of the internal buffers for equality and in constant
   * time.
   * @param rhs The instance to compare for equality.
   * @return True or false.
   */
  bool operator==(const Random &rhs) const;
  bool operator!=(const Random &rhs) const;

  /**
   * The size of the internal random buffer in bytes.
   * @return The number of bytes of randomness.
   */
  size_t Size() const;

  /**
   * An iterator to the first item of the internal buffer.
   * @return A const iterator
   */
  std::vector<uint8_t>::const_iterator Begin() const;
  /**
   * An iterator to indicate an iterator has completed or is not valid.
   * @return A const iterator
   */
  std::vector<uint8_t>::const_iterator End() const;
  /**
   * Encode a representation to string suitable for use in HTTP requests.
   * or unique state index.
   * @return a hex string.
   */
  std::string Str() const;

  /**
   * Decode from the given string representation.
   * @param str The string to decode
   * @return The decoded Random.
   */
  static absl::optional<Random> FromString(absl::string_view str);
};

class RandomGenerator {
 public:
  /**
   * Generate a Random with the requested number of bytes of data read from the
   * generator's random source.
   * @param sz The number of bytes to read from the generator's random source.
   * @return A Random object.
   */
  Random Generate(size_t sz);
};

}  // namespace utilities
}  // namespace common
}  // namespace authservice
#endif  // AUTHSERVICE_SRC_COMMON_UTILITIES_RANDOM_H_
