#ifndef AUTHSERVICE_SRC_FILTERS_OIDC_STATE_COOKIE_CODEC_H_
#define AUTHSERVICE_SRC_FILTERS_OIDC_STATE_COOKIE_CODEC_H_

#include <map>
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
namespace authservice {
namespace filters {
namespace oidc {
/**
 * Encoder, Decoder for a set of value to placed into a cookie.
 */
class StateCookieCodec {
 public:
  /**
   * Encode the given state values
   * @param state data to be encoded.
   * @param nonce data to be encoded.
   * @return the encoded value
   */
  std::string Encode(absl::string_view state, absl::string_view nonce);
  /**
   * Decode the given state cookie value into a state and nonce pair.
   * @param value the value to decode
   * @return the decoded data.
   */
  absl::optional<std::pair<absl::string_view, absl::string_view>> Decode(
      absl::string_view value);
};

}  // namespace oidc
}  // namespace filters
}  // namespace authservice
#endif  // AUTHSERVICE_SRC_FILTERS_OIDC_STATE_COOKIE_CODEC_H_
