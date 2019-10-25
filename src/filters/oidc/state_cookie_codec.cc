#include "state_cookie_codec.h"
#include <sstream>
#include "absl/strings/str_join.h"
#include "absl/strings/str_split.h"
namespace authservice {
namespace filters {
namespace oidc {
namespace {
const char *separator = ";";
}
std::string StateCookieCodec::Encode(absl::string_view state,
                                     absl::string_view nonce) {
  return absl::StrJoin({state, nonce}, separator);
}

absl::optional<std::pair<absl::string_view, absl::string_view>>
StateCookieCodec::Decode(absl::string_view value) {
  std::vector<absl::string_view> values = absl::StrSplit(value, separator);
  if (values.size() != 2) {
    return absl::nullopt;
  }
  return std::pair<absl::string_view, absl::string_view>(values[0], values[1]);
}

}  // namespace oidc
}  // namespace filters
}  // namespace authservice