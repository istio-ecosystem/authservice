#include "authorization_state.h"
#include "absl/strings/match.h"

namespace authservice {
namespace filters {
namespace oidc {

AuthorizationState::AuthorizationState(absl::string_view state, absl::string_view nonce, absl::string_view requestedUrl)
    : state_(state.data()), nonce_(nonce.data()), requested_url_(requestedUrl.data()) {}

std::string &AuthorizationState::GetState() {
  return state_;
}

std::string &AuthorizationState::GetNonce() {
  return nonce_;
}

std::string &AuthorizationState::GetRequestedUrl() {
  return requested_url_;
}

}  // namespace oidc
}  // namespace filters
}  // namespace authservice
