#ifndef AUTHSERVICE_SRC_FILTERS_OIDC_AUTHORIZATION_STATE_H_
#define AUTHSERVICE_SRC_FILTERS_OIDC_AUTHORIZATION_STATE_H_

#include "absl/strings/string_view.h"
#include "absl/types/optional.h"

namespace authservice {
namespace filters {
namespace oidc {

class AuthorizationState {
 private:
  std::string state_;
  std::string nonce_;
  std::string requested_url_;

 public:
  AuthorizationState(absl::string_view state, absl::string_view nonce,
                     absl::string_view requestedUrl);

  std::string &GetState();
  std::string &GetNonce();
  std::string &GetRequestedUrl();
};

}  // namespace oidc
}  // namespace filters
}  // namespace authservice
#endif  // AUTHSERVICE_SRC_FILTERS_OIDC_AUTHORIZATION_STATE_H_
