#ifndef AUTHSERVICE_SESSION_STORE_H
#define AUTHSERVICE_SESSION_STORE_H

#include "src/filters/oidc/authorization_state.h"
#include "src/filters/oidc/token_response.h"

namespace authservice {
namespace filters {
namespace oidc {

class SessionStore;

class SessionStore {
 public:
  virtual void SetTokenResponse(
      absl::string_view session_id,
      std::shared_ptr<TokenResponse> token_response) = 0;

  virtual std::shared_ptr<TokenResponse> GetTokenResponse(
      absl::string_view session_id) = 0;

  virtual void SetAuthorizationState(
      absl::string_view session_id,
      std::shared_ptr<AuthorizationState> authorization_state) = 0;

  virtual std::shared_ptr<AuthorizationState> GetAuthorizationState(
      absl::string_view session_id) = 0;

  virtual void ClearAuthorizationState(absl::string_view session_id) = 0;

  virtual void RemoveSession(absl::string_view session_id) = 0;

  virtual void RemoveAllExpired() = 0;
};

class SessionError : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

using SessionStorePtr = std::shared_ptr<SessionStore>;

}  // namespace oidc
}  // namespace filters
}  // namespace authservice

#endif  // AUTHSERVICE_SESSION_STORE_H
