#ifndef AUTHSERVICE_SESSION_STORE_H
#define AUTHSERVICE_SESSION_STORE_H

#include "src/filters/oidc/token_response.h"

namespace authservice {
namespace filters {
namespace oidc {

class SessionStore;

typedef std::shared_ptr<SessionStore> SessionStorePtr;

class AuthorizationState {

 private:

  std::string state_;
  std::string nonce_;
  std::string requested_url_;

 public:

  AuthorizationState(absl::string_view state, absl::string_view nonce, absl::string_view requestedUrl) :
      state_(state.data()), nonce_(nonce.data()), requested_url_(requestedUrl.data()) {}

  inline std::string &GetState() {
    return state_;
  }

  inline std::string &GetNonce() {
    return nonce_;
  }

  inline std::string &GetRequestedUrl() {
    return requested_url_;
  }

};

class SessionStore {

 public:

  virtual void SetTokenResponse(absl::string_view session_id, std::shared_ptr<TokenResponse> token_response) = 0;

  virtual std::shared_ptr<TokenResponse> GetTokenResponse(absl::string_view session_id) = 0;

  virtual void SetAuthorizationState(absl::string_view session_id,
                                     std::shared_ptr<AuthorizationState> authorization_state) = 0;

  virtual std::shared_ptr<AuthorizationState> GetAuthorizationState(absl::string_view session_id) = 0;

  virtual void ClearAuthorizationState(absl::string_view session_id) = 0;

  virtual void RemoveSession(absl::string_view session_id) = 0;

  virtual void RemoveAllExpired() = 0;

};

}  // namespace oidc
}  // namespace filters
}  // namespace authservice

#endif //AUTHSERVICE_SESSION_STORE_H
