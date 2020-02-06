#ifndef AUTHSERVICE_SESSION_STORE_H
#define AUTHSERVICE_SESSION_STORE_H

#include "src/filters/oidc/token_response.h"

namespace authservice {
namespace filters {
namespace oidc {

class SessionStore;

typedef std::shared_ptr<SessionStore> SessionStorePtr;

class SessionStore {
public:

  virtual void Set(absl::string_view session_id, TokenResponse &token_response) = 0;

  virtual absl::optional<TokenResponse> Get(absl::string_view session_id) = 0;

  virtual void Remove(absl::string_view session_id) = 0;

  virtual void RemoveAllExpired() = 0;
};

}  // namespace oidc
}  // namespace filters
}  // namespace authservice

#endif //AUTHSERVICE_SESSION_STORE_H
