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

  virtual void set(absl::string_view session_id, TokenResponse &token_response) = 0;

  virtual absl::optional<TokenResponse> get(absl::string_view session_id) = 0;

  virtual void remove(absl::string_view session_id) = 0;
};

}  // namespace oidc
}  // namespace filters
}  // namespace authservice

#endif //AUTHSERVICE_SESSION_STORE_H
