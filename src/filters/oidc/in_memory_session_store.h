#ifndef AUTHSERVICE_IN_MEMORY_SESSION_STORE_H
#define AUTHSERVICE_IN_MEMORY_SESSION_STORE_H

#include "src/filters/oidc/session_store.h"

namespace authservice {
namespace filters {
namespace oidc {

class InMemorySessionStore : public SessionStore {
private:
  std::unordered_map<std::string, TokenResponse> map;

public:
  virtual void Set(absl::string_view session_id, TokenResponse &token_response);

  virtual absl::optional<TokenResponse> Get(absl::string_view session_id);

  virtual void Remove(absl::string_view session_id);

  virtual void RemoveAllExpired();
};

}  // namespace oidc
}  // namespace filters
}  // namespace authservice

#endif //AUTHSERVICE_IN_MEMORY_SESSION_STORE_H
