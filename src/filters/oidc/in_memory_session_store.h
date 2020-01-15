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
  virtual void set(absl::string_view session_id, TokenResponse &token_response);

  virtual absl::optional<TokenResponse> get(absl::string_view session_id);

  virtual void remove(absl::string_view session_id);
};

}  // namespace oidc
}  // namespace filters
}  // namespace authservice

#endif //AUTHSERVICE_IN_MEMORY_SESSION_STORE_H
