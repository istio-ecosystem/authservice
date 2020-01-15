#include "in_memory_session_store.h"

namespace authservice {
namespace filters {
namespace oidc {

void InMemorySessionStore::set(absl::string_view session_id, TokenResponse &token_response) {
  //TODO: should this be synchronized somehow? can haz multithreads?
  map.erase(session_id.data());
  map.emplace(session_id, token_response);
}

absl::optional<TokenResponse> InMemorySessionStore::get(absl::string_view session_id) {
  auto search = map.find(session_id.data());
  if (search != map.end()) {
    return absl::optional<TokenResponse>(search->second);
  } else {
    return absl::nullopt;
  }
}

void InMemorySessionStore::remove(absl::string_view session_id) {
  map.erase(session_id.data());
}

}  // namespace oidc
}  // namespace filters
}  // namespace authservice
