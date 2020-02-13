#ifndef AUTHSERVICE_IN_MEMORY_SESSION_STORE_H
#define AUTHSERVICE_IN_MEMORY_SESSION_STORE_H

#include "src/filters/oidc/session_store.h"
#include "src/common/utilities/time_service.h"
#include "src/common/utilities/synchronized.h"

namespace authservice {
namespace filters {
namespace oidc {

class Session;

class InMemorySessionStore : public SessionStore {
private:
  std::unordered_map<std::string, std::shared_ptr<Session>> session_map_;
  std::shared_ptr<common::utilities::TimeService> time_service_;
  uint32_t max_absolute_session_timeout_in_seconds_;
  uint32_t max_session_idle_timeout_in_seconds_;
  std::recursive_mutex mutex_;
  virtual absl::optional<std::shared_ptr<Session>> FindSession(absl::string_view session_id);

public:
  InMemorySessionStore(
      std::shared_ptr<common::utilities::TimeService> time_service,
      uint32_t max_absolute_session_timeout_in_seconds,
      uint32_t max_session_idle_timeout_in_seconds);

  virtual void SetTokenResponse(absl::string_view session_id, TokenResponse &token_response) override;

  virtual void SetRequestedURL(absl::string_view session_id, absl::string_view requested_url) override;

  virtual absl::optional<TokenResponse> GetTokenResponse(absl::string_view session_id) override;

  virtual absl::optional<std::string> GetRequestedURL(absl::string_view session_id) override;

  virtual void RemoveSession(absl::string_view session_id) override;

  virtual void RemoveAllExpired() override;
};

}  // namespace oidc
}  // namespace filters
}  // namespace authservice

#endif //AUTHSERVICE_IN_MEMORY_SESSION_STORE_H
