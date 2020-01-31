#ifndef AUTHSERVICE_IN_MEMORY_SESSION_STORE_H
#define AUTHSERVICE_IN_MEMORY_SESSION_STORE_H

#include "src/filters/oidc/session_store.h"
#include "src/common/utilities/time_service.h"

namespace authservice {
namespace filters {
namespace oidc {

class SessionData {
private:
  TokenResponse token_response_;
  uint32_t time_added_;
  uint32_t time_accessed_;

public:
  SessionData(TokenResponse &token_response, uint32_t time_added);

  TokenResponse &GetTokenResponse();

  uint32_t GetTimeAdded();

  uint32_t GetTimeMostRecentlyAccessed();

  void SetTimeMostRecentlyAccessed(uint32_t time_accessed);
};

class InMemorySessionStore : public SessionStore {
private:
  std::unordered_map<std::string, std::shared_ptr<SessionData>> map;
  std::shared_ptr<common::utilities::TimeService> time_service_;
  uint32_t max_absolute_session_timeout_in_seconds_;
  uint32_t max_session_idle_timeout_in_seconds_;

public:
  InMemorySessionStore(
      std::shared_ptr<common::utilities::TimeService> time_service,
      uint32_t max_absolute_session_timeout_in_seconds,
      uint32_t max_session_idle_timeout_in_seconds);

  virtual void Set(absl::string_view session_id, TokenResponse &token_response) override;

  virtual absl::optional<TokenResponse> Get(absl::string_view session_id) override;

  virtual void Remove(absl::string_view session_id) override;

  virtual void RemoveAllExpired() override;
};

}  // namespace oidc
}  // namespace filters
}  // namespace authservice

#endif //AUTHSERVICE_IN_MEMORY_SESSION_STORE_H
