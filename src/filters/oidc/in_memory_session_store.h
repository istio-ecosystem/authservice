#ifndef AUTHSERVICE_IN_MEMORY_SESSION_STORE_H
#define AUTHSERVICE_IN_MEMORY_SESSION_STORE_H

#include "src/filters/oidc/session_store.h"
#include "src/common/utilities/time_service.h"
#include "src/common/utilities/synchronized.h"

namespace authservice {
namespace filters {
namespace oidc {

class SessionTokenResponse {
private:
  TokenResponse token_response_;
  uint32_t time_added_;
  uint32_t time_accessed_;

public:
  SessionTokenResponse(TokenResponse &token_response, uint32_t time_added);

  inline TokenResponse &GetTokenResponse() {
    return token_response_;
  }

  inline uint32_t GetTimeAdded() {
    return time_added_;
  }

  inline uint32_t GetTimeMostRecentlyAccessed() {
    return time_accessed_;
  }

  inline void SetTimeMostRecentlyAccessed(uint32_t time_accessed) {
    time_accessed_ = time_accessed;
  }

};

class SessionLocation {
private:
  std::string location_;

public:
  SessionLocation(std::string location);

  inline std::string &GetLocation() {
    return location_;
  }
};

class InMemorySessionStore : public SessionStore {
private:
  std::unordered_map<std::string, std::shared_ptr<SessionTokenResponse>> token_response_map;
  std::unordered_map<std::string, std::shared_ptr<SessionLocation>> location_map;
  std::shared_ptr<common::utilities::TimeService> time_service_;
  uint32_t max_absolute_session_timeout_in_seconds_;
  uint32_t max_session_idle_timeout_in_seconds_;
  std::recursive_mutex mutex_;

public:
  InMemorySessionStore(
      std::shared_ptr<common::utilities::TimeService> time_service,
      uint32_t max_absolute_session_timeout_in_seconds,
      uint32_t max_session_idle_timeout_in_seconds);

  virtual void SetTokenResponse(absl::string_view session_id, TokenResponse &token_response) override;

  virtual void SetLocation(absl::string_view session_id, std::string location) override;

  virtual absl::optional<TokenResponse> GetTokenResponse(absl::string_view session_id) override;

  virtual absl::optional<std::string> GetLocation(absl::string_view session_id) override;

  virtual void RemoveSessionTokenResponse(absl::string_view session_id) override;

  virtual void RemoveSessionLocation(absl::string_view session_id) override;

  virtual void RemoveAllExpired() override;
};

}  // namespace oidc
}  // namespace filters
}  // namespace authservice

#endif //AUTHSERVICE_IN_MEMORY_SESSION_STORE_H
