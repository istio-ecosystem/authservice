#ifndef AUTHSERVICE_REDIS_SESSION_STORE_H
#define AUTHSERVICE_REDIS_SESSION_STORE_H

#include "src/filters/oidc/session_store.h"
#include "src/common/utilities/time_service.h"
#include "src/common/utilities/synchronized.h"
#include "src/filters/oidc/redis_wrapper.h"

namespace authservice {
namespace filters {
namespace oidc {

class Session;

class RedisSessionStore : public SessionStore {
private:
  std::unordered_map<std::string, std::shared_ptr<Session>> session_map_;
  std::shared_ptr<common::utilities::TimeService> time_service_;
  uint32_t absolute_session_timeout_in_seconds_;
  uint32_t idle_session_timeout_in_seconds_;
  std::shared_ptr<RedisWrapper> redis_wrapper_;

public:
  RedisSessionStore(
      std::shared_ptr<common::utilities::TimeService> time_service,
      uint32_t absolute_session_timeout_in_seconds,
      uint32_t idle_session_timeout_in_seconds,
      std::shared_ptr<RedisWrapper> redis_wrapper);

  virtual void SetTokenResponse(absl::string_view session_id, std::shared_ptr<TokenResponse> token_response) override;

  virtual std::shared_ptr<TokenResponse> GetTokenResponse(absl::string_view session_id) override;

  virtual void SetAuthorizationState(absl::string_view session_id, std::shared_ptr<AuthorizationState> authorization_state) override;

  virtual std::shared_ptr<AuthorizationState> GetAuthorizationState(absl::string_view session_id) override;

  virtual void ClearAuthorizationState(absl::string_view session_id) override;

  virtual void RemoveSession(absl::string_view session_id) override;

  virtual void RemoveAllExpired() override;

  virtual void RefreshExpiration(absl::string_view session_id);
};

}  // namespace oidc
}  // namespace filters
}  // namespace authservice

#endif //AUTHSERVICE_REDIS_SESSION_STORE_H
