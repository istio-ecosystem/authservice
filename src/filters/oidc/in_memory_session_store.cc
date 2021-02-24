#include "in_memory_session_store.h"

#include <spdlog/spdlog.h>

namespace authservice {
namespace filters {
namespace oidc {

class Session {
 private:
  std::shared_ptr<TokenResponse> token_response_;
  std::shared_ptr<AuthorizationState> authorization_state_;
  uint32_t time_added_;
  uint32_t time_accessed_;

 public:
  explicit Session(uint32_t time_added);

  inline uint32_t GetTimeAdded() { return time_added_; }

  inline void SetTimeMostRecentlyAccessed(uint32_t time_accessed) {
    time_accessed_ = time_accessed;
  }

  inline uint32_t GetTimeMostRecentlyAccessed() { return time_accessed_; }

  inline void SetTokenResponse(std::shared_ptr<TokenResponse> token_response) {
    token_response_ = token_response;
  }

  inline std::shared_ptr<TokenResponse> GetTokenResponse() {
    return token_response_;
  }

  inline void SetAuthorizationState(
      std::shared_ptr<AuthorizationState> authorization_state) {
    authorization_state_ = authorization_state;
  }

  inline std::shared_ptr<AuthorizationState> GetAuthorizationState() {
    return authorization_state_;
  }

  inline void ClearAuthorizationState() { authorization_state_ = nullptr; }
};

Session::Session(uint32_t time_added)
    : token_response_(nullptr),
      authorization_state_(nullptr),
      time_added_(time_added),
      time_accessed_(time_added) {}

InMemorySessionStore::InMemorySessionStore(
    std::shared_ptr<common::utilities::TimeService> time_service,
    uint32_t absolute_session_timeout_in_seconds,
    uint32_t idle_session_timeout_in_seconds)
    : time_service_(time_service),
      absolute_session_timeout_in_seconds_(absolute_session_timeout_in_seconds),
      idle_session_timeout_in_seconds_(idle_session_timeout_in_seconds) {}

void InMemorySessionStore::SetTokenResponse(
    absl::string_view session_id,
    std::shared_ptr<TokenResponse> token_response) {
  std::function<void(Session &)> token_response_setter =
      [&token_response](Session &session) {
        session.SetTokenResponse(token_response);
      };
  Set(session_id, token_response_setter);
}

std::shared_ptr<TokenResponse> InMemorySessionStore::GetTokenResponse(
    absl::string_view session_id) {
  synchronized(mutex_) {
    auto session_optional = FindSession(session_id);
    if (!session_optional.has_value()) {
      return nullptr;
    }
    auto session = session_optional.value();
    session->SetTimeMostRecentlyAccessed(
        time_service_->GetCurrentTimeInSecondsSinceEpoch());
    return session->GetTokenResponse();
  }
}

void InMemorySessionStore::RemoveAllExpired() {
  auto earliest_time_added_to_keep =
      time_service_->GetCurrentTimeInSecondsSinceEpoch() -
      absolute_session_timeout_in_seconds_;
  auto earliest_time_idle_to_keep =
      time_service_->GetCurrentTimeInSecondsSinceEpoch() -
      idle_session_timeout_in_seconds_;

  bool should_check_absolute_timeout = absolute_session_timeout_in_seconds_ > 0;
  bool should_check_idle_timeout = idle_session_timeout_in_seconds_ > 0;

  synchronized(mutex_) {
    auto itr = session_map_.begin();
    while (itr != session_map_.end()) {
      auto session = itr->second;
      bool expired_based_on_time_added =
          session->GetTimeAdded() < earliest_time_added_to_keep;
      bool expired_based_on_idle_time =
          session->GetTimeMostRecentlyAccessed() < earliest_time_idle_to_keep;

      if ((should_check_absolute_timeout && expired_based_on_time_added) ||
          (should_check_idle_timeout && expired_based_on_idle_time)) {
        itr = session_map_.erase(itr);
      } else {
        itr++;
      }
    }
  }
}

void InMemorySessionStore::RemoveSession(absl::string_view session_id) {
  synchronized(mutex_) { session_map_.erase(session_id.data()); }
}

absl::optional<std::shared_ptr<Session>> InMemorySessionStore::FindSession(
    absl::string_view session_id) {
  synchronized(mutex_) {
    auto search = session_map_.find(session_id.data());
    if (search == session_map_.end()) {
      return absl::nullopt;
    }
    return absl::optional<std::shared_ptr<Session>>(search->second);
  }
}

void InMemorySessionStore::SetAuthorizationState(
    absl::string_view session_id,
    std::shared_ptr<AuthorizationState> authorization_state) {
  std::function<void(Session &)> authorization_state_setter =
      [&authorization_state](Session &session) {
        session.SetAuthorizationState(authorization_state);
      };
  Set(session_id, authorization_state_setter);
}

std::shared_ptr<AuthorizationState> InMemorySessionStore::GetAuthorizationState(
    absl::string_view session_id) {
  synchronized(mutex_) {
    auto session_optional = FindSession(session_id);
    if (!session_optional.has_value()) {
      return nullptr;
    }
    auto session = session_optional.value();
    session->SetTimeMostRecentlyAccessed(
        time_service_->GetCurrentTimeInSecondsSinceEpoch());
    return session->GetAuthorizationState();
  }
}

void InMemorySessionStore::ClearAuthorizationState(
    absl::string_view session_id) {
  synchronized(mutex_) {
    auto session_optional = FindSession(session_id);
    if (session_optional.has_value()) {
      auto session = session_optional.value();
      session->SetTimeMostRecentlyAccessed(
          time_service_->GetCurrentTimeInSecondsSinceEpoch());
      session->ClearAuthorizationState();
    }
  }
}

void InMemorySessionStore::Set(absl::string_view session_id,
                               std::function<void(Session &session)> &lambda) {
  synchronized(mutex_) {
    auto session_optional = FindSession(session_id);
    if (session_optional.has_value()) {
      auto session = session_optional.value();
      session->SetTimeMostRecentlyAccessed(
          time_service_->GetCurrentTimeInSecondsSinceEpoch());
      lambda(*session);
    } else {
      auto new_session = std::make_shared<Session>(
          time_service_->GetCurrentTimeInSecondsSinceEpoch());
      lambda(*new_session);
      session_map_.emplace(session_id.data(), new_session);
    }
  }
}

}  // namespace oidc
}  // namespace filters
}  // namespace authservice
