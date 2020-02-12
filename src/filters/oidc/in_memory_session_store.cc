#include <spdlog/spdlog.h>
#include "in_memory_session_store.h"

namespace authservice {
namespace filters {
namespace oidc {

class Session {
private:
  absl::optional<TokenResponse> token_response_;
  absl::optional<std::string> requested_url_;
  uint32_t time_added_;
  uint32_t time_accessed_;

public:
  Session(uint32_t time_added);

  inline uint32_t GetTimeAdded() {
    return time_added_;
  }

  inline void SetTimeMostRecentlyAccessed(uint32_t time_accessed) {
    time_accessed_ = time_accessed;
  }

  inline uint32_t GetTimeMostRecentlyAccessed() {
    return time_accessed_;
  }

  inline void SetTokenResponse(const TokenResponse &tokenResponse) {
    token_response_ = tokenResponse;
  }

  inline absl::optional<TokenResponse> &GetTokenResponse() {
    return token_response_;
  }

  inline void SetRequestedUrl(absl::string_view requestedUrl) {
    requested_url_ = requestedUrl.data();
  }

  inline absl::optional<std::string> GetRequestedURL() {
    return requested_url_;
  }
};

Session::Session(uint32_t time_added)
    : token_response_(absl::nullopt), requested_url_(absl::nullopt), time_added_(time_added),
      time_accessed_(time_added) {}

InMemorySessionStore::InMemorySessionStore(std::shared_ptr<common::utilities::TimeService> time_service,
                                           uint32_t max_absolute_session_timeout_in_seconds,
                                           uint32_t max_session_idle_timeout_in_seconds) :
    time_service_(time_service),
    max_absolute_session_timeout_in_seconds_(max_absolute_session_timeout_in_seconds),
    max_session_idle_timeout_in_seconds_(max_session_idle_timeout_in_seconds) {}

void InMemorySessionStore::SetTokenResponse(absl::string_view session_id, TokenResponse &token_response) {
  synchronized(mutex_) {
    auto search = session_map.find(session_id.data());
    if (search == session_map.end()) {
      auto new_session = std::make_shared<Session>(time_service_->GetCurrentTimeInSecondsSinceEpoch());
      new_session->SetTokenResponse(token_response);
      session_map.emplace(session_id.data(), new_session);
    } else {
      auto session = search->second;
      session->SetTimeMostRecentlyAccessed(time_service_->GetCurrentTimeInSecondsSinceEpoch());
      session->SetTokenResponse(token_response);
    }
  }
}

absl::optional<TokenResponse> InMemorySessionStore::GetTokenResponse(absl::string_view session_id) {
  synchronized(mutex_) {
    auto search = session_map.find(session_id.data());
    if (search == session_map.end()) {
      return absl::nullopt;
    }
    auto value = search->second;
    value->SetTimeMostRecentlyAccessed(time_service_->GetCurrentTimeInSecondsSinceEpoch());
    return absl::optional<TokenResponse>(value->GetTokenResponse());
  }
}

void InMemorySessionStore::SetRequestedURL(absl::string_view session_id, absl::string_view requested_url) {
  synchronized(mutex_) {
    auto search = session_map.find(session_id.data());
    if (search == session_map.end()) {
      auto new_session = std::make_shared<Session>(time_service_->GetCurrentTimeInSecondsSinceEpoch());
      new_session->SetRequestedUrl(requested_url);
      session_map.emplace(session_id.data(), new_session);
    } else {
      auto session = search->second;
      session->SetTimeMostRecentlyAccessed(time_service_->GetCurrentTimeInSecondsSinceEpoch());
      session->SetRequestedUrl(requested_url);
    }
  }
}

absl::optional<std::string> InMemorySessionStore::GetRequestedURL(absl::string_view session_id) {
  synchronized(mutex_) {
    auto search = session_map.find(session_id.data());
    if (search == session_map.end()) {
      return absl::nullopt;
    }
    auto session = search->second;
    session->SetTimeMostRecentlyAccessed(time_service_->GetCurrentTimeInSecondsSinceEpoch());
    return absl::optional<std::string>(session->GetRequestedURL());
  }
}

void InMemorySessionStore::RemoveSession(absl::string_view session_id) {
  synchronized(mutex_) {
    session_map.erase(session_id.data());
  }
}

void InMemorySessionStore::RemoveAllExpired() {
  auto earliest_time_added_to_keep =
      time_service_->GetCurrentTimeInSecondsSinceEpoch() - max_absolute_session_timeout_in_seconds_;
  auto earliest_time_idle_to_keep =
      time_service_->GetCurrentTimeInSecondsSinceEpoch() - max_session_idle_timeout_in_seconds_;

  bool should_check_absolute_timeout = max_absolute_session_timeout_in_seconds_ > 0;
  bool should_check_idle_timeout = max_session_idle_timeout_in_seconds_ > 0;

  synchronized(mutex_) {
    auto itr = session_map.begin();
    while (itr != session_map.end()) {
      auto session = itr->second;
      bool expired_based_on_time_added = session->GetTimeAdded() < earliest_time_added_to_keep;
      bool expired_based_on_idle_time =
          session->GetTimeMostRecentlyAccessed() < earliest_time_idle_to_keep;

      if ((should_check_absolute_timeout && expired_based_on_time_added) ||
          (should_check_idle_timeout && expired_based_on_idle_time)) {
        itr = session_map.erase(itr);
      } else {
        itr++;
      }
    }
  }
}

}  // namespace oidc
}  // namespace filters
}  // namespace authservice
