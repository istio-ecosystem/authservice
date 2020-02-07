#include <spdlog/spdlog.h>
#include "in_memory_session_store.h"

namespace authservice {
namespace filters {
namespace oidc {

SessionTokenResponse::SessionTokenResponse(TokenResponse &token_response, uint32_t time_added)
    : token_response_(token_response), time_added_(time_added), time_accessed_(time_added) {}

SessionLocation::SessionLocation(std::string location)
    : location_(location) {}

InMemorySessionStore::InMemorySessionStore(std::shared_ptr<common::utilities::TimeService> time_service,
                                           uint32_t max_absolute_session_timeout_in_seconds,
                                           uint32_t max_session_idle_timeout_in_seconds) :
    time_service_(time_service),
    max_absolute_session_timeout_in_seconds_(max_absolute_session_timeout_in_seconds),
    max_session_idle_timeout_in_seconds_(max_session_idle_timeout_in_seconds) {}

void InMemorySessionStore::SetTokenResponse(absl::string_view session_id, TokenResponse &token_response) {
  synchronized(mutex_) {
    RemoveSessionTokenResponse(session_id);
    token_response_map.emplace(session_id.data(),
                               std::make_shared<SessionTokenResponse>(token_response, time_service_->GetCurrentTimeInSecondsSinceEpoch()));
  }
}

absl::optional<TokenResponse> InMemorySessionStore::GetTokenResponse(absl::string_view session_id) {
  synchronized(mutex_) {
    auto search = token_response_map.find(session_id.data());
    if (search == token_response_map.end()) {
      return absl::nullopt;
    }
    auto value = search->second;
    value->SetTimeMostRecentlyAccessed(time_service_->GetCurrentTimeInSecondsSinceEpoch());
    return absl::optional<TokenResponse>(value->GetTokenResponse());
  }
}

void InMemorySessionStore::SetLocation(absl::string_view session_id, std::string location) {
  synchronized(mutex_) {
    RemoveSessionLocation(session_id);
    location_map.emplace(session_id.data(),
                         std::make_shared<SessionLocation>(location));
  }
}

absl::optional<std::string> InMemorySessionStore::GetLocation(absl::string_view session_id) {
  synchronized(mutex_) {
    auto search = location_map.find(session_id.data());
    if (search == location_map.end()) {
      return absl::nullopt;
    }
    auto session_data = search->second;
    return absl::optional<std::string>(session_data->GetLocation());
  }
}

void InMemorySessionStore::RemoveSessionTokenResponse(absl::string_view session_id) {
  synchronized(mutex_) {
    token_response_map.erase(session_id.data());
  }
}

void InMemorySessionStore::RemoveSessionLocation(absl::string_view session_id) {
  synchronized(mutex_) {
    location_map.erase(session_id.data());
  }
}

void InMemorySessionStore::RemoveAllExpired() {
  auto earliest_time_added_to_keep =
      time_service_->GetCurrentTimeInSecondsSinceEpoch() - max_absolute_session_timeout_in_seconds_;
  auto earliest_time_idle_to_keep =
      time_service_->GetCurrentTimeInSecondsSinceEpoch() - max_session_idle_timeout_in_seconds_;

  bool check_time_added = max_absolute_session_timeout_in_seconds_ > 0;
  bool check_time_idle = max_session_idle_timeout_in_seconds_ > 0;

  synchronized(mutex_) {
    auto it = token_response_map.begin();
    while (it != token_response_map.end()) {
      auto value = it->second;
      bool expired_based_on_time_added = value->GetTimeAdded() < earliest_time_added_to_keep;
      bool expired_based_on_idle_time = value->GetTimeMostRecentlyAccessed() < earliest_time_idle_to_keep;

      if ((check_time_added && expired_based_on_time_added) || (check_time_idle && expired_based_on_idle_time)) {
        it = token_response_map.erase(it);
      } else {
        it++;
      }
    }
  }
}

}  // namespace oidc
}  // namespace filters
}  // namespace authservice
