#include <spdlog/spdlog.h>
#include "in_memory_session_store.h"

namespace authservice {
namespace filters {
namespace oidc {

SessionOfTokenResponse::SessionOfTokenResponse(TokenResponse &token_response, uint32_t time_added)
    : token_response_(token_response), time_added_(time_added), time_accessed_(time_added) {}

SessionOfRequestedURL::SessionOfRequestedURL(std::string requested_url)
    : requested_url_(requested_url) {}

InMemorySessionStore::InMemorySessionStore(std::shared_ptr<common::utilities::TimeService> time_service,
                                           uint32_t max_absolute_session_timeout_in_seconds,
                                           uint32_t max_session_idle_timeout_in_seconds) :
    time_service_(time_service),
    max_absolute_session_timeout_in_seconds_(max_absolute_session_timeout_in_seconds),
    max_session_idle_timeout_in_seconds_(max_session_idle_timeout_in_seconds) {}

void InMemorySessionStore::SetTokenResponse(absl::string_view session_id, TokenResponse &token_response) {
  synchronized(mutex_) {
    RemoveSessionOfTokenResponse(session_id);
    token_response_map.emplace(session_id.data(),
                               std::make_shared<SessionOfTokenResponse>(token_response, time_service_->GetCurrentTimeInSecondsSinceEpoch()));
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

void InMemorySessionStore::SetRequestedURL(absl::string_view session_id, std::string requested_url) {
  synchronized(mutex_) {
    RemoveSessionOfRequestedURL(session_id);
    url_map.emplace(session_id.data(),
                    std::make_shared<SessionOfRequestedURL>(requested_url));
  }
}

absl::optional<std::string> InMemorySessionStore::GetRequestedURL(absl::string_view session_id) {
  synchronized(mutex_) {
    auto search = url_map.find(session_id.data());
    if (search == url_map.end()) {
      return absl::nullopt;
    }
    auto session_data = search->second;
    return absl::optional<std::string>(session_data->GetRequestedURL());
  }
}

void InMemorySessionStore::RemoveSessionOfTokenResponse(absl::string_view session_id) {
  synchronized(mutex_) {
    token_response_map.erase(session_id.data());
  }
}

void InMemorySessionStore::RemoveSessionOfRequestedURL(absl::string_view session_id) {
  synchronized(mutex_) {
    url_map.erase(session_id.data());
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
    auto it = token_response_map.begin();
    while (it != token_response_map.end()) {
      auto value = it->second;
      bool expired_based_on_time_added = value->GetTimeAdded() < earliest_time_added_to_keep;
      bool expired_based_on_idle_time = value->GetTimeMostRecentlyAccessed() < earliest_time_idle_to_keep;

      if ((should_check_absolute_timeout && expired_based_on_time_added) || (should_check_idle_timeout && expired_based_on_idle_time)) {
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
