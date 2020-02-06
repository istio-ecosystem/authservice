#include <spdlog/spdlog.h>
#include "in_memory_session_store.h"

namespace authservice {
namespace filters {
namespace oidc {

InMemorySessionStore::InMemorySessionStore(std::shared_ptr<common::utilities::TimeService> time_service,
                                           uint32_t max_absolute_session_timeout_in_seconds,
                                           uint32_t max_session_idle_timeout_in_seconds) :
    time_service_(time_service),
    max_absolute_session_timeout_in_seconds_(max_absolute_session_timeout_in_seconds),
    max_session_idle_timeout_in_seconds_(max_session_idle_timeout_in_seconds) {}

void InMemorySessionStore::Set(absl::string_view session_id, TokenResponse &token_response) {
  synchronized(mutex_) {
    Remove(session_id);
    map.emplace(session_id.data(),
                std::make_shared<SessionData>(token_response, time_service_->GetCurrentTimeInSecondsSinceEpoch()));
  }
}

absl::optional <TokenResponse> InMemorySessionStore::Get(absl::string_view session_id) {
  synchronized(mutex_) {
    auto search = map.find(session_id.data());
    if (search != map.end()) {
      auto value = search->second;
      value->SetTimeMostRecentlyAccessed(time_service_->GetCurrentTimeInSecondsSinceEpoch());
      return absl::optional<TokenResponse>(value->GetTokenResponse());
    } else {
      return absl::nullopt;
    }
  }
}

void InMemorySessionStore::Remove(absl::string_view session_id) {
  synchronized(mutex_) {
    map.erase(session_id.data());
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
    auto it = map.begin();
    while (it != map.end()) {
      auto value = it->second;
      bool expired_based_on_time_added = value->GetTimeAdded() < earliest_time_added_to_keep;
      bool expired_based_on_idle_time = value->GetTimeMostRecentlyAccessed() < earliest_time_idle_to_keep;

      if ((check_time_added && expired_based_on_time_added) || (check_time_idle && expired_based_on_idle_time)) {
        it = map.erase(it);
      } else {
        it++;
      }
    }
  }
}

SessionData::SessionData(TokenResponse &token_response, uint32_t time_added)
    : token_response_(token_response), time_added_(time_added), time_accessed_(time_added) {}

std::string SessionData::to_string() {
  return "expiry:" + std::to_string(token_response_.GetAccessTokenExpiry().value());
}


std::string InMemorySessionStore::to_string() {
  std::string output;
  std::string result;
  std::string convert;
  for (const auto & it : map) {
    convert = it.second->to_string();
    output += (it.first) + ":" + (convert) + ", ";
  }
  result = output.substr(0, output.size() - 2);
  return result;
}

}  // namespace oidc
}  // namespace filters
}  // namespace authservice
