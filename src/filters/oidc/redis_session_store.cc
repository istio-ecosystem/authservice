#include <spdlog/spdlog.h>
#include "redis_session_store.h"
#include <string>

namespace authservice {
namespace filters {
namespace oidc {

RedisSessionStore::RedisSessionStore(std::shared_ptr<common::utilities::TimeService> time_service,
                                     uint32_t absolute_session_timeout_in_seconds,
                                     uint32_t idle_session_timeout_in_seconds,
                                     std::shared_ptr<RedisWrapper> redis_wrapper) :
    time_service_(time_service),
    absolute_session_timeout_in_seconds_(absolute_session_timeout_in_seconds),
    idle_session_timeout_in_seconds_(idle_session_timeout_in_seconds),
    redis_wrapper_(redis_wrapper) {}

void RedisSessionStore::SetTokenResponse(absl::string_view session_id, std::shared_ptr<TokenResponse> token_response) {
  redis_wrapper_->hset(session_id, "id_token", std::string(token_response->IDToken().jwt_));
  redis_wrapper_->hset(session_id, "access_token", *token_response->AccessToken());
  redis_wrapper_->hset(session_id, "refresh_token", *token_response->RefreshToken());
  redis_wrapper_->hset(session_id, "access_token_expiry", std::to_string(*token_response->GetAccessTokenExpiry()));

  redis_wrapper_->hsetnx(session_id, "time_added", std::to_string(time_service_->GetCurrentTimeInSecondsSinceEpoch()));

  RefreshExpiration(session_id);
}

std::shared_ptr<TokenResponse> RedisSessionStore::GetTokenResponse(absl::string_view session_id) {
  google::jwt_verify::Jwt jwt_id_token;
  if (!redis_wrapper_->hexists(session_id, "id_token")) {
    return nullptr;
  }

  auto status = jwt_id_token.parseFromString(redis_wrapper_->hget(session_id, "id_token").value());
  if (status != google::jwt_verify::Status::Ok) {
    spdlog::info("{}: failed to parse `id_token` into a JWT: {}", __func__,
                 google::jwt_verify::getStatusString(status));
    return nullptr;
  }

  auto token_response = std::make_shared<TokenResponse>(jwt_id_token);

  auto access_token = redis_wrapper_->hget(session_id, "access_token");
  if (access_token) {
    token_response->SetAccessToken(absl::string_view(access_token.value()));
  }

  auto access_token_expiry = redis_wrapper_->hget(session_id, "access_token_expiry");
  if (access_token_expiry) {
    token_response->SetAccessTokenExpiry(std::stoi(access_token_expiry.value()));
  }

  auto refresh_token = redis_wrapper_->hget(session_id, "refresh_token");
  if (refresh_token) {
    token_response->SetRefreshToken(absl::string_view(refresh_token.value()));
  }

  RefreshExpiration(session_id);

  return token_response;
}

void RedisSessionStore::RemoveSession(absl::string_view session_id) {
  redis_wrapper_->del(session_id);
}

void RedisSessionStore::SetAuthorizationState(absl::string_view session_id,
                                              std::shared_ptr<AuthorizationState> authorization_state) {
  redis_wrapper_->hset(session_id, "state", std::string(authorization_state->GetState()));
  redis_wrapper_->hset(session_id, "nonce", authorization_state->GetNonce());
  redis_wrapper_->hset(session_id, "requested_url", authorization_state->GetRequestedUrl());

  redis_wrapper_->hsetnx(session_id, "time_added", std::to_string(time_service_->GetCurrentTimeInSecondsSinceEpoch()));

  RefreshExpiration(session_id);
}

std::shared_ptr<AuthorizationState> RedisSessionStore::GetAuthorizationState(absl::string_view session_id) {
  if (!redis_wrapper_->hexists(session_id, "state")) {
    return nullptr;
  }

  auto state = redis_wrapper_->hget(session_id, "state");
  auto nonce = redis_wrapper_->hget(session_id, "nonce");
  auto requested_url = redis_wrapper_->hget(session_id, "requested_url");

  RefreshExpiration(session_id);

  return std::make_shared<AuthorizationState>(absl::string_view(state.value()),
                                              absl::string_view(nonce.value()),
                                              absl::string_view(requested_url.value()));
}

void RedisSessionStore::ClearAuthorizationState(absl::string_view session_id) {
  redis_wrapper_->hdel(session_id, "state");
  redis_wrapper_->hdel(session_id, "nonce");
  redis_wrapper_->hdel(session_id, "requested_url");

  RefreshExpiration(session_id);
}

// abs: 200 idle:60
// 0 expireat(0+60)
//30 expireat(30 +60)
//170 expireat(0 + 200)

void RedisSessionStore::RefreshExpiration(absl::string_view session_id) {
  int current_timestamp = time_service_->GetCurrentTimeInSecondsSinceEpoch(); // 1000
  int timestamp_added = std::stoi(redis_wrapper_->hget(session_id, "time_added").value()); // 500
  if ((absolute_session_timeout_in_seconds_ + timestamp_added) < idle_session_timeout_in_seconds_ + current_timestamp) { // if 128 + 995 < 42 + 1000
    redis_wrapper_->expireat(session_id, absolute_session_timeout_in_seconds_ + timestamp_added); // 42 + 995
  } else {
    redis_wrapper_->expireat(session_id, idle_session_timeout_in_seconds_ + current_timestamp); // expireat(42+1000)
  }
}

void RedisSessionStore::RemoveAllExpired() {}

}  // namespace oidc
}  // namespace filters
}  // namespace authservice
