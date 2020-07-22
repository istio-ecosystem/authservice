#include <spdlog/spdlog.h>
#include "redis_session_store.h"
#include <string>

namespace authservice {
namespace filters {
namespace oidc {

namespace {
  const char *id_token_key_ = "id_token";
  const char *access_token_key_ = "access_token";
  const char *access_token_expiry_key_ = "access_token_expiry";
  const char *refresh_token_key_ = "refresh_token";
  const char *state_key_ = "state";
  const char *nonce_key_ = "nonce";
  const char *requested_url_key_ = "requested_url";
  const char *time_added_key_ = "time_added";
} // namespace

RedisSessionStore::RedisSessionStore(std::shared_ptr<common::utilities::TimeService> time_service,
                                     uint32_t absolute_session_timeout_in_seconds,
                                     uint32_t idle_session_timeout_in_seconds,
                                     std::shared_ptr<RedisWrapper> redis_wrapper) :
    time_service_(time_service),
    absolute_session_timeout_in_seconds_(absolute_session_timeout_in_seconds),
    idle_session_timeout_in_seconds_(idle_session_timeout_in_seconds),
    redis_wrapper_(redis_wrapper) {}

void RedisSessionStore::SetTokenResponse(absl::string_view session_id, std::shared_ptr<TokenResponse> token_response) {
  redis_wrapper_->hset(session_id, id_token_key_, std::string(token_response->IDToken().jwt_));

  if (token_response->AccessToken().has_value()) {
    redis_wrapper_->hset(session_id, access_token_key_, *token_response->AccessToken());
  } else {
    redis_wrapper_->hdel(session_id, access_token_key_);
  }

  if (token_response->RefreshToken().has_value()) {
    redis_wrapper_->hset(session_id, refresh_token_key_, *token_response->RefreshToken());
  } else {
    redis_wrapper_->hdel(session_id, refresh_token_key_);
  }

  if (token_response->GetAccessTokenExpiry().has_value()) {
    redis_wrapper_->hset(session_id, access_token_expiry_key_, std::to_string(*token_response->GetAccessTokenExpiry()));
  } else {
    redis_wrapper_->hdel(session_id, access_token_expiry_key_);
  }

  redis_wrapper_->hsetnx(session_id, time_added_key_, std::to_string(time_service_->GetCurrentTimeInSecondsSinceEpoch()));

  RefreshExpiration(session_id);
}

std::shared_ptr<TokenResponse> RedisSessionStore::GetTokenResponse(absl::string_view session_id) {
  google::jwt_verify::Jwt jwt_id_token;
  if (!redis_wrapper_->hexists(session_id, id_token_key_)) {
    return nullptr;
  }

  auto status = jwt_id_token.parseFromString(redis_wrapper_->hget(session_id, id_token_key_).value());
  if (status != google::jwt_verify::Status::Ok) {
    spdlog::info("{}: failed to parse `id_token` into a JWT: {}", __func__,
                 google::jwt_verify::getStatusString(status));
    return nullptr;
  }

  auto token_response = std::make_shared<TokenResponse>(jwt_id_token);

  auto access_token = redis_wrapper_->hget(session_id, access_token_key_);
  if (access_token) {
    token_response->SetAccessToken(absl::string_view(access_token.value()));
  }

  auto access_token_expiry = redis_wrapper_->hget(session_id, access_token_expiry_key_);
  if (access_token_expiry) {
    token_response->SetAccessTokenExpiry(std::stoi(access_token_expiry.value()));
  }

  auto refresh_token = redis_wrapper_->hget(session_id, refresh_token_key_);
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
  redis_wrapper_->hset(session_id, state_key_, std::string(authorization_state->GetState()));
  redis_wrapper_->hset(session_id, nonce_key_, authorization_state->GetNonce());
  redis_wrapper_->hset(session_id, requested_url_key_, authorization_state->GetRequestedUrl());

  redis_wrapper_->hsetnx(session_id, time_added_key_, std::to_string(time_service_->GetCurrentTimeInSecondsSinceEpoch()));

  RefreshExpiration(session_id);
}

std::shared_ptr<AuthorizationState> RedisSessionStore::GetAuthorizationState(absl::string_view session_id) {
  if (!redis_wrapper_->hexists(session_id, state_key_)) {
    return nullptr;
  }

  auto state = redis_wrapper_->hget(session_id, state_key_);
  auto nonce = redis_wrapper_->hget(session_id, nonce_key_);
  auto requested_url = redis_wrapper_->hget(session_id, requested_url_key_);

  RefreshExpiration(session_id);

  return std::make_shared<AuthorizationState>(absl::string_view(state.value()),
                                              absl::string_view(nonce.value()),
                                              absl::string_view(requested_url.value()));
}

void RedisSessionStore::ClearAuthorizationState(absl::string_view session_id) {
  redis_wrapper_->hdel(session_id, state_key_);
  redis_wrapper_->hdel(session_id, nonce_key_);
  redis_wrapper_->hdel(session_id, requested_url_key_);

  RefreshExpiration(session_id);
}

void RedisSessionStore::RefreshExpiration(absl::string_view session_id) {
  auto time_added_opt = redis_wrapper_->hget(session_id, time_added_key_);
  if (!time_added_opt.has_value()) {
    redis_wrapper_->del(session_id);
    return;
  }
  int timestamp_added = std::stoi(time_added_opt.value());
  int current_timestamp = time_service_->GetCurrentTimeInSecondsSinceEpoch();
  if ((absolute_session_timeout_in_seconds_ + timestamp_added) < idle_session_timeout_in_seconds_ + current_timestamp) {
    redis_wrapper_->expireat(session_id, absolute_session_timeout_in_seconds_ + timestamp_added);
  } else {
    redis_wrapper_->expireat(session_id, idle_session_timeout_in_seconds_ + current_timestamp);
  }
}

void RedisSessionStore::RemoveAllExpired() {}

}  // namespace oidc
}  // namespace filters
}  // namespace authservice
