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
  auto redis_session_id = sw::redis::StringView(session_id.data());
  redis_wrapper_->hset(redis_session_id, "id_token", std::string(token_response->IDToken().jwt_));
  redis_wrapper_->hset(redis_session_id, "access_token", sw::redis::StringView(*token_response->AccessToken()));
  redis_wrapper_->hset(redis_session_id, "refresh_token", sw::redis::StringView(*token_response->RefreshToken()));
  redis_wrapper_->hset(redis_session_id,
               "access_token_expiry",
               sw::redis::StringView(std::to_string(*token_response->GetAccessTokenExpiry())));

  redis_wrapper_->hsetnx(redis_session_id,
                 "time_added",
                 sw::redis::StringView(std::to_string(time_service_->GetCurrentTimeInSecondsSinceEpoch())));

  RefreshExpiration(redis_session_id);
}

std::shared_ptr<TokenResponse> RedisSessionStore::GetTokenResponse(absl::string_view session_id) {
  google::jwt_verify::Jwt jwt_id_token;
  auto redis_session_id = sw::redis::StringView(session_id.data());

  if (!redis_wrapper_->hexists(redis_session_id, "id_token")) {
    return nullptr;
  }

  auto status = jwt_id_token.parseFromString(redis_wrapper_->hget(redis_session_id, "id_token").value());
  if (status != google::jwt_verify::Status::Ok) {
    spdlog::info("{}: failed to parse `id_token` into a JWT: {}", __func__,
                 google::jwt_verify::getStatusString(status));
    return nullptr;
  }
  auto access_token = redis_wrapper_->hget(redis_session_id, "access_token");
  auto refresh_token = redis_wrapper_->hget(redis_session_id, "refresh_token");
  auto access_token_expiry = redis_wrapper_->hget(redis_session_id, "access_token_expiry");

  auto token_response = std::make_shared<TokenResponse>(jwt_id_token);

  // TODO: check for existence of these fields
  //set access
  token_response->SetAccessToken(absl::string_view(access_token.value()));
  //set refresh
  token_response->SetRefreshToken(absl::string_view(refresh_token.value()));
  //set access expiry
  token_response->SetAccessTokenExpiry(std::stoi(access_token_expiry.value()));

  RefreshExpiration(redis_session_id);

  return token_response;
}

void RedisSessionStore::RemoveSession(absl::string_view session_id) {
  redis_wrapper_->del(sw::redis::StringView(session_id.data()));
}

void RedisSessionStore::SetAuthorizationState(absl::string_view session_id,
                                              std::shared_ptr<AuthorizationState> authorization_state) {
  auto redis_session_id = sw::redis::StringView(session_id.data());
  redis_wrapper_->hset(redis_session_id, "state", std::string(authorization_state->GetState()));
  redis_wrapper_->hset(redis_session_id, "nonce", sw::redis::StringView(authorization_state->GetNonce()));
  redis_wrapper_->hset(redis_session_id, "requested_url", sw::redis::StringView(authorization_state->GetRequestedUrl()));

  redis_wrapper_->hsetnx(redis_session_id,
                 "time_added",
                 sw::redis::StringView(std::to_string(time_service_->GetCurrentTimeInSecondsSinceEpoch())));

  RefreshExpiration(redis_session_id);
}

std::shared_ptr<AuthorizationState> RedisSessionStore::GetAuthorizationState(absl::string_view session_id) {
  auto redis_session_id = sw::redis::StringView(session_id.data());

  if (!redis_wrapper_->hexists(redis_session_id, "state")) {
    return nullptr;
  }

  auto state = redis_wrapper_->hget(redis_session_id, "state");
  auto nonce = redis_wrapper_->hget(redis_session_id, "nonce");
  auto requested_url = redis_wrapper_->hget(redis_session_id, "requested_url");

  RefreshExpiration(redis_session_id);

  return std::make_shared<AuthorizationState>(absl::string_view(state.value()),
                                              absl::string_view(nonce.value()),
                                              absl::string_view(requested_url.value()));
}

void RedisSessionStore::ClearAuthorizationState(absl::string_view session_id) {
  auto redis_session_id = sw::redis::StringView(session_id.data());

  redis_wrapper_->hdel(redis_session_id, "state");
  redis_wrapper_->hdel(redis_session_id, "nonce");
  redis_wrapper_->hdel(redis_session_id, "requested_url");

  RefreshExpiration(redis_session_id);
}

// abs: 200 idle:60
// 0 expireat(0+60)
//30 expireat(30 +60)
//170 expireat(0 + 200)

void RedisSessionStore::RefreshExpiration(sw::redis::StringView session_id) {
  int current_time = time_service_->GetCurrentTimeInSecondsSinceEpoch();
  int time_added = std::stoi(redis_wrapper_->hget(session_id, "time_added").value());
  if ((absolute_session_timeout_in_seconds_ + time_added) < idle_session_timeout_in_seconds_ + current_time) {
    redis_wrapper_->expireat(session_id, absolute_session_timeout_in_seconds_ + time_added);
  } else {
    redis_wrapper_->expireat(session_id, idle_session_timeout_in_seconds_ + current_time);
  }
}

void RedisSessionStore::RemoveAllExpired() {}

}  // namespace oidc
}  // namespace filters
}  // namespace authservice
