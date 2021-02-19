#include "redis_session_store.h"

#include <spdlog/spdlog.h>

#include <string>

namespace authservice {
namespace filters {
namespace oidc {

namespace {
std::string id_token_key_ = "id_token";
std::string access_token_key_ = "access_token";
std::string access_token_expiry_key_ = "access_token_expiry";
std::string refresh_token_key_ = "refresh_token";
std::string state_key_ = "state";
std::string nonce_key_ = "nonce";
std::string requested_url_key_ = "requested_url";
std::string time_added_key_ = "time_added";
}  // namespace

RedisSessionStore::RedisSessionStore(
    std::shared_ptr<common::utilities::TimeService> time_service,
    uint32_t absolute_session_timeout_in_seconds,
    uint32_t idle_session_timeout_in_seconds,
    std::shared_ptr<RedisRetryWrapper> redis_wrapper)
    : time_service_(time_service),
      absolute_session_timeout_in_seconds_(absolute_session_timeout_in_seconds),
      idle_session_timeout_in_seconds_(idle_session_timeout_in_seconds),
      redis_wrapper_(redis_wrapper) {}

void RedisSessionStore::SetTokenResponse(
    absl::string_view session_id,
    std::shared_ptr<TokenResponse> token_response) {
  // TODO: update tests in this class to throw RedisErrors and ensure they're
  // rethrown as SessionErrors
  try {
    redis_wrapper_->hset(session_id, id_token_key_,
                         std::string(token_response->IDToken().jwt_));
    std::vector<std::string> keys_to_be_deleted;

    if (token_response->AccessToken().has_value()) {
      redis_wrapper_->hset(session_id, access_token_key_,
                           *token_response->AccessToken());
    } else {
      keys_to_be_deleted.emplace_back(access_token_key_);
    }

    if (token_response->RefreshToken().has_value()) {
      redis_wrapper_->hset(session_id, refresh_token_key_,
                           *token_response->RefreshToken());
    } else {
      keys_to_be_deleted.emplace_back(refresh_token_key_);
    }

    if (token_response->GetAccessTokenExpiry().has_value()) {
      redis_wrapper_->hset(
          session_id, access_token_expiry_key_,
          std::to_string(*token_response->GetAccessTokenExpiry()));
    } else {
      keys_to_be_deleted.emplace_back(access_token_expiry_key_);
    }

    if (!keys_to_be_deleted.empty()) {
      redis_wrapper_->hdel(session_id, keys_to_be_deleted);
    }
    redis_wrapper_->hsetnx(
        session_id, time_added_key_,
        std::to_string(time_service_->GetCurrentTimeInSecondsSinceEpoch()));

    RefreshExpiration(session_id);
  } catch (RedisError &redisError) {
    throw SessionError(redisError.what());
  }
}

std::shared_ptr<TokenResponse> RedisSessionStore::GetTokenResponse(
    absl::string_view session_id) {
  const auto fields = std::vector<std::string>(
      {id_token_key_, access_token_key_, refresh_token_key_,
       access_token_expiry_key_, time_added_key_});

  std::unordered_map<std::string, absl::optional<std::string>>
      token_response_map;
  try {
    token_response_map = redis_wrapper_->hmget(session_id, fields);
  } catch (RedisError &redisError) {
    throw SessionError(redisError.what());
  }

  if (!token_response_map.at(id_token_key_)) {
    spdlog::trace("{}: id_token not found, returning null token_response",
                  __func__);
    return nullptr;
  }

  google::jwt_verify::Jwt jwt_id_token;
  auto status = jwt_id_token.parseFromString(
      token_response_map.at(id_token_key_).value());
  if (status != google::jwt_verify::Status::Ok) {
    spdlog::info("{}: failed to parse `id_token` into a JWT: {}", __func__,
                 google::jwt_verify::getStatusString(status));
    return nullptr;
  }

  auto token_response = std::make_shared<TokenResponse>(jwt_id_token);

  auto access_token = token_response_map.at(access_token_key_);
  if (access_token) {
    token_response->SetAccessToken(absl::string_view(access_token.value()));
  }

  auto access_token_expiry = token_response_map.at(access_token_expiry_key_);
  if (access_token_expiry) {
    token_response->SetAccessTokenExpiry(
        std::stoi(access_token_expiry.value()));
  }

  auto refresh_token = token_response_map.at(refresh_token_key_);
  if (refresh_token) {
    token_response->SetRefreshToken(absl::string_view(refresh_token.value()));
  }

  RefreshExpiration(session_id, token_response_map.at(time_added_key_));

  return token_response;
}

void RedisSessionStore::RemoveSession(absl::string_view session_id) {
  try {
    redis_wrapper_->del(session_id);
  } catch (RedisError &redisError) {
    throw SessionError(redisError.what());
  }
}

void RedisSessionStore::SetAuthorizationState(
    absl::string_view session_id,
    std::shared_ptr<AuthorizationState> authorization_state) {
  try {
    std::unordered_map<std::string, std::string> auth_state_map = {
        {state_key_, std::string(authorization_state->GetState())},
        {nonce_key_, authorization_state->GetNonce()},
        {requested_url_key_, authorization_state->GetRequestedUrl()},
    };
    redis_wrapper_->hmset(session_id, auth_state_map);

    redis_wrapper_->hsetnx(
        session_id, time_added_key_,
        std::to_string(time_service_->GetCurrentTimeInSecondsSinceEpoch()));

    RefreshExpiration(session_id);
  } catch (RedisError &redisError) {
    throw SessionError(redisError.what());
  }
}

std::shared_ptr<AuthorizationState> RedisSessionStore::GetAuthorizationState(
    absl::string_view session_id) {
  try {
    const auto fields = std::vector<std::string>(
        {state_key_, nonce_key_, requested_url_key_, time_added_key_});

    auto auth_state_map = redis_wrapper_->hmget(session_id, fields);

    auto state = auth_state_map.at(state_key_);
    auto nonce = auth_state_map.at(nonce_key_);
    auto requested_url = auth_state_map.at(requested_url_key_);

    if (!state || !nonce || !requested_url) {
      return nullptr;
    }

    RefreshExpiration(session_id, auth_state_map.at(time_added_key_));

    return std::make_shared<AuthorizationState>(state.value(), nonce.value(),
                                                requested_url.value());
  } catch (RedisError &redisError) {
    throw SessionError(redisError.what());
  }
}

void RedisSessionStore::ClearAuthorizationState(absl::string_view session_id) {
  try {
    std::vector<std::string> keys = {state_key_, nonce_key_,
                                     requested_url_key_};
    redis_wrapper_->hdel(session_id, keys);
    RefreshExpiration(session_id);
  } catch (RedisError &redisError) {
    throw SessionError(redisError.what());
  }
}

void RedisSessionStore::RefreshExpiration(absl::string_view session_id) {
  auto time_added_opt = redis_wrapper_->hget(session_id, time_added_key_);
  RefreshExpiration(session_id, time_added_opt);
}

void RedisSessionStore::RefreshExpiration(
    absl::string_view session_id, absl::optional<std::string> time_added_opt) {
  if (!time_added_opt.has_value()) {
    redis_wrapper_->del(session_id);
    throw SessionError(
        "Unexpected error: Session did not contain creation timestamp");
  }
  auto time_added = std::stoi(time_added_opt.value());
  auto current_time = time_service_->GetCurrentTimeInSecondsSinceEpoch();
  if (absolute_session_timeout_in_seconds_ == 0 &&
      idle_session_timeout_in_seconds_ == 0) {
    return;
  }
  if (absolute_session_timeout_in_seconds_ == 0) {
    redis_wrapper_->expireat(session_id,
                             idle_session_timeout_in_seconds_ + current_time);
  } else if (idle_session_timeout_in_seconds_ == 0) {
    redis_wrapper_->expireat(session_id,
                             absolute_session_timeout_in_seconds_ + time_added);
  } else {
    auto absolute_end_time = absolute_session_timeout_in_seconds_ + time_added;
    auto idle_end_time = idle_session_timeout_in_seconds_ + current_time;
    auto expire_at_time =
        absolute_end_time < idle_end_time ? absolute_end_time : idle_end_time;
    redis_wrapper_->expireat(session_id, expire_at_time);
  }
}

void RedisSessionStore::RemoveAllExpired() {}

}  // namespace oidc
}  // namespace filters
}  // namespace authservice
