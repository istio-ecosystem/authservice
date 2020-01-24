#include "token_response.h"
#include "absl/strings/match.h"
#include "absl/time/clock.h"
#include "google/protobuf/struct.pb.h"
#include "google/protobuf/util/json_util.h"
#include "jwt_verify_lib/struct_utils.h"
#include "jwt_verify_lib/verify.h"
#include "spdlog/spdlog.h"

namespace authservice {
namespace filters {
namespace oidc {
namespace {
const char *nonce_field = "nonce";
const char *token_type_field = "token_type";
const char *bearer_token_type = "bearer";
const char *id_token_field = "id_token";
const char *access_token_field = "access_token";
const char *expires_in_field = "expires_in";
const char *refresh_token_field = "refresh_token";
}  // namespace

TokenResponse::TokenResponse(const google::jwt_verify::Jwt &id_token)
    : id_token_(id_token), access_token_expiry_(0) {}

void TokenResponse::SetAccessToken(absl::string_view access_token) {
  access_token_ = std::string(access_token.data(), access_token.size());
}

void TokenResponse::SetRefreshToken(absl::string_view refresh_token) {
  refresh_token_ = std::string(refresh_token.data(), refresh_token.size());
}

void TokenResponse::SetAccessTokenExpiry(int64_t expiry) {
  access_token_expiry_ = expiry;
}

const google::jwt_verify::Jwt &TokenResponse::IDToken() const {
  return id_token_;
}

absl::optional<const std::string> TokenResponse::AccessToken() const {
  if (!access_token_.empty()) {
    return access_token_;
  }
  return absl::nullopt;
}

absl::optional<const std::string> TokenResponse::RefreshToken() const {
  if (!refresh_token_.empty()) {
    return refresh_token_;
  }
  return absl::nullopt;
}

absl::optional<int64_t> TokenResponse::GetAccessTokenExpiry() const {
  if (access_token_expiry_) {
    return access_token_expiry_;
  }
  return absl::nullopt;
}

int64_t TokenResponse::GetIDTokenExpiry() const {
  return static_cast<int64_t>(id_token_.exp_);
}

TokenResponseParserImpl::TokenResponseParserImpl(
    google::jwt_verify::JwksPtr keys)
    : keys_(std::move(keys)) {}


absl::optional<TokenResponse> TokenResponseParserImpl::Parse(
    const std::string &client_id,
    const std::string &nonce,
    const std::string &raw_response_string
) const {
  ::google::protobuf::util::JsonParseOptions options;
  options.ignore_unknown_fields = true;
  options.case_insensitive_enum_parsing = false;
  ::google::protobuf::Struct message;
  ::google::protobuf::StringPiece raw_string_piece(raw_response_string.data());

  const auto status = ::google::protobuf::util::JsonStringToMessage(raw_string_piece, &message, options);
  if (!status.ok()) {
    spdlog::info("{}: JSON parsing error: {}", __func__, status.message().data());
    return absl::nullopt;
  }

  google::protobuf::Map<std::string, google::protobuf::Value> fields = message.fields();

  absl::optional<google::jwt_verify::Jwt> optional_id_token = ParseIDToken(fields);
  if (!optional_id_token.has_value()) {
    return absl::nullopt;
  }

  google::jwt_verify::Jwt &id_token = optional_id_token.value();
  if (IsIDTokenInvalid(client_id, nonce, id_token)) {
    return absl::nullopt;
  }

  auto result = absl::make_optional<TokenResponse>(id_token);

  auto access_token_iter = fields.find(access_token_field);
  if (access_token_iter != fields.end()) {
    result->SetAccessToken(access_token_iter->second.string_value());
  }
  
  auto refresh_token_iter = fields.find(refresh_token_field);
  if (refresh_token_iter != fields.end()) {
    result->SetRefreshToken(refresh_token_iter->second.string_value());
  }

  const absl::optional<int64_t> &expiry = ParseAccessTokenExpiry(fields);
  if (expiry.has_value()) {
    result->SetAccessTokenExpiry(expiry.value());
  }

  if (IsInvalid(fields)) {
    return absl::nullopt;
  }

  return result;
}

absl::optional<TokenResponse> TokenResponseParserImpl::ParseRefreshTokenResponse(
    const TokenResponse existing_token_response,
    const std::string &client_id,
    const std::string &raw_response_string
) const {
  ::google::protobuf::util::JsonParseOptions options;
  options.ignore_unknown_fields = true;
  options.case_insensitive_enum_parsing = false;
  ::google::protobuf::Struct message;
  ::google::protobuf::StringPiece raw_string_piece(raw_response_string.data());

  const auto status = ::google::protobuf::util::JsonStringToMessage(raw_string_piece, &message, options);
  if (!status.ok()) {
    spdlog::info("{}: JSON parsing error: {}", __func__, status.message().data());
    return absl::nullopt;
  }

  google::protobuf::Map<std::string, google::protobuf::Value> fields = message.fields();

  const google::jwt_verify::Jwt &id_token = existing_token_response.IDToken();
  auto result = absl::make_optional<TokenResponse>(id_token);
  auto new_id_token = ParseIDToken(fields);
  if (new_id_token.has_value()) {
    result = absl::make_optional<TokenResponse>(new_id_token.value());
  }

  auto access_token_iter = fields.find(access_token_field);
  if (access_token_iter != fields.end()) {
    result->SetAccessToken(access_token_iter->second.string_value());
  }

  auto refresh_token_iter = fields.find(refresh_token_field);
  if (refresh_token_iter != fields.end()) {
    result->SetRefreshToken(refresh_token_iter->second.string_value());
  }

  const absl::optional<int64_t> &expiry = ParseAccessTokenExpiry(fields);
  if (expiry.has_value()) {
    result->SetAccessTokenExpiry(expiry.value());
  }

  if (IsInvalid(fields)) {
    return absl::nullopt;
  }

  return result;
}

absl::optional<google::jwt_verify::Jwt> TokenResponseParserImpl::ParseIDToken(
    google::protobuf::Map<std::string, google::protobuf::Value> fields
) const {
  google::jwt_verify::Jwt id_token;
  // There must be an id_token
  auto id_token_str = fields.find(id_token_field);
  if (id_token_str == fields.end() ||
      id_token_str->second.kind_case() != google::protobuf::Value::kStringValue) {
    spdlog::info("{}: missing or invalid `id_token` in token response", __func__);
    return absl::nullopt;
  }
  auto jwt_status = id_token.parseFromString(id_token_str->second.string_value());
  if (jwt_status != google::jwt_verify::Status::Ok) {
    spdlog::info("{}: failed to parse `id_token` into a JWT: {}", __func__,
                 google::jwt_verify::getStatusString(jwt_status));
    return absl::nullopt;
  }
  return absl::optional<google::jwt_verify::Jwt>(id_token);
}

bool TokenResponseParserImpl::IsInvalid(google::protobuf::Map<std::string, google::protobuf::Value> &fields) const {

  // https://openid.net/specs/openid-connect-core-1_0.html#TokenResponse
  // token_type must be Bearer
  auto token_type = fields.find(token_type_field);
  if (token_type == fields.end() ||
      !(absl::EqualsIgnoreCase(token_type->second.string_value(), bearer_token_type))) {
    spdlog::info("{}: missing or incorrect `token_type` in token response", __func__);
    return true;
  }

  auto expires_in_iter = fields.find(expires_in_field);
  if (expires_in_iter != fields.end()) {
    auto expires_in = int64_t(expires_in_iter->second.number_value());
    if (expires_in <= 0) {
      spdlog::info("{}: invalid `expired_in` token response field", __func__);
      return true;
    }
  }

  return false;
}

bool TokenResponseParserImpl::IsIDTokenInvalid(
    const std::string &client_id,
    const std::string &nonce,
    google::jwt_verify::Jwt &id_token
) const {
  // Verify the token contains a `nonce` claim and that it matches our expected value.
  // Verify the token signature & that our client_id is set as an entry in the token's `aud` field.
  std::vector<std::string> audiences = {client_id};
  auto jwt_status = google::jwt_verify::verifyJwt(id_token, *keys_, audiences);
  if (jwt_status != google::jwt_verify::Status::Ok) {
    spdlog::info("{}: `id_token` verification failed: {}", __func__, google::jwt_verify::getStatusString(jwt_status));
    return true;
  }

  std::string extracted_nonce;
  google::jwt_verify::StructUtils getter(id_token.payload_pb_);
  if (getter.GetString(nonce_field, &extracted_nonce) != google::jwt_verify::StructUtils::OK) {
    spdlog::info("{}: failed to retrieve `nonce` from id_token", __func__);
    return true;
  }

  if (nonce != extracted_nonce) {
    spdlog::info("{}: invalid `nonce` field in id_token", __func__);
    return true;
  }

  return false;
}

absl::optional<int64_t> TokenResponseParserImpl::ParseAccessTokenExpiry(
    google::protobuf::Map<std::string, google::protobuf::Value> &fields
) const {
  // expires_in field takes precedence over JWT timeout.
  auto expires_in_iter = fields.find(expires_in_field);
  if (expires_in_iter != fields.end()) {
    auto expires_in = int64_t(expires_in_iter->second.number_value());
    // Knock 5 seconds off the expiry time to take into account the time it may have taken to retrieve the token.
    return absl::ToUnixSeconds(absl::Now()) + expires_in - 5;
  }
  return absl::nullopt;
}

}  // namespace oidc
}  // namespace filters
}  // namespace authservice
