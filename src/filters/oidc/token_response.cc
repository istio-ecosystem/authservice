#include "token_response.h"
#include "google/protobuf/struct.pb.h"
#include "google/protobuf/util/json_util.h"
#include "jwt_verify_lib/verify.h"
#include "spdlog/spdlog.h"

namespace transparent_auth {
namespace filters {
namespace oidc {
namespace {
    const char *token_type_field = "token_type";
    const char *bearer_token_type = "Bearer";
    const char *id_token_field = "id_token";
    const char *access_token_field = "access_token";
} // namespace
TokenResponse::TokenResponse(const google::jwt_verify::Jwt &id_token)
    : id_token_(id_token){}

void TokenResponse::SetAccessToken(absl::string_view access_token) {
  access_token_ = std::string(access_token.data(), access_token.size());
}

const google::jwt_verify::Jwt &TokenResponse::IDToken() const {
  return id_token_;
}

absl::string_view TokenResponse::AccessToken() const {
    return access_token_;
}

TokenResponseParserImpl::TokenResponseParserImpl(
    google::jwt_verify::JwksPtr keys)
    : keys_(std::move(keys)) {}

absl::optional<TokenResponse> TokenResponseParserImpl::Parse(
    absl::string_view nonce, absl::string_view raw) const {
  ::google::protobuf::util::JsonParseOptions options;
  options.ignore_unknown_fields = true;
  options.case_insensitive_enum_parsing = false;
  ::google::protobuf::Struct message;
  ::google::protobuf::StringPiece str(raw.data());
  const auto status =
      ::google::protobuf::util::JsonStringToMessage(str, &message, options);
  if (!status.ok()) {
    spdlog::info("{}: JSON parsing error: {}", __func__,
                 status.message().data());
    return absl::nullopt;
  }
  auto fields = message.fields();
  // https://openid.net/specs/openid-connect-core-1_0.html#TokenResponse
  // token_type must be Bearer
  auto token_type = fields.find(token_type_field);
  if (token_type == fields.end() ||
      !(token_type->second.string_value() == bearer_token_type)) {
    spdlog::info("{}: missing or incorrect `token_type` in token response",
                 __func__);
    return absl::nullopt;
  }
  // There must be an id_token
  auto id_token_str = fields.find(id_token_field);
  if (id_token_str == fields.end() ||
      id_token_str->second.kind_case() !=
          google::protobuf::Value::kStringValue) {
    spdlog::info("{}: missing or invalid `id_token` in token response",
                 __func__);
    return absl::nullopt;
  }

  google::jwt_verify::Jwt id_token;
  auto jwt_status =
      id_token.parseFromString(id_token_str->second.string_value());
  if (jwt_status != google::jwt_verify::Status::Ok) {
    spdlog::info("{}: failed to parse `id_token` into a JWT: {}", __func__,
                 google::jwt_verify::getStatusString(jwt_status));
    return absl::nullopt;
  }
  // TODO: verify the audiences
  jwt_status = google::jwt_verify::verifyJwt(id_token, *keys_);
  if (jwt_status != google::jwt_verify::Status::Ok) {
    spdlog::info("{}: failed to verify `id_token` signature: {}", __func__,
                 google::jwt_verify::getStatusString(jwt_status));
    return absl::nullopt;
  }
  // TODO: verify given nonce.
  auto result = absl::make_optional<TokenResponse>(id_token);
  // There might be an access token too.
  auto access_token_iter = fields.find(access_token_field);
  if (access_token_iter != fields.end()) {
    result->SetAccessToken(access_token_iter->second.string_value());
  }
  return result;
}

}  // namespace oidc
}  // namespace filters
}  // namespace transparent_auth
