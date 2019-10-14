#include "token_response.h"
#include "google/protobuf/struct.pb.h"
#include "google/protobuf/util/json_util.h"
#include "jwt_verify_lib/verify.h"
#include "spdlog/spdlog.h"

namespace transparent_auth {
namespace filters {
namespace oidc {
TokenResponse::TokenResponse(const google::jwt_verify::Jwt &id_token)
    : id_token_(id_token) {}

const google::jwt_verify::Jwt &TokenResponse::IDToken() const {
  return id_token_;
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
  auto token_type = fields.find("token_type");
  if (token_type == fields.end() ||
      !(token_type->second.string_value() == "Bearer" ||
        token_type->second.string_value() ==
            "bearer")) {  // We allow either Bearer or bearer
    spdlog::info("{}: missing or incorrect `token_type` in token response",
                 __func__);
    return absl::nullopt;
  }
  // There must be an id_token
  auto id_token_str = fields.find("id_token");
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
  return absl::make_optional<TokenResponse>(id_token);
}

}  // namespace oidc
}  // namespace filters
}  // namespace transparent_auth
