#include "token_response.h"
#include "google/protobuf/struct.pb.h"
#include "google/protobuf/util/json_util.h"
#include "jwt_verify_lib/struct_utils.h"
#include "jwt_verify_lib/verify.h"
#include "spdlog/spdlog.h"

namespace transparent_auth {
namespace filters {
namespace oidc {
namespace {
    const char *nonce_field = "nonce";
} // namespace
TokenResponse::TokenResponse(const google::jwt_verify::Jwt &id_token)
    : id_token_(id_token) {}

const google::jwt_verify::Jwt &TokenResponse::IDToken() const {
  return id_token_;
}

TokenResponseParserImpl::TokenResponseParserImpl(
    google::jwt_verify::JwksPtr keys)
    : keys_(std::move(keys)) {}

absl::optional<TokenResponse> TokenResponseParserImpl::Parse(
    const std::string &client_id, const std::string &nonce, const std::string &raw) const {
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
  // Verify our client_id is set as an entry in the token's `aud` field.
  std::vector<std::string> audiences = {client_id};
  jwt_status = google::jwt_verify::verifyJwt(id_token, *keys_, audiences);
  if (jwt_status != google::jwt_verify::Status::Ok) {
    spdlog::info("{}: `id_token` verification failed: {}", __func__, google::jwt_verify::getStatusString(jwt_status));
    return absl::nullopt;
  }
  // Verify the token contains a `nonce` claim and that it matches our expected value.
  std::string extracted_nonce;
  google::jwt_verify::StructUtils getter(id_token.payload_pb_);
  if (getter.GetString(nonce_field, &extracted_nonce) != google::jwt_verify::StructUtils::OK) {
    spdlog::info("{}: failed to retrieve `nonce` from id_token", __func__);
    return absl::nullopt;
  }
  if (nonce != extracted_nonce) {
    spdlog::info("{}: invlaid `nonce` field in id_token", __func__);
    return absl::nullopt;
  }
  return absl::make_optional<TokenResponse>(id_token);
}

}  // namespace oidc
}  // namespace filters
}  // namespace transparent_auth
