#include "src/filters/oidc/jwt_verifier.h"

#include <fmt/ostream.h>

#include "jwt_verify_lib/struct_utils.h"
#include "jwt_verify_lib/verify.h"

namespace authservice {
namespace filters {
namespace oidc {

absl::Status JwtVerifier::verify(
    const google::jwt_verify::Jwt& jwt, std::vector<std::string>&& aud,
    absl::flat_hash_map<std::string, std::string>&& expected_fields) const {
  if (google::jwt_verify::verifyJwt(
          jwt, *resolver_cache_->getResolver()->jwks(), std::move(aud)) !=
      google::jwt_verify::Status::Ok) {
    return absl::InvalidArgumentError(
        "failed to verify signature or find expected audiences.");
  }

  for (auto&& [expected_key, expected_value] : expected_fields) {
    google::jwt_verify::StructUtils getter(jwt.payload_pb_);
    std::string actual_value;

    if (getter.GetString(expected_key, &actual_value) !=
        google::jwt_verify::StructUtils::OK) {
      return absl::InvalidArgumentError(fmt::format(
          "JWT does not have expected key {} in the payload", expected_key));
    }
    if (actual_value != expected_value) {
      return absl::InvalidArgumentError(fmt::format(
          "JWT does not have expected key and value {}:{} in the payload",
          expected_key, expected_value));
    }
  }

  return absl::OkStatus();
}

absl::Status JwtVerifier::verify(
    const std::string& jwt, std::vector<std::string>&& aud,
    absl::flat_hash_map<std::string, std::string>&& expected_fields) const {
  google::jwt_verify::Jwt target;
  if (target.parseFromString(jwt) != google::jwt_verify::Status::Ok) {
    return absl::InvalidArgumentError("failed to parse JWT");
  }
  return verify(target, std::move(aud), std::move(expected_fields));
}

}  // namespace oidc
}  // namespace filters
}  // namespace authservice
