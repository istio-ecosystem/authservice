#include "src/filters/oidc/jwt_verifier.h"

#include "jwt_verify_lib/struct_utils.h"
#include "jwt_verify_lib/verify.h"

namespace authservice {
namespace filters {
namespace oidc {

bool JwtVerifier::verify(
    const google::jwt_verify::Jwt& jwt, std::vector<std::string>&& aud,
    absl::flat_hash_map<std::string, std::string>&& expected_fields) const {
  if (google::jwt_verify::verifyJwt(jwt, *keys_, std::move(aud)) !=
      google::jwt_verify::Status::Ok) {
    return false;
  }

  for (auto&& [expected_key, expected_value] : expected_fields) {
    google::jwt_verify::StructUtils getter(jwt.payload_pb_);
    std::string actual_value;

    if (getter.GetString(expected_key, &actual_value) !=
        google::jwt_verify::StructUtils::OK) {
      return false;
    }
    if (actual_value != expected_value) {
      return false;
    }
  }

  return true;
}

bool JwtVerifier::verify(
    const std::string& jwt, std::vector<std::string>&& aud,
    absl::flat_hash_map<std::string, std::string>&& expected_fields) const {
  google::jwt_verify::Jwt target;
  if (target.parseFromString(jwt) != google::jwt_verify::Status::Ok) {
    return false;
  }
  return verify(target, std::move(aud), std::move(expected_fields));
}

}  // namespace oidc
}  // namespace filters
}  // namespace authservice
