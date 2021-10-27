#ifndef AUTHSERVICE_SRC_FILTERS_OIDC_JWT_VERIFIER_H_
#define AUTHSERVICE_SRC_FILTERS_OIDC_JWT_VERIFYER_H_

#include <string>

#include "absl/container/flat_hash_map.h"
#include "jwt_verify_lib/jwks.h"
#include "jwt_verify_lib/jwt.h"

namespace authservice {
namespace filters {
namespace oidc {

class JwtVerifier {
 public:
  JwtVerifier(google::jwt_verify::JwksPtr& keys) : keys_(keys) {}
  bool verify(
      const google::jwt_verify::Jwt& jwt, std::vector<std::string>&& aud,
      absl::flat_hash_map<std::string, std::string>&& expected_fields) const;
  bool verify(
      const std::string& jwt, std::vector<std::string>&& aud,
      absl::flat_hash_map<std::string, std::string>&& expected_fields) const;

 private:
  google::jwt_verify::JwksPtr& keys_;
};

}  // namespace oidc
}  // namespace filters
}  // namespace authservice

#endif
