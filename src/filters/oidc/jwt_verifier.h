#ifndef AUTHSERVICE_SRC_FILTERS_OIDC_JWT_VERIFIER_H_
#define AUTHSERVICE_SRC_FILTERS_OIDC_JWT_VERIFYER_H_

#include <string>

#include "absl/container/flat_hash_map.h"
#include "absl/status/status.h"
#include "jwt_verify_lib/jwks.h"
#include "jwt_verify_lib/jwt.h"
#include "src/filters/oidc/jwks_resolver.h"

namespace authservice {
namespace filters {
namespace oidc {

// TODO(shikugawa): add jwt_verifyer_test.cc
class JwtVerifier {
 public:
  JwtVerifier(oidc::JwksResolverCachePtr resolver_cache)
      : resolver_cache_(resolver_cache) {}
  absl::Status verify(
      const google::jwt_verify::Jwt& jwt, std::vector<std::string>&& aud,
      absl::flat_hash_map<std::string, std::string>&& expected_fields) const;
  absl::Status verify(
      const std::string& jwt, std::vector<std::string>&& aud,
      absl::flat_hash_map<std::string, std::string>&& expected_fields) const;

 private:
  JwksResolverCachePtr resolver_cache_;
};

}  // namespace oidc
}  // namespace filters
}  // namespace authservice

#endif
