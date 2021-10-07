#ifndef AUTHSERVICE_SRC_FILTERS_OIDC_TOKEN_RESPONSE_H_
#define AUTHSERVICE_SRC_FILTERS_OIDC_TOKEN_RESPONSE_H_

#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "jwt_verify_lib/jwks.h"
#include "jwt_verify_lib/jwt.h"

namespace authservice {
namespace filters {
namespace oidc {

/**
 * TokenResponse represents a response from a token retrieval request as defined
 * in
 * https://openid.net/specs/openid-connect-core-1_0.html#TokenResponse.
 */
class TokenResponse {
 private:
  google::jwt_verify::Jwt id_token_;
  std::string access_token_;
  std::string refresh_token_;
  int64_t access_token_expiry_;

 public:
  TokenResponse(const google::jwt_verify::Jwt &id_token);
  void SetAccessToken(absl::string_view access_token);
  void SetRefreshToken(absl::string_view refresh_token);
  void SetAccessTokenExpiry(int64_t expiry);
  const google::jwt_verify::Jwt &IDToken() const;
  absl::optional<const std::string> AccessToken() const;
  absl::optional<const std::string> RefreshToken() const;
  absl::optional<int64_t> GetAccessTokenExpiry() const;
  int64_t GetIDTokenExpiry() const;
};

class TokenResponseParser;
typedef std::shared_ptr<TokenResponseParser> TokenResponseParserPtr;

/**
 * TokenResponseParser provides methods for parsing a raw input stream into a
 * @refitem TokenResponse.
 */
class TokenResponseParser {
 public:
  virtual ~TokenResponseParser(){};

  /**
   * Parse the given token response.
   * @param client_id the expected client_id that should be present in the
   * id_token `aud` field.
   * @param nonce the expected nonce that should be present in the id_token
   * @param raw the raw response to be parsed
   * @return either an empty result indicating an error or a TokenResponse.
   */
  virtual std::shared_ptr<TokenResponse> Parse(
      const std::string &client_id, const std::string &nonce,
      const std::string &raw) const = 0;

  virtual std::shared_ptr<TokenResponse> ParseRefreshTokenResponse(
      const TokenResponse &existing_token_response,
      const std::string &raw_response_string) const = 0;
};

/**
 * TokenResponseParser provides methods for parsing a raw input stream into a
 * @refitem TokenResponse.
 */
class TokenResponseParserImpl final : public TokenResponseParser {
 private:
  google::jwt_verify::JwksPtr &keys_;

  absl::optional<int64_t> ParseAccessTokenExpiry(
      google::protobuf::Map<std::string, google::protobuf::Value> &fields)
      const;

  bool IsInvalid(google::protobuf::Map<std::string, google::protobuf::Value>
                     &fields) const;

  bool IsIDTokenInvalid(const std::string &client_id, const std::string &nonce,
                        google::jwt_verify::Jwt &id_token) const;

  absl::optional<google::jwt_verify::Jwt> ParseIDToken(
      google::protobuf::Map<std::string, google::protobuf::Value> fields) const;

 public:
  TokenResponseParserImpl(google::jwt_verify::JwksPtr &keys);
  std::shared_ptr<TokenResponse> Parse(
      const std::string &client_id, const std::string &nonce,
      const std::string &raw_response_string) const override;

  std::shared_ptr<TokenResponse> ParseRefreshTokenResponse(
      const TokenResponse &existing_token_response,
      const std::string &raw_response_string) const override;
};

}  // namespace oidc
}  // namespace filters
}  // namespace authservice
#endif  // AUTHSERVICE_SRC_FILTERS_OIDC_TOKEN_RESPONSE_H_
