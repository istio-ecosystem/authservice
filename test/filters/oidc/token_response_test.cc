#include "src/filters/oidc/token_response.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace authservice {
namespace filters {
namespace oidc {
namespace {
const char *valid_jwt_signing_key_ =
    "MIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSvvkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdV"
    "ha4s38XM/pa/yr47av7+z3VTmvDRyAHcaT92whREFpLv9cj5lTeJSibyr/Mrm/Yt"
    "jCZVWgaOYIhwrXwKLqPr/11inWsAkfIytvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwz"
    "GTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0e+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1"
    "FtGJiJvOwRsIfVChDpYStTcHTCMqtvWbV6L11BWkpzGXSW4Hv43qa+GSYOD2QU68"
    "Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9MwIDAQAB";
const char *invalid_jwt_signing_key_ =
    "MIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSvvkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdV"
    "ha4s38XM/pa/yr47av7+z3VTmvDRyAHcaT92whREFpLv9cj5lTeJSibyr/Mrm/Yt"
    "jCZVWgaOYIhwrXwKLqPr/11inWsAkfIytvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwz"
    "GTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0e+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1"
    "FtGJiJvOwRsIfVChDpYStTcHTCMqtvWbV6L11BWkpAGXSW4Hv43qa+GSYOD2QU68"
    "Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9MwIDAQAB";

const char *valid_token_response_no_access_token =
    R"({"token_type":"bearer","id_token":"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.POstGetfAytaZS82wHcjoTyoqhMyxXiWdR7Nn7A29DNSl0EiXLdwJ6xC6AfgZWF1bOsS_TuYI3OG85AmiExREkrS6tDfTQ2B3WXlrr-wp5AokiRbz3_oB4OxG-W9KcEEbDRcZc0nH3L7LzYptiy1PtAylQGxHTWZXtGz4ht0bAecBgmpdgXMguEIcoqPJ1n3pIWk_dUZegpqx0Lka21H6XxUTxiy8OcaarA8zdnPUnV6AmNP3ecFawIFYdvJB_cm-GvpCSbr8G8y_Mllj8f4x9nBH8pQux89_6gUY618iYv7tuPWBFfEbLxtF2pZS6YC1aSfLQxeNe8djT9YjpvRZA"})";

const char *valid_token_response_with_access_token =
    R"({"token_type":"Bearer","access_token":"expected","id_token":"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.POstGetfAytaZS82wHcjoTyoqhMyxXiWdR7Nn7A29DNSl0EiXLdwJ6xC6AfgZWF1bOsS_TuYI3OG85AmiExREkrS6tDfTQ2B3WXlrr-wp5AokiRbz3_oB4OxG-W9KcEEbDRcZc0nH3L7LzYptiy1PtAylQGxHTWZXtGz4ht0bAecBgmpdgXMguEIcoqPJ1n3pIWk_dUZegpqx0Lka21H6XxUTxiy8OcaarA8zdnPUnV6AmNP3ecFawIFYdvJB_cm-GvpCSbr8G8y_Mllj8f4x9nBH8pQux89_6gUY618iYv7tuPWBFfEbLxtF2pZS6YC1aSfLQxeNe8djT9YjpvRZA"})";

};  // namespace

TEST(TokenResponseParser, ParseInvalidJSON) {
  auto jwks = google::jwt_verify::Jwks::createFrom(
      valid_jwt_signing_key_, google::jwt_verify::Jwks::PEM);
  EXPECT_EQ(jwks->getStatus(), google::jwt_verify::Status::Ok);
  TokenResponseParserImpl parser(std::move(jwks));
  auto result = parser.Parse("", "invalid json");
  ASSERT_FALSE(result.has_value());
}

TEST(TokenResponseParser, ParseMissingTokenType) {
  auto jwks = google::jwt_verify::Jwks::createFrom(
      valid_jwt_signing_key_, google::jwt_verify::Jwks::PEM);
  EXPECT_EQ(jwks->getStatus(), google::jwt_verify::Status::Ok);
  TokenResponseParserImpl parser(std::move(jwks));
  auto result = parser.Parse("", R"({})");
  ASSERT_FALSE(result.has_value());
}

TEST(TokenResponseParser, ParseInvalidTokenType) {
  auto jwks = google::jwt_verify::Jwks::createFrom(
      valid_jwt_signing_key_, google::jwt_verify::Jwks::PEM);
  EXPECT_EQ(jwks->getStatus(), google::jwt_verify::Status::Ok);
  TokenResponseParserImpl parser(std::move(jwks));
  auto result = parser.Parse("", R"({"token_type":"NotBearer"})");
  ASSERT_FALSE(result.has_value());
}

TEST(TokenResponseParser, ParseMissingIdentityToken) {
  auto jwks = google::jwt_verify::Jwks::createFrom(
      valid_jwt_signing_key_, google::jwt_verify::Jwks::PEM);
  EXPECT_EQ(jwks->getStatus(), google::jwt_verify::Status::Ok);
  TokenResponseParserImpl parser(std::move(jwks));
  auto result = parser.Parse("", R"({"token_type":"Bearer"})");
  ASSERT_FALSE(result.has_value());
}

TEST(TokenResponseParser, ParseInvalidIdentityTokenType) {
  auto jwks = google::jwt_verify::Jwks::createFrom(
      valid_jwt_signing_key_, google::jwt_verify::Jwks::PEM);
  EXPECT_EQ(jwks->getStatus(), google::jwt_verify::Status::Ok);
  TokenResponseParserImpl parser(std::move(jwks));
  auto result = parser.Parse("", R"({"token_type":"Bearer","id_token":1})");
  ASSERT_FALSE(result.has_value());
}

TEST(TokenResponseParser, ParseInvalidJwtEncoding) {
  auto jwks = google::jwt_verify::Jwks::createFrom(
      valid_jwt_signing_key_, google::jwt_verify::Jwks::PEM);
  EXPECT_EQ(jwks->getStatus(), google::jwt_verify::Status::Ok);
  TokenResponseParserImpl parser(std::move(jwks));
  auto result =
      parser.Parse("", R"({"token_type":"Bearer","id_token":"wrong"})");
  ASSERT_FALSE(result.has_value());
}

TEST(TokenResponseParser, ParseInvalidJwtSignature) {
  auto jwks = google::jwt_verify::Jwks::createFrom(
      invalid_jwt_signing_key_, google::jwt_verify::Jwks::PEM);
  EXPECT_EQ(jwks->getStatus(), google::jwt_verify::Status::Ok);
  TokenResponseParserImpl parser(std::move(jwks));
  auto result = parser.Parse("", valid_token_response_no_access_token);
  ASSERT_FALSE(result.has_value());
}

TEST(TokenResponseParser, Parse) {
  auto jwks = google::jwt_verify::Jwks::createFrom(
      valid_jwt_signing_key_, google::jwt_verify::Jwks::PEM);
  EXPECT_EQ(jwks->getStatus(), google::jwt_verify::Status::Ok);
  TokenResponseParserImpl parser(std::move(jwks));

  auto result = parser.Parse("", valid_token_response_no_access_token);
  ASSERT_TRUE(result.has_value());
  auto access_token = result->AccessToken();
  ASSERT_EQ(access_token, std::string());

  result = parser.Parse("", valid_token_response_with_access_token);
  ASSERT_TRUE(result.has_value());
  access_token = result->AccessToken();
  ASSERT_EQ(access_token, absl::string_view("expected"));
}
}  // namespace oidc
}  // namespace filters
}  // namespace authservice
