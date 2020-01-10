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

const char *client_id = "client1";
const char *nonce = "random";
const char *valid_token_response_Bearer_without_access_token =
    R"({"token_type":"Bearer","id_token":"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMiwiYXVkIjpbImNsaWVudDEiXSwibm9uY2UiOiJyYW5kb20ifQ.NQi_VTRjZ8jv5cAp4inpuQ9STfVgCoWfONjLnZEMk8la8s99J9b6QmcKtO2tabTgvcseikVNlPuB6fZztY_fxhdrNE0dBNAl1lhz_AWBz6Yr-D82LLKk5NQ-IKDloF19Pic0Ub9pGCqNLOlmRXRVcfwwq5nISzfP6OdrjepRZ2Jd3rc2HvHYm-6GstH4xkKViABVwCDmwlAOi47bdHPByHkZOOnHSQEElr4tqO_uAQRpj36Yvt-95nPKhWaufZhcpYKk1H7ZRmylJQuG_dhlw4gN1i5iWBMk-Sj_2xyk05Bap1qkKSeHTxyqzhtDAH0LHYZdo_2hU-7YnL4JRhVVwg"})";
const char *valid_token_response_bearer_with_access_token =
    R"({"token_type":"bearer","access_token":"access_token_value","expires_in":3600,"id_token":"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMiwiYXVkIjpbImNsaWVudDEiXSwibm9uY2UiOiJyYW5kb20ifQ.NQi_VTRjZ8jv5cAp4inpuQ9STfVgCoWfONjLnZEMk8la8s99J9b6QmcKtO2tabTgvcseikVNlPuB6fZztY_fxhdrNE0dBNAl1lhz_AWBz6Yr-D82LLKk5NQ-IKDloF19Pic0Ub9pGCqNLOlmRXRVcfwwq5nISzfP6OdrjepRZ2Jd3rc2HvHYm-6GstH4xkKViABVwCDmwlAOi47bdHPByHkZOOnHSQEElr4tqO_uAQRpj36Yvt-95nPKhWaufZhcpYKk1H7ZRmylJQuG_dhlw4gN1i5iWBMk-Sj_2xyk05Bap1qkKSeHTxyqzhtDAH0LHYZdo_2hU-7YnL4JRhVVwg"})";
const char *valid_token_response_bearer_with_access_token_and_refresh_token =
    R"({"token_type":"bearer","access_token":"access_token_value","refresh_token":"refresh_token_value","expires_in":3600,"id_token":"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMiwiYXVkIjpbImNsaWVudDEiXSwibm9uY2UiOiJyYW5kb20ifQ.NQi_VTRjZ8jv5cAp4inpuQ9STfVgCoWfONjLnZEMk8la8s99J9b6QmcKtO2tabTgvcseikVNlPuB6fZztY_fxhdrNE0dBNAl1lhz_AWBz6Yr-D82LLKk5NQ-IKDloF19Pic0Ub9pGCqNLOlmRXRVcfwwq5nISzfP6OdrjepRZ2Jd3rc2HvHYm-6GstH4xkKViABVwCDmwlAOi47bdHPByHkZOOnHSQEElr4tqO_uAQRpj36Yvt-95nPKhWaufZhcpYKk1H7ZRmylJQuG_dhlw4gN1i5iWBMk-Sj_2xyk05Bap1qkKSeHTxyqzhtDAH0LHYZdo_2hU-7YnL4JRhVVwg"})";
const char *invalid_expires_in_token_response =
    R"({"token_type":"bearer","access_token":"expected","expires_in":-1,"id_token":"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMiwiYXVkIjpbImNsaWVudDEiXSwibm9uY2UiOiJyYW5kb20ifQ.NQi_VTRjZ8jv5cAp4inpuQ9STfVgCoWfONjLnZEMk8la8s99J9b6QmcKtO2tabTgvcseikVNlPuB6fZztY_fxhdrNE0dBNAl1lhz_AWBz6Yr-D82LLKk5NQ-IKDloF19Pic0Ub9pGCqNLOlmRXRVcfwwq5nISzfP6OdrjepRZ2Jd3rc2HvHYm-6GstH4xkKViABVwCDmwlAOi47bdHPByHkZOOnHSQEElr4tqO_uAQRpj36Yvt-95nPKhWaufZhcpYKk1H7ZRmylJQuG_dhlw4gN1i5iWBMk-Sj_2xyk05Bap1qkKSeHTxyqzhtDAH0LHYZdo_2hU-7YnL4JRhVVwg"})";
};  // namespace

TEST(TokenResponseParser, ParseInvalidJSON) {
  auto jwks = google::jwt_verify::Jwks::createFrom(
      valid_jwt_signing_key_, google::jwt_verify::Jwks::PEM);
  EXPECT_EQ(jwks->getStatus(), google::jwt_verify::Status::Ok);
  TokenResponseParserImpl parser(std::move(jwks));
  auto result = parser.Parse(client_id, nonce, "invalid json");
  ASSERT_FALSE(result.has_value());
}

TEST(TokenResponseParser, ParseMissingTokenType) {
  auto jwks = google::jwt_verify::Jwks::createFrom(
      valid_jwt_signing_key_, google::jwt_verify::Jwks::PEM);
  EXPECT_EQ(jwks->getStatus(), google::jwt_verify::Status::Ok);
  TokenResponseParserImpl parser(std::move(jwks));
  auto result = parser.Parse(client_id, nonce, R"({})");
  ASSERT_FALSE(result.has_value());
}

TEST(TokenResponseParser, ParseInvalidTokenType) {
  auto jwks = google::jwt_verify::Jwks::createFrom(
      valid_jwt_signing_key_, google::jwt_verify::Jwks::PEM);
  EXPECT_EQ(jwks->getStatus(), google::jwt_verify::Status::Ok);
  TokenResponseParserImpl parser(std::move(jwks));
  auto result = parser.Parse(client_id, nonce, R"({"token_type":"NotBearer"})");
  ASSERT_FALSE(result.has_value());
}

TEST(TokenResponseParser, ParseMissingIdentityToken) {
  auto jwks = google::jwt_verify::Jwks::createFrom(
      valid_jwt_signing_key_, google::jwt_verify::Jwks::PEM);
  EXPECT_EQ(jwks->getStatus(), google::jwt_verify::Status::Ok);
  TokenResponseParserImpl parser(std::move(jwks));
  auto result = parser.Parse(client_id, nonce, R"({"token_type":"Bearer"})");
  ASSERT_FALSE(result.has_value());
}

TEST(TokenResponseParser, ParseInvalidIdentityTokenType) {
  auto jwks = google::jwt_verify::Jwks::createFrom(
      valid_jwt_signing_key_, google::jwt_verify::Jwks::PEM);
  EXPECT_EQ(jwks->getStatus(), google::jwt_verify::Status::Ok);
  TokenResponseParserImpl parser(std::move(jwks));
  auto result = parser.Parse(client_id, nonce, R"({"token_type":"Bearer","id_token":1})");
  ASSERT_FALSE(result.has_value());
}

TEST(TokenResponseParser, ParseInvalidJwtEncoding) {
  auto jwks = google::jwt_verify::Jwks::createFrom(
      valid_jwt_signing_key_, google::jwt_verify::Jwks::PEM);
  EXPECT_EQ(jwks->getStatus(), google::jwt_verify::Status::Ok);
  TokenResponseParserImpl parser(std::move(jwks));
  auto result =
      parser.Parse(client_id, nonce, R"({"token_type":"Bearer","id_token":"wrong"})");
  ASSERT_FALSE(result.has_value());
}

TEST(TokenResponseParser, ParseInvalidJwtSignature) {
  auto jwks = google::jwt_verify::Jwks::createFrom(
      invalid_jwt_signing_key_, google::jwt_verify::Jwks::PEM);
  EXPECT_EQ(jwks->getStatus(), google::jwt_verify::Status::Ok);
  TokenResponseParserImpl parser(std::move(jwks));
  auto result = parser.Parse(client_id, nonce, valid_token_response_Bearer_without_access_token);
  ASSERT_FALSE(result.has_value());
}

TEST(TokenResponseParser, ParseMissingAudience) {
  auto jwks = google::jwt_verify::Jwks::createFrom(
      invalid_jwt_signing_key_, google::jwt_verify::Jwks::PEM);
  EXPECT_EQ(jwks->getStatus(), google::jwt_verify::Status::Ok);
  TokenResponseParserImpl parser(std::move(jwks));
  auto result = parser.Parse("missing", nonce, valid_token_response_Bearer_without_access_token);
  ASSERT_FALSE(result.has_value());
}

TEST(TokenResponseParser, ParseInvalidNonce) {
  auto jwks = google::jwt_verify::Jwks::createFrom(
      invalid_jwt_signing_key_, google::jwt_verify::Jwks::PEM);
  EXPECT_EQ(jwks->getStatus(), google::jwt_verify::Status::Ok);
  TokenResponseParserImpl parser(std::move(jwks));
  auto result = parser.Parse(client_id, "invalid", valid_token_response_Bearer_without_access_token);
  ASSERT_FALSE(result.has_value());
}

TEST(TokenResponseParser, InvalidExpiresInFieldValue) {
  auto jwks = google::jwt_verify::Jwks::createFrom(
      valid_jwt_signing_key_, google::jwt_verify::Jwks::PEM);
  EXPECT_EQ(jwks->getStatus(), google::jwt_verify::Status::Ok);
  TokenResponseParserImpl parser(std::move(jwks));

  auto result = parser.Parse(client_id, nonce, invalid_expires_in_token_response);
  ASSERT_FALSE(result.has_value());
}

TEST(TokenResponseParser, Parse) {
  auto jwks = google::jwt_verify::Jwks::createFrom(
      valid_jwt_signing_key_, google::jwt_verify::Jwks::PEM);
  EXPECT_EQ(jwks->getStatus(), google::jwt_verify::Status::Ok);
  TokenResponseParserImpl parser(std::move(jwks));

  auto result = parser.Parse(client_id, nonce, valid_token_response_Bearer_without_access_token);
  ASSERT_TRUE(result.has_value());
  auto access_token1 = result->AccessToken();
  ASSERT_FALSE(access_token1.has_value());
  auto refresh_token1 = result->RefreshToken();
  ASSERT_FALSE(refresh_token1.has_value());
  auto expiry1 = result->Expiry();
  ASSERT_FALSE(expiry1.has_value());

  result = parser.Parse(client_id, nonce, valid_token_response_bearer_with_access_token);
  ASSERT_TRUE(result.has_value());
  auto access_token2 = result->AccessToken();
  ASSERT_TRUE(access_token2.has_value());
  ASSERT_EQ(*access_token2, "access_token_value");
  auto refresh_token2 = result->RefreshToken();
  ASSERT_FALSE(refresh_token2.has_value());
  auto expiry2 = result->Expiry();
  ASSERT_TRUE(expiry2.has_value());

  result = parser.Parse(client_id, nonce, valid_token_response_bearer_with_access_token_and_refresh_token);
  ASSERT_TRUE(result.has_value());
  auto access_token3 = result->AccessToken();
  ASSERT_TRUE(access_token3.has_value());
  ASSERT_EQ(*access_token3, "access_token_value");
  auto refresh_token3 = result->RefreshToken();
  ASSERT_TRUE(refresh_token3.has_value());
  ASSERT_EQ(*refresh_token3, "refresh_token_value");
  auto expiry3 = result->Expiry();
  ASSERT_TRUE(expiry3.has_value());
}
}  // namespace oidc
}  // namespace filters
}  // namespace authservice
