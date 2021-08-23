#include "src/filters/oidc/token_response.h"

#include <google/protobuf/util/json_util.h>
#include <spdlog/spdlog.h>

#include "gtest/gtest.h"

namespace authservice {
namespace filters {
namespace oidc {
namespace {

// Shamelessly stolen from
// https://github.com/envoyproxy/envoy/blob/74436a6303825e0a6873222efff591ea1001cf87/test/extensions/filters/http/jwt_authn/test_common.h
// RS256 private key
//-----BEGIN PRIVATE KEY-----
//    MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC6n3u6qsX0xY49
//    o+TBJoF64A8s6v0UpxpYZ1UQbNDh/dmrlYpVmjDH1MIHGYiY0nWqZSLXekHyi3Az
//    +XmV9jUAUEzFVtAJRee0ui+ENqJK9injAYOMXNCJgD6lSryHoxRkGeGV5iuRTteU
//    IHA1XI3yo0ySksDsoVljP7jzoadXY0gknH/gEZrcd0rBAbGLa2O5CxC9qjlbjGZJ
//    VpoRaikHAzLZCaWFIVC49SlNrLBOpRxSr/pJ8AeFnggNr8XER3ZzbPyAUa1+y31x
//    jeVFh/5z9l1uhjeao31K7f6PfPmvZIdaWEH8s0CPJaUEay9sY+VOoPOJhDBk3hoa
//    ypUpBv1XAgMBAAECggEAc5HaJJIm/trsqD17pyV6X6arnyxyx7xn80Eii4ZnoNv8
//    VWbJARP4i3e1JIJqdgE3PutctUYP2u0A8h7XbcfHsMcJk9ecA3IX+HKohF71CCkD
//    bYH9fgnoVo5lvSTYNcMHGKpyacrdRiImHKQt+M21VgJMpCRfdurAmVbX6YA9Sj6w
//    SBFrZbWkBHiHg7w++xKr+VeTHW/8fXI5bvSPAm/XB6dDKAcSXYiJJJhIoaVR9cHn
//    1ePRDLpEwfDpBHeepd/S3qR37mIbHmo8SVytDY2xTUaIoaRfXRWGMYSyxl0y4RsZ
//    Vo6Tp9Tj2fyohvB/S+lE34zhxnsHToK2JZvPeoyHCQKBgQDyEcjaUZiPdx7K63CT
//    d57QNYC6DTjtKWnfO2q/vAVyAPwS30NcVuXj3/1yc0L+eExpctn8tcLfvDi1xZPY
//    dW2L3SZKgRJXL+JHTCEkP8To/qNLhBqitcKYwp0gtpoZbUjZdZwn18QJx7Mw/nFC
//    lJhSYRl+FjVolY3qBaS6eD7imwKBgQDFXNmeAV5FFF0FqGRsLYl0hhXTR6Hi/hKQ
//    OyRALBW9LUKbsazwWEFGRlqbEWd1OcOF5SSV4d3u7wLQRTDeNELXUFvivok12GR3
//    gNl9nDJ5KKYGFmqxM0pzfbT5m3Lsrr2FTIq8gM9GBpQAOmzQIkEu62yELtt2rRf0
//    1pTh+UbN9QKBgF88kAEUySjofLzpFElwbpML+bE5MoRcHsMs5Tq6BopryMDEBgR2
//    S8vzfAtjPaBQQ//Yp9q8yAauTsF1Ek2/JXI5d68oSMb0l9nlIcTZMedZB3XWa4RI
//    bl8bciZEsSv/ywGDPASQ5xfR8bX85SKEw8jlWto4cprK/CJuRfj3BgaxAoGAAmQf
//    ltR5aejXP6xMmyrqEWlWdlrV0UQ2wVyWEdj24nXb6rr6V2caU1mi22IYmMj8X3Dp
//    Qo+b+rsWk6Ni9i436RfmJRcd3nMitHfxKp5r1h/x8vzuifsPGdsaCDQj7k4nqafF
//    vobo+/Y0cNREYTkpBQKBLBDNQ+DQ+3xmDV7RxskCgYBCo6u2b/DZWFLoq3VpAm8u
//    1ZgL8qxY/bbyA02IKF84QPFczDM5wiLjDGbGnOcIYYMvTHf1LJU4FozzYkB0GicX
//    Y0tBQIHaaLWbPk1RZdPfR9kAp16iwk8H+V4UVjLfsTP7ocEfNCzZztmds83h8mTL
//    DSwE5aY76Cs8XLcF/GNJRQ==
//-----END PRIVATE KEY-----

// A good public key based on above private key
const char valid_jwt_signing_key_[] = R"(
{
  "keys": [
    {
      "kty": "RSA",
      "alg": "RS256",
      "use": "sig",
      "kid": "62a93512c9ee4c7f8067b5a216dade2763d32a47",
      "n": "up97uqrF9MWOPaPkwSaBeuAPLOr9FKcaWGdVEGzQ4f3Zq5WKVZowx9TCBxmImNJ1qmUi13pB8otwM_l5lfY1AFBMxVbQCUXntLovhDaiSvYp4wGDjFzQiYA-pUq8h6MUZBnhleYrkU7XlCBwNVyN8qNMkpLA7KFZYz-486GnV2NIJJx_4BGa3HdKwQGxi2tjuQsQvao5W4xmSVaaEWopBwMy2QmlhSFQuPUpTaywTqUcUq_6SfAHhZ4IDa_FxEd2c2z8gFGtfst9cY3lRYf-c_ZdboY3mqN9Su3-j3z5r2SHWlhB_LNAjyWlBGsvbGPlTqDziYQwZN4aGsqVKQb9Vw",
      "e": "AQAB"
    },
    {
      "kty": "RSA",
      "alg": "RS256",
      "use": "sig",
      "kid": "b3319a147514df7ee5e4bcdee51350cc890cc89e",
      "n": "up97uqrF9MWOPaPkwSaBeuAPLOr9FKcaWGdVEGzQ4f3Zq5WKVZowx9TCBxmImNJ1qmUi13pB8otwM_l5lfY1AFBMxVbQCUXntLovhDaiSvYp4wGDjFzQiYA-pUq8h6MUZBnhleYrkU7XlCBwNVyN8qNMkpLA7KFZYz-486GnV2NIJJx_4BGa3HdKwQGxi2tjuQsQvao5W4xmSVaaEWopBwMy2QmlhSFQuPUpTaywTqUcUq_6SfAHhZ4IDa_FxEd2c2z8gFGtfst9cY3lRYf-c_ZdboY3mqN9Su3-j3z5r2SHWlhB_LNAjyWlBGsvbGPlTqDziYQwZN4aGsqVKQb9Vw",
      "e": "AQAB"
    }
  ]
}
)";

const char *invalid_jwt_signing_key_ =
    "MIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSvvkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdV"
    "ha4s38XM/pa/yr47av7+z3VTmvDRyAHcaT92whREFpLv9cj5lTeJSibyr/Mrm/Yt"
    "jCZVWgaOYIhwrXwKLqPr/11inWsAkfIytvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwz"
    "GTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0e+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1"
    "FtGJiJvOwRsIfVChDpYStTcHTCMqtvWbV6L11BWkpAGXSW4Hv43qa+GSYOD2QU68"
    "Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9MwIDAQAB";

const char *client_id = "client1";
const char *nonce = "random";

// The id token in the following token responses was generated using
// https://jwt.io The Algorithm was set to RS256, the id token json was pasted
// into the payload field, and the above private and public keys were pasted
// into the corresponding fields. The encoded input should have been updated
// with those values and the result from that field was pasted into the id_token
// field of the following json string. id token payload: { "iss":
// "https://example.com", "sub": "test@example.com", "exp": 2001001001, "iat":
// 1901001001, "aud": ["client1"], "nonce": "random" }
const char *valid_token_response_Bearer_without_access_token =
    R"({"token_type":"Bearer","id_token":"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwic3ViIjoidGVzdEBleGFtcGxlLmNvbSIsImV4cCI6MjAwMTAwMTAwMSwiaWF0IjoxOTAxMDAxMDAxLCJhdWQiOlsiY2xpZW50MSJdLCJub25jZSI6InJhbmRvbSJ9.Qf0vE5QhnqlSpcxNn093d6ko2hOHveSs9ShusFYiUVxzS4J9xjmjTeyKkH7RfWWUL7_tFB6a7PC33BGdhUnCxYaHJbTmvLKDBy-AZyvzszBY35j8Kp1MPU-DPyR2LkwCoHKAD50pEro6iwB3Zd4SB1WE99_1SbJtAzpfdeQSCbcDOZgl2tQsDnB2OskwzjOdrEQyIrRl8vZOGbJyUHkz7pg6qUtnesjVSRWqWglQBXcS3rNpJi5Gt3L00IOqdozOlqS4ShCaLnbGZbCP9qey31d2SKLl6HNzULxa0LExvAqzcVM-f87WUWuVe30g6SBAZGlJA8wxyJgXF3Rrh1iKUg"})";

const char *valid_token_response_bearer_with_access_token =
    R"({"token_type":"bearer","access_token":"access_token_value","expires_in":3600,"id_token":"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwic3ViIjoidGVzdEBleGFtcGxlLmNvbSIsImV4cCI6MjAwMTAwMTAwMSwiaWF0IjoxOTAxMDAxMDAxLCJhdWQiOlsiY2xpZW50MSJdLCJub25jZSI6InJhbmRvbSJ9.Qf0vE5QhnqlSpcxNn093d6ko2hOHveSs9ShusFYiUVxzS4J9xjmjTeyKkH7RfWWUL7_tFB6a7PC33BGdhUnCxYaHJbTmvLKDBy-AZyvzszBY35j8Kp1MPU-DPyR2LkwCoHKAD50pEro6iwB3Zd4SB1WE99_1SbJtAzpfdeQSCbcDOZgl2tQsDnB2OskwzjOdrEQyIrRl8vZOGbJyUHkz7pg6qUtnesjVSRWqWglQBXcS3rNpJi5Gt3L00IOqdozOlqS4ShCaLnbGZbCP9qey31d2SKLl6HNzULxa0LExvAqzcVM-f87WUWuVe30g6SBAZGlJA8wxyJgXF3Rrh1iKUg"})";
const char *valid_token_response_bearer_with_access_token_and_refresh_token =
    R"({"token_type":"bearer","access_token":"access_token_value","refresh_token":"refresh_token_value","expires_in":3600,"id_token":"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwic3ViIjoidGVzdEBleGFtcGxlLmNvbSIsImV4cCI6MjAwMTAwMTAwMSwiaWF0IjoxOTAxMDAxMDAxLCJhdWQiOlsiY2xpZW50MSJdLCJub25jZSI6InJhbmRvbSJ9.Qf0vE5QhnqlSpcxNn093d6ko2hOHveSs9ShusFYiUVxzS4J9xjmjTeyKkH7RfWWUL7_tFB6a7PC33BGdhUnCxYaHJbTmvLKDBy-AZyvzszBY35j8Kp1MPU-DPyR2LkwCoHKAD50pEro6iwB3Zd4SB1WE99_1SbJtAzpfdeQSCbcDOZgl2tQsDnB2OskwzjOdrEQyIrRl8vZOGbJyUHkz7pg6qUtnesjVSRWqWglQBXcS3rNpJi5Gt3L00IOqdozOlqS4ShCaLnbGZbCP9qey31d2SKLl6HNzULxa0LExvAqzcVM-f87WUWuVe30g6SBAZGlJA8wxyJgXF3Rrh1iKUg"})";
const char *invalid_expires_in_token_response =
    R"({"token_type":"bearer","access_token":"expected","expires_in":-1,"id_token":"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwic3ViIjoidGVzdEBleGFtcGxlLmNvbSIsImV4cCI6MjAwMTAwMTAwMSwiaWF0IjoxOTAxMDAxMDAxLCJhdWQiOlsiY2xpZW50MSJdLCJub25jZSI6InJhbmRvbSJ9.Qf0vE5QhnqlSpcxNn093d6ko2hOHveSs9ShusFYiUVxzS4J9xjmjTeyKkH7RfWWUL7_tFB6a7PC33BGdhUnCxYaHJbTmvLKDBy-AZyvzszBY35j8Kp1MPU-DPyR2LkwCoHKAD50pEro6iwB3Zd4SB1WE99_1SbJtAzpfdeQSCbcDOZgl2tQsDnB2OskwzjOdrEQyIrRl8vZOGbJyUHkz7pg6qUtnesjVSRWqWglQBXcS3rNpJi5Gt3L00IOqdozOlqS4ShCaLnbGZbCP9qey31d2SKLl6HNzULxa0LExvAqzcVM-f87WUWuVe30g6SBAZGlJA8wxyJgXF3Rrh1iKUg"})";
const char *
    valid_refresh_token_response_bearer_with_access_token_and_refresh_token_no_id_token =
        R"({"token_type":"bearer","access_token":"refreshed_access_token_value","refresh_token":"refreshed_refresh_token_value","expires_in":3700})";

};  // namespace

class TokenResponseParserTest : public ::testing::Test {
 protected:
  std::shared_ptr<TokenResponseParserImpl> parser_;

  void SetUp() override {
    auto jwks = google::jwt_verify::Jwks::createFrom(
        valid_jwt_signing_key_, google::jwt_verify::Jwks::JWKS);
    EXPECT_EQ(jwks->getStatus(), google::jwt_verify::Status::Ok);
    parser_ = std::make_shared<TokenResponseParserImpl>(std::move(jwks));
  }

  std::shared_ptr<TokenResponse> ValidTokenResponse();
  std::shared_ptr<TokenResponse> ValidTokenResponseWithRefreshToken();
};

std::shared_ptr<TokenResponse> TokenResponseParserTest::ValidTokenResponse() {
  return parser_->Parse(client_id, nonce,
                        valid_token_response_Bearer_without_access_token);
}

std::shared_ptr<TokenResponse>
TokenResponseParserTest::ValidTokenResponseWithRefreshToken() {
  return parser_->Parse(
      client_id, nonce,
      valid_token_response_bearer_with_access_token_and_refresh_token);
}

TEST_F(TokenResponseParserTest, ParseInvalidJSON) {
  auto result = parser_->Parse(client_id, nonce, "invalid json");
  ASSERT_FALSE(result);
}

TEST_F(TokenResponseParserTest, ParseMissingTokenType) {
  auto result = parser_->Parse(client_id, nonce, R"({})");
  ASSERT_FALSE(result);
}

TEST_F(TokenResponseParserTest, ParseInvalidTokenType) {
  auto result =
      parser_->Parse(client_id, nonce, R"({"token_type":"NotBearer"})");
  ASSERT_FALSE(result);
}

TEST_F(TokenResponseParserTest, ParseMissingIdentityToken) {
  auto result = parser_->Parse(client_id, nonce, R"({"token_type":"Bearer"})");
  ASSERT_FALSE(result);
}

TEST_F(TokenResponseParserTest, ParseInvalidIdentityTokenType) {
  auto result = parser_->Parse(client_id, nonce,
                               R"({"token_type":"Bearer","id_token":1})");
  ASSERT_FALSE(result);
}

TEST_F(TokenResponseParserTest, ParseInvalidJwtEncoding) {
  auto result = parser_->Parse(client_id, nonce,
                               R"({"token_type":"Bearer","id_token":"wrong"})");
  ASSERT_FALSE(result);
}

TEST_F(TokenResponseParserTest, ParseInvalidJwtSignature) {
  auto jwks = google::jwt_verify::Jwks::createFrom(
      invalid_jwt_signing_key_, google::jwt_verify::Jwks::PEM);
  EXPECT_EQ(jwks->getStatus(), google::jwt_verify::Status::JwksPemBadBase64);
  TokenResponseParserImpl parser(std::move(jwks));
  auto result = parser.Parse(client_id, nonce,
                             valid_token_response_Bearer_without_access_token);
  ASSERT_FALSE(result);
}

TEST_F(TokenResponseParserTest, ParseMissingAudience) {
  auto result = parser_->Parse(
      "missing", nonce, valid_token_response_Bearer_without_access_token);
  ASSERT_FALSE(result);
}

TEST_F(TokenResponseParserTest, ParseInvalidNonce) {
  auto result = parser_->Parse(
      client_id, "invalid", valid_token_response_Bearer_without_access_token);
  ASSERT_FALSE(result);
}

TEST_F(TokenResponseParserTest, InvalidExpiresInFieldValue) {
  auto result =
      parser_->Parse(client_id, nonce, invalid_expires_in_token_response);
  ASSERT_FALSE(result);
}

TEST_F(TokenResponseParserTest,
       Parse_TokenTypeField_MustBeBearer_IgnoringCase) {
  const char *response_string = R"({"token_type":"BabyBearer",
                                    "id_token":"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwic3ViIjoidGVzdEBleGFtcGxlLmNvbSIsImV4cCI6MjAwMTAwMTAwMSwiaWF0IjoxOTAxMDAxMDAxLCJhdWQiOlsiY2xpZW50MSJdLCJub25jZSI6InJhbmRvbSJ9.Qf0vE5QhnqlSpcxNn093d6ko2hOHveSs9ShusFYiUVxzS4J9xjmjTeyKkH7RfWWUL7_tFB6a7PC33BGdhUnCxYaHJbTmvLKDBy-AZyvzszBY35j8Kp1MPU-DPyR2LkwCoHKAD50pEro6iwB3Zd4SB1WE99_1SbJtAzpfdeQSCbcDOZgl2tQsDnB2OskwzjOdrEQyIrRl8vZOGbJyUHkz7pg6qUtnesjVSRWqWglQBXcS3rNpJi5Gt3L00IOqdozOlqS4ShCaLnbGZbCP9qey31d2SKLl6HNzULxa0LExvAqzcVM-f87WUWuVe30g6SBAZGlJA8wxyJgXF3Rrh1iKUg"
                                    })";

  auto result = parser_->Parse(client_id, nonce, response_string);
  ASSERT_FALSE(result);
}

TEST_F(TokenResponseParserTest,
       ParseRefreshTokenResponse_TokenTypeField_MustBeBearer_IgnoringCase) {
  auto existing_token_response = ValidTokenResponse();

  const char *response_string = R"({"token_type":"baby-bearer",
                                    "access_token":"refreshed_access_token_value",
                                    "refresh_token":"refreshed_refresh_token_value"})";

  auto result = parser_->ParseRefreshTokenResponse(*existing_token_response,
                                                   response_string);
  ASSERT_FALSE(result);
}

TEST_F(TokenResponseParserTest, Parse_TokenTypeField_MustBePresent) {
  const char *response_string =
      R"({"id_token":"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwic3ViIjoidGVzdEBleGFtcGxlLmNvbSIsImV4cCI6MjAwMTAwMTAwMSwiaWF0IjoxOTAxMDAxMDAxLCJhdWQiOlsiY2xpZW50MSJdLCJub25jZSI6InJhbmRvbSJ9.Qf0vE5QhnqlSpcxNn093d6ko2hOHveSs9ShusFYiUVxzS4J9xjmjTeyKkH7RfWWUL7_tFB6a7PC33BGdhUnCxYaHJbTmvLKDBy-AZyvzszBY35j8Kp1MPU-DPyR2LkwCoHKAD50pEro6iwB3Zd4SB1WE99_1SbJtAzpfdeQSCbcDOZgl2tQsDnB2OskwzjOdrEQyIrRl8vZOGbJyUHkz7pg6qUtnesjVSRWqWglQBXcS3rNpJi5Gt3L00IOqdozOlqS4ShCaLnbGZbCP9qey31d2SKLl6HNzULxa0LExvAqzcVM-f87WUWuVe30g6SBAZGlJA8wxyJgXF3Rrh1iKUg"})";

  auto result = parser_->Parse(client_id, nonce, response_string);

  ASSERT_FALSE(result);
}

TEST_F(TokenResponseParserTest, Parse) {
  auto result = parser_->Parse(
      client_id, nonce, valid_token_response_Bearer_without_access_token);
  ASSERT_TRUE(result);
  auto access_token1 = result->AccessToken();
  ASSERT_FALSE(access_token1.has_value());
  auto refresh_token1 = result->RefreshToken();
  ASSERT_FALSE(refresh_token1.has_value());
  auto access_token_expiry1 = result->GetAccessTokenExpiry();
  ASSERT_FALSE(access_token_expiry1.has_value());
  auto id_token_expiry = result->GetIDTokenExpiry();
  ASSERT_EQ(2001001001, id_token_expiry);

  result = parser_->Parse(client_id, nonce,
                          valid_token_response_bearer_with_access_token);
  ASSERT_TRUE(result);
  auto access_token2 = result->AccessToken();
  ASSERT_TRUE(access_token2.has_value());
  ASSERT_EQ(*access_token2, "access_token_value");
  auto refresh_token2 = result->RefreshToken();
  ASSERT_FALSE(refresh_token2.has_value());
  auto access_token_expiry2 = result->GetAccessTokenExpiry();
  ASSERT_TRUE(access_token_expiry2.has_value());

  result = parser_->Parse(
      client_id, nonce,
      valid_token_response_bearer_with_access_token_and_refresh_token);
  ASSERT_TRUE(result);
  auto access_token3 = result->AccessToken();
  ASSERT_TRUE(access_token3.has_value());
  ASSERT_EQ(*access_token3, "access_token_value");
  auto refresh_token3 = result->RefreshToken();
  ASSERT_TRUE(refresh_token3.has_value());
  ASSERT_EQ(*refresh_token3, "refresh_token_value");
  auto access_token_expiry3 = result->GetAccessTokenExpiry();
  ASSERT_TRUE(access_token_expiry3.has_value());
}

TEST_F(TokenResponseParserTest,
       ParseRefreshTokenResponse_TokenTypeField_MustBePresent) {
  auto existing_token_response = ValidTokenResponse();

  const char *response_string =
      R"({"access_token":"refreshed_access_token_value",
                                    "refresh_token":"refreshed_refresh_token_value"})";

  auto result = parser_->ParseRefreshTokenResponse(*existing_token_response,
                                                   response_string);
  ASSERT_FALSE(result);
}

TEST_F(
    TokenResponseParserTest,
    ParseRefreshTokenResponse_ReturnsAnEmptyOptional_WhenTheExpiresInFieldIsInvalid_ByHavingAnInvalidValueOfZero) {
  auto existing_token_response = ValidTokenResponse();

  const char *response_string = R"({"token_type":"bearer",
                                    "access_token":"refreshed_access_token_value",
                                    "refresh_token":"refreshed_refresh_token_value",
                                    "expires_in": 0})";

  auto result = parser_->ParseRefreshTokenResponse(*existing_token_response,
                                                   response_string);
  ASSERT_FALSE(result);
}

TEST_F(
    TokenResponseParserTest,
    ParseRefreshTokenResponse_ConsidersResponseValid_WhenTheExpiresInFieldIsOmitted) {
https:  // tools.ietf.org/html/rfc6749#section-5.1 The expires_in field is
        // recommended and not required.
  auto existing_token_response = ValidTokenResponse();

  const char *response_string = R"({"token_type":"bearer",
                                    "access_token":"refreshed_access_token_value",
                                    "refresh_token":"refreshed_refresh_token_value"})";

  auto result = parser_->ParseRefreshTokenResponse(*existing_token_response,
                                                   response_string);
  ASSERT_TRUE(result);
}

TEST_F(TokenResponseParserTest, ParseRefreshTokenResponse) {
  auto existing_token_response = ValidTokenResponse();

  const char *response_string =
      valid_refresh_token_response_bearer_with_access_token_and_refresh_token_no_id_token;
  auto refreshed_token_response = parser_->ParseRefreshTokenResponse(
      *existing_token_response, response_string);
  ASSERT_TRUE(refreshed_token_response);

  ASSERT_EQ(existing_token_response->IDToken().jwt_,
            refreshed_token_response->IDToken().jwt_);
  auto refreshed_id_token_expiry = refreshed_token_response->GetIDTokenExpiry();
  ASSERT_EQ(existing_token_response->GetIDTokenExpiry(),
            refreshed_id_token_expiry);

  auto refreshed_access_token = refreshed_token_response->AccessToken();
  ASSERT_TRUE(refreshed_access_token.has_value());
  ASSERT_EQ("refreshed_access_token_value", refreshed_access_token.value());

  auto refreshed_refresh_token = refreshed_token_response->RefreshToken();
  ASSERT_TRUE(refreshed_refresh_token.has_value());
  ASSERT_EQ("refreshed_refresh_token_value", refreshed_refresh_token.value());

  auto refreshed_access_token_expiry =
      refreshed_token_response->GetAccessTokenExpiry();
  ASSERT_TRUE(refreshed_access_token_expiry.has_value());
}

TEST_F(
    TokenResponseParserTest,
    ParseRefreshTokenResponse_ReturnsRefreshedIdToken_WhenAnIdTokenIsIncludedInTheRefreshTokenResponse) {
  // id_token exp of May 29, 2062
  const char *test_refreshed_id_token_jwt_string_ =
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
      "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTA2MTI5MDIy"
      "LCJleHAiOjI5MTYxMzkwMjJ9.w8Q1JBUHvCj4LDxOM9SiiD9d7XaBzjyle5uoZlvdQFs";
  google::jwt_verify::Jwt test_refreshed_id_token_jwt_;
  auto existing_token_response = ValidTokenResponse();
  auto response_string = R"({"token_type":"bearer",
                                    "id_token":")" +
                         std::string(test_refreshed_id_token_jwt_string_) +
                         "\",\n"
                         R"("access_token":"refreshed_access_token_value",
                                    "refresh_token":"refreshed_refresh_token_value"})";

  auto refreshed_token_response = parser_->ParseRefreshTokenResponse(
      *existing_token_response, response_string);

  auto actual = refreshed_token_response->IDToken().jwt_;
  auto expected = test_refreshed_id_token_jwt_string_;
  ASSERT_EQ(expected, actual);
}

TEST_F(
    TokenResponseParserTest,
    ParseRefreshTokenResponse_ReturnsExistingRefreshToken_WhenARefreshTokenIsNotIncludedInTheRefreshTokenResponse) {
  auto existing_token_response = ValidTokenResponseWithRefreshToken();

  const char *response_string = valid_token_response_bearer_with_access_token;
  auto refreshed_token_response = parser_->ParseRefreshTokenResponse(
      *existing_token_response, response_string);

  ASSERT_TRUE(refreshed_token_response);

  auto actual_refresh_token = refreshed_token_response->RefreshToken();
  ASSERT_TRUE(actual_refresh_token.has_value());
  ASSERT_EQ("refresh_token_value", actual_refresh_token.value());
}

}  // namespace oidc
}  // namespace filters
}  // namespace authservice
