#include "gtest/gtest.h"
#include "src/filters/oidc/in_memory_session_store.h"

namespace authservice {
namespace filters {
namespace oidc {

class InMemorySessionStoreTest : public ::testing::Test {
protected:
  google::jwt_verify::Jwt id_token_jwt;

  void SetUp() override {
    auto jwt_status = id_token_jwt.parseFromString(
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMiwiYXVkIjpbImNsaWVudDEiXSwibm9uY2UiOiJyYW5kb20ifQ.NQi_VTRjZ8jv5cAp4inpuQ9STfVgCoWfONjLnZEMk8la8s99J9b6QmcKtO2tabTgvcseikVNlPuB6fZztY_fxhdrNE0dBNAl1lhz_AWBz6Yr-D82LLKk5NQ-IKDloF19Pic0Ub9pGCqNLOlmRXRVcfwwq5nISzfP6OdrjepRZ2Jd3rc2HvHYm-6GstH4xkKViABVwCDmwlAOi47bdHPByHkZOOnHSQEElr4tqO_uAQRpj36Yvt-95nPKhWaufZhcpYKk1H7ZRmylJQuG_dhlw4gN1i5iWBMk-Sj_2xyk05Bap1qkKSeHTxyqzhtDAH0LHYZdo_2hU-7YnL4JRhVVwg");
    ASSERT_EQ(jwt_status, google::jwt_verify::Status::Ok);
  }

  std::shared_ptr<TokenResponse> CreateTokenResponse();
};

std::shared_ptr<TokenResponse> InMemorySessionStoreTest::CreateTokenResponse() {
  auto token_response = std::make_shared<TokenResponse>(id_token_jwt);
  token_response->SetRefreshToken("fake_refresh_token");
  token_response->SetAccessToken("fake_access_token");
  token_response->SetAccessTokenExpiry(42);
  return token_response;
}


TEST_F(InMemorySessionStoreTest, SetAndGet) {
  InMemorySessionStore in_memory_session_store;
  auto session_id = std::string("fake_session_id");
  auto other_session_id = "other_session_id";
  auto token_response = CreateTokenResponse();

  auto result = in_memory_session_store.get(session_id);
  ASSERT_FALSE(result.has_value());

  in_memory_session_store.set(session_id, *token_response);
  // mutate the original to make sure that on the get() we're getting back a copy of the original made at the time of set()
  token_response->SetAccessToken("fake_access_token2");

  result = in_memory_session_store.get(session_id);
  ASSERT_TRUE(result.has_value());
  ASSERT_EQ(result.value().IDToken().jwt_, id_token_jwt.jwt_);
  ASSERT_EQ(result.value().RefreshToken(), "fake_refresh_token");
  ASSERT_EQ(result.value().AccessToken(), "fake_access_token");
  ASSERT_EQ(result.value().GetAccessTokenExpiry(), 42);

  token_response->SetAccessTokenExpiry(99);
  in_memory_session_store.set(session_id, *token_response); // overwrite

  result = in_memory_session_store.get(session_id);
  ASSERT_TRUE(result.has_value());
  ASSERT_EQ(result.value().IDToken().jwt_, id_token_jwt.jwt_);
  ASSERT_EQ(result.value().RefreshToken(), "fake_refresh_token");
  ASSERT_EQ(result.value().AccessToken(), "fake_access_token2");
  ASSERT_EQ(result.value().GetAccessTokenExpiry(), 99);

  result = in_memory_session_store.get(other_session_id);
  ASSERT_FALSE(result.has_value());
}

TEST_F(InMemorySessionStoreTest, Remove) {
  InMemorySessionStore in_memory_session_store;
  auto session_id = std::string("fake_session_id");
  auto token_response = CreateTokenResponse();

  in_memory_session_store.set(session_id, *token_response);
  ASSERT_TRUE(in_memory_session_store.get(session_id).has_value());
  in_memory_session_store.remove(session_id);
  ASSERT_FALSE(in_memory_session_store.get(session_id).has_value());

  in_memory_session_store.remove("other-session-id"); // ignore non-existent keys without error
}

}  // namespace oidc
}  // namespace filters
}  // namespace authservice
