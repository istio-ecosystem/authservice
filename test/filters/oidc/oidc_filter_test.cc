#include "src/filters/oidc/oidc_filter.h"
#include <regex>
#include "absl/strings/str_join.h"
#include "google/rpc/code.pb.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "src/common/http/headers.h"
#include "test/common/http/mocks.h"
#include "test/common/session/mocks.h"
#include "test/filters/oidc/mocks.h"
#include "src/filters/oidc/in_memory_session_store.h"

namespace envoy {
namespace api {
namespace v2 {
namespace core {

// Used for printing header information on test failures
void PrintTo(const ::envoy::api::v2::core::HeaderValueOption &header, ::std::ostream *os) {
  std::string json;
  google::protobuf::util::MessageToJsonString(header, &json);

  *os << json;
}

}
}
}
}

namespace authservice {
namespace filters {
namespace oidc {

using ::testing::_;
using ::testing::Eq;
using ::testing::StrEq;
using ::testing::AnyOf;
using ::testing::AllOf;
using ::testing::Return;
using ::testing::ByMove;
using ::testing::Property;
using ::testing::StartsWith;
using ::testing::MatchesRegex;
using ::testing::UnorderedElementsAre;

namespace {

::testing::internal::UnorderedElementsAreArrayMatcher<::testing::Matcher<envoy::api::v2::core::HeaderValueOption>>
ContainsHeaders(std::vector<std::pair<std::string, ::testing::Matcher<std::string>>> headers) {
  std::vector<::testing::Matcher<envoy::api::v2::core::HeaderValueOption>> matchers;

  for(const auto& header : headers) {
    matchers.push_back(
      Property(&envoy::api::v2::core::HeaderValueOption::header, AllOf(
        Property(&envoy::api::v2::core::HeaderValue::key, StrEq(header.first)),
        Property(&envoy::api::v2::core::HeaderValue::value, header.second)
      )));
  }

  return ::testing::UnorderedElementsAreArray(matchers);
}

}

class OidcFilterTest : public ::testing::Test {
 protected:
  authservice::config::oidc::OIDCConfig config_;
  std::string callback_host_;
  std::shared_ptr<TokenResponseParserMock> parser_mock_;
  std::shared_ptr<common::session::TokenEncryptorMock> cryptor_mock_;
  std::shared_ptr<common::session::SessionIdGeneratorMock> session_id_generator_mock_;
  std::shared_ptr<SessionStore> session_store_;
  std::shared_ptr<TokenResponse> test_token_response_;

  // id_token exp of Feb 2, 2062
  const char* test_id_token_jwt_string_ = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTA2MTI5MDIyLCJleHAiOjI5MDYxMzkwMjJ9.jV2_EH7JB30wgg248x2AlCkZnIUH417I_7FPw3nr5BQ";
  google::jwt_verify::Jwt test_id_token_jwt_;

  void SetUp() override {
    config_.mutable_authorization()->set_scheme("https");
    config_.mutable_authorization()->set_hostname("acme-idp.tld");
    config_.mutable_authorization()->set_port(443);
    config_.mutable_authorization()->set_path("/authorization");
    config_.mutable_token()->set_scheme("https");
    config_.mutable_token()->set_hostname("acme-idp.tld");
    config_.mutable_token()->set_port(443);
    config_.mutable_token()->set_path("/token");
    config_.mutable_jwks_uri()->set_scheme("https");
    config_.mutable_jwks_uri()->set_hostname("acme-idp.tld");
    config_.mutable_jwks_uri()->set_port(443);
    config_.mutable_jwks_uri()->set_path("/token");
    config_.set_jwks("some-jwks");
    config_.mutable_callback()->set_scheme("https");
    config_.mutable_callback()->set_hostname("me.tld");
    config_.mutable_callback()->set_port(443);
    config_.mutable_callback()->set_path("/callback");
    config_.set_client_id("example-app");
    config_.set_client_secret("ZXhhbXBsZS1hcHAtc2VjcmV0");
    config_.set_cryptor_secret("xxx123");
    config_.set_landing_page("/landing-page");
    config_.set_cookie_name_prefix("cookie-prefix");
    config_.mutable_id_token()->set_header("authorization");
    config_.mutable_id_token()->set_preamble("Bearer");
    config_.set_timeout(300);

    std::stringstream callback_host;
    callback_host << config_.callback().hostname() << ':' << std::dec << config_.callback().port();
    callback_host_ = callback_host.str();

    parser_mock_ = std::make_shared<TokenResponseParserMock>();
    cryptor_mock_ = std::make_shared<common::session::TokenEncryptorMock>();
    session_id_generator_mock_ = std::make_shared<common::session::SessionIdGeneratorMock>();
    session_store_ = std::static_pointer_cast<SessionStore>(std::make_shared<InMemorySessionStore>());

    auto jwt_status = test_id_token_jwt_.parseFromString(test_id_token_jwt_string_);
    ASSERT_EQ(jwt_status, google::jwt_verify::Status::Ok);

    test_token_response_ = std::make_shared<TokenResponse>(test_id_token_jwt_);
    test_token_response_->SetAccessToken("expected_access_token");
    test_token_response_->SetAccessTokenExpiry(10000000000); // not expired, Sat 20 Nov 2286
  }

  void RetrieveToken(config::oidc::OIDCConfig &oidcConfig, std::string callback_host_on_request);

  void EnableAccessTokens(config::oidc::OIDCConfig &oidcConfig);

  void SetExpiredAccessTokenResponseInSessionStore();
};

TEST_F(OidcFilterTest, Constructor) {
  OidcFilter filter(common::http::ptr_t(), config_, parser_mock_, cryptor_mock_, session_id_generator_mock_, session_store_);
}

TEST_F(OidcFilterTest, Name) {
  OidcFilter filter(common::http::ptr_t(), config_, parser_mock_, cryptor_mock_, session_id_generator_mock_, session_store_);
  ASSERT_EQ(filter.Name().compare("oidc"), 0);
}

TEST_F(OidcFilterTest, GetStateCookieName) {
  config_.clear_cookie_name_prefix();
  OidcFilter filter1(common::http::ptr_t(), config_, parser_mock_, cryptor_mock_, session_id_generator_mock_, session_store_);
  ASSERT_EQ(filter1.GetStateCookieName(), "__Host-authservice-state-cookie");

  config_.set_cookie_name_prefix("my-prefix");
  OidcFilter filter2(common::http::ptr_t(), config_, parser_mock_, cryptor_mock_, session_id_generator_mock_, session_store_);
  ASSERT_EQ(filter2.GetStateCookieName(),
            "__Host-my-prefix-authservice-state-cookie");
}

TEST_F(OidcFilterTest, GetSessionIdCookieName) {
  config_.clear_cookie_name_prefix();
  OidcFilter filter1(common::http::ptr_t(), config_, parser_mock_, cryptor_mock_, session_id_generator_mock_, session_store_);
  ASSERT_EQ(filter1.GetSessionIdCookieName(),
            "__Host-authservice-session-id-cookie");

  config_.set_cookie_name_prefix("my-prefix");
  OidcFilter filter2(common::http::ptr_t(), config_, parser_mock_, cryptor_mock_, session_id_generator_mock_, session_store_);
  ASSERT_EQ(filter2.GetSessionIdCookieName(),
            "__Host-my-prefix-authservice-session-id-cookie");
}

TEST_F(OidcFilterTest, NoHttpHeader) {
  OidcFilter filter(common::http::ptr_t(), config_, parser_mock_, cryptor_mock_, session_id_generator_mock_, session_store_);

  ::envoy::service::auth::v2::CheckRequest request;
  ::envoy::service::auth::v2::CheckResponse response;
  auto status = filter.Process(&request, &response);
  ASSERT_EQ(status, google::rpc::Code::INVALID_ARGUMENT);
}

/* TODO: Reinstate
TEST_F(OidcFilterTest, NoHttpSchema) {
  OidcFilter filter(common::http::ptr_t(), config);
  ::envoy::service::auth::v2::CheckRequest request;
  ::envoy::service::auth::v2::CheckResponse response;
  auto status = filter.Process(&request, &response);
  ASSERT_EQ(status.error_code(), ::grpc::StatusCode::INVALID_ARGUMENT);
}
 */

TEST_F(OidcFilterTest, NoAuthorization) {
  EXPECT_CALL(*cryptor_mock_, Encrypt(_)).WillOnce(Return("encrypted"));
  EXPECT_CALL(*session_id_generator_mock_, Generate()).WillOnce(Return("session123"));
  OidcFilter filter(common::http::ptr_t(), config_, parser_mock_, cryptor_mock_, session_id_generator_mock_, session_store_);
  ::envoy::service::auth::v2::CheckRequest request;
  ::envoy::service::auth::v2::CheckResponse response;
  auto httpRequest = request.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->set_scheme("https");

  auto status = filter.Process(&request, &response);
  ASSERT_EQ(status, google::rpc::Code::UNAUTHENTICATED);
  ASSERT_EQ(response.denied_response().status().code(),
            ::envoy::type::StatusCode::Found);

  ASSERT_THAT(
    response.denied_response().headers(),
    ContainsHeaders({
      {
        common::http::headers::Location,
        MatchesRegex(
          "^https://acme-idp\\.tld/"
          "authorization\\?client_id=example-app&nonce=[A-Za-z0-9_-]{43}&"
          "redirect_uri=https%3A%2F%2Fme\\.tld%2Fcallback&response_type=code&"
          "scope=openid&state=[A-Za-z0-9_-]{43}$")
      },
      {common::http::headers::CacheControl, StrEq(common::http::headers::CacheControlDirectives::NoCache)},
      {common::http::headers::Pragma, StrEq(common::http::headers::PragmaDirectives::NoCache)},
      {
       common::http::headers::SetCookie,
        StrEq("__Host-cookie-prefix-authservice-state-cookie=encrypted; "
              "HttpOnly; Max-Age=300; Path=/; "
              "SameSite=Lax; Secure")
      },
      {
       common::http::headers::SetCookie,
        StrEq("__Host-cookie-prefix-authservice-session-id-cookie=session123; "
              "HttpOnly; Path=/; "
              "SameSite=Lax; Secure")
      }
    })
  );
}

TEST_F(OidcFilterTest, NoSessionCookie) {
  EXPECT_CALL(*cryptor_mock_, Encrypt(_)).WillOnce(Return("encrypted"));
  EXPECT_CALL(*session_id_generator_mock_, Generate()).WillOnce(Return("session123"));
  OidcFilter filter(common::http::ptr_t(), config_, parser_mock_, cryptor_mock_, session_id_generator_mock_, session_store_);
  ::envoy::service::auth::v2::CheckRequest request;
  ::envoy::service::auth::v2::CheckResponse response;
  auto httpRequest =
      request.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->set_scheme("https");
  httpRequest->mutable_headers()->insert(
      {common::http::headers::Cookie, "invalid"});

  auto status = filter.Process(&request, &response);
  // We expect to be redirected to authenticate
  ASSERT_EQ(status, google::rpc::Code::UNAUTHENTICATED);

  ASSERT_THAT(
    response.denied_response().headers(),
    ContainsHeaders({
      {common::http::headers::Location, StartsWith(common::http::http::ToUrl(config_.authorization()))},
      {common::http::headers::CacheControl, StrEq(common::http::headers::CacheControlDirectives::NoCache)},
      {common::http::headers::Pragma, StrEq(common::http::headers::PragmaDirectives::NoCache)},
      {
        common::http::headers::SetCookie,
        StrEq("__Host-cookie-prefix-authservice-state-cookie=encrypted; "
              "HttpOnly; Max-Age=300; Path=/; "
              "SameSite=Lax; Secure")
      },
      {
        common::http::headers::SetCookie,
        StrEq("__Host-cookie-prefix-authservice-session-id-cookie=session123; "
              "HttpOnly; Path=/; "
              "SameSite=Lax; Secure")
      }
    })
  );
}

TEST_F(OidcFilterTest, AlreadyHasUnexpiredIdTokenShouldSendRequestToAppWithAuthorizationHeaderContainingIdToken) {
  OidcFilter filter(common::http::ptr_t(), config_, parser_mock_, cryptor_mock_, session_id_generator_mock_, session_store_);
  session_store_->set("session123", *test_token_response_);
  ::envoy::service::auth::v2::CheckRequest request;
  ::envoy::service::auth::v2::CheckResponse response;
  auto httpRequest =
      request.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->set_scheme("https");
  httpRequest->mutable_headers()->insert(
      {common::http::headers::Cookie,
       "__Host-cookie-prefix-authservice-session-id-cookie=session123"});

  auto status = filter.Process(&request, &response);
  ASSERT_EQ(status, google::rpc::Code::OK);

  ASSERT_THAT(
    response.ok_response().headers(),
    ContainsHeaders({
      {common::http::headers::Authorization, StrEq("Bearer " + std::string(test_id_token_jwt_string_))},
    })
  );
}

TEST_F(OidcFilterTest, MissingAccessTokenShouldRedirectToIdpToAuthenticateAgainWhenTheAccessTokenHeaderHasBeenConfigured) {
  EnableAccessTokens(config_);

  TokenResponse token_response(test_id_token_jwt_);
  token_response.SetAccessTokenExpiry(2906139022); //Feb 2, 2062
  token_response.SetAccessToken(nullptr);
  session_store_->set("session123", token_response);

  EXPECT_CALL(*cryptor_mock_, Encrypt(_)).WillOnce(Return("encrypted"));
  OidcFilter filter(common::http::ptr_t(), config_, parser_mock_, cryptor_mock_, session_id_generator_mock_, session_store_);
  ::envoy::service::auth::v2::CheckRequest request;
  ::envoy::service::auth::v2::CheckResponse response;
  auto httpRequest =
      request.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->set_scheme("https");
  httpRequest->mutable_headers()->insert(
      {common::http::headers::Cookie,
       "__Host-cookie-prefix-authservice-session-id-cookie=session123"});

  auto status = filter.Process(&request, &response);
  // We expect to be redirected to authenticate
  ASSERT_EQ(status, google::rpc::Code::UNAUTHENTICATED);

  ASSERT_THAT(
    response.denied_response().headers(),
    ContainsHeaders({
      {common::http::headers::Location, StartsWith(common::http::http::ToUrl(config_.authorization()))},
      {common::http::headers::CacheControl, StrEq(common::http::headers::CacheControlDirectives::NoCache)},
      {common::http::headers::Pragma, StrEq(common::http::headers::PragmaDirectives::NoCache)},
      {
        common::http::headers::SetCookie,
        StrEq("__Host-cookie-prefix-authservice-state-cookie=encrypted; "
              "HttpOnly; Max-Age=300; Path=/; "
              "SameSite=Lax; Secure")
      }
    })
  );
}

TEST_F(OidcFilterTest, ExpiredAccessTokenShouldRedirectToIdpToAuthenticateAgainWhenTheAccessTokenHeaderHasBeenConfigured_AndThereIsNoRefreshToken) {
  EnableAccessTokens(config_);

  TokenResponse token_response(test_id_token_jwt_); // id token, not expired
  token_response.SetAccessTokenExpiry(1); // already expired
  token_response.SetAccessToken("fake_access_token");
  session_store_->set("session123", token_response);

  EXPECT_CALL(*cryptor_mock_, Encrypt(_)).WillOnce(Return("encrypted"));
  OidcFilter filter(common::http::ptr_t(), config_, parser_mock_, cryptor_mock_, session_id_generator_mock_, session_store_);
  ::envoy::service::auth::v2::CheckRequest request;
  ::envoy::service::auth::v2::CheckResponse response;
  auto httpRequest =
      request.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->set_scheme("https");
  httpRequest->mutable_headers()->insert(
      {common::http::headers::Cookie,
       "__Host-cookie-prefix-authservice-session-id-cookie=session123"});

  auto status = filter.Process(&request, &response);
  // We expect to be redirected to authenticate
  ASSERT_EQ(status, google::rpc::Code::UNAUTHENTICATED);

  ASSERT_THAT(
      response.denied_response().headers(),
      ContainsHeaders({
                          {common::http::headers::Location, StartsWith(common::http::http::ToUrl(config_.authorization()))},
                          {common::http::headers::CacheControl, StrEq(common::http::headers::CacheControlDirectives::NoCache)},
                          {common::http::headers::Pragma, StrEq(common::http::headers::PragmaDirectives::NoCache)},
                          {
                           common::http::headers::SetCookie,
                              StrEq("__Host-cookie-prefix-authservice-state-cookie=encrypted; "
                                    "HttpOnly; Max-Age=300; Path=/; "
                                    "SameSite=Lax; Secure")
                          }
                      })
  );
}

// id token is unexpired, access token is expired, server returns only access token from refresh endpoint
TEST_F(OidcFilterTest, ExpiredAccessTokenShouldRefreshTheTokenResponseWhenTheAccessTokenHeaderHasBeenConfiguredAndThereIsRefreshToken) {
  EnableAccessTokens(config_);

  SetExpiredAccessTokenResponseInSessionStore();

  auto mocked_http = new common::http::http_mock();
  auto *pMessage = new beast::http::response<beast::http::string_body>();
  auto raw_http_token_response_from_idp = common::http::response_t(pMessage);
  raw_http_token_response_from_idp->result(beast::http::status::ok);
  EXPECT_CALL(*mocked_http, Post(_, _, _, _, _)).WillOnce(Return(ByMove(std::move(raw_http_token_response_from_idp))));

  auto jwt_status = test_id_token_jwt_.parseFromString(test_id_token_jwt_string_);
  ASSERT_EQ(jwt_status, google::jwt_verify::Status::Ok);

  TokenResponse test_refresh_token_response(test_id_token_jwt_);
  test_refresh_token_response.SetAccessToken("expected_refreshed_access_token");
  test_refresh_token_response.SetAccessTokenExpiry(11000000000); // July 30, 2318
  test_refresh_token_response.SetRefreshToken("expected_refreshed_refresh_token");

  EXPECT_CALL(*parser_mock_, ParseRefreshTokenResponse(_, _, _))
      .WillOnce(::testing::Return(test_refresh_token_response));

  OidcFilter filter(common::http::ptr_t(mocked_http), config_, parser_mock_, cryptor_mock_, session_id_generator_mock_, session_store_);

  ::envoy::service::auth::v2::CheckRequest request;
  ::envoy::service::auth::v2::CheckResponse response;

  auto httpRequest = request.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->set_scheme("https");
  httpRequest->mutable_headers()->insert(
      {common::http::headers::Cookie, "__Host-cookie-prefix-authservice-session-id-cookie=session123"});

  auto status = filter.Process(&request, &response);
  ASSERT_EQ(status, google::rpc::Code::OK);
  ASSERT_THAT(
      response.ok_response().headers(),
      ContainsHeaders({
                          {common::http::headers::Authorization, StrEq("Bearer " + std::string(test_id_token_jwt_string_))},
                          {"access_token", StrEq("expected_refreshed_access_token")},
                      })
  );
  
  auto stored_token_response = session_store_->get("session123");
  ASSERT_TRUE(stored_token_response.has_value());
  ASSERT_EQ(stored_token_response.value().IDToken().jwt_, test_id_token_jwt_string_);
  ASSERT_EQ(stored_token_response.value().AccessToken(), "expected_refreshed_access_token");
  ASSERT_EQ(stored_token_response.value().GetAccessTokenExpiry(), 11000000000);
  ASSERT_EQ(stored_token_response.value().RefreshToken(), "expected_refreshed_refresh_token");
}

TEST_F(OidcFilterTest, Process_RedirectsUsersToAuthenticate_WhenThereIsNoStoredTokenResponseAssociatedWithTheUsersSession) {
  EnableAccessTokens(config_);

  auto mocked_http = new common::http::http_mock();
  EXPECT_CALL(*cryptor_mock_, Encrypt(_)).WillOnce(Return("encrypted"));

  OidcFilter filter(common::http::ptr_t(mocked_http), config_, parser_mock_, cryptor_mock_, session_id_generator_mock_, session_store_);

  ::envoy::service::auth::v2::CheckRequest request;
  ::envoy::service::auth::v2::CheckResponse response;

  auto httpRequest = request.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->set_scheme("https");
  httpRequest->mutable_headers()->insert(
      {common::http::headers::Cookie, "__Host-cookie-prefix-authservice-session-id-cookie=session123"});

  auto status = filter.Process(&request, &response);

  ASSERT_EQ(status, google::rpc::Code::UNAUTHENTICATED);
  ASSERT_THAT(
      response.denied_response().headers(),
      ContainsHeaders({
                          {common::http::headers::Location, StartsWith(common::http::http::ToUrl(config_.authorization()))},
                          {common::http::headers::CacheControl, StrEq(common::http::headers::CacheControlDirectives::NoCache)},
                          {common::http::headers::Pragma, StrEq(common::http::headers::PragmaDirectives::NoCache)},
                          {
                           common::http::headers::SetCookie,
                              StrEq("__Host-cookie-prefix-authservice-state-cookie=encrypted; "
                                    "HttpOnly; Max-Age=300; Path=/; "
                                    "SameSite=Lax; Secure")
                          }
                      })
  );

  auto stored_token_response = session_store_->get("session123");
  ASSERT_FALSE(stored_token_response.has_value());
}

TEST_F(OidcFilterTest, Process_RedirectsUsersToAuthenticate_WhenFailingToParseTheRefreshedTokenResponse) {
  EnableAccessTokens(config_);

  SetExpiredAccessTokenResponseInSessionStore();

  auto mocked_http = new common::http::http_mock();
  auto *pMessage = new beast::http::response<beast::http::string_body>();
  auto raw_http_token_response_from_idp = common::http::response_t(pMessage);
  raw_http_token_response_from_idp->result(beast::http::status::ok);
  EXPECT_CALL(*mocked_http, Post(_, _, _, _, _)).WillOnce(Return(ByMove(std::move(raw_http_token_response_from_idp))));

  EXPECT_CALL(*parser_mock_, ParseRefreshTokenResponse(_, _, _))
      .WillOnce(::testing::Return(absl::nullopt));
  EXPECT_CALL(*cryptor_mock_, Encrypt(_)).WillOnce(Return("encrypted"));

  OidcFilter filter(common::http::ptr_t(mocked_http), config_, parser_mock_, cryptor_mock_, session_id_generator_mock_, session_store_);

  ::envoy::service::auth::v2::CheckRequest request;
  ::envoy::service::auth::v2::CheckResponse response;

  auto httpRequest = request.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->set_scheme("https");
  httpRequest->mutable_headers()->insert(
      {common::http::headers::Cookie, "__Host-cookie-prefix-authservice-session-id-cookie=session123"});

  auto status = filter.Process(&request, &response);

  ASSERT_EQ(status, google::rpc::Code::UNAUTHENTICATED);
  ASSERT_THAT(
      response.denied_response().headers(),
      ContainsHeaders({
                          {common::http::headers::Location, StartsWith(common::http::http::ToUrl(config_.authorization()))},
                          {common::http::headers::CacheControl, StrEq(common::http::headers::CacheControlDirectives::NoCache)},
                          {common::http::headers::Pragma, StrEq(common::http::headers::PragmaDirectives::NoCache)},
                          {
                           common::http::headers::SetCookie,
                              StrEq("__Host-cookie-prefix-authservice-state-cookie=encrypted; "
                                    "HttpOnly; Max-Age=300; Path=/; "
                                    "SameSite=Lax; Secure")
                          }
                      })
  );

  auto stored_token_response = session_store_->get("session123");
  ASSERT_FALSE(stored_token_response.has_value());
}

TEST_F(OidcFilterTest, Process_RedirectsUsersToAuthenticate_WhenFailingToEstablishHttpConnectionToIDP) {
  EnableAccessTokens(config_);

  SetExpiredAccessTokenResponseInSessionStore();

  auto mocked_http = new common::http::http_mock();
  EXPECT_CALL(*mocked_http, Post(_, _, _, _, _)).WillOnce(Return(ByMove(nullptr)));

  EXPECT_CALL(*cryptor_mock_, Encrypt(_)).WillOnce(Return("encrypted"));

  OidcFilter filter(common::http::ptr_t(mocked_http), config_, parser_mock_, cryptor_mock_, session_id_generator_mock_, session_store_);

  ::envoy::service::auth::v2::CheckRequest request;
  ::envoy::service::auth::v2::CheckResponse response;

  auto httpRequest = request.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->set_scheme("https");
  httpRequest->mutable_headers()->insert(
      {common::http::headers::Cookie, "__Host-cookie-prefix-authservice-session-id-cookie=session123"});

  auto status = filter.Process(&request, &response);
  ASSERT_EQ(status, google::rpc::Code::UNAUTHENTICATED);
  ASSERT_THAT(
      response.denied_response().headers(),
      ContainsHeaders({
                          {common::http::headers::Location, StartsWith(common::http::http::ToUrl(config_.authorization()))},
                          {common::http::headers::CacheControl, StrEq(common::http::headers::CacheControlDirectives::NoCache)},
                          {common::http::headers::Pragma, StrEq(common::http::headers::PragmaDirectives::NoCache)},
                          {
                           common::http::headers::SetCookie,
                              StrEq("__Host-cookie-prefix-authservice-state-cookie=encrypted; "
                                    "HttpOnly; Max-Age=300; Path=/; "
                                    "SameSite=Lax; Secure")
                          }
                      })
  );

  auto stored_token_response = session_store_->get("session123");
  ASSERT_FALSE(stored_token_response.has_value());
}

TEST_F(OidcFilterTest, Process_RedirectsUsersToAuthenticate_WhenIDPReturnsUnsuccessfulHttpResponseCode) {
  EnableAccessTokens(config_);

  SetExpiredAccessTokenResponseInSessionStore();

  auto mocked_http = new common::http::http_mock();
  auto *pMessage = new beast::http::response<beast::http::string_body>();
  auto raw_http_token_response_from_idp = common::http::response_t(pMessage);
  raw_http_token_response_from_idp->result(beast::http::status::bad_request);
  EXPECT_CALL(*mocked_http, Post(_, _, _, _, _)).WillOnce(Return(ByMove(std::move(raw_http_token_response_from_idp))));

  EXPECT_CALL(*cryptor_mock_, Encrypt(_)).WillOnce(Return("encrypted")); // The redirect to IDP requires a state/nonce cookie.
  EXPECT_CALL(*parser_mock_, ParseRefreshTokenResponse(_, _, _)).Times(0); // we want the code to return before attempting to parse the bad response

  auto jwt_status = test_id_token_jwt_.parseFromString(test_id_token_jwt_string_);
  ASSERT_EQ(jwt_status, google::jwt_verify::Status::Ok);


  OidcFilter filter(common::http::ptr_t(mocked_http), config_, parser_mock_, cryptor_mock_, session_id_generator_mock_, session_store_);


  ::envoy::service::auth::v2::CheckRequest request;
  ::envoy::service::auth::v2::CheckResponse response;

  auto httpRequest = request.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->set_scheme("https");
  httpRequest->mutable_headers()->insert(
      {common::http::headers::Cookie, "__Host-cookie-prefix-authservice-session-id-cookie=session123"});
  auto status = filter.Process(&request, &response);

  ASSERT_EQ(status, google::rpc::Code::UNAUTHENTICATED);
  ASSERT_THAT(
      response.denied_response().headers(),
      ContainsHeaders({
                          {common::http::headers::Location, StartsWith(common::http::http::ToUrl(config_.authorization()))},
                          {common::http::headers::CacheControl, StrEq(common::http::headers::CacheControlDirectives::NoCache)},
                          {common::http::headers::Pragma, StrEq(common::http::headers::PragmaDirectives::NoCache)},
                          {
                           common::http::headers::SetCookie,
                              StrEq("__Host-cookie-prefix-authservice-state-cookie=encrypted; "
                                    "HttpOnly; Max-Age=300; Path=/; "
                                    "SameSite=Lax; Secure")
                          }
                      })
  );

  auto stored_token_response = session_store_->get("session123");
  ASSERT_FALSE(stored_token_response.has_value());
}

TEST_F(OidcFilterTest, ShouldPermitTheRequestToContinue_WhenTokenResponseWithAccessTokenButNoExpiresInTime_GivenTheAccessTokenHeaderHasBeenConfigured) {
  EnableAccessTokens(config_);

  TokenResponse token_response(test_id_token_jwt_); // id token, not expired
  token_response.SetAccessTokenExpiry(0);
  token_response.SetAccessToken("fake_access_token");
  session_store_->set("session123", token_response);

  OidcFilter filter(common::http::ptr_t(), config_, parser_mock_, cryptor_mock_, session_id_generator_mock_, session_store_);
  ::envoy::service::auth::v2::CheckRequest request;
  ::envoy::service::auth::v2::CheckResponse response;
  auto httpRequest = request.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->set_scheme("https");
  httpRequest->mutable_headers()->insert(
      {common::http::headers::Cookie, "__Host-cookie-prefix-authservice-session-id-cookie=session123"});

  auto status = filter.Process(&request, &response);

  ASSERT_EQ(status, google::rpc::Code::OK);
  ASSERT_THAT(
      response.ok_response().headers(),
      ContainsHeaders({
                          {common::http::headers::Authorization, StrEq("Bearer " + std::string(test_id_token_jwt_string_))},
                          {"access_token", StrEq("fake_access_token")},
                      })
  );
}

TEST_F(OidcFilterTest, ExpiredIdTokenShouldRedirectToIdpToAuthenticateAgainWhenTheAccessTokenHeaderHasBeenConfigured) {
  EnableAccessTokens(config_);

  //ID Token with exp of Sep 22, 2017
  const char* expired_id_token_jwt_string = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTA2MTI5MDIyLCJleHAiOjE1MDYxMzkwMjJ9.nYUg1lKTjuuT5aD2HuoPzOUtWCgenscZXisuCEzho1s";
  google::jwt_verify::Jwt expired_id_token_jwt;

  auto jwt_status = expired_id_token_jwt.parseFromString(expired_id_token_jwt_string);
  ASSERT_EQ(jwt_status, google::jwt_verify::Status::Ok);

  TokenResponse token_response(expired_id_token_jwt);
  token_response.SetAccessToken("expected_access_token");
  token_response.SetAccessTokenExpiry(10000000000); // access token not expired, Sat 20 Nov 2286

  session_store_->set("session123", token_response);

  EXPECT_CALL(*cryptor_mock_, Encrypt(_)).WillOnce(Return("encrypted"));
  OidcFilter filter(common::http::ptr_t(), config_, parser_mock_, cryptor_mock_, session_id_generator_mock_, session_store_);
  ::envoy::service::auth::v2::CheckRequest request;
  ::envoy::service::auth::v2::CheckResponse response;
  auto httpRequest =
      request.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->set_scheme("https");
  httpRequest->mutable_headers()->insert(
      {common::http::headers::Cookie,
       "__Host-cookie-prefix-authservice-session-id-cookie=session123"});

  auto status = filter.Process(&request, &response);
  // We expect to be redirected to authenticate because the id_token is expired
  ASSERT_EQ(status, google::rpc::Code::UNAUTHENTICATED);

  ASSERT_THAT(
      response.denied_response().headers(),
      ContainsHeaders({
                          {common::http::headers::Location, StartsWith(common::http::http::ToUrl(config_.authorization()))},
                          {common::http::headers::CacheControl, StrEq(common::http::headers::CacheControlDirectives::NoCache)},
                          {common::http::headers::Pragma, StrEq(common::http::headers::PragmaDirectives::NoCache)},
                          {
                           common::http::headers::SetCookie,
                              StrEq("__Host-cookie-prefix-authservice-state-cookie=encrypted; "
                                    "HttpOnly; Max-Age=300; Path=/; "
                                    "SameSite=Lax; Secure")
                          }
                      })
  );
}

TEST_F(OidcFilterTest, AlreadyHasUnexpiredTokensShouldSendRequestToAppWithHeadersContainingBothTokensWhenTheAccessTokenHeaderHasBeenConfigured) {
  EnableAccessTokens(config_);
  session_store_->set("session123", *test_token_response_);
  OidcFilter filter(common::http::ptr_t(), config_, parser_mock_, cryptor_mock_, session_id_generator_mock_, session_store_);
  ::envoy::service::auth::v2::CheckRequest request;
  ::envoy::service::auth::v2::CheckResponse response;
  auto httpRequest = request.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->set_scheme("https");
  httpRequest->mutable_headers()->insert(
      {common::http::headers::Cookie,
       "__Host-cookie-prefix-authservice-session-id-cookie=session123"});

  auto status = filter.Process(&request, &response);
  ASSERT_EQ(status, google::rpc::Code::OK);

  ASSERT_THAT(
    response.ok_response().headers(),
    ContainsHeaders({
      {common::http::headers::Authorization, StrEq("Bearer " + std::string(test_id_token_jwt_string_))},
      {"access_token", StrEq("expected_access_token")},
    })
  );
}

TEST_F(OidcFilterTest, LogoutWithCookies) {
  session_store_->set("session123", *test_token_response_);
  config_.mutable_logout()->set_path("/logout");
  config_.mutable_logout()->set_redirect_to_uri("https://redirect-uri");
  OidcFilter filter(common::http::ptr_t(), config_, parser_mock_, cryptor_mock_, session_id_generator_mock_, session_store_);
  ::envoy::service::auth::v2::CheckRequest request;
  ::envoy::service::auth::v2::CheckResponse response;
  auto httpRequest =
      request.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->set_scheme("https");
  httpRequest->mutable_headers()->insert(
      {common::http::headers::Cookie,
       "__Host-cookie-prefix-authservice-state-cookie=state; "
       "__Host-cookie-prefix-authservice-session-id-cookie=session123"
      });
  httpRequest->set_path("/logout");

  auto status = filter.Process(&request, &response);

  ASSERT_FALSE(session_store_->get("session123").has_value());

  ASSERT_EQ(status, google::rpc::Code::UNAUTHENTICATED);
  ASSERT_EQ(response.denied_response().status().code(),
            ::envoy::type::StatusCode::Found);

  ASSERT_THAT(
      response.denied_response().headers(),
      ContainsHeaders({
        {common::http::headers::Location, StrEq("https://redirect-uri")},
        {common::http::headers::CacheControl, StrEq(common::http::headers::CacheControlDirectives::NoCache)},
        {common::http::headers::Pragma, StrEq(common::http::headers::PragmaDirectives::NoCache)},
        {common::http::headers::SetCookie, StrEq(
            "__Host-cookie-prefix-authservice-state-cookie=deleted; HttpOnly; Max-Age=0; Path=/; SameSite=Lax; Secure")},
        {common::http::headers::SetCookie, StrEq(
            "__Host-cookie-prefix-authservice-session-id-cookie=deleted; HttpOnly; Max-Age=0; Path=/; SameSite=Lax; Secure")}
    })
  );
}

TEST_F(OidcFilterTest, LogoutWithNoCookies) {
  config_.mutable_logout()->set_path("/logout");
  config_.mutable_logout()->set_redirect_to_uri("https://redirect-uri");
  OidcFilter filter(common::http::ptr_t(), config_, parser_mock_, cryptor_mock_, session_id_generator_mock_, session_store_);
  ::envoy::service::auth::v2::CheckRequest request;
  ::envoy::service::auth::v2::CheckResponse response;
  auto httpRequest =
      request.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->set_scheme("https");
  httpRequest->set_path("/logout");

  auto status = filter.Process(&request, &response);

  ASSERT_EQ(status, google::rpc::Code::UNAUTHENTICATED);
  ASSERT_EQ(response.denied_response().status().code(),
            ::envoy::type::StatusCode::Found);

  ASSERT_THAT(
      response.denied_response().headers(),
      ContainsHeaders({
                          {common::http::headers::Location, StrEq("https://redirect-uri")},
                          {common::http::headers::CacheControl, StrEq(common::http::headers::CacheControlDirectives::NoCache)},
                          {common::http::headers::Pragma, StrEq(common::http::headers::PragmaDirectives::NoCache)},
                          {common::http::headers::SetCookie, StrEq(
                              "__Host-cookie-prefix-authservice-state-cookie=deleted; HttpOnly; Max-Age=0; Path=/; SameSite=Lax; Secure")},
                          {common::http::headers::SetCookie, StrEq(
                              "__Host-cookie-prefix-authservice-session-id-cookie=deleted; HttpOnly; Max-Age=0; Path=/; SameSite=Lax; Secure")}
                      })
  );
}

void OidcFilterTest::SetExpiredAccessTokenResponseInSessionStore() {
  TokenResponse expired_token_response(test_id_token_jwt_); // id token, not expired
  expired_token_response.SetAccessTokenExpiry(1); // acccess token already expired
  expired_token_response.SetAccessToken("fake_access_token");
  expired_token_response.SetRefreshToken("fake_refresh_token");
  session_store_->set("session123", expired_token_response);
}

void OidcFilterTest::EnableAccessTokens(config::oidc::OIDCConfig &oidcConfig) {
  oidcConfig.mutable_access_token()->set_header("access_token");
}

void OidcFilterTest::RetrieveToken(config::oidc::OIDCConfig &oidcConfig, std::string callback_host_on_request) {
  EXPECT_CALL(*parser_mock_, Parse(oidcConfig.client_id(), ::testing::_, ::testing::_))
      .WillOnce(::testing::Return(*test_token_response_));
  auto mocked_http = new common::http::http_mock();
  auto raw_http = common::http::response_t(
      new beast::http::response<beast::http::string_body>());
  raw_http->result(beast::http::status::ok);
  EXPECT_CALL(*mocked_http, Post(_, _, _, _, _))
      .WillOnce(Return(ByMove(std::move(raw_http))));
  OidcFilter filter(common::http::ptr_t(mocked_http), oidcConfig, parser_mock_, cryptor_mock_, session_id_generator_mock_, session_store_);
  ::envoy::service::auth::v2::CheckRequest request;
  ::envoy::service::auth::v2::CheckResponse response;
  auto httpRequest = request.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->set_scheme("");  // Seems like it should be "https", but in practice is empty
  httpRequest->set_host(callback_host_on_request);
  httpRequest->mutable_headers()->insert(
      {common::http::headers::Cookie,
       "__Host-cookie-prefix-authservice-state-cookie=valid; "
       "__Host-cookie-prefix-authservice-session-id-cookie=session123"});
  EXPECT_CALL(*cryptor_mock_, Decrypt("valid"))
      .WillOnce(Return(
          absl::optional<std::string>("expectedstate;expectednonce")));
  std::vector<absl::string_view> parts = {oidcConfig.callback().path().c_str(),
                                          "code=value&state=expectedstate"};
  httpRequest->set_path(absl::StrJoin(parts, "?"));

  auto code = filter.Process(&request, &response);
  ASSERT_EQ(code, google::rpc::Code::UNAUTHENTICATED);

  auto stored_token_response = session_store_->get("session123");
  ASSERT_TRUE(stored_token_response.has_value());
  ASSERT_EQ(stored_token_response.value().IDToken().jwt_, test_id_token_jwt_string_);
  ASSERT_EQ(stored_token_response.value().AccessToken(), "expected_access_token");
  ASSERT_EQ(stored_token_response.value().GetAccessTokenExpiry(), 10000000000);

  ASSERT_THAT(
    response.denied_response().headers(),
    ContainsHeaders({
      {common::http::headers::Location, StartsWith(oidcConfig.landing_page())},
      {common::http::headers::CacheControl, StrEq(common::http::headers::CacheControlDirectives::NoCache)},
      {common::http::headers::Pragma, StrEq(common::http::headers::PragmaDirectives::NoCache)},
      {
        common::http::headers::SetCookie,
        StrEq("__Host-cookie-prefix-authservice-state-cookie=deleted; "
              "HttpOnly; Max-Age=0; Path=/; SameSite=Lax; "
              "Secure")
      }
    })
  );
}

TEST_F(OidcFilterTest, RetrieveTokenWithoutAccessTokenHeaderNameConfigured) {
  RetrieveToken(config_, callback_host_);
}

TEST_F(OidcFilterTest, RetrieveTokenWithoutAccessTokenHeaderNameConfiguredWhenThePortIsNotInTheRequestHostnameAndTheConfiguredCallbackIsTheDefaultHttpsPort) {
  config_.mutable_callback()->set_scheme("https");
  config_.mutable_callback()->set_port(443);
  RetrieveToken(config_, config_.callback().hostname());
}

TEST_F(OidcFilterTest, RetrieveTokenWithoutAccessTokenHeaderNameConfiguredWhenThePortIsNotInTheRequestHostnameAndTheConfiguredCallbackIsTheDefaultHttpPort) {
  config_.mutable_callback()->set_scheme("http");
  config_.mutable_callback()->set_port(80);
  RetrieveToken(config_, config_.callback().hostname());
}

TEST_F(OidcFilterTest, RetrieveTokenWithAccessTokenHeaderNameConfigured) {
  EnableAccessTokens(config_);
  google::jwt_verify::Jwt jwt = {};
  auto token_response = absl::make_optional<TokenResponse>(jwt);
  token_response->SetAccessToken("expected_access_token");
  EXPECT_CALL(*parser_mock_, Parse(config_.client_id(), ::testing::_, ::testing::_))
      .WillOnce(::testing::Return(token_response));
  auto mocked_http = new common::http::http_mock();
  auto raw_http = common::http::response_t(
      new beast::http::response<beast::http::string_body>());
  raw_http->result(beast::http::status::ok);
  EXPECT_CALL(*mocked_http, Post(_, _, _, _, _))
      .WillOnce(Return(ByMove(std::move(raw_http))));
  OidcFilter filter(common::http::ptr_t(mocked_http), config_, parser_mock_, cryptor_mock_, session_id_generator_mock_, session_store_);
  ::envoy::service::auth::v2::CheckRequest request;
  ::envoy::service::auth::v2::CheckResponse response;
  auto httpRequest = request.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->set_scheme("");  // Seems like it should be "https", but in practice is empty
  httpRequest->set_host(callback_host_);
  httpRequest->mutable_headers()->insert(
      {common::http::headers::Cookie,
       "__Host-cookie-prefix-authservice-state-cookie=valid; "
       "__Host-cookie-prefix-authservice-session-id-cookie=session123"});
  EXPECT_CALL(*cryptor_mock_, Decrypt("valid"))
      .WillOnce(Return(
          absl::optional<std::string>("expectedstate;expectednonce")));
  std::vector<absl::string_view> parts = {config_.callback().path().c_str(),
                                          "code=value&state=expectedstate"};
  httpRequest->set_path(absl::StrJoin(parts, "?"));
  auto code = filter.Process(&request, &response);
  ASSERT_EQ(code, google::rpc::Code::UNAUTHENTICATED);

  ASSERT_THAT(
    response.denied_response().headers(),
    ContainsHeaders({
      {common::http::headers::Location, StartsWith(config_.landing_page())},
      {common::http::headers::CacheControl, StrEq(common::http::headers::CacheControlDirectives::NoCache)},
      {common::http::headers::Pragma, StrEq(common::http::headers::PragmaDirectives::NoCache)},
      {
        common::http::headers::SetCookie,
        StrEq("__Host-cookie-prefix-authservice-state-cookie=deleted; "
              "HttpOnly; Max-Age=0; Path=/; SameSite=Lax; "
              "Secure")
      }
    })
  );
}

TEST_F(OidcFilterTest, RetrieveTokenWhenTokenResponseIsMissingAccessToken) {
  EnableAccessTokens(config_);
  google::jwt_verify::Jwt jwt = {};
  auto token_response = absl::make_optional<TokenResponse>(jwt);
  EXPECT_CALL(*parser_mock_, Parse(config_.client_id(), ::testing::_, ::testing::_))
      .WillOnce(::testing::Return(token_response));
  auto mocked_http = new common::http::http_mock();
  auto raw_http = common::http::response_t(
      new beast::http::response<beast::http::string_body>());
  raw_http->result(beast::http::status::ok);
  EXPECT_CALL(*mocked_http, Post(_, _, _, _, _))
      .WillOnce(Return(ByMove(std::move(raw_http))));
  ASSERT_FALSE(session_store_->get("session123").has_value());
  OidcFilter filter(common::http::ptr_t(mocked_http), config_, parser_mock_, cryptor_mock_, session_id_generator_mock_, session_store_);
  ::envoy::service::auth::v2::CheckRequest request;
  ::envoy::service::auth::v2::CheckResponse response;
  auto httpRequest =
      request.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->set_scheme(
      "");  // Seems like it should be "https", but in practice is empty
  httpRequest->set_host(callback_host_);
  httpRequest->mutable_headers()->insert(
      {common::http::headers::Cookie,
       "__Host-cookie-prefix-authservice-state-cookie=valid; "
       "__Host-cookie-prefix-authservice-session-id-cookie=session123"});
  EXPECT_CALL(*cryptor_mock_, Decrypt("valid"))
      .WillOnce(Return(
          absl::optional<std::string>("expectedstate;expectednonce")));
  EXPECT_CALL(*cryptor_mock_, Encrypt(_)).Times(0);
  std::vector<absl::string_view> parts = {config_.callback().path().c_str(),
                                          "code=value&state=expectedstate"};
  httpRequest->set_path(absl::StrJoin(parts, "?"));
  auto code = filter.Process(&request, &response);
  ASSERT_EQ(code, google::rpc::Code::INVALID_ARGUMENT);

  ASSERT_FALSE(session_store_->get("session123").has_value());
  ASSERT_THAT(
    response.denied_response().headers(),
    ContainsHeaders({
      {common::http::headers::CacheControl, StrEq(common::http::headers::CacheControlDirectives::NoCache)},
      {common::http::headers::Pragma, StrEq(common::http::headers::PragmaDirectives::NoCache)},
      {
        common::http::headers::SetCookie,
        StrEq("__Host-cookie-prefix-authservice-state-cookie=deleted; "
              "HttpOnly; Max-Age=0; Path=/; "
              "SameSite=Lax; Secure"),
      },
    })
  );
}

TEST_F(OidcFilterTest, RetrieveTokenMissingStateCookie) {
  auto mocked_http = new common::http::http_mock();
  OidcFilter filter(common::http::ptr_t(mocked_http), config_, parser_mock_, cryptor_mock_, session_id_generator_mock_, session_store_);
  ::envoy::service::auth::v2::CheckRequest request;
  ::envoy::service::auth::v2::CheckResponse response;
  auto httpRequest =
      request.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->set_scheme("https");
  httpRequest->set_host(callback_host_);
  httpRequest->mutable_headers()->insert(
      {common::http::headers::Cookie,
       "__Host-cookie-prefix-authservice-session-id-cookie=session123"});
  std::vector<absl::string_view> parts = {config_.callback().path().c_str(),
                                          "code=value&state=expectedstate"};
  httpRequest->set_path(absl::StrJoin(parts, "?"));
  auto code = filter.Process(&request, &response);
  ASSERT_EQ(code, google::rpc::Code::INVALID_ARGUMENT);

  ASSERT_THAT(
    response.denied_response().headers(),
    ContainsHeaders({
      {common::http::headers::CacheControl, StrEq(common::http::headers::CacheControlDirectives::NoCache)},
      {common::http::headers::Pragma, StrEq(common::http::headers::PragmaDirectives::NoCache)},
      {
        common::http::headers::SetCookie,
        StrEq("__Host-cookie-prefix-authservice-state-cookie=deleted; "
              "HttpOnly; Max-Age=0; Path=/; "
              "SameSite=Lax; Secure"),
      },
    })
  );
}

TEST_F(OidcFilterTest, RetrieveTokenInvalidStateCookie) {
  auto mocked_http = new common::http::http_mock();
  OidcFilter filter(common::http::ptr_t(mocked_http), config_, parser_mock_, cryptor_mock_, session_id_generator_mock_, session_store_);
  ::envoy::service::auth::v2::CheckRequest request;
  ::envoy::service::auth::v2::CheckResponse response;
  auto httpRequest =
      request.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->set_scheme("https");
  httpRequest->set_host(callback_host_);
  httpRequest->mutable_headers()->insert(
      {common::http::headers::Cookie,
       "__Host-cookie-prefix-authservice-state-cookie=invalid; "
       "__Host-cookie-prefix-authservice-session-id-cookie=session123"});
  EXPECT_CALL(*cryptor_mock_, Decrypt("invalid"))
      .WillOnce(Return(absl::nullopt));
  std::vector<absl::string_view> parts = {config_.callback().path().c_str(),
                                          "code=value&state=expectedstate"};
  httpRequest->set_path(absl::StrJoin(parts, "?"));
  auto code = filter.Process(&request, &response);
  ASSERT_EQ(code, google::rpc::Code::INVALID_ARGUMENT);

  ASSERT_THAT(
    response.denied_response().headers(),
    ContainsHeaders({
      {common::http::headers::CacheControl, StrEq(common::http::headers::CacheControlDirectives::NoCache)},
      {common::http::headers::Pragma, StrEq(common::http::headers::PragmaDirectives::NoCache)},
      {
        common::http::headers::SetCookie,
        StrEq("__Host-cookie-prefix-authservice-state-cookie=deleted; "
              "HttpOnly; Max-Age=0; Path=/; "
              "SameSite=Lax; Secure"),
      },
    })
  );
}

TEST_F(OidcFilterTest, RetrieveTokenInvalidStateCookieFormat) {
  auto mocked_http = new common::http::http_mock();
  OidcFilter filter(common::http::ptr_t(mocked_http), config_, parser_mock_, cryptor_mock_, session_id_generator_mock_, session_store_);
  ::envoy::service::auth::v2::CheckRequest request;
  ::envoy::service::auth::v2::CheckResponse response;
  auto httpRequest =
      request.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->set_scheme("https");
  httpRequest->set_host(callback_host_);
  httpRequest->mutable_headers()->insert(
      {common::http::headers::Cookie,
       "__Host-cookie-prefix-authservice-state-cookie=valid; "
       "__Host-cookie-prefix-authservice-session-id-cookie=session123"});
  EXPECT_CALL(*cryptor_mock_, Decrypt("valid"))
      .WillOnce(
          Return(absl::optional<std::string>("invalidformat")));
  std::vector<absl::string_view> parts = {config_.callback().path().c_str(),
                                          "code=value&state=expectedstate"};
  httpRequest->set_path(absl::StrJoin(parts, "?"));
  auto code = filter.Process(&request, &response);
  ASSERT_EQ(code, google::rpc::Code::INVALID_ARGUMENT);

  ASSERT_THAT(
    response.denied_response().headers(),
    ContainsHeaders({
      {common::http::headers::CacheControl, StrEq(common::http::headers::CacheControlDirectives::NoCache)},
      {common::http::headers::Pragma, StrEq(common::http::headers::PragmaDirectives::NoCache)},
      {
        common::http::headers::SetCookie,
        StrEq("__Host-cookie-prefix-authservice-state-cookie=deleted; "
              "HttpOnly; Max-Age=0; Path=/; "
              "SameSite=Lax; Secure"),
      },
    })
  );
}

TEST_F(OidcFilterTest, RetrieveTokenMissingCode) {
  OidcFilter filter(common::http::ptr_t(), config_, parser_mock_, cryptor_mock_, session_id_generator_mock_, session_store_);
  ::envoy::service::auth::v2::CheckRequest request;
  ::envoy::service::auth::v2::CheckResponse response;
  auto httpRequest =
      request.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->set_scheme("https");
  httpRequest->set_host(callback_host_);
  httpRequest->set_path(config_.callback().path());
  std::vector<absl::string_view> parts = {config_.callback().path().c_str(),
                                          "key=value&state=expectedstate"};
  httpRequest->set_path(absl::StrJoin(parts, "?"));
  httpRequest->mutable_headers()->insert(
      {common::http::headers::Cookie,
       "__Host-cookie-prefix-authservice-session-id-cookie=session123"});

  auto code = filter.Process(&request, &response);
  ASSERT_EQ(code, google::rpc::Code::INVALID_ARGUMENT);

  ASSERT_THAT(
    response.denied_response().headers(),
    ContainsHeaders({
      {common::http::headers::CacheControl, StrEq(common::http::headers::CacheControlDirectives::NoCache)},
      {common::http::headers::Pragma, StrEq(common::http::headers::PragmaDirectives::NoCache)},
      {
        common::http::headers::SetCookie,
        StrEq("__Host-cookie-prefix-authservice-state-cookie=deleted; "
              "HttpOnly; Max-Age=0; Path=/; "
              "SameSite=Lax; Secure"),
      },
    })
  );
}

TEST_F(OidcFilterTest, RetrieveTokenMissingState) {
  OidcFilter filter(common::http::ptr_t(), config_, parser_mock_, cryptor_mock_, session_id_generator_mock_, session_store_);
  ::envoy::service::auth::v2::CheckRequest request;
  ::envoy::service::auth::v2::CheckResponse response;
  auto httpRequest =
      request.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->set_scheme("https");
  httpRequest->set_host(callback_host_);
  httpRequest->set_path(config_.callback().path());
  std::vector<absl::string_view> parts = {config_.callback().path().c_str(),
                                          "code=value"};
  httpRequest->set_path(absl::StrJoin(parts, "?"));
  httpRequest->mutable_headers()->insert(
      {common::http::headers::Cookie,
       "__Host-cookie-prefix-authservice-session-id-cookie=session123"});

  auto code = filter.Process(&request, &response);
  ASSERT_EQ(code, google::rpc::Code::INVALID_ARGUMENT);

  ASSERT_THAT(
    response.denied_response().headers(),
    ContainsHeaders({
      {common::http::headers::CacheControl, StrEq(common::http::headers::CacheControlDirectives::NoCache)},
      {common::http::headers::Pragma, StrEq(common::http::headers::PragmaDirectives::NoCache)},
      {
        common::http::headers::SetCookie,
        StrEq("__Host-cookie-prefix-authservice-state-cookie=deleted; "
              "HttpOnly; Max-Age=0; Path=/; "
              "SameSite=Lax; Secure"),
      },
    })
  );
}

TEST_F(OidcFilterTest, RetrieveTokenUnexpectedState) {
  OidcFilter filter(common::http::ptr_t(), config_, parser_mock_, cryptor_mock_, session_id_generator_mock_, session_store_);
  ::envoy::service::auth::v2::CheckRequest request;
  ::envoy::service::auth::v2::CheckResponse response;
  auto httpRequest =
      request.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->set_scheme("https");
  httpRequest->set_host(callback_host_);
  httpRequest->set_path(config_.callback().path());
  std::vector<absl::string_view> parts = {config_.callback().path().c_str(),
                                          "code=value&state=unexpectedstate"};
  httpRequest->set_path(absl::StrJoin(parts, "?"));
  httpRequest->mutable_headers()->insert(
      {common::http::headers::Cookie,
       "__Host-cookie-prefix-authservice-session-id-cookie=session123"});

  auto code = filter.Process(&request, &response);
  ASSERT_EQ(code, google::rpc::Code::INVALID_ARGUMENT);

  ASSERT_THAT(
    response.denied_response().headers(),
    ContainsHeaders({
      {common::http::headers::CacheControl, StrEq(common::http::headers::CacheControlDirectives::NoCache)},
      {common::http::headers::Pragma, StrEq(common::http::headers::PragmaDirectives::NoCache)},
      {
        common::http::headers::SetCookie,
        StrEq("__Host-cookie-prefix-authservice-state-cookie=deleted; "
              "HttpOnly; Max-Age=0; Path=/; "
              "SameSite=Lax; Secure"),
      },
    })
  );
}

TEST_F(OidcFilterTest, RetrieveTokenBrokenPipe) {
  auto *http_mock = new common::http::http_mock();
  auto raw_http = common::http::response_t();
  EXPECT_CALL(*http_mock, Post(_, _, _, _, _))
      .WillOnce(Return(ByMove(std::move(raw_http))));
  OidcFilter filter(common::http::ptr_t(http_mock), config_, parser_mock_, cryptor_mock_, session_id_generator_mock_, session_store_);
  ::envoy::service::auth::v2::CheckRequest request;
  ::envoy::service::auth::v2::CheckResponse response;
  auto httpRequest =
      request.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->set_scheme("https");
  httpRequest->set_host(callback_host_);
  httpRequest->set_path(config_.callback().path());
  httpRequest->mutable_headers()->insert(
      {common::http::headers::Cookie,
       "__Host-cookie-prefix-authservice-state-cookie=valid; "
       "__Host-cookie-prefix-authservice-session-id-cookie=session123"});
  EXPECT_CALL(*cryptor_mock_, Decrypt("valid"))
      .WillOnce(Return(
          absl::optional<std::string>("expectedstate;expectednonce")));
  std::vector<absl::string_view> parts = {config_.callback().path().c_str(),
                                          "code=value&state=expectedstate"};
  httpRequest->set_path(absl::StrJoin(parts, "?"));
  auto code = filter.Process(&request, &response);
  ASSERT_EQ(code, google::rpc::Code::INTERNAL);

  ASSERT_THAT(
    response.denied_response().headers(),
    ContainsHeaders({
      {common::http::headers::CacheControl, StrEq(common::http::headers::CacheControlDirectives::NoCache)},
      {common::http::headers::Pragma, StrEq(common::http::headers::PragmaDirectives::NoCache)},
      {
        common::http::headers::SetCookie,
        StrEq("__Host-cookie-prefix-authservice-state-cookie=deleted; "
              "HttpOnly; Max-Age=0; Path=/; "
              "SameSite=Lax; Secure"),
      },
    })
  );
}

TEST_F(OidcFilterTest, RetrieveTokenInvalidResponse) {
  EXPECT_CALL(*parser_mock_, Parse(config_.client_id(), ::testing::_, ::testing::_))
      .WillOnce(::testing::Return(absl::nullopt));
  auto *http_mock = new common::http::http_mock();
  auto raw_http = common::http::response_t(
      (new beast::http::response<beast::http::string_body>()));
  EXPECT_CALL(*http_mock, Post(_, _, _, _, _))
      .WillOnce(Return(ByMove(std::move(raw_http))));
  OidcFilter filter(common::http::ptr_t(http_mock), config_, parser_mock_, cryptor_mock_, session_id_generator_mock_, session_store_);
  ::envoy::service::auth::v2::CheckRequest request;
  ::envoy::service::auth::v2::CheckResponse response;
  auto httpRequest =
      request.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->set_scheme("https");
  httpRequest->set_host(callback_host_);
  httpRequest->set_path(config_.callback().path());
  httpRequest->mutable_headers()->insert(
      {common::http::headers::Cookie,
       "__Host-cookie-prefix-authservice-state-cookie=valid; "
       "__Host-cookie-prefix-authservice-session-id-cookie=session123"});
  EXPECT_CALL(*cryptor_mock_, Decrypt("valid"))
      .WillOnce(Return(
          absl::optional<std::string>("expectedstate;expectednonce")));
  std::vector<absl::string_view> parts = {config_.callback().path().c_str(),
                                          "code=value&state=expectedstate"};
  httpRequest->set_path(absl::StrJoin(parts, "?"));
  auto code = filter.Process(&request, &response);
  ASSERT_EQ(code, google::rpc::Code::INVALID_ARGUMENT);

  ASSERT_THAT(
    response.denied_response().headers(),
    ContainsHeaders({
      {common::http::headers::CacheControl, StrEq(common::http::headers::CacheControlDirectives::NoCache)},
      {common::http::headers::Pragma, StrEq(common::http::headers::PragmaDirectives::NoCache)},
      {
        common::http::headers::SetCookie,
        StrEq("__Host-cookie-prefix-authservice-state-cookie=deleted; "
              "HttpOnly; Max-Age=0; Path=/; "
              "SameSite=Lax; Secure"),
      },
    })
  );
}

}  // namespace oidc
}  // namespace filters
}  // namespace authservice
