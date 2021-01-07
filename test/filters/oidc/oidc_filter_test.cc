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
using ::testing::Throw;
using ::testing::StrEq;
using ::testing::AnyOf;
using ::testing::AllOf;
using ::testing::Return;
using ::testing::ByMove;
using ::testing::Property;
using ::testing::StartsWith;
using ::testing::MatchesRegex;
using ::testing::UnorderedElementsAre;

using namespace common::http::headers;

namespace {

::testing::internal::UnorderedElementsAreArrayMatcher<::testing::Matcher<envoy::api::v2::core::HeaderValueOption>>
ContainsHeaders(std::vector<std::pair<std::string, ::testing::Matcher<std::string>>> headers) {
  std::vector<::testing::Matcher<envoy::api::v2::core::HeaderValueOption>> matchers;

  for (const auto &header : headers) {
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

  config::oidc::OIDCConfig config_;
  std::string callback_host_;
  std::string callback_path_;
  std::shared_ptr<TokenResponseParserMock> parser_mock_;
  std::shared_ptr<common::session::SessionStringGeneratorMock> session_string_generator_mock_;
  std::shared_ptr<SessionStore> session_store_;
  std::shared_ptr<SessionStoreMock> session_store_mock_;
  std::shared_ptr<TokenResponse> test_token_response_;
  ::envoy::service::auth::v2::CheckRequest request_;
  ::envoy::service::auth::v2::CheckResponse response_;

  // id_token exp of Feb 2, 2062
  const char *test_id_token_jwt_string_ =
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTA2MTI5MDIyLCJleHAiOjI5MDYxMzkwMjJ9.jV2_EH7JB30wgg248x2AlCkZnIUH417I_7FPw3nr5BQ";
  const std::string requested_url_ = "https://example.com/summary?foo=bar";
  google::jwt_verify::Jwt test_id_token_jwt_;
  const std::string expected_session_cookie_name = "__Host-cookie-prefix-authservice-session-id-cookie";
  const std::string token_uri = "https://acme-idp.tld/token";

  void SetUp() override {
    config_.set_authorization_uri("https://acme-idp.tld/authorization");
    config_.set_token_uri(token_uri);
    config_.set_jwks("some-jwks");
    config_.set_client_id("example-app");
    config_.set_client_secret("ZXhhbXBsZS1hcHAtc2VjcmV0");
    config_.set_cookie_name_prefix("cookie-prefix");
    config_.mutable_id_token()->set_header("authorization");
    config_.mutable_id_token()->set_preamble("Bearer");
    config_.set_trusted_certificate_authority("some-ca");
    config_.set_proxy_uri("http://some-proxy-uri.com");

    config_.set_callback_uri("https://me.tld/callback");
    callback_host_ = "me.tld:443";
    callback_path_ = "/callback";

    parser_mock_ = std::make_shared<TokenResponseParserMock>();
    session_string_generator_mock_ = std::make_shared<common::session::SessionStringGeneratorMock>();
    session_store_ = std::static_pointer_cast<SessionStore>(std::make_shared<InMemorySessionStore>(
        std::make_shared<common::utilities::TimeService>(), 1000, 1000)
    );
    session_store_mock_ = std::make_shared<SessionStoreMock>();

    auto jwt_status = test_id_token_jwt_.parseFromString(test_id_token_jwt_string_);
    ASSERT_EQ(jwt_status, google::jwt_verify::Status::Ok);

    test_token_response_ = std::make_shared<TokenResponse>(test_id_token_jwt_);
    test_token_response_->SetAccessToken("expected_access_token");
    test_token_response_->SetAccessTokenExpiry(10000000000); // not expired, Sat 20 Nov 2286

    auto httpRequest = request_.mutable_attributes()->mutable_request()->mutable_http();
    // In practice, envoyproxy always forwards requests with empty scheme to authservice even though it "should" be https
    httpRequest->set_scheme("");
    httpRequest->set_host("example.com");
    httpRequest->set_path("/summary");
    httpRequest->set_query("foo=bar");
  }

  void AssertRetrieveToken(config::oidc::OIDCConfig &oidcConfig, std::string callback_host_on_request);

  void EnableAccessTokens(config::oidc::OIDCConfig &oidcConfig);

  void SetExpiredAccessTokenResponseInSessionStore();

  void AssertRequestedUrlAndStateAndNonceHaveBeenStored(absl::string_view session_id,
                                                        absl::string_view expected_requested_url,
                                                        absl::string_view expected_state,
                                                        absl::string_view expected_nonce);

  void MockSessionGenerator(absl::string_view session_id, absl::string_view state, absl::string_view nonce);


  static google::rpc::Code ProcessAndWaitForAsio(OidcFilter &filter,
                                                 const ::envoy::service::auth::v2::CheckRequest *request,
                                                 ::envoy::service::auth::v2::CheckResponse *response);

  void AssertSessionErrorResponse(google::rpc::Code status);

  google::rpc::Code MakeRequestWhichWillCauseTokenRetrieval(absl::string_view session_id);

};

google::rpc::Code OidcFilterTest::ProcessAndWaitForAsio(OidcFilter &filter,
                                                        const ::envoy::service::auth::v2::CheckRequest *request,
                                                        ::envoy::service::auth::v2::CheckResponse *response) {
  // Create a new io_context. All of the async IO handled inside the
  // spawn below will be handled by this new io_context.
  boost::asio::io_context ioc;
  google::rpc::Code code;

  // Spawn a co-routine to run the filter.
  boost::asio::spawn(ioc, [&](boost::asio::yield_context yield) {
    code = filter.Process(request, response, ioc, yield);
  });

  // Run the I/O context to completion, on the current thread.
  // This consumes the current thread until all of the async
  // I/O from the above spawn is finished.
  ioc.run();

  return code;
}

TEST_F(OidcFilterTest, Constructor) {
  OidcFilter filter(common::http::ptr_t(), config_, parser_mock_, session_string_generator_mock_, session_store_);
}

TEST_F(OidcFilterTest, Name) {
  OidcFilter filter(common::http::ptr_t(), config_, parser_mock_, session_string_generator_mock_, session_store_);
  ASSERT_EQ(filter.Name().compare("oidc"), 0);
}

TEST_F(OidcFilterTest, GetSessionIdCookieName) {
  config_.clear_cookie_name_prefix();
  OidcFilter filter1(common::http::ptr_t(), config_, parser_mock_, session_string_generator_mock_, session_store_);
  ASSERT_EQ(filter1.GetSessionIdCookieName(),
            "__Host-authservice-session-id-cookie");

  config_.set_cookie_name_prefix("my-prefix");
  OidcFilter filter2(common::http::ptr_t(), config_, parser_mock_, session_string_generator_mock_, session_store_);
  ASSERT_EQ(filter2.GetSessionIdCookieName(),
            "__Host-my-prefix-authservice-session-id-cookie");
}

TEST_F(OidcFilterTest, NoHttpHeader) {
  OidcFilter filter(common::http::ptr_t(), config_, parser_mock_, session_string_generator_mock_, session_store_);

  ::envoy::service::auth::v2::CheckRequest request;
  ::envoy::service::auth::v2::CheckResponse response;
  auto status = ProcessAndWaitForAsio(filter, &request, &response);
  ASSERT_EQ(status, google::rpc::Code::INVALID_ARGUMENT);
}

/* TODO: Reinstate
TEST_F(OidcFilterTest, NoHttpSchema) {
  OidcFilter filter(common::http::ptr_t(), config);
  ::envoy::service::auth::v2::CheckRequest request;
  ::envoy::service::auth::v2::CheckResponse response;
  auto status = ProcessAndWaitForAsio(filter, &request, &response);
  ASSERT_EQ(status.error_code(), ::grpc::StatusCode::INVALID_ARGUMENT);
}
 */

TEST_F(OidcFilterTest, NoAuthorization) {
  std::string session_id = "session123";
  std::string state = "some-state";
  std::string nonce = "some-nonce";
  MockSessionGenerator(session_id, state, nonce);

  OidcFilter filter(common::http::ptr_t(), config_, parser_mock_, session_string_generator_mock_, session_store_);

  auto status = ProcessAndWaitForAsio(filter, &request_, &response_);
  ASSERT_EQ(status, google::rpc::Code::UNAUTHENTICATED);
  ASSERT_EQ(response_.denied_response().status().code(),
            ::envoy::type::StatusCode::Found);

  AssertRequestedUrlAndStateAndNonceHaveBeenStored(session_id, requested_url_, state, nonce);

  ASSERT_THAT(
      response_.denied_response().headers(),
      ContainsHeaders({
                          {Location, StrEq("https://acme-idp.tld/"
                                           "authorization?client_id=example-app&nonce=" + nonce +
                              "&redirect_uri=https%3A%2F%2Fme.tld%2Fcallback&response_type=code&"
                              "scope=openid&state=" + state)
                          },
                          {CacheControl, StrEq(CacheControlDirectives::NoCache)},
                          {Pragma, StrEq(PragmaDirectives::NoCache)},
                          {SetCookie, StrEq(expected_session_cookie_name + "=" + session_id +
                              "; "
                              "HttpOnly; Path=/; "
                              "SameSite=Lax; Secure")
                          }
                      })
  );
}

TEST_F(OidcFilterTest, ReturnsUnauthorized_WhenSessionStoreThrowsErrorFromRemoveSessionWhileRedirectingToIdp) {
  auto httpRequest = request_.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->mutable_headers()->insert({Cookie, expected_session_cookie_name + "=" + "session123"});
  EXPECT_CALL(*session_store_mock_, RemoveSession(Eq("session123"))).Times(1)
      .WillRepeatedly(Throw(SessionError("session error msg")));
  OidcFilter filter(common::http::ptr_t(), config_, parser_mock_, session_string_generator_mock_, session_store_mock_);

  auto status = ProcessAndWaitForAsio(filter, &request_, &response_);;

  AssertSessionErrorResponse(status);
}

TEST_F(OidcFilterTest, ReturnsUnauthorized_WhenSessionStoreThrowsErrorFromSetAuthorizationStateWhileRedirectingToIdp) {
  MockSessionGenerator("session123", "some-state", "some-nonce");
  EXPECT_CALL(*session_store_mock_, SetAuthorizationState(Eq("session123"), _)).Times(1)
      .WillRepeatedly(Throw(SessionError("session error msg")));
  OidcFilter filter(common::http::ptr_t(), config_, parser_mock_, session_string_generator_mock_, session_store_mock_);

  auto status = ProcessAndWaitForAsio(filter, &request_, &response_);;

  AssertSessionErrorResponse(status);
}

TEST_F(OidcFilterTest, NoAuthorization_WithoutPathOrQueryParameters) {
  auto session_id = "session123";
  auto state = "some-state";
  auto nonce = "some-nonce";
  MockSessionGenerator(session_id, state, nonce);

  auto httpRequest = request_.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->clear_query();
  httpRequest->clear_path();

  OidcFilter filter(common::http::ptr_t(), config_, parser_mock_, session_string_generator_mock_, session_store_);

  ProcessAndWaitForAsio(filter, &request_, &response_);
  AssertRequestedUrlAndStateAndNonceHaveBeenStored(session_id, "https://example.com", state, nonce);
}

TEST_F(OidcFilterTest, AlreadyHasUnexpiredIdTokenShouldSendRequestToAppWithAuthorizationHeaderContainingIdToken) {
  OidcFilter filter(common::http::ptr_t(), config_, parser_mock_, session_string_generator_mock_, session_store_);
  session_store_->SetTokenResponse("session123", test_token_response_);
  auto httpRequest =
      request_.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->mutable_headers()->insert({Cookie, expected_session_cookie_name + "=" + "session123"});

  auto status = ProcessAndWaitForAsio(filter, &request_, &response_);
  ASSERT_EQ(status, google::rpc::Code::OK);

  ASSERT_THAT(
      response_.ok_response().headers(),
      ContainsHeaders({
                          {Authorization, StrEq("Bearer " + std::string(test_id_token_jwt_string_))},
                      })
  );
}

TEST_F(OidcFilterTest,
       ShouldRedirectToIdpToAuthenticateAgain_WhenAccessTokenIsMissing_GivenTheAccessTokenHeaderHasBeenConfigured) {
  EnableAccessTokens(config_);

  auto old_session_id = std::string("session123");
  auto new_session_id = std::string("session456");
  auto state = "some-state";
  auto nonce = "some-nonce";
  MockSessionGenerator(new_session_id, state, nonce);

  TokenResponse token_response(test_id_token_jwt_);
  token_response.SetAccessTokenExpiry(2906139022); //Feb 2, 2062
  token_response.SetAccessToken(nullptr);
  session_store_->SetTokenResponse(old_session_id, std::make_shared<TokenResponse>(token_response));

  OidcFilter filter(common::http::ptr_t(), config_, parser_mock_, session_string_generator_mock_, session_store_);
  auto httpRequest = request_.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->mutable_headers()->insert({Cookie, expected_session_cookie_name + "=" + "session123"});

  auto status = ProcessAndWaitForAsio(filter, &request_, &response_);

  AssertRequestedUrlAndStateAndNonceHaveBeenStored(new_session_id, requested_url_, state, nonce);

  // We expect to be redirected to authenticate
  ASSERT_EQ(status, google::rpc::Code::UNAUTHENTICATED);

  ASSERT_THAT(
      response_.denied_response().headers(),
      ContainsHeaders({
                          {Location, StartsWith(config_.authorization_uri())},
                          {CacheControl, StrEq(CacheControlDirectives::NoCache)},
                          {Pragma, StrEq(PragmaDirectives::NoCache)},
                          {SetCookie, StrEq(expected_session_cookie_name + "=" + new_session_id +
                              "; HttpOnly; Path=/; SameSite=Lax; Secure")
                          }
                      })
  );

  // Old token should be deleted
  ASSERT_FALSE(session_store_->GetTokenResponse(old_session_id));
}

TEST_F(OidcFilterTest,
       ExpiredAccessToken_ShouldRedirectToIdpToAuthenticateAgain_WhenTheAccessTokenHeaderHasBeenConfigured_GivenThereIsNoRefreshToken) {
  EnableAccessTokens(config_);

  auto old_session_id = std::string("session123");
  auto new_session_id = std::string("session456");
  auto state = "some-state";
  auto nonce = "some-nonce";
  MockSessionGenerator(new_session_id, state, nonce);

  TokenResponse token_response(test_id_token_jwt_); // id token, not expired
  token_response.SetAccessTokenExpiry(1); // already expired
  token_response.SetAccessToken("fake_access_token");
  session_store_->SetTokenResponse(old_session_id, std::make_shared<TokenResponse>(token_response));

  OidcFilter filter(common::http::ptr_t(), config_, parser_mock_, session_string_generator_mock_, session_store_);
  auto httpRequest =
      request_.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->mutable_headers()->insert({Cookie, expected_session_cookie_name + "=" + old_session_id});

  auto status = ProcessAndWaitForAsio(filter, &request_, &response_);
  // We expect to be redirected to authenticate
  ASSERT_EQ(status, google::rpc::Code::UNAUTHENTICATED);

  AssertRequestedUrlAndStateAndNonceHaveBeenStored(new_session_id, requested_url_, state, nonce);
  ASSERT_FALSE(session_store_->GetTokenResponse(old_session_id));

  ASSERT_THAT(
      response_.denied_response().headers(),
      ContainsHeaders({
                          {Location, StartsWith(config_.authorization_uri())},
                          {CacheControl, StrEq(CacheControlDirectives::NoCache)},
                          {Pragma, StrEq(PragmaDirectives::NoCache)},
                          {SetCookie, StrEq(expected_session_cookie_name + "=" + new_session_id +
                              "; HttpOnly; Path=/; SameSite=Lax; Secure")}
                      })
  );
}

// id token is unexpired, access token is expired, server returns only access token from refresh endpoint
TEST_F(OidcFilterTest,
       ExpiredAccessTokenShouldRefreshTheTokenResponse_WhenTheAccessTokenHeaderHasBeenConfigured_GivenThereIsRefreshToken) {
  EnableAccessTokens(config_);

  SetExpiredAccessTokenResponseInSessionStore();

  auto mocked_http = new common::http::HttpMock();
  auto *pMessage = new beast::http::response<beast::http::string_body>();
  auto raw_http_token_response_from_idp = common::http::response_t(pMessage);
  raw_http_token_response_from_idp->result(beast::http::status::ok);
  EXPECT_CALL(*mocked_http, Post(Eq(token_uri), _, _, Eq("some-ca"), Eq("http://some-proxy-uri.com"), _, _, _)).WillOnce(
      Return(ByMove(std::move(raw_http_token_response_from_idp))));

  auto jwt_status = test_id_token_jwt_.parseFromString(test_id_token_jwt_string_);
  ASSERT_EQ(jwt_status, google::jwt_verify::Status::Ok);

  auto test_refresh_token_response = std::make_shared<TokenResponse>(test_id_token_jwt_);
  test_refresh_token_response->SetAccessToken("expected_refreshed_access_token");
  test_refresh_token_response->SetAccessTokenExpiry(11000000000); // July 30, 2318
  test_refresh_token_response->SetRefreshToken("expected_refreshed_refresh_token");

  EXPECT_CALL(*parser_mock_, ParseRefreshTokenResponse(_, _))
      .WillOnce(::testing::Return(test_refresh_token_response));

  OidcFilter filter(common::http::ptr_t(mocked_http), config_, parser_mock_, session_string_generator_mock_,
                    session_store_);

  auto httpRequest = request_.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->mutable_headers()->insert({Cookie, expected_session_cookie_name + "=" + "session123"});

  auto status = ProcessAndWaitForAsio(filter, &request_, &response_);
  ASSERT_EQ(status, google::rpc::Code::OK);
  ASSERT_THAT(
      response_.ok_response().headers(),
      ContainsHeaders({
                          {Authorization, StrEq("Bearer " + std::string(test_id_token_jwt_string_))},
                          {"access_token", StrEq("expected_refreshed_access_token")},
                      })
  );

  auto stored_token_response = session_store_->GetTokenResponse("session123");
  ASSERT_TRUE(stored_token_response);
  ASSERT_EQ(stored_token_response->IDToken().jwt_, test_id_token_jwt_string_);
  ASSERT_EQ(stored_token_response->AccessToken(), "expected_refreshed_access_token");
  ASSERT_EQ(stored_token_response->GetAccessTokenExpiry(), 11000000000);
  ASSERT_EQ(stored_token_response->RefreshToken(), "expected_refreshed_refresh_token");
}

TEST_F(OidcFilterTest, ReturnsUnauthorized_WhenSessionStoreThrowsErrorDuringRefreshTokenFlow) {
  EnableAccessTokens(config_);

  auto mocked_http = new common::http::HttpMock();
  auto *pMessage = new beast::http::response<beast::http::string_body>();
  auto raw_http_token_response_from_idp = common::http::response_t(pMessage);
  raw_http_token_response_from_idp->result(beast::http::status::ok);
  EXPECT_CALL(*mocked_http, Post(Eq(token_uri), _, _, Eq("some-ca"), Eq("http://some-proxy-uri.com"), _, _, _)).WillOnce(
      Return(ByMove(std::move(raw_http_token_response_from_idp))));

  auto jwt_status = test_id_token_jwt_.parseFromString(test_id_token_jwt_string_);
  ASSERT_EQ(jwt_status, google::jwt_verify::Status::Ok);

  auto test_refresh_token_response = std::make_shared<TokenResponse>(test_id_token_jwt_);
  test_refresh_token_response->SetAccessToken("expected_refreshed_access_token");
  test_refresh_token_response->SetAccessTokenExpiry(11000000000); // July 30, 2318
  test_refresh_token_response->SetRefreshToken("expected_refreshed_refresh_token");

  EXPECT_CALL(*parser_mock_, ParseRefreshTokenResponse(_, _))
      .WillOnce(::testing::Return(test_refresh_token_response));

  auto token_response_from_session = std::make_shared<TokenResponse>(test_id_token_jwt_);
  token_response_from_session->SetAccessToken("fake_access_token");
  token_response_from_session->SetRefreshToken("fake_refresh_token");
  token_response_from_session->SetAccessTokenExpiry(1); // access token already expired
  EXPECT_CALL(*session_store_mock_, GetTokenResponse(Eq("session123"))).Times(1).WillOnce(
      Return(token_response_from_session));

  EXPECT_CALL(*session_store_mock_, SetTokenResponse(Eq("session123"), _)).Times(1)
      .WillRepeatedly(Throw(SessionError("session error msg")));

  OidcFilter filter(common::http::ptr_t(mocked_http), config_, parser_mock_, session_string_generator_mock_,
                    session_store_mock_);

  auto httpRequest = request_.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->mutable_headers()->insert({Cookie, expected_session_cookie_name + "=" + "session123"});

  auto status = ProcessAndWaitForAsio(filter, &request_, &response_);;

  AssertSessionErrorResponse(status);
}

TEST_F(OidcFilterTest,
       Process_RedirectsUsersToAuthenticate_AndGeneratesNewSessionId_WhenThereIsNoStoredTokenResponseAssociatedWithTheUsersSession) {
  EnableAccessTokens(config_);

  auto mocked_http = new common::http::HttpMock();
  auto old_session_id = std::string("session123");
  auto new_session_id = std::string("session456");
  auto state = "some-state";
  auto nonce = "some-nonce";
  MockSessionGenerator(new_session_id, state, nonce);

  OidcFilter filter(common::http::ptr_t(mocked_http), config_, parser_mock_, session_string_generator_mock_,
                    session_store_);

  auto httpRequest = request_.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->mutable_headers()->insert({Cookie, expected_session_cookie_name + "=" + old_session_id});

  auto status = ProcessAndWaitForAsio(filter, &request_, &response_);

  ASSERT_EQ(status, google::rpc::Code::UNAUTHENTICATED);

  AssertRequestedUrlAndStateAndNonceHaveBeenStored(new_session_id, requested_url_, state, nonce);
  ASSERT_FALSE(session_store_->GetAuthorizationState(old_session_id));

  ASSERT_THAT(
      response_.denied_response().headers(),
      ContainsHeaders({
                          {Location, StartsWith(config_.authorization_uri())},
                          {CacheControl, StrEq(CacheControlDirectives::NoCache)},
                          {Pragma, StrEq(PragmaDirectives::NoCache)},
                          {SetCookie, StrEq(expected_session_cookie_name + "=" + new_session_id +
                              "; HttpOnly; Path=/; SameSite=Lax; Secure")}
                      })
  );
}

TEST_F(OidcFilterTest, Process_RedirectsUsersToAuthenticate_WhenFailingToParseTheRefreshedTokenResponse) {
  EnableAccessTokens(config_);

  SetExpiredAccessTokenResponseInSessionStore();

  auto mocked_http = new common::http::HttpMock();
  auto *pMessage = new beast::http::response<beast::http::string_body>();
  auto raw_http_token_response_from_idp = common::http::response_t(pMessage);
  raw_http_token_response_from_idp->result(beast::http::status::ok);
  EXPECT_CALL(*mocked_http, Post(Eq(token_uri), _, _, Eq("some-ca"), Eq("http://some-proxy-uri.com"), _, _, _)).WillOnce(
      Return(ByMove(std::move(raw_http_token_response_from_idp))));

  EXPECT_CALL(*parser_mock_, ParseRefreshTokenResponse(_, _)).WillOnce(::testing::Return(nullptr));

  auto old_session_id = std::string("session123");
  auto new_session_id = std::string("session456");
  auto state = "some-state";
  auto nonce = "some-nonce";
  MockSessionGenerator(new_session_id, state, nonce);

  OidcFilter filter(common::http::ptr_t(mocked_http), config_, parser_mock_, session_string_generator_mock_,
                    session_store_);

  auto httpRequest = request_.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->mutable_headers()->insert({Cookie, expected_session_cookie_name + "=" + old_session_id});

  auto status = ProcessAndWaitForAsio(filter, &request_, &response_);

  AssertRequestedUrlAndStateAndNonceHaveBeenStored(new_session_id, requested_url_, state, nonce);

  ASSERT_EQ(status, google::rpc::Code::UNAUTHENTICATED);
  ASSERT_THAT(
      response_.denied_response().headers(),
      ContainsHeaders({
                          {Location, StartsWith(config_.authorization_uri())},
                          {CacheControl, StrEq(CacheControlDirectives::NoCache)},
                          {Pragma, StrEq(PragmaDirectives::NoCache)},
                          {SetCookie, StrEq(expected_session_cookie_name + "=" + new_session_id +
                              "; HttpOnly; Path=/; SameSite=Lax; Secure")}
                      })
  );

  ASSERT_FALSE(session_store_->GetTokenResponse(old_session_id));
}

TEST_F(OidcFilterTest, Process_RedirectsUsersToAuthenticate_WhenFailingToEstablishHttpConnectionToIDP) {
  EnableAccessTokens(config_);

  SetExpiredAccessTokenResponseInSessionStore();

  auto mocked_http = new common::http::HttpMock();
  EXPECT_CALL(*mocked_http, Post(Eq(token_uri), _, _, Eq("some-ca"), Eq("http://some-proxy-uri.com"), _, _, _)).WillOnce(
      Return(ByMove(nullptr)));

  auto old_session_id = std::string("session123");
  auto new_session_id = std::string("session456");
  auto state = "some-state";
  auto nonce = "some-nonce";
  MockSessionGenerator(new_session_id, state, nonce);

  OidcFilter filter(common::http::ptr_t(mocked_http), config_, parser_mock_, session_string_generator_mock_,
                    session_store_);

  auto httpRequest = request_.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->mutable_headers()->insert({Cookie, expected_session_cookie_name + "=" + old_session_id});

  auto status = ProcessAndWaitForAsio(filter, &request_, &response_);
  ASSERT_EQ(status, google::rpc::Code::UNAUTHENTICATED);
  AssertRequestedUrlAndStateAndNonceHaveBeenStored(new_session_id, requested_url_, state, nonce);

  ASSERT_THAT(
      response_.denied_response().headers(),
      ContainsHeaders({
                          {Location, StartsWith(config_.authorization_uri())},
                          {CacheControl, StrEq(CacheControlDirectives::NoCache)},
                          {Pragma, StrEq(PragmaDirectives::NoCache)},
                          {SetCookie, StrEq(expected_session_cookie_name + "=" + new_session_id +
                              "; HttpOnly; Path=/; SameSite=Lax; Secure")}
                      })
  );

  ASSERT_FALSE(session_store_->GetTokenResponse(old_session_id));
}

TEST_F(OidcFilterTest, Process_RedirectsUsersToAuthenticate_WhenIDPReturnsUnsuccessfulHttpResponseCode) {
  EnableAccessTokens(config_);

  SetExpiredAccessTokenResponseInSessionStore();

  auto mocked_http = new common::http::HttpMock();
  auto *pMessage = new beast::http::response<beast::http::string_body>();
  auto raw_http_token_response_from_idp = common::http::response_t(pMessage);
  raw_http_token_response_from_idp->result(beast::http::status::bad_request);
  EXPECT_CALL(*mocked_http, Post(Eq(token_uri), _, _, Eq("some-ca"), Eq("http://some-proxy-uri.com"), _, _, _)).WillOnce(
      Return(ByMove(std::move(raw_http_token_response_from_idp))));

  // we want the code to return before attempting to parse the bad response
  EXPECT_CALL(*parser_mock_, ParseRefreshTokenResponse(_, _)).Times(0);

  auto old_session_id = std::string("session123");
  auto new_session_id = std::string("session456");
  auto state = "some-state";
  auto nonce = "some-nonce";
  MockSessionGenerator(new_session_id, state, nonce);

  auto jwt_status = test_id_token_jwt_.parseFromString(test_id_token_jwt_string_);
  ASSERT_EQ(jwt_status, google::jwt_verify::Status::Ok);

  OidcFilter filter(common::http::ptr_t(mocked_http), config_, parser_mock_, session_string_generator_mock_,
                    session_store_);

  auto httpRequest = request_.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->mutable_headers()->insert({Cookie, expected_session_cookie_name + "=" + old_session_id});
  auto status = ProcessAndWaitForAsio(filter, &request_, &response_);

  ASSERT_EQ(status, google::rpc::Code::UNAUTHENTICATED);
  AssertRequestedUrlAndStateAndNonceHaveBeenStored(new_session_id, requested_url_, state, nonce);
  ASSERT_THAT(
      response_.denied_response().headers(),
      ContainsHeaders({
                          {Location, StartsWith(config_.authorization_uri())},
                          {CacheControl, StrEq(CacheControlDirectives::NoCache)},
                          {Pragma, StrEq(PragmaDirectives::NoCache)},
                          {SetCookie, StrEq(expected_session_cookie_name + "=" + new_session_id +
                              "; HttpOnly; Path=/; SameSite=Lax; Secure")}
                      })
  );

  ASSERT_FALSE(session_store_->GetTokenResponse(old_session_id));
}

TEST_F(OidcFilterTest,
       Process_PermitsTheRequestToContinue_GivenTheAccessTokenIsExpired_ButGivenTheAccessTokenHeaderHasNotBeenConfigured) {
  TokenResponse token_response(test_id_token_jwt_); // id token, not expired
  token_response.SetAccessTokenExpiry(1); // access token, already expired
  token_response.SetAccessToken("fake_access_token");
  session_store_->SetTokenResponse("session123", std::make_shared<TokenResponse>(token_response));

  auto httpRequest = request_.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->mutable_headers()->insert({Cookie, expected_session_cookie_name + "=" + "session123"});

  OidcFilter filter(common::http::ptr_t(), config_, parser_mock_, session_string_generator_mock_, session_store_);

  auto status = ProcessAndWaitForAsio(filter, &request_, &response_);

  ASSERT_EQ(status, google::rpc::Code::OK);
  ASSERT_THAT(
      response_.ok_response().headers(),
      ContainsHeaders({
                          {Authorization, StrEq("Bearer " + std::string(test_id_token_jwt_string_))}
                      })
  );
}

TEST_F(OidcFilterTest,
       ShouldPermitTheRequestToContinue_WhenTokenResponseWithAccessTokenButNoExpiresInTime_GivenTheAccessTokenHeaderHasBeenConfigured) {
  EnableAccessTokens(config_);

  TokenResponse token_response(test_id_token_jwt_); // id token, not expired
  token_response.SetAccessTokenExpiry(0);
  token_response.SetAccessToken("fake_access_token");
  session_store_->SetTokenResponse("session123", std::make_shared<TokenResponse>(token_response));

  OidcFilter filter(common::http::ptr_t(), config_, parser_mock_, session_string_generator_mock_, session_store_);
  auto httpRequest = request_.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->mutable_headers()->insert({Cookie, expected_session_cookie_name + "=" + "session123"});

  auto status = ProcessAndWaitForAsio(filter, &request_, &response_);

  ASSERT_EQ(status, google::rpc::Code::OK);
  ASSERT_THAT(
      response_.ok_response().headers(),
      ContainsHeaders({
                          {Authorization, StrEq("Bearer " + std::string(test_id_token_jwt_string_))},
                          {"access_token", StrEq("fake_access_token")},
                      })
  );
}

TEST_F(OidcFilterTest, ExpiredIdTokenShouldRedirectToIdpToAuthenticateAgainWhenTheAccessTokenHeaderHasBeenConfigured) {
  EnableAccessTokens(config_);

  //ID Token with exp of Sep 22, 2017
  const char *expired_id_token_jwt_string =
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTA2MTI5MDIyLCJleHAiOjE1MDYxMzkwMjJ9.nYUg1lKTjuuT5aD2HuoPzOUtWCgenscZXisuCEzho1s";
  google::jwt_verify::Jwt expired_id_token_jwt;

  auto jwt_status = expired_id_token_jwt.parseFromString(expired_id_token_jwt_string);
  ASSERT_EQ(jwt_status, google::jwt_verify::Status::Ok);

  TokenResponse token_response(expired_id_token_jwt);
  token_response.SetAccessToken("expected_access_token");
  token_response.SetAccessTokenExpiry(10000000000); // access token not expired, Sat 20 Nov 2286

  auto old_session_id = std::string("session123");
  auto new_session_id = std::string("session456");
  auto state = "some-state";
  auto nonce = "some-nonce";
  MockSessionGenerator(new_session_id, state, nonce);

  OidcFilter filter(common::http::ptr_t(), config_, parser_mock_, session_string_generator_mock_, session_store_);
  auto httpRequest =
      request_.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->mutable_headers()->insert({Cookie, expected_session_cookie_name + "=" + old_session_id});

  session_store_->SetTokenResponse(old_session_id, std::make_shared<TokenResponse>(token_response));

  auto status = ProcessAndWaitForAsio(filter, &request_, &response_);
  // We expect to be redirected to authenticate because the id_token is expired
  ASSERT_EQ(status, google::rpc::Code::UNAUTHENTICATED);
  AssertRequestedUrlAndStateAndNonceHaveBeenStored(new_session_id, requested_url_, state, nonce);
  ASSERT_THAT(
      response_.denied_response().headers(),
      ContainsHeaders({
                          {Location, StartsWith(config_.authorization_uri())},
                          {CacheControl, StrEq(CacheControlDirectives::NoCache)},
                          {Pragma, StrEq(PragmaDirectives::NoCache)},
                          {SetCookie, StrEq(expected_session_cookie_name + "=" + new_session_id +
                              "; HttpOnly; Path=/; SameSite=Lax; Secure")}
                      })
  );
}

TEST_F(OidcFilterTest,
       AlreadyHasUnexpiredTokensShouldSendRequestToAppWithHeadersContainingBothTokensWhenTheAccessTokenHeaderHasBeenConfigured) {
  EnableAccessTokens(config_);
  session_store_->SetTokenResponse("session123", test_token_response_);
  OidcFilter filter(common::http::ptr_t(), config_, parser_mock_, session_string_generator_mock_, session_store_);
  auto httpRequest = request_.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->mutable_headers()->insert({Cookie, expected_session_cookie_name + "=" + "session123"});

  auto status = ProcessAndWaitForAsio(filter, &request_, &response_);
  ASSERT_EQ(status, google::rpc::Code::OK);

  ASSERT_THAT(
      response_.ok_response().headers(),
      ContainsHeaders({
                          {Authorization, StrEq("Bearer " + std::string(test_id_token_jwt_string_))},
                          {"access_token", StrEq("expected_access_token")},
                      })
  );
}

TEST_F(OidcFilterTest, ReturnsUnauthorized_WhenSessionStoreThrowsErrorWhileTryingToGetTheSession) {
  OidcFilter filter(common::http::ptr_t(), config_, parser_mock_, session_string_generator_mock_, session_store_mock_);
  auto httpRequest = request_.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->mutable_headers()->insert({Cookie, expected_session_cookie_name + "=" + "session123"});

  EXPECT_CALL(*session_store_mock_, GetTokenResponse(Eq("session123"))).Times(1)
      .WillRepeatedly(Throw(SessionError("session error msg")));

  auto status = ProcessAndWaitForAsio(filter, &request_, &response_);;

  AssertSessionErrorResponse(status);
}

TEST_F(OidcFilterTest, LogoutWithCookies) {
  session_store_->SetTokenResponse("session123", test_token_response_);
  config_.mutable_logout()->set_path("/logout");
  config_.mutable_logout()->set_redirect_uri("https://redirect-uri");
  OidcFilter filter(common::http::ptr_t(), config_, parser_mock_, session_string_generator_mock_, session_store_);
  auto httpRequest =
      request_.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->mutable_headers()->insert({Cookie, expected_session_cookie_name + "=" + "session123"});
  httpRequest->set_path("/logout");

  auto status = ProcessAndWaitForAsio(filter, &request_, &response_);

  ASSERT_FALSE(session_store_->GetTokenResponse("session123"));

  ASSERT_EQ(status, google::rpc::Code::UNAUTHENTICATED);
  ASSERT_EQ(response_.denied_response().status().code(),
            ::envoy::type::StatusCode::Found);

  ASSERT_THAT(
      response_.denied_response().headers(),
      ContainsHeaders({
                          {Location, StrEq("https://redirect-uri")},
                          {CacheControl, StrEq(CacheControlDirectives::NoCache)},
                          {Pragma, StrEq(PragmaDirectives::NoCache)},
                          {SetCookie, StrEq(expected_session_cookie_name +
                              "=deleted; HttpOnly; Max-Age=0; Path=/; SameSite=Lax; Secure")}
                      })
  );
}

TEST_F(OidcFilterTest, ReturnsUnauthorized_WhenSessionStoreThrowsErrorDuringLogout) {
  config_.mutable_logout()->set_path("/logout");
  config_.mutable_logout()->set_redirect_uri("https://redirect-uri");
  OidcFilter filter(common::http::ptr_t(), config_, parser_mock_, session_string_generator_mock_, session_store_mock_);
  auto httpRequest =
      request_.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->mutable_headers()->insert({Cookie, expected_session_cookie_name + "=" + "session123"});
  httpRequest->set_path("/logout");
  EXPECT_CALL(*session_store_mock_, RemoveSession(Eq("session123"))).Times(1)
      .WillRepeatedly(Throw(SessionError("session error msg")));

  auto status = ProcessAndWaitForAsio(filter, &request_, &response_);;

  AssertSessionErrorResponse(status);
}

TEST_F(OidcFilterTest, LogoutWithNoCookies) {
  config_.mutable_logout()->set_path("/logout");
  config_.mutable_logout()->set_redirect_uri("https://redirect-uri");
  OidcFilter filter(common::http::ptr_t(), config_, parser_mock_, session_string_generator_mock_, session_store_);
  auto httpRequest = request_.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->set_path("/logout");

  auto status = ProcessAndWaitForAsio(filter, &request_, &response_);

  ASSERT_EQ(status, google::rpc::Code::UNAUTHENTICATED);
  ASSERT_EQ(response_.denied_response().status().code(),
            ::envoy::type::StatusCode::Found);

  ASSERT_THAT(
      response_.denied_response().headers(),
      ContainsHeaders({
                          {Location, StrEq("https://redirect-uri")},
                          {CacheControl, StrEq(CacheControlDirectives::NoCache)},
                          {Pragma, StrEq(PragmaDirectives::NoCache)},
                          {SetCookie, StrEq(expected_session_cookie_name +
                              "=deleted; HttpOnly; Max-Age=0; Path=/; SameSite=Lax; Secure")}
                      })
  );
}

TEST_F(OidcFilterTest, RetrieveToken_RedirectsUser_WithoutAccessTokenHeaderNameConfigured) {
  config_.set_callback_uri("https://me.tld/callback");
  AssertRetrieveToken(config_, "me.tld:443");
}

TEST_F(OidcFilterTest,
       RetrieveToken_RedirectsUser_WithoutAccessTokenHeaderNameConfiguredWhenThePortIsNotInTheRequestHostnameAndTheConfiguredCallbackIsExplicitlyTheDefaultHttpsPort) {
  config_.set_callback_uri("https://me.tld:443/callback");
  AssertRetrieveToken(config_, "me.tld");
}

TEST_F(OidcFilterTest,
       RetrieveToken_RedirectsUser_WithoutAccessTokenHeaderNameConfiguredWhenThePortIsNotInTheRequestHostnameAndTheConfiguredCallbackIsImplicitlyTheDefaultHttpsPort) {
  config_.set_callback_uri("https://me.tld/callback");
  AssertRetrieveToken(config_, "me.tld");
}

TEST_F(OidcFilterTest, RetrieveToken_RedirectsUser_WithAccessTokenHeaderNameConfigured) {
  EnableAccessTokens(config_);
  AssertRetrieveToken(config_, "me.tld");
}

TEST_F(OidcFilterTest, RetrieveToken_ReturnsError_WhenAuthorizationStateInfoCannotBeFoundInSession) {
  std::string session_id = "session123";
  auto mocked_http = new common::http::HttpMock();
  OidcFilter filter(common::http::ptr_t(mocked_http), config_, parser_mock_, session_string_generator_mock_,
                    session_store_);

  auto httpRequest = request_.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->set_host(callback_host_);
  httpRequest->mutable_headers()->insert({Cookie, expected_session_cookie_name + "=" + session_id});
  std::vector<std::string> parts = {callback_path_, "code=value&state=some-state-value"};
  httpRequest->set_path(absl::StrJoin(parts, "?"));

  auto code = ProcessAndWaitForAsio(filter, &request_, &response_);
  ASSERT_EQ(code, google::rpc::Code::UNAUTHENTICATED);
  ASSERT_EQ(response_.denied_response().status().code(), ::envoy::type::StatusCode::BadRequest);
  ASSERT_EQ(response_.denied_response().body(), "Oops, your session has expired. Please try again.");
  ASSERT_THAT(
      response_.denied_response().headers(),
      ContainsHeaders({
                          {CacheControl, StrEq(CacheControlDirectives::NoCache)},
                          {Pragma, StrEq(PragmaDirectives::NoCache)},
                      })
  );
}

TEST_F(OidcFilterTest, ReturnsUnauthorized_WhenSessionStoreThrowsError_GettingAuthorizationStateDuringRetrieveToken) {
  std::string session_id = "session123";
  auto mocked_http = new common::http::HttpMock();
  OidcFilter filter(common::http::ptr_t(mocked_http), config_, parser_mock_, session_string_generator_mock_,
                    session_store_mock_);

  auto httpRequest = request_.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->set_host(callback_host_);
  httpRequest->mutable_headers()->insert({Cookie, expected_session_cookie_name + "=" + session_id});
  std::vector<std::string> parts = {callback_path_, "code=value&state=some-state-value"};
  httpRequest->set_path(absl::StrJoin(parts, "?"));
  EXPECT_CALL(*session_store_mock_, GetAuthorizationState(Eq("session123"))).Times(1)
      .WillRepeatedly(Throw(SessionError("session error msg")));

  auto code = ProcessAndWaitForAsio(filter, &request_, &response_);;
  AssertSessionErrorResponse(code);
}

TEST_F(OidcFilterTest, ReturnsUnauthorized_WhenSessionStoreThrowsError_ClearAuthorizationStateDuringRetrieveToken) {
  std::string session_id = "session123";
  EXPECT_CALL(*session_store_mock_, ClearAuthorizationState(Eq(session_id))).Times(1)
      .WillOnce(Throw(SessionError("session error msg")));
  auto status = MakeRequestWhichWillCauseTokenRetrieval(session_id);
  AssertSessionErrorResponse(status);
}

TEST_F(OidcFilterTest, ReturnsUnauthorized_WhenSessionStoreThrowsError_SetTokenResponseDuringRetrieveToken) {
  std::string session_id = "session123";
  EXPECT_CALL(*session_store_mock_, SetTokenResponse(Eq(session_id), _)).Times(1)
      .WillOnce(Throw(SessionError("session error msg")));
  auto status = MakeRequestWhichWillCauseTokenRetrieval(session_id);
  AssertSessionErrorResponse(status);
}

google::rpc::Code OidcFilterTest::MakeRequestWhichWillCauseTokenRetrieval(absl::string_view session_id) {
  config_.set_callback_uri("https://me.tld/callback");
  auto callback_host_on_request = "me.tld";
  std::string state = "expectedstate";
  std::string nonce = "expectednonce";
  std::string requested_url = "https://example.com/summary";
  auto authorization_state = std::make_shared<AuthorizationState>(state, nonce, requested_url);
  EXPECT_CALL(*session_store_mock_, GetAuthorizationState(Eq(session_id))).Times(1)
      .WillOnce(Return(authorization_state));
  EXPECT_CALL(*parser_mock_, Parse(config_.client_id(), nonce, ::testing::_))
      .WillOnce(::testing::Return(test_token_response_));
  auto mocked_http = new common::http::HttpMock();
  auto raw_http = common::http::response_t(new beast::http::response<beast::http::string_body>());
  raw_http->result(beast::http::status::ok);
  EXPECT_CALL(*mocked_http, Post(Eq(token_uri), _, _, Eq("some-ca"), Eq("http://some-proxy-uri.com"), _, _, _))
      .WillOnce(Return(ByMove(std::move(raw_http))));
  OidcFilter filter(common::http::ptr_t(mocked_http), config_, parser_mock_, session_string_generator_mock_,
                    session_store_mock_);
  auto httpRequest = request_.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->set_host(callback_host_on_request);
  httpRequest->mutable_headers()->insert({Cookie, expected_session_cookie_name + "=" + session_id.data()});
  std::vector<std::string> parts = {callback_path_, "code=value&state=" + state};
  httpRequest->set_path(absl::StrJoin(parts, "?"));
  return ProcessAndWaitForAsio(filter, &request_, &response_);;
}

TEST_F(OidcFilterTest, RetrieveToken_ReturnsError_WhenTokenResponseIsMissingAccessToken) {
  std::string session_id = "session123";
  std::string state = "expectedstate";
  std::string nonce = "expectednonce";
  std::string requested_url = "https://example.com/summary";
  auto authorization_state = std::make_shared<AuthorizationState>(state, nonce, requested_url);
  session_store_->SetAuthorizationState(session_id, authorization_state);

  EnableAccessTokens(config_);
  google::jwt_verify::Jwt jwt = {};
  auto token_response = std::make_shared<TokenResponse>(jwt);
  EXPECT_CALL(*parser_mock_, Parse(config_.client_id(), nonce, ::testing::_))
      .WillOnce(::testing::Return(token_response));
  auto mocked_http = new common::http::HttpMock();
  auto raw_http = common::http::response_t(
      new beast::http::response<beast::http::string_body>());
  raw_http->result(beast::http::status::ok);
  EXPECT_CALL(*mocked_http, Post(Eq(token_uri), _, _, Eq("some-ca"), Eq("http://some-proxy-uri.com"), _, _, _))
      .WillOnce(Return(ByMove(std::move(raw_http))));
  ASSERT_FALSE(session_store_->GetTokenResponse(session_id));
  OidcFilter filter(common::http::ptr_t(mocked_http), config_, parser_mock_, session_string_generator_mock_,
                    session_store_);

  auto httpRequest = request_.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->set_host(callback_host_);
  httpRequest->mutable_headers()->insert({Cookie, expected_session_cookie_name + "=" + session_id});

  std::vector<std::string> parts = {callback_path_, "code=value&state=" + state};
  httpRequest->set_path(absl::StrJoin(parts, "?"));
  auto code = ProcessAndWaitForAsio(filter, &request_, &response_);
  ASSERT_EQ(code, google::rpc::Code::INVALID_ARGUMENT);

  ASSERT_FALSE(session_store_->GetTokenResponse(session_id));

  ASSERT_THAT(
      response_.denied_response().headers(),
      ContainsHeaders({
                          {CacheControl, StrEq(CacheControlDirectives::NoCache)},
                          {Pragma, StrEq(PragmaDirectives::NoCache)},
                      })
  );
}

TEST_F(OidcFilterTest, RetrieveToken_ReturnsError_WhenMissingCode) {
  std::string session_id = "session123";
  std::string state = "expectedstate";
  std::string nonce = "expectednonce";
  std::string requested_url = "https://example.com/summary";
  auto authorization_state = std::make_shared<AuthorizationState>(state, nonce, requested_url);
  session_store_->SetAuthorizationState(session_id, authorization_state);

  OidcFilter filter(common::http::ptr_t(), config_, parser_mock_, session_string_generator_mock_, session_store_);
  auto httpRequest =
      request_.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->set_host(callback_host_);
  std::vector<std::string> parts = {callback_path_, "key=value&state=" + state};
  httpRequest->set_path(absl::StrJoin(parts, "?"));
  httpRequest->mutable_headers()->insert({Cookie, expected_session_cookie_name + "=" + session_id});

  auto code = ProcessAndWaitForAsio(filter, &request_, &response_);
  ASSERT_EQ(code, google::rpc::Code::INVALID_ARGUMENT);

  ASSERT_THAT(
      response_.denied_response().headers(),
      ContainsHeaders({
                          {CacheControl, StrEq(CacheControlDirectives::NoCache)},
                          {Pragma, StrEq(PragmaDirectives::NoCache)},
                      })
  );
}

TEST_F(OidcFilterTest, RetrieveToken_ReturnsError_WhenMissingState) {
  OidcFilter filter(common::http::ptr_t(), config_, parser_mock_, session_string_generator_mock_, session_store_);
  auto httpRequest =
      request_.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->set_host(callback_host_);
  std::vector<std::string> parts = {callback_path_.c_str(), "code=value"};
  httpRequest->set_path(absl::StrJoin(parts, "?"));
  httpRequest->mutable_headers()->insert({Cookie, expected_session_cookie_name + "=" + "session123"});

  auto code = ProcessAndWaitForAsio(filter, &request_, &response_);
  ASSERT_EQ(code, google::rpc::Code::INVALID_ARGUMENT);

  ASSERT_THAT(
      response_.denied_response().headers(),
      ContainsHeaders({
                          {CacheControl, StrEq(CacheControlDirectives::NoCache)},
                          {Pragma, StrEq(PragmaDirectives::NoCache)},
                      })
  );
}

TEST_F(OidcFilterTest, RetrieveToken_ReturnsError_WhenUnexpectedState) {
  std::string session_id = "session123";
  std::string state = "expectedstate";
  std::string nonce = "expectednonce";
  std::string requested_url = "https://example.com/summary";
  auto authorization_state = std::make_shared<AuthorizationState>(state, nonce, requested_url);
  session_store_->SetAuthorizationState(session_id, authorization_state);

  OidcFilter filter(common::http::ptr_t(), config_, parser_mock_, session_string_generator_mock_, session_store_);
  auto httpRequest =
      request_.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->set_host(callback_host_);
  std::vector<std::string> parts = {callback_path_, "code=value&state=unexpectedstate"};
  httpRequest->set_path(absl::StrJoin(parts, "?"));
  httpRequest->mutable_headers()->insert({Cookie, expected_session_cookie_name + "=" + session_id});

  auto code = ProcessAndWaitForAsio(filter, &request_, &response_);
  ASSERT_EQ(code, google::rpc::Code::INVALID_ARGUMENT);

  ASSERT_THAT(
      response_.denied_response().headers(),
      ContainsHeaders({
                          {CacheControl, StrEq(CacheControlDirectives::NoCache)},
                          {Pragma, StrEq(PragmaDirectives::NoCache)},
                      })
  );
}

TEST_F(OidcFilterTest, RetrieveToken_ReturnsError_WhenBrokenPipe) {
  std::string session_id = "session123";
  std::string state = "expectedstate";
  std::string nonce = "expectednonce";
  std::string requested_url = "https://example.com/summary";
  auto authorization_state = std::make_shared<AuthorizationState>(state, nonce, requested_url);
  session_store_->SetAuthorizationState(session_id, authorization_state);

  auto *mocked_http = new common::http::HttpMock();
  auto raw_http = common::http::response_t();
  EXPECT_CALL(*mocked_http, Post(Eq(token_uri), _, _, Eq("some-ca"), Eq("http://some-proxy-uri.com"), _, _, _))
      .WillOnce(Return(ByMove(std::move(raw_http))));
  OidcFilter filter(common::http::ptr_t(mocked_http), config_, parser_mock_, session_string_generator_mock_,
                    session_store_);
  auto httpRequest =
      request_.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->set_host(callback_host_);
  httpRequest->mutable_headers()->insert({Cookie, expected_session_cookie_name + "=" + session_id});
  std::vector<std::string> parts = {callback_path_, "code=value&state=" + state};
  httpRequest->set_path(absl::StrJoin(parts, "?"));
  auto code = ProcessAndWaitForAsio(filter, &request_, &response_);
  ASSERT_EQ(code, google::rpc::Code::INTERNAL);

  ASSERT_THAT(
      response_.denied_response().headers(),
      ContainsHeaders({
                          {CacheControl, StrEq(CacheControlDirectives::NoCache)},
                          {Pragma, StrEq(PragmaDirectives::NoCache)},
                      })
  );
}

TEST_F(OidcFilterTest, RetrieveToken_ReturnsError_WhenInvalidResponse) {
  std::string session_id = "session123";
  std::string state = "expectedstate";
  std::string nonce = "expectednonce";
  std::string requested_url = "https://example.com/summary";
  auto authorization_state = std::make_shared<AuthorizationState>(state, nonce, requested_url);
  session_store_->SetAuthorizationState(session_id, authorization_state);

  EXPECT_CALL(*parser_mock_, Parse(config_.client_id(), nonce, ::testing::_))
      .WillOnce(::testing::Return(nullptr));
  auto *mocked_http = new common::http::HttpMock();
  auto raw_http = common::http::response_t(
      (new beast::http::response<beast::http::string_body>()));
  EXPECT_CALL(*mocked_http, Post(Eq(token_uri), _, _, Eq("some-ca"), Eq("http://some-proxy-uri.com"), _, _, _))
      .WillOnce(Return(ByMove(std::move(raw_http))));
  OidcFilter filter(common::http::ptr_t(mocked_http), config_, parser_mock_, session_string_generator_mock_,
                    session_store_);
  auto httpRequest =
      request_.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->set_host(callback_host_);
  httpRequest->mutable_headers()->insert({Cookie, expected_session_cookie_name + "=" + session_id});
  std::vector<std::string> parts = {callback_path_, "code=value&state=" + state};
  httpRequest->set_path(absl::StrJoin(parts, "?"));
  auto code = ProcessAndWaitForAsio(filter, &request_, &response_);
  ASSERT_EQ(code, google::rpc::Code::INVALID_ARGUMENT);

  ASSERT_THAT(
      response_.denied_response().headers(),
      ContainsHeaders({
                          {CacheControl, StrEq(CacheControlDirectives::NoCache)},
                          {Pragma, StrEq(PragmaDirectives::NoCache)},
                      })
  );
}

void OidcFilterTest::AssertRequestedUrlAndStateAndNonceHaveBeenStored(absl::string_view session_id,
                                                                      absl::string_view expected_requested_url,
                                                                      absl::string_view expected_state,
                                                                      absl::string_view expected_nonce) {
  auto authorization_state = session_store_->GetAuthorizationState(session_id.data());
  ASSERT_TRUE(authorization_state);

  ASSERT_EQ(authorization_state->GetRequestedUrl(), expected_requested_url.data());
  ASSERT_EQ(authorization_state->GetState(), expected_state.data());
  ASSERT_EQ(authorization_state->GetNonce(), expected_nonce.data());
}

void
OidcFilterTest::MockSessionGenerator(absl::string_view session_id, absl::string_view state, absl::string_view nonce) {
  EXPECT_CALL(*session_string_generator_mock_, GenerateSessionId()).WillOnce(Return(session_id.data()));
  EXPECT_CALL(*session_string_generator_mock_, GenerateState()).WillOnce(Return(state.data()));
  EXPECT_CALL(*session_string_generator_mock_, GenerateNonce()).WillOnce(Return(nonce.data()));
}

void OidcFilterTest::SetExpiredAccessTokenResponseInSessionStore() {
  TokenResponse expired_token_response(test_id_token_jwt_); // id token, not expired
  expired_token_response.SetAccessTokenExpiry(1); // access token already expired
  expired_token_response.SetAccessToken("fake_access_token");
  expired_token_response.SetRefreshToken("fake_refresh_token");
  session_store_->SetTokenResponse("session123", std::make_shared<TokenResponse>(expired_token_response));
}

void OidcFilterTest::EnableAccessTokens(config::oidc::OIDCConfig &oidcConfig) {
  oidcConfig.mutable_access_token()->set_header("access_token");
}

void OidcFilterTest::AssertSessionErrorResponse(google::rpc::Code status) {
  ASSERT_EQ(status, google::rpc::Code::UNAUTHENTICATED);
  ASSERT_EQ(response_.denied_response().status().code(), ::envoy::type::StatusCode::Unauthorized);
  ASSERT_EQ(response_.denied_response().body(),
            "There was an error accessing your session data. Try again later.");
}

void OidcFilterTest::AssertRetrieveToken(config::oidc::OIDCConfig &oidcConfig, std::string callback_host_on_request) {
  std::string session_id = "session123";
  std::string state = "expectedstate";
  std::string nonce = "expectednonce";
  std::string requested_url = "https://example.com/summary";
  auto authorization_state = std::make_shared<AuthorizationState>(state, nonce, requested_url);
  session_store_->SetAuthorizationState(session_id, authorization_state);

  EXPECT_CALL(*parser_mock_, Parse(oidcConfig.client_id(), nonce, ::testing::_))
      .WillOnce(::testing::Return(test_token_response_));
  auto mocked_http = new common::http::HttpMock();
  auto raw_http = common::http::response_t(
      new beast::http::response<beast::http::string_body>());
  raw_http->result(beast::http::status::ok);
  EXPECT_CALL(*mocked_http, Post(Eq(token_uri), _, _, Eq("some-ca"), Eq("http://some-proxy-uri.com"), _, _, _))
      .WillOnce(Return(ByMove(std::move(raw_http))));
  OidcFilter filter(common::http::ptr_t(mocked_http), oidcConfig, parser_mock_, session_string_generator_mock_,
                    session_store_);
  auto httpRequest = request_.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->set_host(callback_host_on_request);
  httpRequest->mutable_headers()->insert({Cookie, expected_session_cookie_name + "=" + session_id});
  std::vector<std::string> parts = {callback_path_, "code=value&state=" + state};
  httpRequest->set_path(absl::StrJoin(parts, "?"));

  auto code = ProcessAndWaitForAsio(filter, &request_, &response_);
  ASSERT_EQ(code, google::rpc::Code::UNAUTHENTICATED);

  auto stored_token_response = session_store_->GetTokenResponse(session_id);
  ASSERT_TRUE(stored_token_response);
  ASSERT_EQ(stored_token_response->IDToken().jwt_, test_id_token_jwt_string_);
  ASSERT_EQ(stored_token_response->AccessToken(), "expected_access_token");
  ASSERT_EQ(stored_token_response->GetAccessTokenExpiry(), 10000000000);

  ASSERT_FALSE(session_store_->GetAuthorizationState(session_id));

  ASSERT_THAT(
      response_.denied_response().headers(),
      ContainsHeaders({
                          {Location, StartsWith(requested_url)},
                          {CacheControl, StrEq(CacheControlDirectives::NoCache)},
                          {Pragma, StrEq(PragmaDirectives::NoCache)},
                      })
  );
}

}  // namespace oidc
}  // namespace filters
}  // namespace authservice
