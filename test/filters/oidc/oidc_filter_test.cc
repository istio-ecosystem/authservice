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

::testing::internal::UnorderedElementsAreArrayMatcher<::testing::Matcher<envoy::api::v2::core::HeaderValueOption>> ContainsHeaders(std::vector<std::pair<std::string, ::testing::Matcher<std::string>>> headers) {
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

class OidcFilterTest : public ::testing::Test {
 protected:
  authservice::config::oidc::OIDCConfig config_;

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
  }
};

TEST_F(OidcFilterTest, Constructor) {
  auto parser_mock = std::make_shared<TokenResponseParserMock>();
  auto cryptor_mock = std::make_shared<common::session::TokenEncryptorMock>();
  OidcFilter filter(common::http::ptr_t(), config_, parser_mock, cryptor_mock);
}

TEST_F(OidcFilterTest, Name) {
  auto parser_mock = std::make_shared<TokenResponseParserMock>();
  auto cryptor_mock = std::make_shared<common::session::TokenEncryptorMock>();
  OidcFilter filter(common::http::ptr_t(), config_, parser_mock, cryptor_mock);
  ASSERT_EQ(filter.Name().compare("oidc"), 0);
}

TEST_F(OidcFilterTest, GetStateCookieName) {
  auto parser_mock = std::make_shared<TokenResponseParserMock>();
  auto cryptor_mock = std::make_shared<common::session::TokenEncryptorMock>();

  config_.clear_cookie_name_prefix();
  OidcFilter filter1(common::http::ptr_t(), config_, parser_mock, cryptor_mock);
  ASSERT_EQ(filter1.GetStateCookieName(), "__Host-authservice-state-cookie");

  config_.set_cookie_name_prefix("my-prefix");
  OidcFilter filter2(common::http::ptr_t(), config_, parser_mock, cryptor_mock);
  ASSERT_EQ(filter2.GetStateCookieName(),
            "__Host-my-prefix-authservice-state-cookie");
}

TEST_F(OidcFilterTest, GetIdTokenCookieName) {
  auto parser_mock = std::make_shared<TokenResponseParserMock>();
  auto cryptor_mock = std::make_shared<common::session::TokenEncryptorMock>();

  config_.clear_cookie_name_prefix();
  OidcFilter filter1(common::http::ptr_t(), config_, parser_mock, cryptor_mock);
  ASSERT_EQ(filter1.GetIdTokenCookieName(),
            "__Host-authservice-id-token-cookie");

  config_.set_cookie_name_prefix("my-prefix");
  OidcFilter filter2(common::http::ptr_t(), config_, parser_mock, cryptor_mock);
  ASSERT_EQ(filter2.GetIdTokenCookieName(),
            "__Host-my-prefix-authservice-id-token-cookie");
}

TEST_F(OidcFilterTest, GetAccessTokenCookieName) {
  auto parser_mock = std::make_shared<TokenResponseParserMock>();
  auto cryptor_mock = std::make_shared<common::session::TokenEncryptorMock>();

  config_.clear_cookie_name_prefix();
  OidcFilter filter1(common::http::ptr_t(), config_, parser_mock, cryptor_mock);
  ASSERT_EQ(filter1.GetAccessTokenCookieName(),
            "__Host-authservice-access-token-cookie");

  config_.set_cookie_name_prefix("my-prefix");
  OidcFilter filter2(common::http::ptr_t(), config_, parser_mock, cryptor_mock);
  ASSERT_EQ(filter2.GetAccessTokenCookieName(),
            "__Host-my-prefix-authservice-access-token-cookie");
}

TEST_F(OidcFilterTest, NoHttpHeader) {
  auto parser_mock = std::make_shared<TokenResponseParserMock>();
  auto cryptor_mock = std::make_shared<common::session::TokenEncryptorMock>();
  OidcFilter filter(common::http::ptr_t(), config_, parser_mock, cryptor_mock);

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
  auto parser_mock = std::make_shared<TokenResponseParserMock>();
  auto cryptor_mock = std::make_shared<common::session::TokenEncryptorMock>();
  EXPECT_CALL(*cryptor_mock, Encrypt(_))
      .WillOnce(Return("encrypted"));
  OidcFilter filter(common::http::ptr_t(), config_, parser_mock, cryptor_mock);
  ::envoy::service::auth::v2::CheckRequest request;
  ::envoy::service::auth::v2::CheckResponse response;
  auto httpRequest =
      request.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->set_scheme("https");
  auto status = filter.Process(&request, &response);
  ASSERT_EQ(status, google::rpc::Code::UNAUTHENTICATED);
  ASSERT_EQ(response.denied_response().status().code(),
            ::envoy::type::StatusCode::Found);
  ASSERT_EQ(response.denied_response().headers().size(), 4);

  for (const auto& iter : response.denied_response().headers()) {
    if (iter.header().key() == common::http::headers::Location) {
      std::regex re(
          "^https://acme-idp\\.tld/"
          "authorization\\?client_id=example-app&nonce=[A-Za-z0-9_-]{43}&"
          "redirect_uri=https%3A%2F%2Fme\\.tld%2Fcallback&response_type=code&"
          "scope=openid&state=[A-Za-z0-9_-]{43}$");
      ASSERT_TRUE(std::regex_match(iter.header().value(), re));
    } else if (iter.header().key() == common::http::headers::CacheControl) {
      ASSERT_EQ(iter.header().value(),
                common::http::headers::CacheControlDirectives::NoCache);
    } else if (iter.header().key() == common::http::headers::Pragma) {
      ASSERT_EQ(iter.header().value(),
                common::http::headers::PragmaDirectives::NoCache);
    } else if (iter.header().key() == common::http::headers::SetCookie) {
      ASSERT_EQ(iter.header().value(),
                "__Host-cookie-prefix-authservice-state-cookie=encrypted; "
                "HttpOnly; Max-Age=300; Path=/; "
                "SameSite=Lax; Secure");
    } else {
      FAIL();  // Unexpected header!
    }
  }
}

TEST_F(OidcFilterTest, InvalidCookies) {
  auto parser_mock = std::make_shared<TokenResponseParserMock>();
  auto cryptor_mock = std::make_shared<common::session::TokenEncryptorMock>();
  EXPECT_CALL(*cryptor_mock, Encrypt(_))
      .WillOnce(Return("encrypted"));
  OidcFilter filter(common::http::ptr_t(), config_, parser_mock, cryptor_mock);
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
  ASSERT_EQ(response.denied_response().headers().size(), 4);

  for (const auto& iter : response.denied_response().headers()) {
    if (iter.header().key() == common::http::headers::Location) {
      ASSERT_EQ(iter.header().value().find(
                    common::http::http::ToUrl(config_.authorization())),
                0);
    } else if (iter.header().key() == common::http::headers::CacheControl) {
      ASSERT_EQ(iter.header().value(),
                common::http::headers::CacheControlDirectives::NoCache);
    } else if (iter.header().key() == common::http::headers::Pragma) {
      ASSERT_EQ(iter.header().value(),
                common::http::headers::PragmaDirectives::NoCache);
    } else if (iter.header().key() == common::http::headers::SetCookie) {
      ASSERT_EQ(iter.header().value(),
                "__Host-cookie-prefix-authservice-state-cookie=encrypted; "
                "HttpOnly; Max-Age=300; Path=/; "
                "SameSite=Lax; Secure");
    } else {
      FAIL();  // Unexpected header!
    }
  }
}

TEST_F(OidcFilterTest, InvalidIdToken) {
  auto parser_mock = std::make_shared<TokenResponseParserMock>();
  auto cryptor_mock = std::make_shared<common::session::TokenEncryptorMock>();
  EXPECT_CALL(*cryptor_mock, Encrypt(_))
      .WillOnce(Return("encrypted"));
  OidcFilter filter(common::http::ptr_t(), config_, parser_mock, cryptor_mock);
  ::envoy::service::auth::v2::CheckRequest request;
  ::envoy::service::auth::v2::CheckResponse response;
  auto httpRequest =
      request.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->set_scheme("https");
  httpRequest->mutable_headers()->insert(
      {common::http::headers::Cookie,
       "__Host-cookie-prefix-authservice-id-token-cookie=invalid"});
  EXPECT_CALL(*cryptor_mock, Decrypt("invalid"))
      .WillOnce(Return(absl::nullopt));

  auto status = filter.Process(&request, &response);
  // We expect to be redirected to authenticate
  ASSERT_EQ(status, google::rpc::Code::UNAUTHENTICATED);
  ASSERT_EQ(response.denied_response().headers().size(), 4);

  for (const auto& iter : response.denied_response().headers()) {
    if (iter.header().key() == common::http::headers::Location) {
      ASSERT_EQ(iter.header().value().find(
                    common::http::http::ToUrl(config_.authorization())),
                0);
    } else if (iter.header().key() == common::http::headers::CacheControl) {
      ASSERT_EQ(iter.header().value(),
                common::http::headers::CacheControlDirectives::NoCache);
    } else if (iter.header().key() == common::http::headers::Pragma) {
      ASSERT_EQ(iter.header().value(),
                common::http::headers::PragmaDirectives::NoCache);
    } else if (iter.header().key() == common::http::headers::SetCookie) {
      ASSERT_EQ(iter.header().value(),
                "__Host-cookie-prefix-authservice-state-cookie=encrypted; "
                "HttpOnly; Max-Age=300; Path=/; "
                "SameSite=Lax; Secure");
    } else {
      FAIL();  // Unexpected header!
    }
  }
}

TEST_F(OidcFilterTest, ValidIdToken) {
  auto parser_mock = std::make_shared<TokenResponseParserMock>();
  auto cryptor_mock = std::make_shared<common::session::TokenEncryptorMock>();
  OidcFilter filter(common::http::ptr_t(), config_, parser_mock, cryptor_mock);
  ::envoy::service::auth::v2::CheckRequest request;
  ::envoy::service::auth::v2::CheckResponse response;
  auto httpRequest =
      request.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->set_scheme("https");
  httpRequest->mutable_headers()->insert(
      {common::http::headers::Cookie,
       "__Host-cookie-prefix-authservice-id-token-cookie=valid"});
  EXPECT_CALL(*cryptor_mock, Decrypt("valid"))
      .WillOnce(Return(absl::optional<std::string>("secret")));

  auto status = filter.Process(&request, &response);
  ASSERT_EQ(status, google::rpc::Code::OK);
  ASSERT_EQ(response.ok_response().headers().size(), 1);
  ASSERT_STREQ(common::http::headers::Authorization,
               response.ok_response().headers()[0].header().key().c_str());
  ASSERT_STREQ("Bearer secret",
               response.ok_response().headers()[0].header().value().c_str());
}

TEST_F(OidcFilterTest, MissingAccessToken) {
  config_.mutable_access_token()->set_header("access_token");
  auto parser_mock = std::make_shared<TokenResponseParserMock>();
  auto cryptor_mock = std::make_shared<common::session::TokenEncryptorMock>();
  EXPECT_CALL(*cryptor_mock, Encrypt(_))
      .WillOnce(Return("encrypted"));
  OidcFilter filter(common::http::ptr_t(), config_, parser_mock, cryptor_mock);
  ::envoy::service::auth::v2::CheckRequest request;
  ::envoy::service::auth::v2::CheckResponse response;
  auto httpRequest =
      request.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->set_scheme("https");
  httpRequest->mutable_headers()->insert(
      {common::http::headers::Cookie,
       "__Host-cookie-prefix-authservice-id-token-cookie=valid"});
  EXPECT_CALL(*cryptor_mock, Decrypt("valid"))
      .WillOnce(Return(absl::optional<std::string>("secret")));

  auto status = filter.Process(&request, &response);
  // We expect to be redirected to authenticate
  ASSERT_EQ(status, google::rpc::Code::UNAUTHENTICATED);
  ASSERT_EQ(response.denied_response().headers().size(), 4);

  for (const auto& iter : response.denied_response().headers()) {
    if (iter.header().key() == common::http::headers::Location) {
      ASSERT_EQ(iter.header().value().find(
                    common::http::http::ToUrl(config_.authorization())),
                0);
    } else if (iter.header().key() == common::http::headers::CacheControl) {
      ASSERT_EQ(iter.header().value(),
                common::http::headers::CacheControlDirectives::NoCache);
    } else if (iter.header().key() == common::http::headers::Pragma) {
      ASSERT_EQ(iter.header().value(),
                common::http::headers::PragmaDirectives::NoCache);
    } else if (iter.header().key() == common::http::headers::SetCookie) {
      ASSERT_EQ(iter.header().value(),
                "__Host-cookie-prefix-authservice-state-cookie=encrypted; "
                "HttpOnly; Max-Age=300; Path=/; "
                "SameSite=Lax; Secure");
    } else {
      FAIL();  // Unexpected header!
    }
  }
}

TEST_F(OidcFilterTest, InvalidAccessToken) {
  config_.mutable_access_token()->set_header("access_token");
  auto parser_mock = std::make_shared<TokenResponseParserMock>();
  auto cryptor_mock = std::make_shared<common::session::TokenEncryptorMock>();
  EXPECT_CALL(*cryptor_mock, Encrypt(_))
      .WillOnce(Return("encrypted"));
  OidcFilter filter(common::http::ptr_t(), config_, parser_mock, cryptor_mock);
  ::envoy::service::auth::v2::CheckRequest request;
  ::envoy::service::auth::v2::CheckResponse response;
  auto httpRequest =
      request.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->set_scheme("https");
  httpRequest->mutable_headers()->insert(
      {common::http::headers::Cookie,
       "__Host-cookie-prefix-authservice-id-token-cookie=valid; "
       "__Host-cookie-prefix-authservice-access-token-cookie=invalid"});
  EXPECT_CALL(*cryptor_mock, Decrypt("valid"))
      .WillOnce(Return(absl::optional<std::string>("secret")));
  EXPECT_CALL(*cryptor_mock, Decrypt("invalid"))
      .WillOnce(Return(absl::nullopt));

  auto status = filter.Process(&request, &response);
  // We expect to be redirected to authenticate
  ASSERT_EQ(status, google::rpc::Code::UNAUTHENTICATED);
  ASSERT_EQ(response.denied_response().headers().size(), 4);

  for (const auto& iter : response.denied_response().headers()) {
    if (iter.header().key() == common::http::headers::Location) {
      ASSERT_EQ(iter.header().value().find(
                    common::http::http::ToUrl(config_.authorization())),
                0);
    } else if (iter.header().key() == common::http::headers::CacheControl) {
      ASSERT_EQ(iter.header().value(),
                common::http::headers::CacheControlDirectives::NoCache);
    } else if (iter.header().key() == common::http::headers::Pragma) {
      ASSERT_EQ(iter.header().value(),
                common::http::headers::PragmaDirectives::NoCache);
    } else if (iter.header().key() == common::http::headers::SetCookie) {
      ASSERT_EQ(iter.header().value(),
                "__Host-cookie-prefix-authservice-state-cookie=encrypted; "
                "HttpOnly; Max-Age=300; Path=/; "
                "SameSite=Lax; Secure");
    } else {
      FAIL();  // Unexpected header!
    }
  }
}

TEST_F(OidcFilterTest, ValidIdAndAccessTokens) {
  config_.mutable_access_token()->set_header("access_token");
  auto parser_mock = std::make_shared<TokenResponseParserMock>();
  auto cryptor_mock = std::make_shared<common::session::TokenEncryptorMock>();
  OidcFilter filter(common::http::ptr_t(), config_, parser_mock, cryptor_mock);
  ::envoy::service::auth::v2::CheckRequest request;
  ::envoy::service::auth::v2::CheckResponse response;
  auto httpRequest =
      request.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->set_scheme("https");
  httpRequest->mutable_headers()->insert(
      {common::http::headers::Cookie,
       "__Host-cookie-prefix-authservice-id-token-cookie=identity; "
       "__Host-cookie-prefix-authservice-access-token-cookie=access"});
  EXPECT_CALL(*cryptor_mock, Decrypt("identity"))
      .WillOnce(Return(absl::optional<std::string>("id_secret")));
  EXPECT_CALL(*cryptor_mock, Decrypt("access"))
      .WillOnce(
          Return(absl::optional<std::string>("access_secret")));

  auto status = filter.Process(&request, &response);
  ASSERT_EQ(status, google::rpc::Code::OK);
  ASSERT_EQ(response.ok_response().headers().size(), 2);
  ASSERT_STREQ(common::http::headers::Authorization,
               response.ok_response().headers()[0].header().key().c_str());
  ASSERT_STREQ("Bearer id_secret",
               response.ok_response().headers()[0].header().value().c_str());
  ASSERT_STREQ("access_token",
               response.ok_response().headers()[1].header().key().c_str());
  ASSERT_STREQ("access_secret",
               response.ok_response().headers()[1].header().value().c_str());
}

TEST_F(OidcFilterTest, RetrieveTokenWithOutAccessToken) {
  google::jwt_verify::Jwt jwt = {};
  auto parser_mock = std::make_shared<TokenResponseParserMock>();
  auto cryptor_mock = std::make_shared<common::session::TokenEncryptorMock>();
  auto token_response = absl::make_optional<TokenResponse>(jwt);
  token_response->SetAccessToken("expected_access_token");
  EXPECT_CALL(*parser_mock, Parse(config_.client_id(), ::testing::_, ::testing::_))
      .WillOnce(::testing::Return(token_response));
  auto mocked_http = new common::http::http_mock();
  auto raw_http = common::http::response_t(
      new beast::http::response<beast::http::string_body>());
  raw_http->result(beast::http::status::ok);
  EXPECT_CALL(*mocked_http, Post(_, _, _, _, _))
      .WillOnce(Return(ByMove(std::move(raw_http))));
  OidcFilter filter(common::http::ptr_t(mocked_http), config_, parser_mock,
                    cryptor_mock);
  ::envoy::service::auth::v2::CheckRequest request;
  ::envoy::service::auth::v2::CheckResponse response;
  auto httpRequest =
      request.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->set_scheme(
      "");  // Seems like it should be "https", but in practice is empty
  httpRequest->set_host(config_.callback().hostname());
  httpRequest->mutable_headers()->insert(
      {common::http::headers::Cookie,
       "__Host-cookie-prefix-authservice-state-cookie=valid"});
  EXPECT_CALL(*cryptor_mock, Decrypt("valid"))
      .WillOnce(Return(
          absl::optional<std::string>("expectedstate;expectednonce")));
  EXPECT_CALL(*cryptor_mock, Encrypt(_))
      .WillOnce(Return("encryptedtoken"));
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
      {common::http::headers::SetCookie,
        AnyOf(
          MatchesRegex("^__Host-cookie-prefix-authservice-id-token-"
                       "cookie=encryptedtoken; HttpOnly; Max-Age=[0-9]+; "
                       "Path=/; SameSite=Lax; Secure$"),
          StrEq("__Host-cookie-prefix-authservice-state-cookie=deleted; "
                "HttpOnly; Max-Age=0; Path=/; SameSite=Lax; "
                "Secure")
        )
      }}
    )
  );
}

TEST_F(OidcFilterTest, RetrieveTokenWithAccessToken) {
  config_.mutable_access_token()->set_header("access_token");
  google::jwt_verify::Jwt jwt = {};
  auto parser_mock = std::make_shared<TokenResponseParserMock>();
  auto cryptor_mock = std::make_shared<common::session::TokenEncryptorMock>();
  auto token_response = absl::make_optional<TokenResponse>(jwt);
  token_response->SetAccessToken("expected_access_token");
  EXPECT_CALL(*parser_mock, Parse(config_.client_id(), ::testing::_, ::testing::_))
      .WillOnce(::testing::Return(token_response));
  auto mocked_http = new common::http::http_mock();
  auto raw_http = common::http::response_t(
      new beast::http::response<beast::http::string_body>());
  raw_http->result(beast::http::status::ok);
  EXPECT_CALL(*mocked_http, Post(_, _, _, _, _))
      .WillOnce(Return(ByMove(std::move(raw_http))));
  OidcFilter filter(common::http::ptr_t(mocked_http), config_, parser_mock,
                    cryptor_mock);
  ::envoy::service::auth::v2::CheckRequest request;
  ::envoy::service::auth::v2::CheckResponse response;
  auto httpRequest =
      request.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->set_scheme(
      "");  // Seems like it should be "https", but in practice is empty
  httpRequest->set_host(config_.callback().hostname());
  httpRequest->mutable_headers()->insert(
      {common::http::headers::Cookie,
       "__Host-cookie-prefix-authservice-state-cookie=valid"});
  EXPECT_CALL(*cryptor_mock, Decrypt("valid"))
      .WillOnce(Return(
          absl::optional<std::string>("expectedstate;expectednonce")));
  EXPECT_CALL(*cryptor_mock, Encrypt(_))
      .Times(2)
      .WillRepeatedly(Return("encryptedtoken"));
  std::vector<absl::string_view> parts = {config_.callback().path().c_str(),
                                          "code=value&state=expectedstate"};
  httpRequest->set_path(absl::StrJoin(parts, "?"));
  auto code = filter.Process(&request, &response);
  ASSERT_EQ(code, google::rpc::Code::UNAUTHENTICATED);

  ASSERT_EQ(response.denied_response().headers().size(), 6);

  for (const auto& iter : response.denied_response().headers()) {
    if (iter.header().key() == common::http::headers::Location) {
      ASSERT_EQ(iter.header().value().find(config_.landing_page()), 0);
    } else if (iter.header().key() == common::http::headers::CacheControl) {
      ASSERT_EQ(iter.header().value(),
                common::http::headers::CacheControlDirectives::NoCache);
    } else if (iter.header().key() == common::http::headers::Pragma) {
      ASSERT_EQ(iter.header().value(),
                common::http::headers::PragmaDirectives::NoCache);
    } else if (iter.header().key() == common::http::headers::SetCookie) {
      std::regex id_re("^__Host-cookie-prefix-authservice-id-token-"
                    "cookie=encryptedtoken; HttpOnly; Max-Age=[0-9]+; "
                    "Path=/; SameSite=Lax; Secure$");
      std::regex access_re("^__Host-cookie-prefix-authservice-access-token-"
                       "cookie=encryptedtoken; HttpOnly; Max-Age=[0-9]+; "
                       "Path=/; SameSite=Lax; Secure$");
      ASSERT_TRUE(std::regex_match(iter.header().value(), id_re) || std::regex_match(iter.header().value(), access_re) ||
                  (iter.header().value() ==
                   "__Host-cookie-prefix-authservice-state-cookie=deleted; "
                   "HttpOnly; Max-Age=0; Path=/; SameSite=Lax; "
                   "Secure"));
    } else {
      FAIL();  // Unexpected header!
    }
  }
}

TEST_F(OidcFilterTest, RetrieveTokenMissingAccessToken) {
  config_.mutable_access_token()->set_header("access_token");
  google::jwt_verify::Jwt jwt = {};
  auto parser_mock = std::make_shared<TokenResponseParserMock>();
  auto cryptor_mock = std::make_shared<common::session::TokenEncryptorMock>();
  auto token_response = absl::make_optional<TokenResponse>(jwt);
  EXPECT_CALL(*parser_mock, Parse(config_.client_id(), ::testing::_, ::testing::_))
      .WillOnce(::testing::Return(token_response));
  auto mocked_http = new common::http::http_mock();
  auto raw_http = common::http::response_t(
      new beast::http::response<beast::http::string_body>());
  raw_http->result(beast::http::status::ok);
  EXPECT_CALL(*mocked_http, Post(_, _, _, _, _))
      .WillOnce(Return(ByMove(std::move(raw_http))));
  OidcFilter filter(common::http::ptr_t(mocked_http), config_, parser_mock,
                    cryptor_mock);
  ::envoy::service::auth::v2::CheckRequest request;
  ::envoy::service::auth::v2::CheckResponse response;
  auto httpRequest =
      request.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->set_scheme(
      "");  // Seems like it should be "https", but in practice is empty
  httpRequest->set_host(config_.callback().hostname());
  httpRequest->mutable_headers()->insert(
      {common::http::headers::Cookie,
       "__Host-cookie-prefix-authservice-state-cookie=valid"});
  EXPECT_CALL(*cryptor_mock, Decrypt("valid"))
      .WillOnce(Return(
          absl::optional<std::string>("expectedstate;expectednonce")));
  EXPECT_CALL(*cryptor_mock, Encrypt(_)).Times(0);
  std::vector<absl::string_view> parts = {config_.callback().path().c_str(),
                                          "code=value&state=expectedstate"};
  httpRequest->set_path(absl::StrJoin(parts, "?"));
  auto code = filter.Process(&request, &response);
  ASSERT_EQ(code, google::rpc::Code::INVALID_ARGUMENT);

  ASSERT_EQ(response.denied_response().headers().size(), 3);

  for (const auto& iter : response.denied_response().headers()) {
    if (iter.header().key() == common::http::headers::CacheControl) {
      ASSERT_EQ(iter.header().value(),
                common::http::headers::CacheControlDirectives::NoCache);
    } else if (iter.header().key() == common::http::headers::Pragma) {
      ASSERT_EQ(iter.header().value(),
                common::http::headers::PragmaDirectives::NoCache);
    } else if (iter.header().key() == common::http::headers::SetCookie) {
      ASSERT_EQ(iter.header().value(),
                "__Host-cookie-prefix-authservice-state-cookie=deleted; "
                "HttpOnly; Max-Age=0; Path=/; "
                "SameSite=Lax; Secure");
    } else {
      auto val = iter.header().value();
      std::cerr << val << std::endl;
      FAIL();  // Unexpected header!
    }
  }
}

TEST_F(OidcFilterTest, RetrieveTokenMissingStateCookie) {
  auto parser_mock = std::make_shared<TokenResponseParserMock>();
  auto cryptor_mock = std::make_shared<common::session::TokenEncryptorMock>();
  auto mocked_http = new common::http::http_mock();
  OidcFilter filter(common::http::ptr_t(mocked_http), config_, parser_mock,
                    cryptor_mock);
  ::envoy::service::auth::v2::CheckRequest request;
  ::envoy::service::auth::v2::CheckResponse response;
  auto httpRequest =
      request.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->set_scheme("https");
  httpRequest->set_host(config_.callback().hostname());
  std::vector<absl::string_view> parts = {config_.callback().path().c_str(),
                                          "code=value&state=expectedstate"};
  httpRequest->set_path(absl::StrJoin(parts, "?"));
  auto code = filter.Process(&request, &response);
  ASSERT_EQ(code, google::rpc::Code::INVALID_ARGUMENT);

  ASSERT_EQ(response.denied_response().headers().size(), 3);

  for (const auto& iter : response.denied_response().headers()) {
    if (iter.header().key() == common::http::headers::CacheControl) {
      ASSERT_EQ(iter.header().value(),
                common::http::headers::CacheControlDirectives::NoCache);
    } else if (iter.header().key() == common::http::headers::Pragma) {
      ASSERT_EQ(iter.header().value(),
                common::http::headers::PragmaDirectives::NoCache);
    } else if (iter.header().key() == common::http::headers::SetCookie) {
      ASSERT_EQ(iter.header().value(),
                "__Host-cookie-prefix-authservice-state-cookie=deleted; "
                "HttpOnly; Max-Age=0; Path=/; "
                "SameSite=Lax; Secure");
    } else {
      FAIL();  // Unexpected header!
    }
  }
}

TEST_F(OidcFilterTest, RetrieveTokenInvalidStateCookie) {
  auto parser_mock = std::make_shared<TokenResponseParserMock>();
  auto cryptor_mock = std::make_shared<common::session::TokenEncryptorMock>();
  auto mocked_http = new common::http::http_mock();
  OidcFilter filter(common::http::ptr_t(mocked_http), config_, parser_mock,
                    cryptor_mock);
  ::envoy::service::auth::v2::CheckRequest request;
  ::envoy::service::auth::v2::CheckResponse response;
  auto httpRequest =
      request.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->set_scheme("https");
  httpRequest->set_host(config_.callback().hostname());
  httpRequest->mutable_headers()->insert(
      {common::http::headers::Cookie,
       "__Host-cookie-prefix-authservice-state-cookie=invalid"});
  EXPECT_CALL(*cryptor_mock, Decrypt("invalid"))
      .WillOnce(Return(absl::nullopt));
  std::vector<absl::string_view> parts = {config_.callback().path().c_str(),
                                          "code=value&state=expectedstate"};
  httpRequest->set_path(absl::StrJoin(parts, "?"));
  auto code = filter.Process(&request, &response);
  ASSERT_EQ(code, google::rpc::Code::INVALID_ARGUMENT);

  ASSERT_EQ(response.denied_response().headers().size(), 3);

  for (const auto& iter : response.denied_response().headers()) {
    if (iter.header().key() == common::http::headers::CacheControl) {
      ASSERT_EQ(iter.header().value(),
                common::http::headers::CacheControlDirectives::NoCache);
    } else if (iter.header().key() == common::http::headers::Pragma) {
      ASSERT_EQ(iter.header().value(),
                common::http::headers::PragmaDirectives::NoCache);
    } else if (iter.header().key() == common::http::headers::SetCookie) {
      ASSERT_EQ(iter.header().value(),
                "__Host-cookie-prefix-authservice-state-cookie=deleted; "
                "HttpOnly; Max-Age=0; Path=/; "
                "SameSite=Lax; Secure");
    } else {
      FAIL();  // Unexpected header!
    }
  }
}

TEST_F(OidcFilterTest, RetrieveTokenInvalidStateCookieFormat) {
  auto parser_mock = std::make_shared<TokenResponseParserMock>();
  auto cryptor_mock = std::make_shared<common::session::TokenEncryptorMock>();
  auto mocked_http = new common::http::http_mock();
  OidcFilter filter(common::http::ptr_t(mocked_http), config_, parser_mock,
                    cryptor_mock);
  ::envoy::service::auth::v2::CheckRequest request;
  ::envoy::service::auth::v2::CheckResponse response;
  auto httpRequest =
      request.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->set_scheme("https");
  httpRequest->set_host(config_.callback().hostname());
  httpRequest->mutable_headers()->insert(
      {common::http::headers::Cookie,
       "__Host-cookie-prefix-authservice-state-cookie=valid"});
  EXPECT_CALL(*cryptor_mock, Decrypt("valid"))
      .WillOnce(
          Return(absl::optional<std::string>("invalidformat")));
  std::vector<absl::string_view> parts = {config_.callback().path().c_str(),
                                          "code=value&state=expectedstate"};
  httpRequest->set_path(absl::StrJoin(parts, "?"));
  auto code = filter.Process(&request, &response);
  ASSERT_EQ(code, google::rpc::Code::INVALID_ARGUMENT);

  ASSERT_EQ(response.denied_response().headers().size(), 3);

  for (const auto& iter : response.denied_response().headers()) {
    if (iter.header().key() == common::http::headers::CacheControl) {
      ASSERT_EQ(iter.header().value(),
                common::http::headers::CacheControlDirectives::NoCache);
    } else if (iter.header().key() == common::http::headers::Pragma) {
      ASSERT_EQ(iter.header().value(),
                common::http::headers::PragmaDirectives::NoCache);
    } else if (iter.header().key() == common::http::headers::SetCookie) {
      ASSERT_EQ(iter.header().value(),
                "__Host-cookie-prefix-authservice-state-cookie=deleted; "
                "HttpOnly; Max-Age=0; Path=/; "
                "SameSite=Lax; Secure");
    } else {
      FAIL();  // Unexpected header!
    }
  }
}

TEST_F(OidcFilterTest, RetrieveTokenMissingCode) {
  auto parser_mock = std::make_shared<TokenResponseParserMock>();
  auto cryptor_mock = std::make_shared<common::session::TokenEncryptorMock>();
  OidcFilter filter(common::http::ptr_t(), config_, parser_mock, cryptor_mock);
  ::envoy::service::auth::v2::CheckRequest request;
  ::envoy::service::auth::v2::CheckResponse response;
  auto httpRequest =
      request.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->set_scheme("https");
  httpRequest->set_host(config_.callback().hostname());
  httpRequest->set_path(config_.callback().path());
  std::vector<absl::string_view> parts = {config_.callback().path().c_str(),
                                          "key=value&state=expectedstate"};
  httpRequest->set_path(absl::StrJoin(parts, "?"));
  auto code = filter.Process(&request, &response);
  ASSERT_EQ(code, google::rpc::Code::INVALID_ARGUMENT);

  ASSERT_EQ(response.denied_response().headers().size(), 3);

  for (const auto& iter : response.denied_response().headers()) {
    if (iter.header().key() == common::http::headers::CacheControl) {
      ASSERT_EQ(iter.header().value(),
                common::http::headers::CacheControlDirectives::NoCache);
    } else if (iter.header().key() == common::http::headers::Pragma) {
      ASSERT_EQ(iter.header().value(),
                common::http::headers::PragmaDirectives::NoCache);
    } else if (iter.header().key() == common::http::headers::SetCookie) {
      ASSERT_EQ(iter.header().value(),
                "__Host-cookie-prefix-authservice-state-cookie=deleted; "
                "HttpOnly; Max-Age=0; Path=/; "
                "SameSite=Lax; Secure");
    } else {
      FAIL();  // Unexpected header!
    }
  }
}

TEST_F(OidcFilterTest, RetrieveTokenMissingState) {
  auto parser_mock = std::make_shared<TokenResponseParserMock>();
  auto cryptor_mock = std::make_shared<common::session::TokenEncryptorMock>();
  OidcFilter filter(common::http::ptr_t(), config_, parser_mock, cryptor_mock);
  ::envoy::service::auth::v2::CheckRequest request;
  ::envoy::service::auth::v2::CheckResponse response;
  auto httpRequest =
      request.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->set_scheme("https");
  httpRequest->set_host(config_.callback().hostname());
  httpRequest->set_path(config_.callback().path());
  std::vector<absl::string_view> parts = {config_.callback().path().c_str(),
                                          "code=value"};
  httpRequest->set_path(absl::StrJoin(parts, "?"));
  auto code = filter.Process(&request, &response);
  ASSERT_EQ(code, google::rpc::Code::INVALID_ARGUMENT);

  ASSERT_EQ(response.denied_response().headers().size(), 3);

  for (const auto& iter : response.denied_response().headers()) {
    if (iter.header().key() == common::http::headers::CacheControl) {
      ASSERT_EQ(iter.header().value(),
                common::http::headers::CacheControlDirectives::NoCache);
    } else if (iter.header().key() == common::http::headers::Pragma) {
      ASSERT_EQ(iter.header().value(),
                common::http::headers::PragmaDirectives::NoCache);
    } else if (iter.header().key() == common::http::headers::SetCookie) {
      ASSERT_EQ(iter.header().value(),
                "__Host-cookie-prefix-authservice-state-cookie=deleted; "
                "HttpOnly; Max-Age=0; Path=/; "
                "SameSite=Lax; Secure");
    } else {
      FAIL();  // Unexpected header!
    }
  }
}

TEST_F(OidcFilterTest, RetrieveTokenUnexpectedState) {
  auto parser_mock = std::make_shared<TokenResponseParserMock>();
  auto cryptor_mock = std::make_shared<common::session::TokenEncryptorMock>();
  OidcFilter filter(common::http::ptr_t(), config_, parser_mock, cryptor_mock);
  ::envoy::service::auth::v2::CheckRequest request;
  ::envoy::service::auth::v2::CheckResponse response;
  auto httpRequest =
      request.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->set_scheme("https");
  httpRequest->set_host(config_.callback().hostname());
  httpRequest->set_path(config_.callback().path());
  std::vector<absl::string_view> parts = {config_.callback().path().c_str(),
                                          "code=value&state=unexpectedstate"};
  httpRequest->set_path(absl::StrJoin(parts, "?"));
  auto code = filter.Process(&request, &response);
  ASSERT_EQ(code, google::rpc::Code::INVALID_ARGUMENT);

  ASSERT_EQ(response.denied_response().headers().size(), 3);

  for (const auto& iter : response.denied_response().headers()) {
    if (iter.header().key() == common::http::headers::CacheControl) {
      ASSERT_EQ(iter.header().value(),
                common::http::headers::CacheControlDirectives::NoCache);
    } else if (iter.header().key() == common::http::headers::Pragma) {
      ASSERT_EQ(iter.header().value(),
                common::http::headers::PragmaDirectives::NoCache);
    } else if (iter.header().key() == common::http::headers::SetCookie) {
      ASSERT_EQ(iter.header().value(),
                "__Host-cookie-prefix-authservice-state-cookie=deleted; "
                "HttpOnly; Max-Age=0; Path=/; "
                "SameSite=Lax; Secure");
    } else {
      FAIL();  // Unexpected header!
    }
  }
}

TEST_F(OidcFilterTest, RetrieveTokenBrokenPipe) {
  auto parser_mock = std::make_shared<TokenResponseParserMock>();
  auto cryptor_mock = std::make_shared<common::session::TokenEncryptorMock>();
  auto *http_mock = new common::http::http_mock();
  auto raw_http = common::http::response_t();
  EXPECT_CALL(*http_mock, Post(_, _, _, _, _))
      .WillOnce(Return(ByMove(std::move(raw_http))));
  OidcFilter filter(common::http::ptr_t(http_mock), config_, parser_mock,
                    cryptor_mock);
  ::envoy::service::auth::v2::CheckRequest request;
  ::envoy::service::auth::v2::CheckResponse response;
  auto httpRequest =
      request.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->set_scheme("https");
  httpRequest->set_host(config_.callback().hostname());
  httpRequest->set_path(config_.callback().path());
  httpRequest->mutable_headers()->insert(
      {common::http::headers::Cookie,
       "__Host-cookie-prefix-authservice-state-cookie=valid"});
  EXPECT_CALL(*cryptor_mock, Decrypt("valid"))
      .WillOnce(Return(
          absl::optional<std::string>("expectedstate;expectednonce")));
  std::vector<absl::string_view> parts = {config_.callback().path().c_str(),
                                          "code=value&state=expectedstate"};
  httpRequest->set_path(absl::StrJoin(parts, "?"));
  auto code = filter.Process(&request, &response);
  ASSERT_EQ(code, google::rpc::Code::INTERNAL);

  ASSERT_EQ(response.denied_response().headers().size(), 3);

  for (const auto& iter : response.denied_response().headers()) {
    if (iter.header().key() == common::http::headers::CacheControl) {
      ASSERT_EQ(iter.header().value(),
                common::http::headers::CacheControlDirectives::NoCache);
    } else if (iter.header().key() == common::http::headers::Pragma) {
      ASSERT_EQ(iter.header().value(),
                common::http::headers::PragmaDirectives::NoCache);
    } else if (iter.header().key() == common::http::headers::SetCookie) {
      ASSERT_EQ(iter.header().value(),
                "__Host-cookie-prefix-authservice-state-cookie=deleted; "
                "HttpOnly; Max-Age=0; Path=/; "
                "SameSite=Lax; Secure");
    } else {
      FAIL();  // Unexpected header!
    }
  }
}

TEST_F(OidcFilterTest, RetrieveTokenInvalidResponse) {
  auto parser_mock = std::make_shared<TokenResponseParserMock>();
  auto cryptor_mock = std::make_shared<common::session::TokenEncryptorMock>();
  EXPECT_CALL(*parser_mock, Parse(config_.client_id(), ::testing::_, ::testing::_))
      .WillOnce(::testing::Return(absl::nullopt));
  auto *http_mock = new common::http::http_mock();
  auto raw_http = common::http::response_t(
      (new beast::http::response<beast::http::string_body>()));
  EXPECT_CALL(*http_mock, Post(_, _, _, _, _))
      .WillOnce(Return(ByMove(std::move(raw_http))));
  OidcFilter filter(common::http::ptr_t(http_mock), config_, parser_mock,
                    cryptor_mock);
  ::envoy::service::auth::v2::CheckRequest request;
  ::envoy::service::auth::v2::CheckResponse response;
  auto httpRequest =
      request.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->set_scheme("https");
  httpRequest->set_host(config_.callback().hostname());
  httpRequest->set_path(config_.callback().path());
  httpRequest->mutable_headers()->insert(
      {common::http::headers::Cookie,
       "__Host-cookie-prefix-authservice-state-cookie=valid"});
  EXPECT_CALL(*cryptor_mock, Decrypt("valid"))
      .WillOnce(Return(
          absl::optional<std::string>("expectedstate;expectednonce")));
  std::vector<absl::string_view> parts = {config_.callback().path().c_str(),
                                          "code=value&state=expectedstate"};
  httpRequest->set_path(absl::StrJoin(parts, "?"));
  auto code = filter.Process(&request, &response);
  ASSERT_EQ(code, google::rpc::Code::INVALID_ARGUMENT);

  ASSERT_EQ(response.denied_response().headers().size(), 3);

  for (const auto& iter : response.denied_response().headers()) {
    if (iter.header().key() == common::http::headers::CacheControl) {
      ASSERT_EQ(iter.header().value(),
                common::http::headers::CacheControlDirectives::NoCache);
    } else if (iter.header().key() == common::http::headers::Pragma) {
      ASSERT_EQ(iter.header().value(),
                common::http::headers::PragmaDirectives::NoCache);
    } else if (iter.header().key() == common::http::headers::SetCookie) {
      ASSERT_EQ(iter.header().value(),
                "__Host-cookie-prefix-authservice-state-cookie=deleted; "
                "HttpOnly; Max-Age=0; Path=/; "
                "SameSite=Lax; Secure");
    } else {
      FAIL();  // Unexpected header!
    }
  }
}

}  // namespace oidc
}  // namespace filters
}  // namespace authservice
