#include "src/filters/oidc/oidc_filter.h"
#include "absl/strings/str_join.h"
#include "external/com_google_googleapis/google/rpc/code.pb.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "src/common/http/headers.h"
#include "test/common/http/mocks.h"
#include "test/common/session/mocks.h"
#include "test/filters/oidc/mocks.h"

namespace transparent_auth {
namespace filters {
namespace oidc {
namespace {

const common::http::Endpoint authorization_endpoint = {
    .scheme = "https",
    .hostname = "acme-idp.tld",
    .port = 443,
    .path = "/authorization",
};
const common::http::Endpoint token_endpoint = {
    .scheme = "https",
    .hostname = "acme-idp.tld",
    .port = 443,
    .path = "/token",
};
const common::http::Endpoint jwks_endpoint = {
    .scheme = "https", .hostname = "acme-idp.tld", .port = 443, .path = "/jwks",
};
const std::string client_id = "example-app";
const std::string client_secret = "ZXhhbXBsZS1hcHAtc2VjcmV0";
const common::http::Endpoint callback_path = {
    .scheme = "https", .hostname = "me.tld", .port = 443, .path = "/callback",
};
const std::string landing_page = "/landing-page";
const OidcIdPConfiguration config(authorization_endpoint, token_endpoint,
                                  jwks_endpoint, client_id, client_secret, {},
                                  callback_path, landing_page);
}

TEST(OidcFilterTest, Constructor) {
  TokenResponseParserMock parser_mock;
  auto cryptor_mock = std::make_shared<common::session::TokenEncryptorMock>();
  OidcFilter filter(common::http::ptr_t(), config, parser_mock, cryptor_mock);
}

TEST(OidcFilterTest, Name) {
  TokenResponseParserMock parser_mock;
  auto cryptor_mock = std::make_shared<common::session::TokenEncryptorMock>();
  OidcFilter filter(common::http::ptr_t(), config, parser_mock, cryptor_mock);
  ASSERT_EQ(filter.Name().compare("oidc"), 0);
}

TEST(OidcFilterTest, NoHttpHeader) {
  TokenResponseParserMock parser_mock;
  auto cryptor_mock = std::make_shared<common::session::TokenEncryptorMock>();
  OidcFilter filter(common::http::ptr_t(), config, parser_mock, cryptor_mock);

  ::envoy::service::auth::v2::CheckRequest request;
  ::envoy::service::auth::v2::CheckResponse response;
  auto status = filter.Process(&request, &response);
  ASSERT_EQ(status, google::rpc::Code::INVALID_ARGUMENT);
}

/* TODO: Reinstate
TEST(OidcFilterTest, NoHttpSchema) {
  OidcFilter filter(common::http::ptr_t(), config);
  ::envoy::service::auth::v2::CheckRequest request;
  ::envoy::service::auth::v2::CheckResponse response;
  auto status = filter.Process(&request, &response);
  ASSERT_EQ(status.error_code(), ::grpc::StatusCode::INVALID_ARGUMENT);
}
 */

TEST(OidcFilterTest, NoAuthorization) {
  TokenResponseParserMock parser_mock;
  auto cryptor_mock = std::make_shared<common::session::TokenEncryptorMock>();
  EXPECT_CALL(*cryptor_mock, Encrypt(::testing::_))
      .WillOnce(::testing::Return("encrypted"));
  OidcFilter filter(common::http::ptr_t(), config, parser_mock, cryptor_mock);
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

  for (auto iter : response.denied_response().headers()) {
    if (iter.header().key() == common::http::headers::Location) {
      ASSERT_EQ(iter.header().value().find(authorization_endpoint.ToUrl()), 0);
    } else if (iter.header().key() == common::http::headers::CacheControl) {
      ASSERT_EQ(iter.header().value(),
                common::http::headers::CacheControlDirectives::NoCache);
    } else if (iter.header().key() == common::http::headers::Pragma) {
      ASSERT_EQ(iter.header().value(),
                common::http::headers::PragmaDirectives::NoCache);
    } else if (iter.header().key() == common::http::headers::SetCookie) {
      ASSERT_EQ(iter.header().value(),
                "__Host-acme-state-cookie=encrypted; HttpOnly; Path=/; "
                "SameSite=Lax; Secure");
    } else {
      FAIL();  // Unexpected header!
    }
  }
}

TEST(OidcFilterTest, InvalidCookies) {
  TokenResponseParserMock parser_mock;
  auto cryptor_mock = std::make_shared<common::session::TokenEncryptorMock>();
  EXPECT_CALL(*cryptor_mock, Encrypt(::testing::_))
      .WillOnce(::testing::Return("encrypted"));
  OidcFilter filter(common::http::ptr_t(), config, parser_mock, cryptor_mock);
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

  for (auto iter : response.denied_response().headers()) {
    if (iter.header().key() == common::http::headers::Location) {
      ASSERT_EQ(iter.header().value().find(authorization_endpoint.ToUrl()), 0);
    } else if (iter.header().key() == common::http::headers::CacheControl) {
      ASSERT_EQ(iter.header().value(),
                common::http::headers::CacheControlDirectives::NoCache);
    } else if (iter.header().key() == common::http::headers::Pragma) {
      ASSERT_EQ(iter.header().value(),
                common::http::headers::PragmaDirectives::NoCache);
    } else if (iter.header().key() == common::http::headers::SetCookie) {
      ASSERT_EQ(iter.header().value(),
                "__Host-acme-state-cookie=encrypted; HttpOnly; Path=/; "
                "SameSite=Lax; Secure");
    } else {
      FAIL();  // Unexpected header!
    }
  }
}

TEST(OidcFilterTest, InvalidSessionToken) {
  TokenResponseParserMock parser_mock;
  auto cryptor_mock = std::make_shared<common::session::TokenEncryptorMock>();
  EXPECT_CALL(*cryptor_mock, Encrypt(::testing::_))
      .WillOnce(::testing::Return("encrypted"));
  OidcFilter filter(common::http::ptr_t(), config, parser_mock, cryptor_mock);
  ::envoy::service::auth::v2::CheckRequest request;
  ::envoy::service::auth::v2::CheckResponse response;
  auto httpRequest =
      request.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->set_scheme("https");
  httpRequest->mutable_headers()->insert(
      {common::http::headers::Cookie,
       "__Host-acme-id-token-session-cookie=invalid"});
  EXPECT_CALL(*cryptor_mock, Decrypt("invalid"))
      .WillOnce(::testing::Return(absl::nullopt));

  auto status = filter.Process(&request, &response);
  // We expect to be redirected to authenticate
  ASSERT_EQ(status, google::rpc::Code::UNAUTHENTICATED);
  ASSERT_EQ(response.denied_response().headers().size(), 4);

  for (auto iter : response.denied_response().headers()) {
    if (iter.header().key() == common::http::headers::Location) {
      ASSERT_EQ(iter.header().value().find(authorization_endpoint.ToUrl()), 0);
    } else if (iter.header().key() == common::http::headers::CacheControl) {
      ASSERT_EQ(iter.header().value(),
                common::http::headers::CacheControlDirectives::NoCache);
    } else if (iter.header().key() == common::http::headers::Pragma) {
      ASSERT_EQ(iter.header().value(),
                common::http::headers::PragmaDirectives::NoCache);
    } else if (iter.header().key() == common::http::headers::SetCookie) {
      ASSERT_EQ(iter.header().value(),
                "__Host-acme-state-cookie=encrypted; HttpOnly; Path=/; "
                "SameSite=Lax; Secure");
    } else {
      FAIL();  // Unexpected header!
    }
  }
}

TEST(OidcFilterTest, ValidSessionToken) {
  TokenResponseParserMock parser_mock;
  auto cryptor_mock = std::make_shared<common::session::TokenEncryptorMock>();
  OidcFilter filter(common::http::ptr_t(), config, parser_mock, cryptor_mock);
  ::envoy::service::auth::v2::CheckRequest request;
  ::envoy::service::auth::v2::CheckResponse response;
  auto httpRequest =
      request.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->set_scheme("https");
  httpRequest->mutable_headers()->insert(
      {common::http::headers::Cookie,
       "__Host-acme-id-token-session-cookie=valid"});
  EXPECT_CALL(*cryptor_mock, Decrypt("valid"))
      .WillOnce(::testing::Return(absl::optional<std::string>("secret")));

  auto status = filter.Process(&request, &response);
  // We expect to be redirected to authenticate
  ASSERT_EQ(status, google::rpc::Code::OK);
  ASSERT_EQ(response.ok_response().headers().size(), 1);
  ASSERT_STREQ(common::http::headers::Authorization,
               response.ok_response().headers()[0].header().key().c_str());
  ASSERT_STREQ("Bearer secret",
               response.ok_response().headers()[0].header().value().c_str());
}

TEST(OidcFilterTest, RetrieveToken) {
  google::jwt_verify::Jwt jwt = {};
  TokenResponseParserMock parser_mock;
  auto cryptor_mock = std::make_shared<common::session::TokenEncryptorMock>();
  EXPECT_CALL(parser_mock, Parse(::testing::_, ::testing::_))
      .WillOnce(::testing::Return(absl::make_optional<TokenResponse>(jwt)));
  common::http::http_mock *mocked_http = new common::http::http_mock();
  auto raw_http = common::http::response_t(
      new beast::http::response<beast::http::string_body>());
  raw_http->result(beast::http::status::ok);
  EXPECT_CALL(*mocked_http, Post(token_endpoint, ::testing::_, ::testing::_))
      .WillOnce(::testing::Return(::testing::ByMove(std::move(raw_http))));
  OidcFilter filter(common::http::ptr_t(mocked_http), config, parser_mock,
                    cryptor_mock);
  ::envoy::service::auth::v2::CheckRequest request;
  ::envoy::service::auth::v2::CheckResponse response;
  auto httpRequest =
      request.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->set_scheme(""); // Seems like it should be "https", but in practice is empty
  httpRequest->set_host(callback_path.hostname);
  httpRequest->mutable_headers()->insert(
      {common::http::headers::Cookie, "__Host-acme-state-cookie=valid"});
  EXPECT_CALL(*cryptor_mock, Decrypt("valid"))
      .WillOnce(::testing::Return(
          absl::optional<std::string>("expectedstate;expectednonce")));
  EXPECT_CALL(*cryptor_mock, Encrypt(::testing::_))
      .WillOnce(::testing::Return("encryptedtoken"));
  std::vector<absl::string_view> parts = {callback_path.path.c_str(),
                                          "code=value&state=expectedstate"};
  httpRequest->set_path(absl::StrJoin(parts, "?"));
  auto code = filter.Process(&request, &response);
  ASSERT_EQ(code, google::rpc::Code::UNAUTHENTICATED);

  ASSERT_EQ(response.denied_response().headers().size(), 5);

  for (auto iter : response.denied_response().headers()) {
    if (iter.header().key() == common::http::headers::Location) {
      ASSERT_EQ(iter.header().value().find(config.LandingPage()), 0);
    } else if (iter.header().key() == common::http::headers::CacheControl) {
      ASSERT_EQ(iter.header().value(),
                common::http::headers::CacheControlDirectives::NoCache);
    } else if (iter.header().key() == common::http::headers::Pragma) {
      ASSERT_EQ(iter.header().value(),
                common::http::headers::PragmaDirectives::NoCache);
    } else if (iter.header().key() == common::http::headers::SetCookie) {
      ASSERT_TRUE((iter.header().value() == "__Host-acme-id-token-session-"
                                            "cookie=encryptedtoken; HttpOnly; "
                                            "Path=/; SameSite=Lax; Secure") ||
                  (iter.header().value() == "__Host-acme-state-cookie=deleted; "
                                            "HttpOnly; Path=/; SameSite=Lax; "
                                            "Secure"));
    } else {
      FAIL();  // Unexpected header!
    }
  }
}

TEST(OidcFilterTest, RetrieveTokenMissingStateCookie) {
  TokenResponseParserMock parser_mock;
  auto cryptor_mock = std::make_shared<common::session::TokenEncryptorMock>();
  common::http::http_mock *mocked_http = new common::http::http_mock();
  OidcFilter filter(common::http::ptr_t(mocked_http), config, parser_mock,
                    cryptor_mock);
  ::envoy::service::auth::v2::CheckRequest request;
  ::envoy::service::auth::v2::CheckResponse response;
  auto httpRequest =
      request.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->set_scheme("https");
  httpRequest->set_host(callback_path.hostname);
  std::vector<absl::string_view> parts = {callback_path.path.c_str(),
                                          "code=value&state=expectedstate"};
  httpRequest->set_path(absl::StrJoin(parts, "?"));
  auto code = filter.Process(&request, &response);
  ASSERT_EQ(code, google::rpc::Code::INVALID_ARGUMENT);

  ASSERT_EQ(response.denied_response().headers().size(), 3);

  for (auto iter : response.denied_response().headers()) {
    if (iter.header().key() == common::http::headers::CacheControl) {
      ASSERT_EQ(iter.header().value(),
                common::http::headers::CacheControlDirectives::NoCache);
    } else if (iter.header().key() == common::http::headers::Pragma) {
      ASSERT_EQ(iter.header().value(),
                common::http::headers::PragmaDirectives::NoCache);
    } else if (iter.header().key() == common::http::headers::SetCookie) {
      ASSERT_EQ(iter.header().value(),
                "__Host-acme-state-cookie=deleted; HttpOnly; Path=/; "
                "SameSite=Lax; Secure");
    } else {
      FAIL();  // Unexpected header!
    }
  }
}

TEST(OidcFilterTest, RetrieveTokenInvalidStateCookie) {
  TokenResponseParserMock parser_mock;
  auto cryptor_mock = std::make_shared<common::session::TokenEncryptorMock>();
  common::http::http_mock *mocked_http = new common::http::http_mock();
  OidcFilter filter(common::http::ptr_t(mocked_http), config, parser_mock,
                    cryptor_mock);
  ::envoy::service::auth::v2::CheckRequest request;
  ::envoy::service::auth::v2::CheckResponse response;
  auto httpRequest =
      request.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->set_scheme("https");
  httpRequest->set_host(callback_path.hostname);
  httpRequest->mutable_headers()->insert(
      {common::http::headers::Cookie, "__Host-acme-state-cookie=invalid"});
  EXPECT_CALL(*cryptor_mock, Decrypt("invalid"))
      .WillOnce(::testing::Return(absl::nullopt));
  std::vector<absl::string_view> parts = {callback_path.path.c_str(),
                                          "code=value&state=expectedstate"};
  httpRequest->set_path(absl::StrJoin(parts, "?"));
  auto code = filter.Process(&request, &response);
  ASSERT_EQ(code, google::rpc::Code::INVALID_ARGUMENT);

  ASSERT_EQ(response.denied_response().headers().size(), 3);

  for (auto iter : response.denied_response().headers()) {
    if (iter.header().key() == common::http::headers::CacheControl) {
      ASSERT_EQ(iter.header().value(),
                common::http::headers::CacheControlDirectives::NoCache);
    } else if (iter.header().key() == common::http::headers::Pragma) {
      ASSERT_EQ(iter.header().value(),
                common::http::headers::PragmaDirectives::NoCache);
    } else if (iter.header().key() == common::http::headers::SetCookie) {
      ASSERT_EQ(iter.header().value(),
                "__Host-acme-state-cookie=deleted; HttpOnly; Path=/; "
                "SameSite=Lax; Secure");
    } else {
      FAIL();  // Unexpected header!
    }
  }
}

TEST(OidcFilterTest, RetrieveTokenInvalidStateCookieFormat) {
  TokenResponseParserMock parser_mock;
  auto cryptor_mock = std::make_shared<common::session::TokenEncryptorMock>();
  common::http::http_mock *mocked_http = new common::http::http_mock();
  OidcFilter filter(common::http::ptr_t(mocked_http), config, parser_mock,
                    cryptor_mock);
  ::envoy::service::auth::v2::CheckRequest request;
  ::envoy::service::auth::v2::CheckResponse response;
  auto httpRequest =
      request.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->set_scheme("https");
  httpRequest->set_host(callback_path.hostname);
  httpRequest->mutable_headers()->insert(
      {common::http::headers::Cookie, "__Host-acme-state-cookie=valid"});
  EXPECT_CALL(*cryptor_mock, Decrypt("valid"))
      .WillOnce(
          ::testing::Return(absl::optional<std::string>("invalidformat")));
  std::vector<absl::string_view> parts = {callback_path.path.c_str(),
                                          "code=value&state=expectedstate"};
  httpRequest->set_path(absl::StrJoin(parts, "?"));
  auto code = filter.Process(&request, &response);
  ASSERT_EQ(code, google::rpc::Code::INVALID_ARGUMENT);

  ASSERT_EQ(response.denied_response().headers().size(), 3);

  for (auto iter : response.denied_response().headers()) {
    if (iter.header().key() == common::http::headers::CacheControl) {
      ASSERT_EQ(iter.header().value(),
                common::http::headers::CacheControlDirectives::NoCache);
    } else if (iter.header().key() == common::http::headers::Pragma) {
      ASSERT_EQ(iter.header().value(),
                common::http::headers::PragmaDirectives::NoCache);
    } else if (iter.header().key() == common::http::headers::SetCookie) {
      ASSERT_EQ(iter.header().value(),
                "__Host-acme-state-cookie=deleted; HttpOnly; Path=/; "
                "SameSite=Lax; Secure");
    } else {
      FAIL();  // Unexpected header!
    }
  }
}

TEST(OidcFilterTest, RetrieveTokenMissingCode) {
  TokenResponseParserMock parser_mock;
  auto cryptor_mock = std::make_shared<common::session::TokenEncryptorMock>();
  OidcFilter filter(common::http::ptr_t(), config, parser_mock, cryptor_mock);
  ::envoy::service::auth::v2::CheckRequest request;
  ::envoy::service::auth::v2::CheckResponse response;
  auto httpRequest =
      request.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->set_scheme("https");
  httpRequest->set_host(callback_path.hostname);
  httpRequest->set_path(callback_path.path);
  std::vector<absl::string_view> parts = {callback_path.path.c_str(),
                                          "key=value&state=expectedstate"};
  httpRequest->set_path(absl::StrJoin(parts, "?"));
  auto code = filter.Process(&request, &response);
  ASSERT_EQ(code, google::rpc::Code::INVALID_ARGUMENT);

  ASSERT_EQ(response.denied_response().headers().size(), 3);

  for (auto iter : response.denied_response().headers()) {
    if (iter.header().key() == common::http::headers::CacheControl) {
      ASSERT_EQ(iter.header().value(),
                common::http::headers::CacheControlDirectives::NoCache);
    } else if (iter.header().key() == common::http::headers::Pragma) {
      ASSERT_EQ(iter.header().value(),
                common::http::headers::PragmaDirectives::NoCache);
    } else if (iter.header().key() == common::http::headers::SetCookie) {
      ASSERT_EQ(iter.header().value(),
                "__Host-acme-state-cookie=deleted; HttpOnly; Path=/; "
                "SameSite=Lax; Secure");
    } else {
      FAIL();  // Unexpected header!
    }
  }
}

TEST(OidcFilterTest, RetrieveTokenMissingState) {
  TokenResponseParserMock parser_mock;
  auto cryptor_mock = std::make_shared<common::session::TokenEncryptorMock>();
  OidcFilter filter(common::http::ptr_t(), config, parser_mock, cryptor_mock);
  ::envoy::service::auth::v2::CheckRequest request;
  ::envoy::service::auth::v2::CheckResponse response;
  auto httpRequest =
      request.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->set_scheme("https");
  httpRequest->set_host(callback_path.hostname);
  httpRequest->set_path(callback_path.path);
  std::vector<absl::string_view> parts = {callback_path.path.c_str(),
                                          "code=value"};
  httpRequest->set_path(absl::StrJoin(parts, "?"));
  auto code = filter.Process(&request, &response);
  ASSERT_EQ(code, google::rpc::Code::INVALID_ARGUMENT);

  ASSERT_EQ(response.denied_response().headers().size(), 3);

  for (auto iter : response.denied_response().headers()) {
    if (iter.header().key() == common::http::headers::CacheControl) {
      ASSERT_EQ(iter.header().value(),
                common::http::headers::CacheControlDirectives::NoCache);
    } else if (iter.header().key() == common::http::headers::Pragma) {
      ASSERT_EQ(iter.header().value(),
                common::http::headers::PragmaDirectives::NoCache);
    } else if (iter.header().key() == common::http::headers::SetCookie) {
      ASSERT_EQ(iter.header().value(),
                "__Host-acme-state-cookie=deleted; HttpOnly; Path=/; "
                "SameSite=Lax; Secure");
    } else {
      FAIL();  // Unexpected header!
    }
  }
}

TEST(OidcFilterTest, RetrieveTokenUnexpectedState) {
  TokenResponseParserMock parser_mock;
  auto cryptor_mock = std::make_shared<common::session::TokenEncryptorMock>();
  OidcFilter filter(common::http::ptr_t(), config, parser_mock, cryptor_mock);
  ::envoy::service::auth::v2::CheckRequest request;
  ::envoy::service::auth::v2::CheckResponse response;
  auto httpRequest =
      request.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->set_scheme("https");
  httpRequest->set_host(callback_path.hostname);
  httpRequest->set_path(callback_path.path);
  std::vector<absl::string_view> parts = {callback_path.path.c_str(),
                                          "code=value&state=unexpectedstate"};
  httpRequest->set_path(absl::StrJoin(parts, "?"));
  auto code = filter.Process(&request, &response);
  ASSERT_EQ(code, google::rpc::Code::INVALID_ARGUMENT);

  ASSERT_EQ(response.denied_response().headers().size(), 3);

  for (auto iter : response.denied_response().headers()) {
    if (iter.header().key() == common::http::headers::CacheControl) {
      ASSERT_EQ(iter.header().value(),
                common::http::headers::CacheControlDirectives::NoCache);
    } else if (iter.header().key() == common::http::headers::Pragma) {
      ASSERT_EQ(iter.header().value(),
                common::http::headers::PragmaDirectives::NoCache);
    } else if (iter.header().key() == common::http::headers::SetCookie) {
      ASSERT_EQ(iter.header().value(),
                "__Host-acme-state-cookie=deleted; HttpOnly; Path=/; "
                "SameSite=Lax; Secure");
    } else {
      FAIL();  // Unexpected header!
    }
  }
}

TEST(OidcFilterTest, RetrieveTokenBrokenPipe) {
  TokenResponseParserMock parser_mock;
  auto cryptor_mock = std::make_shared<common::session::TokenEncryptorMock>();
  common::http::http_mock *http_mock = new common::http::http_mock();
  auto raw_http = common::http::response_t();
  EXPECT_CALL(*http_mock, Post(token_endpoint, ::testing::_, ::testing::_))
      .WillOnce(::testing::Return(::testing::ByMove(std::move(raw_http))));
  OidcFilter filter(common::http::ptr_t(http_mock), config, parser_mock,
                    cryptor_mock);
  ::envoy::service::auth::v2::CheckRequest request;
  ::envoy::service::auth::v2::CheckResponse response;
  auto httpRequest =
      request.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->set_scheme("https");
  httpRequest->set_host(callback_path.hostname);
  httpRequest->set_path(callback_path.path);
  httpRequest->mutable_headers()->insert(
      {common::http::headers::Cookie, "__Host-acme-state-cookie=valid"});
  EXPECT_CALL(*cryptor_mock, Decrypt("valid"))
      .WillOnce(::testing::Return(
          absl::optional<std::string>("expectedstate;expectednonce")));
  std::vector<absl::string_view> parts = {callback_path.path.c_str(),
                                          "code=value&state=expectedstate"};
  httpRequest->set_path(absl::StrJoin(parts, "?"));
  auto code = filter.Process(&request, &response);
  ASSERT_EQ(code, google::rpc::Code::INTERNAL);

  ASSERT_EQ(response.denied_response().headers().size(), 3);

  for (auto iter : response.denied_response().headers()) {
    if (iter.header().key() == common::http::headers::CacheControl) {
      ASSERT_EQ(iter.header().value(),
                common::http::headers::CacheControlDirectives::NoCache);
    } else if (iter.header().key() == common::http::headers::Pragma) {
      ASSERT_EQ(iter.header().value(),
                common::http::headers::PragmaDirectives::NoCache);
    } else if (iter.header().key() == common::http::headers::SetCookie) {
      ASSERT_EQ(iter.header().value(),
                "__Host-acme-state-cookie=deleted; HttpOnly; Path=/; "
                "SameSite=Lax; Secure");
    } else {
      FAIL();  // Unexpected header!
    }
  }
}

TEST(OidcFilterTest, RetrieveTokenInvalidResponse) {
  TokenResponseParserMock parser_mock;
  auto cryptor_mock = std::make_shared<common::session::TokenEncryptorMock>();
  EXPECT_CALL(parser_mock, Parse(::testing::_, ::testing::_))
      .WillOnce(::testing::Return(absl::nullopt));
  common::http::http_mock *http_mock = new common::http::http_mock();
  auto raw_http = common::http::response_t(
      (new beast::http::response<beast::http::string_body>()));
  EXPECT_CALL(*http_mock, Post(token_endpoint, ::testing::_, ::testing::_))
      .WillOnce(::testing::Return(::testing::ByMove(std::move(raw_http))));
  OidcFilter filter(common::http::ptr_t(http_mock), config, parser_mock,
                    cryptor_mock);
  ::envoy::service::auth::v2::CheckRequest request;
  ::envoy::service::auth::v2::CheckResponse response;
  auto httpRequest =
      request.mutable_attributes()->mutable_request()->mutable_http();
  httpRequest->set_scheme("https");
  httpRequest->set_host(callback_path.hostname);
  httpRequest->set_path(callback_path.path);
  httpRequest->mutable_headers()->insert(
      {common::http::headers::Cookie, "__Host-acme-state-cookie=valid"});
  EXPECT_CALL(*cryptor_mock, Decrypt("valid"))
      .WillOnce(::testing::Return(
          absl::optional<std::string>("expectedstate;expectednonce")));
  std::vector<absl::string_view> parts = {callback_path.path.c_str(),
                                          "code=value&state=expectedstate"};
  httpRequest->set_path(absl::StrJoin(parts, "?"));
  auto code = filter.Process(&request, &response);
  ASSERT_EQ(code, google::rpc::Code::INVALID_ARGUMENT);

  ASSERT_EQ(response.denied_response().headers().size(), 3);

  for (auto iter : response.denied_response().headers()) {
    if (iter.header().key() == common::http::headers::CacheControl) {
      ASSERT_EQ(iter.header().value(),
                common::http::headers::CacheControlDirectives::NoCache);
    } else if (iter.header().key() == common::http::headers::Pragma) {
      ASSERT_EQ(iter.header().value(),
                common::http::headers::PragmaDirectives::NoCache);
    } else if (iter.header().key() == common::http::headers::SetCookie) {
      ASSERT_EQ(iter.header().value(),
                "__Host-acme-state-cookie=deleted; HttpOnly; Path=/; "
                "SameSite=Lax; Secure");
    } else {
      FAIL();  // Unexpected header!
    }
  }
}

}  // namespace oidc
}  // namespace service
}  // namespace transparent_auth
