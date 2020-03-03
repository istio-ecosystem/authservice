#include "src/common/http/http.h"
#include "config/common/config.pb.h"
#include "gtest/gtest.h"
#include "src/common/http/headers.h"

namespace authservice {
namespace common {
namespace http {
namespace {
struct {
  const char *raw;
  const char *encoded;
} hex_test_case = {
    .raw =
        R"RAW(abcdefghijklmnopqrstuvwxyz0123456789-._~!#$&'()*+,/:;=?@[] abcdef)RAW",
    .encoded =
        "abcdefghijklmnopqrstuvwxyz0123456789-._~%21%23%24%26%27%28%29%2A%2B%"
        "2C%2F%3A%3B%3D%3F%40%5B%5D%20abcdef",
};

struct {
  const char *raw;
  const std::multimap<absl::string_view, absl::string_view> encoded;
} query_test_case = {.raw = R"RAW(cde=456%207&state=abc%20123)RAW",
                     .encoded = {{"cde", "456 7"}, {"state", "abc 123"}}};

struct {
  const char *raw;
  const std::multimap<absl::string_view, absl::string_view> encoded;
} form_test_case = {.raw = R"RAW(abc=123&cde=456+7&987=%0D%0A)RAW",
                    .encoded = {
                        {"abc", "123"},
                        {"cde", "456 7"},
                        {"987", "\r\n"},
                    }};
}  // namespace

TEST(Http, ToUrl) {
  struct {
    struct {
      const char *scheme;
      const char *hostname;
      int port;
      const char *path;
    } endpoint;
    const char *url;
  } test_cases[] = {
      {
          .endpoint = {.scheme = "https",
                       .hostname = "foo",
                       .port = 443,
                       .path = "/bar"},
          .url = "https://foo/bar",
      },
      {
          .endpoint =
              {.scheme = "http", .hostname = "foo", .port = 80, .path = "/bar"},
          .url = "http://foo/bar",
      },
      {
          .endpoint = {.scheme = "https",
                       .hostname = "foo",
                       .port = 8443,
                       .path = "/bar"},
          .url = "https://foo:8443/bar",
      },
      {
          .endpoint = {.scheme = "http",
                       .hostname = "foo",
                       .port = 8080,
                       .path = "/bar"},
          .url = "http://foo:8080/bar",
      },
  };
  for (auto test : test_cases) {
    config::common::Endpoint e;
    e.set_scheme(test.endpoint.scheme);
    e.set_hostname(test.endpoint.hostname);
    e.set_port(test.endpoint.port);
    e.set_path(test.endpoint.path);
    auto url = Http::ToUrl(e);
    ASSERT_STREQ(url.c_str(), test.url);
  }
}

TEST(Http, UrlSafeEncode) {
  std::string encoded = Http::UrlSafeEncode(hex_test_case.raw);

  ASSERT_STREQ(hex_test_case.encoded, encoded.c_str());
}

TEST(Http, UrlSafeDecode) {
  absl::optional<std::string> decoded =
      Http::UrlSafeDecode(hex_test_case.encoded);

  EXPECT_TRUE(decoded.has_value());
  ASSERT_EQ(hex_test_case.raw, *decoded);
}

TEST(Http, EncodeQueryData) {
  auto result = Http::EncodeQueryData(query_test_case.encoded);
  std::string expectedResult = query_test_case.raw;
  ASSERT_EQ(expectedResult, result);
  auto decoded = Http::DecodeQueryData(result);
  ASSERT_TRUE(decoded.has_value());
  ASSERT_EQ(query_test_case.encoded.size(), decoded->size());
  for (auto val : query_test_case.encoded) {
    auto iter = decoded->find(val.first.data());
    ASSERT_TRUE(iter != decoded->end());
    ASSERT_EQ(iter->second, val.second);
  }
}

TEST(Http, DecodeFormData) {
  auto result = Http::DecodeFormData(form_test_case.raw);
  EXPECT_TRUE(result.has_value());
  ASSERT_EQ(form_test_case.encoded.size(), result->size());
  for (auto val : form_test_case.encoded) {
    auto iter = result->find(val.first.data());
    ASSERT_TRUE(iter != result->end());
    ASSERT_EQ(iter->second, val.second);
  }
}

TEST(Http, EncodeFormData) {
  auto result = Http::EncodeFormData(form_test_case.encoded);
  auto decoded = Http::DecodeFormData(result);
  EXPECT_TRUE(decoded.has_value());
  ASSERT_EQ(form_test_case.encoded.size(), decoded->size());
  for (auto val : form_test_case.encoded) {
    auto iter = decoded->find(val.first.data());
    ASSERT_TRUE(iter != decoded->end());
    ASSERT_EQ(iter->second, val.second);
  }
}

TEST(Http, EncodeBasicAuth) {
  // Known-answer extracted from https://tools.ietf.org/html/rfc7617#section-2 .
  auto result = Http::EncodeBasicAuth("Aladdin", "open sesame");
  ASSERT_STREQ("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==", result.c_str());
}

TEST(Http, EncodeSetCookie) {
  std::set<absl::string_view> directives = {
      headers::SetCookieDirectives::HttpOnly,
      headers::SetCookieDirectives::SameSiteStrict,
      headers::SetCookieDirectives::Secure};
  auto result = Http::EncodeSetCookie("name", "value", directives);
  ASSERT_STREQ("name=value; HttpOnly; SameSite=Strict; Secure", result.c_str());
}

TEST(Http, EncodeCookies) {
  auto cookies1 = "name=value";
  auto result = Http::DecodeCookies(cookies1);
  ASSERT_TRUE(result.has_value());
  ASSERT_EQ(result->size(), 1);
  ASSERT_STREQ((*result)["name"].c_str(), "value");

  auto cookies2 = "first=1; second=2; third=3";
  result = Http::DecodeCookies(cookies2);
  ASSERT_TRUE(result.has_value());
  ASSERT_EQ(result->size(), 3);
  ASSERT_STREQ((*result)["first"].c_str(), "1");
  ASSERT_STREQ((*result)["second"].c_str(), "2");
  ASSERT_STREQ((*result)["third"].c_str(), "3");

  auto cookies3 = "name";
  result = Http::DecodeCookies(cookies3);
  ASSERT_FALSE(result.has_value());

  auto cookies4 = "first=1;second=2";
  result = Http::DecodeCookies(cookies4);
  ASSERT_FALSE(result.has_value());
}

TEST(Http, DecodePath) {
  auto result1 = Http::DecodePath("/path?query#fragment");
  ASSERT_EQ("/path", std::string(result1[0].data(), result1[0].size()));
  ASSERT_EQ("query", std::string(result1[1].data(), result1[1].size()));
  ASSERT_STREQ("query", result1[1].data());
  ASSERT_STREQ("fragment", result1[2].data());

  auto result2 = Http::DecodePath("/path?query");
  ASSERT_STREQ("/path", result2[0].data());
  ASSERT_STREQ("query", result2[1].data());
  ASSERT_STREQ("", result2[2].data());

  auto result3 = Http::DecodePath("/path#fragment");
  ASSERT_STREQ("/path", result3[0].data());
  ASSERT_STREQ("", result3[1].data());
  ASSERT_STREQ("fragment", result3[2].data());

  auto result4 = Http::DecodePath("/path");
  ASSERT_STREQ("/path", result4[0].data());
  ASSERT_STREQ("", result4[1].data());
  ASSERT_STREQ("", result4[2].data());

  auto result5 = Http::DecodePath("/?#");
  ASSERT_STREQ("/", result5[0].data());
  ASSERT_STREQ("", result5[1].data());
  ASSERT_STREQ("", result5[2].data());
}

}  // namespace http
}  // namespace common
}  // namespace authservice
