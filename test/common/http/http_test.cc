#include "src/common/http/http.h"
#include "gtest/gtest.h"
#include "src/common/http/headers.h"
#include "test/shared/assertions.h"

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

using test_helpers::ASSERT_THROWS_STD_RUNTIME_ERROR;

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

TEST(Http, ParseUri) {
  auto result = Uri("https://example.com/path");
  ASSERT_EQ(result.GetScheme(), "https");
  ASSERT_EQ(result.GetHost(), "example.com");
  ASSERT_EQ(result.GetPort(), 443);
  ASSERT_EQ(result.GetPathQueryFragment(), "/path");
  ASSERT_EQ(result.GetPath(), "/path");
  ASSERT_EQ(result.GetQuery(), "");
  ASSERT_EQ(result.GetFragment(), "");

  result = Uri("https://example/path?query#fragment");
  ASSERT_EQ(result.GetScheme(), "https");
  ASSERT_EQ(result.GetHost(), "example");
  ASSERT_EQ(result.GetPort(), 443);
  ASSERT_EQ(result.GetPathQueryFragment(), "/path?query#fragment");
  ASSERT_EQ(result.GetPath(), "/path");
  ASSERT_EQ(result.GetQuery(), "query");
  ASSERT_EQ(result.GetFragment(), "fragment");

  result = Uri("https://example/path#fragment");
  ASSERT_EQ(result.GetScheme(), "https");
  ASSERT_EQ(result.GetHost(), "example");
  ASSERT_EQ(result.GetPort(), 443);
  ASSERT_EQ(result.GetPathQueryFragment(), "/path#fragment");
  ASSERT_EQ(result.GetPath(), "/path");
  ASSERT_EQ(result.GetQuery(), "");
  ASSERT_EQ(result.GetFragment(), "fragment");

  result = Uri("https://example/?query#fragment");
  ASSERT_EQ(result.GetScheme(), "https");
  ASSERT_EQ(result.GetHost(), "example");
  ASSERT_EQ(result.GetPort(), 443);
  ASSERT_EQ(result.GetPathQueryFragment(), "/?query#fragment");
  ASSERT_EQ(result.GetPath(), "/");
  ASSERT_EQ(result.GetQuery(), "query");
  ASSERT_EQ(result.GetFragment(), "fragment");

  result = Uri("https://example/#fragment");
  ASSERT_EQ(result.GetScheme(), "https");
  ASSERT_EQ(result.GetHost(), "example");
  ASSERT_EQ(result.GetPort(), 443);
  ASSERT_EQ(result.GetPathQueryFragment(), "/#fragment");
  ASSERT_EQ(result.GetPath(), "/");
  ASSERT_EQ(result.GetQuery(), "");
  ASSERT_EQ(result.GetFragment(), "fragment");

  result = Uri("https://www.example.com:1234");
  ASSERT_EQ(result.GetScheme(), "https");
  ASSERT_EQ(result.GetHost(), "www.example.com");
  ASSERT_EQ(result.GetPort(), 1234);
  ASSERT_EQ(result.GetPathQueryFragment(), "/");
  ASSERT_EQ(result.GetPath(), "/");
  ASSERT_EQ(result.GetQuery(), "");
  ASSERT_EQ(result.GetFragment(), "");

  result = Uri("https://www.example.com:1234/path");
  ASSERT_EQ(result.GetScheme(), "https");
  ASSERT_EQ(result.GetHost(), "www.example.com");
  ASSERT_EQ(result.GetPort(), 1234);
  ASSERT_EQ(result.GetPathQueryFragment(), "/path");
  ASSERT_EQ(result.GetPath(), "/path");
  ASSERT_EQ(result.GetQuery(), "");
  ASSERT_EQ(result.GetFragment(), "");

  result = Uri("https://example.com");
  ASSERT_EQ(result.GetScheme(), "https");
  ASSERT_EQ(result.GetHost(), "example.com");
  ASSERT_EQ(result.GetPort(), 443);
  ASSERT_EQ(result.GetPathQueryFragment(), "/");
  ASSERT_EQ(result.GetPath(), "/");
  ASSERT_EQ(result.GetQuery(), "");
  ASSERT_EQ(result.GetFragment(), "");

  result = Uri("https://www.example.com:65535/path");
  ASSERT_EQ(result.GetScheme(), "https");
  ASSERT_EQ(result.GetHost(), "www.example.com");
  ASSERT_EQ(result.GetPort(), 65535);
  ASSERT_EQ(result.GetPathQueryFragment(), "/path");
  ASSERT_EQ(result.GetPath(), "/path");
  ASSERT_EQ(result.GetQuery(), "");
  ASSERT_EQ(result.GetFragment(), "");

  result = Uri("https://www.example.com?que/ry");
  ASSERT_EQ(result.GetScheme(), "https");
  ASSERT_EQ(result.GetHost(), "www.example.com");
  ASSERT_EQ(result.GetPort(), 443);
  ASSERT_EQ(result.GetPathQueryFragment(), "/?que/ry");
  ASSERT_EQ(result.GetPath(), "/");
  ASSERT_EQ(result.GetQuery(), "que/ry");
  ASSERT_EQ(result.GetFragment(), "");

  result = Uri("https://www.example.com#frag/?ment");
  ASSERT_EQ(result.GetScheme(), "https");
  ASSERT_EQ(result.GetHost(), "www.example.com");
  ASSERT_EQ(result.GetPort(), 443);
  ASSERT_EQ(result.GetPathQueryFragment(), "/#frag/?ment");
  ASSERT_EQ(result.GetPath(), "/");
  ASSERT_EQ(result.GetQuery(), "");
  ASSERT_EQ(result.GetFragment(), "frag/?ment");

  result = Uri("https://www.example.com?query#frag/?ment");
  ASSERT_EQ(result.GetScheme(), "https");
  ASSERT_EQ(result.GetHost(), "www.example.com");
  ASSERT_EQ(result.GetPort(), 443);
  ASSERT_EQ(result.GetPathQueryFragment(), "/?query#frag/?ment");
  ASSERT_EQ(result.GetPath(), "/");
  ASSERT_EQ(result.GetQuery(), "query");
  ASSERT_EQ(result.GetFragment(), "frag/?ment");

  ASSERT_THROWS_STD_RUNTIME_ERROR([]() -> void { Uri("noscheme"); }, "uri must be https scheme: noscheme");
  ASSERT_THROWS_STD_RUNTIME_ERROR([]() -> void { Uri("not_https://host"); }, "uri must be https scheme: not_https://host");
  ASSERT_THROWS_STD_RUNTIME_ERROR([]() -> void { Uri("https://"); }, "no host in uri: https://"); // no host
  ASSERT_THROWS_STD_RUNTIME_ERROR([]() -> void { Uri("https://:80/path"); }, "no host in uri: https://:80/path"); // no host
  ASSERT_THROWS_STD_RUNTIME_ERROR([]() -> void { Uri("https://host:/path"); }, "port not valid in uri: https://host:/path"); // colon, but no port
  ASSERT_THROWS_STD_RUNTIME_ERROR([]() -> void { Uri("https://host:a8/path"); }, "port not valid in uri: https://host:a8/path"); // port not an int
  ASSERT_THROWS_STD_RUNTIME_ERROR([]() -> void { Uri("https://host:65536/path"); }, "port value must be between 0 and 65535: https://host:65536/path"); // port int too large
  ASSERT_THROWS_STD_RUNTIME_ERROR([]() -> void { Uri("https://host:-1/path"); }, "port value must be between 0 and 65535: https://host:-1/path"); // port int too small
}

TEST(Http, ParsePathQueryFragment) {
  auto result1 = PathQueryFragment("/path?query#fragment");
  ASSERT_EQ("/path", result1.Path());
  ASSERT_EQ("query", result1.Query());
  ASSERT_EQ("query", result1.Query());
  ASSERT_EQ("fragment", result1.Fragment());

  auto result2 = PathQueryFragment("/path?query");
  ASSERT_EQ("/path", result2.Path());
  ASSERT_EQ("query", result2.Query());
  ASSERT_EQ("", result2.Fragment());

  auto result3 = PathQueryFragment("/path#fragment");
  ASSERT_EQ("/path", result3.Path());
  ASSERT_EQ("", result3.Query());
  ASSERT_EQ("fragment", result3.Fragment());

  auto result4 = PathQueryFragment("/path");
  ASSERT_EQ("/path", result4.Path());
  ASSERT_EQ("", result4.Query());
  ASSERT_EQ("", result4.Fragment());

  auto result5 = PathQueryFragment("/?#");
  ASSERT_EQ("/", result5.Path());
  ASSERT_EQ("", result5.Query());
  ASSERT_EQ("", result5.Fragment());

  auto result6 = PathQueryFragment("/path#fragment?still_fragment/still_fragment");
  ASSERT_EQ("/path", result6.Path());
  ASSERT_EQ("", result6.Query());
  ASSERT_EQ("fragment?still_fragment/still_fragment", result6.Fragment());

  auto result7 = PathQueryFragment("/path?query/still_query#fragment/still_fragment?still_fragment");
  ASSERT_EQ("/path", result7.Path());
  ASSERT_EQ("query/still_query", result7.Query());
  ASSERT_EQ("fragment/still_fragment?still_fragment", result7.Fragment());

  auto result8 = PathQueryFragment("/path#fragment/still_fragment?still_fragment");
  ASSERT_EQ("/path", result8.Path());
  ASSERT_EQ("", result8.Query());
  ASSERT_EQ("fragment/still_fragment?still_fragment", result8.Fragment());

  auto result9 = PathQueryFragment("/#fragment/still_fragment?still_fragment");
  ASSERT_EQ("/", result9.Path());
  ASSERT_EQ("", result9.Query());
  ASSERT_EQ("fragment/still_fragment?still_fragment", result9.Fragment());
}

}  // namespace http
}  // namespace common
}  // namespace authservice
