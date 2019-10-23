#include "src/filters/oidc/state_cookie_codec.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace authservice {
namespace filters {
namespace oidc {
TEST(StateCookieCodecTest, Encode) {
  StateCookieCodec codec;
  auto encoded = codec.Encode("mystate", "mynonce");
  ASSERT_STREQ(encoded.c_str(), "mystate;mynonce");
}

TEST(StateCookieCodecTest, Decode) {
  StateCookieCodec codec;
  auto decoded = codec.Decode("mystate;mynonce");
  ASSERT_TRUE(decoded.has_value());
  ASSERT_EQ(decoded->first, absl::string_view("mystate"));
  ASSERT_EQ(decoded->second, absl::string_view("mynonce"));

  // Too many values
  decoded = codec.Decode("too;many;values");
  ASSERT_FALSE(decoded.has_value());
  // Not enough values
  decoded = codec.Decode("NotEnough");
  ASSERT_FALSE(decoded.has_value());
}
}  // namespace oidc
}  // namespace filters
}  // namespace authservice
