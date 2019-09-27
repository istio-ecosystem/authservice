#include "src/common/utilities/random.h"
#include <algorithm>
#include "gtest/gtest.h"
#include "openssl/rand.h"

namespace transparent_auth {
namespace common {
namespace utilities {

TEST(Random, Rand) {
  RandomGenerator generator;
  for (auto i = 0; i < 100; i++) {
    Random first = generator.Generate(32);
    ASSERT_EQ(32, first.Size());
    // Test strings
    auto str = first.Str();
    auto second = Random::FromString(str);
    ASSERT_TRUE(second.has_value());
    // Test comparators.
    ASSERT_EQ(first, second);
    ASSERT_FALSE(first != *second);
    // Test values
    ASSERT_TRUE(std::equal(first.Begin(), first.End(), second->Begin()));
  }
}

}  // namespace utilities
}  // namespace common
}  // namespace transparent_auth