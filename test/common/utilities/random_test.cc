#include "src/common/utilities/random.h"
#include <algorithm>
#include "gtest/gtest.h"

namespace authservice {
namespace common {
namespace utilities {

TEST(Random, Rand) {
  RandomGenerator generator;

  for (auto i = 0; i < 10; i++) {
    Random random_value = generator.Generate(32);
    ASSERT_EQ(32, random_value.Size());

    // Test strings
    auto random_as_string = random_value.Str();
    auto parsed_back = Random::FromString(random_as_string);
    ASSERT_TRUE(parsed_back.has_value());

    // Test comparators
    ASSERT_EQ(random_value, parsed_back);
    ASSERT_FALSE(random_value != *parsed_back);

    // Test values
    ASSERT_TRUE(std::equal(random_value.Begin(), random_value.End(), parsed_back->Begin()));
  }
}

}  // namespace utilities
}  // namespace common
}  // namespace authservice