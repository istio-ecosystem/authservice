#include "src/filters/pipe.h"

#include "gtest/gtest.h"

namespace authservice {
namespace filters {

TEST(PipeTest, Name) {
  Pipe pipe;
  ASSERT_EQ(pipe.Name().compare("pipe"), 0);
}

}  // namespace filters
}  // namespace authservice
