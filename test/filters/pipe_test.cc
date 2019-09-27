#include "src/filters/pipe.h"
#include "gtest/gtest.h"

namespace transparent_auth {
namespace filters {
TEST(PipeTest, Name) {
  Pipe pipe;
  ASSERT_EQ(pipe.Name().compare("pipe"), 0);
}

}  // namespace filters
}  // namespace transparent_auth
