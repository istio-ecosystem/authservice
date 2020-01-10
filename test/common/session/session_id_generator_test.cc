#include "src/common/session/session_id_generator.h"
#include "gtest/gtest.h"

namespace authservice {
namespace common {
namespace session {

TEST(SessionIdGeneratorTest, Generate) {
  int expected_number_of_printable_characters = 86;

  SessionIdGenerator gen;

  auto session_id1 = gen.Generate();
  ASSERT_EQ(expected_number_of_printable_characters, session_id1.length());

  auto session_id2 = gen.Generate();
  ASSERT_EQ(expected_number_of_printable_characters, session_id2.length());

  ASSERT_NE(session_id1, session_id2);
}

}  // namespace session
}  // namespace common
}  // namespace authservice
