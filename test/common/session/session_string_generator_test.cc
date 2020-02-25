#include "src/common/session/session_string_generator.h"
#include "gtest/gtest.h"

namespace authservice {
namespace common {
namespace session {

TEST(SessionStringGeneratorTest, Generate) {
  int expected_number_of_printable_characters = 86;

  SessionStringGenerator gen;

  auto session_id1 = gen.GenerateSessionId();
  ASSERT_EQ(expected_number_of_printable_characters, session_id1.length());

  auto session_id2 = gen.GenerateSessionId();
  ASSERT_EQ(expected_number_of_printable_characters, session_id2.length());

  ASSERT_NE(session_id1, session_id2);
}

TEST(SessionStringGeneratorTest, GenerateState) {
  int expected_number_of_printable_characters = 43;

  SessionStringGenerator gen;

  auto state1 = gen.GenerateState();
  ASSERT_EQ(expected_number_of_printable_characters, state1.length());

  auto state2 = gen.GenerateState();
  ASSERT_EQ(expected_number_of_printable_characters, state2.length());

  ASSERT_NE(state1, state2);
}

TEST(SessionStringGeneratorTest, GenerateNonce) {
  int expected_number_of_printable_characters = 43;

  SessionStringGenerator gen;

  auto nonce1 = gen.GenerateNonce();
  ASSERT_EQ(expected_number_of_printable_characters, nonce1.length());

  auto nonce2 = gen.GenerateNonce();
  ASSERT_EQ(expected_number_of_printable_characters, nonce2.length());

  ASSERT_NE(nonce1, nonce2);
}

}  // namespace session
}  // namespace common
}  // namespace authservice
