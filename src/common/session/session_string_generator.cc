#include "session_string_generator.h"
#include "src/common/utilities/random.h"

namespace authservice {
namespace common {
namespace session {

std::string SessionStringGenerator::GenerateSessionId() {
  return GenerateRandomString(64);
}

std::string SessionStringGenerator::GenerateNonce() {
  return GenerateRandomString(32);
}

std::string SessionStringGenerator::GenerateState() {
  return GenerateRandomString(32);
}

std::string SessionStringGenerator::GenerateRandomString(int size) {
  utilities::RandomGenerator generator;
  return generator.Generate(size).Str();
}

}  // namespace utilities
}  // namespace common
}  // namespace session
