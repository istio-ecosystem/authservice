#include "session_id_generator.h"
#include "src/common/utilities/random.h"

namespace authservice {
namespace common {
namespace session {

std::string SessionIdGenerator::Generate() {
  utilities::RandomGenerator generator;
  return generator.Generate(64).Str();
}

}  // namespace utilities
}  // namespace common
}  // namespace session
