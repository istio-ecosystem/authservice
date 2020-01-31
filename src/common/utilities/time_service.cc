#include <chrono>
#include "time_service.h"

namespace authservice {
namespace common {
namespace utilities {

int64_t TimeService::GetCurrentTimeInSecondsSinceEpoch() {
  auto seconds = std::chrono::duration_cast<std::chrono::seconds>(
      std::chrono::system_clock::now().time_since_epoch()
  );
  return seconds.count();
}

}  // namespace utilities
}  // namespace common
}  // namespace authservice