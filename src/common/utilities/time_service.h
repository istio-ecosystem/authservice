#ifndef AUTHSERVICE_TIME_SERVICE_H
#define AUTHSERVICE_TIME_SERVICE_H

#include <cstdint>

namespace authservice {
namespace common {
namespace utilities {

class TimeService {
 public:
  virtual int64_t GetCurrentTimeInSecondsSinceEpoch();
};

}  // namespace utilities
}  // namespace common
}  // namespace authservice

#endif  // AUTHSERVICE_TIME_SERVICE_H
