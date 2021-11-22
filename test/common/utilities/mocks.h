#ifndef AUTHSERVICE_TEST_COMMON_UTILITIES_MOCKS_H_
#define AUTHSERVICE_TEST_COMMON_UTILITIES_MOCKS_H_

#include "gmock/gmock.h"
#include "src/common/utilities/time_service.h"

namespace authservice {
namespace common {
namespace utilities {

class TimeServiceMock : public TimeService {
 public:
  MOCK_METHOD(int64_t, GetCurrentTimeInSecondsSinceEpoch, ());
};

}  // namespace utilities
}  // namespace common
}  // namespace authservice
#endif  // AUTHSERVICE_TEST_COMMON_UTILITIES_MOCKS_H_
