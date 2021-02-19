#ifndef AUTHSERVICE_TEST_COMMON_SESSION_MOCKS_H_
#define AUTHSERVICE_TEST_COMMON_SESSION_MOCKS_H_

#include "gmock/gmock.h"
#include "src/common/session/session_string_generator.h"

namespace authservice {
namespace common {
namespace session {

class SessionStringGeneratorMock final : public SessionStringGenerator {
 public:
  MOCK_METHOD(std::string, GenerateSessionId, ());
  MOCK_METHOD(std::string, GenerateState, ());
  MOCK_METHOD(std::string, GenerateNonce, ());
};

}  // namespace session
}  // namespace common
}  // namespace authservice

#endif  // AUTHSERVICE_TEST_COMMON_SESSION_MOCKS_H_
