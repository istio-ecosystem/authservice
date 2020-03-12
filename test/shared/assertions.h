#ifndef AUTHSERVICE_TEST_SHARED_ASSERTIONS_H_
#define AUTHSERVICE_TEST_SHARED_ASSERTIONS_H_

#include <functional>
#include "gtest/gtest.h"

namespace authservice {
namespace test_helpers {

void ASSERT_THROWS_STD_RUNTIME_ERROR(std::function<void()> lambda, const std::string& expected_message) {
  try {
    lambda();
  } catch(std::runtime_error& e) {
    if (std::string(e.what()) != expected_message) {
      FAIL() << "expected exception message '" << expected_message
             << "', but actual message was '" << std::string(e.what()) << "'";
    }
    return;
  } catch(...) {
    FAIL() << "expected to throw std::runtime_error, but threw some other kind of exception";
  }
  FAIL() << "expected to throw, but did not throw any exception";
}

}  // namespace test_helpers
}  // namespace authservice

#endif  // AUTHSERVICE_TEST_SHARED_ASSERTIONS_H_
