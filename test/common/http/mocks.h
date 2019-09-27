#ifndef TRANSPARENT_AUTH_TEST_COMMON_HTTP_MOCKS_H_
#define TRANSPARENT_AUTH_TEST_COMMON_HTTP_MOCKS_H_
#include "gmock/gmock.h"
#include "src/common/http/http.h"
namespace transparent_auth {
namespace common {
namespace http {
class http_mock : public http {
 public:
  MOCK_CONST_METHOD3(
      Post,
      response_t(const common::http::Endpoint &endpoint,
                 const std::map<absl::string_view, absl::string_view> &headers,
                 absl::string_view body));
};
}  // namespace http
}  // namespace common
}  // namespace transparent_auth
#endif  // TRANSPARENT_AUTH_TEST_COMMON_HTTP_MOCKS_H_
