#ifndef AUTHSERVICE_TEST_COMMON_HTTP_MOCKS_H_
#define AUTHSERVICE_TEST_COMMON_HTTP_MOCKS_H_
#include "gmock/gmock.h"
#include "src/common/http/http.h"
namespace authservice {
namespace common {
namespace http {
class http_mock : public http {
 public:
  MOCK_CONST_METHOD3(
      Post,
      response_t(const authservice::config::common::Endpoint &endpoint,
                 const std::map<absl::string_view, absl::string_view> &headers,
                 absl::string_view body));

  MOCK_CONST_METHOD5(
          Post,
          response_t(const authservice::config::common::Endpoint &endpoint,
                  const std::map<absl::string_view, absl::string_view> &headers,
                  absl::string_view body,
                  boost::asio::io_context& ioc,
                  boost::asio::yield_context yield));
};
}  // namespace http
}  // namespace common
}  // namespace authservice
#endif  // AUTHSERVICE_TEST_COMMON_HTTP_MOCKS_H_
