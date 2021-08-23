#ifndef AUTHSERVICE_TEST_COMMON_HTTP_MOCKS_H_
#define AUTHSERVICE_TEST_COMMON_HTTP_MOCKS_H_

#include "gmock/gmock.h"
#include "src/common/http/http.h"

namespace authservice {
namespace common {
namespace http {
class HttpMock : public Http {
 public:
  MOCK_CONST_METHOD7(
      Post,
      response_t(absl::string_view uri,
                 const std::map<absl::string_view, absl::string_view> &headers,
                 absl::string_view body, absl::string_view ca_cert,
                 absl::string_view proxy_uri, boost::asio::io_context &ioc,
                 boost::asio::yield_context yield));

  MOCK_CONST_METHOD7(
      Get,
      response_t(absl::string_view uri,
                 const std::map<absl::string_view, absl::string_view> &headers,
                 absl::string_view body, absl::string_view ca_cert,
                 absl::string_view proxy_uri, boost::asio::io_context &ioc,
                 boost::asio::yield_context yield));
};
}  // namespace http
}  // namespace common
}  // namespace authservice
#endif  // AUTHSERVICE_TEST_COMMON_HTTP_MOCKS_H_
