#ifndef AUTHSERVICE_TEST_COMMON_HTTP_MOCKS_H_
#define AUTHSERVICE_TEST_COMMON_HTTP_MOCKS_H_

#include "gmock/gmock.h"
#include "src/common/http/http.h"

namespace authservice {
namespace common {
namespace http {
class HttpMock : public Http {
 public:
  MOCK_METHOD(response_t, Post,
              (absl::string_view,
               (const std::map<absl::string_view, absl::string_view> &),
               absl::string_view, const TransportSocketOptions &,
               absl::string_view, boost::asio::io_context &,
               boost::asio::yield_context),
              (const));

  MOCK_METHOD(response_t, Get,
              (absl::string_view,
               (const std::map<absl::string_view, absl::string_view> &),
               absl::string_view, const TransportSocketOptions &,
               absl::string_view, boost::asio::io_context &,
               boost::asio::yield_context),
              (const));

  MOCK_METHOD(response_t, SimpleGet,
              (absl::string_view,
               (const std::map<absl::string_view, absl::string_view> &),
               absl::string_view, boost::asio::io_context &,
               boost::asio::yield_context),
              (const));
};
}  // namespace http
}  // namespace common
}  // namespace authservice
#endif  // AUTHSERVICE_TEST_COMMON_HTTP_MOCKS_H_
