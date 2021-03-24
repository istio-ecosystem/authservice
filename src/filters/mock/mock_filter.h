
#ifndef AUTHSERVICE_SRC_FILTERS_MOCK_MOCK_FILTER_H_
#define AUTHSERVICE_SRC_FILTERS_MOCK_MOCK_FILTER_H_
#include "config/mock/config.pb.h"
#include "google/rpc/code.pb.h"
#include "src/filters/filter.h"

namespace authservice {
namespace filters {
namespace mock {

class MockFilter final : public filters::Filter {
 private:
  enum google::rpc::Code return_value_;

 public:
  MockFilter(const config::mock::MockConfig &mock_config);

  google::rpc::Code Process(
      const ::envoy::service::auth::v3::CheckRequest *request,
      ::envoy::service::auth::v3::CheckResponse *response,
      boost::asio::io_context &ioc, boost::asio::yield_context yield) override;

  absl::string_view Name() const override;
};
}  // namespace mock
}  // namespace filters
}  // namespace authservice
#endif
