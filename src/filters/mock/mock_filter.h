
#ifndef AUTHSERVICE_SRC_FILTERS_MOCK_MOCK_FILTER_H_
#define AUTHSERVICE_SRC_FILTERS_MOCK_MOCK_FILTER_H_
#include "config/mock/config.pb.h"
#include "google/rpc/code.pb.h"
#include "src/filters/filter.h"
#include "src/filters/filter_factory.h"

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

class FilterFactory : public filters::FilterFactory {
 public:
  FilterFactory(const config::mock::MockConfig &config) : config_(config) {}

  filters::FilterPtr create() override;

 private:
  const config::mock::MockConfig config_;
};

}  // namespace mock
}  // namespace filters
}  // namespace authservice
#endif
