#include "mock_filter.h"

#include <memory>

#include "spdlog/spdlog.h"

namespace authservice {
namespace filters {
namespace mock {
MockFilter::MockFilter(const config::mock::MockConfig &mock_config) {
  return_value_ =
      mock_config.allow() ? google::rpc::OK : google::rpc::PERMISSION_DENIED;
}

enum google::rpc::Code MockFilter::Process(
    const ::envoy::service::auth::v3::CheckRequest *,
    ::envoy::service::auth::v3::CheckResponse *, boost::asio::io_context &,
    boost::asio::yield_context) {
  spdlog::trace("{}: returning {}", __func__,
                return_value_ == google::rpc::OK ? "OK" : "PERMISSION_DENIED");
  return return_value_;
}

absl::string_view MockFilter::Name() const { return "mock"; }

filters::FilterPtr FilterFactory::create() {
  return std::make_unique<MockFilter>(config_);
}

}  // namespace mock
}  // namespace filters
}  // namespace authservice
