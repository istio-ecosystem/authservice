#include "simple_filter.h"

#include "spdlog/spdlog.h"

namespace authservice {
namespace filters {
namespace simple {
SimpleFilter::SimpleFilter(const config::simple::SimpleConfig &simple_config) {
  return_value_ =
      simple_config.allow() ? google::rpc::OK : google::rpc::PERMISSION_DENIED;
}

enum google::rpc::Code SimpleFilter::Process(
    const ::envoy::service::auth::v3::CheckRequest *,
    ::envoy::service::auth::v3::CheckResponse *, boost::asio::io_context &,
    boost::asio::yield_context) {
  spdlog::trace("{}: returning {}", __func__,
                return_value_ == google::rpc::OK ? "OK" : "PERMISSION_DENIED");
  return return_value_;
}

absl::string_view SimpleFilter::Name() const { return "simple"; }

}  // namespace simple
}  // namespace filters
}  // namespace authservice
