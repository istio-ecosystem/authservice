
#ifndef AUTHSERVICE_SRC_FILTERS_SIMPLE_SIMPLE_FILTER_H_
#define AUTHSERVICE_SRC_FILTERS_SIMPLE_SIMPLE_FILTER_H_
#include "config/simple/config.pb.h"
#include "google/rpc/code.pb.h"
#include "src/filters/filter.h"

namespace authservice {
namespace filters {
namespace simple {

class SimpleFilter final : public filters::Filter {
private:
  enum google::rpc::Code return_value_;
public:
  SimpleFilter(const config::simple::SimpleConfig &simple_config);

  google::rpc::Code Process(
      const ::envoy::service::auth::v3::CheckRequest *request,
      ::envoy::service::auth::v3::CheckResponse *response,
      boost::asio::io_context &ioc, boost::asio::yield_context yield) override;

  absl::string_view Name() const override;
};
}
}
}
#endif