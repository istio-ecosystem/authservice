#ifndef AUTHSERVICE_SRC_FILTERS_PIPE_H_
#define AUTHSERVICE_SRC_FILTERS_PIPE_H_
#include <boost/asio.hpp>
#include <boost/asio/spawn.hpp>
#include <memory>
#include <mutex>
#include <vector>

#include "src/filters/filter.h"

namespace authservice {
namespace filters {

typedef std::unique_ptr<Filter> FilterPtr;

class Pipe final : public Filter {
 private:
  typedef std::vector<FilterPtr> FilterList;
  std::mutex mtx;
  FilterList filters_;

 public:
  Pipe *AddFilter(FilterPtr &&filter);
  Pipe *Remove(const std::string &filter);

  google::rpc::Code Process(
      const ::envoy::service::auth::v3::CheckRequest *request,
      ::envoy::service::auth::v3::CheckResponse *response,
      boost::asio::io_context &ioc, boost::asio::yield_context yield) override;

  // Required to inherit the 2-argument version of Process from the base class
  using filters::Filter::Process;

  absl::string_view Name() const override;
};

}  // namespace filters
}  // namespace authservice

#endif  // AUTHSERVICE_SRC_FILTERS_PIPE_TEST_H_
