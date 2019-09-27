#ifndef TRANSPARENT_AUTH_SRC_FILTERS_PIPE_H_
#define TRANSPARENT_AUTH_SRC_FILTERS_PIPE_H_
#include <memory>
#include <mutex>
#include <vector>

#include "src/filters/filter.h"

namespace transparent_auth {
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
      const ::envoy::service::auth::v2::CheckRequest *request,
      ::envoy::service::auth::v2::CheckResponse *response) override;
  absl::string_view Name() const override;
};

}  // namespace filters
}  // namespace transparent_auth

#endif  // TRANSPARENT_AUTH_SRC_FILTERS_PIPE_TEST_H_
