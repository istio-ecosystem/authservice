#include "pipe.h"
#include "google/rpc/code.pb.h"
#include "grpcpp/support/status.h"

namespace authservice {
namespace filters {
namespace {
const char *filter_name_ = "pipe";
}  // namespace

Pipe *Pipe::AddFilter(FilterPtr &&filter) {
  std::unique_lock<std::mutex> lock(mtx);
  filters_.push_back(std::move(filter));
  return this;
}

Pipe *Pipe::Remove(const std::string &filter) {
  std::unique_lock<std::mutex> lock(mtx);
  for (auto f = filters_.begin(); f != filters_.end(); ++f) {
    if ((*f)->Name() == filter) {
      filters_.erase(f);
    }
  }
  return this;
}

google::rpc::Code Pipe::Process(
        const ::envoy::service::auth::v2::CheckRequest *request,
        ::envoy::service::auth::v2::CheckResponse *response,
        boost::asio::io_context& ioc,
        boost::asio::yield_context yield) {
  std::unique_lock<std::mutex> lock(mtx);
  for (auto &filter : filters_) {
    auto result = filter->Process(request, response, ioc, yield);
    if (result != google::rpc::Code::OK) {
      response->mutable_status()->set_code(result);
      response->mutable_status()->set_message(filter->Name().data(),
                                              filter->Name().size());
      return result;
    }
  }
  response->mutable_status()->set_code(google::rpc::Code::OK);
  response->mutable_status()->set_message("OK");
  return google::rpc::Code::OK;
}

absl::string_view Pipe::Name() const { return filter_name_; }
}  // namespace filters
}  // namespace authservice
