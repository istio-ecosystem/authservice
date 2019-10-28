#ifndef AUTHSERVICE_ASYNC_SERVICE_IMPL_H
#define AUTHSERVICE_ASYNC_SERVICE_IMPL_H

#include "service_impl.h"
#include "envoy/service/auth/v2/external_auth.grpc.pb.h"
#include <boost/asio.hpp>
#include <grpcpp/grpcpp.h>

using namespace envoy::service::auth::v2;

namespace authservice {
namespace service {

class AsyncAuthServiceImpl {
public:
  explicit AsyncAuthServiceImpl(std::shared_ptr<authservice::config::Config> config);

  void Run();

private:
  std::shared_ptr<authservice::config::Config> config_;

  envoy::service::auth::v2::Authorization::AsyncService service_;
  std::unique_ptr<grpc::ServerCompletionQueue> cq_;
  std::unique_ptr<grpc::Server> server_;

  std::shared_ptr<boost::asio::io_context> io_context_;
};

}
}

#endif //AUTHSERVICE_ASYNC_SERVICE_IMPL_H
