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
  explicit AsyncAuthServiceImpl(config::Config config);

  void Run();

private:
  config::Config config_;
  AuthServiceImpl impl_;

  envoy::service::auth::v2::Authorization::AsyncService service_;
  std::unique_ptr<grpc::ServerCompletionQueue> cq_;
  std::unique_ptr<grpc::Server> server_;

  std::shared_ptr<boost::asio::io_context> io_context_;

  std::chrono::seconds interval_in_seconds_;
  boost::asio::steady_timer timer_;
  std::function<void (const boost::system::error_code &ec)> timer_handler_function_;

  void SchedulePeriodicCleanupTask();
};

}
}

#endif //AUTHSERVICE_ASYNC_SERVICE_IMPL_H
