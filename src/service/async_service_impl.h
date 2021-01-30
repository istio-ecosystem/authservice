#ifndef AUTHSERVICE_ASYNC_SERVICE_IMPL_H
#define AUTHSERVICE_ASYNC_SERVICE_IMPL_H

#include "envoy/service/auth/v2/external_auth.grpc.pb.h"
#include "envoy/service/auth/v3/external_auth.grpc.pb.h"
#include "config/config.pb.h"
#include "src/filters/filter_chain.h"
#include <boost/asio.hpp>
#include <grpcpp/grpcpp.h>

namespace authservice {
namespace service {

::grpc::Status CheckV2(
        const ::envoy::service::auth::v2::CheckRequest *request,
        ::envoy::service::auth::v2::CheckResponse *response,
        std::vector<std::unique_ptr<filters::FilterChain>> &chains,
        const google::protobuf::RepeatedPtrField<config::TriggerRule> &trigger_rules_config,
        boost::asio::io_context& ioc,
        boost::asio::yield_context yield);

::grpc::Status Check(
        const ::envoy::service::auth::v3::CheckRequest *request,
        ::envoy::service::auth::v3::CheckResponse *response,
        std::vector<std::unique_ptr<filters::FilterChain>> &chains,
        const google::protobuf::RepeatedPtrField<config::TriggerRule> &trigger_rules_config,
        boost::asio::io_context& ioc,
        boost::asio::yield_context yield);

class ServiceState {
 public:
  virtual ~ServiceState() = default;

  virtual void Proceed() = 0;
};

class ProcessingStateFactory;

class ProcessingStateV2 : public ServiceState {
 public:
   explicit ProcessingStateV2(ProcessingStateFactory& parent, 
      envoy::service::auth::v2::Authorization::AsyncService &service);
  
   void Proceed() override;
  
 private:
  ProcessingStateFactory& parent_;
  grpc::ServerContext ctx_;

  envoy::service::auth::v2::Authorization::AsyncService& service_;
  envoy::service::auth::v2::CheckRequest request_;
  grpc::ServerAsyncResponseWriter<envoy::service::auth::v2::CheckResponse> responder_;
};

class ProcessingState : public ServiceState {
 public:
  ProcessingState(ProcessingStateFactory& parent, 
      envoy::service::auth::v3::Authorization::AsyncService &service);

  void Proceed() override;

 private:
  ProcessingStateFactory& parent_;
  grpc::ServerContext ctx_;


  envoy::service::auth::v3::Authorization::AsyncService& service_;
  envoy::service::auth::v3::CheckRequest request_;
  grpc::ServerAsyncResponseWriter<envoy::service::auth::v3::CheckResponse> responder_;
};

class CompleteState : public ServiceState {
 public:
  explicit CompleteState(ProcessingStateV2 *processor) : processor_v2_(processor) {
  }
  explicit CompleteState(ProcessingState *processor) : processor_v3_(processor) {
  }

  void Proceed() override;

 private:
  ProcessingStateV2 *processor_v2_;
  ProcessingState *processor_v3_;
};

class ProcessingStateFactory {
 public:
  ProcessingStateFactory(std::vector<std::unique_ptr<filters::FilterChain>> &chains,
                  const google::protobuf::RepeatedPtrField<config::TriggerRule> &trigger_rules_config,
                  grpc::ServerCompletionQueue &cq, boost::asio::io_context &io_context);

  ProcessingStateV2* createV2(envoy::service::auth::v2::Authorization::AsyncService &service);
  ProcessingState* create(envoy::service::auth::v3::Authorization::AsyncService &service);

 private:
  grpc::ServerCompletionQueue &cq_;

  // Boost::ASIO I/O service
  boost::asio::io_context &io_context_;

  std::vector<std::unique_ptr<filters::FilterChain>> &chains_;
  const google::protobuf::RepeatedPtrField<config::TriggerRule> &trigger_rules_config_;

  friend class ProcessingStateV2;
  friend class ProcessingState;
};

class AsyncAuthServiceImpl {
 public:
  explicit AsyncAuthServiceImpl(config::Config config);

  void Run();

 private:
  config::Config config_;

  std::vector<std::unique_ptr<filters::FilterChain>> chains_;

  envoy::service::auth::v2::Authorization::AsyncService service_v2_;
  envoy::service::auth::v3::Authorization::AsyncService service_;
  std::unique_ptr<grpc::ServerCompletionQueue> cq_;
  std::unique_ptr<grpc::Server> server_;

  std::shared_ptr<boost::asio::io_context> io_context_;

  std::chrono::seconds interval_in_seconds_;
  boost::asio::steady_timer timer_;
  std::function<void(const boost::system::error_code &ec)> timer_handler_function_;

  std::unique_ptr<ProcessingStateFactory> state_factory_;

  void SchedulePeriodicCleanupTask();
};

}
}

#endif //AUTHSERVICE_ASYNC_SERVICE_IMPL_H
