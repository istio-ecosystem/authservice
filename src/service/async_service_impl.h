#ifndef AUTHSERVICE_ASYNC_SERVICE_IMPL_H
#define AUTHSERVICE_ASYNC_SERVICE_IMPL_H

#include <grpcpp/grpcpp.h>
#include <spdlog/spdlog.h>

#include <boost/asio.hpp>

#include "common/config/version_converter.h"
#include "config/config.pb.h"
#include "envoy/common/exception.h"
#include "envoy/service/auth/v2/external_auth.grpc.pb.h"
#include "envoy/service/auth/v3/external_auth.grpc.pb.h"
#include "src/common/http/http.h"
#include "src/common/utilities/trigger_rules.h"
#include "src/filters/filter_chain.h"

namespace authservice {
namespace service {

template <class RequestType, class ResponseType>
::grpc::Status Check(
    const RequestType &request, ResponseType &response,
    std::vector<std::unique_ptr<filters::FilterChain>> &chains,
    const google::protobuf::RepeatedPtrField<config::TriggerRule>
        &trigger_rules_config,
    boost::asio::io_context &ioc, boost::asio::yield_context yield) {
  spdlog::trace("{}", __func__);

  envoy::service::auth::v3::CheckRequest request_v3;

  if constexpr (std::is_same_v<RequestType,
                               ::envoy::service::auth::v2::CheckRequest>) {
    Envoy::Config::VersionConverter::upgrade(
        static_cast<const google::protobuf::Message &>(request), request_v3);
  } else if (std::is_same_v<RequestType,
                            ::envoy::service::auth::v3::CheckRequest>) {
    request_v3 = request;
  }

  try {
    auto request_path = common::http::PathQueryFragment(
                            request_v3.attributes().request().http().path())
                            .Path();

    if (!common::utilities::trigger_rules::TriggerRuleMatchesPath(
            request_path, trigger_rules_config)) {
      spdlog::debug(
          "{}: no matching trigger rule, so allowing request to proceed "
          "without any authservice functionality {}://{}{} ",
          __func__, request_v3.attributes().request().http().scheme(),
          request_v3.attributes().request().http().host(),
          request_v3.attributes().request().http().path());
      return ::grpc::Status::OK;
    }

    // Find a configured processing chain.
    for (auto &chain : chains) {
      if (chain->Matches(&request_v3)) {
        spdlog::debug(
            "{}: processing request {}://{}{} with filter chain {}", __func__,
            request_v3.attributes().request().http().scheme(),
            request_v3.attributes().request().http().host(),
            request_v3.attributes().request().http().path(), chain->Name());
        envoy::service::auth::v3::CheckResponse response_v3;

        // Create a new instance of a processor.
        auto processor = chain->New();
        auto status = processor->Process(&request_v3, &response_v3, ioc, yield);

        // response v2/v3 conversion layer
        if constexpr (std::is_same_v<
                          ResponseType,
                          ::envoy::service::auth::v2::CheckResponse>) {
          try {
            auto dynamic_response = Envoy::Config::VersionConverter::downgrade(
                static_cast<const google::protobuf::Message &>(response_v3));
            response.CopyFrom(*dynamic_response->msg_);
          } catch (Envoy::EnvoyException &) {
            spdlog::error("{}: Failed to convert v2 response to v3", __func__);
            return ::grpc::Status::CANCELLED;
          }
        } else if (std::is_same_v<ResponseType,
                                  ::envoy::service::auth::v3::CheckResponse>) {
          response = response_v3;
        }

        // See src/filters/filter.h:filter::Process for a description of how
        // status codes should be handled
        switch (status) {
          case google::rpc::Code::OK:  // The request was successful
          case google::rpc::Code::UNAUTHENTICATED:    // A filter indicated the
                                                      // request had no
                                                      // authentication but was
                                                      // processed correctly.
          case google::rpc::Code::PERMISSION_DENIED:  // A filter indicated
            // insufficient permissions
            // for the authenticated
            // requester but was processed
            // correctly.
            return ::grpc::Status::OK;
          case google::rpc::Code::INVALID_ARGUMENT:  // The request was not well
            // formed. Indicate a
            // processing error to the
            // caller.
            return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT,
                                  "invalid request");
          default:  // All other errors are treated as internal processing
                    // failures.
            return ::grpc::Status(::grpc::StatusCode::INTERNAL,
                                  "internal error");
        }
      }
    }

    // No matching filter chain found. Allow request to continue.
    spdlog::debug("{}: no matching filter chain for request to {}://{}{} ",
                  __func__, request.attributes().request().http().scheme(),
                  request.attributes().request().http().host(),
                  request.attributes().request().http().path());
    return ::grpc::Status::OK;
  } catch (const std::exception &exception) {
    spdlog::error("%s unexpected error: %s", __func__, exception.what());
  } catch (...) {
    spdlog::error("%s unexpected error: unknown", __func__);
  }
  return ::grpc::Status(::grpc::StatusCode::INTERNAL, "internal error");
}

class ServiceState {
 public:
  virtual ~ServiceState() = default;

  virtual void Proceed() = 0;
};

class ProcessingStateFactory;

class ProcessingStateV2 : public ServiceState {
 public:
  explicit ProcessingStateV2(
      ProcessingStateFactory &parent,
      envoy::service::auth::v2::Authorization::AsyncService &service);

  void Proceed() override;

 private:
  ProcessingStateFactory &parent_;
  grpc::ServerContext ctx_;

  envoy::service::auth::v2::Authorization::AsyncService &service_;
  envoy::service::auth::v2::CheckRequest request_;
  grpc::ServerAsyncResponseWriter<envoy::service::auth::v2::CheckResponse>
      responder_;
};

class ProcessingState : public ServiceState {
 public:
  ProcessingState(
      ProcessingStateFactory &parent,
      envoy::service::auth::v3::Authorization::AsyncService &service);

  void Proceed() override;

 private:
  ProcessingStateFactory &parent_;
  grpc::ServerContext ctx_;

  envoy::service::auth::v3::Authorization::AsyncService &service_;
  envoy::service::auth::v3::CheckRequest request_;
  grpc::ServerAsyncResponseWriter<envoy::service::auth::v3::CheckResponse>
      responder_;
};

class CompleteState : public ServiceState {
 public:
  explicit CompleteState(ProcessingStateV2 *processor)
      : processor_v2_(processor), processor_v3_(nullptr) {}
  explicit CompleteState(ProcessingState *processor)
      : processor_v2_(nullptr), processor_v3_(processor) {}

  void Proceed() override;

 private:
  ProcessingStateV2 *processor_v2_;
  ProcessingState *processor_v3_;
};

class ProcessingStateFactory {
 public:
  ProcessingStateFactory(
      std::vector<std::unique_ptr<filters::FilterChain>> &chains,
      const google::protobuf::RepeatedPtrField<config::TriggerRule>
          &trigger_rules_config,
      grpc::ServerCompletionQueue &cq, boost::asio::io_context &io_context);

  ProcessingStateV2 *createV2(
      envoy::service::auth::v2::Authorization::AsyncService &service);
  ProcessingState *create(
      envoy::service::auth::v3::Authorization::AsyncService &service);

 private:
  grpc::ServerCompletionQueue &cq_;

  // Boost::ASIO I/O service
  boost::asio::io_context &io_context_;

  std::vector<std::unique_ptr<filters::FilterChain>> &chains_;
  const google::protobuf::RepeatedPtrField<config::TriggerRule>
      &trigger_rules_config_;

  friend class ProcessingStateV2;
  friend class ProcessingState;
};

class AsyncAuthServiceImpl {
 public:
  explicit AsyncAuthServiceImpl(const config::Config &config);

  void Run();

 private:
  std::string address_and_port_;
  config::Config config_;

  std::vector<std::unique_ptr<filters::FilterChain>> chains_;

  envoy::service::auth::v2::Authorization::AsyncService service_v2_;
  envoy::service::auth::v3::Authorization::AsyncService service_;
  std::unique_ptr<grpc::ServerCompletionQueue> cq_;
  std::unique_ptr<grpc::Server> server_;

  std::shared_ptr<boost::asio::io_context> io_context_;

  std::chrono::seconds interval_in_seconds_;
  boost::asio::steady_timer timer_;
  std::function<void(const boost::system::error_code &ec)>
      timer_handler_function_;

  std::unique_ptr<ProcessingStateFactory> state_factory_;

  void SchedulePeriodicCleanupTask();
};

}  // namespace service
}  // namespace authservice

#endif  // AUTHSERVICE_ASYNC_SERVICE_IMPL_H
