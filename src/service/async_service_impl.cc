#include "async_service_impl.h"

#include <grpcpp/server_builder.h>

#include <boost/asio.hpp>
#include <boost/thread/thread.hpp>
#include <memory>
#include <stdexcept>

#include "rpc/healthcheck.pb.h"
#include "src/common/http/http.h"
#include "src/config/get_config.h"

namespace authservice {
namespace service {

ProcessingStateV2::ProcessingStateV2(
    ProcessingStateFactory &parent,
    envoy::service::auth::v2::Authorization::AsyncService &service)
    : parent_(parent), service_(service), responder_(&ctx_) {
  spdlog::warn(
      "Creating V2 request processor state. V2 will be deprecated in 2021 Q1");
  service_.RequestCheck(&ctx_, &request_, &responder_, &parent_.cq_,
                        &parent_.cq_, this);
}

void ProcessingStateV2::Proceed() {
  // Spawn a new instance to serve new clients while we process this one
  // This will later be pulled off the queue for processing and ultimately
  // deleted in the destructor of CompleteState
  parent_.createV2(service_);

  spdlog::trace("Launching V2 request processor worker");

  boost::asio::spawn(
      parent_.io_context_, [this](boost::asio::yield_context yield) {
        spdlog::trace("Processing V2 request");

        envoy::service::auth::v2::CheckResponse response;
        authservice::service::Check(request_, response, parent_.chains_,
                                    parent_.trigger_rules_config_,
                                    parent_.io_context_, yield);

        this->responder_.Finish(response, grpc::Status::OK,
                                new CompleteState(this));

        spdlog::trace("Request processing complete");
      });
}

ProcessingState::ProcessingState(
    ProcessingStateFactory &parent,
    envoy::service::auth::v3::Authorization::AsyncService &service)
    : parent_(parent), service_(service), responder_(&ctx_) {
  spdlog::trace("Creating V3 request processor state");
  service_.RequestCheck(&ctx_, &request_, &responder_, &parent_.cq_,
                        &parent_.cq_, this);
}

void ProcessingState::Proceed() {
  // Spawn a new instance to serve new clients while we process this one
  // This will later be pulled off the queue for processing and ultimately
  // deleted in the destructor of CompleteState
  parent_.create(service_);

  spdlog::trace("Launching request processor worker");

  // The actual processing.
  // Invokes this lambda on any available thread running the run() method of
  // this io_context_ instance.
  boost::asio::spawn(
      parent_.io_context_, [this](boost::asio::yield_context yield) {
        spdlog::trace("Processing request");

        envoy::service::auth::v3::CheckResponse response;
        authservice::service::Check(request_, response, parent_.chains_,
                                    parent_.trigger_rules_config_,
                                    parent_.io_context_, yield);

        this->responder_.Finish(response, grpc::Status::OK,
                                new CompleteState(this));

        spdlog::trace("Request processing complete");
      });
}

void CompleteState::Proceed() {
  spdlog::trace("Processing completion and deleting state");

  if (!processor_v2_) delete processor_v2_;

  if (!processor_v3_) delete processor_v3_;

  delete this;
}

void ActiveHealthcheckState::Proceed() {
  new ActiveHealthcheckState(cq_, chains_, service_);

  grpc::health::v1::HealthCheckResponse response;
  grpc::health::v1::HealthCheckResponse::ServingStatus status =
      grpc::health::v1::HealthCheckResponse::SERVING;

  for (auto &&chain : chains_) {
    if (!chain->jwksActive()) {
      status = grpc::health::v1::HealthCheckResponse::NOT_SERVING;
    }
  }

  response.set_status(status);
  this->responder_.Finish(response, grpc::Status::OK,
                          new HealthcheckResponseCompletionState(this));
}

void HealthcheckResponseCompletionState::Proceed() {
  delete active_health_state_;
  delete this;
}

ProcessingStateFactory::ProcessingStateFactory(
    std::vector<std::unique_ptr<filters::FilterChain>> &chains,
    const google::protobuf::RepeatedPtrField<config::TriggerRule>
        &trigger_rules_config,
    grpc::ServerCompletionQueue &cq, boost::asio::io_context &io_context)
    : cq_(cq),
      io_context_(io_context),
      chains_(chains),
      trigger_rules_config_(trigger_rules_config) {}

ProcessingStateV2 *ProcessingStateFactory::createV2(
    envoy::service::auth::v2::Authorization::AsyncService &service) {
  return new ProcessingStateV2(*this, service);
}

ProcessingState *ProcessingStateFactory::create(
    envoy::service::auth::v3::Authorization::AsyncService &service) {
  return new ProcessingState(*this, service);
}

AsyncAuthServiceImpl::AsyncAuthServiceImpl(const config::Config &config)
    : address_and_port_(
          fmt::format("{}:{}", config.listen_address(), config.listen_port())),
      config_(config),
      io_context_(std::make_shared<boost::asio::io_context>()),
      interval_in_seconds_(60),
      timer_(*io_context_, interval_in_seconds_) {
  for (const auto &chain_config : config_.chains()) {
    auto chain = std::make_unique<filters::FilterChainImpl>(
        *io_context_, chain_config, config_.threads());
    chains_.push_back(std::move(chain));
  }
  grpc::ServerBuilder builder;
  builder.AddListeningPort(address_and_port_,
                           grpc::InsecureServerCredentials());
  builder.RegisterService(&service_);
  builder.RegisterService(&service_v2_);
  builder.RegisterService(&health_service_);
  cq_ = builder.AddCompletionQueue();
  server_ = builder.BuildAndStart();

  state_factory_ = std::make_unique<ProcessingStateFactory>(
      chains_, config_.trigger_rules(), *cq_, *io_context_);
}

void AsyncAuthServiceImpl::Run() {
  // Add a work object to the IO service so it will not shut down when it has
  // nothing left to do
  auto work = std::make_shared<boost::asio::io_context::work>(*io_context_);

  SchedulePeriodicCleanupTask();

  // Spin up our worker threads
  // Config validation should have already ensured that the number of threads is
  // > 0
  boost::thread_group threadpool;
  for (unsigned int i = 0; i < config_.threads(); ++i) {
    threadpool.create_thread([this]() {
      while (true) {
        try {
          // The asio library provides a guarantee that callback handlers will
          // only be called from threads that are currently calling
          // io_context::run(). The io_context::run() function will also
          // continue to run while there is still "work" to do. Async methods
          // which take a boost::asio::yield_context as an argument will use
          // that yield as a callback handler when the async operation has
          // completed. The yield_context will restore the stack, registers, and
          // execution pointer of the calling method, effectively allowing that
          // method to pick up right where it left off, and continue on any
          // worker thread.
          this->io_context_
              ->run();  // run the io_context's event processing loop
          break;
        } catch (std::exception &e) {
          spdlog::error("Unexpected error in worker thread: {}", e.what());
        }
      }
    });
  }

  spdlog::info("{}: Server listening on {}", __func__, address_and_port_);

  try {
    // Spawn a new state instance to serve new clients
    // This will later be pulled off the queue for processing and ultimately
    // deleted in the destructor of CompleteState
    state_factory_->create(service_);
    state_factory_->createV2(service_v2_);
    new ActiveHealthcheckState(*cq_, chains_, health_service_);

    void *tag;
    bool ok;
    while (cq_->Next(&tag, &ok)) {
      // Block waiting to read the next event from the completion queue. The
      // event is uniquely identified by its tag, which in this case is the
      // memory address of a CallData instance.
      // The return value of Next should always be checked. This return value
      // tells us whether there is any kind of event or cq_ is shutting down.
      if (!ok) {
        spdlog::error("{}: Unexpected error: !ok", __func__);
      }
      static_cast<ServiceState *>(tag)->Proceed();
    }
  } catch (const std::exception &e) {
    spdlog::error("{}: Unexpected error: {}", __func__, e.what());
  }

  spdlog::info("Server shutting down");

  // Start shutting down gRPC
  server_->Shutdown();
  cq_->Shutdown();

  // The destructor of the completion queue will abort if there are any
  // outstanding events, so we must drain the queue before we allow that to
  // happen
  try {
    void *tag;
    bool ok;
    while (cq_->Next(&tag, &ok)) {
      delete static_cast<ServiceState *>(tag);
    }
  } catch (const std::exception &e) {
    spdlog::error("{}: Unexpected error: {}", __func__, e.what());
  }

  // Reset the work item for the IO service will terminate once it finishes any
  // outstanding jobs
  work.reset();
  threadpool.join_all();
}

void AsyncAuthServiceImpl::SchedulePeriodicCleanupTask() {
  timer_handler_function_ = [this](const boost::system::error_code &ec) {
    spdlog::info("{}: Starting periodic cleanup (period of {} seconds)",
                 __func__, interval_in_seconds_.count());

    for (const auto &chain : chains_) {
      chain->DoPeriodicCleanup();
    }

    // Reset the timer for some seconds in the future
    timer_.expires_at(std::chrono::steady_clock::now() + interval_in_seconds_);

    // Schedule the next invocation of this same handler on the same timer
    timer_.async_wait(timer_handler_function_);
  };

  // Schedule the first invocation of the handler on the timer
  timer_.async_wait(timer_handler_function_);
}

}  // namespace service
}  // namespace authservice