#include "async_service_impl.h"
#include "src/config/get_config.h"
#include <boost/asio.hpp>
#include <boost/thread/thread.hpp>
#include <grpcpp/server_builder.h>
#include "src/common/http/http.h"
#include "src/common/utilities/trigger_rules.h"

namespace authservice {
namespace service {

ProcessingState::ProcessingState(std::vector<std::unique_ptr<filters::FilterChain>> &chains,
                const google::protobuf::RepeatedPtrField<config::TriggerRule> &trigger_rules_config,
                Authorization::AsyncService &service,
                grpc::ServerCompletionQueue &cq,
                boost::asio::io_context &io_context) : chains_(chains),
                                                      trigger_rules_config_(trigger_rules_config),
                                                      service_(service),
                                                      cq_(cq),
                                                      responder_(&ctx_),
                                                      io_context_(io_context) {
  spdlog::trace("Creating processor state");
  service.RequestCheck(&ctx_, &request_, &responder_, &cq_, &cq_, this);
}

::grpc::Status Check(
    const ::envoy::service::auth::v2::CheckRequest *request,
    ::envoy::service::auth::v2::CheckResponse *response,
                          std::vector<std::unique_ptr<filters::FilterChain>> &chains,
            const google::protobuf::RepeatedPtrField<config::TriggerRule> &trigger_rules_config,
            boost::asio::io_context& ioc,
            boost::asio::yield_context yield) {
              spdlog::trace("{}", __func__);
              try {
                auto request_path = common::http::PathQueryFragment(request->attributes().request().http().path()).Path();
                if (!common::utilities::trigger_rules::TriggerRuleMatchesPath(request_path, trigger_rules_config)) {
                  spdlog::debug(
          "{}: no matching trigger rule, so allowing request to proceed without any authservice functionality {}://{}{} ",
          __func__,
          request->attributes().request().http().scheme(), request->attributes().request().http().host(),
          request->attributes().request().http().path());
      return ::grpc::Status::OK;
    }

    // Find a configured processing chain.
    for (auto &chain : chains) {
      if (chain->Matches(request)) {
        spdlog::debug("{}: processing request {}://{}{} with filter chain {}", __func__,
                      request->attributes().request().http().scheme(), request->attributes().request().http().host(),
                      request->attributes().request().http().path(), chain->Name());
        // Create a new instance of a processor.
        auto processor = chain->New();
        auto status = processor->Process(request, response, ioc, yield);
        // See src/filters/filter.h:filter::Process for a description of how status
        // codes should be handled
        switch (status) {
          case google::rpc::Code::OK:               // The request was successful
          case google::rpc::Code::UNAUTHENTICATED:  // A filter indicated the
            // request had no authentication
            // but was processed correctly.
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
          default:  // All other errors are treated as internal processing failures.
            return ::grpc::Status(::grpc::StatusCode::INTERNAL, "internal error");
        }
      }
    }

    // No matching filter chain found. Allow request to continue.
    spdlog::debug("{}: no matching filter chain for request to {}://{}{} ", __func__,
                  request->attributes().request().http().scheme(), request->attributes().request().http().host(),
                  request->attributes().request().http().path());
    return ::grpc::Status::OK;
  } catch (const std::exception &exception) {
    spdlog::error("%s unexpected error: %s", __func__, exception.what());
  } catch (...) {
    spdlog::error("%s unexpected error: unknown", __func__);
  }
  return ::grpc::Status(::grpc::StatusCode::INTERNAL, "internal error");
}

void ProcessingState::Proceed() {
  // Spawn a new instance to serve new clients while we process this one
  // This will later be pulled off the queue for processing and ultimately deleted in the destructor
  // of CompleteState
  new ProcessingState(chains_, trigger_rules_config_, service_, cq_, io_context_);

  spdlog::trace("Launching request processor worker");

  // The actual processing.
  // Invokes this lambda on any available thread running the run() method of this io_context_ instance.
  boost::asio::spawn(io_context_, [this](boost::asio::yield_context yield) {
    spdlog::trace("Processing request");

    CheckResponse response;
    authservice::service::Check(&request_, &response, chains_, trigger_rules_config_, this->io_context_, yield);

    this->responder_.Finish(response, grpc::Status::OK, new CompleteState(this));

    spdlog::trace("Request processing complete");
  });
}

void CompleteState::Proceed() {
  spdlog::trace("Processing completion and deleting state");

  delete processor_;
  delete this;
}

AsyncAuthServiceImpl::AsyncAuthServiceImpl(config::Config config)
    : config_(std::move(config)),
      io_context_(std::make_shared<boost::asio::io_context>()),
      interval_in_seconds_(60),
      timer_(*io_context_, interval_in_seconds_) {
  for (const auto &chain_config : config_.chains()) {
    std::unique_ptr<filters::FilterChain> chain(new filters::FilterChainImpl(chain_config));
    chains_.push_back(std::move(chain));
  }
  grpc::ServerBuilder builder;
  builder.AddListeningPort(config::GetConfiguredAddress(config_), grpc::InsecureServerCredentials());
  builder.RegisterService(&service_);
  cq_ = builder.AddCompletionQueue();
  server_ = builder.BuildAndStart();
}

void AsyncAuthServiceImpl::Run() {
  // Add a work object to the IO service so it will not shut down when it has nothing left to do
  auto work = std::make_shared<boost::asio::io_context::work>(*io_context_);

  SchedulePeriodicCleanupTask();

  // Spin up our worker threads
  // Config validation should have already ensured that the number of threads is > 0
  boost::thread_group threadpool;
  for (unsigned int i = 0; i < config_.threads(); ++i) {
    threadpool.create_thread([this](){
      while(true) {
        try {
          // The asio library provides a guarantee that callback handlers will only
          // be called from threads that are currently calling io_context::run().
          // The io_context::run() function will also continue to run while there
          // is still "work" to do.
          // Async methods which take a boost::asio::yield_context as an argument
          // will use that yield as a callback handler when the async operation has completed.
          // The yield_context will restore the stack, registers, and execution pointer
          // of the calling method, effectively allowing that method to pick up
          // right where it left off, and continue on any worker thread.
          this->io_context_->run(); // run the io_context's event processing loop
          break;
        } catch(std::exception & e) {
          spdlog::error("Unexpected error in worker thread: {}", e.what());
        }
      }
    });
  }

  spdlog::info("{}: Server listening on {}", __func__, config::GetConfiguredAddress(config_));

  try {
    // Spawn a new state instance to serve new clients
    // This will later be pulled off the queue for processing and ultimately deleted in the destructor
    // of CompleteState
    new ProcessingState(chains_, config_.trigger_rules(), service_, *cq_, *io_context_);

    void *tag;
    bool ok;
    while (cq_->Next(&tag, &ok)) {
      // Block waiting to read the next event from the completion queue. The
      // event is uniquely identified by its tag, which in this case is the
      // memory address of a CallData instance.
      // The return value of Next should always be checked. This return value
      // tells us whether there is any kind of event or cq_ is shutting down.
      if(!ok) {
        spdlog::error("{}: Unexpected error: !ok", __func__);
        break;
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

  // The destructor of the completion queue will abort if there are any outstanding events, so we
  // must drain the queue before we allow that to happen
  try {
    void *tag;
    bool ok;
    while (cq_->Next(&tag, &ok)) {
      delete static_cast<ServiceState *>(tag);
    }
  } catch (const std::exception &e) {
    spdlog::error("{}: Unexpected error: {}", __func__, e.what());
  }

  // Reset the work item for the IO service will terminate once it finishes any outstanding jobs
  work.reset();
  threadpool.join_all();
}

void AsyncAuthServiceImpl::SchedulePeriodicCleanupTask() {
  timer_handler_function_ = [this](const boost::system::error_code &ec) {
    spdlog::info("{}: Starting periodic cleanup (period of {} seconds)", __func__, interval_in_seconds_.count());

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

}
}