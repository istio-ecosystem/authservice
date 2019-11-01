#include "async_service_impl.h"
#include "src/config/get_config.h"
#include <boost/asio.hpp>
#include <boost/thread/thread.hpp>
#include <grpcpp/grpcpp.h>
#include <grpcpp/server_builder.h>

namespace authservice {
namespace service {

class ServiceState {
public:
  virtual ~ServiceState() = default;

  virtual void Proceed() = 0;
};

class ProcessingState;

class CompleteState : public ServiceState {
public:
  explicit CompleteState(ProcessingState *processor) : processor_(processor) {
  }

  void Proceed() override;

private:
  ProcessingState *processor_;
};

class ProcessingState : public ServiceState {
public:
  ProcessingState(std::shared_ptr<authservice::config::Config> config, Authorization::AsyncService &service,
                  grpc::ServerCompletionQueue &cq, boost::asio::io_context &io_context)
          : service_(service), cq_(cq), responder_(&ctx_), io_context_(io_context), config_(std::move(config)),
            impl_(*config_) {
    spdlog::trace("Creating processor state");
    service.RequestCheck(&ctx_, &request_, &responder_, &cq_, &cq_, this);
  }

  void Proceed() override {
    // Spawn a new instance to serve new clients while we process this one
    new ProcessingState(config_, service_, cq_, io_context_);

    spdlog::trace("Launching request processor worker");

    // The actual processing
    boost::asio::spawn(io_context_, [this](boost::asio::yield_context yield) {
      spdlog::trace("Processing request");

      CheckResponse response;
      this->impl_.Check(&ctx_, &request_, &response);

      this->responder_.Finish(response, grpc::Status::OK, new CompleteState(this));

      spdlog::trace("Request processing complete");
    });
  }

private:
  // GRPC service/queue/context
  Authorization::AsyncService &service_;
  grpc::ServerCompletionQueue &cq_;
  grpc::ServerContext ctx_;

  // The GRPC request we've received
  CheckRequest request_;
  // Used to send the GRPC response
  grpc::ServerAsyncResponseWriter<CheckResponse> responder_;

  // Boost::ASIO I/O service
  boost::asio::io_context &io_context_;

  std::shared_ptr<authservice::config::Config> config_;
  authservice::service::AuthServiceImpl impl_;
};

void CompleteState::Proceed() {
  spdlog::trace("Processing completion and deleting state");

  delete processor_;
  delete this;
}

AsyncAuthServiceImpl::AsyncAuthServiceImpl(std::shared_ptr<authservice::config::Config> config)
        : config_(std::move(config)),
          io_context_(std::make_shared<boost::asio::io_context>()) {
  grpc::ServerBuilder builder;
  builder.AddListeningPort(config::GetConfiguredAddress(*config_), grpc::InsecureServerCredentials());
  builder.RegisterService(&service_);
  cq_ = builder.AddCompletionQueue();
  server_ = builder.BuildAndStart();
}

void AsyncAuthServiceImpl::Run() {
  // Add a work object to the IO service so it will not shut down when it has nothing left to do
  auto work = std::make_shared<boost::asio::io_context::work>(*io_context_);

  // Spin up our worker threads
  // Config validation should have already ensured that the number of threads is > 0
  boost::thread_group threadpool;
  for (unsigned int i = 0; i < config_->threads(); ++i) {
    threadpool.create_thread([this](){
      while(true) {
        try {
          this->io_context_->run();
          break;
        } catch(std::exception & e) {
          spdlog::error("Unexpected error in worker thread: {}", e.what());
        }
      }
    });
  }

  spdlog::info("{}: Server listening on {}", __func__, config::GetConfiguredAddress(*config_));

  try {
    // Spawn a new state instance to serve new clients.
    new ProcessingState(config_, service_, *cq_, *io_context_);

    void *tag;
    bool ok;
    while (true) {
      // Block waiting to read the next event from the completion queue. The
      // event is uniquely identified by its tag, which in this case is the
      // memory address of a CallData instance.
      // The return value of Next should always be checked. This return value
      // tells us whether there is any kind of event or cq_ is shutting down.
      if (!cq_->Next(&tag, &ok)) {
        break;
      }
      GPR_ASSERT(ok);

      static_cast<ServiceState *>(tag)->Proceed();
    }
  } catch (const std::exception &e) {
    spdlog::error("{}: Unexpected error: {}", __func__, e.what());
  }

  spdlog::info("Server shutting down");

  // Start shutting down gRPC
  server_->Shutdown();
  cq_->Shutdown();

  // Continue calling Next to process any outstanding events.
  try {
    void *tag;
    bool ok;
    while (true) {
      if (!cq_->Next(&tag, &ok)) {
        break;
      }
      GPR_ASSERT(ok);

      static_cast<ServiceState *>(tag)->Proceed();
    }
  } catch (const std::exception &e) {
    spdlog::error("{}: Unexpected error: {}", __func__, e.what());
  }

  // Reset the work item for the IO service will terminate once it finishes any outstanding jobs
  work.reset();
  threadpool.join_all();
}

}
}