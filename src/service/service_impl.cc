#include "service_impl.h"
#include <grpcpp/grpcpp.h>
#include <memory>
#include "spdlog/spdlog.h"

namespace authservice {
namespace service {

AuthServiceImpl::AuthServiceImpl(const config::Config& config) {
  for (const auto &chain_config : config.chains()) {
    std::unique_ptr<filters::FilterChain> chain(new filters::FilterChainImpl(chain_config));
    chains_.push_back(std::move(chain));
  }
}

::grpc::Status AuthServiceImpl::Check(
    ::grpc::ServerContext *,
    const ::envoy::service::auth::v2::CheckRequest *request,
    ::envoy::service::auth::v2::CheckResponse *response) {
  spdlog::trace("{}", __func__);
  try {
    // Find a configured processing chain.
    for (auto &chain : chains_) {
      if (chain->Matches(request)) {
        spdlog::debug("{}: processing request {}://{}{} with filter chain {}", __func__, request->attributes().request().http().scheme(), request->attributes().request().http().host(), request->attributes().request().http().path(), chain->Name());
        // Create a new instance of a processor.
        auto processor = chain->New();
        auto status = processor->Process(request, response);
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
    spdlog::debug("{}: no matching filter chain for request to {}://{}{} ", __func__, request->attributes().request().http().scheme(), request->attributes().request().http().host(), request->attributes().request().http().path());
    return ::grpc::Status::OK;
  } catch (const std::exception &exception) {
    spdlog::error("%s unexpected error: %s", __func__, exception.what());
  } catch (...) {
    spdlog::error("%s unexpected error: unknown", __func__);
  }
  return ::grpc::Status(::grpc::StatusCode::INTERNAL, "internal error");
}

void AuthServiceImpl::DoPeriodicCleanup() {
  for (const auto &chain : chains_) {
    chain->DoPeriodicCleanup();
  }
}

}  // namespace service
}  // namespace authservice
