#include <grpcpp/grpcpp.h>
#include <grpcpp/server_builder.h>
#include <cassert>
#include <cstdio>
#include <boost/asio.hpp>
#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/flags/usage.h"
#include "absl/strings/str_cat.h"
#include "envoy/service/auth/v2/external_auth.pb.validate.h"
#include "grpcpp/server.h"
#include "include/spdlog/spdlog.h"
#include "spdlog/common.h"
#include "spdlog/sinks/stdout_sinks.h"
#include "spdlog/spdlog.h"
#include "src/config/getconfig.h"
#include "src/service/service_impl.h"

using grpc::Server;
using grpc::ServerBuilder;

namespace authservice {
namespace service {

spdlog::level::level_enum GetConfiguredLogLevel(
    const std::shared_ptr<authservice::config::Config>& config) {
  auto log_level_string = config->log_level();
  spdlog::level::level_enum level;

  if (log_level_string == "trace" || log_level_string.empty()) {
    level = spdlog::level::level_enum::trace;
  } else if (log_level_string == "debug") {
    level = spdlog::level::level_enum::debug;
  } else if (log_level_string == "info") {
    level = spdlog::level::level_enum::info;
  } else if (log_level_string == "error") {
    level = spdlog::level::level_enum::err;
  } else if (log_level_string == "critical") {
    level = spdlog::level::level_enum::critical;
  } else {
    spdlog::error(
        "{}: Unexpected log_level config '{}': must be one of [trace, debug, "
        "info, error, critical]",
        __func__, log_level_string);
    abort();
  }

  return level;
}

std::string GetConfiguredAddress(
    const std::shared_ptr<authservice::config::Config>& config) {
  std::stringstream address_string_builder;

  address_string_builder << config->listen_address() << ":" << std::dec
                         << config->listen_port();
  auto address = address_string_builder.str();
  return address;
}

void RunServer(const std::shared_ptr<authservice::config::Config>& config) {
  auto io_service = std::make_shared<boost::asio::io_service>();
  auto work = std::make_shared<boost::asio::io_service::work>(*io_service);

  envoy::service::auth::v2::Authorization::AsyncService service;

  auto address = GetConfiguredAddress(config);
  ServerBuilder builder;
  builder.AddListeningPort(address, grpc::InsecureServerCredentials());
  builder.RegisterService(&service);
  auto cq = builder.AddCompletionQueue();
  auto server = builder.BuildAndStart();
  spdlog::info("{}: Server listening on {}", __func__, address);

  void* tag;
  bool ok;
  while (true) {
    // Block waiting to read the next event from the completion queue. The
    // event is uniquely identified by its tag, which in this case is the
    // memory address of a CallData instance.
    // The return value of Next should always be checked. This return value
    // tells us whether there is any kind of event or cq_ is shutting down.
    GPR_ASSERT(cq->Next(&tag, &ok));
    GPR_ASSERT(ok);

//    service.RequestCheck(&ctx_, &request_, &responder_, cq_, cq_,
//                              this);
  }
}

}  // namespace service
}  // namespace authservice

ABSL_FLAG(std::string, filter_config, "/etc/authservice/config.json",
          "path to filter config");

int main(int argc, char** argv) {
  absl::SetProgramUsageMessage(absl::StrCat("run an auth server:\n", argv[0]));
  absl::ParseCommandLine(argc, argv);

  auto console = spdlog::stdout_logger_mt("console");
  spdlog::set_default_logger(console);

  try {
    auto config =
        authservice::config::GetConfig(absl::GetFlag(FLAGS_filter_config));
    console->set_level(
        authservice::service::GetConfiguredLogLevel(config));
    authservice::service::RunServer(config);
  } catch (const std::exception& e) {
    spdlog::error("{}: Unexpected error: {}", __func__, e.what());
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}
