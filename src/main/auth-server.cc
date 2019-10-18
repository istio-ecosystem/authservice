#include <grpcpp/grpcpp.h>
#include <grpcpp/server_builder.h>
#include <cassert>
#include <cstdio>
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
#include "src/service/serviceimpl.h"

using grpc::Server;
using grpc::ServerBuilder;

namespace transparent_auth {
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
  auto configured_address = config->listen_address();
  auto configured_port = config->listen_port();

  if (configured_address.empty()) {
    configured_address = "127.0.0.1";
  }
  if (configured_port.empty()) {
    configured_port = "10003";
  }

  address_string_builder << configured_address << ":" << std::dec
                         << configured_port;
  auto address = address_string_builder.str();
  return address;
}

void RunServer(const std::shared_ptr<authservice::config::Config>& config) {
  auto address = GetConfiguredAddress(config);
  AuthServiceImpl auth_service(config);
  ServerBuilder builder;
  builder.AddListeningPort(address, grpc::InsecureServerCredentials());
  builder.RegisterService(&auth_service);
  std::unique_ptr<Server> server(builder.BuildAndStart());
  spdlog::info("{}: Server listening on {}", __func__, address);
  server->Wait();
}

}  // namespace service
}  // namespace transparent_auth

ABSL_FLAG(std::string, filter_config, "/etc/authservice/config.json",
          "path to filter config");

int main(int argc, char** argv) {
  absl::SetProgramUsageMessage(absl::StrCat("run an auth server:\n", argv[0]));
  absl::ParseCommandLine(argc, argv);

  auto console = spdlog::stdout_logger_mt("console");
  spdlog::set_default_logger(console);

  try {
    auto config =
        transparent_auth::config::GetConfig(absl::GetFlag(FLAGS_filter_config));
    console->set_level(
        transparent_auth::service::GetConfiguredLogLevel(config));
    transparent_auth::service::RunServer(config);
  } catch (const std::exception& e) {
    spdlog::error("{}: Unexpected error: {}", __func__, e.what());
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}
