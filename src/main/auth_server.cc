#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/flags/usage.h"
#include "absl/strings/str_cat.h"
#include "envoy/service/auth/v2/external_auth.pb.validate.h"
#include "spdlog/sinks/stdout_sinks.h"
#include "spdlog/spdlog.h"
#include "src/config/get_config.h"
#include "src/service/async_service_impl.h"

using namespace authservice::config;
using namespace authservice::service;

namespace authservice {
namespace service {

void RunServer(const config::Config &config) {
  AsyncAuthServiceImpl service(config);
  service.Run();
}

}  // namespace service
}  // namespace authservice

ABSL_FLAG(std::string, filter_config, "/etc/authservice/config.json",
          "path to filter config");

int main(int argc, char **argv) {
  absl::SetProgramUsageMessage(absl::StrCat("run an auth server:\n", argv[0]));
  absl::ParseCommandLine(argc, argv);

  auto console = spdlog::stdout_logger_mt("console");
  spdlog::set_default_logger(console);

  try {
    auto config = GetConfig(absl::GetFlag(FLAGS_filter_config));
    console->set_level(GetConfiguredLogLevel(*config));
    RunServer(*config);
  } catch (const std::exception &e) {
    spdlog::error("{}: Unexpected error: {}", __func__, e.what());
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}
