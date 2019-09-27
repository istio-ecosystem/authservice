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
#include "spdlog/common.h"
#include "spdlog/sinks/stdout_sinks.h"
#include "spdlog/spdlog.h"
#include "spdlog/spdlog.h"
#include "src/service/serviceimpl.h"

using grpc::ServerBuilder;
using grpc::Server;

namespace transparent_auth {
namespace service {

void RunServer(const string &address) {
  AuthServiceImpl auth_service;
  ServerBuilder builder;
  builder.AddListeningPort(address, grpc::InsecureServerCredentials());
  builder.RegisterService(&auth_service);
  std::unique_ptr<Server> server(builder.BuildAndStart());
  std::cout << "Server listening on " << address << std::endl;
  server->Wait();
}
}  // namespace service
}  // namespace transparent_auth

#define LOG_LEVELS \
  LEVEL(trace)     \
  LEVEL(debug)     \
  LEVEL(info)      \
  LEVEL(err)       \
  LEVEL(critical)

static bool StrToLogLevel(const std::string &str,
                          spdlog::level::level_enum *level) {
#define LEVEL(name)                           \
  if (str == #name) {                         \
    *level = spdlog::level::level_enum::name; \
    return true;                              \
  }
  LOG_LEVELS
#undef LEVEL
  return false;
}

static std::string LogLevelToStr(spdlog::level::level_enum input) {
  switch (input) {
#define LEVEL(name)                     \
  case spdlog::level::level_enum::name: \
    return #name;
    LOG_LEVELS
#undef LEVEL
    default:
      assert(false);
      return "info";
  }
}

struct LogLevel {
  explicit LogLevel() {}
  spdlog::level::level_enum level = spdlog::level::level_enum::info;
};

std::string AbslUnparseFlag(const LogLevel &level) {
  return LogLevelToStr(level.level);
}

bool AbslParseFlag(absl::string_view text, LogLevel *level,
                   std::string *error) {
  std::string str;
  if (!absl::ParseFlag(text, &str, error)) {
    return false;
  }
  if (!StrToLogLevel(str, &level->level)) {
    *error = "one of [trace, debug, info, error, critical]";
    return false;
  }
  return true;
}

ABSL_FLAG(LogLevel, loglevel, LogLevel(), "log level");
ABSL_FLAG(std::string, address, "0.0.0.0", "address to bind to");
ABSL_FLAG(uint16_t, port, 5001, "port to listen on");

int main(int argc, char **argv) {
  absl::SetProgramUsageMessage(absl::StrCat("run an auth server:\n", argv[0]));
  absl::ParseCommandLine(argc, argv);
  auto console = spdlog::stdout_logger_mt("console");
  spdlog::set_default_logger(console);
  console->set_level(absl::GetFlag(FLAGS_loglevel).level);
  std::stringstream builder;
  builder << absl::GetFlag(FLAGS_address) << ":" << std::dec
          << absl::GetFlag(FLAGS_port);
  transparent_auth::service::RunServer(builder.str());
  return 0;
}
