#include "get_config.h"
#include <boost/algorithm/string/join.hpp>
#include <google/protobuf/util/json_util.h>
#include "spdlog/spdlog.h"
#include <fstream>
#include <iostream>
#include <sstream>
#include "config/config.pb.validate.h"

using namespace std;
using namespace google::protobuf::util;
using namespace authservice::config;

namespace authservice {
namespace config {

shared_ptr<authservice::config::Config> GetConfig(
    const string &configFileName) {
  ifstream configFile(configFileName);
  if (!configFile) {
    throw runtime_error("failed to open filter config");
  }
  stringstream buf;
  buf << configFile.rdbuf();
  configFile.close();

  shared_ptr<Config> config = make_shared<Config>();
  auto status = JsonStringToMessage(buf.str(), config.get());
  if (!status.ok()) {
    throw runtime_error(status.error_message());
  }

  std::string error;
  if (!Validate(*(config.get()), &error)) {
    throw runtime_error(error);
  }

  return config;
}

spdlog::level::level_enum GetConfiguredLogLevel(const authservice::config::Config& config) {
  auto log_level_string = config.log_level();
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
    spdlog::error("{}: Unexpected log_level config '{}': must be one of [trace, debug, info, error, critical]",
                  __func__, log_level_string);
    abort();
  }

  return level;
}

std::string GetConfiguredAddress(const authservice::config::Config& config) {
  std::stringstream address_string_builder;

  address_string_builder << config.listen_address() << ":" << std::dec
                         << config.listen_port();
  auto address = address_string_builder.str();
  return address;
}

}  // namespace config
}  // namespace authservice
