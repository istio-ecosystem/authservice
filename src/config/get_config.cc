#include "get_config.h"
#include <google/protobuf/util/json_util.h>
#include "spdlog/spdlog.h"
#include <fstream>
#include <iostream>
#include <sstream>
#include "config/config.pb.validate.h"
#include "src/common/http/http.h"
#include "absl/strings/string_view.h"
#include <fmt/ostream.h>

using namespace std;
using namespace google::protobuf::util;

namespace authservice {
namespace config {

void validateUri(absl::string_view uri, absl::string_view uri_name) {
  array<string, 3> path_query_fragment_array;
  try {
    auto parsed_uri = common::http::Http::ParseUri(uri);
    path_query_fragment_array = common::http::Http::DecodePath(parsed_uri.PathQueryFragment());
  } catch (runtime_error &e) {
    throw runtime_error(fmt::format("invalid {}: ", uri_name) + e.what());
  }
  if (!path_query_fragment_array[1].empty() || !path_query_fragment_array[2].empty()) {
    throw runtime_error(fmt::format("invalid {}: query params and fragments not allowed: {}", uri_name, uri));
  }

}

unique_ptr<Config> GetConfig(const string &configFileName) {
  ifstream configFile(configFileName);
  if (!configFile) {
    throw runtime_error("failed to open filter config");
  }
  stringstream buf;
  buf << configFile.rdbuf();
  configFile.close();

  unique_ptr<Config> config(new Config);
  auto status = JsonStringToMessage(buf.str(), config.get());
  if (!status.ok()) {
    throw runtime_error(status.error_message());
  }

  string error;
  if (!Validate(*(config.get()), &error)) {
    throw runtime_error(error);
  }

  for (const auto &chain : config->chains()) {
    validateUri(chain.filters(0).oidc().authorization_uri(), "authorization_uri");
    validateUri(chain.filters(0).oidc().callback_uri(), "callback_uri");
    validateUri(chain.filters(0).oidc().token_uri(), "token_uri");
  }

  return config;
}

spdlog::level::level_enum GetConfiguredLogLevel(const Config &config) {
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

string GetConfiguredAddress(const Config &config) {
  stringstream address_string_builder;
  address_string_builder << config.listen_address() << ":" << dec << config.listen_port();
  auto address = address_string_builder.str();
  return address;
}

}  // namespace config
}  // namespace authservice
