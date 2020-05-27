#include "get_config.h"
#include <google/protobuf/util/json_util.h>
#include "spdlog/spdlog.h"
#include <fstream>
#include <iostream>
#include "config/config.pb.validate.h"
#include "src/common/http/http.h"
#include "absl/strings/string_view.h"
#include <fmt/ostream.h>
#include <memory>

using namespace std;
using namespace google::protobuf::util;

namespace authservice {
namespace config {

void ValidateUri(absl::string_view uri, absl::string_view uri_name, absl::string_view required_scheme) {
  unique_ptr<common::http::Uri> parsed_uri;
  try {
    parsed_uri = unique_ptr<common::http::Uri>(new common::http::Uri(uri));
  } catch (runtime_error &e) {
    if (std::string(e.what()).find("uri must be http or https scheme") != std::string::npos) {
      throw runtime_error(fmt::format("invalid {}: uri must be {} scheme: {}", uri_name, required_scheme, uri));
    }
    throw runtime_error(fmt::format("invalid {}: ", uri_name) + e.what());
  }
  if (parsed_uri->HasQuery() || parsed_uri->HasFragment()) {
    throw runtime_error(fmt::format("invalid {}: query params and fragments not allowed: {}", uri_name, uri));
  }
  if (parsed_uri->GetScheme() != required_scheme) {
    throw runtime_error(fmt::format("invalid {}: uri must be {} scheme: {}", uri_name, required_scheme, uri));
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
    ValidateUri(chain.filters(0).oidc().authorization_uri(), "authorization_uri", "https");
//    ValidateUri(chain.filters(0).oidc().callback_uri(), "callback_uri", "https");
    ValidateUri(chain.filters(0).oidc().token_uri(), "token_uri", "https");
    const auto proxy_uri = chain.filters(0).oidc().proxy_uri();
    if (!proxy_uri.empty()) {
      ValidateUri(proxy_uri, "proxy_uri", "http");
    }
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
