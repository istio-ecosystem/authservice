#include "get_config.h"

#include <fmt/ostream.h>
#include <google/protobuf/util/json_util.h>

#include <cassert>
#include <fstream>
#include <iostream>
#include <memory>

#include "config/config.pb.validate.h"
#include "spdlog/spdlog.h"
#include "src/common/http/http.h"

using namespace std;
using namespace google::protobuf::util;

namespace authservice {
namespace config {

void ConfigValidator::ValidateAll(const Config& config) {
  string error;
  if (!Validate(config, &error)) {
    throw std::runtime_error(error);
  }

  for (const auto& chain : config.chains()) {
    for (const auto& filter : chain.filters()) {
      assert(!filter.has_oidc_override());
      if (filter.has_mock()) {
        continue;
      } else if (filter.has_oidc()) {
        ConfigValidator::ValidateOIDCConfig(filter.oidc());
        continue;
      }
      // not reached
    }
  }
}

void ConfigValidator::ValidateOIDCConfig(
    const config::oidc::OIDCConfig& config) {
  ValidateUri(config.authorization_uri(), "authorization_uri", "https");
  ValidateUri(config.callback_uri(), "callback_uri", "https");
  ValidateUri(config.token_uri(), "token_uri", "https");

  const auto proxy_uri = config.proxy_uri();
  if (!proxy_uri.empty()) {
    ValidateUri(proxy_uri, "proxy_uri", "http");
  }
}

void ConfigValidator::ValidateUri(absl::string_view uri,
                                  absl::string_view uri_type,
                                  absl::string_view required_scheme) {
  std::unique_ptr<common::http::Uri> parsed_uri;
  try {
    parsed_uri = std::make_unique<common::http::Uri>(uri);
  } catch (std::runtime_error& e) {
    if (std::string(e.what()).find("uri must be http or https scheme") !=
        std::string::npos) {
      throw std::runtime_error(
          fmt::format("invalid {}: uri must be {} scheme: {}", uri_type,
                      required_scheme, uri));
    }
    throw std::runtime_error(fmt::format("invalid {}: ", uri_type) + e.what());
  }
  if (parsed_uri->HasQuery() || parsed_uri->HasFragment()) {
    throw std::runtime_error(
        fmt::format("invalid {}: query params and fragments not allowed: {}",
                    uri_type, uri));
  }
  if (parsed_uri->GetScheme() != required_scheme) {
    throw std::runtime_error(
        fmt::format("invalid {}: uri must be {} scheme: {}", uri_type,
                    required_scheme, uri));
  }
}

spdlog::level::level_enum GetConfiguredLogLevel(const Config& config) {
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
    spdlog::error(
        "{}: Unexpected log_level config '{}': must be one of [trace, debug, "
        "info, error, critical]",
        __func__, log_level_string);
    abort();
  }

  return level;
}

unique_ptr<Config> GetConfig(const string& configFileName) {
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
    throw runtime_error(status.error_message().ToString());
  }

  const auto has_default_oidc_config = config->has_default_oidc_config();
  for (auto& filter_chain : *config->mutable_chains()) {
    for (auto& filter : *filter_chain.mutable_filters()) {
      if (filter.has_oidc_override()) {
        if (!has_default_oidc_config) {
          throw std::runtime_error(
              "oidc_config must be utilized with default_oidc_config");
        }

        config::oidc::OIDCConfig new_filter = config->default_oidc_config();
        dynamic_cast<google::protobuf::Message*>(&new_filter)
            ->MergeFrom(filter.oidc_override());
        filter.clear_oidc_override();
        *filter.mutable_oidc() = new_filter;
      }
    }
  }

  if (has_default_oidc_config) {
    config->clear_default_oidc_config();
  }

  ConfigValidator::ValidateAll(*config);

  return config;
}

}  // namespace config
}  // namespace authservice
