
#ifndef AUTHSERVICE_SRC_CONFIG_GETCONFIG_H
#define AUTHSERVICE_SRC_CONFIG_GETCONFIG_H

#include "absl/strings/string_view.h"
#include "config/config.pb.h"
#include "config/oidc/config.pb.h"
#include "spdlog/spdlog.h"

namespace authservice {
namespace config {

class ConfigValidator {
 public:
  static void ValidateAll(const Config& config);

 private:
  static void ValidateOIDCConfig(const config::oidc::OIDCConfig& config,
                                 bool not_strict_https);
  static void ValidateUri(absl::string_view uri, absl::string_view uri_type,
                          absl::string_view required_scheme);
};

spdlog::level::level_enum GetConfiguredLogLevel(const Config& config);

std::unique_ptr<Config> GetConfig(const std::string& configFile);

}  // namespace config
}  // namespace authservice

#endif  // AUTHSERVICE_SRC_CONFIG_GETCONFIG_H
