
#ifndef AUTHSERVICE_SRC_CONFIG_GETCONFIG_H
#define AUTHSERVICE_SRC_CONFIG_GETCONFIG_H

#include "config/config.pb.h"
#include "spdlog/spdlog.h"

namespace authservice {
namespace config {

std::shared_ptr<authservice::config::Config> GetConfig(
    const std::string& configFile);

void ValidateConfig(const authservice::config::Config &config);

spdlog::level::level_enum GetConfiguredLogLevel(const authservice::config::Config& config);
std::string GetConfiguredAddress(const authservice::config::Config& config);

}  // namespace config
}  // namespace authservice

#endif  // AUTHSERVICE_SRC_CONFIG_GETCONFIG_H
