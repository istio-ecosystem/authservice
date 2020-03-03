
#ifndef AUTHSERVICE_SRC_CONFIG_GETCONFIG_H
#define AUTHSERVICE_SRC_CONFIG_GETCONFIG_H

#include "config/config.pb.h"
#include "spdlog/spdlog.h"

namespace authservice {
namespace config {

std::unique_ptr<Config> GetConfig(
    const std::string& configFile);

spdlog::level::level_enum GetConfiguredLogLevel(const Config& config);
std::string GetConfiguredAddress(const Config& config);

}  // namespace config
}  // namespace authservice

#endif  // AUTHSERVICE_SRC_CONFIG_GETCONFIG_H
