
#ifndef TRANSPARENT_AUTH_SRC_CONFIG_GETCONFIG_H
#define TRANSPARENT_AUTH_SRC_CONFIG_GETCONFIG_H

#include "config/config.pb.h"

namespace transparent_auth {
namespace config {
std::unique_ptr<authservice::config::Config> GetConfig(
    const std::string &configFile);
}  // namespace config
}  // namespace transparent_auth

#endif  // TRANSPARENT_AUTH_SRC_CONFIG_GETCONFIG_H
