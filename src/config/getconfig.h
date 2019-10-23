
#ifndef AUTHSERVICE_SRC_CONFIG_GETCONFIG_H
#define AUTHSERVICE_SRC_CONFIG_GETCONFIG_H

#include "config/config.pb.h"

namespace authservice {
namespace config {

std::shared_ptr<authservice::config::Config> GetConfig(
    const std::string& configFile);

}  // namespace config
}  // namespace authservice

#endif  // AUTHSERVICE_SRC_CONFIG_GETCONFIG_H
