
#include "getconfig.h"

#include <google/protobuf/util/json_util.h>
#include <fstream>
#include <iostream>
#include <sstream>
using namespace std;
using namespace google::protobuf::util;
using namespace authservice::config;

namespace transparent_auth {
namespace config {
std::shared_ptr<authservice::config::Config> GetConfig(
    const std::string& configFileName) {
  ifstream configFile(configFileName);
  if (!configFile) {
    throw std::runtime_error("failed to open filter config");
  }
  stringstream buf;
  buf << configFile.rdbuf();
  configFile.close();

  std::shared_ptr<Config> config = std::make_shared<Config>();
  auto status = JsonStringToMessage(buf.str(), config.get());
  if (!status.ok()) {
    throw std::runtime_error(status.error_message());
  }
  return config;
}
}  // namespace config
}  // namespace transparent_auth
