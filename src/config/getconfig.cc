
#include "getconfig.h"
#include <google/protobuf/util/json_util.h>
#include <boost/algorithm/string/join.hpp>
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
}  // namespace config
}  // namespace authservice
