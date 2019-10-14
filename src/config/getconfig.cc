
#include "getconfig.h"
#include <boost/algorithm/string/join.hpp>
#include <google/protobuf/util/json_util.h>
#include <fstream>
#include <iostream>
#include <sstream>

using namespace std;
using namespace google::protobuf::util;
using namespace authservice::config;

namespace transparent_auth {
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
  return config;
}

void ValidateEndpoint(const common::Endpoint &endpoint_config, vector<string> &errors, const string &type) {
  if (endpoint_config.scheme().empty()) { errors.emplace_back("filters.oidc." + type + ".scheme"); }
  if (endpoint_config.hostname().empty()) { errors.emplace_back("filters.oidc." + type + ".hostname"); }
  if (endpoint_config.path().empty()) { errors.emplace_back("filters.oidc." + type + ".path"); }
  if (endpoint_config.port() == 0) { errors.emplace_back("filters.oidc." + type + ".port"); }
}

void ValidateOidcConfig(const oidc::OIDCConfig &oidc) {
  vector<string> errors;

  ValidateEndpoint(oidc.authorization(), errors, "authorization");
  ValidateEndpoint(oidc.token(), errors, "token");
  if (oidc.jwks().empty()) { errors.emplace_back("filters.oidc.jwks"); }
  ValidateEndpoint(oidc.callback(), errors, "callback");
  if (oidc.client_id().empty()) { errors.emplace_back("filters.oidc.client_id"); }
  if (oidc.client_secret().empty()) { errors.emplace_back("filters.oidc.client_secret"); }
  if (oidc.landing_page().empty()) { errors.emplace_back("filters.oidc.landing_page"); }
  if (oidc.cryptor_secret().empty()) { errors.emplace_back("filters.oidc.cryptor_secret"); }

  if (!errors.empty()) {
    auto error_string = boost::algorithm::join(errors, ", ");
    throw runtime_error("Missing required configuration: " + error_string);
  }
}

}  // namespace config
}  // namespace transparent_auth
