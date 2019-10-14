#ifndef TRANSPARENT_AUTH_SERVICEIMPL_H
#define TRANSPARENT_AUTH_SERVICEIMPL_H
#include "config/config.pb.h"
#include "envoy/service/auth/v2/external_auth.grpc.pb.h"
#include "src/filters/oidc/token_response.h"
#include "src/filters/pipe.h"

using namespace envoy::service::auth::v2;

namespace transparent_auth {
namespace service {

class AuthServiceImpl final : public Authorization::Service {
 private:
  std::unique_ptr<filters::Pipe> root_;
  std::unique_ptr<authservice::config::Config> config_;

 public:
  AuthServiceImpl(const std::string& config);
  ::grpc::Status Check(
      ::grpc::ServerContext* context,
      const ::envoy::service::auth::v2::CheckRequest* request,
      ::envoy::service::auth::v2::CheckResponse* response) override;
};
}  // namespace service
}  // namespace transparent_auth

#endif  // TRANSPARENT_AUTH_SERVICEIMPL_H
