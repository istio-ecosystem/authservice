#ifndef AUTHSERVICE_SERVICEIMPL_H
#define AUTHSERVICE_SERVICEIMPL_H
#include "config/config.pb.h"
#include "envoy/service/auth/v2/external_auth.grpc.pb.h"
#include "src/filters/oidc/token_response.h"
#include "src/filters/pipe.h"

using namespace envoy::service::auth::v2;

namespace authservice {
namespace service {

class AuthServiceImpl final : public Authorization::Service {
 private:
  std::unique_ptr<filters::Pipe> root_;

 public:
  AuthServiceImpl(std::shared_ptr<authservice::config::Config> config);
  ::grpc::Status Check(
      ::grpc::ServerContext* context,
      const ::envoy::service::auth::v2::CheckRequest* request,
      ::envoy::service::auth::v2::CheckResponse* response) override;
};
}  // namespace service
}  // namespace authservice

#endif  // AUTHSERVICE_SERVICEIMPL_H
