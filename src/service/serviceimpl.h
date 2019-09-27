#ifndef TRANSPARENT_AUTH_SERVICEIMPL_H
#define TRANSPARENT_AUTH_SERVICEIMPL_H
#include "envoy/service/auth/v2/external_auth.grpc.pb.h"
#include "src/filters/oidc/token_response.h"
#include "src/filters/pipe.h"

using namespace envoy::service::auth::v2;

namespace transparent_auth {
namespace service {

class AuthServiceImpl final : public Authorization::Service {
 private:
  filters::oidc::TokenResponseParserImpl token_request_parser_;
  std::unique_ptr<filters::Pipe> root_;

 public:
  AuthServiceImpl();
  ::grpc::Status Check(
      ::grpc::ServerContext* context,
      const ::envoy::service::auth::v2::CheckRequest* request,
      ::envoy::service::auth::v2::CheckResponse* response) override;
};
}  // namespace service
}  // namespace transparent_auth

#endif  // TRANSPARENT_AUTH_SERVICEIMPL_H
