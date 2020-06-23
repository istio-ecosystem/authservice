#ifndef AUTHSERVICE_SERVICEIMPL_H
#define AUTHSERVICE_SERVICEIMPL_H

#include "config/config.pb.h"
#include "envoy/service/auth/v2/external_auth.grpc.pb.h"
#include "src/filters/filter_chain.h"

using namespace envoy::service::auth::v2;

namespace authservice {
namespace service {

// TODO this class does not need to subclass Authorization::Service,
//  and could either be renamed or maybe does not need to exist if the Check
//  method were moved elsewhere
class AuthServiceImpl final : public Authorization::Service {
 private:
  std::vector<std::unique_ptr<filters::FilterChain>> &chains_;
  const google::protobuf::RepeatedPtrField<config::TriggerRule> &trigger_rules_config_;
  boost::asio::io_context &ioc_;
  boost::asio::yield_context yield_;

 public:
  AuthServiceImpl(std::vector<std::unique_ptr<filters::FilterChain>> &chains,
                  const google::protobuf::RepeatedPtrField<config::TriggerRule> &trigger_rules_config,
                  boost::asio::io_context &ioc,
                  boost::asio::yield_context yield);

  ::grpc::Status Check(
      ::grpc::ServerContext *context,
      const ::envoy::service::auth::v2::CheckRequest *request,
      ::envoy::service::auth::v2::CheckResponse *response) override;

};
}  // namespace service
}  // namespace authservice

#endif  // AUTHSERVICE_SERVICEIMPL_H
