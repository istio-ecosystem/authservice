#include "src/service/async_service_impl.h"
#include "src/service/async_service_impl.cc"
#include "src/config/get_config.h"
#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include <boost/asio.hpp>
#include <boost/thread/thread.hpp>


namespace authservice {
namespace service {

using ::testing::HasSubstr;

TEST(ServiceImplTest, CheckUnmatchedTenantRequest_ForAMatchingTriggerRulesPath) {

//  const google::protobuf::RepeatedPtrField<config::TriggerRule> trigger_rules_config;
//  Authorization::AsyncService service;
  boost::asio::io_context io_context;
//  ProcessingState p(chains, &trigger_rules_config, &service, nullptr, &io_context);
  std::vector<std::unique_ptr<filters::FilterChain>> chains_;

  ::envoy::service::auth::v2::CheckResponse response;
  ::envoy::service::auth::v2::CheckRequest request;
  config::Config config = *config::GetConfig("test/fixtures/valid-config.json");

  for (const auto &chain_config : config.chains()) {
    std::unique_ptr<filters::FilterChain> chain(new filters::FilterChainImpl(chain_config));
    chains_.push_back(std::move(chain));
  }


  request.mutable_attributes()->mutable_request()->mutable_http()->set_scheme("https");
  request.mutable_attributes()->mutable_request()->mutable_http()->set_path("/status/foo#some-fragment"); // this is a matching path for trigger_rules
  auto request_headers = request.mutable_attributes()->mutable_request()->mutable_http()->mutable_headers();
  request_headers->insert({"x-tenant-identifier", "unknown-tenant"});

  ::grpc::Status status = authservice::service::Check(nullptr, &request, &response, chains_, config.trigger_rules(), io_context, nullptr);
  EXPECT_TRUE(status.ok());
  EXPECT_FALSE(response.has_denied_response()); // request allowed to proceed (not redirected for auth)
}

//TEST(ServiceImplTest, CheckMatchedTenantRequest_ForANonMatchingTriggerRulesPath) {
//  ::envoy::service::auth::v2::CheckResponse response;
//  ::envoy::service::auth::v2::CheckRequest request;
//
//  request.mutable_attributes()->mutable_request()->mutable_http()->set_scheme("https");
//  request.mutable_attributes()->mutable_request()->mutable_http()->set_path("/status/version?some-query"); // this is a non-matching path for trigger_rules
//  auto request_headers = request.mutable_attributes()->mutable_request()->mutable_http()->mutable_headers();
//  request_headers->insert({"x-tenant-identifier", "tenant1"});
//
//  ::grpc::Status status = service.Check(nullptr, &request, &response);
//  EXPECT_TRUE(status.ok());
//  EXPECT_FALSE(response.has_denied_response()); // request allowed to proceed (not redirected for auth)
//}
//
//TEST(ServiceImplTest, CheckMatchedTenantRequest_ForAMatchingTriggerRulesPath) {
//  ::envoy::service::auth::v2::CheckResponse response;
//  ::envoy::service::auth::v2::CheckRequest request;
//
//  request.mutable_attributes()->mutable_request()->mutable_http()->set_scheme("https");
//  request.mutable_attributes()->mutable_request()->mutable_http()->set_path("/status/foo?some-query"); // this is a matching path for trigger_rules
//  auto request_headers = request.mutable_attributes()->mutable_request()->mutable_http()->mutable_headers();
//  request_headers->insert({"x-tenant-identifier", "tenant1"});
//
//  ::grpc::Status status = service.Check(nullptr, &request, &response);
//  EXPECT_TRUE(status.ok());
//  EXPECT_EQ(response.denied_response().status().code(), envoy::type::StatusCode::Found); // redirected for auth
//
//  bool hasLocation = false;
//  for(auto& header : response.denied_response().headers()) {
//    if (header.header().key() == "location") {
//      EXPECT_THAT(header.header().value(), HasSubstr("https://google3/path3")); // redirected to the configured IDP
//      hasLocation = true;
//    }
//  }
//  EXPECT_TRUE(hasLocation);
//}

}  // namespace service
}  // namespace authservice
