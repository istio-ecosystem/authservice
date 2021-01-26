#include "src/service/async_service_impl.h"
#include "src/config/get_config.h"
#include "src/filters/filter_chain.h"
#include "gtest/gtest.h"
#include "gmock/gmock.h"

namespace authservice {
namespace service {

using ::testing::HasSubstr;

grpc::Status ProcessAndWaitForAsio(
    const ::envoy::service::auth::v3::CheckRequest *request,
    ::envoy::service::auth::v3::CheckResponse *response,
    std::vector<std::unique_ptr<filters::FilterChain>> &chains,
    const google::protobuf::RepeatedPtrField<config::TriggerRule> &trigger_rules_config) {
  // Create a new io_context. All of the async IO handled inside the
  // spawn below will be handled by this new io_context.
  boost::asio::io_context ioc;
  grpc::Status status;

  // Spawn a co-routine to run the filter.
  boost::asio::spawn(ioc, [&](boost::asio::yield_context yield) {
    status = authservice::service::Check(request, response, chains, trigger_rules_config, ioc, yield);
//    this->responder_.Finish(response, grpc::Status::OK, new CompleteState(this));
  });

  // Run the I/O context to completion, on the current thread.
  // This consumes the current thread until all of the async
  // I/O from the above spawn is finished.
  ioc.run();

  return status;
}

TEST(AsyncServiceImplTest, CheckUnmatchedTenantRequest_ForAMatchingTriggerRulesPath) {

  ::envoy::service::auth::v3::CheckResponse response;
  ::envoy::service::auth::v3::CheckRequest request;

  request.mutable_attributes()->mutable_request()->mutable_http()->set_scheme("https");
  request.mutable_attributes()->mutable_request()->mutable_http()->set_path("/status/foo#some-fragment"); // this is a matching path for trigger_rules
  auto request_headers = request.mutable_attributes()->mutable_request()->mutable_http()->mutable_headers();
  request_headers->insert({"x-tenant-identifier", "unknown-tenant"});

  std::vector<std::unique_ptr<filters::FilterChain>> chains_;
  config::Config config_;

  config_ = *config::GetConfig("test/fixtures/valid-config.json");

  for (const auto &chain_config : config_.chains()) {
    std::unique_ptr<filters::FilterChain> chain(new filters::FilterChainImpl(chain_config, config_.threads()));
    chains_.push_back(std::move(chain));
  }

  auto status = ProcessAndWaitForAsio(&request, &response, chains_, config_.trigger_rules());
  EXPECT_TRUE(status.ok());
  EXPECT_FALSE(response.has_denied_response()); // request allowed to proceed (not redirected for auth)
}

TEST(AsyncServiceImplTest, CheckMatchedTenantRequest_ForANonMatchingTriggerRulesPath) {

  ::envoy::service::auth::v3::CheckResponse response;
  ::envoy::service::auth::v3::CheckRequest request;

  request.mutable_attributes()->mutable_request()->mutable_http()->set_scheme("https");
  request.mutable_attributes()->mutable_request()->mutable_http()->set_path("/status/version?some-query"); // this is a non-matching path for trigger_rules
  auto request_headers = request.mutable_attributes()->mutable_request()->mutable_http()->mutable_headers();
  request_headers->insert({"x-tenant-identifier", "tenant1"});

  std::vector<std::unique_ptr<filters::FilterChain>> chains_;
  config::Config config_;

  config_ = *config::GetConfig("test/fixtures/valid-config.json");

  for (const auto &chain_config : config_.chains()) {
    std::unique_ptr<filters::FilterChain> chain(new filters::FilterChainImpl(chain_config, config_.threads()));
    chains_.push_back(std::move(chain));
  }

  auto status = ProcessAndWaitForAsio(&request, &response, chains_, config_.trigger_rules());
  EXPECT_TRUE(status.ok());
  EXPECT_FALSE(response.has_denied_response()); // request allowed to proceed (not redirected for auth)
}

TEST(AsyncServiceImplTest, CheckMatchedTenantRequest_ForAMatchingTriggerRulesPath) {

  ::envoy::service::auth::v3::CheckResponse response;
  ::envoy::service::auth::v3::CheckRequest request;

  request.mutable_attributes()->mutable_request()->mutable_http()->set_scheme("https");
  request.mutable_attributes()->mutable_request()->mutable_http()->set_path("/status/foo?some-query"); // this is a matching path for trigger_rules
  auto request_headers = request.mutable_attributes()->mutable_request()->mutable_http()->mutable_headers();
  request_headers->insert({"x-tenant-identifier", "tenant1"});

  std::vector<std::unique_ptr<filters::FilterChain>> chains_;
  config::Config config_;

  config_ = *config::GetConfig("test/fixtures/valid-config.json");

  for (const auto &chain_config : config_.chains()) {
    std::unique_ptr<filters::FilterChain> chain(new filters::FilterChainImpl(chain_config, config_.threads()));
    chains_.push_back(std::move(chain));
  }

  auto status = ProcessAndWaitForAsio(&request, &response, chains_, config_.trigger_rules());

  EXPECT_TRUE(status.ok());
  EXPECT_EQ(response.denied_response().status().code(), envoy::type::v3::Found); // redirected for auth

  bool hasLocation = false;
  for (auto &header : response.denied_response().headers()) {
    if (header.header().key() == "location") {
      EXPECT_THAT(header.header().value(), HasSubstr("https://google3/path3")); // redirected to the configured IDP
      hasLocation = true;
    }
  }
  EXPECT_TRUE(hasLocation);
}

}  // namespace service
}  // namespace authservice