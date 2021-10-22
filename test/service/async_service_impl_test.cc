#include "src/service/async_service_impl.h"

#include <gtest/gtest-typed-test.h>

#include <boost/type_traits/is_default_constructible.hpp>
#include <type_traits>

#include "common/config/version_converter.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "src/config/get_config.h"
#include "src/filters/filter_chain.h"

namespace authservice {
namespace service {

using ::testing::HasSubstr;

template <class T>
class AsyncServiceImplTest : public ::testing::Test {
 public:
  grpc::Status check(typename T::first_type *request,
                     typename T::second_type *response) {
    using RequestType = typename T::first_type;
    using ResponseType = typename T::second_type;

    // Create a new io_context. All of the async IO handled inside the
    // spawn below will be handled by this new io_context.
    boost::asio::io_context ioc;
    grpc::Status status;

    // Spawn a co-routine to run the filter.
    boost::asio::spawn(ioc, [&](boost::asio::yield_context yield) {
      status = authservice::service::Check(*request, *response, chains_,
                                           trigger_rules_config_,
                                           default_skip_auth_, ioc, yield);
    });

    // Run the I/O context to completion, on the current thread.
    // This consumes the current thread until all of the async
    // I/O from the above spawn is finished.
    ioc.run();

    return status;
  }

  bool default_skip_auth_{true};
  std::vector<std::unique_ptr<filters::FilterChain>> chains_;
  google::protobuf::RepeatedPtrField<config::TriggerRule> trigger_rules_config_;
  boost::asio::io_context ioc_;
};

using test_types =
    ::testing::Types<std::pair<::envoy::service::auth::v3::CheckRequest,
                               ::envoy::service::auth::v3::CheckResponse>,
                     std::pair<::envoy::service::auth::v2::CheckRequest,
                               ::envoy::service::auth::v2::CheckResponse>>;

TYPED_TEST_CASE(AsyncServiceImplTest, test_types);

TYPED_TEST(AsyncServiceImplTest,
           CheckUnmatchedTenantRequest_ForAMatchingTriggerRulesPath) {
  typename TypeParam::first_type request;
  typename TypeParam::second_type response;

  request.mutable_attributes()->mutable_request()->mutable_http()->set_scheme(
      "https");
  request.mutable_attributes()->mutable_request()->mutable_http()->set_path(
      "/status/foo#some-fragment");  // this is a matching path for
                                     // trigger_rules
  auto request_headers = request.mutable_attributes()
                             ->mutable_request()
                             ->mutable_http()
                             ->mutable_headers();
  request_headers->insert({"x-tenant-identifier", "unknown-tenant"});

  config::Config config = *config::GetConfig("test/fixtures/valid-config.json");
  this->trigger_rules_config_ = config.trigger_rules();

  for (const auto &chain_config : config.chains()) {
    std::unique_ptr<filters::FilterChain> chain(new filters::FilterChainImpl(
        this->ioc_, chain_config, config.threads()));
    this->chains_.push_back(std::move(chain));
  }

  auto status = this->check(&request, &response);
  EXPECT_TRUE(status.ok());
  EXPECT_FALSE(response.has_denied_response());  // request allowed to proceed
                                                 // (not redirected for auth)
}

TYPED_TEST(AsyncServiceImplTest,
           CheckMatchedTenantRequest_ForANonMatchingTriggerRulesPath) {
  typename TypeParam::first_type request;
  typename TypeParam::second_type response;

  request.mutable_attributes()->mutable_request()->mutable_http()->set_scheme(
      "https");
  request.mutable_attributes()->mutable_request()->mutable_http()->set_path(
      "/status/version?some-query");  // this is a non-matching path for
                                      // trigger_rules
  auto request_headers = request.mutable_attributes()
                             ->mutable_request()
                             ->mutable_http()
                             ->mutable_headers();
  request_headers->insert({"x-tenant-identifier", "tenant1"});

  config::Config config = *config::GetConfig("test/fixtures/valid-config.json");
  this->trigger_rules_config_ = config.trigger_rules();

  for (const auto &chain_config : config.chains()) {
    std::unique_ptr<filters::FilterChain> chain(new filters::FilterChainImpl(
        this->ioc_, chain_config, config.threads()));
    this->chains_.push_back(std::move(chain));
  }

  auto status = this->check(&request, &response);
  EXPECT_TRUE(status.ok());
  EXPECT_FALSE(response.has_denied_response());  // request allowed to proceed
                                                 // (not redirected for auth)
}

TYPED_TEST(AsyncServiceImplTest,
           CheckMatchedTenantRequest_ForAMatchingTriggerRulesPath) {
  typename TypeParam::first_type request;
  typename TypeParam::second_type response;

  request.mutable_attributes()->mutable_request()->mutable_http()->set_scheme(
      "https");
  request.mutable_attributes()->mutable_request()->mutable_http()->set_path(
      "/status/foo?some-query");  // this is a matching path for trigger_rules
  auto request_headers = request.mutable_attributes()
                             ->mutable_request()
                             ->mutable_http()
                             ->mutable_headers();
  request_headers->insert({"x-tenant-identifier", "tenant1"});

  config::Config config = *config::GetConfig("test/fixtures/valid-config.json");

  for (const auto &chain_config : config.chains()) {
    std::unique_ptr<filters::FilterChain> chain(new filters::FilterChainImpl(
        this->ioc_, chain_config, config.threads()));
    this->chains_.push_back(std::move(chain));
  }

  auto status = this->check(&request, &response);

  EXPECT_TRUE(status.ok());
  EXPECT_EQ(response.denied_response().status().code(),
            envoy::type::v3::Found);  // redirected for auth

  bool hasLocation = false;
  for (auto &header : response.denied_response().headers()) {
    if (header.header().key() == "location") {
      EXPECT_THAT(
          header.header().value(),
          HasSubstr(
              "https://google3/path3"));  // redirected to the configured IDP
      hasLocation = true;
    }
  }
  EXPECT_TRUE(hasLocation);
}

TYPED_TEST(AsyncServiceImplTest,
           CheckRejectNoMatchedFilterChainWithDefaultDeny) {
  typename TypeParam::first_type request;
  typename TypeParam::second_type response;
  this->default_skip_auth_ = false;
  request.mutable_attributes()->mutable_request()->mutable_http()->set_scheme(
      "https");
  request.mutable_attributes()->mutable_request()->mutable_http()->set_path(
      "/status/foo?some-query");  // this is a matching path for trigger_rules
  auto request_headers = request.mutable_attributes()
                             ->mutable_request()
                             ->mutable_http()
                             ->mutable_headers();
  request_headers->insert({"x-tenant-identifier", "tenant2"});

  config::Config config = *config::GetConfig("test/fixtures/valid-config.json");

  for (const auto &chain_config : config.chains()) {
    std::unique_ptr<filters::FilterChain> chain(new filters::FilterChainImpl(
        this->ioc_, chain_config, config.threads()));
    this->chains_.push_back(std::move(chain));
  }

  auto status = this->check(&request, &response);

  // Can't find matched filter chain.
  EXPECT_FALSE(status.ok());
}

}  // namespace service
}  // namespace authservice
