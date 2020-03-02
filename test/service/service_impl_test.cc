#include "src/service/service_impl.h"
#include "src/config/get_config.h"
#include "gtest/gtest.h"
#include "gmock/gmock.h"

namespace authservice {
namespace service {

using ::testing::HasSubstr;

TEST(ServiceImplTest, CheckUnmatchedRequest) {
  AuthServiceImpl service(
          *config::GetConfig("test/fixtures/valid-config.json"));

  ::envoy::service::auth::v2::CheckResponse response;
  ::envoy::service::auth::v2::CheckRequest request;

  request.mutable_attributes()->mutable_request()->mutable_http()->set_scheme(
      "https");
  auto request_headers = request.mutable_attributes()
                             ->mutable_request()
                             ->mutable_http()
                             ->mutable_headers();
  request_headers->insert({"x-tenant-identifier", "unknown-tenant"});

  ::grpc::Status status = service.Check(nullptr, &request, &response);
  EXPECT_TRUE(status.ok());
  EXPECT_FALSE(response.has_denied_response()); // request allowed to proceed (not redirected for auth)
}

TEST(ServiceImplTest, CheckMatchedRequest) {
  AuthServiceImpl service(
          *config::GetConfig("test/fixtures/valid-config.json"));

  ::envoy::service::auth::v2::CheckResponse response;
  ::envoy::service::auth::v2::CheckRequest request;

  request.mutable_attributes()->mutable_request()->mutable_http()->set_scheme(
      "https");
  auto request_headers = request.mutable_attributes()
      ->mutable_request()
      ->mutable_http()
      ->mutable_headers();
  request_headers->insert({"x-tenant-identifier", "tenant1"});

  ::grpc::Status status = service.Check(nullptr, &request, &response);
  EXPECT_TRUE(status.ok());
  EXPECT_EQ(response.denied_response().status().code(), envoy::type::StatusCode::Found); // redirected for auth

  bool hasLocation = false;
  for(auto& header : response.denied_response().headers()) {
    if (header.header().key() == "location") {
      EXPECT_THAT(header.header().value(), HasSubstr("https://google3/path3")); // redirected to the configured IDP
      hasLocation = true;
    }
  }
  EXPECT_TRUE(hasLocation);
}

}  // namespace service
}  // namespace authservice
