#include "src/service/service_impl.h"
#include "src/config/get_config.h"
#include "gtest/gtest.h"

namespace authservice {
namespace service {
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
}

}  // namespace service
}  // namespace authservice
