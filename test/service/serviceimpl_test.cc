#include "src/service/serviceimpl.h"
#include "gtest/gtest.h"
#include "src/config/getconfig.h"

namespace authservice {
namespace service {
TEST(ServiceImplTest, CheckUnmatchedRequest) {
  auto config = config::GetConfig("test/fixtures/valid-config.json");
  AuthServiceImpl service(config.get());
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
  auto config = config::GetConfig("test/fixtures/valid-config.json");
  AuthServiceImpl service(config.get());
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
