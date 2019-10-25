#include "src/service/serviceimpl.h"
#include "gtest/gtest.h"
#include "src/config/getconfig.h"

namespace authservice {
namespace service {
TEST(ServiceImplTest, Check) {
  AuthServiceImpl service(
      authservice::config::GetConfig("test/fixtures/valid-config.json"));
  ::envoy::service::auth::v2::CheckRequest request;
  ::envoy::service::auth::v2::CheckResponse response;

  request.mutable_attributes()->mutable_request()->mutable_http()->set_scheme(
      "https");
  auto request_headers = request.mutable_attributes()
                             ->mutable_request()
                             ->mutable_http()
                             ->mutable_headers();
  request_headers->insert({"authorization", "something"});

  ::grpc::Status status = service.Check(nullptr, &request, &response);
  EXPECT_TRUE(status.ok());
}

}  // namespace service
}  // namespace authservice
