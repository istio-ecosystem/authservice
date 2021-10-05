#include "src/filters/filter_chain.h"

#include "boost/asio/io_context.hpp"
#include "config/oidc/config.pb.h"
#include "gtest/gtest.h"
#include "src/filters/pipe.h"
#include "test/filters/oidc/mocks.h"

namespace authservice {
namespace filters {

boost::asio::io_context io_context;

TEST(FilterChainTest, Name) {
  auto configuration =
      std::unique_ptr<config::FilterChain>(new config::FilterChain);
  configuration->set_name("expected");
  FilterChainImpl chain1(io_context, *configuration, 1);
  ASSERT_EQ(chain1.Name(), "expected");
}

TEST(FilterChainTest, MatchesWithoutMatchField) {
  auto configuration =
      std::unique_ptr<config::FilterChain>(new config::FilterChain);
  ::envoy::service::auth::v3::CheckRequest request1;
  FilterChainImpl chain1(io_context, *configuration, 1);
  ASSERT_TRUE(chain1.Matches(&request1));
}

TEST(FilterChainTest, MatchesPrefix) {
  auto configuration =
      std::unique_ptr<config::FilterChain>(new config::FilterChain);
  configuration->mutable_match()->set_header("x-prefix-header");
  configuration->mutable_match()->set_prefix("prefixed-");

  // invalid prefix case
  ::envoy::service::auth::v3::CheckRequest request1;
  auto headers1 = request1.mutable_attributes()
                      ->mutable_request()
                      ->mutable_http()
                      ->mutable_headers();
  headers1->insert({"x-prefix-header", "not-prefixed-value"});
  FilterChainImpl chain1(io_context, *configuration, 1);
  ASSERT_FALSE(chain1.Matches(&request1));

  // valid prefix case
  ::envoy::service::auth::v3::CheckRequest request2;
  auto headers2 = request2.mutable_attributes()
                      ->mutable_request()
                      ->mutable_http()
                      ->mutable_headers();
  headers2->insert({"x-prefix-header", "prefixed-value"});
  FilterChainImpl chain2(io_context, *configuration, 1);
  ASSERT_TRUE(chain2.Matches(&request2));
}

TEST(FilterChainTest, MatchesEquality) {
  auto configuration =
      std::unique_ptr<config::FilterChain>(new config::FilterChain);
  configuration->mutable_match()->set_header("x-equality-header");
  configuration->mutable_match()->set_equality("exact-value");

  // invalid header value case
  ::envoy::service::auth::v3::CheckRequest request1;
  auto headers1 = request1.mutable_attributes()
                      ->mutable_request()
                      ->mutable_http()
                      ->mutable_headers();
  headers1->insert({"x-equality-header", "not-an-exact-value"});
  FilterChainImpl chain1(io_context, *configuration, 1);
  ASSERT_FALSE(chain1.Matches(&request1));

  // valid header value case
  ::envoy::service::auth::v3::CheckRequest request2;
  auto headers2 = request2.mutable_attributes()
                      ->mutable_request()
                      ->mutable_http()
                      ->mutable_headers();
  headers2->insert({"x-equality-header", "exact-value"});
  FilterChainImpl chain2(io_context, *configuration, 1);
  ASSERT_TRUE(chain2.Matches(&request2));
}

TEST(FilterChainTest, New) {
  auto configuration =
      std::unique_ptr<config::FilterChain>(new config::FilterChain);
  auto filter_config = configuration->mutable_filters()->Add();
  filter_config->mutable_oidc()->set_jwks("some-value");

  FilterChainImpl chain(io_context, *configuration, 1);
  auto instance = chain.New();
  ASSERT_TRUE(dynamic_cast<Pipe *>(instance.get()) != nullptr);
}

TEST(FilterChainTest, MockFilter) {
  auto configuration = std::make_unique<config::FilterChain>();
  auto filter_config = configuration->mutable_filters()->Add();
  filter_config->mutable_mock()->set_allow(true);

  FilterChainImpl chain(io_context, *configuration, 1);
  auto instance = chain.New();
  ASSERT_TRUE(dynamic_cast<Pipe *>(instance.get()) != nullptr);
}

TEST(FilterChainTest, CheckJwks) {
  // google::jwt_verify::JwksPtr jwks = nullptr;
  // MockJwksResolver resolver(jwks);
}

}  // namespace filters
}  // namespace authservice
