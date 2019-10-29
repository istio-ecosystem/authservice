#include "src/filters/filter_chain.h"
#include "gtest/gtest.h"

namespace authservice {
namespace filters {

TEST(FilterChainTest, MatchesPrefix) {
    auto configuration = std::shared_ptr<authservice::config::FilterChain>(new authservice::config::FilterChain);
    configuration->mutable_match()->set_header("x-prefix-header");
    configuration->mutable_match()->set_prefix("prefixed-");

    // invalid prefix case
    ::envoy::service::auth::v2::CheckRequest request1;
    auto headers1 = request1.mutable_attributes()->mutable_request()->mutable_http()->mutable_headers();
    headers1->insert({"x-prefix-header", "not-prefixed-value"});
    FilterChainImpl chain1(configuration);
    ASSERT_FALSE(chain1.Matches(&request1));

    // valid prefix case
    ::envoy::service::auth::v2::CheckRequest request2;
    auto headers2 = request2.mutable_attributes()->mutable_request()->mutable_http()->mutable_headers();
    headers2->insert({"x-prefix-header", "prefixed-value"});
    FilterChainImpl chain2(configuration);
    ASSERT_TRUE(chain2.Matches(&request2));
}

TEST(FilterChainTest, MatchesEquality) {
  auto configuration = std::shared_ptr<authservice::config::FilterChain>(new authservice::config::FilterChain);
  configuration->mutable_match()->set_header("x-equality-header");
  configuration->mutable_match()->set_equality("exact-value");

  // invalid header value case
  ::envoy::service::auth::v2::CheckRequest request1;
  auto headers1 = request1.mutable_attributes()->mutable_request()->mutable_http()->mutable_headers();
  headers1->insert({"x-equality-header", "not-an-exact-value"});
  FilterChainImpl chain1(configuration);
  ASSERT_FALSE(chain1.Matches(&request1));

  // valid header value case
  ::envoy::service::auth::v2::CheckRequest request2;
  auto headers2 = request2.mutable_attributes()->mutable_request()->mutable_http()->mutable_headers();
  headers2->insert({"x-equality-header", "exact-value"});
  FilterChainImpl chain2(configuration);
  ASSERT_TRUE(chain2.Matches(&request2));
}

}  // namespace filters
}  // namespace authservice