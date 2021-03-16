#include "src/filters/filter_chain.h"

#include "config/oidc/config.pb.h"
#include "gtest/gtest.h"
#include "src/filters/pipe.h"

namespace authservice {
namespace filters {

TEST(FilterChainTest, Name) {
  auto configuration =
      std::unique_ptr<config::FilterChain>(new config::FilterChain);
  configuration->set_name("expected");
  FilterChainImpl chain1(*configuration, 1);
  ASSERT_EQ(chain1.Name(), "expected");
}

TEST(FilterChainTest, MatchesWithoutMatchField) {
  auto configuration =
      std::unique_ptr<config::FilterChain>(new config::FilterChain);
  ::envoy::service::auth::v3::CheckRequest request1;
  FilterChainImpl chain1(*configuration, 1);
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
  FilterChainImpl chain1(*configuration, 1);
  ASSERT_FALSE(chain1.Matches(&request1));

  // valid prefix case
  ::envoy::service::auth::v3::CheckRequest request2;
  auto headers2 = request2.mutable_attributes()
                      ->mutable_request()
                      ->mutable_http()
                      ->mutable_headers();
  headers2->insert({"x-prefix-header", "prefixed-value"});
  FilterChainImpl chain2(*configuration, 1);
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
  FilterChainImpl chain1(*configuration, 1);
  ASSERT_FALSE(chain1.Matches(&request1));

  // valid header value case
  ::envoy::service::auth::v3::CheckRequest request2;
  auto headers2 = request2.mutable_attributes()
                      ->mutable_request()
                      ->mutable_http()
                      ->mutable_headers();
  headers2->insert({"x-equality-header", "exact-value"});
  FilterChainImpl chain2(*configuration, 1);
  ASSERT_TRUE(chain2.Matches(&request2));
}

TEST(FilterChainTest, New) {
  auto configuration =
      std::unique_ptr<config::FilterChain>(new config::FilterChain);
  auto filter_config = configuration->mutable_filters()->Add();
  filter_config->mutable_oidc()->set_jwks("some-value");

  FilterChainImpl chain(*configuration, 1);
  auto instance = chain.New();
  ASSERT_TRUE(dynamic_cast<Pipe *>(instance.get()) != nullptr);
}

TEST(FilterChainTest, Override) {
  auto default_config = config::oidc::LooseOIDCConfig();
  default_config.set_authorization_uri("https://istio.io/auth/default");
  default_config.set_token_uri("https://istio.io/token");
  default_config.set_jwks("default_jwk");
  default_config.mutable_id_token()->set_header("authorization");
  default_config.mutable_id_token()->set_preamble("Bearer");
  default_config.set_client_id("test-istio");
  default_config.set_client_secret("xxxxx-yyyyy-zzzzz");

  auto configuration = std::make_unique<config::FilterChain>();
  auto filter_config = configuration->mutable_filters()->Add();
  filter_config->mutable_oidc_override()->set_jwks("some-value");
  filter_config->mutable_oidc_override()->set_proxy_uri("http://proxy.io");
  filter_config->mutable_oidc_override()->set_callback_uri(
      "https://localhost:8080");

  FilterChainImpl chain(default_config, *configuration, 1);
  auto instance = chain.New();
  ASSERT_TRUE(dynamic_cast<Pipe *>(instance.get()) != nullptr);

  config::FilterChain expected_filter_chain;
  auto oidc_filter = config::oidc::OIDCConfig();
  oidc_filter.set_authorization_uri("https://istio.io/auth/default");
  oidc_filter.set_token_uri("https://istio.io/token");
  oidc_filter.set_jwks("some-value");
  oidc_filter.set_proxy_uri("http://proxy.io");
  oidc_filter.set_callback_uri("https://localhost:8080");
  oidc_filter.set_client_id("test-istio");
  oidc_filter.set_client_secret("xxxxx-yyyyy-zzzzz");
  oidc_filter.mutable_id_token()->set_header("authorization");
  oidc_filter.mutable_id_token()->set_preamble("Bearer");
  *expected_filter_chain.mutable_filters()->Add()->mutable_oidc() = oidc_filter;

  EXPECT_EQ(expected_filter_chain.DebugString(), chain.Config().DebugString());
}

}  // namespace filters
}  // namespace authservice