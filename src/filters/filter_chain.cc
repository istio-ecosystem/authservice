#include "filter_chain.h"

#include <memory>

#include "absl/strings/match.h"
#include "absl/strings/str_cat.h"
#include "boost/asio/io_context.hpp"
#include "config/config.pb.h"
#include "config/oidc/config.pb.h"
#include "config/oidc/config.pb.validate.h"
#include "spdlog/spdlog.h"
#include "src/config/get_config.h"
#include "src/filters/mock/mock_filter.h"
#include "src/filters/oidc/in_memory_session_store.h"
#include "src/filters/oidc/oidc_filter.h"
#include "src/filters/oidc/redis_session_store.h"
#include "src/filters/pipe.h"

namespace authservice {
namespace filters {

FilterChainImpl::FilterChainImpl(boost::asio::io_context& ioc,
                                 config::FilterChain config,
                                 unsigned int threads)
    : threads_(threads),
      config_(std::move(config)),
      oidc_session_store_(nullptr) {
  for (auto& filter : config_.filters()) {
    // TODO(shikugawa): We need an abstraction to handle many types of filters.
    if (filter.type_case() == config::Filter::TypeCase::kOidc) {
      switch (filter.oidc().jwks_config_case()) {
        case config::oidc::OIDCConfig::kJwks:
          jwks_resolver_map_.emplace_back(
              std::make_shared<oidc::StaticJwksResolverImpl>(
                  filter.oidc().jwks()));
          break;
        case config::oidc::OIDCConfig::kJwksFetcher: {
          uint32_t periodic_fetch_interval_sec =
              filter.oidc().jwks_fetcher().periodic_fetch_interval_sec();
          if (periodic_fetch_interval_sec == 0) {
            periodic_fetch_interval_sec = 1200;
          }

          auto http_ptr = common::http::ptr_t(new common::http::HttpImpl);

          jwks_resolver_map_.emplace_back(
              std::make_shared<oidc::DynamicJwksResolverImpl>(
                  filter.oidc().jwks_fetcher().jwks_uri(),
                  std::chrono::seconds(periodic_fetch_interval_sec), http_ptr,
                  ioc));
        } break;
        default:
          throw std::runtime_error("invalid JWKs config type");
      }
    }
  }
}

const std::string& FilterChainImpl::Name() const { return config_.name(); }

bool FilterChainImpl::Matches(
    const ::envoy::service::auth::v3::CheckRequest* request) const {
  spdlog::trace("{}", __func__);
  if (config_.has_match()) {
    auto matched = request->attributes().request().http().headers().find(
        config_.match().header());
    if (matched != request->attributes().request().http().headers().cend()) {
      switch (config_.match().criteria_case()) {
        case config::Match::kPrefix:
          return absl::StartsWith(matched->second, config_.match().prefix());
        case config::Match::kEquality:
          return matched->second == config_.match().equality();
        default:
          throw std::runtime_error(
              "invalid FilterChain match type");  // This should never happen.
      }
    }
    return false;
  }
  return true;
}

std::unique_ptr<Filter> FilterChainImpl::New() {
  spdlog::trace("{}", __func__);
  std::unique_ptr<Pipe> result(new Pipe);
  int oidc_filter_count = 0;
  for (auto i = 0; i < config_.filters_size(); ++i) {
    auto& filter = *config_.mutable_filters(i);
    if (filter.has_oidc()) {
      ++oidc_filter_count;
    } else if (filter.has_mock()) {
      result->AddFilter(std::make_unique<mock::MockFilter>(filter.mock()));
      continue;
    } else {
      throw std::runtime_error("unsupported filter type");
    }

    if (oidc_filter_count > 1) {
      throw std::runtime_error(
          "only one filter of type \"oidc\" is allowed in a chain");
    }
    auto token_response_parser =
        std::make_shared<oidc::TokenResponseParserImpl>(
            jwks_resolver_map_[i]->jwks());
    auto session_string_generator =
        std::make_shared<common::session::SessionStringGenerator>();

    auto http = common::http::ptr_t(new common::http::HttpImpl);

    if (oidc_session_store_ == nullptr) {
      // Note that each incoming request gets a new instance of Filter to handle
      // it, so here we ensure that each instance returned by New() shares the
      // same session store.
      auto absolute_session_timeout = filter.oidc().absolute_session_timeout();
      auto idle_session_timeout = filter.oidc().idle_session_timeout();

      if (filter.oidc().has_redis_session_store_config()) {
        auto redis_sever_uri =
            filter.oidc().redis_session_store_config().server_uri();
        spdlog::trace(
            "{}: redis configuration found. attempting to connect to: {}",
            __func__, redis_sever_uri);
        auto redis_wrapper =
            std::make_shared<oidc::RedisWrapper>(redis_sever_uri, threads_);
        auto redis_retry_wrapper =
            std::make_shared<oidc::RedisRetryWrapper>(redis_wrapper);
        oidc_session_store_ = std::static_pointer_cast<oidc::RedisSessionStore>(
            std::make_shared<oidc::RedisSessionStore>(
                std::make_shared<common::utilities::TimeService>(),
                absolute_session_timeout, idle_session_timeout,
                redis_retry_wrapper));
      } else {
        spdlog::trace("{}: using InMemorySession Store", __func__);
        oidc_session_store_ = std::static_pointer_cast<oidc::SessionStore>(
            std::make_shared<oidc::InMemorySessionStore>(
                std::make_shared<common::utilities::TimeService>(),
                absolute_session_timeout, idle_session_timeout));
      }
    }

    result->AddFilter(FilterPtr(
        new oidc::OidcFilter(http, filter.oidc(), token_response_parser,
                             session_string_generator, oidc_session_store_)));
  }
  return result;
}

void FilterChainImpl::DoPeriodicCleanup() {
  if (oidc_session_store_ != nullptr) {
    spdlog::info("{}: removing expired sessions from chain {}", __func__,
                 Name());
    oidc_session_store_->RemoveAllExpired();
  }
}

bool FilterChainImpl::allJwksActiveInFilters() const {
  for (auto&& jwk_resolver : jwks_resolver_map_) {
    if (jwk_resolver->jwks() == nullptr) {
      return false;
    }
  }
  return true;
}

}  // namespace filters
}  // namespace authservice
