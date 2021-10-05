#include "filter_chain.h"

#include <algorithm>
#include <memory>
#include <stdexcept>

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
  // Validate that filter chain has only one OIDC filter.
  const int oidc_filter_count =
      std::count_if(config_.filters().begin(), config_.filters().end(),
                    [](const auto& filter) { return filter.has_oidc(); });
  if (oidc_filter_count > 1) {
    throw std::runtime_error(
        "only one filter of type \"oidc\" is allowed in a chain");
  }

  bool skip_oidc_preparation = false;

  if (oidc_filter_count == 0) {
    skip_oidc_preparation = true;
  }

  if (!skip_oidc_preparation) {
    // Setup OIDC related modules.
    const auto& oidc_filter =
        std::find_if(config_.filters().begin(), config_.filters().end(),
                     [](const auto& filter) { return filter.has_oidc(); });
    assert(oidc_filter != config_.filters().end());

    // Note that each incoming request gets a new instance of Filter to handle
    // it, so here we ensure that each instance returned by New() shares the
    // same session store.
    auto absolute_session_timeout =
        oidc_filter->oidc().absolute_session_timeout();
    auto idle_session_timeout = oidc_filter->oidc().idle_session_timeout();

    if (oidc_filter->oidc().has_redis_session_store_config()) {
      spdlog::trace("{}: using RedisSession Store", __func__);
      oidc_session_store_ =
          oidc::RedisSessionStoreFactory(
              oidc_filter->oidc().redis_session_store_config(),
              absolute_session_timeout, idle_session_timeout, threads_)
              .create();
    } else {
      spdlog::trace("{}: using InMemorySession Store", __func__);
      oidc_session_store_ = oidc::InMemorySessionStoreFactory(
                                absolute_session_timeout, idle_session_timeout)
                                .create();
    }

    jwks_resolver_cache_ =
        std::make_unique<oidc::JwksResolverCache>(oidc_filter->oidc(), ioc);
  }

  // Create filter chain factory
  for (const auto& filter : config_.filters()) {
    if (filter.has_mock()) {
      filter_factory_chain_.emplace_back(
          std::make_unique<mock::FilterFactory>(filter.mock()));
    } else if (filter.has_oidc()) {
      filter_factory_chain_.emplace_back(std::make_unique<oidc::FilterFactory>(
          filter.oidc(), oidc_session_store_, jwks_resolver_cache_));
    } else {
      throw std::runtime_error("invalid filter type");
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

  for (auto&& filter_factory : filter_factory_chain_) {
    result->AddFilter(filter_factory->create());
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

}  // namespace filters
}  // namespace authservice
