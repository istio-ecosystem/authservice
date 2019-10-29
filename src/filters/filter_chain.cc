#include "filter_chain.h"
#include "spdlog/spdlog.h"
#include "absl/strings/match.h"

namespace authservice {
namespace filters {
    FilterChainImpl::FilterChainImpl(std::shared_ptr<authservice::config::FilterChain> config): config_(config) {
    }

    bool FilterChainImpl::Matches(const ::envoy::service::auth::v2::CheckRequest* request) const {
      spdlog::trace("{}", __func__);
      auto matched = request->attributes().request().http().headers().find(config_->match().header());
      if (matched != request->attributes().request().http().headers().cend()) {
        switch (config_->match().value_case()) {
          case authservice::config::Match::kPrefix:
            return absl::StartsWith(matched->second, config_->match().prefix());
          case authservice::config::Match::kEquality:
            return matched->second == config_->match().equality();
          default:
            throw std::runtime_error("invalid FilterChain match type"); // This should never happen.
        }
      }
      return false;
    }

    std::unique_ptr<Filter> FilterChainImpl::New() {
      spdlog::trace("{}", __func__);
      return std::unique_ptr<Filter>();
    }
}  // namespace filters
}  // namespace authservice
