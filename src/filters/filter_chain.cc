#include "filter_chain.h"
#include "spdlog/spdlog.h"
#include "absl/strings/match.h"
#include "src/filters/oidc/oidc_filter.h"
#include "src/filters/pipe.h"
#include "src/filters/oidc/in_memory_session_store.h"

namespace authservice {
namespace filters {

FilterChainImpl::FilterChainImpl(authservice::config::FilterChain config) : config_(std::move(config)) {
  // Ensure each instance returned by New() has the same session store.
  // Each request gets a new instance of Filter.
  session_store_ = std::static_pointer_cast<filters::oidc::SessionStore>(
      std::make_shared<filters::oidc::InMemorySessionStore>());
}

const std::string &FilterChainImpl::Name() const {
  return config_.name();
}

bool FilterChainImpl::Matches(const ::envoy::service::auth::v2::CheckRequest *request) const {
  spdlog::trace("{}", __func__);
  if (config_.has_match()) {
    auto matched = request->attributes().request().http().headers().find(config_.match().header());
    if (matched != request->attributes().request().http().headers().cend()) {
      switch (config_.match().criteria_case()) {
        case authservice::config::Match::kPrefix:
          return absl::StartsWith(matched->second, config_.match().prefix());
        case authservice::config::Match::kEquality:
          return matched->second == config_.match().equality();
        default:
          throw std::runtime_error("invalid FilterChain match type"); // This should never happen.
      }
    }
    return false;
  }
  return true;
}

std::unique_ptr<Filter> FilterChainImpl::New() {
  spdlog::trace("{}", __func__);
  std::unique_ptr<Pipe> result(new Pipe);
  for (const auto &filter : config_.filters()) {
    if (!filter.has_oidc()) {
      throw std::runtime_error("unsupported filter type");
    }

    auto token_request_parser =
        std::make_shared<oidc::TokenResponseParserImpl>(
            google::jwt_verify::Jwks::createFrom(
                filter.oidc().jwks(), google::jwt_verify::Jwks::Type::JWKS));

    auto token_encryptor = common::session::TokenEncryptor::Create(
        filter.oidc().cryptor_secret(),
        common::session::EncryptionAlg::AES256GCM,
        common::session::HKDFHash::SHA512);

    auto session_id_generator = std::make_shared<common::session::SessionIdGenerator>();

    auto http = common::http::ptr_t(new common::http::http_impl);

    result->AddFilter(filters::FilterPtr(new filters::oidc::OidcFilter(
        http, filter.oidc(), token_request_parser, token_encryptor, session_id_generator, session_store_)));
  }
  return result;
}

}  // namespace filters
}  // namespace authservice
