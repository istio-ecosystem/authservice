#include "src/filters/oidc/jwks_resolver.h"

namespace authservice {
namespace filters {
namespace oidc {

DynamicJwksResolverImpl::JwksFetcher::JwksFetcher(
    DynamicJwksResolverImpl* parent, common::http::ptr_t http_ptr,
    const std::string& jwks_uri,
    std::chrono::seconds periodic_fetch_interval_sec,
    boost::asio::io_context& io_context)
    : parent_(parent),
      jwks_uri_(jwks_uri),
      http_ptr_(http_ptr),
      ioc_(io_context),
      periodic_fetch_interval_sec_(periodic_fetch_interval_sec),
      timer_(ioc_, periodic_fetch_interval_sec_) {
  timer_.async_wait(
      [this](const boost::system::error_code& ec) { this->request(ec); });
}

void DynamicJwksResolverImpl::JwksFetcher::request(
    const boost::system::error_code&) {
  boost::asio::spawn(ioc_, [this](boost::asio::yield_context yield) {
    auto resp = http_ptr_->Get(jwks_uri_, {}, "", "", "", ioc_, yield);

    if (resp == nullptr) {
      spdlog::info("{}: HTTP connection error", __func__);
    } else {
      if (resp->result() != boost::beast::http::status::ok) {
        spdlog::info("{}: HTTP response error: {}", __func__,
                     resp->result_int());
      } else {
        const auto& fetched_jwks = resp->body();
        // TODO(shikugawa): Prevent lock with same jwks.
        parent_->updateJwks(fetched_jwks);
      }
    }

    timer_.expires_at(std::chrono::steady_clock::now() +
                      periodic_fetch_interval_sec_);
    timer_.async_wait(
        [this](const boost::system::error_code& ec) { this->request(ec); });
  });
}

}  // namespace oidc
}  // namespace filters
}  // namespace authservice
