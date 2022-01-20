#include "src/filters/oidc/jwks_resolver.h"

#include <chrono>

namespace authservice {
namespace filters {
namespace oidc {

namespace {
constexpr uint32_t kJwksInitialFetchDelaySec = 3;
constexpr uint32_t kJwksPeriodicFetchIntervalSec = 1200;
}  // namespace

DynamicJwksResolverImpl::JwksFetcher::JwksFetcher(
    DynamicJwksResolverImpl* parent, common::http::ptr_t http_ptr,
    const config::oidc::OIDCConfig::JwksFetcherConfig& config,
    boost::asio::io_context& io_context)
    : parent_(parent),
      jwks_uri_(config.jwks_uri()),
      http_ptr_(http_ptr),
      ioc_(io_context),
      periodic_fetch_interval_sec_(
          std::chrono::seconds(config.periodic_fetch_interval_sec() != 0
                                   ? config.periodic_fetch_interval_sec()
                                   : kJwksPeriodicFetchIntervalSec)),
      timer_(ioc_, periodic_fetch_interval_sec_),
      verify_peer_cert_(!config.skip_verify_peer_cert()) {
  // Extract initial JWKs.
  // After timer callback sucessful, next timer invocation will be scheduled.
  timer_.expires_at(std::chrono::steady_clock::now() +
                    std::chrono::seconds(kJwksInitialFetchDelaySec));
  timer_.async_wait(
      [this](const boost::system::error_code& ec) { this->request(ec); });
}

void DynamicJwksResolverImpl::JwksFetcher::request(
    const boost::system::error_code&) {
  boost::asio::spawn(ioc_, [this](boost::asio::yield_context yield) {
    common::http::TransportSocketOptions opt;
    opt.verify_peer_ = verify_peer_cert_;
    auto resp = http_ptr_->Get(jwks_uri_, {}, "", opt, "", ioc_, yield);
    auto next_schedule_interval = periodic_fetch_interval_sec_;

    if (resp == nullptr) {
      spdlog::warn("{}: HTTP connection error", __func__);
    } else {
      if (resp->result() != boost::beast::http::status::ok) {
        spdlog::warn("{}: HTTP response error: {}", __func__,
                     resp->result_int());
      } else {
        const auto& fetched_jwks = resp->body();
        // TODO(shikugawa): Prevent lock with same jwks.
        parent_->updateJwks(fetched_jwks);
      }
    }

    if (parent_->jwks() == nullptr) {
      // On Kubernetes, depending on the timing of the Pod startup,
      // the first egress HTTP/HTTPS request may fail. This problem
      // goes away after a few seconds from the start of the pod,
      // but by default, the timer is rescheduled after 20 minutes,
      // so if the first fetch fails, the JWKs will be empty for 20 minutes.
      // To prevent this problem, the timer should be rescheduled depending on
      // initial_fetch_delay_sec.
      next_schedule_interval = std::chrono::seconds(kJwksInitialFetchDelaySec);
    }

    timer_.expires_at(std::chrono::steady_clock::now() +
                      next_schedule_interval);
    timer_.async_wait(
        [this](const boost::system::error_code& ec) { this->request(ec); });
  });
}

}  // namespace oidc
}  // namespace filters
}  // namespace authservice
