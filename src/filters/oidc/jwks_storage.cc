#include "src/filters/oidc/jwks_storage.h"

namespace authservice {
namespace filters {
namespace oidc {

NonPermanentJwksStorageImpl::JwksFetcher::JwksFetcher(
    JwksStorage* parent, common::http::ptr_t http_ptr,
    const std::string& jwks_uri, boost::asio::io_context& io_context)
    : parent_(parent),
      jwks_uri_(jwks_uri),
      http_ptr_(http_ptr),
      ioc_(io_context),
      timer_(ioc_, boost::posix_time::seconds(5)) {}

void NonPermanentJwksStorageImpl::JwksFetcher::request(
    const boost::system::error_code&) {
  boost::asio::spawn(ioc_, [this](boost::asio::yield_context yield) {
    auto resp = http_ptr_->DoRequest(jwks_uri_, {}, "", "",
                                     beast::http::verb::get, "", ioc_, yield);
    const auto& fetched_jwks = resp->body();
    // TODO(shikugawa): Prevent lock with same jwks.
    // TODO(shikugawa): Support PEM.
    parent_->updateJwks(fetched_jwks, google::jwt_verify::Jwks::Type::JWKS);

    timer_.expires_at(timer_.expires_at() + boost::posix_time::seconds(5));
    timer_.async_wait(
        [this](const boost::system::error_code& ec) { this->request(ec); });
  });
}

}  // namespace oidc
}  // namespace filters
}  // namespace authservice
