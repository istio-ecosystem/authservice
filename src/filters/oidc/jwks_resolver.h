#ifndef AUTHSERVICE_SRC_FILTERS_OIDC_JWKS_RESOLVER_H_
#define AUTHSERVICE_SRC_FILTERS_OIDC_JWKS_RESOLVER_H_

#include <spdlog/spdlog.h>

#include <iostream>
#include <memory>

#include "absl/synchronization/mutex.h"
#include "jwt_verify_lib/jwks.h"
#include "src/common/http/http.h"

namespace authservice {
namespace filters {
namespace oidc {

class JwksResolver {
 public:
  virtual ~JwksResolver() = default;

  virtual google::jwt_verify::JwksPtr& jwks() = 0;

  virtual const std::string& rawStringJwks() const = 0;

 protected:
  google::jwt_verify::JwksPtr parseJwks(const std::string& jwks) {
    auto jwks_keys = google::jwt_verify::Jwks::createFrom(
        jwks, google::jwt_verify::Jwks::JWKS);
    spdlog::debug("status for jwks parsing: {}, {}", __func__,
                  google::jwt_verify::getStatusString(jwks_keys->getStatus()));

    if (jwks_keys->getStatus() != google::jwt_verify::Status::Ok) {
      spdlog::warn("{}: failed to parse new JWKs, {}", __func__,
                   google::jwt_verify::getStatusString(jwks_keys->getStatus()));
    }

    return jwks_keys;
  }
};

class StaticJwksResolverImpl : public JwksResolver {
 public:
  explicit StaticJwksResolverImpl(const std::string& jwks) : raw_jwks_(jwks) {
    jwks_ = parseJwks(jwks);
  }

  virtual google::jwt_verify::JwksPtr& jwks() override { return jwks_; }

  const std::string& rawStringJwks() const override { return raw_jwks_; }

 private:
  std::string raw_jwks_;
  google::jwt_verify::JwksPtr jwks_;
};

class DynamicJwksResolverImpl : public JwksResolver {
 public:
  class JwksFetcher {
   public:
    JwksFetcher(DynamicJwksResolverImpl* parent, common::http::ptr_t http_ptr,
                const std::string& jwks_uri, std::chrono::seconds duration,
                boost::asio::io_context& ioc);

   private:
    void request(const boost::system::error_code&);

    DynamicJwksResolverImpl* parent_;
    const std::string jwks_uri_;
    common::http::ptr_t http_ptr_;
    boost::asio::io_context& ioc_;
    std::chrono::seconds periodic_fetch_interval_sec_;
    boost::asio::steady_timer timer_;
  };

  explicit DynamicJwksResolverImpl(const std::string& jwks_uri,
                                   std::chrono::seconds duration,
                                   common::http::ptr_t http_ptr,
                                   boost::asio::io_context& ioc) {
    if (duration != std::chrono::seconds(0)) {
      jwks_fetcher_ = std::make_unique<JwksFetcher>(this, http_ptr, jwks_uri,
                                                    duration, ioc);
    }
  }

  void updateJwks(const std::string& new_jwks) {
    absl::MutexLock lck(&mux_);
    auto tmp_jwk = parseJwks(new_jwks);

    if (tmp_jwk->getStatus() != google::jwt_verify::Status::Ok) {
      spdlog::info("{}: failed to update JWKs with status, {}", __func__,
                   google::jwt_verify::getStatusString(tmp_jwk->getStatus()));
      return;
    }

    raw_jwks_ = new_jwks;
    jwks_ = std::move(tmp_jwk);
  }

  google::jwt_verify::JwksPtr& jwks() override {
    absl::ReaderMutexLock lck(&mux_);
    return jwks_;
  }

  const std::string& rawStringJwks() const override { return raw_jwks_; }

 private:
  std::string raw_jwks_ ABSL_GUARDED_BY(mux_);
  google::jwt_verify::JwksPtr jwks_ ABSL_GUARDED_BY(mux_);
  std::unique_ptr<JwksFetcher> jwks_fetcher_;
  absl::Mutex mux_;
};

}  // namespace oidc
}  // namespace filters
}  // namespace authservice

#endif  // AUTHSERVICE_SRC_FILTERS_OIDC_JWKS_RESOLVER_H_
