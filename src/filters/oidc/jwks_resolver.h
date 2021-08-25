#ifndef AUTHSERVICE_SRC_FILTERS_OIDC_JWKS_RESOLVER_H_
#define AUTHSERVICE_SRC_FILTERS_OIDC_JWKS_RESOLVER_H_

#include <spdlog/spdlog.h>

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

  virtual void updateJwks(const std::string& new_jwks,
                          google::jwt_verify::Jwks::Type type) = 0;

  virtual google::jwt_verify::JwksPtr& jwks() = 0;

 protected:
  google::jwt_verify::JwksPtr parseJwks(const std::string& jwks,
                                        google::jwt_verify::Jwks::Type type) {
    auto jwks_keys = google::jwt_verify::Jwks::createFrom(jwks, type);
    spdlog::debug("status for jwks parsing: {}, {}", __func__,
                  google::jwt_verify::getStatusString(jwks_keys->getStatus()));

    if (jwks_keys->getStatus() != google::jwt_verify::Status::Ok) {
      spdlog::warn("{}: failed to parse new JWKs", __func__);
    }

    return jwks_keys;
  }
};

class StaticJwksResolverImpl : public JwksResolver {
 public:
  explicit StaticJwksResolverImpl(const std::string& jwks,
                                  google::jwt_verify::Jwks::Type type)
      : type_(type) {
    jwks_ = parseJwks(jwks, type_);
  }

  void updateJwks(const std::string&, google::jwt_verify::Jwks::Type) override {
  }

  virtual google::jwt_verify::JwksPtr& jwks() override { return jwks_; }

 private:
  google::jwt_verify::JwksPtr jwks_;
  google::jwt_verify::Jwks::Type type_;
};

class DynamicJwksResolverImpl : public JwksResolver {
 public:
  class JwksFetcher {
   public:
    JwksFetcher(JwksResolver* parent, common::http::ptr_t http_ptr,
                const std::string& jwks_uri, std::chrono::seconds duration,
                boost::asio::io_context& ioc);

   private:
    void request(const boost::system::error_code&);

    JwksResolver* parent_;
    const std::string jwks_uri_;
    common::http::ptr_t http_ptr_;
    boost::asio::io_context& ioc_;
    std::chrono::seconds duration_;
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

  void updateJwks(const std::string& new_jwks,
                  google::jwt_verify::Jwks::Type type) override {
    absl::MutexLock lck(&mux_);
    type_ = type;
    jwks_ = parseJwks(new_jwks, type_);
  }

  google::jwt_verify::JwksPtr& jwks() override {
    absl::ReaderMutexLock lck(&mux_);
    return jwks_;
  }

 private:
  google::jwt_verify::JwksPtr jwks_ ABSL_GUARDED_BY(mux_);
  google::jwt_verify::Jwks::Type type_;
  std::unique_ptr<JwksFetcher> jwks_fetcher_;
  absl::Mutex mux_;
};

}  // namespace oidc
}  // namespace filters
}  // namespace authservice

#endif  // AUTHSERVICE_SRC_FILTERS_OIDC_JWKS_RESOLVER_H_
