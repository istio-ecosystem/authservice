#ifndef AUTHSERVICE_SRC_FILTERS_OIDC_JWKS_STORAGE_H_
#define AUTHSERVICE_SRC_FILTERS_OIDC_JWKS_STORAGE_H_

#include <spdlog/spdlog.h>

#include <memory>
#include <mutex>

#include "jwt_verify_lib/jwks.h"
#include "src/common/http/http.h"

namespace authservice {
namespace filters {
namespace oidc {

class JwksStorage {
 public:
  virtual ~JwksStorage() = default;

  virtual void updateJwks(const std::string& new_jwks,
                          google::jwt_verify::Jwks::Type type) = 0;

  virtual google::jwt_verify::JwksPtr jwks() = 0;

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

class PermanentJwksStorageImpl : public JwksStorage {
 public:
  explicit PermanentJwksStorageImpl(const std::string& jwks,
                                    google::jwt_verify::Jwks::Type type)
      : jwks_(jwks), type_(type) {}

  void updateJwks(const std::string&, google::jwt_verify::Jwks::Type) override {
  }

  virtual google::jwt_verify::JwksPtr jwks() override {
    return parseJwks(jwks_, type_);
  }

 private:
  std::string jwks_;
  google::jwt_verify::Jwks::Type type_;
};

class NonPermanentJwksStorageImpl : public JwksStorage {
 public:
  class JwksFetcher {
   public:
    JwksFetcher(JwksStorage* parent, common::http::ptr_t http_ptr,
                const std::string& jwks_uri, std::chrono::seconds duration,
                boost::asio::io_context& ioc);

   private:
    void request(const boost::system::error_code&);

    JwksStorage* parent_;
    const std::string jwks_uri_;
    common::http::ptr_t http_ptr_;
    boost::asio::io_context& ioc_;
    boost::asio::steady_timer timer_;
  };

  explicit NonPermanentJwksStorageImpl(const std::string& jwks_uri,
                                       std::chrono::seconds duration,
                                       boost::asio::io_context& ioc) {
    if (duration != std::chrono::seconds(0)) {
      jwks_fetcher_ = std::make_unique<JwksFetcher>(
          this, common::http::ptr_t(new common::http::HttpImpl), jwks_uri,
          duration, ioc);
    }
  }

  void updateJwks(const std::string& new_jwks,
                  google::jwt_verify::Jwks::Type type) override {
    std::unique_lock<std::mutex> lck(mux_);
    jwks_ = new_jwks;
    type_ = type;
  }

  google::jwt_verify::JwksPtr jwks() override {
    std::unique_lock<std::mutex> lck(mux_);
    return parseJwks(jwks_, type_);
  }

 private:
  std::string jwks_;
  google::jwt_verify::Jwks::Type type_;
  std::unique_ptr<JwksFetcher> jwks_fetcher_;
  mutable std::mutex mux_;
};

}  // namespace oidc
}  // namespace filters
}  // namespace authservice

#endif  // AUTHSERVICE_SRC_FILTERS_OIDC_JWKS_STORAGE_H_
