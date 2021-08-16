#ifndef AUTHSERVICE_SRC_FILTERS_OIDC_JWKS_STORAGE_H_
#define AUTHSERVICE_SRC_FILTERS_OIDC_JWKS_STORAGE_H_

#include <spdlog/spdlog.h>

#include <iostream>
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

  virtual const google::jwt_verify::JwksPtr& jwks() const = 0;
};

class JwksStorageImpl : public JwksStorage {
 public:
  virtual void updateJwks(const std::string&,
                          google::jwt_verify::Jwks::Type) override {}

  virtual const google::jwt_verify::JwksPtr& jwks() const override {
    return jwks_;
  }

 protected:
  google::jwt_verify::JwksPtr parseJwks(const std::string& jwks,
                                        google::jwt_verify::Jwks::Type type) {
    auto jwks_keys = google::jwt_verify::Jwks::createFrom(jwks, type);
    spdlog::debug("status for jwks parsing: {}, {}", __func__,
                  google::jwt_verify::getStatusString(jwks_keys->getStatus()));

    if (jwks_keys->getStatus() == google::jwt_verify::Status::Ok) {
      return jwks_keys;
    }

    return nullptr;
  }

  google::jwt_verify::JwksPtr jwks_;
};

class PermanentJwksStorageImpl : public JwksStorageImpl {
 public:
  explicit PermanentJwksStorageImpl(const std::string& jwks,
                                    google::jwt_verify::Jwks::Type type) {
    jwks_ = parseJwks(jwks, type);
  }

  void updateJwks(const std::string&, google::jwt_verify::Jwks::Type) override {
  }
};

class NonPermanentJwksStorageImpl : public JwksStorageImpl {
 public:
  class JwksFetcher {
   public:
    JwksFetcher(JwksStorage* parent, common::http::ptr_t http_ptr,
                const std::string& jwks_uri, boost::asio::io_context& ioc);

   private:
    void request(const boost::system::error_code&);

    JwksStorage* parent_;
    const std::string jwks_uri_;
    common::http::ptr_t http_ptr_;
    boost::asio::io_context& ioc_;
    boost::asio::deadline_timer timer_;
  };

  explicit NonPermanentJwksStorageImpl(const std::string& jwks_uri,
                                       boost::asio::io_context& ioc)
      : jwks_fetcher_(std::make_unique<JwksFetcher>(
            this, common::http::ptr_t(new common::http::HttpImpl), jwks_uri,
            ioc)) {}

  void updateJwks(const std::string& new_jwks,
                  google::jwt_verify::Jwks::Type type) override {
    std::unique_lock<std::mutex> lck(mux_);
    auto new_jwks_keys = parseJwks(new_jwks, type);

    if (new_jwks_keys->getStatus() == google::jwt_verify::Status::Ok) {
      jwks_.reset(new_jwks_keys.get());
    } else {
      spdlog::error("failed to parse new JWK");
    }
  }

  const google::jwt_verify::JwksPtr& jwks() const override {
    std::unique_lock<std::mutex> lck(mux_);
    return jwks_;
  }

 private:
  std::unique_ptr<JwksFetcher> jwks_fetcher_;
  mutable std::mutex mux_;
};

}  // namespace oidc
}  // namespace filters
}  // namespace authservice

#endif  // AUTHSERVICE_SRC_FILTERS_OIDC_JWKS_STORAGE_H_
