#include "serviceimpl.h"
#include <grpcpp/grpcpp.h>
#include "spdlog/spdlog.h"
#include "src/config/getconfig.h"
#include "src/filters/oidc/oidc_filter.h"
#include "src/filters/pipe.h"

namespace transparent_auth {
namespace service {

namespace {
// TODO: dynamically load config.
const char *jwks =
    R"({"keys":[{"kid":"xxx","kty":"RSA","alg":"RS256","use":"sig","n":"xxx","e":"AQAB","x5c":["xxx"]}]})";
const std::string cryptor_secret = "xxx";
}  // namespace

AuthServiceImpl::AuthServiceImpl(const std::string &config)
    : token_request_parser_(google::jwt_verify::Jwks::createFrom(
          jwks, google::jwt_verify::Jwks::Type::JWKS)) {
  root_.reset(new filters::Pipe);
  config_ = config::GetConfig(config);
  for (const auto &filter : config_->filters()) {
    // TODO: implement filter specific construction.
    if (!filter.has_oidc()) {
      throw std::runtime_error("unsupported filter type");
    }
    root_->AddFilter(filters::FilterPtr(new filters::oidc::OidcFilter(
        common::http::ptr_t(new common::http::http_impl), filter.oidc(),
        token_request_parser_,
        common::session::TokenEncryptor::Create(
            cryptor_secret, common::session::EncryptionAlg::AES256GCM,
            common::session::HKDFHash::SHA512))));
  }
}

::grpc::Status AuthServiceImpl::Check(
    ::grpc::ServerContext *,
    const ::envoy::service::auth::v2::CheckRequest *request,
    ::envoy::service::auth::v2::CheckResponse *response) {
  spdlog::trace("{}", __func__);
  try {
    auto status = root_->Process(request, response);
    // See src/filters/filter.h:filter::Process for a description of how status
    // codes should be handled
    switch (status) {
      case google::rpc::Code::OK:               // The request was successful
      case google::rpc::Code::UNAUTHENTICATED:  // A filter indicated the
                                                // request had no authentication
                                                // but was processed correctly.
      case google::rpc::Code::PERMISSION_DENIED:  // A filter indicated
                                                  // insufficient permissions
                                                  // for the authenticated
                                                  // requester but was processed
                                                  // correctly.
        return ::grpc::Status::OK;
      case google::rpc::Code::INVALID_ARGUMENT:  // The request was not well
                                                 // formed. Indicate a
                                                 // processing error to the
                                                 // caller.
        return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT,
                              "invalid request");
      default:  // All other errors are treated as internal processing failures.
        return ::grpc::Status(::grpc::StatusCode::INTERNAL, "internal error");
    }
  } catch (const std::exception &exception) {
    spdlog::error("%s unexpected error: %s", __func__, exception.what());
  } catch (...) {
    spdlog::error("%s unexpected error: unknown", __func__);
  }
  return ::grpc::Status(::grpc::StatusCode::INTERNAL, "internal error");
}
}  // namespace service
}  // namespace transparent_auth
