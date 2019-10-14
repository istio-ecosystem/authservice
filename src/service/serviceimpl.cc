#include "serviceimpl.h"
#include <grpcpp/grpcpp.h>
#include <memory>
#include "spdlog/spdlog.h"
#include "src/config/getconfig.h"
#include "src/filters/oidc/oidc_filter.h"
#include "src/filters/pipe.h"

namespace transparent_auth {
namespace service {

AuthServiceImpl::AuthServiceImpl(std::shared_ptr<authservice::config::Config> config) {
  root_.reset(new filters::Pipe);
  for (const auto &filter : config->filters()) {
    // TODO: implement filter specific construction.
    if (!filter.has_oidc()) {
      throw std::runtime_error("unsupported filter type");
    }

    auto token_request_parser = std::make_shared<filters::oidc::TokenResponseParserImpl>(
        google::jwt_verify::Jwks::createFrom(filter.oidc().jwks(), google::jwt_verify::Jwks::Type::JWKS));

    auto token_encryptor = common::session::TokenEncryptor::Create(
        filter.oidc().cryptor_secret(), common::session::EncryptionAlg::AES256GCM,
        common::session::HKDFHash::SHA512);

    auto http = common::http::ptr_t(new common::http::http_impl);

    root_->AddFilter(filters::FilterPtr(
        new filters::oidc::OidcFilter(http, filter.oidc(), token_request_parser, token_encryptor)));
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
