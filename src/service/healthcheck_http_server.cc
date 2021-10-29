#include "healthcheck_http_server.h"

namespace authservice {
namespace service {

HealthcheckHttpConnection::HealthcheckHttpConnection(
    HealthcheckAsyncServer& parent,
    const std::vector<std::unique_ptr<filters::FilterChain>>& chains,
    tcp::socket sock)
    : sock_(std::move(sock)), chains_(chains), parent_(parent) {
  startRead();
}

void HealthcheckHttpConnection::startRead() {
  http::async_read(sock_, read_buffer_, request_, [this](auto ec, auto) {
    if (!ec) {
      onReadDone();
    } else {
      sock_.close();
      parent_.removeConnection(this);
    }
  });
}

void HealthcheckHttpConnection::startWrite() {
  http::async_write(sock_, response_, [this](auto ec, auto) {
    if (!ec) {
      onWriteDone();
    } else {
      sock_.close();
      parent_.removeConnection(this);
    }
  });
}

void HealthcheckHttpConnection::onReadDone() {
  response_.version(request_.version());
  http::status status = http::status::ok;

  if (request_.method() != http::verb::get || request_.target() != "/healthz") {
    status = http::status::bad_request;
  } else {
    for (auto&& chain : chains_) {
      if (!chain->jwksActive()) {
        spdlog::warn("{}: chain:{} JWKS is not ready", __func__, chain->Name());
        status = http::status::not_found;
        break;
      }
    }
  }

  response_.result(status);
  startWrite();
}

void HealthcheckHttpConnection::onWriteDone() {
  sock_.close();
  parent_.removeConnection(this);
}

HealthcheckAsyncServer::HealthcheckAsyncServer(
    boost::asio::io_context& ioc,
    const std::vector<std::unique_ptr<filters::FilterChain>>& chains,
    std::string address, uint16_t port)
    : chains_(chains),
      acceptor_(ioc, {beast::net::ip::make_address(address), port}),
      sock_(ioc) {}

HealthcheckAsyncServer::~HealthcheckAsyncServer() {
  for (auto&& conn : active_connections_) {
    delete conn;
  }
  active_connections_.clear();
  acceptor_.close();
}

void HealthcheckAsyncServer::removeConnection(HealthcheckHttpConnection* conn) {
  delete conn;
  active_connections_.remove(conn);
}

void HealthcheckAsyncServer::startAccept() {
  acceptor_.async_accept(sock_, [this](auto ec) {
    if (!ec) {
      active_connections_.emplace_back(
          new HealthcheckHttpConnection(*this, chains_, std::move(sock_)));
    }
    startAccept();
  });
}

}  // namespace service
}  // namespace authservice
