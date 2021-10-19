#pragma once

#include <boost/asio.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/core/flat_buffer.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/http/read.hpp>
#include <boost/beast/version.hpp>

#include "boost/asio/io_context.hpp"
#include "boost/asio/ip/address.hpp"
#include "boost/beast/core/error.hpp"
#include "boost/beast/http/status.hpp"
#include "boost/beast/http/verb.hpp"
#include "boost/beast/http/write.hpp"
#include "boost/thread.hpp"
#include "src/filters/filter_chain.h"

namespace authservice {
namespace service {

namespace beast = boost::beast;    // from <boost/beast.hpp>
namespace http = beast::http;      // from <boost/beast/http.hpp>
using tcp = boost::asio::ip::tcp;  // from <boost/asio/ip/tcp.hpp>

class HealthcheckHttpConnection {
 public:
  HealthcheckHttpConnection(
      const std::vector<std::unique_ptr<filters::FilterChain>> &chains,
      tcp::socket sock)
      : sock_(std::move(sock)), chains_(chains) {
    startRead();
  }

 private:
  void startRead() {
    http::async_read(sock_, read_buffer_, request_,
                     [this](auto, auto) { onReadDone(); });
  }

  void onReadDone() {
    response_.version(request_.version());

    if (request_.method() != http::verb::get) {
      startWrite();
      return;
    }

    http::status status = http::status::ok;

    for (auto &&chain : chains_) {
      if (!chain->jwksActive()) {
        status = http::status::not_found;
        break;
      }
    }

    response_.result(status);
    startWrite();
  }

  void startWrite() {
    http::async_write(sock_, response_,
                      [this](auto ec, auto t) { onWriteDone(ec, t); });
  }

  void onWriteDone(beast::error_code ec, size_t) {
    sock_.shutdown(tcp::socket::shutdown_send, ec);
    delete this;
  }

  tcp::socket sock_;
  const std::vector<std::unique_ptr<filters::FilterChain>> &chains_;
  beast::flat_buffer read_buffer_{256};
  http::request<http::dynamic_body> request_;
  http::response<http::dynamic_body> response_;
};

class HealthcheckAsyncServer {
 public:
  HealthcheckAsyncServer(
      const std::vector<std::unique_ptr<filters::FilterChain>> &chains,
      std::string address, uint16_t port)
      : chains_(chains),
        acceptor_(ioc_, {beast::net::ip::make_address(address), port}),
        sock_(ioc_),
        th_([this] {
          startAccept();
          ioc_.run();
        }) {}

  ~HealthcheckAsyncServer() { ioc_.stop(); }

 private:
  void startAccept() {
    acceptor_.async_accept(sock_, [this](auto ec) {
      if (!ec) {
        new HealthcheckHttpConnection(chains_, std::move(sock_));
      }
      startAccept();
    });
  }

  const std::vector<std::unique_ptr<filters::FilterChain>> &chains_;
  boost::asio::io_context ioc_;
  tcp::acceptor acceptor_;
  tcp::socket sock_;
  boost::thread th_;
};

}  // namespace service
}  // namespace authservice
