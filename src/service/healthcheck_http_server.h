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
#include "boost/system/error_code.hpp"
#include "boost/thread.hpp"
#include "src/filters/filter_chain.h"

namespace authservice {
namespace service {

namespace beast = boost::beast;    // from <boost/beast.hpp>
namespace http = beast::http;      // from <boost/beast/http.hpp>
using tcp = boost::asio::ip::tcp;  // from <boost/asio/ip/tcp.hpp>

class HealthcheckAsyncServer;

/**
 * Abstracted HTTP connection for handling request for healthcheck.
 */
class HealthcheckHttpConnection {
 public:
  HealthcheckHttpConnection(
      HealthcheckAsyncServer& parent,
      const std::vector<std::unique_ptr<filters::FilterChain>>& chains,
      tcp::socket sock);

 private:
  void startRead();
  void onReadDone();
  void startWrite();
  void onWriteDone();

  tcp::socket sock_;
  const std::vector<std::unique_ptr<filters::FilterChain>>& chains_;
  http::request<http::dynamic_body> request_;
  http::response<http::dynamic_body> response_;
  beast::flat_buffer read_buffer_{256};
  boost::system::error_code ec_;
  HealthcheckAsyncServer& parent_;
};

class HealthcheckAsyncServer {
 public:
  HealthcheckAsyncServer(
      const std::vector<std::unique_ptr<filters::FilterChain>>& chains,
      std::string address, uint16_t port);

  ~HealthcheckAsyncServer();
  int getPort() const { return acceptor_.local_endpoint().port(); }
  void removeConnection(HealthcheckHttpConnection* conn);

 private:
  void startAccept();

  std::list<HealthcheckHttpConnection*> active_connections_;
  const std::vector<std::unique_ptr<filters::FilterChain>>& chains_;
  boost::asio::io_context ioc_;
  tcp::acceptor acceptor_;
  tcp::socket sock_;
  boost::thread th_;
};

}  // namespace service
}  // namespace authservice
