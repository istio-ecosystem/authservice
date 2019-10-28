#include "filter.h"
#include <boost/asio.hpp>

namespace authservice {
namespace filters {

google::rpc::Code Filter::Process(
        const ::envoy::service::auth::v2::CheckRequest* request,
        ::envoy::service::auth::v2::CheckResponse* response) {
  boost::asio::io_context ioc;
  google::rpc::Code code;

  // Spawn a co-routine to run the filter.
  boost::asio::spawn(ioc, [&](boost::asio::yield_context yield){
    code = this->Process(request, response, ioc, yield);
  });

  // Run the I/O context to completion.
  ioc.run();

  return code;
}

}
}