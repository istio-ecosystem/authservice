#include "filter.h"
#include <boost/asio.hpp>

namespace authservice {
namespace filters {

google::rpc::Code Filter::Process(
        const ::envoy::service::auth::v2::CheckRequest* request,
        ::envoy::service::auth::v2::CheckResponse* response) {

  // Create a new io_context. All of the async IO handled inside the
  // spawn below will be handled by this new io_context.
  boost::asio::io_context ioc;
  google::rpc::Code code;

  // Spawn a co-routine to run the filter.
  boost::asio::spawn(ioc, [&](boost::asio::yield_context yield) {
    code = this->Process(request, response, ioc, yield);
  });

  // Run the I/O context to completion, on the current thread.
  // This consumes the current thread until all of the async
  // I/O from the above spawn is finished.
  ioc.run();

  return code;
}

}
}
