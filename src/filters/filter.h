#ifndef AUTHSERVICE_SRC_FILTERS_FILTER_H_
#define AUTHSERVICE_SRC_FILTERS_FILTER_H_

#include <boost/asio.hpp>
#include <boost/asio/spawn.hpp>

#include "absl/strings/string_view.h"
#include "envoy/service/auth/v3/external_auth.grpc.pb.h"
#include "google/rpc/code.pb.h"

namespace authservice {
namespace filters {
/**
 * @brief Filter defines an abstract class for processing requests.
 *
 * Filter defines an abstract class for processing requests. Filters are
 * composed into pipelines and processing passes
 * from one filter to the next.
 */

class Filter {
 public:
  virtual ~Filter() = default;
  /**
   * @brief Process a request mutating the response.
   *
   * Process the given request mutating the response to include new and amended
   * fields. Filters should return one of OK, UNAUTHENTICATED, or
   * PERMISSION_DENIED to indicate a request was handled.
   * OK indicates the request should continue to be processed whilst
   * UNAUTHENTICATED or PERMISSION_DENIED indicates the
   * response should be returned to the caller immediately. INVALID_ARGUMENT can
   * be used to indicate the request from the
   * caller is not well formed. Any other status codes are treated as internal
   * processing errors causing an immediate halt
   * to processing which is in turn relayed to the caller.
   *
   * This must be run inside a Boost co-routine passing in the appropriate
   * yield_context so requests can be processed asynchronously
   *
   * @param request the request process.
   * @param response the response to augment.
   * @param ioc The I/O context on which the filter should be executed.
   * @param yield The yield context used to yield processing to other
   * co-routines.
   * @return the status of the processing. One of [OK, UNAUTHENTICATED,
   * PERMISSION_DENIED] for indicating successful processing.
   */
  virtual google::rpc::Code Process(
      const ::envoy::service::auth::v3::CheckRequest *request,
      ::envoy::service::auth::v3::CheckResponse *response,
      boost::asio::io_context &ioc, boost::asio::yield_context yield) = 0;

  /**
   * @brief Name the well-known name of the filter.
   *
   * Name the well-known name of the filter which can be used for logging
   * purposes.
   * @return the filter name.
   */
  virtual absl::string_view Name() const = 0;
};
}  // namespace filters
}  // namespace authservice

#endif  // AUTHSERVICE_SRC_FILTERS_FILTER_H_
