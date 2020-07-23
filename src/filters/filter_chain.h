#ifndef AUTHSERVICE_FILTER_CHAIN_H
#define AUTHSERVICE_FILTER_CHAIN_H

#include "envoy/service/auth/v2/external_auth.grpc.pb.h"
#include "src/filters/filter.h"
#include "config/config.pb.h"
#include "src/filters/oidc/session_store.h"
#include <memory>

namespace authservice {
namespace filters {
/**
 * FilterChain is an object that wraps a Pipe and the criteria for asserting whether a Pipe should process a request.
 */
class FilterChain {
public:
  virtual ~FilterChain() = default;

  /**
   * Name returns a name given to the filter chain for use in debugging and logging.
   * @return the name of the filter chain.
   */
  virtual const std::string &Name() const = 0;

  /**
   * Matches can be used to identify whether a chain should be used to process a request.
   * @param request the request to match against.
   * @return true if that chain should process a request else false.
   */
  virtual bool Matches(const ::envoy::service::auth::v2::CheckRequest *request) const = 0;

  /**
   * New creates a new filter instance that can be used to process a request.
   * @return a new filter instance.
   */
  virtual std::unique_ptr<Filter> New() = 0;

  /**
   * Invoked periodically to give the filter chain a chance to clean up expired sessions and any other resources.
   */
  virtual void DoPeriodicCleanup() = 0;
};

class FilterChainImpl : public FilterChain {
private:
  unsigned int threads_;
  config::FilterChain config_;
  std::shared_ptr<oidc::SessionStore> oidc_session_store_;

public:
  explicit FilterChainImpl(config::FilterChain config, unsigned int threads);

  const std::string &Name() const override;

  bool Matches(const ::envoy::service::auth::v2::CheckRequest *request) const override;

  std::unique_ptr<Filter> New() override;

  virtual void DoPeriodicCleanup() override;
};

}  // namespace filters
}  // namespace authservice
#endif //AUTHSERVICE_FILTER_CHAIN_H
