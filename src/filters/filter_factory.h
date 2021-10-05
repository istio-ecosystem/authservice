#ifndef AUTHSERVICE_FILTER_FACTORY_H
#define AUTHSERVICE_FILTER_FACTORY_H

#include <memory>

#include "src/filters/pipe.h"

namespace authservice {
namespace filters {

class FilterFactory {
 public:
  virtual ~FilterFactory() = default;

  /**
   * Create auth filter in filter chain.
   */
  virtual FilterPtr create() = 0;
};

using FilterFactoryPtr = std::unique_ptr<FilterFactory>;

}  // namespace filters
}  // namespace authservice

#endif
