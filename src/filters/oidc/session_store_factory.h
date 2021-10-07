#ifndef AUTHSERVICE_SESSION_STORE_FACTORY_H
#define AUTHSERVICE_SESSION_STORE_FACTORY_H

namespace authservice {
namespace filters {
namespace oidc {

class SessionStoreFactory {
 public:
  virtual ~SessionStoreFactory() = default;

  virtual SessionStorePtr create() = 0;
};

}  // namespace oidc
}  // namespace filters
}  // namespace authservice

#endif
