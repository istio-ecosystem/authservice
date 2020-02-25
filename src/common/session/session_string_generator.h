#ifndef AUTHSERVICE_SESSION_STRING_GENERATOR_H
#define AUTHSERVICE_SESSION_STRING_GENERATOR_H

#include <memory>
#include <string>

namespace authservice {
namespace common {
namespace session {

class SessionStringGenerator;

typedef std::shared_ptr<SessionStringGenerator> SessionStringGeneratorPtr;

class SessionStringGenerator {
public:
  virtual std::string GenerateSessionId();

  virtual std::string GenerateNonce();

  virtual std::string GenerateState();

private:
  virtual std::string GenerateRandomString(int size);
};

} // namespace session
} // namespace common
} // namespace authservice

#endif //AUTHSERVICE_SESSION_STRING_GENERATOR_H
