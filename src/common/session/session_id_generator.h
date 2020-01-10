#ifndef AUTHSERVICE_SESSION_ID_GENERATOR_H
#define AUTHSERVICE_SESSION_ID_GENERATOR_H

#include <string>

namespace authservice {
namespace common {
namespace session {

class SessionIdGenerator;

typedef std::shared_ptr<SessionIdGenerator> SessionIdGeneratorPtr;

class SessionIdGenerator {
  public:
    /**
     * Generate a session ID
     * @return The session ID as a string
     */
    virtual std::string Generate();
};

} // namespace session
} // namespace common
} // namespace authservice

#endif //AUTHSERVICE_SESSION_ID_GENERATOR_H
