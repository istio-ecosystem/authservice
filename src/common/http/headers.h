#ifndef AUTHSERVICE_HEADERS_H
#define AUTHSERVICE_HEADERS_H
#include <string>

namespace authservice {
namespace common {
namespace http {
// Standard HTTP headers
namespace headers {
static const char *Authorization = "authorization";
static const char *Cookie = "cookie";
static const char *CacheControl = "cache-control";
static const char *ContentType = "content-type";
static const char *Location = "location";
static const char *Pragma = "pragma";
static const char *SetCookie = "set-cookie";

// Cache control directives
namespace CacheControlDirectives {
static const char *NoCache = "no-cache";
}  // namespace CacheControlDirectives

namespace ContentTypeDirectives {
static const char *FormUrlEncoded = "application/x-www-form-urlencoded";
}

namespace PragmaDirectives {
static const char *NoCache = "no-cache";
}  // namespace PragmaDirectives

namespace SetCookieDirectives {
static const char *Secure = "Secure";
static const char *HttpOnly = "HttpOnly";
static const char *SameSiteStrict = "SameSite=Strict";
static const char *SameSiteLax = "SameSite=Lax";
static const char *MaxAge = "Max-Age";
}  // namespace SetCookieDirectives

}  // namespace headers
}  // namespace http
}  // namespace common
}  // namespace authservice

#endif  // AUTHSERVICE_HEADERS_H
