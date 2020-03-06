#ifndef AUTHSERVICE_SRC_COMMON_HTTP_HTTP_H_
#define AUTHSERVICE_SRC_COMMON_HTTP_HTTP_H_

#include <array>
#include <boost/beast.hpp>
#include <boost/asio/spawn.hpp>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"

namespace beast = boost::beast;  // from <boost/beast.hpp>

namespace authservice {
namespace common {
namespace http {

class Http;

typedef std::shared_ptr<Http> ptr_t;
typedef std::unique_ptr<beast::http::response<beast::http::string_body>>
    response_t;

class Uri {
private:
  const std::string https_prefix_ = "https://";
  std::string host_;
  int32_t port_ = 443;
  std::string pathQueryFragment_; // includes the path, query, and fragment (if any)

public:
  explicit Uri(absl::string_view uri);

  Uri(const Uri &uri);

  void operator=(Uri &&uri);

  std::string Scheme() { return "https"; }

  std::string Host() { return host_; }

  int32_t Port() { return port_; }

  std::string PathQueryFragment() { return pathQueryFragment_; }
};

class Http {
public:
  /**
   *
   * encode the given url for use e.g. in an http query field.
   *
   * @param url the url to encode.
   * @return the encoded url.
   */
  static std::string UrlSafeEncode(absl::string_view url);

  /**
   *
   * decode the given url
   *
   * @param url the url to decode.
   * @return the decoded url.
   */
  static absl::optional<std::string> UrlSafeDecode(absl::string_view url);

  /** @brief encode query data.
   *
   * @param data the data to encode.
   * @return the encoded data.
   */
  static std::string EncodeQueryData(
      const std::multimap<absl::string_view, absl::string_view> &data);

  /**
   * @brief decode query data.
   *
   * @param query the query to be decoded
   * @return the decoded query
   */
  static absl::optional<std::multimap<std::string, std::string>>
  DecodeQueryData(absl::string_view query);

  /** @brief encode form data.
   *
   * @param data the data to encode.
   * @return the encoded data.
   */
  static std::string EncodeFormData(
      const std::multimap<absl::string_view, absl::string_view> &data);

  /** @brief Parse form-encoded data.
   *
   * @param form the form-encoded data to parse.
   * @return a map of form-encoded values.
   */
  static absl::optional<std::multimap<std::string, std::string>> DecodeFormData(
      absl::string_view form);

  /** @brief Encode basic auth parameters for use in an authorization header.
   *
   * Encode basic auth parameters for use in an authorization header as defined
   * in https://tools.ietf.org/html/rfc7617.
   *
   * @param username the username to encode
   * @param password the password to encode
   * @return the encoded username and password
   */
  static std::string EncodeBasicAuth(absl::string_view username,
                                     absl::string_view password);

  /**
   * Encode Set-Coookie string using the given parameters.
   * @param name the cookie's name
   * @param value the cookie's value
   * @param directives the cookie directives.
   * @return the encoded Set-Cookie value.
   */
  static std::string EncodeSetCookie(
      absl::string_view name, absl::string_view value,
      const std::set<absl::string_view> &directives);

  /**
   * Decode a Cookie header value into cookies.
   * @param cookies The Cookie header value.
   * @return A map of Cookies or a nullopt.
   */
  static absl::optional<std::map<std::string, std::string>> DecodeCookies(
      absl::string_view cookies);

  /**
 * Decode a uri into a scheme, host, port, and path.
 * @param uri string
 * @return the decoded Uri
 */
  static Uri ParseUri(absl::string_view uri);

  /**
   * Decode a path into a path, query and fragment triple.
   * @param path the path to decode
   * @return the decoded triple
   */
  static std::array<std::string, 3> DecodePath(absl::string_view path);

  /**
   * Virtual destructor
   */
  virtual ~Http() = default;

  /** @brief Asynchronously send a Post http message with a certificate authority.
   * To be used inside a Boost co-routine.
   * @param endpoint the endpoint to call
   * @param headers the http headers
   * @param body the http request body
   * @param ca_cert the ca cert to be trusted in the http call
   * @return http response.
   */
  virtual response_t Post(
      absl::string_view uri,
      const std::map<absl::string_view, absl::string_view> &headers,
      absl::string_view body,
      absl::string_view ca_cert,
      boost::asio::io_context &ioc,
      boost::asio::yield_context yield) const = 0;
};

/**
 * HTTP request implementation
 */
class HttpImpl : public Http {
public:
  response_t Post(
      absl::string_view uri,
      const std::map<absl::string_view, absl::string_view> &headers,
      absl::string_view body,
      absl::string_view ca_cert,
      boost::asio::io_context &ioc,
      boost::asio::yield_context yield) const override;
};

}  // namespace http
}  // namespace common
}  // namespace authservice

#endif  // AUTHSERVICE_SRC_COMMON_HTTP_HTTP_H_
