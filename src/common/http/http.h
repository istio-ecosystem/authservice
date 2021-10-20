#ifndef AUTHSERVICE_SRC_COMMON_HTTP_HTTP_H_
#define AUTHSERVICE_SRC_COMMON_HTTP_HTTP_H_

#include <array>
#include <boost/asio/spawn.hpp>
#include <boost/beast.hpp>
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

class PathQueryFragment {
 private:
  std::string path_;
  std::string query_;
  std::string fragment_;

 public:
  explicit PathQueryFragment(absl::string_view path_query_fragment);

  inline const std::string &Path() const { return path_; }

  inline const std::string &Query() const { return query_; }

  inline bool HasQuery() const { return !query_.empty(); }

  inline const std::string &Fragment() const { return fragment_; }

  inline bool HasFragment() const { return !fragment_.empty(); }
};

class Uri {
 private:
  static const std::string https_prefix_;
  static const std::string http_prefix_;
  std::string host_;
  std::string scheme_;
  int32_t port_;
  std::string pathQueryFragmentString_;  // includes the path, query, and
                                         // fragment (if any)
  PathQueryFragment pathQueryFragment_;

 public:
  explicit Uri(absl::string_view uri);

  Uri(const Uri &uri);

  Uri &operator=(Uri &&uri) noexcept;

  inline std::string GetScheme() { return scheme_; }

  inline std::string GetHost() { return host_; }

  inline int32_t GetPort() { return port_; }

  inline std::string GetPathQueryFragment() { return pathQueryFragmentString_; }

  std::string GetPath();

  std::string GetQuery();

  inline bool HasQuery() const { return pathQueryFragment_.HasQuery(); };

  std::string GetFragment();

  inline bool HasFragment() const { return pathQueryFragment_.HasFragment(); };
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
   * Virtual destructor
   */
  virtual ~Http() = default;

  // TODO(shikugawa): add transport socket abstraction to enable raw or tls
  // socket switching easiliy.
  /** @brief Asynchronously send a Post http message with a certificate
   * authority. To be used inside a Boost co-routine.
   * @param endpoint the endpoint to call
   * @param headers the http headers
   * @param body the http request body
   * @param ca_cert the ca cert to be trusted in the http call
   * @return http response.
   */
  virtual response_t Post(
      absl::string_view uri,
      const std::map<absl::string_view, absl::string_view> &headers,
      absl::string_view body, absl::string_view ca_cert,
      absl::string_view proxy_uri, boost::asio::io_context &ioc,
      boost::asio::yield_context yield) const = 0;

  /** @brief Asynchronously send a Get http message with a certificate
   * authority. To be used inside a Boost co-routine.
   * @param endpoint the endpoint to call
   * @param headers the http headers
   * @param body the http request body
   * @param ca_cert the ca cert to be trusted in the http call
   * @return http response.
   */
  virtual response_t Get(
      absl::string_view uri,
      const std::map<absl::string_view, absl::string_view> &headers,
      absl::string_view body, absl::string_view ca_cert,
      absl::string_view proxy_uri, boost::asio::io_context &ioc,
      boost::asio::yield_context yield) const = 0;

  /** @brief Asynchronously send a non-SSL Get http message with a certificate
   * authority. To be used inside a Boost co-routine.
   * @param endpoint the endpoint to call
   * @param headers the http headers
   * @param body the http request body
   * @return http response.
   */
  virtual response_t SimpleGet(
      absl::string_view uri,
      const std::map<absl::string_view, absl::string_view> &headers,
      absl::string_view body, boost::asio::io_context &ioc,
      boost::asio::yield_context yield) const = 0;
};

/**
 * HTTP request implementation
 */
class HttpImpl : public Http {
 public:
  response_t Post(absl::string_view uri,
                  const std::map<absl::string_view, absl::string_view> &headers,
                  absl::string_view body, absl::string_view ca_cert,
                  absl::string_view proxy_uri, boost::asio::io_context &ioc,
                  boost::asio::yield_context yield) const override;

  response_t Get(absl::string_view uri,
                 const std::map<absl::string_view, absl::string_view> &headers,
                 absl::string_view body, absl::string_view ca_cert,
                 absl::string_view proxy_uri, boost::asio::io_context &ioc,
                 boost::asio::yield_context yield) const override;

  response_t SimpleGet(
      absl::string_view uri,
      const std::map<absl::string_view, absl::string_view> &headers,
      absl::string_view body, boost::asio::io_context &ioc,
      boost::asio::yield_context yield) const override;
};

}  // namespace http
}  // namespace common
}  // namespace authservice

#endif  // AUTHSERVICE_SRC_COMMON_HTTP_HTTP_H_
