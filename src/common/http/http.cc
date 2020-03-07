#include "http.h"
#include <boost/algorithm/string.hpp>
#include <boost/asio/ssl/error.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/asio/spawn.hpp>
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>
#include <sstream>
#include "absl/strings/match.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_join.h"
#include "absl/strings/str_split.h"
#include "spdlog/spdlog.h"

namespace beast = boost::beast;    // from <boost/beast.hpp>
namespace net = boost::asio;       // from <boost/asio.hpp>
namespace ssl = boost::asio::ssl;  // from <boost/asio/ssl.hpp>
using tcp = boost::asio::ip::tcp;  // from <boost/asio/ip/tcp.hpp>

namespace authservice {
namespace common {
namespace http {
namespace {
const char forward_alphabet[] = {
    '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', 'A', 'B', 'C', 'D', 'E', 'F',
};
const uint8_t reverse_alphabet[] = {
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 0,   1,   2,   3,   4,   5,   6,   7,   8,   9,   255, 255,
    255, 255, 255, 255, 255, 10,  11,  12,  13,  14,  15,  255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255,
};

typedef bool (*SafeCharacterFunc)(const char);

bool IsUrlSafeCharacter(const char character) {
  return ((character >= 'A' && character <= 'Z') ||
          (character >= 'a' && character <= 'z') ||
          (character >= '0' && character <= '9') || (character == '-') ||
          (character == '_') || (character == '.') || (character == '~'));
}

bool IsFormDataSafeCharacter(const char character) {
  return IsUrlSafeCharacter(character) || (character == '+');
}

std::string SafeEncode(absl::string_view in, SafeCharacterFunc IsSafe) {
  std::stringstream builder;
  for (auto character : in) {
    // unreserved characters: see https://www.ietf.org/rfc/rfc3986.txt
    if (IsSafe(character)) {
      builder << character;
    } else {
      // percent encode
      builder << '%' << forward_alphabet[(character & 0xf0u) >> 4u]
              << forward_alphabet[character & 0x0fu];
    }
  }
  return builder.str();
}

absl::optional<std::string> SafeDecode(absl::string_view in,
                                       SafeCharacterFunc IsSafe) {
  std::stringstream builder;
  auto iter = in.cbegin();
  while (iter != in.cend()) {
    // unreserved characters: see https://www.ietf.org/rfc/rfc3986.txt
    char character = *iter;
    if (IsSafe(character)) {
      builder << character;
    } else {
      // Must be percent encoding.
      if (character != '%') {
        return absl::optional<std::string>();
      }
      auto first = ++iter;
      // Fail if either there's no more data or the value is out of range
      // (non-ascii).
      if (first == in.cend() || (*first & 0x80)) {
        return absl::nullopt;
      }
      auto second = ++iter;
      // Fail if either there's no more data or the value is out of range
      // (non-ascii).
      if (second == in.cend() || (*second & 0x80)) {
        return absl::optional<std::string>();
      }
      auto top_nibble = reverse_alphabet[uint8_t(*first) & 0x7fu];
      auto bottom_nibble = reverse_alphabet[uint8_t(*second) & 0x7fu];
      // The character is invalid if it is set to the value 255 in the reverse
      // alphabet.
      if ((top_nibble == 255) || (bottom_nibble == 255)) {
        return absl::nullopt;
      }
      // percent encode
      builder << char(((top_nibble << 4u) | bottom_nibble));
    }
    iter++;
  }
  return builder.str();
}

}  // namespace

std::string Http::UrlSafeEncode(absl::string_view url) {
  return SafeEncode(url, IsUrlSafeCharacter);
}

absl::optional<std::string> Http::UrlSafeDecode(absl::string_view url) {
  return SafeDecode(url, IsUrlSafeCharacter);
}

std::string Http::EncodeQueryData(
    const std::multimap<absl::string_view, absl::string_view> &data) {
  std::stringstream builder;
  auto pair = data.cbegin();
  while (pair != data.cend()) {
    std::string key(pair->first.data());
    std::replace(key.begin(), key.end(), ' ', '+');
    std::string value(pair->second.data());
    std::replace(value.begin(), value.end(), ' ', '+');
    builder << SafeEncode(pair->first.data(), IsUrlSafeCharacter) << '='
            << SafeEncode(pair->second.data(), IsUrlSafeCharacter);
    if (++pair != data.cend()) {
      builder << "&";
    }
  }
  return builder.str();
}

absl::optional<std::multimap<std::string, std::string>> Http::DecodeQueryData(
    absl::string_view query) {
  std::multimap<std::string, std::string> result;
  std::vector<std::string> parts;
  boost::split(parts, query, boost::is_any_of("&"));
  for (auto part : parts) {
    std::vector<std::string> pair;
    boost::split(pair, part, boost::is_any_of("="));
    if (pair.size() != 2) {
      return absl::nullopt;
    }
    auto escaped_key = SafeDecode(pair[0], IsUrlSafeCharacter);
    if (!escaped_key.has_value()) {
      return absl::nullopt;
    }
    auto escaped_value = SafeDecode(pair[1], IsUrlSafeCharacter);
    if (!escaped_value.has_value()) {
      return absl::nullopt;
    }
    result.insert(std::make_pair(*escaped_key, *escaped_value));
  }
  return result;
}

std::string Http::EncodeFormData(
    const std::multimap<absl::string_view, absl::string_view> &data) {
  std::stringstream builder;
  auto pair = data.cbegin();
  while (pair != data.cend()) {
    std::string key(pair->first.data());
    std::replace(key.begin(), key.end(), ' ', '+');
    std::string value(pair->second.data());
    std::replace(value.begin(), value.end(), ' ', '+');
    builder << SafeEncode(key, IsFormDataSafeCharacter) << '='
            << SafeEncode(value, IsFormDataSafeCharacter);
    if (++pair != data.end()) {
      builder << "&";
    }
  }
  return builder.str();
}

absl::optional<std::multimap<std::string, std::string>> Http::DecodeFormData(
    absl::string_view form) {
  std::multimap<std::string, std::string> result;
  std::vector<std::string> parts;
  boost::split(parts, form, boost::is_any_of("&"));
  for (auto part : parts) {
    std::vector<std::string> pair;
    boost::split(pair, part, boost::is_any_of("="));
    if (pair.size() != 2) {
      return absl::nullopt;
    }
    auto escaped_key = SafeDecode(pair[0], IsFormDataSafeCharacter);
    if (!escaped_key.has_value()) {
      return absl::nullopt;
    }
    std::replace(escaped_key->begin(), escaped_key->end(), '+', ' ');
    auto escaped_value = SafeDecode(pair[1], IsFormDataSafeCharacter);
    if (!escaped_value.has_value()) {
      return absl::nullopt;
    }
    std::replace(escaped_value->begin(), escaped_value->end(), '+', ' ');
    result.insert(std::make_pair(*escaped_key, *escaped_value));
  }
  return result;
}

std::string Http::EncodeBasicAuth(absl::string_view username,
                                  absl::string_view password) {
  return absl::StrCat(
      "Basic", " ", absl::Base64Escape(absl::StrCat(username, ":", password)));
}

std::string Http::EncodeSetCookie(
    absl::string_view name, absl::string_view value,
    const std::set<absl::string_view> &directives) {
  std::stringstream builder;
  builder << name.data() << '=' << value.data();
  for (auto directive : directives) {
    builder << "; " << directive.data();
  }
  return builder.str();
}

absl::optional<std::map<std::string, std::string>> Http::DecodeCookies(
    absl::string_view cookies) {
  // https://tools.ietf.org/html/rfc6265#section-5.4
  std::map<std::string, std::string> result;
  std::vector<absl::string_view> cookie_list = absl::StrSplit(cookies, "; ");
  for (auto cookie : cookie_list) {
    std::vector<absl::string_view> cookie_parts = absl::StrSplit(cookie, '=');
    if (cookie_parts.size() != 2) {
      // Invalid cookie encoding. Must Name=Value
      return absl::nullopt;
    }
    result.emplace(std::string(cookie_parts[0].data(), cookie_parts[0].size()),
                   std::string(cookie_parts[1].data(), cookie_parts[1].size()));
  }
  return result;
}

Uri::Uri(absl::string_view uri) : pathQueryFragment_("/") {
  if (uri.find(https_prefix_) != 0) { // must start with https://
    throw std::runtime_error(absl::StrCat("uri must be https scheme: ", uri));
  }
  if (uri.length() == https_prefix_.length()) {
    throw std::runtime_error(absl::StrCat("no host in uri: ", uri));
  }
  auto uri_without_scheme = uri.substr(https_prefix_.length());

  std::string host_and_port;
  auto positions = {uri_without_scheme.find('/'), uri_without_scheme.find('?'), uri_without_scheme.find('#')};
  absl::string_view::size_type end_of_host_and_port_index = uri_without_scheme.length();
  for (auto ptr = positions.begin(); ptr < positions.end(); ptr++) {
    if (*ptr == absl::string_view::npos) {
      continue;
    }
    end_of_host_and_port_index = std::min(end_of_host_and_port_index, *ptr);
  }
  host_and_port = std::string(uri_without_scheme.substr(0, end_of_host_and_port_index).data(),
                              end_of_host_and_port_index);
  pathQueryFragmentString_ = std::string(uri_without_scheme.substr(end_of_host_and_port_index).data());
  if (!absl::StartsWith(pathQueryFragmentString_, "/")) {
    pathQueryFragmentString_ = "/" + pathQueryFragmentString_;
  }

  pathQueryFragment_ = http::PathQueryFragment(pathQueryFragmentString_);

  auto colon_position = host_and_port.find(':');
  if (colon_position == 0) {
    throw std::runtime_error(absl::StrCat("no host in uri: ", uri));
  }
  if (colon_position != absl::string_view::npos) {
    auto port = host_and_port.substr(colon_position + 1);
    try {
      port_ = std::stoi(port);
    } catch (const std::exception &e) {
      throw std::runtime_error(absl::StrCat("port not valid in uri: ", uri));
    }
    if (port_ > 65535 || port_ < 0) {
      throw std::runtime_error(absl::StrCat("port value must be between 0 and 65535: ", uri));
    }
    host_ = std::string(host_and_port.substr(0, colon_position).data(), colon_position);
  } else {
    host_ = host_and_port;
  }
}

const std::string Uri::https_prefix_ = "https://";

Uri &Uri::operator=(Uri &&uri) noexcept {
  host_ = uri.host_;
  port_ = uri.port_;
  pathQueryFragmentString_ = uri.pathQueryFragmentString_;
  pathQueryFragment_ = uri.pathQueryFragment_;
  return *this;
}

Uri::Uri(const Uri &uri)
    : host_(uri.host_),
      port_(uri.port_),
      pathQueryFragmentString_(uri.pathQueryFragmentString_),
      pathQueryFragment_(uri.pathQueryFragment_) {
}

std::string Uri::Path() {
  return pathQueryFragment_.Path();
}

std::string Uri::Fragment() {
  return pathQueryFragment_.Fragment();
}

std::string Uri::Query() {
  return pathQueryFragment_.Query();
}

PathQueryFragment::PathQueryFragment(absl::string_view path_query_fragment) {
  // See https://tools.ietf.org/html/rfc3986#section-3.4 and https://tools.ietf.org/html/rfc3986#section-3.5
  auto question_mark_position = path_query_fragment.find('?');
  auto hashtag_position = path_query_fragment.find("#");
  if (question_mark_position == absl::string_view::npos && hashtag_position == absl::string_view::npos) {
    path_ = std::string(path_query_fragment.data());
  } else if (question_mark_position == absl::string_view::npos) {
    path_ = std::string(path_query_fragment.substr(0, hashtag_position).data(), hashtag_position);
    fragment_ = std::string(path_query_fragment.substr(hashtag_position + 1).data());
  } else if (hashtag_position == absl::string_view::npos) {
    path_ = std::string(path_query_fragment.substr(0, question_mark_position).data(), question_mark_position);
    query_ = std::string(path_query_fragment.substr(question_mark_position + 1).data());
  } else {
    if (question_mark_position < hashtag_position) {
      auto query_length = hashtag_position - question_mark_position - 1;
      path_ = std::string(path_query_fragment.substr(0, question_mark_position).data(), question_mark_position);
      query_ = std::string(path_query_fragment.substr(question_mark_position + 1, query_length).data(), query_length);
      fragment_ = std::string(path_query_fragment.substr(hashtag_position + 1).data());
    } else {
      path_ = std::string(path_query_fragment.substr(0, hashtag_position).data(), hashtag_position);
      fragment_ = std::string(path_query_fragment.substr(hashtag_position + 1).data());
    }
  }
}

response_t HttpImpl::Post(absl::string_view uri,
                          const std::map<absl::string_view, absl::string_view> &headers, absl::string_view body,
                          absl::string_view ca_cert, boost::asio::io_context &ioc,
                          boost::asio::yield_context yield) const {
  spdlog::trace("{}", __func__);
  try {
    int version = 11;

    ssl::context ctx(ssl::context::tlsv12_client);
    ctx.set_verify_mode(ssl::verify_peer);
    ctx.set_default_verify_paths();

    if (!ca_cert.empty()) {
      spdlog::info("{}: Trusting the provided certificate authority", __func__);
      beast::error_code ca_ec;
      ctx.add_certificate_authority(
          boost::asio::buffer(ca_cert.data(), ca_cert.size()), ca_ec);
      if (ca_ec) {
        throw boost::system::system_error{ca_ec};
      }
    }

    auto parsed_uri = http::Uri(uri);

    tcp::resolver resolver(ioc);
    beast::ssl_stream<beast::tcp_stream> stream(ioc, ctx);
    if (!SSL_set_tlsext_host_name(stream.native_handle(),
                                  parsed_uri.Host().c_str())) {
      throw boost::system::error_code{static_cast<int>(::ERR_get_error()),
                                      boost::asio::error::get_ssl_category()};
    }
    const auto results =
        resolver.async_resolve(parsed_uri.Host(), std::to_string(parsed_uri.Port()), yield);
    beast::get_lowest_layer(stream).async_connect(results, yield);
    stream.async_handshake(ssl::stream_base::client, yield);
    // Set up an HTTP POST request message
    beast::http::request<beast::http::string_body> req{
        beast::http::verb::post, parsed_uri.PathQueryFragment(), version};
    req.set(beast::http::field::host, parsed_uri.Host());
    for (auto header : headers) {
      req.set(boost::beast::string_view(header.first.data()),
              boost::beast::string_view(header.second.data()));
    }
    auto &req_body = req.body();
    req_body.reserve(body.size());
    req_body.append(body.begin(), body.end());
    req.prepare_payload();
    // Send the HTTP request to the remote host
    beast::http::async_write(stream, req, yield);

    // Read response
    beast::flat_buffer buffer;
    response_t res(new beast::http::response<beast::http::string_body>);
    beast::http::async_read(stream, buffer, *res, yield);

    // Gracefully close the socket.
    // Receive an error code instead of throwing an exception if this fails, so we can ignore some
    // expected not_connected errors.
    boost::system::error_code ec;
    stream.async_shutdown(yield[ec]);

    if (ec) {
      // when trusted CA is not configured
      // not_connected happens sometimes so don't bother reporting it.
      if (ec != beast::errc::not_connected) {
        if (ca_cert.empty()) {
          spdlog::info("{}: HTTP error encountered: {}", __func__, ec.message());
          return response_t();
        }

          // when trusted CA is configured
          // stream_truncated also happen sometime and we choose to ignore the stream_truncated error,
          // as recommended by the github thread: https://github.com/boostorg/beast/issues/824
        else if (ec != boost::asio::ssl::error::stream_truncated) {
          spdlog::info("{}: HTTP error encountered: {}", __func__, ec.message());
          return response_t();
        }
      }
    }

    return res;
    // If we get here then the connection is closed gracefully
  } catch (std::exception const &e) {
    spdlog::info("{}: unexpected exception: {}", __func__, e.what());
    return response_t();
  }
}

}  // namespace http
}  // namespace common
}  // namespace authservice
