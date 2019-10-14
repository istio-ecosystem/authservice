#include "http.h"
#include <boost/algorithm/string.hpp>
#include <boost/asio/ssl/error.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>
#include <iomanip>
#include <ios>
#include <iostream>
#include <sstream>
#include "absl/strings/escaping.h"
#include "absl/strings/str_join.h"
#include "absl/strings/str_split.h"
#include "spdlog/spdlog.h"

namespace beast = boost::beast;    // from <boost/beast.hpp>
namespace net = boost::asio;       // from <boost/asio.hpp>
namespace ssl = boost::asio::ssl;  // from <boost/asio/ssl.hpp>
using tcp = boost::asio::ip::tcp;  // from <boost/asio/ip/tcp.hpp>

namespace transparent_auth {
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

std::string http::UrlSafeEncode(absl::string_view url) {
  return SafeEncode(url, IsUrlSafeCharacter);
}

absl::optional<std::string> http::UrlSafeDecode(absl::string_view url) {
  return SafeDecode(url, IsUrlSafeCharacter);
}

std::string http::EncodeQueryData(
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

absl::optional<std::multimap<std::string, std::string>> http::DecodeQueryData(
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

std::string http::EncodeFormData(
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

absl::optional<std::multimap<std::string, std::string>> http::DecodeFormData(
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

std::string http::EncodeBasicAuth(absl::string_view username,
                                  absl::string_view password) {
  return absl::StrCat(
      "Basic", " ", absl::Base64Escape(absl::StrCat(username, ":", password)));
}

std::string http::EncodeSetCookie(
    absl::string_view name, absl::string_view value,
    const std::set<absl::string_view> &directives) {
  std::stringstream builder;
  builder << name.data() << '=' << value.data();
  for (auto directive : directives) {
    builder << "; " << directive.data();
  }
  return builder.str();
}

absl::optional<std::map<std::string, std::string>> http::DecodeCookies(
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

std::array<std::string, 3> http::DecodePath(absl::string_view path) {
  // See https://tools.ietf.org/html/rfc3986#section-3.4 and
  // https://tools.ietf.org/html/rfc3986#section-3.5
  std::array<std::string, 3> result;
  auto tmp = path;
  auto query_position = tmp.find("?");
  if (query_position != absl::string_view::npos) {
    // We have a query.
    tmp = tmp.substr(query_position + 1);
  }
  auto fragment_position = tmp.find("#");
  if (fragment_position != absl::string_view::npos) {
    // we have a frament
    if (query_position != absl::string_view::npos) {
      result[0] =
          std::string(path.substr(0, query_position).data(), query_position);
      result[1] = std::string(tmp.substr(0, fragment_position).data(),
                              fragment_position);
    } else {
      result[0] = std::string(tmp.substr(0, fragment_position).data(),
                              fragment_position);
    }
    if (fragment_position + 1 < path.size()) {
      result[2] = std::string(tmp.substr(fragment_position + 1).data());
    }
  } else {
    if (query_position != absl::string_view::npos) {
      result[0] =
          std::string(path.substr(0, query_position).data(), query_position);
      if (query_position + 1 < path.size()) {
        result[1] = std::string(path.substr(query_position + 1));
      }
    } else {
      result[0] = std::string(path.data());
    }
  }
  return result;
}

std::string http::ToUrl(const authservice::config::common::Endpoint &endpoint) {
  std::stringstream builder;
  builder << endpoint.scheme() << "://" << endpoint.hostname();
  if (endpoint.port() != 80 && endpoint.port() != 443) {
    builder << ":" << std::to_string(endpoint.port());
  }
  builder << endpoint.path();
  return builder.str();
}

response_t http_impl::Post(
    const authservice::config::common::Endpoint &endpoint,
    const std::map<absl::string_view, absl::string_view> &headers,
    absl::string_view body) const {
  spdlog::trace("{}", __func__);
  try {
    int version = 11;
    beast::error_code ec;

    // The io_context is required for all I/O
    net::io_context ioc;
    ssl::context ctx(ssl::context::tlsv12_client);
    // TODO: verify_peer should be used but is not currently working.
    ctx.set_verify_mode(ssl::verify_none);
    ctx.set_default_verify_paths();

    tcp::resolver resolver(ioc);
    beast::ssl_stream<beast::tcp_stream> stream(ioc, ctx);
    if (!SSL_set_tlsext_host_name(stream.native_handle(),
                                  endpoint.hostname().c_str())) {
      boost::system::error_code ec{static_cast<int>(::ERR_get_error()),
                                   boost::asio::error::get_ssl_category()};
      throw boost::system::system_error{ec};
    }
    const auto results =
        resolver.resolve(endpoint.hostname(), std::to_string(endpoint.port()));
    beast::get_lowest_layer(stream).connect(results);
    stream.handshake(ssl::stream_base::client);
    // Set up an HTTP POST request message
    beast::http::request<beast::http::string_body> req{
        beast::http::verb::post, endpoint.path(), version};
    req.set(beast::http::field::host, endpoint.hostname());
    for (auto header : headers) {
      req.set(boost::beast::string_view(header.first.data()),
              boost::beast::string_view(header.second.data()));
    }
    auto &req_body = req.body();
    req_body.reserve(body.size());
    req_body.append(body.begin(), body.end());
    req.prepare_payload();
    // Send the HTTP request to the remote host
    beast::http::write(stream, req);

    // Read response
    beast::flat_buffer buffer;
    response_t res(new beast::http::response<beast::http::string_body>);
    beast::http::read(stream, buffer, *res);

    // Gracefully close the socket
    stream.shutdown(ec);
    // not_connected happens sometimes
    // so don't bother reporting it.
    if (ec && ec != beast::errc::not_connected) {
      spdlog::info("{}: HTTP error encountered: {}", __func__, ec.message());
      return response_t();
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
}  // namespace transparent_auth
