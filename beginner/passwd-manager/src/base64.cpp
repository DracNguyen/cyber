#include "pv/base64.hpp"

#include <array>
#include <stdexcept>

namespace pv::base64 {

namespace {
constexpr char kTable[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::array<int, 256> BuildReverseTable() {
  std::array<int, 256> rev{};
  rev.fill(-1);
  for (int i = 0; i < 64; ++i) {
    rev[static_cast<unsigned char>(kTable[i])] = i;
  }
  return rev;
}
}  // namespace

std::string encode(const std::vector<std::uint8_t>& data) {
  std::string out;
  out.reserve(((data.size() + 2) / 3) * 4);

  std::size_t i = 0;
  while (i + 3 <= data.size()) {
    std::uint32_t chunk = (static_cast<std::uint32_t>(data[i]) << 16) |
                           (static_cast<std::uint32_t>(data[i + 1]) << 8) |
                           static_cast<std::uint32_t>(data[i + 2]);
    out.push_back(kTable[(chunk >> 18) & 0x3F]);
    out.push_back(kTable[(chunk >> 12) & 0x3F]);
    out.push_back(kTable[(chunk >> 6) & 0x3F]);
    out.push_back(kTable[chunk & 0x3F]);
    i += 3;
  }

  const std::size_t remaining = data.size() - i;
  if (remaining == 1) {
    std::uint32_t chunk = static_cast<std::uint32_t>(data[i]) << 16;
    out.push_back(kTable[(chunk >> 18) & 0x3F]);
    out.push_back(kTable[(chunk >> 12) & 0x3F]);
    out.push_back('=');
    out.push_back('=');
  } else if (remaining == 2) {
    std::uint32_t chunk = (static_cast<std::uint32_t>(data[i]) << 16) |
                           (static_cast<std::uint32_t>(data[i + 1]) << 8);
    out.push_back(kTable[(chunk >> 18) & 0x3F]);
    out.push_back(kTable[(chunk >> 12) & 0x3F]);
    out.push_back(kTable[(chunk >> 6) & 0x3F]);
    out.push_back('=');
  }
  return out;
}

std::vector<std::uint8_t> decode(const std::string& text) {
  static const std::array<int, 256> rev = BuildReverseTable();

  // Strip whitespace defensively; ignore trailing '=' padding.
  std::vector<int> vals;
  vals.reserve(text.size());
  for (char c : text) {
    if (c == '=' || c == '\n' || c == '\r' || c == ' ') continue;
    int v = rev[static_cast<unsigned char>(c)];
    if (v < 0) {
      throw std::invalid_argument("base64::decode: invalid character");
    }
    vals.push_back(v);
  }

  std::vector<std::uint8_t> out;
  out.reserve((vals.size() * 3) / 4 + 3);

  std::size_t i = 0;
  while (i + 4 <= vals.size()) {
    std::uint32_t chunk = (static_cast<std::uint32_t>(vals[i]) << 18) |
                           (static_cast<std::uint32_t>(vals[i + 1]) << 12) |
                           (static_cast<std::uint32_t>(vals[i + 2]) << 6) |
                           static_cast<std::uint32_t>(vals[i + 3]);
    out.push_back(static_cast<std::uint8_t>((chunk >> 16) & 0xFF));
    out.push_back(static_cast<std::uint8_t>((chunk >> 8) & 0xFF));
    out.push_back(static_cast<std::uint8_t>(chunk & 0xFF));
    i += 4;
  }

  const std::size_t remaining = vals.size() - i;
  if (remaining == 2) {
    std::uint32_t chunk = (static_cast<std::uint32_t>(vals[i]) << 18) |
                           (static_cast<std::uint32_t>(vals[i + 1]) << 12);
    out.push_back(static_cast<std::uint8_t>((chunk >> 16) & 0xFF));
  } else if (remaining == 3) {
    std::uint32_t chunk = (static_cast<std::uint32_t>(vals[i]) << 18) |
                           (static_cast<std::uint32_t>(vals[i + 1]) << 12) |
                           (static_cast<std::uint32_t>(vals[i + 2]) << 6);
    out.push_back(static_cast<std::uint8_t>((chunk >> 16) & 0xFF));
    out.push_back(static_cast<std::uint8_t>((chunk >> 8) & 0xFF));
  } else if (remaining != 0) {
    throw std::invalid_argument("base64::decode: malformed input length");
  }

  return out;
}

}  // namespace pv::base64
