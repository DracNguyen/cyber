// base64.hpp
//
// Talks to: nothing.
// Standard base64 (RFC 4648, with padding) so raw bytes (salts, nonces,
// ciphertexts) can round-trip through JSON strings.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace pv::base64 {

std::string encode(const std::vector<std::uint8_t>& data);
std::vector<std::uint8_t> decode(const std::string& text);

}  // namespace pv::base64
