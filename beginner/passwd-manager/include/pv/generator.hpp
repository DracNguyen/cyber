// generator.hpp
//
// Talks to: constants.hpp only.
// Cryptographically secure random password generation. Pure function, no
// I/O -- same rule as crypto.hpp, and for the same reason: the RNG choices
// here matter for security, so this file stays trivial to audit in
// isolation.

#pragma once

#include <cstddef>
#include <string>

namespace pv::generator {

struct Options {
  std::size_t length = 20;
  bool use_lowercase = true;
  bool use_uppercase = true;
  bool use_digits = true;
  bool use_symbols = true;
};

// Throws ValidationError if length is below the minimum, no character pool
// is enabled, or length is too small to fit one character from each
// enabled pool.
std::string GeneratePassword(const Options& options);

}  // namespace pv::generator
