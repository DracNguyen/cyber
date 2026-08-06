#include "pv/generator.hpp"

#include <openssl/rand.h>

#include <stdexcept>
#include <vector>

#include "pv/constants.hpp"
#include "pv/exceptions.hpp"

// Note: this file intentionally calls OpenSSL's RAND_bytes directly rather
// than going through crypto.hpp. Per the architecture, generator.py talks
// only to constants -- it has no reason to depend on the crypto layer, and
// adding that edge would blur the "why does this file exist" boundary for
// no benefit. (crypto.hpp's job is authenticated encryption + key
// derivation; "give me an unbiased random index" is a much smaller need
// that doesn't warrant routing through it.)

namespace pv::generator {

namespace {

// Returns a value in [0, bound) with no modulo bias, via rejection
// sampling. Mirrors Python's secrets.randbelow -- NOT the same as
// `RAND_bytes(...) % bound`, which is subtly biased toward small values
// whenever bound doesn't evenly divide 256/65536/etc.
std::uint32_t RandomBelow(std::uint32_t bound) {
  if (bound == 0) throw std::invalid_argument("RandomBelow: bound must be > 0");
  if (bound == 1) return 0;

  // Smallest number of bits that can represent [0, bound).
  std::uint32_t range = bound - 1;
  int bits = 0;
  while (range > 0) {
    ++bits;
    range >>= 1;
  }
  int bytes_needed = (bits + 7) / 8;

  while (true) {
    std::uint32_t candidate = 0;
    unsigned char buf[4] = {0, 0, 0, 0};
    if (RAND_bytes(buf, bytes_needed) != 1) {
      throw pv::CryptoError("RAND_bytes failed during password generation");
    }
    for (int i = 0; i < bytes_needed; ++i) {
      candidate = (candidate << 8) | buf[i];
    }
    // Mask off any high bits beyond what we asked for.
    if (bits % 8 != 0 || bytes_needed * 8 != bits) {
      candidate &= (1u << bits) - 1;
    }
    if (candidate < bound) return candidate;
    // else: reject and redraw -- keeps the distribution exactly uniform.
  }
}

void SecureShuffle(std::string& chars) {
  // Fisher-Yates using RandomBelow (CSPRNG), NOT std::rand/std::shuffle
  // with a PRNG engine -- an attacker who could predict the shuffle could
  // narrow down the password despite the character pool being large.
  for (std::size_t i = chars.size(); i-- > 1;) {
    std::uint32_t j = RandomBelow(static_cast<std::uint32_t>(i + 1));
    std::swap(chars[i], chars[j]);
  }
}

}  // namespace

std::string GeneratePassword(const Options& options) {
  if (options.length < constants::kGeneratedPasswordMinLen) {
    throw ValidationError("Password length must be at least " +
                           std::to_string(constants::kGeneratedPasswordMinLen) +
                           " characters");
  }

  std::vector<const std::string*> pools;
  if (options.use_lowercase) pools.push_back(&constants::kLowerAlphabet);
  if (options.use_uppercase) pools.push_back(&constants::kUpperAlphabet);
  if (options.use_digits) pools.push_back(&constants::kDigitAlphabet);
  if (options.use_symbols) pools.push_back(&constants::kSymbolAlphabet);

  if (pools.empty()) {
    throw ValidationError(
        "At least one character pool (lowercase/uppercase/digits/symbols) "
        "must be enabled");
  }
  if (options.length < pools.size()) {
    throw ValidationError(
        "Password length must be at least as large as the number of "
        "enabled character pools (need at least one char from each)");
  }

  std::string combined;
  for (const auto* pool : pools) combined += *pool;

  std::string chars;
  chars.reserve(options.length);

  // Guarantee at least one character from each enabled pool.
  for (const auto* pool : pools) {
    chars.push_back((*pool)[RandomBelow(static_cast<std::uint32_t>(pool->size()))]);
  }

  // Fill the rest from the combined pool.
  while (chars.size() < options.length) {
    chars.push_back(
        combined[RandomBelow(static_cast<std::uint32_t>(combined.size()))]);
  }

  SecureShuffle(chars);
  return chars;
}

}  // namespace pv::generator
