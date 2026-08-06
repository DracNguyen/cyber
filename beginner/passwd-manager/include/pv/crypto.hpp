// crypto.hpp
//
// Talks to: constants.hpp only.
// Doesn't talk to: filesystem, network, CLI, terminal.
//
// Pure cryptography. Bytes in, bytes out, no I/O. This is what makes it
// trivial to test in isolation and impossible to accidentally leak a key
// via a stray print/log statement from the wrong layer.
//
// Backing implementations:
//   - Argon2id  -> libargon2  (argon2.h / libargon2)
//   - AES-256-GCM -> OpenSSL EVP  (openssl/evp.h / libcrypto)
//   - CSPRNG    -> OpenSSL RAND_bytes

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "pv/constants.hpp"

namespace pv::crypto {

using Bytes = std::vector<std::uint8_t>;

struct Argon2Params {
  std::uint32_t time_cost = constants::kArgon2TimeCostDefault;
  std::uint32_t memory_cost_kib = constants::kArgon2MemoryCostDefaultKiB;
  std::uint32_t parallelism = constants::kArgon2ParallelismDefault;
};

// Returns today's recommended defaults. Kept as a function (not a global
// constant) so that a future version of this file can ratchet the numbers
// up without touching any caller.
Argon2Params DefaultArgon2Params();

// Rejects parameters below the sanity floor (see constants.hpp). Used when
// *reading* a vault file: a file claiming absurdly cheap KDF cost is either
// corrupted or a deliberate downgrade attempt.
void ValidateArgon2Params(const Argon2Params& params);

// Cryptographically secure random bytes (CSPRNG). Throws CryptoError if the
// underlying RNG call fails.
Bytes RandomBytes(std::size_t n);

// Derives a 32-byte AES-256 key from a password + salt via Argon2id.
// This is the slow, deliberately expensive path (~0.3-0.7s on a modern
// laptop with default params) -- call it once per unlock, not once per
// operation.
Bytes DeriveKey(const std::string& password, const Bytes& salt,
                 const Argon2Params& params);

// AES-256-GCM encrypt. `key` must be 32 bytes, `nonce` must be 12 bytes and
// MUST be freshly random for every call with the same key (never reused).
// Returns ciphertext with the 16-byte authentication tag appended, so the
// vault file only needs to store a single "ciphertext" field.
Bytes AesGcmEncrypt(const Bytes& plaintext, const Bytes& key,
                     const Bytes& nonce);

// AES-256-GCM decrypt + authenticate. `ciphertext_and_tag` is the output of
// AesGcmEncrypt (ciphertext with tag appended). Throws WrongPasswordError if
// authentication fails -- callers should not try to distinguish "wrong
// password" from "corrupted file" any further than that, since the two are
// cryptographically indistinguishable at this layer and telling them apart
// would hand an attacker useful feedback.
Bytes AesGcmDecrypt(const Bytes& ciphertext_and_tag, const Bytes& key,
                     const Bytes& nonce);

// Best-effort in-place zeroing. Defends against the compiler optimizing
// away a "pointless" memset right before a buffer goes out of scope.
void SecureZero(Bytes& data);
void SecureZero(std::string& data);

}  // namespace pv::crypto
