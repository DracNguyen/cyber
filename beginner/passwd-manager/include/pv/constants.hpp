// constants.hpp
//
// Talks to: nothing (no project includes).
// Job: single source of truth for every magic number / fixed string used
// elsewhere. Nothing in this file does I/O.

#pragma once

#include <cstdint>
#include <string>

namespace pv::constants {

// ---- Vault file locations -------------------------------------------------

inline const std::string kDefaultVaultDirName = ".password-vault";
inline const std::string kVaultFileName = "vault.json";
inline const std::string kLockFileSuffix = ".lock";
inline const std::string kTmpFileSuffix = ".tmp";

// ---- File format -----------------------------------------------------------

inline constexpr int kVaultFormatVersion = 1;
inline const std::string kKdfName = "argon2id";
inline const std::string kCipherName = "aes-256-gcm";

// ---- Cryptographic sizes (bytes) ------------------------------------------

inline constexpr std::size_t kSaltLen = 16;
inline constexpr std::size_t kNonceLen = 12;   // AES-GCM standard nonce size
inline constexpr std::size_t kKeyLen = 32;     // AES-256
inline constexpr std::size_t kTagLen = 16;     // GCM auth tag

// ---- Argon2id defaults ------------------------------------------------
// Mirrors the OWASP-recommended baseline: enough memory cost to make
// GPU/ASIC cracking expensive, tuned for ~0.3-0.7s on a modern laptop.

inline constexpr std::uint32_t kArgon2TimeCostDefault = 3;
inline constexpr std::uint32_t kArgon2MemoryCostDefaultKiB = 65536;  // 64 MiB
inline constexpr std::uint32_t kArgon2ParallelismDefault = 4;

// Sanity floors used when *reading* a vault written by some other tool.
// A vault claiming below these values is almost certainly an attempt to
// downgrade the KDF cost, so we refuse to honor it.
inline constexpr std::uint32_t kArgon2TimeCostMin = 1;
inline constexpr std::uint32_t kArgon2MemoryCostMinKiB = 8192;  // 8 MiB
inline constexpr std::uint32_t kArgon2ParallelismMin = 1;

// ---- Password rules ---------------------------------------------------

inline constexpr std::size_t kMasterPasswordMinLen = 8;
inline constexpr std::size_t kGeneratedPasswordMinLen = 8;
inline constexpr std::size_t kGeneratedPasswordDefaultLen = 20;

inline const std::string kLowerAlphabet = "abcdefghijklmnopqrstuvwxyz";
inline const std::string kUpperAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
inline const std::string kDigitAlphabet = "0123456789";
// Deliberately excludes characters that are visually ambiguous or awkward
// to type/shell-quote (no quotes, backticks, backslash).
inline const std::string kSymbolAlphabet = "!@#$%^&*()-_=+[]{}<>?,.";

}  // namespace pv::constants
