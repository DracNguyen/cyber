// exceptions.hpp
//
// Typed exceptions raised by crypto.* and vault.*. main.cpp is the only
// place that catches these and turns them into user-facing messages.

#pragma once

#include <stdexcept>
#include <string>

namespace pv {

class PvError : public std::runtime_error {
 public:
  explicit PvError(const std::string& what) : std::runtime_error(what) {}
};

class VaultNotFoundError : public PvError {
 public:
  using PvError::PvError;
};

class VaultAlreadyExistsError : public PvError {
 public:
  using PvError::PvError;
};

// Thrown when AES-GCM authentication fails. Deliberately generic in wording
// ("wrong master password (or vault file is corrupted)") because a wrong key
// and a tampered/corrupted file are indistinguishable at this layer, and
// distinguishing them for the user would leak information to an attacker.
class WrongPasswordError : public PvError {
 public:
  using PvError::PvError;
};

class InvalidVaultFormatError : public PvError {
 public:
  using PvError::PvError;
};

class EntryNotFoundError : public PvError {
 public:
  using PvError::PvError;
};

class EntryAlreadyExistsError : public PvError {
 public:
  using PvError::PvError;
};

class ValidationError : public PvError {
 public:
  using PvError::PvError;
};

class CryptoError : public PvError {
 public:
  using PvError::PvError;
};

}  // namespace pv
