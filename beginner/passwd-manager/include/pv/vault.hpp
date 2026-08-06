// vault.hpp
//
// Talks to: crypto.hpp, constants.hpp, json.hpp, base64.hpp.
// Doesn't talk to: the terminal, argv, stdin/stdout, Rich-equivalent
// formatting -- that all belongs in main.cpp. This file raises typed
// exceptions (exceptions.hpp); it never prints anything.
//
// Owns: the on-disk file format, atomic+durable+concurrent-safe writes,
// file locking, and entry add/get/delete against the decrypted map.

#pragma once

#include <filesystem>
#include <map>
#include <string>
#include <vector>

#include "pv/crypto.hpp"

namespace pv::vault {

struct Entry {
  std::string username;
  std::string password;
  std::string url;
  std::string notes;
  std::string created_at;  // ISO 8601, e.g. "2026-05-13T14:22:10+00:00"
  std::string updated_at;
};

// Default vault path: ~/.password-vault/vault.json
std::filesystem::path DefaultVaultPath();

// Current UTC time as "YYYY-MM-DDTHH:MM:SS+00:00", used for entry
// created_at/updated_at timestamps.
std::string NowIso8601Utc();

// An unlocked vault holds the derived AES key and decrypted entries in
// memory for the lifetime of the object. Not copyable (the key is
// sensitive); move-only.
//
// Prefer scoping it tightly:
//
//   {
//     UnlockedVault v = UnlockedVault::Unlock(path, master);
//     v.AddEntry("github", entry);
//     v.Save();
//   } // destructor wipes key + entries here
//
class UnlockedVault {
 public:
  UnlockedVault(const UnlockedVault&) = delete;
  UnlockedVault& operator=(const UnlockedVault&) = delete;
  UnlockedVault(UnlockedVault&&) noexcept;
  UnlockedVault& operator=(UnlockedVault&&) noexcept;
  ~UnlockedVault();

  // Creates a brand-new empty vault at `path` and writes it to disk.
  // Throws VaultAlreadyExistsError if a file is already there.
  static UnlockedVault Create(const std::filesystem::path& path,
                               const std::string& master_password);

  // Reads + decrypts an existing vault. Throws VaultNotFoundError,
  // InvalidVaultFormatError, or WrongPasswordError.
  static UnlockedVault Unlock(const std::filesystem::path& path,
                               const std::string& master_password);

  // Entry CRUD. All operate on the in-memory map only; call Save() to
  // persist. `name` may not be empty or contain whitespace.
  void AddEntry(const std::string& name, const Entry& entry,
                bool force = false);
  const Entry& GetEntry(const std::string& name) const;
  void DeleteEntry(const std::string& name);
  std::vector<std::string> Names() const;  // sorted alphabetically
  bool Empty() const { return entries_.empty(); }

  // Rotates the master password: fresh salt, new key derived from the new
  // password, same entries. Only mutates in-memory state -- call Save() to
  // persist. If the process dies between this call and Save() completing,
  // the on-disk file still has the OLD salt/ciphertext and is still
  // readable with the OLD password (see ARCHITECTURE.md section 7).
  void ChangeMasterPassword(const std::string& new_password);

  // Serializes entries, encrypts with a fresh nonce, and writes atomically:
  // flock -> write tmp (mode 0600 from creation) -> fsync -> close ->
  // rename onto the real path -> fsync parent dir -> unlock.
  void Save();

  // Explicit close: wipes the in-memory key and entries. Called
  // automatically by the destructor; safe to call more than once.
  void Close();

 private:
  UnlockedVault() = default;

  std::filesystem::path path_;
  crypto::Bytes salt_;
  crypto::Argon2Params kdf_params_;
  crypto::Bytes key_;
  std::map<std::string, Entry> entries_;
  bool closed_ = false;

  static UnlockedVault BuildFresh(const std::filesystem::path& path,
                                   const std::string& master_password);
  void WriteAtomic(const std::vector<std::uint8_t>& envelope_bytes) const;
};

}  // namespace pv::vault
