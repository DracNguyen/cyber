#include "pv/vault.hpp"

#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>

#include "pv/base64.hpp"
#include "pv/constants.hpp"
#include "pv/exceptions.hpp"
#include "pv/json.hpp"

namespace pv::vault {

namespace fs = std::filesystem;
using crypto::Bytes;

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

std::string NowIso8601Utc() {
  using namespace std::chrono;
  auto now = system_clock::now();
  std::time_t t = system_clock::to_time_t(now);
  std::tm tm_utc{};
  gmtime_r(&t, &tm_utc);
  char buf[40];
  int n = std::snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02d",
                         tm_utc.tm_year + 1900, tm_utc.tm_mon + 1,
                         tm_utc.tm_mday, tm_utc.tm_hour, tm_utc.tm_min,
                         tm_utc.tm_sec);
  return std::string(buf, n) + "+00:00";
}

namespace {

void ValidateEntryName(const std::string& name) {
  if (name.empty()) {
    throw ValidationError("Entry name must not be empty");
  }
  for (char c : name) {
    if (std::isspace(static_cast<unsigned char>(c))) {
      throw ValidationError("Entry name must not contain whitespace");
    }
  }
}

std::string ReadWholeFile(const fs::path& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    throw VaultNotFoundError("No vault found at " + path.string());
  }
  std::ostringstream ss;
  ss << in.rdbuf();
  return ss.str();
}

// Builds the encrypted inner JSON document: name -> entry fields.
json::Value EntriesToJson(const std::map<std::string, Entry>& entries) {
  json::Value obj = json::Value::MakeObject();
  for (const auto& [name, e] : entries) {
    json::Value ev = json::Value::MakeObject();
    ev["username"] = json::Value(e.username);
    ev["password"] = json::Value(e.password);
    ev["url"] = json::Value(e.url);
    ev["notes"] = json::Value(e.notes);
    ev["created_at"] = json::Value(e.created_at);
    ev["updated_at"] = json::Value(e.updated_at);
    obj[name] = ev;
  }
  return obj;
}

std::map<std::string, Entry> EntriesFromJson(const json::Value& v) {
  if (!v.is_object()) {
    throw InvalidVaultFormatError("Decrypted vault contents is not a JSON object");
  }
  std::map<std::string, Entry> out;
  for (const auto& [name, ev] : v.items()) {
    if (!ev.is_object()) {
      throw InvalidVaultFormatError("Entry '" + name + "' is malformed");
    }
    Entry e;
    e.username = ev.get_string("username");
    e.password = ev.get_string("password");
    e.url = ev.contains("url") ? ev.get_string("url") : "";
    e.notes = ev.contains("notes") ? ev.get_string("notes") : "";
    e.created_at = ev.get_string("created_at");
    e.updated_at = ev.get_string("updated_at");
    out.emplace(name, std::move(e));
  }
  return out;
}

}  // namespace

// ---------------------------------------------------------------------------
// Path / lifecycle plumbing
// ---------------------------------------------------------------------------

fs::path DefaultVaultPath() {
  const char* home = std::getenv("HOME");
  fs::path home_dir = home ? fs::path(home) : fs::path(".");
  return home_dir / constants::kDefaultVaultDirName / constants::kVaultFileName;
}

UnlockedVault::UnlockedVault(UnlockedVault&& other) noexcept
    : path_(std::move(other.path_)),
      salt_(std::move(other.salt_)),
      kdf_params_(other.kdf_params_),
      key_(std::move(other.key_)),
      entries_(std::move(other.entries_)),
      closed_(other.closed_) {
  other.closed_ = true;  // don't let the moved-from object wipe our data
}

UnlockedVault& UnlockedVault::operator=(UnlockedVault&& other) noexcept {
  if (this != &other) {
    Close();
    path_ = std::move(other.path_);
    salt_ = std::move(other.salt_);
    kdf_params_ = other.kdf_params_;
    key_ = std::move(other.key_);
    entries_ = std::move(other.entries_);
    closed_ = other.closed_;
    other.closed_ = true;
  }
  return *this;
}

UnlockedVault::~UnlockedVault() { Close(); }

void UnlockedVault::Close() {
  if (closed_) return;
  crypto::SecureZero(key_);
  for (auto& [name, e] : entries_) {
    crypto::SecureZero(e.password);
  }
  entries_.clear();
  closed_ = true;
}

// ---------------------------------------------------------------------------
// Create / Unlock
// ---------------------------------------------------------------------------

UnlockedVault UnlockedVault::BuildFresh(const fs::path& path,
                                         const std::string& master_password) {
  if (master_password.size() < constants::kMasterPasswordMinLen) {
    throw ValidationError(
        "Master password must be at least " +
        std::to_string(constants::kMasterPasswordMinLen) + " characters");
  }
  UnlockedVault v;
  v.path_ = path;
  v.salt_ = crypto::RandomBytes(constants::kSaltLen);
  v.kdf_params_ = crypto::DefaultArgon2Params();
  v.key_ = crypto::DeriveKey(master_password, v.salt_, v.kdf_params_);
  v.closed_ = false;
  return v;
}

UnlockedVault UnlockedVault::Create(const fs::path& path,
                                     const std::string& master_password) {
  if (fs::exists(path)) {
    throw VaultAlreadyExistsError("A vault already exists at " +
                                   path.string());
  }
  fs::create_directories(path.parent_path());
  UnlockedVault v = BuildFresh(path, master_password);
  v.Save();
  return v;
}

UnlockedVault UnlockedVault::Unlock(const fs::path& path,
                                     const std::string& master_password) {
  if (!fs::exists(path)) {
    throw VaultNotFoundError("No vault found at " + path.string());
  }
  std::string raw = ReadWholeFile(path);

  json::Value envelope;
  try {
    envelope = json::Value::parse(raw);
  } catch (const json::ParseError& e) {
    throw InvalidVaultFormatError(std::string("Vault file is not valid JSON: ") +
                                   e.what());
  }

  if (!envelope.is_object() || !envelope.contains("version") ||
      !envelope.contains("kdf") || !envelope.contains("cipher")) {
    throw InvalidVaultFormatError(
        "Vault file is missing required top-level fields");
  }

  std::int64_t version = envelope.get_int("version");
  if (version != constants::kVaultFormatVersion) {
    throw InvalidVaultFormatError(
        "Vault file format version " + std::to_string(version) +
        " is not supported by this build (expected " +
        std::to_string(constants::kVaultFormatVersion) +
        "). Refusing to guess how to read a version we don't recognize.");
  }

  const json::Value& kdf = envelope.at("kdf");
  if (kdf.get_string("name") != constants::kKdfName) {
    throw InvalidVaultFormatError("Unsupported KDF: " + kdf.get_string("name"));
  }
  const json::Value& cipher = envelope.at("cipher");
  if (cipher.get_string("name") != constants::kCipherName) {
    throw InvalidVaultFormatError("Unsupported cipher: " +
                                   cipher.get_string("name"));
  }

  crypto::Argon2Params params;
  params.time_cost = static_cast<std::uint32_t>(kdf.get_int("time_cost"));
  params.memory_cost_kib = static_cast<std::uint32_t>(kdf.get_int("memory_cost"));
  params.parallelism = static_cast<std::uint32_t>(kdf.get_int("parallelism"));
  crypto::ValidateArgon2Params(params);

  Bytes salt = base64::decode(kdf.get_string("salt"));
  Bytes nonce = base64::decode(cipher.get_string("nonce"));
  Bytes ciphertext = base64::decode(cipher.get_string("ciphertext"));

  if (salt.size() != constants::kSaltLen) {
    throw InvalidVaultFormatError("Salt has unexpected length");
  }
  if (nonce.size() != constants::kNonceLen) {
    throw InvalidVaultFormatError("Nonce has unexpected length");
  }

  Bytes key = crypto::DeriveKey(master_password, salt, params);  // slow path
  Bytes plaintext;
  try {
    plaintext = crypto::AesGcmDecrypt(ciphertext, key, nonce);
  } catch (...) {
    crypto::SecureZero(key);
    throw;
  }

  json::Value inner;
  try {
    inner = json::Value::parse(
        std::string(reinterpret_cast<const char*>(plaintext.data()),
                     plaintext.size()));
  } catch (const json::ParseError& e) {
    crypto::SecureZero(key);
    crypto::SecureZero(plaintext);
    throw InvalidVaultFormatError(
        std::string("Decrypted vault contents is not valid JSON: ") +
        e.what());
  }
  auto entries = EntriesFromJson(inner);
  crypto::SecureZero(plaintext);

  UnlockedVault v;
  v.path_ = path;
  v.salt_ = std::move(salt);
  v.kdf_params_ = params;
  v.key_ = std::move(key);
  v.entries_ = std::move(entries);
  v.closed_ = false;
  return v;
}

// ---------------------------------------------------------------------------
// Entry CRUD
// ---------------------------------------------------------------------------

void UnlockedVault::AddEntry(const std::string& name, const Entry& entry,
                              bool force) {
  ValidateEntryName(name);
  if (!force && entries_.count(name) != 0) {
    throw EntryAlreadyExistsError("An entry named '" + name +
                                   "' already exists (use --force to overwrite)");
  }
  entries_[name] = entry;
}

const Entry& UnlockedVault::GetEntry(const std::string& name) const {
  auto it = entries_.find(name);
  if (it == entries_.end()) {
    throw EntryNotFoundError("No entry named '" + name + "'");
  }
  return it->second;
}

void UnlockedVault::DeleteEntry(const std::string& name) {
  auto it = entries_.find(name);
  if (it == entries_.end()) {
    throw EntryNotFoundError("No entry named '" + name + "'");
  }
  crypto::SecureZero(it->second.password);
  entries_.erase(it);
}

std::vector<std::string> UnlockedVault::Names() const {
  std::vector<std::string> names;
  names.reserve(entries_.size());
  for (const auto& [name, e] : entries_) names.push_back(name);
  std::sort(names.begin(), names.end());  // map already iterates sorted,
                                           // but keep this explicit as the
                                           // documented contract.
  return names;
}

void UnlockedVault::ChangeMasterPassword(const std::string& new_password) {
  if (new_password.size() < constants::kMasterPasswordMinLen) {
    throw ValidationError(
        "Master password must be at least " +
        std::to_string(constants::kMasterPasswordMinLen) + " characters");
  }
  Bytes new_salt = crypto::RandomBytes(constants::kSaltLen);
  crypto::Argon2Params defaults = crypto::DefaultArgon2Params();
  Bytes new_key = crypto::DeriveKey(new_password, new_salt, defaults);

  // Only mutate in-memory state here. Disk is untouched until Save() runs,
  // which is exactly why a crash mid-rotation can't lock anyone out (see
  // ARCHITECTURE.md section 7): the old salt/ciphertext on disk is still
  // valid with the old password until the atomic rename lands.
  crypto::SecureZero(key_);
  salt_ = std::move(new_salt);
  kdf_params_ = defaults;
  key_ = std::move(new_key);
}

// ---------------------------------------------------------------------------
// Save: serialize -> encrypt -> atomic durable write
// ---------------------------------------------------------------------------

namespace {

// RAII advisory lock on a sibling ".lock" file. Held across the whole
// save so two `pv` processes can't race each other to write the vault
// (see ARCHITECTURE.md section 9, steps 1 and 8).
class FileLock {
 public:
  explicit FileLock(const fs::path& lock_path) {
    fd_ = ::open(lock_path.c_str(), O_CREAT | O_RDWR, 0600);
    if (fd_ < 0) {
      throw PvError("Failed to open lock file: " + lock_path.string());
    }
    if (::flock(fd_, LOCK_EX) != 0) {
      ::close(fd_);
      throw PvError("Failed to acquire advisory lock on vault");
    }
  }
  ~FileLock() {
    if (fd_ >= 0) {
      ::flock(fd_, LOCK_UN);
      ::close(fd_);
    }
  }
  FileLock(const FileLock&) = delete;
  FileLock& operator=(const FileLock&) = delete;

 private:
  int fd_ = -1;
};

}  // namespace

void UnlockedVault::WriteAtomic(const std::vector<std::uint8_t>& bytes) const {
  fs::path lock_path = path_;
  lock_path += constants::kLockFileSuffix;
  fs::path tmp_path = path_;
  tmp_path += constants::kTmpFileSuffix;

  // Step 1: acquire the advisory lock (held until this function returns).
  FileLock lock(lock_path);

  // Step 2: create the tmp file world-unreadable from the very first
  // syscall -- no window where it's readable before we chmod it, because
  // we never chmod it; the mode is baked into the open() call.
  int fd = ::open(tmp_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (fd < 0) {
    throw PvError("Failed to open temp file for writing: " + tmp_path.string());
  }

  // Step 3: write the envelope bytes.
  std::size_t written = 0;
  while (written < bytes.size()) {
    ssize_t n = ::write(fd, bytes.data() + written, bytes.size() - written);
    if (n < 0) {
      ::close(fd);
      throw PvError("Failed to write vault temp file");
    }
    written += static_cast<std::size_t>(n);
  }

  // Step 4: fsync the data -- without this, "we wrote it" only lives in the
  // page cache and a power loss can erase it (see ARCHITECTURE.md #9).
  if (::fsync(fd) != 0) {
    ::close(fd);
    throw PvError("fsync failed on vault temp file");
  }

  // Step 5: close.
  if (::close(fd) != 0) {
    throw PvError("close failed on vault temp file");
  }

  // Step 6: atomic rename. After this instant, any reader sees either the
  // fully-old file or the fully-new file, never a half-written mix.
  if (::rename(tmp_path.c_str(), path_.c_str()) != 0) {
    throw PvError("Atomic rename onto vault file failed");
  }

  // Step 7: fsync the parent directory so the rename itself survives a
  // power loss (an OS crash right after rename can otherwise revert the
  // directory entry on some filesystems).
  fs::path parent = path_.parent_path();
  if (parent.empty()) parent = ".";
  int dir_fd = ::open(parent.c_str(), O_RDONLY);
  if (dir_fd >= 0) {
    ::fsync(dir_fd);
    ::close(dir_fd);
  }
  // Step 8: lock released automatically when `lock` goes out of scope.
}

void UnlockedVault::Save() {
  json::Value inner = EntriesToJson(entries_);
  std::string inner_text = inner.dump();
  Bytes plaintext(inner_text.begin(), inner_text.end());

  Bytes nonce = crypto::RandomBytes(constants::kNonceLen);  // fresh every save
  Bytes ciphertext = crypto::AesGcmEncrypt(plaintext, key_, nonce);
  crypto::SecureZero(plaintext);

  json::Value envelope = json::Value::MakeObject();
  envelope["version"] = json::Value(static_cast<std::int64_t>(constants::kVaultFormatVersion));

  json::Value kdf = json::Value::MakeObject();
  kdf["name"] = json::Value(constants::kKdfName);
  kdf["salt"] = json::Value(base64::encode(salt_));
  kdf["time_cost"] = json::Value(static_cast<std::int64_t>(kdf_params_.time_cost));
  kdf["memory_cost"] = json::Value(static_cast<std::int64_t>(kdf_params_.memory_cost_kib));
  kdf["parallelism"] = json::Value(static_cast<std::int64_t>(kdf_params_.parallelism));
  envelope["kdf"] = kdf;

  json::Value cipher = json::Value::MakeObject();
  cipher["name"] = json::Value(constants::kCipherName);
  cipher["nonce"] = json::Value(base64::encode(nonce));
  cipher["ciphertext"] = json::Value(base64::encode(ciphertext));
  envelope["cipher"] = cipher;

  std::string envelope_text = envelope.dump();
  std::vector<std::uint8_t> envelope_bytes(envelope_text.begin(), envelope_text.end());
  WriteAtomic(envelope_bytes);
}

}  // namespace pv::vault
