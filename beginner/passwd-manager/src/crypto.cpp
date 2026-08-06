#include "pv/crypto.hpp"

#include <argon2.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <cstring>

#include "pv/exceptions.hpp"

namespace pv::crypto {

namespace {

// RAII wrapper so an early throw can't leak an EVP_CIPHER_CTX.
class CipherCtx {
 public:
  CipherCtx() : ctx_(EVP_CIPHER_CTX_new()) {
    if (!ctx_) throw CryptoError("EVP_CIPHER_CTX_new failed");
  }
  ~CipherCtx() { EVP_CIPHER_CTX_free(ctx_); }
  CipherCtx(const CipherCtx&) = delete;
  CipherCtx& operator=(const CipherCtx&) = delete;
  EVP_CIPHER_CTX* get() { return ctx_; }

 private:
  EVP_CIPHER_CTX* ctx_;
};

}  // namespace

Argon2Params DefaultArgon2Params() { return Argon2Params{}; }

void ValidateArgon2Params(const Argon2Params& params) {
  if (params.time_cost < constants::kArgon2TimeCostMin ||
      params.memory_cost_kib < constants::kArgon2MemoryCostMinKiB ||
      params.parallelism < constants::kArgon2ParallelismMin) {
    throw InvalidVaultFormatError(
        "Argon2 parameters in vault file are below the minimum sanity "
        "floor (refusing to use a suspiciously cheap KDF configuration)");
  }
}

Bytes RandomBytes(std::size_t n) {
  Bytes out(n);
  if (n == 0) return out;
  if (RAND_bytes(out.data(), static_cast<int>(n)) != 1) {
    throw CryptoError("RAND_bytes failed to produce secure randomness");
  }
  return out;
}

Bytes DeriveKey(const std::string& password, const Bytes& salt,
                 const Argon2Params& params) {
  Bytes key(constants::kKeyLen);
  int rc = argon2id_hash_raw(params.time_cost, params.memory_cost_kib,
                              params.parallelism, password.data(),
                              password.size(), salt.data(), salt.size(),
                              key.data(), key.size());
  if (rc != ARGON2_OK) {
    throw CryptoError(std::string("Argon2id key derivation failed: ") +
                       argon2_error_message(rc));
  }
  return key;
}

Bytes AesGcmEncrypt(const Bytes& plaintext, const Bytes& key,
                     const Bytes& nonce) {
  if (key.size() != constants::kKeyLen) {
    throw CryptoError("AES-256-GCM key must be 32 bytes");
  }
  if (nonce.size() != constants::kNonceLen) {
    throw CryptoError("AES-256-GCM nonce must be 12 bytes");
  }

  CipherCtx ctx;
  if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr,
                          nullptr) != 1) {
    throw CryptoError("EVP_EncryptInit_ex (algo select) failed");
  }
  if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN,
                           static_cast<int>(nonce.size()), nullptr) != 1) {
    throw CryptoError("failed to set GCM IV length");
  }
  if (EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(),
                          nonce.data()) != 1) {
    throw CryptoError("EVP_EncryptInit_ex (key/iv) failed");
  }

  Bytes ciphertext(plaintext.size());
  int out_len = 0;
  if (!plaintext.empty()) {
    if (EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &out_len,
                           plaintext.data(),
                           static_cast<int>(plaintext.size())) != 1) {
      throw CryptoError("EVP_EncryptUpdate failed");
    }
  }

  int final_len = 0;
  unsigned char final_buf[16];
  if (EVP_EncryptFinal_ex(ctx.get(), final_buf, &final_len) != 1) {
    throw CryptoError("EVP_EncryptFinal_ex failed");
  }
  ciphertext.resize(static_cast<std::size_t>(out_len));
  ciphertext.insert(ciphertext.end(), final_buf, final_buf + final_len);

  Bytes tag(constants::kTagLen);
  if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG,
                           static_cast<int>(tag.size()), tag.data()) != 1) {
    throw CryptoError("failed to retrieve GCM auth tag");
  }

  ciphertext.insert(ciphertext.end(), tag.begin(), tag.end());
  return ciphertext;
}

Bytes AesGcmDecrypt(const Bytes& ciphertext_and_tag, const Bytes& key,
                     const Bytes& nonce) {
  if (key.size() != constants::kKeyLen) {
    throw CryptoError("AES-256-GCM key must be 32 bytes");
  }
  if (nonce.size() != constants::kNonceLen) {
    throw CryptoError("AES-256-GCM nonce must be 12 bytes");
  }
  if (ciphertext_and_tag.size() < constants::kTagLen) {
    // Too short to even contain a tag -- definitely not a valid vault.
    throw WrongPasswordError(
        "Wrong master password (or vault file is corrupted)");
  }

  const std::size_t body_len = ciphertext_and_tag.size() - constants::kTagLen;
  const std::uint8_t* body = ciphertext_and_tag.data();
  const std::uint8_t* tag_ptr = ciphertext_and_tag.data() + body_len;

  CipherCtx ctx;
  if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr,
                          nullptr) != 1) {
    throw CryptoError("EVP_DecryptInit_ex (algo select) failed");
  }
  if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN,
                           static_cast<int>(nonce.size()), nullptr) != 1) {
    throw CryptoError("failed to set GCM IV length");
  }
  if (EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(),
                          nonce.data()) != 1) {
    throw CryptoError("EVP_DecryptInit_ex (key/iv) failed");
  }

  Bytes plaintext(body_len);
  int out_len = 0;
  if (body_len > 0) {
    if (EVP_DecryptUpdate(ctx.get(), plaintext.data(), &out_len, body,
                           static_cast<int>(body_len)) != 1) {
      throw WrongPasswordError(
          "Wrong master password (or vault file is corrupted)");
    }
  }

  // Tell OpenSSL what tag to check against *before* Final.
  Bytes tag_copy(tag_ptr, tag_ptr + constants::kTagLen);
  if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG,
                           static_cast<int>(tag_copy.size()),
                           tag_copy.data()) != 1) {
    throw CryptoError("failed to set GCM auth tag for verification");
  }

  int final_len = 0;
  unsigned char final_buf[16];
  // A return value != 1 here means authentication failed: wrong key or the
  // ciphertext/tag was tampered with / corrupted. We intentionally collapse
  // both causes into one message (see WrongPasswordError doc comment).
  if (EVP_DecryptFinal_ex(ctx.get(), final_buf, &final_len) != 1) {
    SecureZero(plaintext);
    throw WrongPasswordError(
        "Wrong master password (or vault file is corrupted)");
  }

  plaintext.resize(static_cast<std::size_t>(out_len));
  plaintext.insert(plaintext.end(), final_buf, final_buf + final_len);
  return plaintext;
}

void SecureZero(Bytes& data) {
  if (!data.empty()) {
    // volatile pointer defeats "this memset is dead code" optimization.
    volatile std::uint8_t* p = data.data();
    for (std::size_t i = 0; i < data.size(); ++i) p[i] = 0;
  }
}

void SecureZero(std::string& data) {
  if (!data.empty()) {
    volatile char* p = data.data();
    for (std::size_t i = 0; i < data.size(); ++i) p[i] = 0;
  }
}

}  // namespace pv::crypto
