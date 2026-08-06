# pv — password manager (C++ port)

C++17 port of the 5-file layered password-manager architecture described in
`02-ARCHITECTURE.md`. Same file boundaries, same on-disk format, same atomic
write protocol, same dependency direction.

## Layout (maps 1:1 to the architecture doc)

```
include/pv/constants.hpp     numbers & strings, no project includes
include/pv/exceptions.hpp    typed exceptions (VaultNotFoundError, ...)
include/pv/base64.hpp/.cpp   RFC4648 base64 (no external dep needed)
include/pv/json.hpp/.cpp     tiny JSON tailored to the vault's fixed schema
include/pv/crypto.hpp/.cpp   Argon2id + AES-256-GCM, pure functions, no I/O
include/pv/generator.hpp/.cpp cryptographically secure password generation
include/pv/vault.hpp/.cpp    file format, atomic writes, flock, entry CRUD
src/main.cpp                 CLI (init/add/get/list/delete/change-password/gen)
```

Dependency direction is exactly what section 2 of the architecture doc draws:
`main.cpp` → `vault` → `crypto` → `constants`, plus `generator` → `constants`.
`crypto.cpp` does zero I/O; `vault.cpp` does zero terminal I/O.

## Vault file format

Identical two-layer JSON envelope to the Python version — see section 3 of
the architecture doc. `pv init` on this C++ build and a vault created by the
Python version are readable by either implementation, since both are just
JSON + Argon2id + AES-256-GCM with the same field names.

## Dependencies

- CMake ≥ 3.16, a C++17 compiler
- OpenSSL (`libssl-dev` / `openssl-devel` / `brew install openssl@3`) — used
  only for AES-256-GCM (`EVP_aes_256_gcm`) and secure randomness (`RAND_bytes`)
- libargon2 (`libargon2-dev` / `libargon2-devel` / `brew install argon2`) —
  Argon2id key derivation

If your environment has the runtime `.so` files but not the `-dev` headers
(no package manager network access, minimal containers, etc.), `CMakeLists.txt`
automatically falls back to the hand-written declarations in
`third_party/compat/` and links directly against the runtime libraries. This
fallback was exercised and confirmed working in exactly that kind of
environment while building this project — but installing the real `-dev`
packages is still the recommended path when you can.

## Build

```bash
sudo apt install libssl-dev libargon2-dev   # Debian/Ubuntu
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
./build/pv --help
```

## Usage

```bash
./build/pv init                                 # create ~/.password-vault/vault.json
./build/pv add github                           # prompts for username/password/url/notes
./build/pv add email --generate --length 24     # auto-generate the password
./build/pv get github
./build/pv list                                 # usernames only, never passwords
./build/pv delete github
./build/pv change-password                      # rotates master password, re-encrypts
./build/pv gen 32                               # standalone generator, no vault needed

# override the default vault location:
./build/pv list --vault /path/to/other-vault.json
```

## What differs from the Python version, and why

- **No third-party JSON/CLI-framework dependency.** The vault schema is
  fixed and small (envelope + flat entry dict), so a ~150-line hand-rolled
  JSON reader/writer replaces a general-purpose library, and argv parsing is
  done by hand instead of pulling in something like CLI11 — keeps the build
  dependency-free beyond OpenSSL + libargon2.
- **POSIX-only atomic write path.** `flock`, `fsync`, and directory fsync are
  POSIX APIs (`<fcntl.h>`, `<sys/file.h>`, `<unistd.h>`). This targets
  Linux/macOS, matching how the architecture doc itself describes the POSIX
  path as the primary one (Windows is called out there as losing some of
  these guarantees too).
- **Best-effort key/password wiping** uses a `volatile` pointer loop instead
  of Python's "reassign to zero bytes" trick, for the same reason the doc
  gives for Python: this is a discipline (drop secrets explicitly when done),
  not a cryptographic guarantee — `std::vector`/`std::string` reallocations
  earlier in the program's life can still leave copies in memory that only a
  dedicated secure-allocator would prevent.
