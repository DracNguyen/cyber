cmake_minimum_required(VERSION 3.16)
project(pv LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

# -----------------------------------------------------------------------------
# Dependencies: OpenSSL (AES-256-GCM) and libargon2 (Argon2id).
#
# Normal path: use the real system dev packages.
#   Debian/Ubuntu: sudo apt install libssl-dev libargon2-dev
#   Fedora:        sudo dnf install openssl-devel libargon2-devel
#   macOS:         brew install openssl@3 argon2
#
# Fallback path: some minimal environments (containers, CI images) ship the
# *runtime* .so files but not the -dev headers, and have no network access
# to install them. third_party/compat/ contains a small set of hand-written
# header declarations (function signatures only, no implementation) that
# match the real OpenSSL EVP / libargon2 ABI, so the same runtime libraries
# can still be linked against. This fallback is only used when the real
# headers aren't found -- prefer installing the real -dev packages.
# -----------------------------------------------------------------------------

find_package(OpenSSL QUIET)
find_path(ARGON2_INCLUDE_DIR argon2.h)
find_library(ARGON2_LIBRARY argon2)

set(PV_USING_COMPAT_HEADERS OFF)

if(NOT OpenSSL_FOUND OR NOT ARGON2_INCLUDE_DIR OR NOT ARGON2_LIBRARY)
  message(STATUS "Real dev headers/libs not fully found; checking for the "
                  "bundled compat fallback (runtime .so present, headers "
                  "missing)...")

  find_library(LIBCRYPTO_RUNTIME NAMES crypto libcrypto.so.3)
  find_library(LIBARGON2_RUNTIME NAMES argon2 libargon2.so.1)

  if(LIBCRYPTO_RUNTIME AND LIBARGON2_RUNTIME)
    set(PV_USING_COMPAT_HEADERS ON)
    set(PV_COMPAT_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/compat)
    message(WARNING
      "Building against runtime libcrypto/libargon2 using bundled compat "
      "headers (third_party/compat) because the -dev packages are not "
      "installed. This works, but installing the real dev packages is "
      "recommended:\n"
      "  Debian/Ubuntu: sudo apt install libssl-dev libargon2-dev\n"
      "  Fedora:        sudo dnf install openssl-devel libargon2-devel\n"
      "  macOS:         brew install openssl@3 argon2")
  else()
    message(FATAL_ERROR
      "Neither the dev headers nor the runtime libraries for OpenSSL/"
      "libargon2 could be found. Install:\n"
      "  Debian/Ubuntu: sudo apt install libssl-dev libargon2-dev\n"
      "  Fedora:        sudo dnf install openssl-devel libargon2-devel\n"
      "  macOS:         brew install openssl@3 argon2")
  endif()
endif()

# --- Library (everything except main.cpp) -----------------------------------
add_library(pv_core
  src/base64.cpp
  src/json.cpp
  src/crypto.cpp
  src/generator.cpp
  src/vault.cpp
)
target_include_directories(pv_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_options(pv_core PRIVATE -Wall -Wextra)

if(PV_USING_COMPAT_HEADERS)
  target_include_directories(pv_core PUBLIC ${PV_COMPAT_INCLUDE_DIR})
  target_link_libraries(pv_core PUBLIC ${LIBCRYPTO_RUNTIME} ${LIBARGON2_RUNTIME})
else()
  target_include_directories(pv_core PUBLIC ${ARGON2_INCLUDE_DIR})
  target_link_libraries(pv_core PUBLIC OpenSSL::Crypto ${ARGON2_LIBRARY})
endif()

# --- CLI binary --------------------------------------------------------------
add_executable(pv src/main.cpp)
target_link_libraries(pv PRIVATE pv_core)
target_compile_options(pv PRIVATE -Wall -Wextra)

install(TARGETS pv RUNTIME DESTINATION bin)
