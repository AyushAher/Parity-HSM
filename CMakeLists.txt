cmake_minimum_required(VERSION 3.16)
project(parity_hsm)

set(CMAKE_CXX_STANDARD 17)

include(FetchContent)

# OpenSSL
find_package(OpenSSL REQUIRED)

# Argon2
find_library(ARGON2_LIB argon2 REQUIRED)

# JSON
FetchContent_Declare(
  json
  URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
FetchContent_MakeAvailable(json)

# =========================
# CORE LIB (🔥 IMPORTANT)
# =========================
add_library(parity_core STATIC
    src/crypto/aes.cpp
    src/crypto/rsa.cpp
    src/crypto/xor.cpp

    src/core/hsm.cpp

    src/storage/usb.cpp
    src/storage/disk.cpp
)

target_include_directories(parity_core PRIVATE include)

target_link_libraries(parity_core
    OpenSSL::Crypto
    nlohmann_json::nlohmann_json
    ${ARGON2_LIB}
)

# =========================
# MAIN EXECUTABLE
# =========================
add_executable(parity_hsm
    src/main.cpp
)

target_include_directories(parity_hsm PRIVATE include)

target_link_libraries(parity_hsm
    parity_core
)

# =========================
# PKCS11 MODULE (.so)
# =========================
add_library(parity_pkcs11 SHARED
    src/pkcs11/pkcs11.cpp
    src/pkcs11/object.cpp
    src/pkcs11/crypto.cpp
)

target_include_directories(parity_pkcs11 PRIVATE include)

target_link_libraries(parity_pkcs11
    parity_core
    OpenSSL::Crypto
    nlohmann_json::nlohmann_json
    ${ARGON2_LIB}
)

# Force .so on macOS
set_target_properties(parity_pkcs11 PROPERTIES
    PREFIX "lib"
    SUFFIX ".so"
)