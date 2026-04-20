cmake_minimum_required(VERSION 3.16)
project(parity_hsm)

set(CMAKE_CXX_STANDARD 17)

include(FetchContent)

# OpenSSL
find_package(OpenSSL REQUIRED)

# JSON (auto-download)
FetchContent_Declare(
  json
  URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
)

FetchContent_MakeAvailable(json)

add_executable(parity_hsm
    src/main.cpp
    src/core/hsm.cpp
    src/crypto/rsa.cpp
    src/crypto/aes.cpp
    src/crypto/xor.cpp
    src/storage/usb.cpp
    src/storage/disk.cpp
    src/token/epass.cpp
)

target_include_directories(parity_hsm PRIVATE include)

target_link_libraries(parity_hsm
    OpenSSL::Crypto
    nlohmann_json::nlohmann_json
)

find_library(ARGON2_LIB argon2 REQUIRED)

target_link_libraries(parity_hsm
    OpenSSL::Crypto
    nlohmann_json::nlohmann_json
    ${ARGON2_LIB}
)
FetchContent_Declare(
  json
  URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)