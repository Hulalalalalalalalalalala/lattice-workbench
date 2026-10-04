cmake_minimum_required(VERSION 3.20)
project(messagetag VERSION 0.1.0 LANGUAGES CXX)

# HMAC-SHA-256 is provided by OpenSSL's libcrypto. Point OPENSSL_ROOT_DIR at
# an OpenSSL installation (or set the OPENSSL_ROOT_DIR environment variable)
# if it is not in a standard search location.
if(NOT DEFINED OPENSSL_ROOT_DIR AND DEFINED ENV{OPENSSL_ROOT_DIR})
    set(OPENSSL_ROOT_DIR "$ENV{OPENSSL_ROOT_DIR}")
endif()
if(NOT DEFINED OPENSSL_ROOT_DIR
   AND EXISTS "/opt/gsb-production/toolchains/sl-chen-openssl/sdk/usr/include/openssl/evp.h")
    set(OPENSSL_ROOT_DIR "/opt/gsb-production/toolchains/sl-chen-openssl/sdk/usr")
endif()
find_package(OpenSSL REQUIRED)

add_executable(messagetag src/main.cpp)
target_compile_features(messagetag PRIVATE cxx_std_20)
set_target_properties(messagetag PROPERTIES CXX_EXTENSIONS OFF)
target_link_libraries(messagetag PRIVATE OpenSSL::Crypto)
