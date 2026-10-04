cmake_minimum_required(VERSION 3.20)
project(messagetag VERSION 0.1.0 LANGUAGES CXX)

# OpenSSL may live outside the default search paths (e.g. a local SDK).
if(NOT OPENSSL_ROOT_DIR AND DEFINED ENV{OPENSSL_ROOT_DIR})
    set(OPENSSL_ROOT_DIR "$ENV{OPENSSL_ROOT_DIR}")
endif()
if(NOT OPENSSL_ROOT_DIR AND EXISTS "/opt/gsb-production/toolchains/sl-chen-openssl/sdk/usr/include/openssl/hmac.h")
    set(OPENSSL_ROOT_DIR "/opt/gsb-production/toolchains/sl-chen-openssl/sdk/usr")
    file(GLOB _messagetag_openssl_crypto
         "/opt/gsb-production/toolchains/sl-chen-openssl/sdk/usr/lib/*/libcrypto.so")
    if(_messagetag_openssl_crypto)
        list(GET _messagetag_openssl_crypto 0 _messagetag_openssl_crypto)
        set(OPENSSL_CRYPTO_LIBRARY "${_messagetag_openssl_crypto}" CACHE FILEPATH
            "OpenSSL crypto library")
    endif()
endif()
find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto)

add_executable(messagetag src/main.cpp)
target_compile_features(messagetag PRIVATE cxx_std_20)
set_target_properties(messagetag PROPERTIES CXX_EXTENSIONS OFF)
target_link_libraries(messagetag PRIVATE OpenSSL::Crypto)

# Some SDK layouts keep arch-specific headers (opensslconf.h) in a separate dir.
file(GLOB _messagetag_openssl_arch_include
     "/opt/gsb-production/toolchains/sl-chen-openssl/sdk/usr/include/*/openssl/opensslconf.h")
if(_messagetag_openssl_arch_include)
    list(GET _messagetag_openssl_arch_include 0 _messagetag_openssl_arch_include)
    get_filename_component(_messagetag_openssl_arch_include
                           "${_messagetag_openssl_arch_include}" DIRECTORY)
    get_filename_component(_messagetag_openssl_arch_include
                           "${_messagetag_openssl_arch_include}" DIRECTORY)
    target_include_directories(messagetag PRIVATE "${_messagetag_openssl_arch_include}")
endif()
