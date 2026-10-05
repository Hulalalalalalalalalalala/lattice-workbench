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
find_package(OpenSSL)
if(NOT OpenSSL_FOUND)
    message(FATAL_ERROR
        "OpenSSL development files (headers and libcrypto) were not found. "
        "Install them (e.g. 'sudo apt install libssl-dev') or point "
        "OPENSSL_ROOT_DIR at an OpenSSL installation prefix.")
endif()
# When OPENSSL_ROOT_DIR is given, the headers and the crypto library must
# both come from that prefix; refuse to mix dependencies from different
# OpenSSL installations.
if(DEFINED OPENSSL_ROOT_DIR)
    file(REAL_PATH "${OPENSSL_ROOT_DIR}" _openssl_root)
    file(REAL_PATH "${OPENSSL_INCLUDE_DIR}" _openssl_include)
    file(REAL_PATH "${OPENSSL_CRYPTO_LIBRARY}" _openssl_crypto)
    cmake_path(IS_PREFIX _openssl_root "${_openssl_include}" _include_ok)
    cmake_path(IS_PREFIX _openssl_root "${_openssl_crypto}" _crypto_ok)
    if(NOT _include_ok OR NOT _crypto_ok)
        message(FATAL_ERROR
            "OPENSSL_ROOT_DIR is '${_openssl_root}' but the OpenSSL files "
            "found do not all come from it (headers: '${_openssl_include}', "
            "libcrypto: '${_openssl_crypto}'). Check that this prefix holds "
            "a complete OpenSSL installation and that no other installation "
            "is being picked up (e.g. via pkg-config).")
    endif()
endif()
if(OPENSSL_VERSION VERSION_LESS 1.1.1)
    message(FATAL_ERROR
        "Found OpenSSL ${OPENSSL_VERSION}, but messagetag requires "
        "OpenSSL 1.1.1 or newer (OpenSSL 3.x is also supported).")
endif()
message(STATUS "Using OpenSSL ${OPENSSL_VERSION}: ${OPENSSL_CRYPTO_LIBRARY}")

add_executable(messagetag src/main.cpp)
target_compile_features(messagetag PRIVATE cxx_std_20)
set_target_properties(messagetag PROPERTIES CXX_EXTENSIONS OFF)
target_link_libraries(messagetag PRIVATE OpenSSL::Crypto)

# Regression tests: known-answer vectors (RFC 4231 and independently
# computed HMAC-SHA-256 tags) plus the documented CLI contract, driven by
# tests/regression.py.  Run with `ctest --test-dir build` or directly:
# `python3 tests/regression.py ./build/messagetag`.
include(CTest)
if(BUILD_TESTING)
    find_package(Python3 COMPONENTS Interpreter)
    if(Python3_Interpreter_FOUND)
        add_test(NAME regression
                 COMMAND "${Python3_EXECUTABLE}"
                         "${CMAKE_CURRENT_SOURCE_DIR}/tests/regression.py"
                         "$<TARGET_FILE:messagetag>")
    else()
        message(WARNING
            "Python 3 interpreter not found; the 'regression' test is "
            "disabled. Install Python 3 to enable it.")
    endif()
endif()
