# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set(CCFCRYPTO_SRC
    ${CCF_DIR}/src/crypto/base64.cpp
    ${CCF_DIR}/src/crypto/entropy.cpp
    ${CCF_DIR}/src/crypto/hash.cpp
    ${CCF_DIR}/src/crypto/sha256_hash.cpp
    ${CCF_DIR}/src/crypto/symmetric_key.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto/key_pair.cpp
    ${CCF_DIR}/src/crypto/rsa_key_pair.cpp
    ${CCF_DIR}/src/crypto/verifier.cpp
    ${CCF_DIR}/src/crypto/key_wrap.cpp
    ${CCF_DIR}/src/crypto/hmac.cpp
    ${CCF_DIR}/src/crypto/openssl/symmetric_key.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto/openssl/public_key.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto/openssl/key_pair.cpp
    ${CCF_DIR}/src/crypto/openssl/hash.cpp
    ${CCF_DIR}/src/crypto/openssl/rsa_public_key.cpp
    ${CCF_DIR}/src/crypto/openssl/rsa_key_pair.cpp
    ${CCF_DIR}/src/crypto/openssl/verifier.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto/secp256k1/public_key.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto/secp256k1/key_pair.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/secp256k1/src/secp256k1.c
)

if("sgx" IN_LIST COMPILE_TARGETS)
  add_enclave_library(ccfcrypto.enclave ${CCFCRYPTO_SRC})
  target_include_directories(ccfcrypto.enclave PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/secp256k1>
                             $<INSTALL_INTERFACE:include/3rdparty/secp256k1>
  )

  target_compile_definitions(
    ccfcrypto.enclave PRIVATE HAVE_CONFIG_H SECP256K1_BUILD
  )
target_link_libraries(ccfcrypto.enclave PUBLIC eevm.enclave)

endif()

add_library(ccfcrypto.host STATIC ${CCFCRYPTO_SRC})
add_san(ccfcrypto.host)
target_include_directories(
    ccfcrypto.host  PUBLIC  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/secp256k1>
                            $<INSTALL_INTERFACE:include/3rdparty/secp256k1>
)
target_compile_definitions(
    ccfcrypto.host PRIVATE HAVE_CONFIG_H SECP256K1_BUILD
)
target_compile_options(ccfcrypto.host PUBLIC ${COMPILE_LIBCXX})
target_link_options(ccfcrypto.host PUBLIC ${LINK_LIBCXX})
target_link_libraries(ccfcrypto.host PUBLIC crypto)
target_link_libraries(ccfcrypto.host PUBLIC ssl)
target_link_libraries(ccfcrypto.host PUBLIC eevm.host)
set_property(TARGET ccfcrypto.host PROPERTY POSITION_INDEPENDENT_CODE ON)
