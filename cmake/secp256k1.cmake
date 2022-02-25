# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/FindMbedTLS.cmake)
if("sgx" IN_LIST COMPILE_TARGETS)
  add_library(
    secp256k1.enclave STATIC ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/secp256k1/src/secp256k1.c
  )
  target_include_directories(
    secp256k1.enclave PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/secp256k1>
                             $<INSTALL_INTERFACE:include/3rdparty/secp256k1>
  )
  target_compile_options(
    secp256k1.enclave PRIVATE -fvisibility=hidden -nostdinc
  )
  target_compile_definitions(
    secp256k1.enclave PRIVATE HAVE_CONFIG_H SECP256K1_BUILD
  )
  target_link_libraries(secp256k1.enclave PRIVATE ${OE_TARGET_LIBC})
  set_property(TARGET secp256k1.enclave PROPERTY POSITION_INDEPENDENT_CODE ON)
endif()

add_library(secp256k1.host STATIC ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/secp256k1/src/secp256k1.c)
# Can't add_san to this library, doing so causes a compile error on
# field_*_asm_impl.h: inline assembly requires more registers than available
target_include_directories(
  secp256k1.host PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/secp256k1>
                        $<INSTALL_INTERFACE:include/3rdparty/secp256k1>
)
target_compile_options(secp256k1.host PRIVATE -fvisibility=hidden)
target_compile_definitions(secp256k1.host PRIVATE HAVE_CONFIG_H SECP256K1_BUILD)
set_property(TARGET secp256k1.host PROPERTY POSITION_INDEPENDENT_CODE ON)

target_include_directories(secp256k1.host PRIVATE ${MBEDTLS_INCLUDE_DIRS})
target_link_libraries(secp256k1.host PRIVATE ${MBEDTLS_LIBRARIES})