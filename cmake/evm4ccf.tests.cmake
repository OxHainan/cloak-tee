
list(APPEND LINK_LIBCXX -lc++ -lc++abi -lc++fs -stdlib=libc++)

function(add_uint_test name)
  add_executable(${name} ${ARGN})
  target_compile_options(${name} PRIVATE -stdlib=libc++)
  enable_coverage(${name})
  target_link_libraries(
    ${name}
    PRIVATE
    ${LINK_LIBCXX}
    keccak_host
    # keccak_enclave
    intx::intx
    evm4ccf.virtual
  )
  target_include_directories(${name} 
    PRIVATE
    /opt/openenclave/include
    ${CMAKE_CURRENT_LIST_DIR}/../include
    ${EVM_DIR}/include
    ${CCF_DIR}/include/3rdparty
    ${CCF_DIR}/include/ccf
    ${OE_LIBCXX_INCLUDE_DIR}
    ${OE_LIBC_INCLUDE_DIR}
    ${OE_INCLUDE_DIR}
    ${EVM_DIR}/3rdparty
    ${EVM_DIR}/3rdparty/intx
    ${EVM_DIR}/3rdparty/doctest
  )
  use_client_mbedtls(${name})
  add_san(${name})

  add_test(NAME ${name} 
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/unit_test_wrapper.sh ${name}
  )
  set_property(
    TEST ${name}
    APPEND
    PROPERTY LABELS unit_test
  )
endfunction()


if (test)
  file(GLOB TESTS_DIR ${CMAKE_CURRENT_LIST_DIR}/../tests/*.cpp*)
  foreach(FILE_PATH ${TESTS_DIR})
    STRING(REGEX REPLACE ".+/(.+)\\..*" "\\1" FILE_NAME ${FILE_PATH})
    add_uint_test(${FILE_NAME} ${FILE_PATH})
  endforeach(FILE_PATH)
endif()