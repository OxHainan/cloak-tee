# This is not standalone - it expects to be included with options and variables configured

include_directories(
  ${CCF_DIR}/include/3rdparty
  ${CCF_DIR}/include/ccf
  )

include_directories(
  ${EVM_DIR}/3rdparty
  )

# Build Keccak library for use inside the enclave
file(GLOB KECCAK_SOURCES
    ${EVM_DIR}/3rdparty/keccak/*.c
  )
enable_language(ASM)
add_enclave_library_c(keccak_enclave "${KECCAK_SOURCES}")

add_library(keccak_host SHARED "${KECCAK_SOURCES}")


# Build eEVM library for use inside the enclave
set(EVM_CPP_FILES
  ${EVM_DIR}/src/disassembler.cpp
  ${EVM_DIR}/src/stack.cpp
  ${EVM_DIR}/src/transaction.cpp
  ${EVM_DIR}/src/util.cpp
  ${EVM_DIR}/src/processor.cpp
  )

# add_library(enclave_evm STATIC
#   ${EVM_CPP_FILES})
# target_include_directories(enclave_evm SYSTEM PRIVATE
#   ${OE_LIBCXX_INCLUDE_DIR}
#   ${OE_LIBC_INCLUDE_DIR}
#   ${EVM_DIR}/include
#   ${EVM_DIR}/3rdparty
#   )
# target_link_libraries(enclave_evm PRIVATE
#   intx::intx
#   )
# # target_compile_options(enclave_evm PRIVATE
# #   -U__linux__
# # )
# set_property(TARGET enclave_evm PROPERTY POSITION_INDEPENDENT_CODE ON)

set(EVM4CCF_FILE
  ${CMAKE_CURRENT_LIST_DIR}/../src/app/evm_for_ccf.cpp
  ${CMAKE_CURRENT_LIST_DIR}/../src/app/workerqueue.cpp

)
# Build app
add_ccf_app(evm4ccf
  SRCS
    ${EVM4CCF_FILE}
    ${EVM_CPP_FILES}
  INCLUDE_DIRS
    ${CMAKE_CURRENT_LIST_DIR}/../include
    ${EVM_DIR}/include
  LINK_LIBS_ENCLAVE
    intx::intx
    keccak_enclave
  LINK_LIBS_VIRTUAL
    intx::intx
    keccak_host
)

# Generate an ephemeral signing key
add_custom_command(
  OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/signing_key.pem
  COMMAND openssl genrsa -out ${CMAKE_CURRENT_BINARY_DIR}/signing_key.pem -3 3072
)

add_custom_target(
  signing_key ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/signing_key.pem
)

# Sign the application
sign_app_library(evm4ccf.enclave
  ${CMAKE_CURRENT_LIST_DIR}/../src/app/oe_sign.conf
  ${CMAKE_CURRENT_BINARY_DIR}/signing_key.pem
)

add_executable(main  ${CMAKE_CURRENT_LIST_DIR}/../src/app/main.cpp)
target_compile_options(main PRIVATE -stdlib=libc++)

target_link_libraries(main
  PRIVATE
  -stdlib=libc++
      -lc++
      -lc++abi
    intx::intx
    evm4ccf.virtual
    # keccak_enclave
    keccak_host
)

target_include_directories(
  main
  SYSTEM PRIVATE
  ${CMAKE_CURRENT_LIST_DIR}/../include
  ${EVM_DIR}/include
  ${CCF_DIR}/3rdparty
  ${OE_LIBCXX_INCLUDE_DIR}
  ${OE_LIBC_INCLUDE_DIR}
  ${OE_INCLUDE_DIR}
  ${EVM_DIR}/3rdparty
  ${EVM_DIR}/3rdparty/intx
)