option(RECORD_TRACE "Record a detailed trace of EVM execution when transaction fails" OFF)
if(RECORD_TRACE)
  add_definitions(-DRECORD_TRACE)
endif(RECORD_TRACE)

set(EVM_3RD_PARTY_INTERNAL_DIR "${EVM_DIR}/3rdparty/internal")

file(GLOB KECCAK_SRC ${EVM_3RD_PARTY_INTERNAL_DIR}/keccak/*.c)
include_directories(SYSTEM ${EVM_3RD_PARTY_INTERNAL_DIR} ${EVM_3RD_PARTY_INTERNAL_DIR}/intx/include)
set(INTX_SRC
    ${EVM_3RD_PARTY_INTERNAL_DIR}/intx/lib/intx/div.cpp
    ${EVM_3RD_PARTY_INTERNAL_DIR}/intx/lib/intx/div.hpp
)
enable_language(ASM)

set(EEVM_SRC
    ${EVM_DIR}/src/disassembler.cpp
    ${EVM_DIR}/src/stack.cpp
    ${EVM_DIR}/src/transaction.cpp
    ${EVM_DIR}/src/util.cpp
    ${EVM_DIR}/src/processor.cpp
    ${EVM_DIR}/src/keccak256.cpp
)

if("sgx" IN_LIST COMPILE_TARGETS)
    add_enclave_library_c(eevm.enclave ${EEVM_SRC} ${KECCAK_SRC} ${INTX_SRC})
    target_include_directories(eevm.enclave PRIVATE ${EVM_DIR}/include)
endif()

add_host_library(eevm.host STATIC ${EEVM_SRC} ${KECCAK_SRC} ${INTX_SRC})
target_include_directories(eevm.host PRIVATE ${EVM_DIR}/include )
