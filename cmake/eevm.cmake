option(RECORD_TRACE "Record a detailed trace of EVM execution when transaction fails" OFF)
if(RECORD_TRACE)
  add_definitions(-DRECORD_TRACE)
endif(RECORD_TRACE)

set(EVM_3RD_PARTY_INTERNAL_DIR "${EVM_DIR}/3rdparty/internal")

file(GLOB KECCAK_SRC ${EVM_3RD_PARTY_INTERNAL_DIR}/keccak/*.c)
include_directories(SYSTEM ${EVM_3RD_PARTY_INTERNAL_DIR})

enable_language(ASM)

add_subdirectory(${EVM_3RD_PARTY_INTERNAL_DIR})
set(EEVM_SRC
    ${EVM_DIR}/src/disassembler.cpp
    ${EVM_DIR}/src/stack.cpp
    ${EVM_DIR}/src/transaction.cpp
    ${EVM_DIR}/src/util.cpp
    ${EVM_DIR}/src/processor.cpp
)

if("sgx" IN_LIST COMPILE_TARGETS)
    add_enclave_library_c(eevm.enclave ${EEVM_SRC} ${KECCAK_SRC})
    target_include_directories(eevm.enclave PRIVATE ${EVM_DIR}/include)
    target_link_libraries(eevm.enclave PUBLIC intx::intx)
endif()

add_host_library(eevm.host STATIC ${EEVM_SRC} ${KECCAK_SRC})
target_include_directories(eevm.host PRIVATE ${EVM_DIR}/include)
target_link_libraries(eevm.host PUBLIC intx::intx)

