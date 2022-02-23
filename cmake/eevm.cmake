option(RECORD_TRACE "Record a detailed trace of EVM execution when transaction fails" OFF)
if(RECORD_TRACE)
  add_definitions(-DRECORD_TRACE)
endif(RECORD_TRACE)

add_subdirectory(${EVM_DIR}/3rdparty)

file(GLOB KECCAK_SRC 
    ${EVM_DIR}/3rdparty/keccak/*.c
)
enable_language(ASM)
add_enclave_library_c(keccak.enclave "${KECCAK_SRC}")

add_host_library(keccak.host "${KECCAK_SRC}")

set(EEVM_SRC
    ${EVM_DIR}/src/disassembler.cpp
    ${EVM_DIR}/src/stack.cpp
    ${EVM_DIR}/src/transaction.cpp
    ${EVM_DIR}/src/util.cpp
    ${EVM_DIR}/src/processor.cpp
)

if("sgx" IN_LIST COMPILE_TARGETS)
    add_enclave_library_c(
        eevm.enclave ${EEVM_SRC} ${KECCAK_SRC}
    )
    target_include_directories(eevm.enclave PRIVATE 
        ${EVM_DIR}/3rdparty
        ${EVM_DIR}/include
    )
    target_link_libraries(eevm.enclave PUBLIC intx::intx)
endif()

add_host_library(eevm.host STATIC ${EEVM_SRC} ${KECCAK_SRC})
target_include_directories(eevm.host PRIVATE
    ${EVM_DIR}/3rdparty
    ${EVM_DIR}/include
)
target_link_libraries(eevm.host PUBLIC intx::intx)

