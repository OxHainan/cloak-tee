include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/secp256k1.cmake)

if (NOT TARGET ccf)
    find_package(ccf REQUIRED)
endif()


add_ccf_app(cloak 
    SRCS
    ${CMAKE_CURRENT_SOURCE_DIR}/src/app/cloak_for_ccf.cpp
    ${EEVM_SRC} 
    INCLUDE_DIRS
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${OpenEnclave_DIR}/../../include/3rdparty
    ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${EVM_DIR}/include
    ${EVM_DIR}/3rdparty

    LINK_LIBS_ENCLAVE keccak.enclave secp256k1.enclave intx::intx
    LINK_LIBS_VIRTUAL keccak.host secp256k1.host intx::intx INSTALL_LIBS ON
)

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/signning_key.pem
    COMMAND openssl genrsa -out ${CMAKE_CURRENT_BINARY_DIR}/signning_key.pem -3 3072
)

add_custom_target(
    cloak_signning_key ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/signning_key.pem
)

sign_app_library(
    cloak.enclave ${CMAKE_CURRENT_SOURCE_DIR}/src/app/oe_sign.conf
    ${CMAKE_CURRENT_BINARY_DIR}/signning_key.pem
)
