
if (NOT TARGET ccf)
    find_package(ccf REQUIRED)
endif()
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/3rdparty)
include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR}/src)
include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR}/include)
add_ccf_app(cloak 
    SRCS
    ${CMAKE_CURRENT_SOURCE_DIR}/src/app/cloak_for_ccf.cpp
    INCLUDE_DIRS
    ${OpenEnclave_DIR}/../../include/3rdparty  

    LINK_LIBS_ENCLAVE eevm.enclave  
    LINK_LIBS_VIRTUAL eevm.host INSTALL_LIBS ON
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
