cmake_minimum_required(VERSION 3.11)


add_definitions(-DOE_API_VERSION=2)
set(CMAKE_CXX_STANDARD 17)

# Paths to dependencies - currently explicit
set(CCF_DIR "/opt/ccf-0.15.2" CACHE PATH "Path to CCF install")
set(EVM_DIR ${CMAKE_CURRENT_SOURCE_DIR}/eEVM)


include(${CCF_DIR}/cmake/preproject.cmake)

project(evm-for-ccf 
  LANGUAGES C CXX
  )

include(${CCF_DIR}/cmake/tools.cmake)
include(${CCF_DIR}/cmake/ccf.cmake)
include(${CCF_DIR}/cmake/ccf_app.cmake)


add_subdirectory(${EVM_DIR}/3rdparty)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/tests/setup_env.sh ${CMAKE_CURRENT_BINARY_DIR}/tests.sh COPYONLY)

option(RECORD_TRACE "Record a detailed trace of EVM execution when transaction fails" OFF)
if(RECORD_TRACE)
  add_definitions(-DRECORD_TRACE)
endif(RECORD_TRACE)

option(CLOAK_DEBUG_LOGGING "Enable cloak debug logging" OFF)
if(CLOAK_DEBUG_LOGGING)
    add_compile_definitions(CLOAK_DEBUG_LOGGING)
endif()

include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/evm4ccf.app.cmake)
