cmake_minimum_required(VERSION 3.11.0)
project(binary-tsan)
enable_testing()
set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")
include(CheckCXXCompilerFlag)
CHECK_CXX_COMPILER_FLAG(-std=c++17 HAVE_C17)
if (NOT HAVE_C17)
    message(FATAL_ERROR "Your compiler does not understand -std=c++17, consider updating your compiler")
endif()
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall")
SET(CMAKE_CXX_STANDARD 17)
SET(CMAKE_CXX_STANDARD_REQUIRED YES)
SET(CMAKE_CXX_EXTENSIONS ON)

if(NOT CMAKE_BUILD_TYPE)
    message(STATUS "Setting build type to Release")
    set(CMAKE_BUILD_TYPE "Release")
endif()

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/ps-plugin)

add_subdirectory(src)

# create libraries for zipr and irdb sdks
set(IRDBLIB_LOCATION "/home/andi/Masterarbeit/zipr/irdb-libs/lib/")

add_library(_irdb-sdk SHARED IMPORTED)
target_include_directories(_irdb-sdk INTERFACE "irdb-sdk/include/")
# just select a library
set_property(TARGET _irdb-sdk PROPERTY IMPORTED_LOCATION
    "${IRDBLIB_LOCATION}/libirdb-core.so"
)
set_property(TARGET _irdb-sdk PROPERTY INTERFACE_LINK_LIBRARIES
    "${IRDBLIB_LOCATION}/libirdb-core.so"
    "${IRDBLIB_LOCATION}/libirdb-cfg.so"
    "${IRDBLIB_LOCATION}/libirdb-deep.so"
    "${IRDBLIB_LOCATION}/libirdb-elfdep.so"
    "${IRDBLIB_LOCATION}/libirdb-syscall.so"
    "${IRDBLIB_LOCATION}/libirdb-transform.so"
    "${IRDBLIB_LOCATION}/libirdb-util.so"
)

add_library(irdb-sdk INTERFACE)
target_link_libraries(irdb-sdk
    INTERFACE _irdb-sdk
)
