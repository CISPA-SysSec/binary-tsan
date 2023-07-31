cmake_minimum_required(VERSION 3.11.0)
project(binary-tsan CXX ASM)
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

set(PLUGIN_PATH ${CMAKE_BINARY_DIR}/ps-plugin)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PLUGIN_PATH})

set(ZIPR_PLUGIN_PATH ${CMAKE_BINARY_DIR}/zipr-plugin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${ZIPR_PLUGIN_PATH})

if(NOT ZIPR_LOCATION)
    message(FATAL_ERROR "Please provide a valid zipr location")
endif()

# configure scripts
set(TSAN_SCRIPT ${CMAKE_BINARY_DIR}/thread-sanitizer.sh)
configure_file(${CMAKE_SOURCE_DIR}/scripts/thread-sanitizer.sh.in ${TSAN_SCRIPT} @ONLY)

# create libraries for the irdb sdk
set(IRDBLIB_LOCATION "${ZIPR_LOCATION}/irdb-libs/lib/")

add_library(_irdb-sdk SHARED IMPORTED)
target_include_directories(_irdb-sdk INTERFACE "${ZIPR_LOCATION}/irdb-sdk/include/")
target_include_directories(_irdb-sdk INTERFACE "${ZIPR_LOCATION}/irdb-libs/third_party/capstone/include/")
# just select a library
set_property(TARGET _irdb-sdk PROPERTY IMPORTED_LOCATION
    "${IRDBLIB_LOCATION}/${CMAKE_SHARED_LIBRARY_PREFIX}irdb-core${CMAKE_SHARED_LIBRARY_SUFFIX}"
)
set_property(TARGET _irdb-sdk PROPERTY INTERFACE_LINK_LIBRARIES
    "${IRDBLIB_LOCATION}/${CMAKE_SHARED_LIBRARY_PREFIX}irdb-core${CMAKE_SHARED_LIBRARY_SUFFIX}"
    "${IRDBLIB_LOCATION}/${CMAKE_SHARED_LIBRARY_PREFIX}irdb-cfg${CMAKE_SHARED_LIBRARY_SUFFIX}"
    "${IRDBLIB_LOCATION}/${CMAKE_SHARED_LIBRARY_PREFIX}irdb-deep${CMAKE_SHARED_LIBRARY_SUFFIX}"
    "${IRDBLIB_LOCATION}/${CMAKE_SHARED_LIBRARY_PREFIX}irdb-elfdep${CMAKE_SHARED_LIBRARY_SUFFIX}"
    "${IRDBLIB_LOCATION}/${CMAKE_SHARED_LIBRARY_PREFIX}irdb-syscall${CMAKE_SHARED_LIBRARY_SUFFIX}"
    "${IRDBLIB_LOCATION}/${CMAKE_SHARED_LIBRARY_PREFIX}irdb-transform${CMAKE_SHARED_LIBRARY_SUFFIX}"
    "${IRDBLIB_LOCATION}/${CMAKE_SHARED_LIBRARY_PREFIX}irdb-util${CMAKE_SHARED_LIBRARY_SUFFIX}"
    "${IRDBLIB_LOCATION}/${CMAKE_SHARED_LIBRARY_PREFIX}capstone${CMAKE_SHARED_LIBRARY_SUFFIX}"
)

add_library(irdb-sdk INTERFACE)
target_link_libraries(irdb-sdk
    INTERFACE _irdb-sdk
)

add_library(zipr-sdk INTERFACE)
target_link_libraries(zipr-sdk
    INTERFACE irdb-sdk
)
target_include_directories(zipr-sdk INTERFACE "${ZIPR_LOCATION}/zipr-sdk/include/")

# TODO: make it optional and disable the necessary code if not found
find_package(Protobuf 3.3.0 REQUIRED)

add_subdirectory(src)
add_subdirectory(libtsan)

include(GetCTestsuite)
include(GetCoreutils)
include(AddTests)
