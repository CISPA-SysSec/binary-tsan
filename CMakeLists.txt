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
add_library(irdb-sdk INTERFACE)
target_include_directories(irdb-sdk INTERFACE "irdb-sdk/include/")

add_library(zipr-sdk INTERFACE)
target_link_libraries(zipr-sdk
    INTERFACE irdb-sdk
)
target_include_directories(zipr-sdk INTERFACE "zipr-sdk/include/")
