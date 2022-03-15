# Build for the runtime interception helper library.

add_library(interception STATIC
    interception_linux.cpp
    interception_mac.cpp
    interception_win.cpp
    interception_type_test.cpp

    interception.h
    interception_linux.h
    interception_mac.h
    interception_win.h
)

set_property(TARGET interception PROPERTY POSITION_INDEPENDENT_CODE ON)

target_compile_options(interception INTERFACE ${LIBTSAN_COMPILER_FLAGS})


target_include_directories(interception PUBLIC ..)
