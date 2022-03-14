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

target_compile_options(interception INTERFACE -Wall -W -Wno-unused-parameter -Wwrite-strings -pedantic -Wno-long-long  -fPIC -fno-builtin -fno-exceptions -fno-rtti -fomit-frame-pointer -funwind-tables -fvisibility=hidden -Wno-variadic-macros)


target_include_directories(interception PUBLIC ..)
