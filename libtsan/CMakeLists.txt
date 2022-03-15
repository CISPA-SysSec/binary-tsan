set(LIBTSAN_COMPILER_FLAGS -Wall -W -Wno-unused-parameter -Wwrite-strings -pedantic -Wno-long-long  -fPIC -fno-builtin -fno-exceptions -fno-rtti -fomit-frame-pointer -funwind-tables -fvisibility=hidden -Wno-variadic-macros)

add_subdirectory(tsan)
add_subdirectory(interception)
add_subdirectory(sanitizer_common)
