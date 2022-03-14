SET(CMAKE_ASM_FLAGS "${CFLAGS} -x assembler-with-cpp")

add_library(libtsan SHARED
    tsan_clock.cpp
	tsan_debugging.cpp
	tsan_external.cpp
	tsan_fd.cpp
	tsan_flags.cpp
	tsan_ignoreset.cpp
	tsan_interceptors_posix.cpp
	tsan_interceptors_mac.cpp
	tsan_interface_ann.cpp
	tsan_interface_atomic.cpp
	tsan_interface.cpp
	tsan_interface_java.cpp
	tsan_malloc_mac.cpp
	tsan_md5.cpp
	tsan_mman.cpp
	tsan_mutex.cpp
	tsan_mutexset.cpp
	tsan_new_delete.cpp
	tsan_platform_linux.cpp
	tsan_platform_mac.cpp
	tsan_platform_posix.cpp
	tsan_platform_windows.cpp
	tsan_report.cpp
	tsan_rtl.cpp
	tsan_rtl_mutex.cpp
	tsan_rtl_proc.cpp
	tsan_rtl_report.cpp
	tsan_rtl_thread.cpp
	tsan_stack_trace.cpp
	tsan_stat.cpp
	tsan_suppressions.cpp
	tsan_symbolize.cpp
	tsan_sync.cpp 
    
    tsan_rtl_amd64.S
)

set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
set(THREADS_PREFER_PTHREAD_FLAG TRUE)
find_package(Threads REQUIRED)

target_link_libraries(libtsan
    PRIVATE interception
    PRIVATE sanitizer_common
    PUBLIC Threads::Threads
)

target_compile_options(libtsan INTERFACE -Wall -W -Wno-unused-parameter -Wwrite-strings -pedantic -Wno-long-long  -fPIC -fno-builtin -fno-exceptions -fno-rtti -fomit-frame-pointer -funwind-tables -fvisibility=hidden -Wno-variadic-macros)
