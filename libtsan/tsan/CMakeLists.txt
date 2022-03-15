SET(CMAKE_ASM_FLAGS "${CFLAGS} -x assembler-with-cpp")

add_library(libtsan-nosse STATIC
    tsan_rtl.cpp

    tsan_rtl.h
)

target_link_libraries(libtsan-nosse
    PRIVATE interception
    PRIVATE sanitizer_common
)

set_property(TARGET libtsan-nosse PROPERTY POSITION_INDEPENDENT_CODE ON)

target_compile_options(libtsan-nosse
    PRIVATE -mno-sse
    INTERFACE ${LIBTSAN_COMPILER_FLAGS}
)

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
	tsan_stack_trace.cpp
	tsan_stat.cpp
	tsan_suppressions.cpp
	tsan_symbolize.cpp
    tsan_sync.cpp
    tsan_rtl_mutex.cpp
    tsan_rtl_proc.cpp
    tsan_rtl_report.cpp
    tsan_rtl_thread.cpp

    tsan_clock.h
    tsan_defs.h
    tsan_dense_alloc.h
    tsan_dispatch_defs.h
    tsan_fd.h
    tsan_flags.h
    tsan_ignoreset.h
    tsan_interceptors.h
    tsan_interface_ann.h
    tsan_interface_inl.h
    tsan_interface_java.h
    tsan_interface.h
    tsan_mman.h
    tsan_mutex.h
    tsan_mutexset.h
    tsan_platform.h
    tsan_ppc_regs.h
    tsan_report.h
    tsan_stack_trace.h
    tsan_stat.h
    tsan_suppressions.h
    tsan_symbolize.h
    tsan_sync.h
    tsan_trace.h
    tsan_update_shadow_word_inl.h
    tsan_flags.inc
    
    tsan_rtl_amd64.S
)

target_link_libraries(libtsan
    PRIVATE interception
    PRIVATE sanitizer_common
    PRIVATE libtsan-nosse
)

target_compile_options(libtsan INTERFACE ${LIBTSAN_COMPILER_FLAGS})
