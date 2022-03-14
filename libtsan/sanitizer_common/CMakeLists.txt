# Build system for the common Sanitizer runtime support library components.
# These components are shared between AddressSanitizer and ThreadSanitizer.

add_library(sanitizer_common STATIC
    sancov_flags.cpp
	sanitizer_allocator.cpp
	sanitizer_allocator_checks.cpp
	sanitizer_allocator_report.cpp
	sanitizer_common.cpp
	sanitizer_common_libcdep.cpp
	sanitizer_coverage_libcdep_new.cpp
	sanitizer_deadlock_detector1.cpp
	sanitizer_deadlock_detector2.cpp
	sanitizer_errno.cpp
	sanitizer_file.cpp
	sanitizer_flags.cpp
	sanitizer_flag_parser.cpp
	sanitizer_libc.cpp
	sanitizer_libignore.cpp
	sanitizer_linux.cpp
	sanitizer_linux_libcdep.cpp
	sanitizer_linux_s390.cpp
	sanitizer_mac.cpp
	sanitizer_mac_libcdep.cpp
	sanitizer_netbsd.cpp
	sanitizer_openbsd.cpp
	sanitizer_persistent_allocator.cpp
	sanitizer_platform_limits_freebsd.cpp
	sanitizer_platform_limits_linux.cpp
	sanitizer_platform_limits_openbsd.cpp
	sanitizer_platform_limits_posix.cpp
	sanitizer_platform_limits_solaris.cpp
	sanitizer_posix.cpp
	sanitizer_posix_libcdep.cpp
	sanitizer_printf.cpp
	sanitizer_procmaps_bsd.cpp
	sanitizer_procmaps_common.cpp
	sanitizer_procmaps_linux.cpp
	sanitizer_procmaps_mac.cpp
	sanitizer_procmaps_solaris.cpp
	sanitizer_rtems.cpp
	sanitizer_solaris.cpp
	sanitizer_stackdepot.cpp
	sanitizer_stacktrace.cpp
	sanitizer_stacktrace_libcdep.cpp
	sanitizer_stacktrace_sparc.cpp
	sanitizer_symbolizer_mac.cpp
	sanitizer_symbolizer_report.cpp
	sanitizer_stacktrace_printer.cpp
	sanitizer_stoptheworld_linux_libcdep.cpp
	sanitizer_stoptheworld_mac.cpp
	sanitizer_suppressions.cpp
	sanitizer_symbolizer.cpp
	sanitizer_symbolizer_libbacktrace.cpp
	sanitizer_symbolizer_libcdep.cpp
	sanitizer_symbolizer_posix_libcdep.cpp
	sanitizer_symbolizer_win.cpp
	sanitizer_termination.cpp
	sanitizer_thread_registry.cpp
	sanitizer_tls_get_addr.cpp
	sanitizer_unwind_linux_libcdep.cpp
	sanitizer_unwind_win.cpp
	sanitizer_win.cpp
)

target_compile_options(sanitizer_common INTERFACE -Wall -W -Wno-unused-parameter -Wwrite-strings -pedantic -Wno-long-long  -fPIC -fno-builtin -fno-exceptions -fno-rtti -fomit-frame-pointer -funwind-tables -fvisibility=hidden -Wno-variadic-macros)


set_property(TARGET sanitizer_common PROPERTY POSITION_INDEPENDENT_CODE ON)

target_include_directories(sanitizer_common PUBLIC ..)
