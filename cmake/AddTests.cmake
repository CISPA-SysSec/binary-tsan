add_test(NAME run-tsan-tests
	COMMAND python3 "${CMAKE_SOURCE_DIR}/scripts/run-tsan-tests.py" "./thread-sanitizer.sh" "tsan-test-output/"
	WORKING_DIRECTORY "${CMAKE_BINARY_DIR}")

# add_test(NAME coreutils-instrument-and-run
# 	COMMAND bash -c "${CMAKE_SOURCE_DIR}/scripts/instrument-all.sh ${CMAKE_BINARY_DIR}/thread-sanitizer.sh ${COREUTILS_DIRECTORY}/src && cd ${COREUTILS_DIRECTORY} && make SUBDIRS=. check"
# 	WORKING_DIRECTORY "${COREUTILS_INSTRUMENT_FOLDER}")

if(HAVE_C_TESTSUITE)
    add_test(NAME c-testsuite
        COMMAND ./single-exec clang-tsan-rewrite
        WORKING_DIRECTORY "${C_TESTSUITE_DIRECTORY}")
endif()

# show what went wrong by default
add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
    USES_TERMINAL)

add_dependencies(check tsan translate-stacktrace libtsan project_c_testsuite project_coreutils)
