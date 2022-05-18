add_test(NAME run-tsan-tests
	COMMAND python3 "${CMAKE_SOURCE_DIR}/scripts/run-tsan-tests.py" "./thread-sanitizer.sh" "tsan-test-output/"
	WORKING_DIRECTORY "${CMAKE_BUILD_DIRECTORY}")

add_test(NAME c-testsuite
	COMMAND ./single-exec clang-tsan-rewrite
	WORKING_DIRECTORY "${C_TESTSUITE_DIRECTORY}")

# show what went wrong by default
add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
    USES_TERMINAL)

add_dependencies(check tsan translate-stacktrace libtsan project_c_testsuite) 
