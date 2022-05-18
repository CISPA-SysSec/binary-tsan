include(ExternalProject)

set(TESTSUITE_PATCH_FILE ${CMAKE_BINARY_DIR}/c-testsuite.patch)
configure_file(${CMAKE_SOURCE_DIR}/cmake/c-testsuite.patch.in ${TESTSUITE_PATCH_FILE} @ONLY)

find_program(TMSU_LOCATION NAMES tmsu)

if(TMSU_LOCATION)

    set(HAVE_C_TESTSUITE TRUE)

    ExternalProject_Add(project_c_testsuite
        GIT_REPOSITORY https://github.com/c-testsuite/c-testsuite.git
        GIT_TAG 5c7275656d751de0e68b2d340a95b5681858ed07
        PATCH_COMMAND cat ${TESTSUITE_PATCH_FILE} | patch -p1
        BUILD_IN_SOURCE TRUE
        CONFIGURE_COMMAND tmsu init && ./scripts/make-search-index
        BUILD_COMMAND ""
        INSTALL_COMMAND ""
    )

    externalproject_get_property(project_c_testsuite source_dir)
    set(C_TESTSUITE_DIRECTORY ${source_dir})
    set_target_properties(project_c_testsuite PROPERTIES EXCLUDE_FROM_ALL true)

else()

    message("tmsu is not installed, c-testsuite will be run")

    set(HAVE_C_TESTSUITE FALSE)

    add_custom_target(project_c_testsuite)

endif()
