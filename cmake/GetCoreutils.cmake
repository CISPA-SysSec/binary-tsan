include(ExternalProject)

set(COREUTILS_INSTRUMENT_FOLDER ${CMAKE_BINARY_DIR}/coreutils-instrumented)
file(MAKE_DIRECTORY ${COREUTILS_INSTRUMENT_FOLDER})

set(COREUTILS_PATCH_FILE ${CMAKE_BINARY_DIR}/coreutils.patch)
configure_file(${CMAKE_SOURCE_DIR}/cmake/coreutils.patch.in ${COREUTILS_PATCH_FILE} @ONLY)


ExternalProject_Add(project_coreutils
    URL https://ftp.wrz.de/pub/gnu/coreutils/coreutils-9.1.tar.xz
    PATCH_COMMAND cat ${COREUTILS_PATCH_FILE} | patch -p1
    BUILD_IN_SOURCE TRUE
    CONFIGURE_COMMAND "./configure"
    INSTALL_COMMAND ""
)

externalproject_get_property(project_coreutils source_dir)
set(COREUTILS_DIRECTORY ${source_dir})
set_target_properties(project_coreutils PROPERTIES EXCLUDE_FROM_ALL true)
