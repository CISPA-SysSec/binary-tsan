add_executable(tsan
    tsan.cpp
    tsantransform.cpp
    tsantransform.h
    cfgtodot.cpp
    cfgtodot.h
    deadregisteranalysis.cpp
    deadregisteranalysis.h
    pointeranalysis.cpp
    pointeranalysis.h
    fixedpointanalysis.cpp
    fixedpointanalysis.h
    analysis.cpp
    analysis.h
    register.cpp
    register.h
    exceptionhandling.cpp
    exceptionhandling.h
    annotations.cpp
    annotations.h
)
target_link_libraries(tsan
    PRIVATE irdb-sdk
    PRIVATE common
    PRIVATE protobuf-files
)
# the .exe postfix is required by the zipr framework
set_target_properties(tsan PROPERTIES OUTPUT_NAME "tsan.exe")

add_compile_definitions(LIBTSANLOCATION=\"${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/liblibtsan.so\")
