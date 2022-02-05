add_library(instructionmap SHARED
    instructionmap.cpp
    instructionmap.h
)
target_link_libraries(instructionmap
    PRIVATE zipr-sdk
    PRIVATE common
    PRIVATE protobuf-files
)
# the .zpi postfix is required by the zipr framework
set_target_properties(instructionmap PROPERTIES LIBRARY_OUTPUT_NAME "instructionmap.zpi")
set_target_properties(instructionmap PROPERTIES PREFIX "")
set_target_properties(instructionmap PROPERTIES SUFFIX "")
