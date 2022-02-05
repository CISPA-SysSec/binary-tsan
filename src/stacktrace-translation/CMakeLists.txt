add_executable(translate-stacktrace
    stacktracetranslation.cpp
)
target_link_libraries(translate-stacktrace
    PRIVATE common
    PRIVATE protobuf-files
)
