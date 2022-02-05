add_library(protobuf-files SHARED)

set(PROTO_FILES
    instrumentationmap.proto
)
protobuf_generate_cpp(PROTO_SOURCES PROTO_HEADERS ${PROTO_FILES})

target_sources(protobuf-files PRIVATE ${PROTO_SOURCES} ${PROTO_HEADERS} ${PROTO_FILES})

# disable warnings for generated files
target_compile_options(protobuf-files PUBLIC -w)

target_link_libraries(protobuf-files
    PUBLIC ${Protobuf_LIBRARIES}
)
target_include_directories(protobuf-files
    PUBLIC ${CMAKE_CURRENT_BINARY_DIR}/..
)
target_include_directories(protobuf-files SYSTEM
    PUBLIC ${PROTOBUF_INCLUDE_DIR}
    PRIVATE ${PROTOBUF_INCLUDE_DIR}
)
