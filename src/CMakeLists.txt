add_library(tsan SHARED
    tsan.cpp
)
target_link_libraries(tsan
    PRIVATE zipr-sdk
)
target_include_directories(tsan
    INTERFACE include
)
