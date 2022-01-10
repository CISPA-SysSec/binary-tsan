add_library(tsan SHARED
    tsan.cpp
    tsantransform.cpp
    tsantransform.h
)
target_link_libraries(tsan
    PRIVATE zipr-sdk
)
target_include_directories(tsan
    INTERFACE include
)
