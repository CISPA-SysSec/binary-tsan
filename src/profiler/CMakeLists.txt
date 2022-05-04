add_library(profiler SHARED
    profiler.cpp
)
target_link_libraries(profiler
    PRIVATE sanitizer_common
    PRIVATE common
)
