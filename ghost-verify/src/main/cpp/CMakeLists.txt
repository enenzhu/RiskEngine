cmake_minimum_required(VERSION 3.22.1)
project(ghost_verify)

add_library(ghost_verify SHARED
        ghost_native.cpp
)

find_library(log-lib log)
find_library(egl-lib EGL)
find_library(gles-lib GLESv2)
find_library(android-lib android)

target_link_libraries(ghost_verify
        ${log-lib}
        ${egl-lib}
        ${gles-lib}
        ${android-lib}
)
