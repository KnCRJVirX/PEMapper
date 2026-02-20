cmake_minimum_required(VERSION 3.20)
project(PEMapper C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 默认构建类型为 Debug
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
endif()
set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS Debug Release RelWithDebInfo MinSizeRel)

add_executable(PEMapper
    main.cpp
)

target_include_directories(PEMapper PRIVATE
    ${CMAKE_SOURCE_DIR}
)

# 链接所需的 Windows 系统库
target_link_libraries(PEMapper PRIVATE
    kernel32
    user32
    psapi
    ntdll
)

# 各构建类型专属编译选项
target_compile_options(PEMapper PRIVATE
    $<$<CONFIG:Debug>:          -g -O0 -DDEBUG>
    $<$<CONFIG:Release>:        -O2 -DNDEBUG>
    $<$<CONFIG:RelWithDebInfo>: -O2 -g -DNDEBUG>
    $<$<CONFIG:MinSizeRel>:     -Os -DNDEBUG>
)

# 各构建类型专属链接选项
target_link_options(PEMapper PRIVATE
    $<$<CONFIG:Release>:     -s>
    $<$<CONFIG:MinSizeRel>:  -s>
)

# dlltest.dll
add_library(dlltest SHARED
    dlltest.c
)
set_target_properties(dlltest PROPERTIES PREFIX "")

target_include_directories(dlltest PRIVATE
    ${CMAKE_SOURCE_DIR}
)

target_link_libraries(dlltest PRIVATE
    kernel32
    user32
)

target_compile_options(dlltest PRIVATE
    $<$<CONFIG:Debug>:          -g -O0 -DDEBUG>
    $<$<CONFIG:Release>:        -O2 -DNDEBUG>
    $<$<CONFIG:RelWithDebInfo>: -O2 -g -DNDEBUG>
    $<$<CONFIG:MinSizeRel>:     -Os -DNDEBUG>
)

target_link_options(dlltest PRIVATE
    $<$<CONFIG:Release>:     -s>
    $<$<CONFIG:MinSizeRel>:  -s>
)
