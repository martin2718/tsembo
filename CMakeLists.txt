cmake_minimum_required(VERSION 3.16)
project(tsembo
    VERSION 0.1.0
    DESCRIPTION "tsembo"
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(TSEMBO_BUILD_TESTS "Build tests" ON)

add_subdirectory(src)

if(TSEMBO_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
