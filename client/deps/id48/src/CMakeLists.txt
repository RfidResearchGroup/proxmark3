cmake_minimum_required(VERSION 3.21)

project(id48lib LANGUAGES C CXX ASM)

add_library(id48lib STATIC
    id48_data.c
    id48_generator.c
    id48_recover.c
)

# Compile options/warnings for C sources only (use generator expression)
target_compile_options(id48lib PRIVATE
    $<$<COMPILE_LANGUAGE:C>:-Wpedantic -Wall -Werror -O3 -Wno-unknown-pragmas -Wno-inline -Wno-unused-function>
)

# Prefer compile_definitions over embedding -D in compile options
target_compile_definitions(id48lib PRIVATE ID48_NO_STDIO)

# Private include dirs for internal headers, PUBLIC for the library API
target_include_directories(id48lib
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/id48
    PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR}/../public
)

set_property(TARGET id48lib PROPERTY POSITION_INDEPENDENT_CODE ON)
