cmake_minimum_required(VERSION 3.21)

project(id48_project LANGUAGES C CXX ASM)

# Project-wide language standards (subdirectories inherit if not overridden)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_subdirectory(src)
add_subdirectory(tests)

