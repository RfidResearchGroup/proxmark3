cmake_minimum_required(VERSION 3.20)

# Option to build the firmware for the Proxmark3/5. This will include the armsrc and bootrom directories.
option(BUILD_FIRMWARE "Build the firmware for the Proxmark3/5" ON)

# If building for pm3 device, not client, the compiler will be arm-none-eabi-gcc, so the test program will not compile.
# This is a workaround to prevent CMake from trying to compile the test program,
# which will fail because the compiler is not for the host system.
if (BUILD_FIRMWARE)
    include(${CMAKE_CURRENT_SOURCE_DIR}/tools/FixCompileTest.cmake)
    include(${CMAKE_CURRENT_SOURCE_DIR}/tools/ToolchainForArm.cmake)
endif ()

# Project name and languages
project(Proxmark3 C CXX ASM)

# add subdirectories, which will contain their own CMakeLists.txt files
if (BUILD_FIRMWARE)
    add_subdirectory(armsrc)
    add_subdirectory(bootrom)
else ()
    add_subdirectory(client)
endif ()
