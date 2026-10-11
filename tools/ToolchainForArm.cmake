# If it has already been found, there is no need to search again.
if(NOT DEFINED CMAKE_C_COMPILER)
    set(TOOLCHAIN_PREFIX arm-none-eabi-)

    # 1. Find the compiler
    find_program(ARM_GCC_COMPILER   ${TOOLCHAIN_PREFIX}gcc)
    find_program(ARM_GXX_COMPILER   ${TOOLCHAIN_PREFIX}g++)
    find_program(ARM_ASM_COMPILER   ${TOOLCHAIN_PREFIX}gcc)

    # 2. Check if the core C compiler is found
    if(ARM_GCC_COMPILER)
        message(STATUS "Found ARM GCC: ${ARM_GCC_COMPILER}")

        # Set the found absolute paths (with or without .exe) directly to CMake
        set(CMAKE_C_COMPILER   ${ARM_GCC_COMPILER} CACHE PATH "C compiler")
        set(CMAKE_CXX_COMPILER ${ARM_GXX_COMPILER} CACHE PATH "CXX compiler")
        set(CMAKE_ASM_COMPILER ${ARM_ASM_COMPILER} CACHE PATH "ASM compiler")

    else()
        message(WARNING "ARM GCC (${TOOLCHAIN_PREFIX}gcc) not found in PATH!")
    endif()

endif ()