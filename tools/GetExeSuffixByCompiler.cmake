function(get_exe_suffix OUTPUT_VAR GCC_COMPILER)
    set(TEST_SRC ${CMAKE_CURRENT_BINARY_DIR}/detect_suffix.c)
    set(TEST_EXE ${CMAKE_CURRENT_BINARY_DIR}/detect_suffix)

    file(WRITE ${TEST_SRC} "int main(){return 0;}\n")

    execute_process(
            COMMAND ${GCC_COMPILER} ${TEST_SRC} -o ${TEST_EXE}
            RESULT_VARIABLE RES
    )

    if (EXISTS "${TEST_EXE}.exe")
        set(${OUTPUT_VAR} ".exe" PARENT_SCOPE)
    else ()
        set(${OUTPUT_VAR} "" PARENT_SCOPE)
    endif ()

    # Clear
    file(REMOVE ${TEST_SRC} ${TEST_EXE} ${TEST_EXE}.exe ${TEST_EXE}.o)
endfunction()

# Usage:
#  get_exe_suffix(${C_COMPILER_HOST} DETECTED_SUFFIX)
#  message(STATUS "Detected suffix: '${DETECTED_SUFFIX}'")
