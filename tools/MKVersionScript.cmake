# ------------------------------------------------------------------------
#                      Power by DXL
#
# Detect platform for run mkversion script
#
# Injection variable:
#   MKVERSION_SCRIPT_FOUND      - Is script found?
#   MKVERSION_SCRIPT            - The script full path
#   MKVERSION_SCRIPT_TYPE       - Script file type: "bat" or "sh"
#   VERSION_INFO                - Version info from mkversion.(bat|sh) --short
#   MKVERSION_AVAILABLE         - A boolean variable, tell me is script working and VERSION_INFO set.
#   MKVERSION_CMD               - The final command used to generate the source file version_pm3.c

# Only once run on setup（MKVERSION_AVAILABLE is a cached variable. Next reload will direct set and skip.）
if (DEFINED MKVERSION_AVAILABLE)
    return()
endif ()

# Setup variable and export
set(MKVERSION_SCRIPT_FOUND FALSE)
set(MKVERSION_SCRIPT "")
set(MKVERSION_SCRIPT_TYPE "")
set(VERSION_INFO "unknown")
set(MKVERSION_AVAILABLE FALSE)

# The script for platform
set(MKVERSION_CANDIDATES_BAT "${CMAKE_CURRENT_LIST_DIR}/mkversion.bat")
set(MKVERSION_CANDIDATES_SH "${CMAKE_CURRENT_LIST_DIR}/mkversion.sh")

# We are running on the Windows?
set(MKVERSION_RUN_NATIVE_WINDOWS FALSE)
execute_process(COMMAND uname OUTPUT_VARIABLE uname)
if (uname MATCHES "^MSYS" OR uname MATCHES "^MINGW" OR uname MATCHES "^Lin")
    message(STATUS "Not running on native Windows (uname is ${uname}).")
else ()
    set(MKVERSION_RUN_NATIVE_WINDOWS TRUE)
endif ()

# First setup, we can run once '--short' for mkversion script to get like 'Iceman/master/b36b61feb-dirty'
if (MKVERSION_RUN_NATIVE_WINDOWS)
    execute_process(
        COMMAND cmd /c call "${MKVERSION_CANDIDATES_BAT}" --short
        OUTPUT_VARIABLE _output
        ERROR_QUIET
        OUTPUT_STRIP_TRAILING_WHITESPACE
        WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
        RESULT_VARIABLE _result
    )
    if (${_result} EQUAL 0)
        set(MKVERSION_SCRIPT "${MKVERSION_CANDIDATES_BAT}")
        set(MKVERSION_SCRIPT_TYPE "bat")
        set(VERSION_INFO "${_output}")
        set(MKVERSION_SCRIPT_FOUND TRUE)
    endif ()
else ()
    # Is 'sh' available?
    find_program(SH_COMMAND sh)
    if (SH_COMMAND)
        execute_process(
            COMMAND "${SH_COMMAND}" "${MKVERSION_CANDIDATES_SH}" --short
            OUTPUT_VARIABLE _output
            ERROR_QUIET
            OUTPUT_STRIP_TRAILING_WHITESPACE
            WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
            RESULT_VARIABLE _result
        )
        if (${_result} EQUAL 0)
            set(MKVERSION_SCRIPT "${MKVERSION_CANDIDATES_SH}")
            set(MKVERSION_SCRIPT_TYPE "sh")
            set(VERSION_INFO "${_output}")
            set(MKVERSION_SCRIPT_FOUND TRUE)
        endif ()
    endif ()
endif ()

# Finally, the script found and version info from '--short' available?
if (MKVERSION_SCRIPT_FOUND AND NOT "${VERSION_INFO}" STREQUAL "")
    set(MKVERSION_AVAILABLE TRUE)
else ()
    set(MKVERSION_AVAILABLE FALSE)
endif ()

# Export finally cmd for generate version_pm3.c
if (MKVERSION_SCRIPT_TYPE STREQUAL "sh")  # What's shell type we are?
    set(MKVERSION_CMD ${CMAKE_COMMAND} -E env bash ${MKVERSION_SCRIPT}) # Unix/Linux/macOS: call sh
elseif (MKVERSION_SCRIPT_TYPE STREQUAL "bat")
    set(MKVERSION_CMD cmd /c ${MKVERSION_SCRIPT}) # Windows: call bat
else ()
    message(FATAL_ERROR "MKVERSION_SCRIPT_TYPE must be 'sh' or 'bat', but got '${MKVERSION_SCRIPT_TYPE}'")
endif ()

# Set variables to cached level, next reload CmakeLists.txt will skip run this subscript(MKVersionScript.cmake).
set(MKVERSION_SCRIPT_FOUND ${MKVERSION_SCRIPT_FOUND} CACHE INTERNAL "Whether a mkversion script was found")
set(MKVERSION_SCRIPT ${MKVERSION_SCRIPT} CACHE INTERNAL "Full path to the mkversion script")
set(MKVERSION_SCRIPT_TYPE ${MKVERSION_SCRIPT_TYPE} CACHE INTERNAL "Type of script: 'bat' or 'sh'")
set(VERSION_INFO ${VERSION_INFO} CACHE INTERNAL "Version info string from --short")
set(MKVERSION_AVAILABLE ${MKVERSION_AVAILABLE} CACHE INTERNAL "Whether version info is available")
set(MKVERSION_CMD ${MKVERSION_CMD} CACHE INTERNAL "Command to generate version info")

# Debug info（Optional, can enable when debuging...）
if (FALSE)
    message(STATUS "===================================================================")
    message(STATUS "MKVERSION_SCRIPT_FOUND: ${MKVERSION_SCRIPT_FOUND}")
    message(STATUS "MKVERSION_SCRIPT: ${MKVERSION_SCRIPT}")
    message(STATUS "MKVERSION_SCRIPT_TYPE: ${MKVERSION_SCRIPT_TYPE}")
    message(STATUS "VERSION_INFO: ${VERSION_INFO}")
    message(STATUS "MKVERSION_CMD: ${MKVERSION_CMD}")
    message(STATUS "===================================================================")
endif ()
