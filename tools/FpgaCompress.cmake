if (NOT DEFINED PLATFORM)
    message(FATAL_ERROR "Include this module after PLATFORM check.")
endif ()

#[[
        Make All variables private(Exclude EXE)!!!
]]

# For get_exe_suffix function to detect the suffix of executable for current compiler, like '.exe' for Windows.
include(${CMAKE_CURRENT_LIST_DIR}/GetExeSuffixByCompiler.cmake)

set(_fc_MYINCLUDES -I${CMAKE_CURRENT_LIST_DIR}/../common_fpga)
set(_fc_MYCFLAGS -std=c99 -D_ISOC99_SOURCE)

if (PLATFORM STREQUAL PM3ICOPYX)
    set(_fc_MYDEFS -DXC3)
else ()
    set(_fc_MYDEFS)
endif ()

set(_fc_MYINCLUDES ${_fc_MYINCLUDES} -I${CMAKE_CURRENT_LIST_DIR}/../common/lz4)
set(_fc_MYCFLAGS ${_fc_MYCFLAGS} -DLZ4_MEMORY_USAGE=20 -Wno-redundant-decls -Wno-old-style-definition -Wno-missing-prototypes -Wno-missing-declarations)
set(_fc_MYSRCS ${_fc_MYSRCS}
    ${CMAKE_CURRENT_LIST_DIR}/fpga_compress/fpga_compress.c
    ${CMAKE_CURRENT_LIST_DIR}/../common/lz4/lz4hc.c
    ${CMAKE_CURRENT_LIST_DIR}/../common/lz4/lz4.c)

# The target name for fpga_compress
set(FPGA_COMPRESS fpga_compress)
get_exe_suffix(FPGA_COMPRESS_EXE_SUFFIX ${C_COMPILER_HOST})
get_filename_component(FPGA_COMPRESS_EXE "${CMAKE_CURRENT_LIST_DIR}/fpga_compress/${FPGA_COMPRESS}${FPGA_COMPRESS_EXE_SUFFIX}" ABSOLUTE) # executable filename + suffix
add_custom_command(OUTPUT ${FPGA_COMPRESS_EXE}
        # COMMAND ${CMAKE_COMMAND} -E echo "[=] CC ${FPGA_COMPRESS} executable"
        COMMAND ${C_COMPILER_HOST}
        ${_fc_MYCFLAGS}
        ${_fc_MYDEFS}
        ${_fc_MYINCLUDES}
        ${_fc_MYSRCS}
        -o ${FPGA_COMPRESS_EXE}
        DEPENDS ${_fc_MYSRCS} # if src update, this custom command will run. tips: only .c files watch now, you can add .h files watch if need.
        WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/fpga_compress
        COMMENT "Build 'fpga_compress' executable for next step"
        VERBATIM)

# add_custom_target always run if project build, but add_custom_command can cached output if no files update.
add_custom_target(${FPGA_COMPRESS} DEPENDS ${FPGA_COMPRESS_EXE})
