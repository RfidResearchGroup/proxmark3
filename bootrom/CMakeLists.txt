cmake_minimum_required(VERSION 3.20)

# Fix error when 'compile a simple test program.'
include(${CMAKE_CURRENT_LIST_DIR}/../tools/FixCompileTest.cmake)

# Ensure direct bootrom builds also select ARM cross-compilers.
include(${CMAKE_CURRENT_LIST_DIR}/../tools/ToolchainForArm.cmake)

project(bootrom C ASM) # Set variables needs before the project defining.

# Hardware abstraction layer for ARM platform.
include(${CMAKE_CURRENT_LIST_DIR}/../common_arm/Hal.cmake)

# Include the MKVersion script for generating version_pm3.c
include(${CMAKE_CURRENT_LIST_DIR}/../tools/MKVersionScript.cmake)

# ---

set(OBJDIR ${CMAKE_BINARY_DIR}/obj)
set(DEFAULT_VERSION_C ${CMAKE_CURRENT_LIST_DIR}/../common/default_version_pm3.c)
set(VERSION_PM3_C ${CMAKE_CURRENT_BINARY_DIR}/version_pm3.c)

set(INC_DIRS
        ${CMAKE_CURRENT_LIST_DIR}/../include
        ${CMAKE_CURRENT_LIST_DIR}/../common
        ${CMAKE_CURRENT_LIST_DIR}/../common_arm/sys
        ${CMAKE_CURRENT_LIST_DIR}/../common_arm/wdt
        ${CMAKE_CURRENT_LIST_DIR}/../common_arm/flash_code
        ${CMAKE_CURRENT_LIST_DIR}/../common_arm/gpio
        ${CMAKE_CURRENT_LIST_DIR}/../common_arm/usb
        ${CMAKE_CURRENT_LIST_DIR}/../common_arm/ticks
)

set(THUMBSRC
        ${CMAKE_CURRENT_LIST_DIR}/bootrom.c
        ${VERSION_PM3_C}
        ../common_arm/usb/usb_cdc_desc.c)

if (PM5)
    set(THUMBSRC ${THUMBSRC}
            ${CMAKE_CURRENT_LIST_DIR}/../common_arm/sys/sys_hw_at32.c
            ${CMAKE_CURRENT_LIST_DIR}/../common_arm/ticks/ticks_hw_at32.c
            ${CMAKE_CURRENT_LIST_DIR}/../common_arm/gpio/gpio_hw_at32.c
            ${CMAKE_CURRENT_LIST_DIR}/../common_arm/usb/usb_cdc_at32.c
            ${CMAKE_CURRENT_LIST_DIR}/../common_arm/flash_code/flash_code_hw_at32.c
    )
    set(ASMSRC flash-reset-at32.s ram-reset-at32.s)
else ()
    set(THUMBSRC ${THUMBSRC}
            ${CMAKE_CURRENT_LIST_DIR}/../common_arm/sys/sys_hw_at91.c
            ${CMAKE_CURRENT_LIST_DIR}/../common_arm/ticks/ticks_hw_at91.c
            ${CMAKE_CURRENT_LIST_DIR}/../common_arm/gpio/gpio_hw_at91.c
            ${CMAKE_CURRENT_LIST_DIR}/../common_arm/usb/usb_cdc_at91.c
            ${CMAKE_CURRENT_LIST_DIR}/../common_arm/flash_code/flash_code_hw_at91.c
    )
    set(ASMSRC flash-reset-at91.s ram-reset-at91.s)
endif ()

# stdint.h provided locally until GCC 4.5 becomes C99 compliant
set(APP_CFLAGS -I. -ffunction-sections -fdata-sections -DAS_BOOTROM)

# stack-protect , no-pie reduces size on Gentoo Hardened 8.2 gcc,  no-common makes sure uninitialized vars don't end up in COMMON area
set(APP_CFLAGS ${APP_CFLAGS} -fno-stack-protector -fno-pie -fno-common)

if ("${PLATFORM_DEFS}" MATCHES "WITH_FLASH")
    set(INC_DIRS ${INC_DIRS} ${CMAKE_CURRENT_LIST_DIR}/../common_arm/flash_data)
    if (PM5)
        set(SRC_FLASH ../common_arm/flash_data/flashmem_hw_at32.c)
        set(SRC_TICKS ../common_arm/ticks/ticks_hw_at32.c)
    else ()
        set(SRC_FLASH ../common_arm/flash_data/flashmem_hw_at91.c)
        set(SRC_TICKS ../common_arm/ticks/ticks_hw_at91.c)
    endif ()
    set(SRC_FLASH ${SRC_FLASH} ../common_arm/flash_data/flashmem_core.c)
    set(SRC_TICKS ${SRC_TICKS} ../common_arm/ticks/ticks_core.c)
    set(THUMBSRC ${THUMBSRC} ${SRC_FLASH} ${SRC_TICKS})
endif ()

if (PM5)
    set(LDSCRIPT ${CMAKE_CURRENT_LIST_DIR}/ldscript-flash-at32)
else ()
    set(LDSCRIPT ${CMAKE_CURRENT_LIST_DIR}/ldscript-flash-at91)
endif ()

set(APP_CFLAGS ${APP_CFLAGS} ${PLATFORM_DEFS})

# Do not move this inclusion before the definition of {THUMB,ASM,ARM}SRC
include(${CMAKE_CURRENT_LIST_DIR}/../common_arm/Common.cmake)

if (PM5)
    include(${CMAKE_CURRENT_LIST_DIR}/../armlib/pm5_at32_armlib.cmake)
    set(LIBS ${LIBS} pm5_at32_armlib)
endif ()

# Fix: warning: bootrom\bootrom.elf has a LOAD segment with RWX permissions
set(CROSS_LDFLAGS ${CROSS_LDFLAGS} -Wl,--no-warn-rwx-segments)

# Create version_pm3.c before bootrom build.
add_custom_command(
        OUTPUT ${VERSION_PM3_C}
        DEPENDS ${DEFAULT_VERSION_C}
        COMMAND ${MKVERSION_CMD} ${VERSION_PM3_C} || ${CMAKE_COMMAND} -E copy ${DEFAULT_VERSION_C} ${VERSION_PM3_C}
        COMMENT "Call mkversion.xx script to generate 'version_pm3.c', if mkversion return fail, fallback is default_version_pm3.c"
        VERBATIM
)

# ---------------- Output dir ----------------
file(MAKE_DIRECTORY ${OBJDIR})
get_filename_component(OUTPUT_BOOTROM_HEX ${OBJDIR}/${PROJECT_NAME}.hex ABSOLUTE)
get_filename_component(OUTPUT_BOOTROM_BIN ${OBJDIR}/${PROJECT_NAME}.bin ABSOLUTE)

add_executable(bootrom.elf ${THUMBSRC} ${ASMSRC})
set_target_properties(bootrom.elf PROPERTIES # The 'bootrom.elf' output to ${OBJDIR}
        RUNTIME_OUTPUT_DIRECTORY "${OBJDIR}"
        OUTPUT_NAME "bootrom"
        SUFFIX ".elf" # OK, OBJDIR + OUTPUT_NAME + SUFFIX = /xxx/obj/bootrom.elf
)
target_link_options(bootrom.elf PRIVATE -Wl,-Map=${PROJECT_BINARY_DIR}/${PROJECT_NAME}.map) # output map file
target_link_options(bootrom.elf PRIVATE -L ${CMAKE_CURRENT_LIST_DIR} -T ${LDSCRIPT} ${CROSS_LDFLAGS})
target_compile_options(bootrom.elf PRIVATE ${CROSS_CFLAGS}) # !!!! WARN !!!! No -mthumb on here
set_source_files_properties(${THUMBSRC} PROPERTIES COMPILE_OPTIONS "-mthumb") # THUMBSRC is '-mthumb' flag required.
target_include_directories(bootrom.elf PRIVATE ${INC_DIRS})
target_link_libraries(bootrom.elf ${LIBS})

# Generate HEX and BIN files for fullimage finally
add_custom_command(TARGET bootrom.elf POST_BUILD
        # COMMAND ${CMAKE_COMMAND} -E echo "[=] GEN(10) bootrom.elf(HEX,BIN)"
        COMMAND ${CMAKE_OBJCOPY} -Oihex $<TARGET_FILE:${PROJECT_NAME}.elf> ${OUTPUT_BOOTROM_HEX}
        COMMAND ${CMAKE_OBJCOPY} -Obinary $<TARGET_FILE:${PROJECT_NAME}.elf> ${OUTPUT_BOOTROM_BIN}
        COMMENT "Build bootrom.hex & bootrom.bin"
)
