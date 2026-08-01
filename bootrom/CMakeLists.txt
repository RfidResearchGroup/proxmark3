cmake_minimum_required(VERSION 3.20)

# Fix error when 'compile a simple test program.'
include(${CMAKE_CURRENT_SOURCE_DIR}/../tools/FixCompileTest.cmake)

project(bootrom C ASM) # Set variables needs before the project defining.

# Hardware abstraction layer for ARM platform.
include(../common_arm/Hal.cmake)

# ---

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
    ${CMAKE_CURRENT_LIST_DIR}/version_pm3.c
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

# PM5 related
if (PM5)
    set(SRC_PM5_HARDWARE
        # cmsis
        ../armlib/at32_sys/cmsis/cm4/device_support/system_at32f435_437.c
        # driver
        ../armlib/at32_sys/drivers/src/at32f435_437_crm.c
        ../armlib/at32_sys/drivers/src/at32f435_437_misc.c
        ../armlib/at32_sys/drivers/src/at32f435_437_gpio.c
        ../armlib/at32_sys/drivers/src/at32f435_437_usb.c
        ../armlib/at32_sys/drivers/src/at32f435_437_qspi.c
        ../armlib/at32_sys/drivers/src/at32f435_437_tmr.c
        ../armlib/at32_sys/drivers/src/at32f435_437_flash.c
        # usb middlewares
        ../armlib/at32_usb/usb_drivers/src/usb_core.c
        ../armlib/at32_usb/usb_drivers/src/usbd_core.c
        ../armlib/at32_usb/usb_drivers/src/usbd_int.c
        ../armlib/at32_usb/usb_drivers/src/usbd_sdr.c
        ../armlib/at32_usb/usbd_class/cdc/cdc_class.c
        ../armlib/at32_usb/usbd_class/cdc/cdc_desc.c
    )
    list(APPEND APP_CFLAGS
        -DCRM_MODULE_ENABLED
        -DMISC_MODULE_ENABLED
        -DGPIO_MODULE_ENABLED
        -DUSB_MODULE_ENABLED
        -DQSPI_MODULE_ENABLED
        -DTMR_MODULE_ENABLED
        -DFLASH_MODULE_ENABLED
    )
    list(APPEND INC_DIRS
        ../armlib/at32_sys
        ../armlib/at32_sys/cmsis/cm4/core_support
        ../armlib/at32_sys/cmsis/cm4/device_support
        ../armlib/at32_sys/drivers/inc
        ../armlib/at32_usb
        ../armlib/at32_usb/usb_drivers/inc
        ../armlib/at32_usb/usbd_class/cdc
    )
    list(APPEND APP_CFLAGS
        -DUSBD_SUPPORT_WINUSB=1
        -mcpu=cortex-m4  # Kernel Type
        -DAT32F435RGT7   # Chip Type
        -DUSE_STDPERIPH_DRIVER
        -DAT_START_F435_V1
        -DPM5 # !!! IMPORTANT !!!
    )
endif ()

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
    set(THUMBSRC ${THUMBSRC} ${SRC_PM5_HARDWARE}) # Hardware related to PM5.
    set(LDSCRIPT ${CMAKE_CURRENT_SOURCE_DIR}/ldscript-flash-at32)
else ()
    set(LDSCRIPT ${CMAKE_CURRENT_SOURCE_DIR}/ldscript-flash-at91)
endif ()

set(APP_CFLAGS ${APP_CFLAGS} ${PLATFORM_DEFS})

# Do not move this inclusion before the definition of {THUMB,ASM,ARM}SRC
include(${CMAKE_CURRENT_SOURCE_DIR}/../common_arm/Common.cmake)

# Fix: warning: bootrom\bootrom.elf has a LOAD segment with RWX permissions
set(CROSS_LDFLAGS ${CROSS_LDFLAGS} -Wl,--no-warn-rwx-segments)

add_executable(bootrom.elf ${THUMBSRC} ${ASMSRC})
set_target_properties(bootrom.elf PROPERTIES # The 'bootrom.elf' output to ${OBJDIR}
    RUNTIME_OUTPUT_DIRECTORY "${OBJDIR}"
    OUTPUT_NAME "bootrom"
    SUFFIX ".elf" # OK, OBJDIR + OUTPUT_NAME + SUFFIX = /xxx/obj/bootrom.elf
)
target_link_options(bootrom.elf PRIVATE -Wl,-Map=${PROJECT_BINARY_DIR}/${PROJECT_NAME}.map) # output map file
target_link_options(bootrom.elf PRIVATE -L ${CMAKE_CURRENT_SOURCE_DIR} -T ${LDSCRIPT} ${CROSS_LDFLAGS})
target_compile_options(bootrom.elf PRIVATE ${CROSS_CFLAGS}) # !!!! WARN !!!! No -mthumb on here
set_source_files_properties(${THUMBSRC} PROPERTIES COMPILE_OPTIONS "-mthumb") # THUMBSRC is '-mthumb' flag required.
target_include_directories(bootrom.elf PRIVATE ${INC_DIRS})
target_link_libraries(bootrom.elf ${LIBS})

# Generate HEX and BIN files for fullimage finally
add_custom_command(TARGET bootrom.elf POST_BUILD
    # COMMAND ${CMAKE_COMMAND} -E echo "[=] GEN(10) bootrom.elf(HEX,BIN)"
    COMMAND ${CMAKE_OBJCOPY} -Oihex bootrom.elf bootrom.hex
    COMMAND ${CMAKE_OBJCOPY} -Obinary bootrom.elf bootrom.bin
    COMMENT "Build bootrom.hex & bootrom.bin"
)
