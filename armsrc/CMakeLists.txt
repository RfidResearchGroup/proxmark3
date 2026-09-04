cmake_minimum_required(VERSION 3.20)

# Fix error when 'compile a simple test program.'
include(${CMAKE_CURRENT_LIST_DIR}/../tools/FixCompileTest.cmake)

# Ensure direct armsrc builds also select ARM cross-compilers.
include(${CMAKE_CURRENT_LIST_DIR}/../tools/ToolchainForArm.cmake)

# Set variables needs before the project defining.
project(fullimage C CXX ASM)

# Compile tools for project build step, preprocessor and postprocessor
#  So this compiler need run on host platform
find_program(C_COMPILER_HOST gcc)
if (NOT C_COMPILER_HOST)
    message(FATAL_ERROR "GCC for tools build on host is no found, Plz give the cmake arg like 'cmake -DC_COMPILER_HOST=/your path/'")
endif ()

# Genarate version info by mkversion script
include(${CMAKE_CURRENT_LIST_DIR}/../tools/MKVersionScript.cmake)

# Import options for standalone mode
#  Used 'STANDALONE_REQ_DEFS' & 'STANDALONE_PLATFORM_DEFS' variables.
include(${CMAKE_CURRENT_LIST_DIR}/Standalone/StandAloneOption.cmake)

# Hardware abstraction layer for ARM platform.
include(${CMAKE_CURRENT_LIST_DIR}/../common_arm/Hal.cmake)

# Setup FPGA Compress.
include(${CMAKE_CURRENT_LIST_DIR}/../tools/FpgaCompress.cmake)

# ---------------------------------------------------------------------------------

set(APP_CFLAGS ${PLATFORM_DEFS} -ffunction-sections -fdata-sections)

set(INC_DIRS
        ../include
        ../common_arm
        ../common_arm/rssi
        ../common_arm/rgb
        ../common_arm/ticks
        ../common_arm/usb
        ../common_arm/flash_data
        ../common_arm/flash_code
        ../common_arm/gpio
        ../common_arm/sys
        ../common_arm/fpga
        ../common_arm/wdt
        ../common_fpga
        ../common
        ../common/lz4
        .
)

# Hal for platform
if (PM5)
    set(SRC_TICKS ../common_arm/ticks/ticks_hw_at32.c)
    set(SRC_GPIO ../common_arm/gpio/gpio_hw_at32.c)
    set(SRC_WDT ../common_arm/wdt/wdt_hw_at32.c)
    set(SRC_RSSI ../common_arm/rssi/rssi_hw_at32.c)
    set(SRC_RGB ../common_arm/rgb/rgb_hw_at32.c)
    set(SRC_SYS ../common_arm/sys/sys_hw_at32.c)
    set(SRC_FLASH_DATA ../common_arm/flash_data/flashmem_hw_at32.c)
    set(SRC_USB_CDC ../common_arm/usb/usb_cdc_at32.c)
    set(SRC_FPGA ../common_arm/fpga/fpga_hw_at32.c ../common_arm/fpga/fpga_gw_jtag.c)
    set(LDSCRIPT ${CMAKE_CURRENT_LIST_DIR}/ldscript.osimage.at32)
else ()
    set(SRC_TICKS ../common_arm/ticks/ticks_hw_at91.c)
    set(SRC_GPIO ../common_arm/gpio/gpio_hw_at91.c)
    set(SRC_WDT ../common_arm/wdt/wdt_hw_at91.c)
    set(SRC_RSSI ../common_arm/rssi/rssi_hw_at91.c)
    set(SRC_RGB "")
    set(SRC_SYS ../common_arm/sys/sys_hw_at91.c)
    set(SRC_FLASH_DATA ../common_arm/flash_data/flashmem_hw_at91.c)
    set(SRC_USB_CDC ../common_arm/usb/usb_cdc_at91.c)
    set(SRC_FPGA ../common_arm/fpga/fpga_hw_at91.c)
    set(LDSCRIPT ${CMAKE_CURRENT_LIST_DIR}/ldscript.osimage.at91)
endif ()

set(SRC_LF
        lfops.c
        lfsampling.c
        pcf7931.c
        ../common/lfdemod.c
        lfadc.c
)

set(SRC_HF hfops.c)

set(SRC_ISO15693
        iso15693.c
        ../common/iso15693tools.c)

set(SRC_ISO14443a
        iso14443a.c
        secc.c
        mifareutil.c
        mifarecmd.c
        epa.c
        mifaresim.c
        sam_common.c
        sam_mfc.c
        sam_seos.c
        sam_sc.c
)

#UNUSED: mifaresniff.c

set(SRC_ISO14443b iso14443b.c)

set(SRC_FELICA felica.c felicasim.c)

set(SRC_CRAPTO1
        ../common/crapto1/crypto1.c
        desfire_crypto.c
        mifaredesfire.c
        ../common/mbedtls/des.c
        ../common/mbedtls/aes.c
        ../common/mbedtls/platform_util.c
)

set(SRC_CRC
        ../common/crc.c
        ../common/crc16.c
        ../common/crc32.c)

set(SRC_ICLASS
        iclass.c
        optimized_cipherutils.c
        optimized_ikeys.c
        optimized_elite.c
        optimized_cipher.c
        sam_picopass.c
)

set(SRC_SEOS
        seos.c
        ../common/mbedtls/sha1.c
        ../common/mbedtls/sha256.c)

set(SRC_LEGIC
        legicrf.c
        legicrfsim.c
        ../common/legic_prng.c)

set(SRC_NFCBARCODE thinfilm.c)

#   SRC_BEE = bee.c
#   set(SRC_BEE bee.c)

message(STATUS "APP_CFLAGS = ${APP_CFLAGS}")

# RDV4 or PM5 related hardware support
if ("${APP_CFLAGS}" MATCHES "WITH_FLASH")
    set(SRC_FLASH ${SRC_FLASH_DATA} ../common_arm/flash_data/flashmem_core.c)
    set(SRC_SPIFFS
            spiffs.c
            spiffs_cache.c
            spiffs_check.c
            spiffs_gc.c
            spiffs_nucleus.c
            spiffs_hydrogen.c
    )
else ()
    set(SRC_FLASH)
    set(SRC_SPIFFS)
endif ()

if ("${APP_CFLAGS}" MATCHES "WITH_SMARTCARD")
    set(SRC_SMARTCARD i2c.c i2c_direct.c emvsim.c)
else ()
    set(SRC_SMARTCARD)
endif ()

if ("${APP_CFLAGS}" MATCHES "WITH_FPC_USART")
    set(SRC_FPC usart.c)
else ()
    set(SRC_FPC)
endif ()

# BWM charger (AW32001) + fuel gauge (BQ27427), incl. the optional low-batt beep
if ("${APP_CFLAGS}" MATCHES "WITH_BWM_STATUS" OR "${APP_CFLAGS}" MATCHES "WITH_BWM_CHARGERKICK")
    set(SRC_BWM_CHARGER bwm_charger.c)
else ()
    set(SRC_BWM_CHARGER)
endif ()

# PM5 antenna-RGB power/battery indicator
if ("${APP_CFLAGS}" MATCHES "WITH_PM5_PWR_LED")
    set(SRC_RGB_INDICATOR rgb_indicator.c)
else ()
    set(SRC_RGB_INDICATOR)
endif ()

if ("${APP_CFLAGS}" MATCHES "WITH_HITAG")
    set(SRC_HITAG
            ../common/hitag2/hitag2_crypto.c
            hitag_common.c
            hitag2.c
            hitagS.c
            hitagu.c
            hitag2_crack.c
    )
    list(APPEND INC_DIRS ../common/hitag2)
else ()
    set(SRC_HITAG)
endif ()

if ("${APP_CFLAGS}" MATCHES "WITH_EM4x50")
    set(SRC_EM4x50
            em4x50.c
            ../common/bruteforce.c)
else ()
    set(SRC_EM4x50)
endif ()

if ("${APP_CFLAGS}" MATCHES "WITH_EM4x70")
    set(SRC_EM4x70 em4x70.c)
else ()
    set(SRC_EM4x70)
endif ()

if ("${APP_CFLAGS}" MATCHES "WITH_LCD")
    # LCD module is disabled. file name is fonts_disabled.c and LCD_disabled.c
    # So, if WITH_LCD enable, we need show error for DEV.
    set(SRC_LCD fonts.c LCD.c)
    message(FATAL_ERROR "LCD functions is unavailable")
else ()
    set(SRC_LCD)
endif ()

if ("${APP_CFLAGS}" MATCHES "WITH_ZX8211")
    set(SRC_ZX lfzx.c)
else ()
    set(SRC_ZX)
endif ()

# Generic standalone Mode injection of source code
include(${CMAKE_CURRENT_LIST_DIR}/Standalone/StandAloneSource.cmake)

# The lz4 source files required for decompressing the fpga config at run time
set(SRC_LZ4 ../common/lz4/lz4.c)
# Additional defines required to compile lz4
set(LZ4_CFLAGS "-DLZ4_MEMORY_USAGE=8" "-DLZ4_HEAPMODE=0")
list(APPEND APP_CFLAGS ${LZ4_CFLAGS})
# lz4 includes:
list(APPEND INC_DIRS ../common/lz4)

# stdint.h provided locally until GCC 4.5 becomes C99 compliant,
# stack-protect , no-pie reduces size on Gentoo Hardened 8.2 gcc
list(APPEND APP_CFLAGS -I. -fno-stack-protector -fno-pie)

# Compile these in thumb mode (small size)
set(THUMBSRC
        start.c
        ${SRC_LCD}
        ${SRC_ISO15693}
        ${SRC_NFCBARCODE}
        ${SRC_LF}
        ${SRC_LZ4}
        ${SRC_LEGIC}
        ${SRC_FLASH}
        ${SRC_SMARTCARD}
        ${SRC_FPC}
        ${SRC_HITAG}
        ${SRC_EM4x50}
        ${SRC_EM4x70}
        ${SRC_SPIFFS}
        ${SRC_HF}
        ${SRC_ISO14443a}
        ${SRC_ISO14443b}
        ${SRC_CRAPTO1}
        ${SRC_ICLASS}
        ${SRC_SEOS}
        ${SRC_EMV}
        ${SRC_CRC}
        ${SRC_FELICA}
        ${SRC_STANDALONE}
        ${SRC_ZX}
        ${SRC_BWM_CHARGER}
        ${SRC_RGB_INDICATOR}
        appmain.c
        printf.c
        dbprint.c
        ../common/commonutil.c
        util.c
        string.c
        BigBuf.c
        ${SRC_RSSI}
        ${SRC_RGB}
        ${SRC_TICKS}
        ${SRC_GPIO}
        ${SRC_WDT}
        ${SRC_SYS}
        ../common_arm/rssi/rssi_core.c
        ../common_arm/ticks/ticks_core.c
        hfsnoop.c
        ../common/generator.c
        cmac_calc.c
        cmac_3des.c
)

if (PM5)
    list(APPEND THUMBSRC startup_at32f435_437.s)
    list(APPEND THUMBSRC i2c.c)
    list(APPEND THUMBSRC buzzer.c) # generic mainboard buzzer (QC self-test + BWM low-batt)
    list(APPEND THUMBSRC at32_unit_test.c) # TODO DXL: AT32单元测试代码
endif ()

# These are to be compiled in ARM mode
set(ARMSRC
        ../common_arm/fpga/fpga_loader.c
        ../common_arm/fpga/fpga_core.c
        ${SRC_FPGA}
        ../common_arm/usb/usb_read_ng.c
        ../common_arm/usb/usb_cdc_desc.c
        ${SRC_USB_CDC} # AT32 or AT91 usb module, api defs all in usb_cdc.h
        cmd.c
)

set(VERSIONSRC version_pm3.c fpga_version_info.c)

# Import common settings for arm build, such as common cflags, etc.
# Do not move this inclusion before the definition of {THUMB,ASM,ARM}SRC
include(${CMAKE_CURRENT_LIST_DIR}/../common_arm/Common.cmake)

if (PM5)
    include(${CMAKE_CURRENT_LIST_DIR}/../armlib/pm5_at32_armlib.cmake)
    set(LIBS ${LIBS} pm5_at32_armlib)
    # set(CROSS_LDFLAGS ${CROSS_LDFLAGS} -mfloat-abi=hard -mfpu=fpv4-sp-d16) # TODO DXL: Hardware float core enable?
    set(CROSS_LDFLAGS ${CROSS_LDFLAGS} -mcpu=cortex-m4)
endif ()

message(STATUS "LDSCRIPT = ${LDSCRIPT}")
message(STATUS "CROSS_CFLAGS = ${CROSS_CFLAGS}")

# =====================================================
# FPGA_COMPRESS_EXE   -> 可执行文件完整路径（如 /path/to/fpga_compress）
# FPGA_BITSTREAMS     -> 所有 .bit 文件列表
# OBJDIR              -> 构建输出目录（如 ${CMAKE_BINARY_DIR}/obj）
# APP_CFLAGS          -> 编译标志（如 "WITH_COMPRESSION"）
# THUMBSRC            -> 需用 -mthumb 编译的 C 源文件
# ARMSRC              -> 可用 ARM 模式编译的 C 源文件
# ASMSRC              -> 汇编文件（.s）
# VERSIONSRC          -> version_pm3.c和fpga_version_info.c（或其路径）
# INC_DIRS            -> 包含目录列表
# CROSS_CFLAGS        -> 通用编译标志（如 -O2, -Wall）
# CROSS_LDFLAGS       -> 链接标志（如 -nostartfiles）
# CMAKE_OBJCOPY       -> objcopy 工具路径
# LDSCRIPT            -> 链接脚本路径
# DEFAULT_VERSION_C   -> 默认 version 模板文件
# =====================================================

#[[
# Firmware and Compressed Data Integration: LZ4-based .data Section Compression Scheme

1. Compile Firmware
   - Compile C/C++ source code normally to generate an ELF file with the original .data section.
   - The linker calculates the .data size and reserves VMA (Virtual Memory Address) space in RAM.

2. Extract .data Section to Binary
   - Use objcopy to extract the raw .data section from the ELF, generating an uncompressed binary (e.g., data.bin).

3. Compress Data and Add Metadata
   - Compress data.bin using LZ4 (or similar) to produce a compressed stream (e.g., data.bin.z).
   - Prepend a 4-byte header containing the original .data size (avail_out), used for decompression bounds checking.

4. Update .data Content in ELF
   - Use objcopy --update-section to replace the .data section in the ELF with the compressed data (including 4-byte header).
   - This operation only changes the content and LMA (Load Memory Address) size, not the VMA (RAM address or reserved space).

5. Generate Final Firmware Image
   - Convert the updated ELF to .bin or .hex format for flashing.
   - The .data section in Flash now contains compressed data, significantly reducing firmware size.

6. Runtime Decompression
   - At startup, read the .data section start address (__data_src_start__) from Flash.
   - Read the first 4 bytes to get the original size (avail_out).
   - Call LZ4_decompress_safe to decompress the data into the RAM region from __data_start__ to __data_end__.
   - After decompression, .data variables are restored and the program continues.

# Key Insight: VMA Reservation Mechanism
- The linker reserves sufficient RAM space for the .data section at link time, based on the original (uncompressed) size.
- Compression only affects storage in Flash (LMA), not the runtime layout in RAM (VMA).
- The decompression target is precisely defined by linker symbols __data_start__ and __data_end__, ensuring safety and correctness.
]]

set(OBJDIR ${CMAKE_BINARY_DIR}/obj)
set(DEFAULT_VERSION_C ${CMAKE_CURRENT_LIST_DIR}/../common/default_version_pm3.c)

# ---------------- Output dir ----------------
file(MAKE_DIRECTORY ${OBJDIR})
get_filename_component(OBJDIR_NAME ${OBJDIR} NAME)

# ---------------- Output files ----------------
get_filename_component(FPGA_VERSION_C ${CMAKE_CURRENT_LIST_DIR}/fpga_version_info.c ABSOLUTE)
get_filename_component(FPGA_BIT_Z ${OBJDIR}/fpga_all.bit.z ABSOLUTE)
get_filename_component(FPGA_BIT_Z_NAME ${FPGA_BIT_Z} NAME)
get_filename_component(FPGA_ALL_O ${OBJDIR}/fpga_all.o ABSOLUTE)
get_filename_component(VERSION_PM3_C ${CMAKE_CURRENT_LIST_DIR}/version_pm3.c ABSOLUTE)
get_filename_component(STAGE1_ELF ${OBJDIR}/fullimage.stage1.elf ABSOLUTE)
get_filename_component(DATA_BIN ${OBJDIR}/fullimage.data.bin ABSOLUTE)
get_filename_component(DATA_BIN_Z ${OBJDIR}/fullimage.data.bin.z ABSOLUTE)
get_filename_component(FINAL_ELF ${OBJDIR}/fullimage.elf ABSOLUTE)
get_filename_component(OUTPUT_S19 ${OBJDIR}/fullimage.s19 ABSOLUTE)
get_filename_component(OUTPUT_STAGE1_HEX ${OBJDIR}/fullimage.stage1.hex ABSOLUTE)
get_filename_component(OUTPUT_STAGE1_BIN ${OBJDIR}/fullimage.stage1.bin ABSOLUTE)
get_filename_component(OUTPUT_FINAL_HEX ${OBJDIR}/fullimage.hex ABSOLUTE)
get_filename_component(OUTPUT_FINAL_BIN ${OBJDIR}/fullimage.bin ABSOLUTE)

# ---------------- 1. Create fpga_version_info.c ----------------
set(FPGA_BITSTREAMS_ABSOLUTE_PATH) # Convert all .bit files from relative to absolute path
foreach (bitFile ${FPGA_BITSTREAMS})
    get_filename_component(bitFileAbPath ${bitFile} ABSOLUTE) # get absolute path
    list(APPEND FPGA_BITSTREAMS_ABSOLUTE_PATH ${bitFileAbPath}) # append to list
endforeach ()
add_custom_command(
        OUTPUT ${FPGA_VERSION_C}
        # COMMAND ${CMAKE_COMMAND} -E echo "[=] GEN(1) fpga_version_info.c"
        COMMAND ${FPGA_COMPRESS_EXE} -v ${FPGA_BITSTREAMS_ABSOLUTE_PATH} ${FPGA_VERSION_C}
        DEPENDS ${FPGA_BITSTREAMS_ABSOLUTE_PATH}
        DEPENDS ${FPGA_COMPRESS_EXE} # Before this step run, we need to build 'fpga_compress' executable
        COMMAND_EXPAND_LISTS
        COMMENT "Call the 'fpga_compress' to generate 'fpga_version_info.c' for armsrc"
        VERBATIM
)

# ---------------- 2. Create fpga_all.bit.z ----------------
#  If no fpga pack to arm fw required, skip this.
add_custom_command(
        OUTPUT ${FPGA_BIT_Z}
        # COMMAND ${CMAKE_COMMAND} -E echo "[=] GEN(2) fpga_all.bit.z"
        COMMAND ${FPGA_COMPRESS_EXE} ${FPGA_BITSTREAMS_ABSOLUTE_PATH} ${FPGA_BIT_Z}
        DEPENDS ${FPGA_BITSTREAMS_ABSOLUTE_PATH}
        DEPENDS ${FPGA_COMPRESS_EXE} # Ensure host tool is built before running it.
        COMMAND_EXPAND_LISTS
        COMMENT "Call the 'fpga_compress' to compress fpga bit files, output 'fpga_all.bit.z'"
        VERBATIM
)

# ---------------- 3. Create fpga_all.o ----------------
#  If no fpga pack to arm fw required, skip this step.
#  The _binary_obj_fpga_all_bit_z_start and _binary_obj_fpga_all_bit_z_end will generate by 'objcopy'
#  Yes, fpga_all.o contain 'binary<path>_<format>_start', 'binary<path>_<format>_size', 'binary<path>_<format>_end'
#  More info view: https://stackoverflow.com/questions/60295013/is-it-possible-to-make-a-hardcoding-with-the-help-of-the-command-objcopy
#  Tips: the binary file put in '.data' section.
add_custom_command(
        OUTPUT ${FPGA_ALL_O}
        # !!! Important !!! Must enter parent dir of obj output dir, to create fpga_all.o
        #  The objcopy command needs to generate object file for 'fpga_all.bit.z' outside the obj directory.
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        # COMMAND ${CMAKE_COMMAND} -E echo "[=] GEN(3) fpga_all.o"
        COMMAND ${CMAKE_OBJCOPY} -O elf32-littlearm -I binary -B arm --prefix-sections=fpga_all_bit ${OBJDIR_NAME}/${FPGA_BIT_Z_NAME} ${FPGA_ALL_O}
        DEPENDS ${FPGA_BIT_Z}
        COMMENT "Call the objcopy to convert binary to elf file."
        VERBATIM
)

# ---------------- 4. Create version_pm3.c ----------------
if (SKIP_FPGA_EMBED)  # If pack fpga bit files to arm, we need from step1,2,3 start build, otherwise skip step2,3.
    set(FPGA_ALL_O_MKVERSION_DEP)  # <-- Important, unset it will let this step(4) no DEPENDS with 'FPGA_ALL_O'.
else ()
    set(FPGA_ALL_O_MKVERSION_DEP ${FPGA_ALL_O})
endif ()

add_custom_command(
        OUTPUT ${VERSION_PM3_C}
        # COMMAND ${CMAKE_COMMAND} -E echo "[=] GEN(4) version_pm3.c"
        DEPENDS ${DEFAULT_VERSION_C} ${FPGA_VERSION_C} ${FPGA_ALL_O_MKVERSION_DEP}
        COMMAND ${MKVERSION_CMD} ${VERSION_PM3_C} || ${CMAKE_COMMAND} -E copy ${DEFAULT_VERSION_C} ${VERSION_PM3_C}
        COMMENT "Call mkversion.xx script to generate 'version_pm3.c', if mkversion return fail, fallback is default_version_pm3.c"
        VERBATIM
)

# ---------------- 5. Build fulliamge elf but stage1, not '.data' section compressed ----------------
set(ALL_SRCS ${THUMBSRC} ${ARMSRC} ${ASMSRC} ${VERSIONSRC})

add_executable(fullimage.stage1.elf ${ALL_SRCS})
set_target_properties(fullimage.stage1.elf PROPERTIES # The 'fullimage.stage1.elf' output to ${OBJDIR}
        RUNTIME_OUTPUT_DIRECTORY "${OBJDIR}"
        OUTPUT_NAME "fullimage.stage1"
        SUFFIX ".elf" # OK, OBJDIR + OUTPUT_NAME + SUFFIX = /xxx/obj/fullimage.stage1.elf
)
target_link_options(fullimage.stage1.elf PRIVATE -Wl,-Map=${PROJECT_BINARY_DIR}/${PROJECT_NAME}.map) # output map file
target_link_options(fullimage.stage1.elf PRIVATE -L ${CMAKE_CURRENT_LIST_DIR} -T ${LDSCRIPT} ${CROSS_LDFLAGS})
target_compile_options(fullimage.stage1.elf PRIVATE ${CROSS_CFLAGS}) # !!!! WARN !!!! No -mthumb on here
set_source_files_properties(${THUMBSRC} PROPERTIES COMPILE_OPTIONS "-mthumb") # THUMBSRC is '-mthumb' flag required.
target_include_directories(fullimage.stage1.elf PRIVATE ${INC_DIRS})
target_link_libraries(fullimage.stage1.elf ${LIBS})
if (NOT SKIP_FPGA_EMBED) # Link fpga data(not compressed)
    set_property(TARGET fullimage.stage1.elf APPEND PROPERTY LINK_LIBRARIES ${FPGA_ALL_O})
endif ()

# Generate HEX and BIN files for stage 1 for easy downloading to device and debugging device.
add_custom_command(TARGET ${PROJECT_NAME}.stage1.elf POST_BUILD
        # COMMAND ${CMAKE_COMMAND} -E echo "[=] GEN(5) ${PROJECT_NAME}.stage1.(HEX,BIN)"
        COMMAND ${CMAKE_OBJCOPY} -Oihex $<TARGET_FILE:${PROJECT_NAME}.stage1.elf> ${OUTPUT_STAGE1_HEX}
        COMMAND ${CMAKE_OBJCOPY} -Obinary $<TARGET_FILE:${PROJECT_NAME}.stage1.elf> ${OUTPUT_STAGE1_BIN}
        COMMENT "Build ${PROJECT_NAME}.stage1.hex & ${PROJECT_NAME}.stage1.bin"
)

# ---------------- 6. Pull '.data' section from 'fullimage.stage1.elf' ----------------
#  Tips: fpga_all.o maybe pack to elf on stage1, is uncompress data binary, next step will compress(all '.data' section).
#    When this step is reached, the linker has allocated a specific vma for the data segment. Compression is only to reduce the firmware volume.
add_custom_command(
        OUTPUT ${DATA_BIN}
        # COMMAND ${CMAKE_COMMAND} -E echo "[=] GEN(6) pull '.data'(uncompressed)"
        COMMAND ${CMAKE_OBJCOPY} -O binary --only-section .data ${STAGE1_ELF} ${DATA_BIN}
        DEPENDS fullimage.stage1.elf
        COMMENT "Call the 'objcopy' to pull the '.data' section from 'fullimage.stage1.elf'"
        VERBATIM
)

# ---------------- 7. Compress '.data' section binary to 'fullimage.data.bin.z' ----------------
# About '.data' section compress: https://www.eevblog.com/forum/microcontrollers/compression-of-data-(initialized-variables)-section/
add_custom_command(
        OUTPUT ${DATA_BIN_Z}
        # COMMAND ${CMAKE_COMMAND} -E echo "[=] GEN(7) fullimage.data.bin.z"
        COMMAND ${FPGA_COMPRESS_EXE} ${DATA_BIN} ${DATA_BIN_Z}
        DEPENDS ${DATA_BIN}
        DEPENDS ${FPGA_COMPRESS_EXE} # Ensure host tool is built before running it.
        COMMENT "Call the 'fpga_compress' to compress '.data' section from 'fullimage.stage1.elf'"
        VERBATIM
)

# ---------------- 8. Pack data bin and gen fullimage.elf ----------------
if ("${APP_CFLAGS}" MATCHES "WITH_COMPRESSION|WITH_COMPRESSION=1")
    add_custom_command(
            OUTPUT ${FINAL_ELF}
            # COMMAND ${CMAKE_COMMAND} -E echo "[=] LD(8) fullimage.elf (with compression)"
            COMMAND ${CMAKE_OBJCOPY} -O elf32-littlearm --strip-all --update-section .data=${DATA_BIN_Z} ${STAGE1_ELF} ${FINAL_ELF}
            DEPENDS ${STAGE1_ELF} ${DATA_BIN_Z}
            COMMENT "Put the compressed '.data' section to 'fullimage.stage1.elf' for build 'fullimage.elf'"
            VERBATIM
    )
else ()
    add_custom_command(
            OUTPUT ${FINAL_ELF}
            # COMMAND ${CMAKE_COMMAND} -E echo "[=] MIN(8) fullimage.elf (without compression) "
            COMMAND ${CMAKE_OBJCOPY} -O elf32-littlearm --strip-all ${STAGE1_ELF} ${FINAL_ELF}
            DEPENDS ${STAGE1_ELF}
            COMMENT "Copy 'fullimage.stage1.elf' to 'fullimage.elf' if no compress required"
            VERBATIM
    )
endif ()

# ---------------- 9. Generate S19 format file ----------------
add_custom_command(
        OUTPUT ${OUTPUT_S19}
        # COMMAND ${CMAKE_COMMAND} -E echo "[=] GEN(9) S19 file"
        COMMAND ${CMAKE_OBJCOPY}
        -Osrec
        --srec-forceS3
        --strip-debug
        --no-change-warnings
        --change-addresses=-0x100000
        --change-start=0
        --change-section-address=.bss+0
        --change-section-address=.data-0x100000
        --change-section-address=.commonarea+0
        ${FINAL_ELF}
        ${OUTPUT_S19}
        DEPENDS ${FINAL_ELF}
        COMMENT "Call the objcopy to convert ELF to S19 format"
        VERBATIM
)

# ---------------- 10. Finally, start build the fullimage, the 'All' build will from here start ----------------
add_custom_target(fullimage ALL DEPENDS ${OUTPUT_S19} COMMENT "Build fullimage")
add_dependencies(fullimage fullimage.stage1.elf) # fullimage dependencies tree start, 9 -> 1 -> 9
# Generate HEX and BIN files for fullimage finally
add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
        # COMMAND ${CMAKE_COMMAND} -E echo "[=] GEN(10) ${PROJECT_NAME}(HEX,BIN)"
        COMMAND ${CMAKE_OBJCOPY} -Oihex ${FINAL_ELF} ${OUTPUT_FINAL_HEX}
        COMMAND ${CMAKE_OBJCOPY} -Obinary ${FINAL_ELF} ${OUTPUT_FINAL_BIN}
        COMMENT "Build ${PROJECT_NAME}.hex & ${PROJECT_NAME}.bin"
)
