#[[
+============================================+
| PLATFORM        | DESCRIPTION              |
+============================================+
| PM3RDV4 (def)   | Proxmark3 RDV4           |
+--------------------------------------------+
| PM3GENERIC      | Proxmark3 generic target |
+--------------------------------------------+
| PM3ICOPYX       | iCopy-X with XC3S100E    |
+--------------------------------------------+
| PM5             | Proxmark5                |
+--------------------------------------------+
]]
set(PLATFORM "PM3RDV4" CACHE STRING "Default platform is PM3RDV4 if no platform specified")
set_property(CACHE PLATFORM PROPERTY STRINGS "PM3RDV4" "PM3GENERIC" "PM3ICOPYX" "PM5")

#[[
+============================================+
| PLATFORM_EXTRAS | DESCRIPTION              |
+============================================+
| BTADDON         | Proxmark3 RDV4 BT add-on |
+--------------------------------------------+
]]
set(PLATFORM_EXTRAS "" CACHE STRING "Default PLATFORM_EXTRAS is unset")
set_property(CACHE PLATFORM_EXTRAS PROPERTY STRINGS "BTADDON" "")

# Skip fpga bit stream files pack to arm's fw?
# Some platform is no download in arm side required.
set(SKIP_FPGA_EMBED FALSE CACHE STRING "It is enabled by default. Package the fpga image to the arm firmware.")

# The arm platform name & fpga platform name
set(PLTNAME "Unknown Platform")
set(PLATFORM_FPGA "fpga-undefined")

if (PLATFORM STREQUAL "PM3RDV4")
    # FPGA bitstream files, the order doesn't matter anymore
    set(FPGA_BITSTREAMS ../fpga/fpga_pm3_hf.bit)
    if (NOT SKIP_LF)
        list(APPEND FPGA_BITSTREAMS ../fpga/fpga_pm3_lf.bit)
    endif ()
    if (NOT SKIP_FELICA)
        list(APPEND FPGA_BITSTREAMS ../fpga/fpga_pm3_felica.bit)
    endif ()
    if (NOT SKIP_ISO15693)
        list(APPEND FPGA_BITSTREAMS ../fpga/fpga_pm3_hf_15.bit)
    endif ()
    set(PLATFORM_DEFS -DWITH_SMARTCARD -DWITH_FLASH -DRDV4 -DCHIP_AT91SAM7S)
    set(PLTNAME "Proxmark3 RDV4")
    set(PLATFORM_FPGA "xc2s30")
    set(RDV4 TRUE)
elseif (PLATFORM STREQUAL "PM3OTHER")
    message(WARNING "PLATFORM=PM3OTHER is deprecated, please use PLATFORM=PM3GENERIC")
    set(_IS_GENERIC TRUE) # Fall through to PM3GENERIC behavior
elseif (PLATFORM STREQUAL "PM3GENERIC")
    set(_IS_GENERIC TRUE)
elseif (PLATFORM STREQUAL "PM3ICOPYX")
    set(FPGA_BITSTREAMS ../fpga/fpga_icopyx_hf.bit)
    set(PLATFORM_DEFS -DWITH_FLASH -DICOPYX -DXC3 -DCHIP_AT91SAM7S)
    set(PLTNAME "iCopy-X with XC3S100E")
    set(PLATFORM_FPGA "xc3s100e")
elseif (PLATFORM STREQUAL "PM5")
    # TODO DXL 我们暂时不需要指定FPGA比特流文件，因为实际上我们大概率要做FPGA的静态烧录，而不是附加到ARM固件中动态下载
    set(FPGA_BITSTREAMS ../fpga/fpga_pm3_hf.bit) # TODO DXL 虽然可以不把打包比特流，但是还是得把FPGA的版本信息给生成，让EXE依赖。
    set(SKIP_FPGA_EMBED TRUE) # important!!! disable the fpga bit files pack to arm!
    set(SKIP_COMPRESSION TRUE) # Skip data section compress. The new mcu has enough flash space.
    set(PLATFORM_DEFS -DWITH_FLASH -DPM5 -DCHIP_AT32F435_37) # TODO DXL 暂时不要编译i2c -DWITH_SMARTCARD
    set(PLTNAME "Proxmark5")
    set(PLATFORM_FPGA "GW1NR-LV2MG49GC6/i5")
    set(PM5 TRUE)
else ()
    message(FATAL_ERROR "Invalid or empty PLATFORM: ${PLATFORM}. Known platforms: PM3RDV4, PM3GENERIC, PM3ICOPYX (PM3OTHER is deprecated)")
endif ()

# PM3GENERIC and PM3OTHER
if (_IS_GENERIC)
    set(FPGA_BITSTREAMS ../fpga/fpga_pm3_hf.bit)
    if (NOT SKIP_LF)
        list(APPEND FPGA_BITSTREAMS ../fpga/fpga_pm3_lf.bit)
    endif ()
    if (NOT SKIP_FELICA)
        list(APPEND FPGA_BITSTREAMS ../fpga/fpga_pm3_felica.bit)
    endif ()
    if (NOT SKIP_ISO15693)
        list(APPEND FPGA_BITSTREAMS ../fpga/fpga_pm3_hf_15.bit)
    endif ()
    set(PLTNAME "Proxmark3 generic target")
    set(PLATFORM_FPGA "xc2s30")
    set(PLATFORM_DEFS -DCHIP_AT91SAM7S)
    if (LED_ORDER STREQUAL "PM3EASY")
        list(APPEND PLATFORM_DEFS -DLED_ORDER_PM3EASY)
    endif ()
endif ()

# If no fpga bitstream pack to arm, set flag for arm compile.
if (SKIP_FPGA_EMBED)
    list(APPEND PLATFORM_DEFS -DNO_FPGA_BITSTREAM_PACK)
endif ()

# parsing additional PLATFORM_EXTRAS tokens
set(PLATFORM_EXTRAS_TMP ${PLATFORM_EXTRAS})
if ("${PLATFORM_EXTRAS_TMP}" MATCHES "SMARTCARD")
    list(APPEND PLATFORM_DEFS -DWITH_SMARTCARD)
    list(REMOVE_ITEM PLATFORM_EXTRAS_TMP "SMARTCARD")
endif ()
if ("${PLATFORM_EXTRAS_TMP}" MATCHES "FLASH")
    list(APPEND PLATFORM_DEFS -DWITH_FLASH)
    list(REMOVE_ITEM PLATFORM_EXTRAS_TMP "FLASH")
endif ()
if ("${PLATFORM_EXTRAS_TMP}" MATCHES "BTADDON")
    list(APPEND PLATFORM_DEFS -DWITH_FPC_USART_HOST)
    list(REMOVE_ITEM PLATFORM_EXTRAS_TMP "BTADDON")
endif ()
if ("${PLATFORM_EXTRAS_TMP}" MATCHES "FPC_USART_DEV")
    list(APPEND PLATFORM_DEFS -DWITH_FPC_USART_DEV)
    list(REMOVE_ITEM PLATFORM_EXTRAS_TMP "FPC_USART_DEV")
endif ()
if (PLATFORM_EXTRAS_TMP)
    message(FATAL_ERROR "Unknown PLATFORM_EXTRAS token(s): ${PLATFORM_EXTRAS_TMP}")
endif ()

# common LF support
if (NOT SKIP_LF)
    list(APPEND PLATFORM_DEFS -DWITH_LF)
endif ()
if (NOT SKIP_HITAG)
    list(APPEND PLATFORM_DEFS -DWITH_HITAG)
endif ()
if (NOT SKIP_EM4x50)
    list(APPEND PLATFORM_DEFS -DWITH_EM4x50)
endif ()
if (NOT SKIP_EM4x70)
    list(APPEND PLATFORM_DEFS -DWITH_EM4x70)
endif ()
if (NOT SKIP_ZX8211)
    list(APPEND PLATFORM_DEFS -DWITH_ZX8211)
endif ()

# common HF support
if (NOT SKIP_HF)
    list(APPEND PLATFORM_DEFS -DWITH_GENERAL_HF)
endif ()
if (NOT SKIP_ISO15693)
    list(APPEND PLATFORM_DEFS -DWITH_ISO15693)
endif ()
if (NOT SKIP_LEGICRF)
    list(APPEND PLATFORM_DEFS -DWITH_LEGICRF)
endif ()
if (NOT SKIP_ISO14443b)
    list(APPEND PLATFORM_DEFS -DWITH_ISO14443b)
endif ()
if (NOT SKIP_ISO14443a)
    list(APPEND PLATFORM_DEFS -DWITH_ISO14443a)
endif ()
if (NOT SKIP_ICLASS)
    list(APPEND PLATFORM_DEFS -DWITH_ICLASS)
endif ()
if (NOT SKIP_FELICA)
    list(APPEND PLATFORM_DEFS -DWITH_FELICA)
endif ()
if (NOT SKIP_NFCBARCODE)
    list(APPEND PLATFORM_DEFS -DWITH_NFCBARCODE)
endif ()
if (NOT SKIP_HFSNIFF)
    list(APPEND PLATFORM_DEFS -DWITH_HFSNIFF)
endif ()
if (NOT SKIP_HFPLOT)
    list(APPEND PLATFORM_DEFS -DWITH_HFPLOT)
endif ()
if (NOT SKIP_COMPRESSION)
    list(APPEND PLATFORM_DEFS -DWITH_COMPRESSION)
endif ()

# Standalone mode
if (STANDALONE_REQ_DEFS)
    message(STATUS "-------------- PLATFORM_DEFS = ${PLATFORM_DEFS}")
    if (NOT "${PLATFORM_DEFS};" MATCHES ".*;(${STANDALONE_REQ_DEFS});.*")
        message(FATAL_ERROR "Chosen Standalone mode ${STANDALONE} requires ${STANDALONE_REQ_DEFS}, unsupported by ${PLTNAME}")
    endif ()
endif ()
if (DEFINED STANDALONE_PLATFORM_DEFS AND NOT "${STANDALONE_PLATFORM_DEFS}" STREQUAL "")
    list(APPEND PLATFORM_DEFS ${STANDALONE_PLATFORM_DEFS})
endif ()
# Find and print standalone-related definitions
string(REGEX MATCHALL "WITH_STANDALONE_[^;]+" STANDALONE_DEFS_FOUND "${PLATFORM_DEFS}")

# Misc (LCD support)
if ("${PLATFORM_DEFS}" MATCHES "WITH_LCD")
    list(APPEND PLATFORM_DEFS -DWITH_LCD)
endif ()

# WITH_FPC_USART_* needs WITH_FPC_USART
string(FIND "${PLATFORM_DEFS}" "WITH_FPC_USART_" _FPC_POS)
if (NOT _FPC_POS STREQUAL "-1")
    list(APPEND PLATFORM_DEFS -DWITH_FPC_USART)
endif ()

# Extract non-standalone platform defs (remove -DWITH_ prefix and STANDALONE* entries)
string(REPLACE "-DWITH_" "" PLATFORM_DEFS_CLEAN "${PLATFORM_DEFS}")
separate_arguments(PLATFORM_DEFS_CLEAN)
# Filter out STANDALONE entries
set(PLATFORM_DEFS_INFO)
foreach (def ${PLATFORM_DEFS_CLEAN})
    if (NOT def MATCHES "^STANDALONE_")
        list(APPEND PLATFORM_DEFS_INFO ${def})
    endif ()
endforeach ()
list(REMOVE_DUPLICATES PLATFORM_DEFS_INFO)
# Extract standalone mode (remove 'STANDALONE_' prefix)

message(STATUS "PLATFORM_DEFS_INFO = ${PLATFORM_DEFS_INFO}")

set(PLATFORM_DEFS_INFO_STANDALONE)
foreach (def ${PLATFORM_DEFS_CLEAN})
    if (def MATCHES "^STANDALONE_(.+)")
        list(APPEND PLATFORM_DEFS_INFO_STANDALONE "${CMAKE_MATCH_1}")
    endif ()
endforeach ()
list(REMOVE_DUPLICATES PLATFORM_DEFS_INFO_STANDALONE)

# Check that only one Standalone mode is selected
list(LENGTH PLATFORM_DEFS_INFO_STANDALONE STANDALONE_COUNT)
if (STANDALONE_COUNT GREATER 1)
    message(FATAL_ERROR "You must choose only one Standalone mode!: ${PLATFORM_DEFS_INFO_STANDALONE}")
endif ()

# Set extras info
set(PLATFORM_EXTRAS_INFO ${PLATFORM_EXTRAS})
if (NOT PLATFORM_EXTRAS_INFO)
    set(PLATFORM_EXTRAS_INFO "No extra selected")
endif ()

message(STATUS "PLATFORM_DEFS_INFO_STANDALONE = ${PLATFORM_DEFS_INFO_STANDALONE}")

# Set standalone info
if (NOT PLATFORM_DEFS_INFO_STANDALONE)
    set(PLATFORM_DEFS_INFO_STANDALONE "No standalone mode selected")
endif ()

# Default platform size
if (NOT PLATFORM_SIZE)
    set(PLATFORM_SIZE 512)
endif ()

# Show some vars.
message(STATUS "===================================================================")
message(STATUS "Version info     : ${VERSION_INFO} ")
message(STATUS "Platform name    : ${PLTNAME} ")
message(STATUS "PLATFORM         : ${PLATFORM} ")
message(STATUS "PLATFORM_FPGA    : ${PLATFORM_FPGA} ")
message(STATUS "PLATFORM_SIZE    : ${PLATFORM_SIZE} ")
message(STATUS "Platform extras  : ${PLATFORM_EXTRAS_INFO} ")
message(STATUS "Included options : ${PLATFORM_DEFS_INFO} ")
message(STATUS "Standalone mode  : ${PLATFORM_DEFS_INFO_STANDALONE} ")
message(STATUS "C Compiler Host  : ${C_COMPILER_HOST}")
message(STATUS "===================================================================")
