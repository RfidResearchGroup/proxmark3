cmake_minimum_required(VERSION 3.16)
project(proxmark3)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

if(CMAKE_VERSION VERSION_LESS "3.7.0")
    set(CMAKE_INCLUDE_CURRENT_DIR ON)
endif()

set(CMAKE_CXX_STANDARD 14)

#set(Qt5_DIR "/opt/Qt/5.13.0/gcc_64/lib/cmake/Qt5")

find_package(Qt5 COMPONENTS Core Widgets Gui)

SET (CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

INCLUDE(FindSSE)
if(NOT SSE2_FOUND)
    MESSAGE(STATUS "Could not find hardware support for SSE2 on this machine.")
endif(NOT SSE2_FOUND)
if(NOT SSE3_FOUND)
    MESSAGE(STATUS "Could not find hardware support for SSE3 on this machine.")
endif(NOT SSE3_FOUND)
if(NOT SSSE3_FOUND)
    MESSAGE(STATUS "Could not find hardware support for SSSE3 on this machine.")
endif(NOT SSSE3_FOUND)
if(NOT SSE4_1_FOUND)
    MESSAGE(STATUS "Could not find hardware support for SSE4.1 on this machine.")
endif(NOT SSE4_1_FOUND)
if(NOT AVX_FOUND)
    MESSAGE(STATUS "Could not find hardware support for AVX on this machine.")
endif(NOT AVX_FOUND)
if(NOT AVX2_FOUND)
    MESSAGE(STATUS "Could not find hardware support for AVX2 on this machine.")
endif(NOT AVX2_FOUND)
if(NOT AVX512_FOUND)
    MESSAGE(STATUS "Could not find hardware support for AVX512 on this machine.")
endif(NOT AVX512_FOUND)

add_subdirectory(deps)

include_directories(
        ..
        SYSTEM
        deps
        ../common
        ../include
        deps/jansson
        deps/tinycbor
        deps/liblua
        client/deps/mbedtls/include
        deps/amiitool
        deps/cliparser
        deps/reveng
        ../common/zlib
        src
        src/uart
)

#file(GLOB_RECURSE TARGET_HEADERS ${CMAKE_CURRENT_LIST_DIR}/src/*.h)
#file(GLOB_RECURSE TARGET_SOURCES ${CMAKE_CURRENT_LIST_DIR}/src/*.cpp)

set (TARGET_SOURCES
        src/proxmark3.c
        src/proxmark3.h
        ../common/commonutil.c
        ../common/commonutil.h
        ../common/util_posix.c
        ../common/util_posix.h
        ../common/parity.c
        ../common/parity.h
        ../common/bucketsort.c
        ../common/bucketsort.h
        ../common/crapto1/crapto1.c
        ../common/crapto1/crapto1.h
        ../common/crapto1/crypto1.c
        ../common/crc.c
        ../common/crc.h
        ../common/crc16.c
        ../common/crc16.h
        ../common/crc32.c
        ../common/crc32.h
        ../common/crc64.c
        ../common/crc64.h
        ../common/lfdemod.c
        ../common/lfdemod.h
        ../common/legic_prng.c
        ../common/legic_prng.h
        ../common/iso15693tools.c
        ../common/iso15693tools.h
        ../common/cardhelper.c
        ../common/cardhelper.h
        ../common/generator.c
        ../common/generator.h
        deps/cliparser/argtable3.c
        deps/cliparser/argtable3.h
        deps/cliparser/cliparser.c
        deps/cliparser/cliparser.h
        deps/cliparser/getopt.h
        deps/hardnested/hardnested_bruteforce.c
        deps/hardnested/hardnested_bruteforce.h
        src/crypto/asn1dump.c
        src/crypto/asn1dump.h
        src/crypto/asn1utils.c
        src/crypto/asn1utils.h
        src/crypto/libpcrypto.c
        src/crypto/libpcrypto.h
        src/emv/test/cda_test.c
        src/emv/test/cda_test.h
        src/emv/test/crypto_test.c
        src/emv/test/crypto_test.h
        src/emv/test/cryptotest.c
        src/emv/test/cryptotest.h
        src/emv/test/dda_test.c
        src/emv/test/dda_test.h
        src/emv/test/sda_test.c
        src/emv/test/sda_test.h
        src/emv/apduinfo.c
        src/emv/apduinfo.h
        src/emv/cmdemv.c
        src/emv/cmdemv.h
        src/emv/crypto.c
        src/emv/crypto.h
        src/emv/crypto_backend.h
        src/emv/crypto_polarssl.c
        src/emv/dol.c
        src/emv/dol.h
        src/emv/dump.c
        src/emv/dump.h
        src/emv/emv_pk.c
        src/emv/emv_pk.h
        src/emv/emv_pki.c
        src/emv/emv_pki.h
        src/emv/emv_pki_priv.c
        src/emv/emv_pki_priv.h
        src/emv/emv_roca.c
        src/emv/emv_roca.h
        src/emv/emv_tags.c
        src/emv/emv_tags.h
        src/emv/emvcore.c
        src/emv/emvcore.h
        src/emv/emvjson.c
        src/emv/emvjson.h
        src/emv/tlv.c
        src/emv/tlv.h
        src/fido/additional_ca.c
        src/fido/additional_ca.h
        src/fido/cbortools.c
        src/fido/cbortools.h
        src/fido/cose.c
        src/fido/cose.h
        src/fido/fidocore.c
        src/fido/fidocore.h
        src/loclass/cipher.c
        src/loclass/cipher.h
        src/loclass/cipherutils.c
        src/loclass/cipherutils.h
        src/loclass/elite_crack.c
        src/loclass/elite_crack.h
        src/loclass/hash1_brute.c
        src/loclass/hash1_brute.h
        src/loclass/ikeys.c
        src/loclass/ikeys.h
        src/mifare/mad.c
        src/mifare/mad.h
        src/mifare/mfkey.c
        src/mifare/mfkey.h
        src/mifare/mifare4.c
        src/mifare/mifare4.h
        src/mifare/mifaredefault.c
        src/mifare/mifaredefault.h
        src/mifare/mifarehost.c
        src/mifare/mifarehost.h
        src/mifare/ndef.c
        src/mifare/ndef.h
        src/mifare/desfire_crypto.c
        src/mifare/desfire_crypto.h
        src/uart/uart.h
        src/uart/uart_posix.c
        src/uart/uart_win32.c
        src/ui/overlays.ui
        src/aidsearch.c
        src/aidsearch.h
        src/cmdanalyse.c
        src/cmdanalyse.h
        src/cmdcrc.c
        src/cmdcrc.h
        src/cmddata.c
        src/cmddata.h
        src/cmdflashmem.c
        src/cmdflashmem.h
        src/cmdflashmemspiffs.c
        src/cmdflashmemspiffs.h
        src/cmdhf.c
        src/cmdhf.h
        src/cmdhf14a.c
        src/cmdhf14a.h
        src/cmdhf14b.c
        src/cmdhf14b.h
        src/cmdhf15.c
        src/cmdhf15.h
        src/cmdhfcryptorf.c
        src/cmdhfcryptorf.h
        src/cmdhfepa.c
        src/cmdhfepa.h
        src/cmdhffelica.c
        src/cmdhffelica.h
        src/cmdhffido.c
        src/cmdhffido.h
        src/cmdhficlass.c
        src/cmdhficlass.h
        src/cmdhflegic.c
        src/cmdhflegic.h
        src/cmdhflist.c
        src/cmdhflist.h
        src/cmdhflto.c
        src/cmdhflto.h
        src/cmdhfmf.c
        src/cmdhfmf.h
        src/cmdhfmfdes.c
        src/cmdhfmfdes.h
        src/cmdhfmfhard.c
        src/cmdhfmfhard.h
        src/cmdhfmfp.c
        src/cmdhfmfp.h
        src/cmdhfmfu.c
        src/cmdhfmfu.h
        src/cmdhfthinfilm.c
        src/cmdhfthinfilm.h
        src/cmdhftopaz.c
        src/cmdhftopaz.h
        src/cmdhw.c
        src/cmdhw.h
        src/cmdlf.c
        src/cmdlf.h
        src/cmdlfawid.c
        src/cmdlfawid.h
        src/cmdlfcotag.c
        src/cmdlfcotag.h
        src/cmdlfem4x.c
        src/cmdlfem4x.h
        src/cmdlffdx.c
        src/cmdlffdx.h
        src/cmdlfgallagher.c
        src/cmdlfgallagher.h
        src/cmdlfguard.c
        src/cmdlfguard.h
        src/cmdlfhid.c
        src/cmdlfhid.h
        src/cmdlfhitag.c
        src/cmdlfhitag.h
        src/cmdlfindala.c
        src/cmdlfindala.h
        src/cmdlfio.c
        src/cmdlfio.h
        src/cmdlfjablotron.c
        src/cmdlfjablotron.h
        src/cmdlfkeri.c
        src/cmdlfkeri.h
        src/cmdlfmotorola.c
        src/cmdlfmotorola.h
        src/cmdlfnedap.c
        src/cmdlfnedap.h
        src/cmdlfnexwatch.c
        src/cmdlfnexwatch.h
        src/cmdlfnoralsy.c
        src/cmdlfnoralsy.h
        src/cmdlfpac.c
        src/cmdlfpac.h
        src/cmdlfparadox.c
        src/cmdlfparadox.h
        src/cmdlfpcf7931.c
        src/cmdlfpcf7931.h
        src/cmdlfpresco.c
        src/cmdlfpresco.h
        src/cmdlfpyramid.c
        src/cmdlfpyramid.h
        src/cmdlfsecurakey.c
        src/cmdlfsecurakey.h
        src/cmdlft55xx.c
        src/cmdlft55xx.h
        src/cmdlfti.c
        src/cmdlfti.h
        src/cmdlfverichip.c
        src/cmdlfverichip.h
        src/cmdlfviking.c
        src/cmdlfviking.h
        src/cmdlfvisa2000.c
        src/cmdlfvisa2000.h
        src/cmdmain.c
        src/cmdmain.h
        src/cmdparser.c
        src/cmdparser.h
        src/cmdscript.c
        src/cmdscript.h
        src/cmdsmartcard.c
        src/cmdsmartcard.h
        src/cmdtrace.c
        src/cmdtrace.h
        src/cmdusart.c
        src/cmdusart.h
        src/cmdwiegand.c
        src/cmdwiegand.h
        src/comms.c
        src/comms.h
        src/elf.h
        src/emojis.h
        src/emojis_alt.h
        src/fileutils.c
        src/fileutils.h
        src/flash.c
        src/flash.h
        src/graph.c
        src/graph.h
        src/preferences.c
        src/preferences.h
        src/pm3_binlib.c
        src/pm3_binlib.h
        src/pm3_bit_limits.h
        src/pm3_bitlib.c
        src/pm3_bitlib.h
        src/polarssl_config.h
        src/prng.c
        src/prng.h
        src/proxendian.h
        src/scandir.c
        src/scandir.h
        src/scripting.c
        src/scripting.h
        src/tea.c
        src/tea.h
        src/ui.c
        src/ui.h
        src/util.c
        src/util.h
        src/whereami.c
        src/whereami.h
        src/wiegand_formats.c
        src/wiegand_formats.h
        src/wiegand_formatutils.c
        src/wiegand_formatutils.h
        )

set(ADDITIONAL_SRC "")
set(ADDITIONAL_LNK "")

set(X86_CPUS x86 x86_64 i686)

message(STATUS "CMAKE_SYSTEM_PROCESSOR := ${CMAKE_SYSTEM_PROCESSOR}")

if (APPLE)
    message("Apple device detected.")
    set(ADDITIONAL_SRC src/util_darwin.h  src/util_darwin.m ${ADDITIONAL_SRC})
    set(ADDITIONAL_LNK "-framework Foundation" "-framework AppKit")
    set_target_properties(proxmark3 PROPERTIES LINK_FLAGS "-Wl,-F/Library/Frameworks")
endif (APPLE)

if (MINGW)
    set(CMAKE_CXX_FLAGS "-mno-ms-bitfields -fexec-charset=cp850 ${CMAKE_CXX_FLAGS}")
endif (MINGW)

set(CMAKE_CXX_FLAGS "-Wall -Werror -O3")


if(NOT Qt5_FOUND)
    message("Qt5 library not found, not building gui")
    set(TARGET_SOURCES
            src/guidummy.cpp
            ${TARGET_SOURCES})
endif(NOT Qt5_FOUND)
if (Qt5_FOUND)
    message("Qt5 library found, building gui :)")
    set (TARGET_SOURCES
            src/proxgui.cpp
            src/proxgui.h
            src/proxguiqt.cpp
            src/proxguiqt.h
            ${TARGET_SOURCES})
    add_custom_command(OUTPUT src/proxguiqt.moc.cpp
            COMMAND "$(MOC) -o src/proxguiqt.moc.cpp proxguiqt.h"
            COMMENT "Creating src/proxguiqt.moc.cpp"
            )
    add_definitions("-DHAVE_GUI")
    set(ADDITIONAL_LNK Qt5::Core Qt5::Widgets Qt5::Gui ${ADDITIONAL_LNK})
endif (Qt5_FOUND)

add_executable(
        proxmark3
        ${TARGET_SOURCES}
)

find_library(jansson REQUIRED)
find_library(tinycbor REQUIRED)
find_library(lua REQUIRED)
find_library(mbedtls REQUIRED)
find_library(reveng REQUIRED)
find_library(z REQUIRED)
find_library(hardnested REQUIRED)

target_include_directories(proxmark3 PUBLIC mbedtls jansson lua tinycbor amiibo reveng z hardnested)
target_link_libraries(proxmark3 readline pthread m mbedtls jansson lua tinycbor amiibo reveng z hardnested ${ADDITIONAL_LNK})

install(TARGETS proxmark3 DESTINATION "bin")
install(DIRECTORY cmdscripts lualibs luascripts resources dictionaries DESTINATION "share/proxmark3")

add_custom_command(OUTPUT lualibs/pm3_cmd.lua
        COMMAND "awk -f pm3_cmd_h2lua.awk ../include/pm3_cmd.h >  lualibs/pm3_cmd.lua"
        COMMENT "Creating lualibs/pm3_cmd.lua"
        )

add_custom_command(OUTPUT lualibs/mfc_default_keys.lua
        COMMAND "awk -f default_keys_dic2lua.awk mfc_default_keys.dic >  lualibs/mfc_default_keys.lua"
        COMMENT "Creating lualibs/mfc_default_keys.lua"
        )

add_custom_command(OUTPUT src/ui/ui_overlays.h
        COMMAND "$(UIC) src/ui/overlays.ui > src/ui/ui_overlays.h"
        COMMENT "Creating ui/ui_overlays.h"
        )

#"make package" will trigger this
SET(CPACK_GENERATOR "DEB")
SET(CPACK_DEBIAN_PACKAGE_MAINTAINER "Iceman")
INCLUDE(CPack)