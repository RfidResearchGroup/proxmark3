# MINGW:
#  On ProxSpace 3.4:
#    cmake -G"MSYS Makefiles" ..
#  On Proxspace 3.3 or less, you need to install cmake:
#    pacman -S mingw-w64-x86_64-cmake
#    /mingw64/bin/cmake -G"MSYS Makefiles" ..

cmake_minimum_required(VERSION 3.10)
project(proxmark3)

if(CMAKE_VERSION VERSION_LESS "3.7.0")
    set(CMAKE_INCLUDE_CURRENT_DIR ON)
endif()

if(APPLE AND EXISTS /usr/local/opt/qt5)
    # Homebrew installs Qt5 (up to at least 5.11.0) in
    # /usr/local/qt5. Ensure that it can be found by CMake
    # since it is not in the default /usr/local prefix.
    # Add it to PATHS so that it doesn't override the
    # CMAKE_PREFIX_PATH environment variable.
    # QT_FIND_PACKAGE_OPTIONS should be passed to find_package,
    # e.g. find_package(Qt5Core ${QT_FIND_PACKAGE_OPTIONS})
    list(APPEND QT_FIND_PACKAGE_OPTIONS PATHS /usr/local/opt/qt5)
endif()
set(QT_PACKAGELIST
    Qt5Core
    Qt5Widgets
    Qt5Gui
)
set(Qt5_FOUND ON)
foreach(_qt_package IN LISTS QT_PACKAGELIST)
    find_package(${_qt_package} QUIET ${QT_FIND_PACKAGE_OPTIONS})
    if(NOT ${_qt_package}_FOUND)
        set(Qt5_FOUND OFF)
    endif(NOT ${_qt_package}_FOUND)
endforeach()

find_package(PkgConfig)
pkg_search_module(BLUEZ QUIET bluez)
pkg_search_module(PYTHON3 QUIET python3)
pkg_search_module(PYTHON3EMBED QUIET python3-embed)

SET (CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

add_subdirectory(deps)

set (TARGET_SOURCES
        src/proxmark3.c
        ../common/commonutil.c
        ../common/util_posix.c
        ../common/parity.c
        ../common/bucketsort.c
        ../common/crapto1/crapto1.c
        ../common/crapto1/crypto1.c
        ../common/crc.c
        ../common/crc16.c
        ../common/crc32.c
        ../common/crc64.c
        ../common/lfdemod.c
        ../common/legic_prng.c
        ../common/iso15693tools.c
        ../common/cardhelper.c
        ../common/generator.c
        src/crypto/asn1dump.c
        src/crypto/asn1utils.c
        src/crypto/libpcrypto.c
        src/emv/test/cda_test.c
        src/emv/test/crypto_test.c
        src/emv/test/cryptotest.c
        src/emv/test/dda_test.c
        src/emv/test/sda_test.c
        src/emv/apduinfo.c
        src/emv/cmdemv.c
        src/emv/crypto.c
        src/emv/crypto_polarssl.c
        src/emv/dol.c
        src/emv/dump.c
        src/emv/emv_pk.c
        src/emv/emv_pki.c
        src/emv/emv_pki_priv.c
        src/emv/emv_roca.c
        src/emv/emv_tags.c
        src/emv/emvcore.c
        src/emv/emvjson.c
        src/emv/tlv.c
        src/fido/additional_ca.c
        src/fido/cbortools.c
        src/fido/cose.c
        src/fido/fidocore.c
        src/loclass/cipher.c
        src/loclass/cipherutils.c
        src/loclass/elite_crack.c
        src/loclass/hash1_brute.c
        src/loclass/ikeys.c
        src/mifare/mad.c
        src/mifare/mfkey.c
        src/mifare/mifare4.c
        src/mifare/mifaredefault.c
        src/mifare/mifarehost.c
        src/mifare/ndef.c
        src/mifare/desfire_crypto.c
        src/uart/uart_posix.c
        src/uart/uart_win32.c
        src/ui/overlays.ui
        src/aidsearch.c
        src/cmdanalyse.c
        src/cmdcrc.c
        src/cmddata.c
        src/cmdflashmem.c
        src/cmdflashmemspiffs.c
        src/cmdhf.c
        src/cmdhf14a.c
        src/cmdhf14b.c
        src/cmdhf15.c
        src/cmdhfcryptorf.c
        src/cmdhfepa.c
        src/cmdhffelica.c
        src/cmdhffido.c
        src/cmdhficlass.c
        src/cmdhflegic.c
        src/cmdhflist.c
        src/cmdhflto.c
        src/cmdhfmf.c
        src/cmdhfmfdes.c
        src/cmdhfmfhard.c
        src/cmdhfmfp.c
        src/cmdhfmfu.c
        src/cmdhfthinfilm.c
        src/cmdhftopaz.c
        src/cmdhw.c
        src/cmdlf.c
        src/cmdlfawid.c
        src/cmdlfcotag.c
        src/cmdlfem4x.c
        src/cmdlffdx.c
        src/cmdlfgallagher.c
        src/cmdlfguard.c
        src/cmdlfhid.c
        src/cmdlfhitag.c
        src/cmdlfindala.c
        src/cmdlfio.c
        src/cmdlfjablotron.c
        src/cmdlfkeri.c
        src/cmdlfmotorola.c
        src/cmdlfnedap.c
        src/cmdlfnexwatch.c
        src/cmdlfnoralsy.c
        src/cmdlfpac.c
        src/cmdlfparadox.c
        src/cmdlfpcf7931.c
        src/cmdlfpresco.c
        src/cmdlfpyramid.c
        src/cmdlfsecurakey.c
        src/cmdlft55xx.c
        src/cmdlfti.c
        src/cmdlfverichip.c
        src/cmdlfviking.c
        src/cmdlfvisa2000.c
        src/cmdmain.c
        src/cmdparser.c
        src/cmdscript.c
        src/cmdsmartcard.c
        src/cmdtrace.c
        src/cmdusart.c
        src/cmdwiegand.c
        src/comms.c
        src/fileutils.c
        src/flash.c
        src/graph.c
        src/jansson_path.c
        src/preferences.c
        src/pm3_binlib.c
        src/pm3_bitlib.c
        src/prng.c
        src/scandir.c
        src/scripting.c
        src/tea.c
        src/ui.c
        src/util.c
        src/wiegand_formats.c
        src/wiegand_formatutils.c
        ${CMAKE_BINARY_DIR}/version.c
        )

add_custom_command(
    OUTPUT  ${CMAKE_BINARY_DIR}/version.c
    COMMAND sh ${CMAKE_SOURCE_DIR}/../tools/mkversion.sh > ${CMAKE_BINARY_DIR}/version.c || perl ${CMAKE_SOURCE_DIR}/../tools/mkversion.pl > ${CMAKE_BINARY_DIR}/version.c || ${CMAKE_COMMAND} -E copy ${CMAKE_SOURCE_DIR}/../common/default_version.c ${CMAKE_BINARY_DIR}/version.c
    DEPENDS ${CMAKE_SOURCE_DIR}/../common/default_version.c
)

set(ADDITIONAL_SRC "")
set(ADDITIONAL_LNK "")
set(ADDITIONAL_DIRS "")
set(X86_CPUS x86 x86_64 i686)

message(STATUS "CMAKE_SYSTEM_PROCESSOR := ${CMAKE_SYSTEM_PROCESSOR}")

if (APPLE)
    message("Apple device detected.")
    set(ADDITIONAL_SRC src/util_darwin.h  src/util_darwin.m ${ADDITIONAL_SRC})
    set(ADDITIONAL_LNK "-framework Foundation" "-framework AppKit")
endif (APPLE)

if (Qt5_FOUND)
    message("Qt5 library found, building gui :)")
    set(CMAKE_AUTOMOC ON)
    set(CMAKE_AUTORCC ON)
    set(CMAKE_AUTOUIC ON)
    set (TARGET_SOURCES
            src/proxgui.cpp
            src/proxguiqt.cpp
            ${TARGET_SOURCES})

    add_definitions("-DHAVE_GUI")
    set(ADDITIONAL_LNK Qt5::Core Qt5::Widgets Qt5::Gui ${ADDITIONAL_LNK})
else (Qt5_FOUND)
    message("Qt5 library not found, not building gui")
    set(TARGET_SOURCES
            src/guidummy.cpp
            ${TARGET_SOURCES})
endif (Qt5_FOUND)

if (BLUEZ_FOUND)
    message("Bluez library found, building native Bluetooth support :)")
    add_definitions("-DHAVE_BLUEZ")
    set(ADDITIONAL_LNK bluetooth ${ADDITIONAL_LNK})
endif (BLUEZ_FOUND)

if (PYTHON3EMBED_FOUND)
    message("Python3 library found, building with python3 support :)")
    add_definitions("-DHAVE_PYTHON")
    set(ADDITIONAL_DIRS ${PYTHON3EMBED_INCLUDE_DIRS} ${ADDITIONAL_DIRS})
    set(ADDITIONAL_LNK ${PYTHON3EMBED_LIBRARIES} ${ADDITIONAL_LNK})
    set(ADDITIONAL_LNKDIRS ${PYTHON3EMBED_LIBRARY_DIRS} ${ADDITIONAL_LNKDIRS})
elseif (PYTHON3_FOUND)
    message("Python3 library found, building with python3 support :)")
    add_definitions("-DHAVE_PYTHON")
    set(ADDITIONAL_DIRS ${PYTHON3_INCLUDE_DIRS} ${ADDITIONAL_DIRS})
    set(ADDITIONAL_LNK ${PYTHON3_LIBRARIES} ${ADDITIONAL_LNK})
    set(ADDITIONAL_LNKDIRS ${PYTHON3_LIBRARY_DIRS} ${ADDITIONAL_LNKDIRS})
endif (PYTHON3EMBED_FOUND)

add_executable(
        proxmark3
        ${TARGET_SOURCES}
        ${ADDITIONAL_SRC}
)

target_compile_options(proxmark3 PUBLIC -Wall -Werror -O3)

if (MINGW)
    # Mingw uses by default Microsoft printf, we want the GNU printf (e.g. for %z)
    # and setting _ISOC99_SOURCE sets internally __USE_MINGW_ANSI_STDIO=1
    # FTR __USE_MINGW_ANSI_STDIO seems deprecated in Mingw32
    # but not Mingw64 https://fr.osdn.net/projects/mingw/lists/archive/users/2019-January/000199.html
    target_compile_definitions(proxmark3 PRIVATE _ISOC99_SOURCE)

    set(CMAKE_C_FLAGS "-mno-ms-bitfields -fexec-charset=cp850 ${CMAKE_C_FLAGS}")
    set(CMAKE_CXX_FLAGS "-mno-ms-bitfields -fexec-charset=cp850 ${CMAKE_CXX_FLAGS}")
endif (MINGW)

target_include_directories(proxmark3 PRIVATE
        ../common
        ../common_fpga
        ../include
        src
        ${ADDITIONAL_DIRS}
)

if (APPLE)
    set_target_properties(proxmark3 PROPERTIES LINK_FLAGS "-Wl,-F/Library/Frameworks, -L/usr/local/opt/readline/lib")
    set_target_properties(proxmark3 PROPERTIES COMPILE_FLAGS "-I/usr/local/opt/readline/include")
else (APPLE)
    # required for Raspberry Pi, but breaks with clang (OSX). Need to be at the end of the linker line.
    set(ADDITIONAL_LNK ${ADDITIONAL_LNK} -Wl,--as-needed -latomic -Wl,--no-as-needed)
endif (APPLE)


find_library(pm3rrg_rdv4_cliparser REQUIRED)
find_library(pm3rrg_rdv4_jansson REQUIRED)
find_library(pm3rrg_rdv4_tinycbor REQUIRED)
find_library(pm3rrg_rdv4_lua REQUIRED)
find_library(pm3rrg_rdv4_mbedtls REQUIRED)
find_library(pm3rrg_rdv4_reveng REQUIRED)
find_library(pm3rrg_rdv4_z REQUIRED)
find_library(pm3rrg_rdv4_hardnested REQUIRED)
find_library(pm3rrg_rdv4_whereami REQUIRED)

target_link_libraries(proxmark3 PRIVATE
        readline
        pthread
        m
        pm3rrg_rdv4_mbedtls
        pm3rrg_rdv4_cliparser
        pm3rrg_rdv4_jansson
        pm3rrg_rdv4_lua
        pm3rrg_rdv4_tinycbor
        pm3rrg_rdv4_amiibo
        pm3rrg_rdv4_reveng
        pm3rrg_rdv4_z
        pm3rrg_rdv4_hardnested
        pm3rrg_rdv4_whereami
        ${ADDITIONAL_LNK})

target_link_directories(proxmark3 PRIVATE ${ADDITIONAL_LNKDIRS})

install(TARGETS proxmark3 DESTINATION "bin")
install(DIRECTORY cmdscripts lualibs luascripts pyscripts resources dictionaries DESTINATION "share/proxmark3")

add_custom_command(OUTPUT lualibs/pm3_cmd.lua
        COMMAND "awk -f pm3_cmd_h2lua.awk ../include/pm3_cmd.h >  lualibs/pm3_cmd.lua"
        COMMENT "Creating lualibs/pm3_cmd.lua"
        )

add_custom_command(OUTPUT lualibs/mfc_default_keys.lua
        COMMAND "awk -f default_keys_dic2lua.awk mfc_default_keys.dic >  lualibs/mfc_default_keys.lua"
        COMMENT "Creating lualibs/mfc_default_keys.lua"
        )

#"make package" will trigger this
SET(CPACK_GENERATOR "DEB")
SET(CPACK_DEBIAN_PACKAGE_MAINTAINER "Iceman")
INCLUDE(CPack)
