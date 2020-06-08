# MINGW:
#  On ProxSpace 3.4:
#    cmake -G"MSYS Makefiles" ..
#  On Proxspace 3.3 or less, you need to install cmake:
#    pacman -S mingw-w64-x86_64-cmake
#    /mingw64/bin/cmake -G"MSYS Makefiles" ..

cmake_minimum_required(VERSION 3.10)
project(proxmark3)
SET (PM3_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/..)

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
    set(Qt5_LIBRARIES ${${_qt_package}_LIBRARIES} ${Qt5_LIBRARIES})
    if(NOT ${_qt_package}_FOUND)
        set(Qt5_FOUND OFF)
    endif(NOT ${_qt_package}_FOUND)
endforeach()

find_package(PkgConfig)
if (NOT SKIPBT EQUAL 1)
    pkg_search_module(BLUEZ QUIET bluez)
endif()
pkg_search_module(PYTHON3 QUIET python3)
pkg_search_module(PYTHON3EMBED QUIET python3-embed)

add_subdirectory(${PM3_ROOT}/client/deps deps)

set (TARGET_SOURCES
        ${PM3_ROOT}/common/commonutil.c
        ${PM3_ROOT}/common/util_posix.c
        ${PM3_ROOT}/common/parity.c
        ${PM3_ROOT}/common/bucketsort.c
        ${PM3_ROOT}/common/crapto1/crapto1.c
        ${PM3_ROOT}/common/crapto1/crypto1.c
        ${PM3_ROOT}/common/crc.c
        ${PM3_ROOT}/common/crc16.c
        ${PM3_ROOT}/common/crc32.c
        ${PM3_ROOT}/common/crc64.c
        ${PM3_ROOT}/common/lfdemod.c
        ${PM3_ROOT}/common/legic_prng.c
        ${PM3_ROOT}/common/iso15693tools.c
        ${PM3_ROOT}/common/cardhelper.c
        ${PM3_ROOT}/common/generator.c
        ${PM3_ROOT}/client/src/crypto/asn1dump.c
        ${PM3_ROOT}/client/src/crypto/asn1utils.c
        ${PM3_ROOT}/client/src/crypto/libpcrypto.c
        ${PM3_ROOT}/client/src/emv/test/cda_test.c
        ${PM3_ROOT}/client/src/emv/test/crypto_test.c
        ${PM3_ROOT}/client/src/emv/test/cryptotest.c
        ${PM3_ROOT}/client/src/emv/test/dda_test.c
        ${PM3_ROOT}/client/src/emv/test/sda_test.c
        ${PM3_ROOT}/client/src/emv/apduinfo.c
        ${PM3_ROOT}/client/src/emv/cmdemv.c
        ${PM3_ROOT}/client/src/emv/crypto.c
        ${PM3_ROOT}/client/src/emv/crypto_polarssl.c
        ${PM3_ROOT}/client/src/emv/dol.c
        ${PM3_ROOT}/client/src/emv/dump.c
        ${PM3_ROOT}/client/src/emv/emv_pk.c
        ${PM3_ROOT}/client/src/emv/emv_pki.c
        ${PM3_ROOT}/client/src/emv/emv_pki_priv.c
        ${PM3_ROOT}/client/src/emv/emv_roca.c
        ${PM3_ROOT}/client/src/emv/emv_tags.c
        ${PM3_ROOT}/client/src/emv/emvcore.c
        ${PM3_ROOT}/client/src/emv/emvjson.c
        ${PM3_ROOT}/client/src/emv/tlv.c
        ${PM3_ROOT}/client/src/fido/additional_ca.c
        ${PM3_ROOT}/client/src/fido/cbortools.c
        ${PM3_ROOT}/client/src/fido/cose.c
        ${PM3_ROOT}/client/src/fido/fidocore.c
        ${PM3_ROOT}/client/src/loclass/cipher.c
        ${PM3_ROOT}/client/src/loclass/cipherutils.c
        ${PM3_ROOT}/client/src/loclass/elite_crack.c
        ${PM3_ROOT}/client/src/loclass/hash1_brute.c
        ${PM3_ROOT}/client/src/loclass/ikeys.c
        ${PM3_ROOT}/client/src/mifare/mad.c
        ${PM3_ROOT}/client/src/mifare/mfkey.c
        ${PM3_ROOT}/client/src/mifare/mifare4.c
        ${PM3_ROOT}/client/src/mifare/mifaredefault.c
        ${PM3_ROOT}/client/src/mifare/mifarehost.c
        ${PM3_ROOT}/client/src/mifare/ndef.c
        ${PM3_ROOT}/client/src/mifare/desfire_crypto.c
        ${PM3_ROOT}/client/src/uart/uart_posix.c
        ${PM3_ROOT}/client/src/uart/uart_win32.c
        ${PM3_ROOT}/client/src/ui/overlays.ui
        ${PM3_ROOT}/client/src/aidsearch.c
        ${PM3_ROOT}/client/src/cmdanalyse.c
        ${PM3_ROOT}/client/src/cmdcrc.c
        ${PM3_ROOT}/client/src/cmddata.c
        ${PM3_ROOT}/client/src/cmdflashmem.c
        ${PM3_ROOT}/client/src/cmdflashmemspiffs.c
        ${PM3_ROOT}/client/src/cmdhf.c
        ${PM3_ROOT}/client/src/cmdhf14a.c
        ${PM3_ROOT}/client/src/cmdhf14b.c
        ${PM3_ROOT}/client/src/cmdhf15.c
        ${PM3_ROOT}/client/src/cmdhfcryptorf.c
        ${PM3_ROOT}/client/src/cmdhfepa.c
        ${PM3_ROOT}/client/src/cmdhffelica.c
        ${PM3_ROOT}/client/src/cmdhffido.c
        ${PM3_ROOT}/client/src/cmdhficlass.c
        ${PM3_ROOT}/client/src/cmdhflegic.c
        ${PM3_ROOT}/client/src/cmdhflist.c
        ${PM3_ROOT}/client/src/cmdhflto.c
        ${PM3_ROOT}/client/src/cmdhfmf.c
        ${PM3_ROOT}/client/src/cmdhfmfdes.c
        ${PM3_ROOT}/client/src/cmdhfmfhard.c
        ${PM3_ROOT}/client/src/cmdhfmfp.c
        ${PM3_ROOT}/client/src/cmdhfmfu.c
        ${PM3_ROOT}/client/src/cmdhfthinfilm.c
        ${PM3_ROOT}/client/src/cmdhftopaz.c
        ${PM3_ROOT}/client/src/cmdhw.c
        ${PM3_ROOT}/client/src/cmdlf.c
        ${PM3_ROOT}/client/src/cmdlfawid.c
        ${PM3_ROOT}/client/src/cmdlfcotag.c
        ${PM3_ROOT}/client/src/cmdlfem4x.c
        ${PM3_ROOT}/client/src/cmdlffdx.c
        ${PM3_ROOT}/client/src/cmdlfgallagher.c
        ${PM3_ROOT}/client/src/cmdlfguard.c
        ${PM3_ROOT}/client/src/cmdlfhid.c
        ${PM3_ROOT}/client/src/cmdlfhitag.c
        ${PM3_ROOT}/client/src/cmdlfindala.c
        ${PM3_ROOT}/client/src/cmdlfio.c
        ${PM3_ROOT}/client/src/cmdlfjablotron.c
        ${PM3_ROOT}/client/src/cmdlfkeri.c
        ${PM3_ROOT}/client/src/cmdlfmotorola.c
        ${PM3_ROOT}/client/src/cmdlfnedap.c
        ${PM3_ROOT}/client/src/cmdlfnexwatch.c
        ${PM3_ROOT}/client/src/cmdlfnoralsy.c
        ${PM3_ROOT}/client/src/cmdlfpac.c
        ${PM3_ROOT}/client/src/cmdlfparadox.c
        ${PM3_ROOT}/client/src/cmdlfpcf7931.c
        ${PM3_ROOT}/client/src/cmdlfpresco.c
        ${PM3_ROOT}/client/src/cmdlfpyramid.c
        ${PM3_ROOT}/client/src/cmdlfsecurakey.c
        ${PM3_ROOT}/client/src/cmdlft55xx.c
        ${PM3_ROOT}/client/src/cmdlfti.c
        ${PM3_ROOT}/client/src/cmdlfverichip.c
        ${PM3_ROOT}/client/src/cmdlfviking.c
        ${PM3_ROOT}/client/src/cmdlfvisa2000.c
        ${PM3_ROOT}/client/src/cmdmain.c
        ${PM3_ROOT}/client/src/cmdparser.c
        ${PM3_ROOT}/client/src/cmdscript.c
        ${PM3_ROOT}/client/src/cmdsmartcard.c
        ${PM3_ROOT}/client/src/cmdtrace.c
        ${PM3_ROOT}/client/src/cmdusart.c
        ${PM3_ROOT}/client/src/cmdwiegand.c
        ${PM3_ROOT}/client/src/comms.c
        ${PM3_ROOT}/client/src/fileutils.c
        ${PM3_ROOT}/client/src/flash.c
        ${PM3_ROOT}/client/src/graph.c
        ${PM3_ROOT}/client/src/jansson_path.c
        ${PM3_ROOT}/client/src/preferences.c
        ${PM3_ROOT}/client/src/pm3_binlib.c
        ${PM3_ROOT}/client/src/pm3_bitlib.c
        ${PM3_ROOT}/client/src/prng.c
        ${PM3_ROOT}/client/src/scandir.c
        ${PM3_ROOT}/client/src/scripting.c
        ${PM3_ROOT}/client/src/tea.c
        ${PM3_ROOT}/client/src/ui.c
        ${PM3_ROOT}/client/src/util.c
        ${PM3_ROOT}/client/src/wiegand_formats.c
        ${PM3_ROOT}/client/src/wiegand_formatutils.c
        ${CMAKE_BINARY_DIR}/version.c
        )

add_custom_command(
    OUTPUT  ${CMAKE_BINARY_DIR}/version.c
    COMMAND sh ${PM3_ROOT}/tools/mkversion.sh > ${CMAKE_BINARY_DIR}/version.c || perl ${PM3_ROOT}/tools/mkversion.pl > ${CMAKE_BINARY_DIR}/version.c || ${CMAKE_COMMAND} -E copy ${PM3_ROOT}/common/default_version.c ${CMAKE_BINARY_DIR}/version.c
    DEPENDS ${PM3_ROOT}/common/default_version.c
)

set(ADDITIONAL_SRC "")
set(ADDITIONAL_LNK "")
set(ADDITIONAL_DIRS "")
set(ADDITIONAL_LNKDIRS "")
set(X86_CPUS x86 x86_64 i686)

message(STATUS "CMAKE_SYSTEM_PROCESSOR := ${CMAKE_SYSTEM_PROCESSOR}")

if (APPLE)
    message("Apple device detected.")
    set(ADDITIONAL_SRC ${PM3_ROOT}/client/src/util_darwin.h  ${PM3_ROOT}/client/src/util_darwin.m ${ADDITIONAL_SRC})
    set(ADDITIONAL_LNK "-framework Foundation" "-framework AppKit")
endif (APPLE)

if (Qt5_FOUND)
    message("Qt5 library found, building gui :)")
    set(CMAKE_AUTOMOC ON)
    set(CMAKE_AUTORCC ON)
    set(CMAKE_AUTOUIC ON)
    set (TARGET_SOURCES
            ${PM3_ROOT}/client/src/proxgui.cpp
            ${PM3_ROOT}/client/src/proxguiqt.cpp
            ${TARGET_SOURCES})

    add_definitions("-DHAVE_GUI")
    set(ADDITIONAL_LNK ${Qt5_LIBRARIES} ${ADDITIONAL_LNK})
else (Qt5_FOUND)
    message("Qt5 library not found, not building gui")
    set(TARGET_SOURCES
            ${PM3_ROOT}/client/src/guidummy.cpp
            ${TARGET_SOURCES})
endif (Qt5_FOUND)

if (NOT SKIPBT EQUAL 1)
    if (BLUEZ_FOUND)
        add_definitions("-DHAVE_BLUEZ")
        set(ADDITIONAL_LNK ${BLUEZ_LIBRARIES} ${ADDITIONAL_LNK})
    endif (BLUEZ_FOUND)
endif(NOT SKIPBT EQUAL 1)

if (PYTHON3EMBED_FOUND)
    message("Python3-embed library found, building with python3 support :)")
    add_definitions(-DHAVE_PYTHON)
    set(ADDITIONAL_DIRS ${PYTHON3EMBED_INCLUDE_DIRS} ${ADDITIONAL_DIRS})
    set(ADDITIONAL_LNK ${PYTHON3EMBED_LIBRARIES} ${ADDITIONAL_LNK})
    set(ADDITIONAL_LNKDIRS ${PYTHON3EMBED_LIBRARY_DIRS} ${ADDITIONAL_LNKDIRS})
elseif (PYTHON3_FOUND)
    message("Python3 library found, building with python3 support :)")
    add_definitions(-DHAVE_PYTHON)
    set(ADDITIONAL_DIRS ${PYTHON3_INCLUDE_DIRS} ${ADDITIONAL_DIRS})
    set(ADDITIONAL_LNK ${PYTHON3_LIBRARIES} ${ADDITIONAL_LNK})
    set(ADDITIONAL_LNKDIRS ${PYTHON3_LIBRARY_DIRS} ${ADDITIONAL_LNKDIRS})   
endif (PYTHON3EMBED_FOUND)

message(" ===================================================================)")
if (SKIPBT EQUAL 1)
    message("native BT support: skipped")
else (SKIPBT EQUAL 1)
    if (BLUEZ_FOUND)
        message("native BT support: Bluez found, enabled")
    else (BLUEZ_FOUND)
        message("native BT support: Bluez not found, disabled")
    endif (BLUEZ_FOUND)
endif(SKIPBT EQUAL 1)
message(" ===================================================================)")

add_executable(proxmark3
        ${PM3_ROOT}/client/src/proxmark3.c
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
        ${PM3_ROOT}/common
        ${PM3_ROOT}/common_fpga
        ${PM3_ROOT}/include
        ${PM3_ROOT}/client/src
        ${PM3_ROOT}/client/include
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
find_library(pm3rrg_rdv4_hardnested REQUIRED)
find_library(pm3rrg_rdv4_whereami REQUIRED)

target_link_libraries(proxmark3 PRIVATE
        bz2
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
        pm3rrg_rdv4_hardnested
        pm3rrg_rdv4_whereami
        ${ADDITIONAL_LNK})

# OSX have a hard time compiling python3 dependency with older cmake.
if (PYTHON3EMBED_FOUND OR PYTHON3_FOUND)
    if (NOT CMAKE_VERSION VERSION_LESS 3.13)
           target_link_directories(proxmark3 PRIVATE ${ADDITIONAL_LNKDIRS})
    elseif (APPLE)
           message( SEND_ERROR "Your CMAKE version is too old for Apple platform, please update to a version >=3.13" )
    endif (NOT CMAKE_VERSION VERSION_LESS 3.13)
endif (PYTHON3EMBED_FOUND OR PYTHON3_FOUND)

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
