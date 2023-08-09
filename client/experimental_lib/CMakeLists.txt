#-----------------------------------------------------------------------------
# Copyright (C) Jonathan Westhues, Mar 2006
# Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# See LICENSE.txt for the text of the license.
#-----------------------------------------------------------------------------
# Usage:
#  mkdir build
#  cd build
#  cmake ..     (see below for options)
#  make         (VERBOSE=1 if needed)
#
# MINGW:
#  On ProxSpace 3.4:
#    cmake -G"MSYS Makefiles" ..
#  On Proxspace 3.3 or less, you need to install cmake:
#    pacman -S mingw-w64-x86_64-cmake
#    /mingw64/bin/cmake -G"MSYS Makefiles" ..
#
# Android cross-compilation: (ANDROID_ABI=arm64-v8a for a 64b version)
# cmake \
#    -DCMAKE_TOOLCHAIN_FILE=<path-to-your-android-ndk>/build/cmake/android.toolchain.cmake \
#    -DANDROID_ABI=armeabi-v7a \
#    -DANDROID_NATIVE_API_LEVEL=android-19 \
#    -DSKIPBT=1 -DSKIPPYTHON=1 -DSKIPPTHREAD=1 ..

message(STATUS "CMake ${CMAKE_VERSION}")
cmake_minimum_required(VERSION 3.10)
project(proxmark3)
SET (PM3_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/../..)

if(CMAKE_VERSION VERSION_LESS "3.7.0")
    set(CMAKE_INCLUDE_CURRENT_DIR ON)
endif()

find_package(PkgConfig)

if (NOT SKIPQT EQUAL 1)
    if(APPLE AND EXISTS /usr/local/opt/qt5)
        # Homebrew installs Qt5 (up to at least 5.11.0) in
        # /usr/local/opt/qt5. Ensure that it can be found by CMake
        # since it is not in the default /usr/local prefix.
        # Add it to PATHS so that it doesn't override the
        # CMAKE_PREFIX_PATH environment variable.
        # QT_FIND_PACKAGE_OPTIONS should be passed to find_package,
        # e.g. find_package(Qt5Core ${QT_FIND_PACKAGE_OPTIONS})
        list(APPEND QT_FIND_PACKAGE_OPTIONS PATHS /usr/local/opt/qt5)
    endif(APPLE AND EXISTS /usr/local/opt/qt5)
   if(APPLE AND EXISTS /opt/homebrew/opt/qt5)
        # Homebrew on Apple Silicon installs Qt5 in
        # /opt/homebrew/opt/qt5. Ensure that it can be found by CMake
        # since it is not in the default /usr/local prefix.
        # Add it to PATHS so that it doesn't override the
        # CMAKE_PREFIX_PATH environment variable.
        # QT_FIND_PACKAGE_OPTIONS should be passed to find_package,
        # e.g. find_package(Qt5Core ${QT_FIND_PACKAGE_OPTIONS})
        list(APPEND QT_FIND_PACKAGE_OPTIONS PATHS /opt/homebrew/opt/qt5)
    endif(APPLE AND EXISTS /opt/homebrew/opt/qt5)
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
endif (NOT SKIPQT EQUAL 1)

if (NOT SKIPBT EQUAL 1)
    pkg_search_module(BLUEZ QUIET bluez)
endif (NOT SKIPBT EQUAL 1)

if (NOT SKIPPYTHON EQUAL 1)
    pkg_search_module(PYTHON3 QUIET python3)
    pkg_search_module(PYTHON3EMBED QUIET python3-embed)
endif (NOT SKIPPYTHON EQUAL 1)

# If cross-compiled, we need to init source and build.
if (CMAKE_TOOLCHAIN_FILE)
    if (ANDROID)
        set(CFLAGS_EXTERNAL_LIB "CFLAGS=--target=${CMAKE_C_COMPILER_TARGET} -w")
    endif (ANDROID)
    set(EMBED_READLINE ON)
    set(EMBED_BZIP2 ON)
    set(EMBED_LZ4 ON)
endif (CMAKE_TOOLCHAIN_FILE)

if (EMBED_READLINE OR EMBED_BZIP2 OR EMBED_LZ4)
    include(ExternalProject)
endif (EMBED_READLINE OR EMBED_BZIP2 OR EMBED_LZ4)

if (NOT SKIPREADLINE EQUAL 1)
    if (APPLE)
      find_path(READLINE_INCLUDE_DIRS readline/readline.h /usr/local/opt/readline/include /opt/local/include /opt/include /usr/local/include /usr/include /opt/homebrew/opt/readline/include NO_DEFAULT_PATH)
      find_library(READLINE_LIBRARIES readline /usr/local/opt/readline/lib /opt/local/lib /opt/lib /usr/local/lib /usr/lib /opt/homebrew/opt/readline/lib NO_DEFAULT_PATH)
    endif (APPLE)
    if (EMBED_READLINE)
        ExternalProject_Add(ncurses
            URL                   http://ftp.gnu.org/pub/gnu/ncurses/ncurses-6.1.tar.gz
            PREFIX                deps/ncurses
            DOWNLOAD_DIR          ${CMAKE_CURRENT_SOURCE_DIR}/deps/ncurses
            CONFIGURE_COMMAND     ./configure CC=${CMAKE_C_COMPILER} CXX=${CMAKE_CXX_COMPILER} LD=${CMAKE_C_COMPILER} AR=${CMAKE_AR} RANLIB=${CMAKE_RANLIB} ${CFLAGS_EXTERNAL_LIB} --host=arm --disable-database  --with-fallbacks=ansi-generic,ansi-mini,color_xterm,dtterm,dumb,Eterm,Eterm-256color,Eterm-88color,eterm-color,gnome,gnome-256color,guru,hurd,iTerm.app,konsole,konsole-16color,konsole-256color,konsole-base,konsole-linux,konsole-solaris,konsole-vt100,kterm,kterm-color,linux,linux-16color,linux-basic,mac,mlterm,mlterm-256color,mrxvt,mrxvt-256color,mterm,mterm-ansi,mvterm,nsterm,nsterm-16color,nsterm-256color,pty,putty,putty-256color,putty-vt100,rxvt,rxvt-16color,rxvt-256color,rxvt-88color,rxvt-basic,rxvt-color,screen,screen-16color,screen-256color,simpleterm,st-16color,st-256color,st52,st52-color,stv52,tt,tt52,unknown,vt100,vt102,vte,vte-256color,xterm,xterm-16color,xterm-256color,xterm-88color,xterm-basic,xterm-bold,xterm-color,xterm-utf8,xterm-vt220,xterm-vt52,xterm1,xtermc,xtermm   --enable-termcap --without-ada --without-debug --without-dlsym --without-gpm --without-develop --without-tests --without-cxx-binding --with-termlib
            BUILD_IN_SOURCE       ON
            BUILD_COMMAND         make libs
            INSTALL_COMMAND       ""
            LOG_DOWNLOAD          ON
        )
        ExternalProject_Add_StepTargets(ncurses configure build install)

        ExternalProject_Add(readline
            URL                   ftp://ftp.gnu.org/gnu/readline/readline-8.2.tar.gz
            PREFIX                deps/readline
            DOWNLOAD_DIR          ${CMAKE_CURRENT_SOURCE_DIR}/deps/readline
            CONFIGURE_COMMAND     ./configure CC=${CMAKE_C_COMPILER} CXX=${CMAKE_CXX_COMPILER} LD=${CMAKE_C_COMPILER} AR=${CMAKE_AR} RANLIB=${CMAKE_RANLIB} ${CFLAGS_EXTERNAL_LIB} --host=arm --enable-static
            BUILD_IN_SOURCE       ON
            BUILD_COMMAND         make
            INSTALL_COMMAND       ""
            LOG_DOWNLOAD          ON
        )
        ExternalProject_Add_StepTargets(readline configure build install)
        set(READLINE_INCLUDE_DIRS ${CMAKE_CURRENT_BINARY_DIR}/deps/readline/src/)
        set(READLINE_LIBRARIES ${CMAKE_CURRENT_BINARY_DIR}/deps/readline/src/readline/libreadline.a ${CMAKE_CURRENT_BINARY_DIR}/deps/ncurses/src/ncurses/lib/libtinfo.a)
    else (EMBED_READLINE)
        find_path(READLINE_INCLUDE_DIRS readline/readline.h)
        find_library(READLINE_LIBRARIES readline)
    endif (EMBED_READLINE)
    if (READLINE_INCLUDE_DIRS AND READLINE_LIBRARIES)
        set(READLINE_FOUND ON)
    endif (READLINE_INCLUDE_DIRS AND READLINE_LIBRARIES)
else (NOT SKIPREADLINE EQUAL 1)
    if (NOT SKIPLINENOISE EQUAL 1)
        if (EXISTS ${PM3_ROOT}/client/deps/linenoise/)
            set(LINENOISE_LOCAL_FOUND ON)
        endif (EXISTS ${PM3_ROOT}/client/deps/linenoise/)
    endif (NOT SKIPLINENOISE EQUAL 1)
endif (NOT SKIPREADLINE EQUAL 1)

if (NOT SKIPJANSSONSYSTEM EQUAL 1)
    pkg_check_modules(PC_JANSSON QUIET jansson)
    find_path(JANSSON_INCLUDE_DIRS
            NAMES jansson.h
            HINTS ${PC_JANSSON_INCLUDEDIR} ${PC_JANSSON_INCLUDE_DIRS})
    find_library(JANSSON_LIBRARIES
            NAMES jansson libjansson
            HINTS ${PC_JANSSON_LIBDIR} ${PC_JANSSON_LIBRARY_DIRS})
    if (JANSSON_INCLUDE_DIRS AND JANSSON_LIBRARIES)
        set(JANSSON_FOUND ON)
    endif (JANSSON_INCLUDE_DIRS AND JANSSON_LIBRARIES)
endif (NOT SKIPJANSSONSYSTEM EQUAL 1)

if(EMBED_BZIP2)
    cmake_policy(SET CMP0114 NEW)
    set(BZIP2_BUILD_DIR ${CMAKE_CURRENT_BINARY_DIR}/deps/bzip2/src/bzip2)
    ExternalProject_Add(bzip2
        GIT_REPOSITORY        https://android.googlesource.com/platform/external/bzip2
        GIT_TAG               platform-tools-30.0.2
        PREFIX                deps/bzip2
        SOURCE_DIR            ${CMAKE_CURRENT_SOURCE_DIR}/deps/bzip2
        CONFIGURE_COMMAND     mkdir -p ${BZIP2_BUILD_DIR} && git archive --format tar HEAD | tar -C ${BZIP2_BUILD_DIR} -x
        BUILD_IN_SOURCE       ON
        BUILD_COMMAND         make -C ${BZIP2_BUILD_DIR} -j4 CC=${CMAKE_C_COMPILER} CXX=${CMAKE_CXX_COMPILER} LD=${CMAKE_C_COMPILER} AR=${CMAKE_AR} RANLIB=${CMAKE_RANLIB} ${CFLAGS_EXTERNAL_LIB} libbz2.a
        INSTALL_COMMAND       ""
        LOG_DOWNLOAD          ON
    )
    ExternalProject_Add_StepTargets(bzip2 configure build install)
    set(BZIP2_INCLUDE_DIRS ${CMAKE_CURRENT_BINARY_DIR}/deps/bzip2/src/bzip2)
    set(BZIP2_LIBRARIES ${CMAKE_CURRENT_BINARY_DIR}/deps/bzip2/src/bzip2/libbz2.a)
    set(BZIP2_FOUND ON)
else(EMBED_BZIP2)
    find_package (BZip2 REQUIRED)
endif(EMBED_BZIP2)

if(EMBED_LZ4)
    cmake_policy(SET CMP0114 NEW)
    set(LZ4_BUILD_DIR ${CMAKE_CURRENT_BINARY_DIR}/deps/lz4/src/lz4)
    # Specify SOURCE_DIR will cause some errors
    ExternalProject_Add(lz4
        GIT_REPOSITORY        https://android.googlesource.com/platform/external/lz4
        GIT_TAG               platform-tools-30.0.2
        PREFIX                deps/lz4
        # SOURCE_DIR            ${CMAKE_CURRENT_SOURCE_DIR}/deps/lz4
        CONFIGURE_COMMAND     mkdir -p ${LZ4_BUILD_DIR} && git archive --format tar HEAD | tar -C ${LZ4_BUILD_DIR} -x
        BUILD_IN_SOURCE       ON
        BUILD_COMMAND         make -C ${LZ4_BUILD_DIR}/lib -j4 CC=${CMAKE_C_COMPILER} CXX=${CMAKE_CXX_COMPILER} LD=${CMAKE_C_COMPILER} AR=${CMAKE_AR} RANLIB=${CMAKE_RANLIB} ${CFLAGS_EXTERNAL_LIB} liblz4.a
        INSTALL_COMMAND       ""
        LOG_DOWNLOAD          ON
    )
    ExternalProject_Add_StepTargets(lz4 configure build install)
    set(LZ4_INCLUDE_DIRS ${CMAKE_CURRENT_BINARY_DIR}/deps/lz4/src/lz4/lib)
    set(LZ4_LIBRARIES ${CMAKE_CURRENT_BINARY_DIR}/deps/lz4/src/lz4/lib/liblz4.a)
    set(LZ4_FOUND ON)
else(EMBED_LZ4)
    find_path(LZ4_INCLUDE_DIRS lz4frame.h)
    find_library(LZ4_LIBRARIES lz4)
endif(EMBED_LZ4)

if (LZ4_INCLUDE_DIRS AND LZ4_LIBRARIES)
    set(LZ4_FOUND ON)
endif (LZ4_INCLUDE_DIRS AND LZ4_LIBRARIES)

if (NOT SKIPWHEREAMISYSTEM EQUAL 1)
    find_path(WHEREAMI_INCLUDE_DIRS whereami.h)
    find_library(WHEREAMI_LIBRARIES whereami)
    if (WHEREAMI_INCLUDE_DIRS AND WHEREAMI_LIBRARIES)
        set(WHEREAMI_FOUND ON)
    endif (WHEREAMI_INCLUDE_DIRS AND WHEREAMI_LIBRARIES)
endif (NOT SKIPWHEREAMISYSTEM EQUAL 1)

add_subdirectory(${PM3_ROOT}/client/deps deps)

set (TARGET_SOURCES
        ${PM3_ROOT}/common/commonutil.c
        ${PM3_ROOT}/common/util_posix.c
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
        ${PM3_ROOT}/client/src/emv/cmdemv.c
        ${PM3_ROOT}/client/src/emv/crypto.c
        ${PM3_ROOT}/client/src/emv/crypto_polarssl.c
        ${PM3_ROOT}/client/src/emv/dol.c
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
        ${PM3_ROOT}/client/src/iso7816/apduinfo.c
        ${PM3_ROOT}/client/src/iso7816/iso7816core.c
        ${PM3_ROOT}/client/src/ksx6924/ksx6924core.c
        ${PM3_ROOT}/client/src/cipurse/cipursecrypto.c
        ${PM3_ROOT}/client/src/cipurse/cipursecore.c
        ${PM3_ROOT}/client/src/cipurse/cipursetest.c
        ${PM3_ROOT}/client/src/loclass/cipher.c
        ${PM3_ROOT}/client/src/loclass/cipherutils.c
        ${PM3_ROOT}/client/src/loclass/elite_crack.c
        ${PM3_ROOT}/client/src/loclass/hash1_brute.c
        ${PM3_ROOT}/client/src/loclass/ikeys.c
        ${PM3_ROOT}/client/src/mifare/mad.c
        ${PM3_ROOT}/client/src/mifare/aiddesfire.c
        ${PM3_ROOT}/client/src/mifare/mfkey.c
        ${PM3_ROOT}/client/src/mifare/mifare4.c
        ${PM3_ROOT}/client/src/mifare/mifaredefault.c
        ${PM3_ROOT}/client/src/mifare/mifarehost.c
        ${PM3_ROOT}/client/src/nfc/ndef.c
        ${PM3_ROOT}/client/src/mifare/lrpcrypto.c
        ${PM3_ROOT}/client/src/mifare/desfirecrypto.c
        ${PM3_ROOT}/client/src/mifare/desfiresecurechan.c
        ${PM3_ROOT}/client/src/mifare/desfirecore.c
        ${PM3_ROOT}/client/src/mifare/desfiretest.c
        ${PM3_ROOT}/client/src/mifare/gallaghercore.c
        ${PM3_ROOT}/client/src/uart/uart_posix.c
        ${PM3_ROOT}/client/src/uart/uart_win32.c
        ${PM3_ROOT}/client/src/ui/overlays.ui
        ${PM3_ROOT}/client/src/ui/image.ui
        ${PM3_ROOT}/client/src/aidsearch.c
        ${PM3_ROOT}/client/src/atrs.c
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
        ${PM3_ROOT}/client/src/cmdhfemrtd.c
        ${PM3_ROOT}/client/src/cmdhfepa.c
        ${PM3_ROOT}/client/src/cmdhffelica.c
        ${PM3_ROOT}/client/src/cmdhffido.c
        ${PM3_ROOT}/client/src/cmdhffudan.c
        ${PM3_ROOT}/client/src/cmdhfgallagher.c
        ${PM3_ROOT}/client/src/cmdhfcipurse.c
        ${PM3_ROOT}/client/src/cmdhficlass.c
        ${PM3_ROOT}/client/src/cmdhfjooki.c
        ${PM3_ROOT}/client/src/cmdhfksx6924.c
        ${PM3_ROOT}/client/src/cmdhflegic.c
        ${PM3_ROOT}/client/src/cmdhflist.c
        ${PM3_ROOT}/client/src/cmdhflto.c
        ${PM3_ROOT}/client/src/cmdhfmf.c
        ${PM3_ROOT}/client/src/cmdhfmfdes.c
        ${PM3_ROOT}/client/src/cmdhfmfhard.c
        ${PM3_ROOT}/client/src/cmdhfmfp.c
        ${PM3_ROOT}/client/src/cmdhfmfu.c
        ${PM3_ROOT}/client/src/cmdhfntag424.c
        ${PM3_ROOT}/client/src/cmdhfseos.c
        ${PM3_ROOT}/client/src/cmdhfst.c
        ${PM3_ROOT}/client/src/cmdhfst25ta.c
        ${PM3_ROOT}/client/src/cmdhftesla.c
        ${PM3_ROOT}/client/src/cmdhftexkom.c
        ${PM3_ROOT}/client/src/cmdhfthinfilm.c
        ${PM3_ROOT}/client/src/cmdhftopaz.c
        ${PM3_ROOT}/client/src/cmdhfvas.c
        ${PM3_ROOT}/client/src/cmdhfwaveshare.c
        ${PM3_ROOT}/client/src/cmdhfxerox.c
        ${PM3_ROOT}/client/src/cmdhw.c
        ${PM3_ROOT}/client/src/cmdlf.c
        ${PM3_ROOT}/client/src/cmdlfawid.c
        ${PM3_ROOT}/client/src/cmdlfcotag.c
        ${PM3_ROOT}/client/src/cmdlfdestron.c
        ${PM3_ROOT}/client/src/cmdlfem.c
        ${PM3_ROOT}/client/src/cmdlfem410x.c
        ${PM3_ROOT}/client/src/cmdlfem4x05.c
        ${PM3_ROOT}/client/src/cmdlfem4x50.c
        ${PM3_ROOT}/client/src/cmdlfem4x70.c
        ${PM3_ROOT}/client/src/cmdlffdxb.c
        ${PM3_ROOT}/client/src/cmdlfgallagher.c
        ${PM3_ROOT}/client/src/cmdlfguard.c
        ${PM3_ROOT}/client/src/cmdlfhid.c
        ${PM3_ROOT}/client/src/cmdlfhitag.c
        ${PM3_ROOT}/client/src/cmdlfidteck.c
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
        ${PM3_ROOT}/client/src/cmdlfviking.c
        ${PM3_ROOT}/client/src/cmdlfvisa2000.c
        ${PM3_ROOT}/client/src/cmdlfzx8211.c
        ${PM3_ROOT}/client/src/cmdmain.c
        ${PM3_ROOT}/client/src/cmdnfc.c
        ${PM3_ROOT}/client/src/cmdparser.c
        ${PM3_ROOT}/client/src/cmdpiv.c
        ${PM3_ROOT}/client/src/cmdscript.c
        ${PM3_ROOT}/client/src/cmdsmartcard.c
        ${PM3_ROOT}/client/src/cmdtrace.c
        ${PM3_ROOT}/client/src/cmdusart.c
        ${PM3_ROOT}/client/src/cmdwiegand.c
        ${PM3_ROOT}/client/src/comms.c
        ${PM3_ROOT}/client/src/fileutils.c
        ${PM3_ROOT}/client/src/flash.c
        ${PM3_ROOT}/client/src/graph.c
        ${PM3_ROOT}/client/src/iso4217.c
        ${PM3_ROOT}/client/src/jansson_path.c
        ${PM3_ROOT}/client/src/preferences.c
        ${PM3_ROOT}/client/src/pm3.c
        ${PM3_ROOT}/client/src/pm3_binlib.c
        ${PM3_ROOT}/client/src/pm3_bitlib.c
        ${PM3_ROOT}/client/src/pm3line.c
        ${PM3_ROOT}/client/src/scandir.c
        ${PM3_ROOT}/client/src/scripting.c
        ${PM3_ROOT}/client/src/ui.c
        ${PM3_ROOT}/client/src/util.c
        ${PM3_ROOT}/client/src/wiegand_formats.c
        ${PM3_ROOT}/client/src/wiegand_formatutils.c
        ${CMAKE_BINARY_DIR}/version_pm3.c
        )

add_custom_command(
    OUTPUT  ${CMAKE_BINARY_DIR}/version_pm3.c
    COMMAND sh ${PM3_ROOT}/tools/mkversion.sh ${CMAKE_BINARY_DIR}/version_pm3.c || ${CMAKE_COMMAND} -E copy ${PM3_ROOT}/common/default_version_pm3.c ${CMAKE_BINARY_DIR}/version_pm3.c
    DEPENDS ${PM3_ROOT}/common/default_version_pm3.c
)

set(ADDITIONAL_SRC "")
set(ADDITIONAL_LNK "")
set(ADDITIONAL_DIRS "")
set(ADDITIONAL_LNKDIRS "")
set(X86_CPUS x86 x86_64 i686)

message(STATUS "CMAKE_SYSTEM_PROCESSOR := ${CMAKE_SYSTEM_PROCESSOR}")

if (APPLE)
    message(STATUS "Apple device detected.")
    set(ADDITIONAL_SRC ${PM3_ROOT}/client/src/util_darwin.h  ${PM3_ROOT}/client/src/util_darwin.m ${ADDITIONAL_SRC})

    find_library(UIKIT_LIBRARY UIKit)
    if (NOT UIKIT_LIBRARY)
        message(STATUS "UIKit.framework NOT found!")
    else()
        message(STATUS "UIKit.framework found! ${UIKIT_LIBRARY}")
        set(ADDITIONAL_LNK "-framework Foundation" "-framework UIKit")
    endif()

    find_library(APPKIT_LIBRARY AppKit)
    if (NOT APPKIT_LIBRARY)
      message(STATUS "AppKit.framework NOT found!")
    else()
      message(STATUS "AppKit.framework found! ${APPKIT_LIBRARY}")
      set(ADDITIONAL_LNK "-framework Foundation" "-framework AppKit")
    endif()

endif (APPLE)

if ((NOT SKIPQT EQUAL 1) AND (Qt5_FOUND))
    set(CMAKE_AUTOMOC ON)
    set(CMAKE_AUTORCC ON)
    set(CMAKE_AUTOUIC ON)
    set (TARGET_SOURCES
            ${PM3_ROOT}/client/src/proxgui.cpp
            ${PM3_ROOT}/client/src/proxguiqt.cpp
            ${TARGET_SOURCES})

    add_definitions("-DHAVE_GUI")
    set(ADDITIONAL_LNK ${Qt5_LIBRARIES} ${ADDITIONAL_LNK})
else ((NOT SKIPQT EQUAL 1) AND (Qt5_FOUND))
    set(TARGET_SOURCES
            ${PM3_ROOT}/client/src/guidummy.cpp
            ${TARGET_SOURCES})
endif ((NOT SKIPQT EQUAL 1) AND (Qt5_FOUND))

if (NOT SKIPBT EQUAL 1)
    if (BLUEZ_FOUND)
        add_definitions("-DHAVE_BLUEZ")
        set(ADDITIONAL_LNK ${BLUEZ_LIBRARIES} ${ADDITIONAL_LNK})
    endif (BLUEZ_FOUND)
endif(NOT SKIPBT EQUAL 1)

if (JANSSON_FOUND)
    set(ADDITIONAL_DIRS ${JANSSON_INCLUDE_DIRS} ${ADDITIONAL_DIRS})
    set(ADDITIONAL_LNK ${JANSSON_LIBRARIES} ${ADDITIONAL_LNK})
endif (JANSSON_FOUND)

if (NOT SKIPPYTHON EQUAL 1)
    if (PYTHON3EMBED_FOUND)
        add_definitions(-DHAVE_PYTHON)
        set(ADDITIONAL_DIRS ${PYTHON3EMBED_INCLUDE_DIRS} ${ADDITIONAL_DIRS})
        set(ADDITIONAL_LNK ${PYTHON3EMBED_LIBRARIES} ${ADDITIONAL_LNK})
        set(ADDITIONAL_LNKDIRS ${PYTHON3EMBED_LIBRARY_DIRS} ${ADDITIONAL_LNKDIRS})
    elseif (PYTHON3_FOUND)
        add_definitions(-DHAVE_PYTHON)
        set(ADDITIONAL_DIRS ${PYTHON3_INCLUDE_DIRS} ${ADDITIONAL_DIRS})
        set(ADDITIONAL_LNK ${PYTHON3_LIBRARIES} ${ADDITIONAL_LNK})
        set(ADDITIONAL_LNKDIRS ${PYTHON3_LIBRARY_DIRS} ${ADDITIONAL_LNKDIRS})
    endif (PYTHON3EMBED_FOUND)
endif (NOT SKIPPYTHON EQUAL 1)

if (NOT SKIPREADLINE EQUAL 1)
    if (READLINE_FOUND)
        add_definitions("-DHAVE_READLINE")
        set(ADDITIONAL_DIRS ${READLINE_INCLUDE_DIRS} ${ADDITIONAL_DIRS})
        set(ADDITIONAL_LNK ${READLINE_LIBRARIES} ${ADDITIONAL_LNK})
    endif (READLINE_FOUND)
endif(NOT SKIPREADLINE EQUAL 1)

if (BZIP2_FOUND)
    set(ADDITIONAL_DIRS ${BZIP2_INCLUDE_DIRS} ${ADDITIONAL_DIRS})
    set(ADDITIONAL_LNK ${BZIP2_LIBRARIES} ${ADDITIONAL_LNK})
endif (BZIP2_FOUND)

if (LZ4_FOUND)
    set(ADDITIONAL_DIRS ${LZ4_INCLUDE_DIRS} ${ADDITIONAL_DIRS})
    set(ADDITIONAL_LNK ${LZ4_LIBRARIES} ${ADDITIONAL_LNK})
endif (LZ4_FOUND)

if (WHEREAMI_FOUND)
    set(ADDITIONAL_DIRS ${WHEREAMI_INCLUDE_DIRS} ${ADDITIONAL_DIRS})
    set(ADDITIONAL_LNK ${WHEREAMI_LIBRARIES} ${ADDITIONAL_LNK})
endif (WHEREAMI_FOUND)

message(STATUS "===================================================================")
execute_process(
    COMMAND sh ${PM3_ROOT}/tools/mkversion.sh --short
    OUTPUT_VARIABLE version_pm3
)
string(STRIP ${version_pm3} version_pm3)
message(STATUS "Version info:      ${version_pm3}")
if (SKIPQT EQUAL 1)
    message(STATUS "GUI support:       skipped")
else (SKIPQT EQUAL 1)
    if (Qt5_FOUND)
        message(STATUS "GUI support:       QT5 found, enabled")
    else (Qt5_FOUND)
        message(STATUS "GUI support:       QT5 not found, disabled")
    endif (Qt5_FOUND)
endif (SKIPQT EQUAL 1)

if (SKIPBT EQUAL 1)
    message(STATUS "native BT support: skipped")
else (SKIPBT EQUAL 1)
    if (BLUEZ_FOUND)
        message(STATUS "native BT support: Bluez found, enabled")
    else (BLUEZ_FOUND)
        message(STATUS "native BT support: Bluez not found, disabled")
    endif (BLUEZ_FOUND)
endif(SKIPBT EQUAL 1)

if (BZIP2_FOUND)
    if (EMBED_BZIP2)
        message(STATUS "Bzip2 library:     embedded")
    else (EMBED_BZIP2)
        message(STATUS "Bzip2 library:     system library found")
    endif (EMBED_BZIP2)
else (BZIP2_FOUND)
    message(SEND_ERROR "Bzip2 library:     Bzip2 not found")
endif (BZIP2_FOUND)

if (LZ4_FOUND)
    if (EMBED_LZ4)
        message(STATUS "LZ4 library:       embedded")
    else (EMBED_LZ4)
        message(STATUS "LZ4 library:       system library found")
    endif (EMBED_LZ4)
else (LZ4_FOUND)
    message(SEND_ERROR "LZ4 library:       LZ4 not found")
endif (LZ4_FOUND)

if (SKIPJANSSONSYSTEM EQUAL 1)
    message(STATUS "Jansson library:   local library forced")
else (SKIPJANSSONSYSTEM EQUAL 1)
    if (JANSSON_FOUND)
        message(STATUS "Jansson library:   system library found")
    else (JANSSON_FOUND)
        message(STATUS "Jansson library:   system library not found, using local library")
    endif (JANSSON_FOUND)
endif (SKIPJANSSONSYSTEM EQUAL 1)

if (SKIPPYTHON EQUAL 1)
    message(STATUS "Python3 library:   skipped")
else (SKIPPYTHON EQUAL 1)
    if (PYTHON3EMBED_FOUND)
        message(STATUS "Python3 library:   Python3 embed found, enabled")
    elseif (PYTHON3_FOUND)
        message(STATUS "Python3 library:   Python3 found, enabled")
    else (PYTHON3EMBED_FOUND)
        message(STATUS "Python3 library:   Python3 not found, disabled")
    endif (PYTHON3EMBED_FOUND)
endif(SKIPPYTHON EQUAL 1)

if (SKIPREADLINE EQUAL 1)
    message(STATUS "Readline library:  skipped")
else (SKIPREADLINE EQUAL 1)
    if (READLINE_FOUND)
        if (EMBED_READLINE)
            message(STATUS "Readline library:  embedded")
        else (EMBED_READLINE)
            message(STATUS "Readline library:  system library found")
        endif (EMBED_READLINE)
    else (READLINE_FOUND)
        message(STATUS "Readline library:  Readline not found, disabled")
    endif (READLINE_FOUND)
endif(SKIPREADLINE EQUAL 1)

if (NOT READLINE_FOUND)
    if (SKIPLINENOISE EQUAL 1)
        message(STATUS "Linenoise library: skipped")
    else (SKIPLINENOISE EQUAL 1)
        if (LINENOISE_LOCAL_FOUND)
            message(STATUS "Linenoise library: enabled")
        else (LINENOISE_LOCAL_FOUND)
            message(STATUS "Linenoise library: Linenoise not found, disabled")
        endif (LINENOISE_LOCAL_FOUND)
    endif (SKIPLINENOISE EQUAL 1)
endif (NOT READLINE_FOUND)

if (SKIPWHEREAMISYSTEM EQUAL 1)
    message(STATUS "Whereami library:  local library forced")
else (SKIPWHEREAMISYSTEM EQUAL 1)
    if (WHEREAMI_FOUND)
        message(STATUS "Whereami library:  system library found")
    else (WHEREAMI_FOUND)
        message(STATUS "Whereami library:  system library not found, using local library")
    endif (WHEREAMI_FOUND)
endif (SKIPWHEREAMISYSTEM EQUAL 1)

# Lua SWIG
if (EXISTS ${PM3_ROOT}/client/src/pm3_luawrap.c)
    set (TARGET_SOURCES
            ${PM3_ROOT}/client/src/pm3_luawrap.c
            ${TARGET_SOURCES})
    add_definitions(-DHAVE_LUA_SWIG)
    message(STATUS "Lua SWIG:          wrapper found")
endif (EXISTS ${PM3_ROOT}/client/src/pm3_luawrap.c)

# Python SWIG
if (NOT SKIPPYTHON EQUAL 1)
    if (PYTHON3EMBED_FOUND OR PYTHON3_FOUND)
        if (EXISTS ${PM3_ROOT}/client/src/pm3_pywrap.c)
            set (TARGET_SOURCES
                    ${PM3_ROOT}/client/src/pm3_pywrap.c
                    ${TARGET_SOURCES})
            add_definitions(-DHAVE_PYTHON_SWIG)
            message(STATUS "Python SWIG:       wrapper found")
        endif (EXISTS ${PM3_ROOT}/client/src/pm3_pywrap.c)
    endif (PYTHON3EMBED_FOUND OR PYTHON3_FOUND)
endif (NOT SKIPPYTHON EQUAL 1)
message(STATUS "===================================================================")

add_library(pm3rrg_rdv4 SHARED
        ${PM3_ROOT}/client/src/proxmark3.c
        ${TARGET_SOURCES}
        ${ADDITIONAL_SRC}
)

target_compile_definitions(pm3rrg_rdv4 PRIVATE LIBPM3)

target_compile_options(pm3rrg_rdv4 PUBLIC -Wall -Werror -O3)
if (EMBED_READLINE)
    if (NOT SKIPREADLINE EQUAL 1)
        add_dependencies(pm3rrg_rdv4 ncurses readline)
    endif (NOT SKIPREADLINE EQUAL 1)
endif (EMBED_READLINE)
if (EMBED_BZIP2)
    add_dependencies(pm3rrg_rdv4 bzip2)
endif (EMBED_BZIP2)
if (EMBED_LZ4)
    add_dependencies(pm3rrg_rdv4 lz4)
endif (EMBED_LZ4)

if (MINGW)
    # Mingw uses by default Microsoft printf, we want the GNU printf (e.g. for %z)
    # and setting _ISOC99_SOURCE sets internally __USE_MINGW_ANSI_STDIO=1
    # FTR __USE_MINGW_ANSI_STDIO seems deprecated in Mingw32
    # but not Mingw64 https://fr.osdn.net/projects/mingw/lists/archive/users/2019-January/000199.html
    target_compile_definitions(pm3rrg_rdv4 PRIVATE _ISOC99_SOURCE)

    set(CMAKE_C_FLAGS "-mno-ms-bitfields -fexec-charset=cp850 ${CMAKE_C_FLAGS}")
    set(CMAKE_CXX_FLAGS "-mno-ms-bitfields -fexec-charset=cp850 ${CMAKE_CXX_FLAGS}")

    # GCC 10 has issues with false positives on stringop-overflow,
    # let's disable them for now (cf https://gcc.gnu.org/bugzilla/show_bug.cgi?id=92955, https://gcc.gnu.org/bugzilla/show_bug.cgi?id=94335)
    # beware these flags didn't exist for GCC < 7
    if(CMAKE_COMPILER_IS_GNUCXX)
        execute_process(COMMAND ${CMAKE_C_COMPILER} -dumpversion OUTPUT_VARIABLE GCC_VERSION)
        if (GCC_VERSION VERSION_GREATER 10.0 OR GCC_VERSION VERSION_EQUAL 10.0)
            set(CMAKE_C_FLAGS "-Wno-stringop-overflow -Wno-error=stringop-overflow ${CMAKE_C_FLAGS}")
            set(CMAKE_CXX_FLAGS "-Wno-stringop-overflow -Wno-error=stringop-overflow ${CMAKE_CXX_FLAGS}")
        endif()
    endif(CMAKE_COMPILER_IS_GNUCXX)

endif (MINGW)

target_include_directories(pm3rrg_rdv4 PRIVATE
        ${PM3_ROOT}/common
        ${PM3_ROOT}/common_fpga
        ${PM3_ROOT}/include
        ${PM3_ROOT}/client/src
        ${PM3_ROOT}/client/include
        ${ADDITIONAL_DIRS}
)

if (NOT APPLE)
    # required for Raspberry Pi, but breaks with clang (OSX). Need to be at the end of the linker line.
    set(ADDITIONAL_LNK ${ADDITIONAL_LNK} -Wl,--as-needed -latomic -Wl,--no-as-needed)
endif (NOT APPLE)

if (NOT JANSSON_FOUND)
    set(ADDITIONAL_LNK pm3rrg_rdv4_jansson ${ADDITIONAL_LNK})
endif (NOT JANSSON_FOUND)

if (NOT READLINE_FOUND)
    if (LINENOISE_LOCAL_FOUND)
        add_definitions("-DHAVE_LINENOISE")
        set(ADDITIONAL_LNK pm3rrg_rdv4_linenoise ${ADDITIONAL_LNK})
    endif (LINENOISE_LOCAL_FOUND)
endif (NOT READLINE_FOUND)

if (NOT WHEREAMI_FOUND)
    set(ADDITIONAL_LNK pm3rrg_rdv4_whereami ${ADDITIONAL_LNK})
endif (NOT WHEREAMI_FOUND)

target_link_libraries(pm3rrg_rdv4 PRIVATE
        m
        pm3rrg_rdv4_mbedtls
        pm3rrg_rdv4_cliparser
        pm3rrg_rdv4_lua
        pm3rrg_rdv4_tinycbor
        pm3rrg_rdv4_amiibo
        pm3rrg_rdv4_reveng
        pm3rrg_rdv4_hardnested
        ${ADDITIONAL_LNK})

if (NOT SKIPPTHREAD EQUAL 1)
    target_link_libraries(pm3rrg_rdv4 PRIVATE pthread)
endif (NOT SKIPPTHREAD EQUAL 1)

if (NOT SKIPPYTHON EQUAL 1)
    # OSX have a hard time compiling python3 dependency with older cmake.
    if (PYTHON3EMBED_FOUND OR PYTHON3_FOUND)
        if (NOT CMAKE_VERSION VERSION_LESS 3.13)
               target_link_directories(pm3rrg_rdv4 PRIVATE ${ADDITIONAL_LNKDIRS})
        elseif (APPLE)
               message( SEND_ERROR "Your CMAKE version is too old for Apple platform, please update to a version >=3.13" )
        endif (NOT CMAKE_VERSION VERSION_LESS 3.13)
    endif (PYTHON3EMBED_FOUND OR PYTHON3_FOUND)
endif (NOT SKIPPYTHON EQUAL 1)
