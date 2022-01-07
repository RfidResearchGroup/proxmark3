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
# version
message(STATUS "CMake ${CMAKE_VERSION}")
cmake_minimum_required(VERSION 3.4.1)
project(proxmark3)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3 -fvisibility=hidden -w")

# Root path into client
set(PM3_ROOT ../../)

add_subdirectory(../deps deps)

# Build zlib deps at external
if (CMAKE_MAKE_PROGRAM MATCHES ".*ninja.*")
    set(BZIP2_INCLUDE_DIRS ${BZIP2_ROOT})
    set(BZIP2_LIBRARIES pm3rrg_rdv4_bzip2)
elseif (UNIX) # Cross compile at Unix Makefile System.
    # bzip2 dep.
    include(ExternalProject)
    set(CFLAGS_EXTERNAL_LIB "CFLAGS=--target=${CMAKE_C_COMPILER_TARGET} -w")
    set(BZIP2_BUILD_DIR ${CMAKE_CURRENT_BINARY_DIR}/deps/bzip2/src/bzip2)
    ExternalProject_Add(bzip2
            GIT_REPOSITORY https://android.googlesource.com/platform/external/bzip2
            GIT_TAG platform-tools-30.0.2
            PREFIX deps/bzip2
            #SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/deps/bzip2
            CONFIGURE_COMMAND mkdir -p ${BZIP2_BUILD_DIR} && git archive --format tar HEAD | tar -C ${BZIP2_BUILD_DIR} -x
            BUILD_IN_SOURCE ON
            BUILD_COMMAND make -C ${BZIP2_BUILD_DIR} -j4 CC=${CMAKE_C_COMPILER} CXX=${CMAKE_CXX_COMPILER} LD=${CMAKE_C_COMPILER} AR=${CMAKE_AR} RANLIB=${CMAKE_RANLIB} ${CFLAGS_EXTERNAL_LIB} libbz2.a
            INSTALL_COMMAND ""
            LOG_DOWNLOAD ON
            )
    ExternalProject_Add_StepTargets(bzip2 configure build install)
    set(BZIP2_INCLUDE_DIRS ${CMAKE_CURRENT_BINARY_DIR}/deps/bzip2/src/bzip2)
    set(BZIP2_LIBRARIES ${CMAKE_CURRENT_BINARY_DIR}/deps/bzip2/src/bzip2/libbz2.a)
else ()
    message(ERROR "Please implement your BZIP2 import.")
endif ()

# client resources
add_library(pm3rrg_rdv4 SHARED
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
        ${PM3_ROOT}/client/src/cmdhfseos.c
        ${PM3_ROOT}/client/src/cmdhfst.c
        ${PM3_ROOT}/client/src/cmdhfst25ta.c
        ${PM3_ROOT}/client/src/cmdhfthinfilm.c
        ${PM3_ROOT}/client/src/cmdhftopaz.c
        ${PM3_ROOT}/client/src/cmdhfwaveshare.c
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
        # android resources
        jni_tools.c
        pm3_main.c
        )

# includes
target_include_directories(pm3rrg_rdv4 PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${BZIP2_INCLUDE_DIRS}
        ${PM3_ROOT}/common
        ${PM3_ROOT}/common_fpga
        ${PM3_ROOT}/include
        ${PM3_ROOT}/client/src
        ${PM3_ROOT}/client/include
        )

target_link_libraries(pm3rrg_rdv4
        ${BZIP2_LIBRARIES}
        pm3rrg_rdv4_hardnested
        pm3rrg_rdv4_mbedtls
        pm3rrg_rdv4_cliparser
        pm3rrg_rdv4_jansson
        pm3rrg_rdv4_lua
        pm3rrg_rdv4_tinycbor
        pm3rrg_rdv4_amiibo
        pm3rrg_rdv4_reveng
        pm3rrg_rdv4_whereami
        android
        log)
