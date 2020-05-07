# version
cmake_minimum_required(VERSION 3.4.1)

# We are build on android platform, so we need add def "ANDROID"
# NDK version for SDK 19 doesn't implement the whole C++11 standard in the STL.
# see: https://stackoverflow.com/questions/44736135/ndk-clang-error-undefined-reference-to-localeconv
# so we need add def getlocaledecpoint()='.'
add_definitions(-DANDROID -D"getlocaledecpoint()='.'" -DZ_SOLO)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99 -O3 -fvisibility=hidden -w")

# Root path into client
set(PM3_ROOT ../../)

add_subdirectory(../deps deps)

# client resources
add_library(pm3rrg_rdv4 SHARED
        ${PM3_ROOT}/common/util_posix.c
        ${PM3_ROOT}/common/crapto1/crapto1.c
        ${PM3_ROOT}/common/crapto1/crypto1.c
        ${PM3_ROOT}/common/crc.c
        ${PM3_ROOT}/common/crc16.c
        ${PM3_ROOT}/common/crc32.c
        ${PM3_ROOT}/common/crc64.c
        ${PM3_ROOT}/common/cardhelper.c
        ${PM3_ROOT}/common/parity.c
        ${PM3_ROOT}/common/commonutil.c
        ${PM3_ROOT}/common/generator.c
        ${PM3_ROOT}/common/lfdemod.c
        ${PM3_ROOT}/common/iso15693tools.c
        ${PM3_ROOT}/common/bucketsort.c
        ${PM3_ROOT}/common/legic_prng.c
        # client inside
        ${PM3_ROOT}/client/src/fileutils.c
        ${PM3_ROOT}/client/src/uart/uart_posix.c
        ${PM3_ROOT}/client/src/loclass/cipherutils.c
        ${PM3_ROOT}/client/src/loclass/cipher.c
        ${PM3_ROOT}/client/src/loclass/ikeys.c
        ${PM3_ROOT}/client/src/loclass/elite_crack.c
        ${PM3_ROOT}/client/src/emv/emvcore.c
        ${PM3_ROOT}/client/src/emv/cmdemv.c
        ${PM3_ROOT}/client/src/emv/tlv.c
        ${PM3_ROOT}/client/src/emv/dol.c
        ${PM3_ROOT}/client/src/emv/emv_tags.c
        ${PM3_ROOT}/client/src/emv/emv_roca.c
        ${PM3_ROOT}/client/src/emv/dump.c
        ${PM3_ROOT}/client/src/emv/crypto_polarssl.c
        ${PM3_ROOT}/client/src/emv/crypto.c
        ${PM3_ROOT}/client/src/emv/emv_pk.c
        ${PM3_ROOT}/client/src/emv/emv_pki.c
        ${PM3_ROOT}/client/src/emv/emvjson.c
        ${PM3_ROOT}/client/src/emv/apduinfo.c
        ${PM3_ROOT}/client/src/emv/test/cryptotest.c
        ${PM3_ROOT}/client/src/emv/test/sda_test.c
        ${PM3_ROOT}/client/src/emv/test/dda_test.c
        ${PM3_ROOT}/client/src/emv/test/cda_test.c
        ${PM3_ROOT}/client/src/emv/test/crypto_test.c
        ${PM3_ROOT}/client/src/emv/test/cryptotest.c
        ${PM3_ROOT}/client/src/emv/test/sda_test.c
        ${PM3_ROOT}/client/src/emv/test/dda_test.c
        ${PM3_ROOT}/client/src/emv/test/cda_test.c
        ${PM3_ROOT}/client/src/emv/test/crypto_test.c
        ${PM3_ROOT}/client/src/crypto/libpcrypto.c
        ${PM3_ROOT}/client/src/crypto/asn1utils.c
        ${PM3_ROOT}/client/src/crypto/asn1dump.c
        ${PM3_ROOT}/client/src/mifare/mad.c
        ${PM3_ROOT}/client/src/mifare/mfkey.c
        ${PM3_ROOT}/client/src/mifare/mifare4.c
        ${PM3_ROOT}/client/src/mifare/mifarehost.c
        ${PM3_ROOT}/client/src/mifare/ndef.c
        ${PM3_ROOT}/client/src/mifare/desfire_crypto.c
        ${PM3_ROOT}/client/src/mifare/mifaredefault.c
        ${PM3_ROOT}/client/src/fido/cose.c
        ${PM3_ROOT}/client/src/fido/fidocore.c
        ${PM3_ROOT}/client/src/fido/cbortools.c
        ${PM3_ROOT}/client/src/fido/additional_ca.c
        ${PM3_ROOT}/client/src/preferences.c
        ${PM3_ROOT}/client/src/graph.c
        ${PM3_ROOT}/client/src/ui.c
        ${PM3_ROOT}/client/src/tea.c
        ${PM3_ROOT}/client/src/util.c
        ${PM3_ROOT}/client/src/comms.c
        ${PM3_ROOT}/client/src/cmdcrc.c
        ${PM3_ROOT}/client/src/cmdanalyse.c
        ${PM3_ROOT}/client/src/cmddata.c
        ${PM3_ROOT}/client/src/cmdtrace.c
        ${PM3_ROOT}/client/src/cmdhf.c
        ${PM3_ROOT}/client/src/cmdhflto.c
        ${PM3_ROOT}/client/src/aidsearch.c
        ${PM3_ROOT}/client/src/cmdhf14a.c
        ${PM3_ROOT}/client/src/cmdhf14b.c
        ${PM3_ROOT}/client/src/cmdwiegand.c
        ${PM3_ROOT}/client/src/wiegand_formatutils.c
        ${PM3_ROOT}/client/src/wiegand_formats.c
        ${PM3_ROOT}/client/src/cmdlfmotorola.c
        ${PM3_ROOT}/client/src/cmdlfgallagher.c
        ${PM3_ROOT}/client/src/cmdhf15.c
        ${PM3_ROOT}/client/src/cmdhfepa.c
        ${PM3_ROOT}/client/src/cmdhflegic.c
        ${PM3_ROOT}/client/src/cmdhfthinfilm.c
        ${PM3_ROOT}/client/src/cmdflashmemspiffs.c
        ${PM3_ROOT}/client/src/cmdhffelica.c
        ${PM3_ROOT}/client/src/cmdhficlass.c
        ${PM3_ROOT}/client/src/cmdhflist.c
        ${PM3_ROOT}/client/src/cmdhfmf.c
        ${PM3_ROOT}/client/src/cmdhfmfdes.c
        ${PM3_ROOT}/client/src/cmdhfmfu.c
        ${PM3_ROOT}/client/src/cmdhfmfp.c
        ${PM3_ROOT}/client/src/cmdhffido.c
        ${PM3_ROOT}/client/src/cmdhftopaz.c
        ${PM3_ROOT}/client/src/cmdhw.c
        ${PM3_ROOT}/client/src/cmdlf.c
        ${PM3_ROOT}/client/src/cmdlfkeri.c
        ${PM3_ROOT}/client/src/cmdlffdx.c
        ${PM3_ROOT}/client/src/cmdlfio.c
        ${PM3_ROOT}/client/src/cmdlfem4x.c
        ${PM3_ROOT}/client/src/cmdlfhid.c
        ${PM3_ROOT}/client/src/cmdlfnedap.c
        ${PM3_ROOT}/client/src/cmdlfguard.c
        ${PM3_ROOT}/client/src/cmdlfhitag.c
        ${PM3_ROOT}/client/src/cmdlfjablotron.c
        ${PM3_ROOT}/client/src/cmdsmartcard.c
        ${PM3_ROOT}/client/src/cmdlfti.c
        ${PM3_ROOT}/client/src/cmdlfpac.c
        ${PM3_ROOT}/client/src/cmdlfnoralsy.c
        ${PM3_ROOT}/client/src/cmdlfnexwatch.c
        ${PM3_ROOT}/client/src/cmdlfpresco.c
        ${PM3_ROOT}/client/src/cmdlfindala.c
        ${PM3_ROOT}/client/src/cmdlfviking.c
        ${PM3_ROOT}/client/src/cmdlfsecurakey.c
        ${PM3_ROOT}/client/src/cmdlfpyramid.c
        ${PM3_ROOT}/client/src/cmdlfparadox.c
        ${PM3_ROOT}/client/src/cmdlfcotag.c
        ${PM3_ROOT}/client/src/cmdlfawid.c
        ${PM3_ROOT}/client/src/cmdparser.c
        ${PM3_ROOT}/client/src/cmdscript.c
        ${PM3_ROOT}/client/src/cmdlfvisa2000.c
        ${PM3_ROOT}/client/src/whereami.c
        ${PM3_ROOT}/client/src/cmdmain.c
        ${PM3_ROOT}/client/src/cmdflashmem.c
        ${PM3_ROOT}/client/src/scripting.c
        ${PM3_ROOT}/client/src/pm3_binlib.c
        ${PM3_ROOT}/client/src/pm3_bitlib.c
        ${PM3_ROOT}/client/src/cmdlft55xx.c
        ${PM3_ROOT}/client/src/cmdlfpcf7931.c
        ${PM3_ROOT}/client/src/cmdhfmfhard.c
        ${PM3_ROOT}/client/src/cmdusart.c
        # android resources
        jni_tools.c
        pm3_main.c
        )

# includes
target_include_directories(pm3rrg_rdv4 PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${PM3_ROOT}/include/
        ${PM3_ROOT}/common
        ${PM3_ROOT}/common_fpga
        ${PM3_ROOT}/client/src)

find_library(pm3rrg_rdv4_cliparser REQUIRED)
find_library(pm3rrg_rdv4_jansson REQUIRED)
find_library(pm3rrg_rdv4_tinycbor REQUIRED)
find_library(pm3rrg_rdv4_lua REQUIRED)
find_library(pm3rrg_rdv4_mbedtls REQUIRED)
find_library(pm3rrg_rdv4_reveng REQUIRED)
find_library(pm3rrg_rdv4_z REQUIRED)
find_library(pm3rrg_rdv4_hardnested REQUIRED)

target_link_libraries(pm3rrg_rdv4 pm3rrg_rdv4_hardnested pm3rrg_rdv4_mbedtls pm3rrg_rdv4_cliparser pm3rrg_rdv4_jansson pm3rrg_rdv4_lua pm3rrg_rdv4_tinycbor pm3rrg_rdv4_amiibo pm3rrg_rdv4_reveng pm3rrg_rdv4_z android log)