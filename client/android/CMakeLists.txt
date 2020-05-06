#需要的最cmake版本
cmake_minimum_required(VERSION 3.4.1)

#添加预编译宏定义参数，此次的作用是开启配置文件的引入!
add_definitions(-DANDROID -D"getlocaledecpoint()='.'" -DZ_SOLO)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99 -O3 -fvisibility=hidden -w")

#缩短路径定义
set(PM3_ROOT ../../)

#添加动态库定义
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
        ${PM3_ROOT}/common/mbedtls/aes.c
        ${PM3_ROOT}/common/mbedtls/base64.c
        ${PM3_ROOT}/common/mbedtls/rsa.c
        ${PM3_ROOT}/common/mbedtls/rsa_internal.c
        ${PM3_ROOT}/common/mbedtls/arc4.c
        ${PM3_ROOT}/common/mbedtls/bignum.c
        ${PM3_ROOT}/common/mbedtls/asn1parse.c
        ${PM3_ROOT}/common/mbedtls/asn1write.c
        ${PM3_ROOT}/common/mbedtls/blowfish.c
        ${PM3_ROOT}/common/mbedtls/camellia.c
        ${PM3_ROOT}/common/mbedtls/certs.c
        ${PM3_ROOT}/common/mbedtls/des.c
        ${PM3_ROOT}/common/mbedtls/ecdsa.c
        ${PM3_ROOT}/common/mbedtls/ecp.c
        ${PM3_ROOT}/common/mbedtls/ecp_curves.c
        ${PM3_ROOT}/common/mbedtls/entropy.c
        ${PM3_ROOT}/common/mbedtls/entropy_poll.c
        ${PM3_ROOT}/common/mbedtls/error.c
        ${PM3_ROOT}/common/mbedtls/md.c
        ${PM3_ROOT}/common/mbedtls/md5.c
        ${PM3_ROOT}/common/mbedtls/md_wrap.c
        ${PM3_ROOT}/common/mbedtls/sha1.c
        ${PM3_ROOT}/common/mbedtls/sha256.c
        ${PM3_ROOT}/common/mbedtls/sha512.c
        ${PM3_ROOT}/common/mbedtls/timing.c
        ${PM3_ROOT}/common/mbedtls/cmac.c
        ${PM3_ROOT}/common/mbedtls/oid.c
        ${PM3_ROOT}/common/mbedtls/pem.c
        ${PM3_ROOT}/common/mbedtls/pk.c
        ${PM3_ROOT}/common/mbedtls/pk_wrap.c
        ${PM3_ROOT}/common/mbedtls/pkcs5.c
        ${PM3_ROOT}/common/mbedtls/pkcs12.c
        ${PM3_ROOT}/common/mbedtls/pkparse.c
        ${PM3_ROOT}/common/mbedtls/pkwrite.c
        ${PM3_ROOT}/common/mbedtls/x509.c
        ${PM3_ROOT}/common/mbedtls/x509_crl.c
        ${PM3_ROOT}/common/mbedtls/x509_crt.c
        ${PM3_ROOT}/common/mbedtls/ctr_drbg.c
        ${PM3_ROOT}/common/mbedtls/cipher_wrap.c
        ${PM3_ROOT}/common/mbedtls/cipher.c
        ${PM3_ROOT}/common/mbedtls/platform_util.c
        ${PM3_ROOT}/common//zlib/inflate.c
        ${PM3_ROOT}/common/zlib/inffast.c
        ${PM3_ROOT}/common/zlib/zutil.c
        ${PM3_ROOT}/common/zlib/inftrees.c
        ${PM3_ROOT}/common//zlib/adler32.c
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
        # deps ouside
        ${PM3_ROOT}/client/deps/jansson/utf.c
        ${PM3_ROOT}/client/deps/jansson/dump.c
        ${PM3_ROOT}/client/deps/jansson/path.c
        ${PM3_ROOT}/client/deps/jansson/load.c
        ${PM3_ROOT}/client/deps/jansson/error.c
        ${PM3_ROOT}/client/deps/jansson/value.c
        ${PM3_ROOT}/client/deps/jansson/memory.c
        ${PM3_ROOT}/client/deps/jansson/pack_unpack.c
        ${PM3_ROOT}/client/deps/jansson/hashtable_seed.c
        ${PM3_ROOT}/client/deps/jansson/strbuffer.c
        ${PM3_ROOT}/client/deps/jansson/strconv.c
        ${PM3_ROOT}/client/deps/jansson/hashtable.c
        ${PM3_ROOT}/client/deps/jansson/hashtable.c
        # cliparser
        ${PM3_ROOT}/client/deps/cliparser/cliparser.c
        ${PM3_ROOT}/client/deps/cliparser/argtable3.c
        # tinycbor
        ${PM3_ROOT}/client/deps/tinycbor/cborencoder.c
        ${PM3_ROOT}/client/deps/tinycbor/cborencoder_close_container_checked.c
        ${PM3_ROOT}/client/deps/tinycbor/cborerrorstrings.c
        ${PM3_ROOT}/client/deps/tinycbor/cborparser.c
        ${PM3_ROOT}/client/deps/tinycbor/cborparser_dup_string.c
        ${PM3_ROOT}/client/deps/tinycbor/cborpretty.c
        ${PM3_ROOT}/client/deps/tinycbor/cborpretty_stdio.c
        ${PM3_ROOT}/client/deps/tinycbor/cbortojson.c
        ${PM3_ROOT}/client/deps/tinycbor/cborvalidation.c
        ${PM3_ROOT}/client/deps/tinycbor/open_memstream.c
        # reveng
        ${PM3_ROOT}/client/deps/reveng/cli.c
        ${PM3_ROOT}/client/deps/reveng/bmpbit.c
        ${PM3_ROOT}/client/deps/reveng/preset.c
        ${PM3_ROOT}/client/deps/reveng/model.c
        ${PM3_ROOT}/client/deps/reveng/poly.c
        ${PM3_ROOT}/client/deps/reveng/reveng.c
        # liblua
        ${PM3_ROOT}/client/deps/liblua/lapi.c
        ${PM3_ROOT}/client/deps/liblua/ldo.c
        ${PM3_ROOT}/client/deps/liblua/lgc.c
        ${PM3_ROOT}/client/deps/liblua/ltm.c
        ${PM3_ROOT}/client/deps/liblua/lvm.c
        ${PM3_ROOT}/client/deps/liblua/lzio.c
        ${PM3_ROOT}/client/deps/liblua/lcode.c
        ${PM3_ROOT}/client/deps/liblua/llex.c
        ${PM3_ROOT}/client/deps/liblua/liolib.c
        ${PM3_ROOT}/client/deps/liblua/loslib.c
        ${PM3_ROOT}/client/deps/liblua/lopcodes.c
        ${PM3_ROOT}/client/deps/liblua/lmem.c
        ${PM3_ROOT}/client/deps/liblua/lmathlib.c
        ${PM3_ROOT}/client/deps/liblua/ldump.c
        ${PM3_ROOT}/client/deps/liblua/ldblib.c
        ${PM3_ROOT}/client/deps/liblua/lundump.c
        ${PM3_ROOT}/client/deps/liblua/lcorolib.c
        ${PM3_ROOT}/client/deps/liblua/lauxlib.c
        ${PM3_ROOT}/client/deps/liblua/ltablib.c
        ${PM3_ROOT}/client/deps/liblua/linit.c
        ${PM3_ROOT}/client/deps/liblua/lstring.c
        ${PM3_ROOT}/client/deps/liblua/lctype.c
        ${PM3_ROOT}/client/deps/liblua/ltable.c
        ${PM3_ROOT}/client/deps/liblua/ldebug.c
        ${PM3_ROOT}/client/deps/liblua/lstate.c
        ${PM3_ROOT}/client/deps/liblua/lstrlib.c
        ${PM3_ROOT}/client/deps/liblua/lfunc.c
        ${PM3_ROOT}/client/deps/liblua/lparser.c
        ${PM3_ROOT}/client/deps/liblua/lobject.c
        ${PM3_ROOT}/client/deps/liblua/loadlib.c
        ${PM3_ROOT}/client/deps/liblua/lbaselib.c
        ${PM3_ROOT}/client/deps/liblua/lbitlib.c
        ${PM3_ROOT}/client/deps/hardnested/hardnested_bruteforce.c
        # android source
        jni_tools.c
        pm3_main.c
        )

#添加头文件配置
target_include_directories(pm3rrg_rdv4 PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${PM3_ROOT}/
        ${PM3_ROOT}/include/
        ${PM3_ROOT}/common
        ${PM3_ROOT}/common/zlib
        ${PM3_ROOT}/common_fpga
        ${PM3_ROOT}/common/mbedtls
        ${PM3_ROOT}/client/src
        ${PM3_ROOT}/client/src/fido
        ${PM3_ROOT}/client/src/uart
        ${PM3_ROOT}/client/deps/liblua
        ${PM3_ROOT}/client/deps/reveng
        ${PM3_ROOT}/client/deps/jansson
        ${PM3_ROOT}/client/deps/tinycbor
        ${PM3_ROOT}/client/deps/cliparser
        ${PM3_ROOT}/client/deps/hardnested)

## CPU-specific code
## These are mostly for x86-based architectures, which is not useful for many Android devices.
add_library(pm3rrg_rdv4_hardnested_nosimd OBJECT
        ${PM3_ROOT}/client/deps/hardnested/hardnested_bf_core.c
        ${PM3_ROOT}/client/deps/hardnested/hardnested_bitarray_core.c)

target_include_directories(pm3rrg_rdv4_hardnested_nosimd PRIVATE
        ${PM3_ROOT}/common
        ${PM3_ROOT}/client
        ${PM3_ROOT}/include/
        ${PM3_ROOT}/client/deps/hardnested)

set(X86_CPUS x86 x86_64 i686)

message(STATUS "CMAKE_SYSTEM_PROCESSOR := ${CMAKE_SYSTEM_PROCESSOR}")

if ("${CMAKE_SYSTEM_PROCESSOR}" IN_LIST X86_CPUS)
    message(STATUS "Building optimised x86/x86_64 binaries")
    target_compile_options(pm3rrg_rdv4_hardnested_nosimd BEFORE PRIVATE
            -mno-mmx -mno-sse2 -mno-avx -mno-avx2 -mno-avx512f)

    set_property(TARGET pm3rrg_rdv4_hardnested_nosimd PROPERTY POSITION_INDEPENDENT_CODE ON)

    ## x86 / MMX
    add_library(pm3rrg_rdv4_hardnested_mmx OBJECT
            ${PM3_ROOT}/client/deps/hardnested/hardnested_bf_core.c
            ${PM3_ROOT}/client/deps/hardnested/hardnested_bitarray_core.c)

    target_compile_options(pm3rrg_rdv4_hardnested_mmx BEFORE PRIVATE
            -mmmx -mno-sse2 -mno-avx -mno-avx2 -mno-avx512f)

    target_include_directories(pm3rrg_rdv4_hardnested_mmx PRIVATE
            ${PM3_ROOT}/common
            ${PM3_ROOT}/client
            ${PM3_ROOT}/include/
            ${PM3_ROOT}/client/deps/hardnested)

    set_property(TARGET pm3rrg_rdv4_hardnested_mmx PROPERTY POSITION_INDEPENDENT_CODE ON)

    ## x86 / SSE2
    add_library(pm3rrg_rdv4_hardnested_sse2 OBJECT
            ${PM3_ROOT}/client/deps/hardnested/hardnested_bf_core.c
            ${PM3_ROOT}/client/deps/hardnested/hardnested_bitarray_core.c)

    target_compile_options(pm3rrg_rdv4_hardnested_sse2 BEFORE PRIVATE
            -mmmx -msse2 -mno-avx -mno-avx2 -mno-avx512f)

    target_include_directories(pm3rrg_rdv4_hardnested_sse2 PRIVATE
            ${PM3_ROOT}/common
            ${PM3_ROOT}/client
            ${PM3_ROOT}/include/
            ${PM3_ROOT}/client/deps/hardnested)

    set_property(TARGET pm3rrg_rdv4_hardnested_sse2 PROPERTY POSITION_INDEPENDENT_CODE ON)

    ## x86 / AVX
    add_library(pm3rrg_rdv4_hardnested_avx OBJECT
            ${PM3_ROOT}/client/deps/hardnested/hardnested_bf_core.c
            ${PM3_ROOT}/client/deps/hardnested/hardnested_bitarray_core.c)

    target_compile_options(pm3rrg_rdv4_hardnested_avx BEFORE PRIVATE
            -mmmx -msse2 -mavx -mno-avx2 -mno-avx512f)

    target_include_directories(pm3rrg_rdv4_hardnested_avx PRIVATE
            ${PM3_ROOT}/common
            ${PM3_ROOT}/client
            ${PM3_ROOT}/include/
            ${PM3_ROOT}/client/deps/hardnested)

    set_property(TARGET pm3rrg_rdv4_hardnested_avx PROPERTY POSITION_INDEPENDENT_CODE ON)

    ## x86 / AVX2
    add_library(pm3rrg_rdv4_hardnested_avx2 OBJECT
            ${PM3_ROOT}/client/deps/hardnested/hardnested_bf_core.c
            ${PM3_ROOT}/client/deps/hardnested/hardnested_bitarray_core.c)

    target_compile_options(pm3rrg_rdv4_hardnested_avx2 BEFORE PRIVATE
            -mmmx -msse2 -mavx -mavx2 -mno-avx512f)

    target_include_directories(pm3rrg_rdv4_hardnested_avx2 PRIVATE
            ${PM3_ROOT}/common
            ${PM3_ROOT}/client
            ${PM3_ROOT}/include/
            ${PM3_ROOT}/client/deps/hardnested)

    set_property(TARGET pm3rrg_rdv4_hardnested_avx2 PROPERTY POSITION_INDEPENDENT_CODE ON)

    ## x86 / AVX512
    add_library(pm3rrg_rdv4_hardnested_avx512 OBJECT
            ${PM3_ROOT}/client/deps/hardnested/hardnested_bf_core.c
            ${PM3_ROOT}/client/deps/hardnested/hardnested_bitarray_core.c)

    target_compile_options(pm3rrg_rdv4_hardnested_avx512 BEFORE PRIVATE
            -mmmx -msse2 -mavx -mavx2 -mavx512f)

    target_include_directories(pm3rrg_rdv4_hardnested_avx512 PRIVATE
            ${PM3_ROOT}/common
            ${PM3_ROOT}/client
            ${PM3_ROOT}/include/
            ${PM3_ROOT}/client/deps/hardnested)

    set_property(TARGET pm3rrg_rdv4_hardnested_avx512 PROPERTY POSITION_INDEPENDENT_CODE ON)

    set(SIMD_TARGETS
            $<TARGET_OBJECTS:pm3rrg_rdv4_hardnested_mmx>
            $<TARGET_OBJECTS:pm3rrg_rdv4_hardnested_sse2>
            $<TARGET_OBJECTS:pm3rrg_rdv4_hardnested_avx>
            $<TARGET_OBJECTS:pm3rrg_rdv4_hardnested_avx2>
            $<TARGET_OBJECTS:pm3rrg_rdv4_hardnested_avx512>)
else ()
    message(STATUS "Not building optimised targets")
    set(SIMD_TARGETS)
endif ()

#定义为静态库，被最终的pm3库依赖!
add_library(pm3rrg_rdv4_hardnested STATIC
        $<TARGET_OBJECTS:pm3rrg_rdv4_hardnested_nosimd>
        ${SIMD_TARGETS})

#添加动态库链接!
target_link_libraries(pm3rrg_rdv4 pm3rrg_rdv4_hardnested android log z)