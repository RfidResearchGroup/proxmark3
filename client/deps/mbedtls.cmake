add_library(pm3rrg_rdv4_mbedtls STATIC
        ../../common/mbedtls/aes.c
        ../../common/mbedtls/asn1parse.c
        ../../common/mbedtls/asn1write.c
        ../../common/mbedtls/base64.c
        ../../common/mbedtls/bignum.c
        ../../common/mbedtls/ctr_drbg.c
        ../../common/mbedtls/entropy_poll.c
        ../../common/mbedtls/entropy.c
        ../../common/mbedtls/error.c
        ../../common/mbedtls/ecp.c
        ../../common/mbedtls/ecdh.c
        ../../common/mbedtls/ecc_point_compression.c
        ../../common/mbedtls/gcm.c
        ../../common/mbedtls/ecp_curves.c
        ../../common/mbedtls/certs.c
        ../../common/mbedtls/camellia.c
        ../../common/mbedtls/blowfish.c
        ../../common/mbedtls/cipher_wrap.c
        ../../common/mbedtls/cipher.c
        ../../common/mbedtls/cmac.c
        ../../common/mbedtls/des.c
        ../../common/mbedtls/ecdsa.c
        ../../common/mbedtls/md.c
        ../../common/mbedtls/md5.c
        ../../common/mbedtls/oid.c
        ../../common/mbedtls/pem.c
        ../../common/mbedtls/arc4.c
        ../../common/mbedtls/pk.c
        ../../common/mbedtls/pk_wrap.c
        ../../common/mbedtls/pkwrite.c
        ../../common/mbedtls/pkcs5.c
        ../../common/mbedtls/pkcs12.c
        ../../common/mbedtls/pkparse.c
        ../../common/mbedtls/platform.c
        ../../common/mbedtls/platform_util.c
        ../../common/mbedtls/rsa.c
        ../../common/mbedtls/rsa_internal.c
        ../../common/mbedtls/sha1.c
        ../../common/mbedtls/sha256.c
        ../../common/mbedtls/sha512.c
        ../../common/mbedtls/threading.c
        ../../common/mbedtls/x509.c
        ../../common/mbedtls/x509_crl.c
        ../../common/mbedtls/x509_crt.c
        )

target_include_directories(pm3rrg_rdv4_mbedtls PRIVATE ../../common)
target_include_directories(pm3rrg_rdv4_mbedtls INTERFACE ../../common/mbedtls)
target_compile_options(pm3rrg_rdv4_mbedtls PRIVATE -Wall -Werror -O3)
set_property(TARGET pm3rrg_rdv4_mbedtls PROPERTY POSITION_INDEPENDENT_CODE ON)
