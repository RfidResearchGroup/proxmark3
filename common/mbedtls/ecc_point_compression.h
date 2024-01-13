/*
* Not original to the mbedtls library. Taken from
* https://github.com/mwarning/mbedtls_ecp_compression
* to solve mbedtls' lack of support for elliptic point
* compression and decompression
*
* Released under CC0 1.0 Universal License
*/

/*
* This is all about mbedtls_ecp_decompress() and mbedtls_ecp_compress()
*
* Perform X25519 / Curve25519 point compression and decompression for mbedtls.
* As of mbedtls 2.5.1, mbedtls does not support decompression yet.
*
*/

#include <string.h>

#include "mbedtls/ecp.h"

int mbedtls_ecp_decompress(
    const mbedtls_ecp_group *grp,
    const unsigned char *input, size_t ilen,
    unsigned char *output, size_t *olen, size_t osize
);

int mbedtls_ecp_compress(
    const mbedtls_ecp_group *grp,
    const unsigned char *input, size_t ilen,
    unsigned char *output, size_t *olen, size_t osize
);
