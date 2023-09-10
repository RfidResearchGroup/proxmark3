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

#define MBEDTLS_ALLOW_PRIVATE_ACCESS

#include "ecc_point_compression.h"

int mbedtls_ecp_decompress(
    const mbedtls_ecp_group *grp,
    const unsigned char *input, size_t ilen,
    unsigned char *output, size_t *olen, size_t osize
) {
    int ret;
    size_t plen;
    mbedtls_mpi r;
    mbedtls_mpi x;
    mbedtls_mpi n;

    plen = mbedtls_mpi_size(&grp->P);

    *olen = 2 * plen + 1;

    if (osize < *olen)
        return (MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL);

    if (ilen != plen + 1)
        return (MBEDTLS_ERR_ECP_BAD_INPUT_DATA);

    if (input[0] != 0x02 && input[0] != 0x03)
        return (MBEDTLS_ERR_ECP_BAD_INPUT_DATA);

    // output will consist of 0x04|X|Y
    memcpy(output, input, ilen);
    output[0] = 0x04;

    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&x);
    mbedtls_mpi_init(&n);

    // x <= input
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&x, input + 1, plen));

    // r = x^2
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&r, &x, &x));

    // r = x^2 + a
    if (grp->A.p == NULL) {
        // Special case where a is -3
        MBEDTLS_MPI_CHK(mbedtls_mpi_sub_int(&r, &r, 3));
    } else {
        MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(&r, &r, &grp->A));
    }

    // r = x^3 + ax
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&r, &r, &x));

    // r = x^3 + ax + b
    MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(&r, &r, &grp->B));

    // Calculate square root of r over finite field P:
    //   r = sqrt(x^3 + ax + b) = (x^3 + ax + b) ^ ((P + 1) / 4) (mod P)

    // n = P + 1
    MBEDTLS_MPI_CHK(mbedtls_mpi_add_int(&n, &grp->P, 1));

    // n = (P + 1) / 4
    MBEDTLS_MPI_CHK(mbedtls_mpi_shift_r(&n, 2));

    // r ^ ((P + 1) / 4) (mod p)
    MBEDTLS_MPI_CHK(mbedtls_mpi_exp_mod(&r, &r, &n, &grp->P, NULL));

    // Select solution that has the correct "sign" (equals odd/even solution in finite group)
    if ((input[0] == 0x03) != mbedtls_mpi_get_bit(&r, 0)) {
        // r = p - r
        MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&r, &grp->P, &r));
    }

    // y => output
    ret = mbedtls_mpi_write_binary(&r, output + 1 + plen, plen);

cleanup:
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&x);
    mbedtls_mpi_free(&n);

    return (ret);
}

int mbedtls_ecp_compress(
    const mbedtls_ecp_group *grp,
    const unsigned char *input, size_t ilen,
    unsigned char *output, size_t *olen, size_t osize
) {
    size_t plen;

    plen = mbedtls_mpi_size(&grp->P);

    *olen = plen + 1;

    if (osize < *olen)
        return (MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL);

    if (ilen != 2 * plen + 1)
        return (MBEDTLS_ERR_ECP_BAD_INPUT_DATA);

    if (input[0] != 0x04)
        return (MBEDTLS_ERR_ECP_BAD_INPUT_DATA);

    // output will consist of 0x0?|X
    memcpy(output, input, *olen);

    // Encode even/odd of Y into first byte (either 0x02 or 0x03)
    output[0] = 0x02 + (input[2 * plen] & 1);

    return (0);
}
