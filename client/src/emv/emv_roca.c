//-----------------------------------------------------------------------------
// Borrowed initially from https://gist.github.com/robstradling/f525d423c79690b72e650e2ad38a161d
// Copyright (C) 2017-2018 Rob Stradling
// Copyright (C) 2017-2018 Sectigo Limited
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------
// roca.c - ROCA (CVE-2017-15361) fingerprint checker.
//-----------------------------------------------------------------------------

#include "emv_roca.h"

#include "ui.h"  // Print...
#include "bignum.h"

static void rocacheck_init(mbedtls_mpi *prints) {

    for (int i = 0; i < ROCA_PRINTS_LENGTH; i++)
        mbedtls_mpi_init(&prints[i]);

    mbedtls_mpi_read_string(&prints[0], 10, "1026");
    mbedtls_mpi_read_string(&prints[1], 10, "5658");
    mbedtls_mpi_read_string(&prints[2], 10, "107286");
    mbedtls_mpi_read_string(&prints[3], 10, "199410");
    mbedtls_mpi_read_string(&prints[4], 10, "67109890");
    mbedtls_mpi_read_string(&prints[5], 10, "5310023542746834");
    mbedtls_mpi_read_string(&prints[6], 10, "1455791217086302986");
    mbedtls_mpi_read_string(&prints[7], 10, "20052041432995567486");
    mbedtls_mpi_read_string(&prints[8], 10, "6041388139249378920330");
    mbedtls_mpi_read_string(&prints[9], 10, "207530445072488465666");
    mbedtls_mpi_read_string(&prints[10], 10, "79228162521181866724264247298");
    mbedtls_mpi_read_string(&prints[11], 10, "1760368345969468176824550810518");
    mbedtls_mpi_read_string(&prints[12], 10, "50079290986288516948354744811034");
    mbedtls_mpi_read_string(&prints[13], 10, "473022961816146413042658758988474");
    mbedtls_mpi_read_string(&prints[14], 10, "144390480366845522447407333004847678774");
    mbedtls_mpi_read_string(&prints[15], 10, "1800793591454480341970779146165214289059119882");
    mbedtls_mpi_read_string(&prints[16], 10, "126304807362733370595828809000324029340048915994");
}

static void rocacheck_cleanup(mbedtls_mpi *prints) {
    for (int i = 0; i < ROCA_PRINTS_LENGTH; i++)
        mbedtls_mpi_free(&prints[i]);
}

static int bitand_is_zero(mbedtls_mpi *a, mbedtls_mpi *b) {

    for (int i = 0; i < mbedtls_mpi_bitlen(a); i++) {

        if (mbedtls_mpi_get_bit(a, i) && mbedtls_mpi_get_bit(b, i))
            return 0;
    }
    return 1;
}


static mbedtls_mpi_uint mpi_get_uint(const mbedtls_mpi *X) {

    if (X->n == 1 && X->s > 0) {
        return X->p[0];
    }

    PrintAndLogEx(WARNING, "ZERRRRO!!!\n");
    return 0;
}

/*
static void print_mpi(const char *msg, int radix, const mbedtls_mpi *X) {

    char Xchar[400] = {0};
    size_t len = 0;

    mbedtls_mpi_write_string(X, radix, Xchar, sizeof(Xchar), &len);
    PrintAndLogEx(INFO, "%s[%zu] %s\n", msg, len, Xchar);
}
*/
bool emv_rocacheck(const unsigned char *buf, size_t buflen, bool verbose) {

    mbedtls_mpi t_modulus;
    mbedtls_mpi_init(&t_modulus);

    bool ret = false;
    mbedtls_mpi prints[ROCA_PRINTS_LENGTH];
    uint8_t primes[ROCA_PRINTS_LENGTH] = {
        11, 13, 17, 19, 37, 53, 61, 71, 73, 79, 97, 103, 107, 109, 127, 151, 157
    };

    rocacheck_init(prints);

    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&t_modulus, buf, buflen));

    for (int i = 0; i < ROCA_PRINTS_LENGTH; i++) {

        mbedtls_mpi t_temp;
        mbedtls_mpi t_prime;
        mbedtls_mpi g_one;

        mbedtls_mpi_init(&t_temp);
        mbedtls_mpi_init(&t_prime);
        mbedtls_mpi_init(&g_one);

        MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&g_one, 10, "1"));

        MBEDTLS_MPI_CHK(mbedtls_mpi_add_int(&t_prime, &t_prime, primes[i]));

        MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&t_temp, &t_modulus, &t_prime));

        MBEDTLS_MPI_CHK(mbedtls_mpi_shift_l(&g_one, mpi_get_uint(&t_temp)));

        mbedtls_mpi_free(&t_temp);
        mbedtls_mpi_free(&t_prime);

        if (bitand_is_zero(&g_one, &prints[i])) {
            if (verbose) {
                PrintAndLogEx(FAILED, "No fingerprint found.\n");
            }
            mbedtls_mpi_free(&g_one);
            goto cleanup;
        }
        mbedtls_mpi_free(&g_one);
    }

    ret = true;
    if (verbose)
        PrintAndLogEx(SUCCESS, "Fingerprint found!\n");

cleanup:
    mbedtls_mpi_free(&t_modulus);

    rocacheck_cleanup(prints);
    return ret;
}

int roca_self_test(void) {
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "ROCA check vulnerability tests");

    // positive
    uint8_t keyp[] = "\x94\x4e\x13\x20\x8a\x28\x0c\x37\xef\xc3\x1c\x31\x14\x48\x5e\x59"\
                     "\x01\x92\xad\xbb\x8e\x11\xc8\x7c\xad\x60\xcd\xef\x00\x37\xce\x99"\
                     "\x27\x83\x30\xd3\xf4\x71\xa2\x53\x8f\xa6\x67\x80\x2e\xd2\xa3\xc4"\
                     "\x4a\x8b\x7d\xea\x82\x6e\x88\x8d\x0a\xa3\x41\xfd\x66\x4f\x7f\xa7";

    int ret = 0;
    if (emv_rocacheck(keyp, 64, false)) {
        PrintAndLogEx(SUCCESS, "Weak modulus   [ %s ]", _GREEN_("PASS"));
    } else {
        ret++;
        PrintAndLogEx(FAILED, "Weak modulus   [ %s ]", _RED_("Fail"));
    }

    // negative
    uint8_t keyn[] = "\x84\x4e\x13\x20\x8a\x28\x0c\x37\xef\xc3\x1c\x31\x14\x48\x5e\x59"\
                     "\x01\x92\xad\xbb\x8e\x11\xc8\x7c\xad\x60\xcd\xef\x00\x37\xce\x99"\
                     "\x27\x83\x30\xd3\xf4\x71\xa2\x53\x8f\xa6\x67\x80\x2e\xd2\xa3\xc4"\
                     "\x4a\x8b\x7d\xea\x82\x6e\x88\x8d\x0a\xa3\x41\xfd\x66\x4f\x7f\xa7";

    if (emv_rocacheck(keyn, 64, false)) {
        ret++;
        PrintAndLogEx(FAILED, "Strong modulus [ %s ]", _RED_("Fail"));
    } else {
        PrintAndLogEx(SUCCESS, "Strong modulus [ %s ]", _GREEN_("PASS"));
    }
    return ret;
}
