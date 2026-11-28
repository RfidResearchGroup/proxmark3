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

static int rocacheck_init(mbedtls_mpi *prints) {
    static const char *values[ROCA_PRINTS_LENGTH] = {
        "1026", "5658", "107286", "199410", "67109890",
        "5310023542746834", "1455791217086302986", "20052041432995567486",
        "6041388139249378920330", "207530445072488465666",
        "79228162521181866724264247298", "1760368345969468176824550810518",
        "50079290986288516948354744811034", "473022961816146413042658758988474",
        "144390480366845522447407333004847678774",
        "1800793591454480341970779146165214289059119882",
        "126304807362733370595828809000324029340048915994"
    };

    for (int i = 0; i < ROCA_PRINTS_LENGTH; i++)
        mbedtls_mpi_init(&prints[i]);
    for (int i = 0; i < ROCA_PRINTS_LENGTH; i++) {
        int res = mbedtls_mpi_read_string(&prints[i], 10, values[i]);
        if (res)
            return res;
    }
    return 0;
}

static void rocacheck_cleanup(mbedtls_mpi *prints) {
    for (int i = 0; i < ROCA_PRINTS_LENGTH; i++)
        mbedtls_mpi_free(&prints[i]);
}

emv_roca_result_t emv_rocacheck_ex(const unsigned char *buf, size_t buflen, bool verbose) {
    if (!buf || buflen == 0 || buflen > 4096)
        return EMV_ROCA_ERROR;

    mbedtls_mpi t_modulus;
    mbedtls_mpi_init(&t_modulus);

    emv_roca_result_t result = EMV_ROCA_ERROR;
    mbedtls_mpi prints[ROCA_PRINTS_LENGTH];
    static const uint8_t primes[ROCA_PRINTS_LENGTH] = {
        11, 13, 17, 19, 37, 53, 61, 71, 73, 79, 97, 103, 107, 109, 127, 151, 157
    };

    int res = rocacheck_init(prints);
    if (res)
        goto cleanup;
    res = mbedtls_mpi_read_binary(&t_modulus, buf, buflen);
    if (res || mbedtls_mpi_cmp_int(&t_modulus, 2) < 0)
        goto cleanup;

    for (int i = 0; i < ROCA_PRINTS_LENGTH; i++) {
        mbedtls_mpi_uint remainder = 0;
        res = mbedtls_mpi_mod_int(&remainder, &t_modulus, primes[i]);
        if (res)
            goto cleanup;
        if (!mbedtls_mpi_get_bit(&prints[i], remainder)) {
            result = EMV_ROCA_NOT_FOUND;
            if (verbose)
                PrintAndLogEx(INFO, "ROCA fingerprint not found");
            goto cleanup;
        }
    }

    result = EMV_ROCA_FOUND;
    if (verbose)
        PrintAndLogEx(FAILED, "ROCA fingerprint found");

cleanup:
    mbedtls_mpi_free(&t_modulus);
    rocacheck_cleanup(prints);
    return result;
}

bool emv_rocacheck(const unsigned char *buf, size_t buflen, bool verbose) {
    return emv_rocacheck_ex(buf, buflen, verbose) == EMV_ROCA_FOUND;
}

bool emv_rsa_has_small_factor(const unsigned char *buf, size_t buflen) {
    static const uint8_t primes[] = {
        3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47,
        53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107,
        109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167,
        173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229,
        233, 239, 241, 251
    };
    if (!buf || buflen == 0 || buflen > 4096)
        return false;

    mbedtls_mpi modulus;
    mbedtls_mpi_init(&modulus);
    bool found = false;
    if (mbedtls_mpi_read_binary(&modulus, buf, buflen) || mbedtls_mpi_cmp_int(&modulus, 2) < 0)
        goto cleanup;
    for (size_t i = 0; i < sizeof(primes) / sizeof(primes[0]); i++) {
        mbedtls_mpi_uint remainder = 0;
        if (mbedtls_mpi_mod_int(&remainder, &modulus, primes[i]))
            goto cleanup;
        if (remainder == 0 && mbedtls_mpi_cmp_int(&modulus, primes[i]) != 0) {
            found = true;
            break;
        }
    }

cleanup:
    mbedtls_mpi_free(&modulus);
    return found;
}

bool emv_rsa_has_shared_factor(const unsigned char *a, size_t alen,
                               const unsigned char *b, size_t blen) {
    if (!a || !b || alen == 0 || blen == 0 || alen > 4096 || blen > 4096)
        return false;

    mbedtls_mpi ma, mb, gcd;
    mbedtls_mpi_init(&ma);
    mbedtls_mpi_init(&mb);
    mbedtls_mpi_init(&gcd);
    bool found = false;
    if (mbedtls_mpi_read_binary(&ma, a, alen) || mbedtls_mpi_read_binary(&mb, b, blen) ||
            mbedtls_mpi_cmp_int(&ma, 2) < 0 || mbedtls_mpi_cmp_int(&mb, 2) < 0 ||
            mbedtls_mpi_gcd(&gcd, &ma, &mb))
        goto cleanup;
    found = mbedtls_mpi_cmp_int(&gcd, 1) > 0 &&
            mbedtls_mpi_cmp_mpi(&gcd, &ma) < 0 && mbedtls_mpi_cmp_mpi(&gcd, &mb) < 0;

cleanup:
    mbedtls_mpi_free(&gcd);
    mbedtls_mpi_free(&mb);
    mbedtls_mpi_free(&ma);
    return found;
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
        PrintAndLogEx(SUCCESS, "Weak modulus   ( %s )", _GREEN_("ok"));
    } else {
        ret++;
        PrintAndLogEx(FAILED, "Weak modulus   ( %s )", _RED_("fail"));
    }

    // negative
    uint8_t keyn[] = "\x84\x4e\x13\x20\x8a\x28\x0c\x37\xef\xc3\x1c\x31\x14\x48\x5e\x59"\
                     "\x01\x92\xad\xbb\x8e\x11\xc8\x7c\xad\x60\xcd\xef\x00\x37\xce\x99"\
                     "\x27\x83\x30\xd3\xf4\x71\xa2\x53\x8f\xa6\x67\x80\x2e\xd2\xa3\xc4"\
                     "\x4a\x8b\x7d\xea\x82\x6e\x88\x8d\x0a\xa3\x41\xfd\x66\x4f\x7f\xa7";

    if (emv_rocacheck(keyn, 64, false)) {
        ret++;
        PrintAndLogEx(FAILED, "Non-ROCA key  ( %s )", _RED_("fail"));
    } else {
        PrintAndLogEx(SUCCESS, "Non-ROCA key  ( %s )", _GREEN_("ok"));
    }

    if (emv_rocacheck_ex(NULL, 0, false) != EMV_ROCA_ERROR) {
        ret++;
        PrintAndLogEx(FAILED, "Invalid input  ( %s )", _RED_("fail"));
    } else {
        PrintAndLogEx(SUCCESS, "Invalid input  ( %s )", _GREEN_("ok"));
    }

    const uint8_t factor15[] = {15};
    const uint8_t factor21[] = {21};
    const uint8_t coprime77[] = {77};
    if (!emv_rsa_has_small_factor(factor15, sizeof(factor15)) ||
            !emv_rsa_has_shared_factor(factor15, sizeof(factor15), factor21, sizeof(factor21)) ||
            emv_rsa_has_shared_factor(factor15, sizeof(factor15), coprime77, sizeof(coprime77))) {
        ret++;
        PrintAndLogEx(FAILED, "Factor checks  ( %s )", _RED_("fail"));
    } else {
        PrintAndLogEx(SUCCESS, "Factor checks  ( %s )", _GREEN_("ok"));
    }
    return ret;
}
