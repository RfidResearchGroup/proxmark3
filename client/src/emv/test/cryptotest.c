//-----------------------------------------------------------------------------
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
// Crypto algorithms testing
//-----------------------------------------------------------------------------

#include "cryptotest.h"
#include "util.h"
#include "ui.h"              // printandlog
#include "bignum.h"
#include "aes.h"
#include "cmac.h"
#include "des.h"
#include "ecp.h"
#include "rsa.h"
#include "sha1.h"
#include "md5.h"
#include "x509.h"
#include "base64.h"
#include "ctr_drbg.h"
#include "entropy.h"
//#include "timing.h" // Beware it requires adjustments for ProxSpace
#include "crypto_test.h"
#include "sda_test.h"
#include "dda_test.h"
#include "cda_test.h"
#include "crypto/libpcrypto.h"
#include "emv/emv_roca.h"

int ExecuteCryptoTests(bool verbose, bool ignore_time, bool include_slow_tests) {
    int res;
    bool TestFail = false;

    res = mbedtls_mpi_self_test(verbose);
    if (res) TestFail = true;

    res = mbedtls_aes_self_test(verbose);
    if (res) TestFail = true;

    res = mbedtls_des_self_test(verbose);
    if (res) TestFail = true;

    res = mbedtls_sha1_self_test(verbose);
    if (res) TestFail = true;

    res = mbedtls_md5_self_test(verbose);
    if (res) TestFail = true;

    res = mbedtls_rsa_self_test(verbose);
    if (res) TestFail = true;

    res = mbedtls_entropy_self_test(verbose);
    if (res && !ignore_time) TestFail = true;

    /*
    // retry for CI (when resources too low)
    for (int i = 0; i < 3; i++) {
        res = mbedtls_timing_self_test(verbose);
        if (!res)
            break;
        PrintAndLogEx(WARNING, "Repeat timing test " _RED_("%d"), i + 1);
    }
    if (res && !ignore_time) TestFail = true;
    */

    res = mbedtls_ctr_drbg_self_test(verbose);
    if (res) TestFail = true;

    res = mbedtls_base64_self_test(verbose);
    if (res) TestFail = true;

    res = mbedtls_cmac_self_test(verbose);
    if (res) TestFail = true;

    res = ecdsa_nist_test(verbose);
    if (res) TestFail = true;

    res = mbedtls_ecp_self_test(verbose);
    if (res) TestFail = true;

    res = mbedtls_x509_self_test(verbose);
    if (res) TestFail = true;

    res = exec_sda_test(verbose);
    if (res) TestFail = true;

    res = exec_dda_test(verbose);
    if (res) TestFail = true;

    res = exec_cda_test(verbose);
    if (res) TestFail = true;

    res = exec_crypto_test(verbose, include_slow_tests);
    if (res) TestFail = true;

    res = roca_self_test();
    if (res) TestFail = true;

    PrintAndLogEx(INFO, "--------------------------");

    if (TestFail)
        PrintAndLogEx(FAILED, "\tTest(s) [ %s ]", _RED_("fail"));
    else
        PrintAndLogEx(SUCCESS, "\tTest(s) [ %s ]", _GREEN_("ok"));

    return TestFail;
}

