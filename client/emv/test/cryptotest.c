//-----------------------------------------------------------------------------
// Copyright (C) 2017 Merlok
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Crypto algorithms testing
//-----------------------------------------------------------------------------

#include "cryptotest.h"
#include "util.h"
#include "ui.h"

#include "mbedtls/bignum.h"
#include "mbedtls/aes.h"
#include "mbedtls/cmac.h"
#include "mbedtls/des.h"
#include "mbedtls/ecp.h"
#include "mbedtls/rsa.h"
#include "mbedtls/sha1.h"
#include "mbedtls/md5.h"
#include "mbedtls/x509.h"
#include "mbedtls/base64.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/timing.h"

#include "crypto_test.h"
#include "sda_test.h"
#include "dda_test.h"
#include "cda_test.h"
#include "crypto/libpcrypto.h"
#include "emv/emv_roca.h"

int ExecuteCryptoTests(bool verbose) {
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
    if (res) TestFail = true;

    res = mbedtls_timing_self_test(verbose);
    if (res) TestFail = true;

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

    res = exec_crypto_test(verbose);
    if (res) TestFail = true;

    res = roca_self_test();
    if (res) TestFail = true;

    PrintAndLogEx(NORMAL, "\n--------------------------");

    if (TestFail)
        PrintAndLogEx(FAILED, "\tTest(s) [ %s ]", _RED_("Fail"));
    else
        PrintAndLogEx(SUCCESS, "\tTest(s) [ %s ]", _GREEN_("OK"));

    return TestFail;
}

