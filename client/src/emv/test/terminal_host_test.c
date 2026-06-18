//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------

#include "terminal_host_test.h"
#include "../terminal/emv_term_arqc.h"
#include "../terminal/emv_term_host.h"
#include "ui.h"
#include "fileutils.h"
#include <string.h>

static int test_sk_derive(bool verbose) {
    uint8_t ac_mk[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                         0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10};
    uint8_t sk1[16] = {0};
    uint8_t sk2[16] = {0};
    emv_term_sk_derive_ac(ac_mk, 0x0042, sk1);
    emv_term_sk_derive_ac(ac_mk, 0x0042, sk2);

    if (memcmp(sk1, sk2, 16) != 0) {
        if (verbose) {
            PrintAndLogEx(ERR, "SK derive not deterministic");
        }
        return 1;
    }

    emv_term_sk_derive_ac(ac_mk, 0x0043, sk2);
    if (memcmp(sk1, sk2, 16) == 0) {
        if (verbose) {
            PrintAndLogEx(ERR, "SK derive should differ for different ATC");
        }
        return 1;
    }

    if (verbose) {
        PrintAndLogEx(SUCCESS, "SK derive (ATC=0042) OK");
    }
    return 0;
}

static int test_arqc_roundtrip(bool verbose) {
    uint8_t ac_mk[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                         0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10};
    uint8_t cdol1[] = {
        0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x01, 0x24, 0x08, 0x26, 0x00, 0x42,
    };
    uint8_t sk[16] = {0};
    emv_term_sk_derive_ac(ac_mk, 0x0042, sk);

    uint8_t arqc[8] = {0};
    emv_term_retail_mac_3des(sk, cdol1, sizeof(cdol1), arqc);

    if (!emv_term_arqc_verify(sk, cdol1, sizeof(cdol1), arqc, 8)) {
        if (verbose) {
            PrintAndLogEx(ERR, "ARQC self-verify failed");
        }
        return 1;
    }

    uint8_t bad[8] = {0};
    memcpy(bad, arqc, 8);
    bad[0] ^= 0xFF;
    if (emv_term_arqc_verify(sk, cdol1, sizeof(cdol1), bad, 8)) {
        if (verbose) {
            PrintAndLogEx(ERR, "ARQC verify should fail on tampered MAC");
        }
        return 1;
    }

    if (verbose) {
        PrintAndLogEx(SUCCESS, "ARQC verify roundtrip OK");
    }
    return 0;
}

static int test_arpc_cvn18(bool verbose) {
    uint8_t ac_mk[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                         0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10};
    uint8_t cdol1[] = {0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00};
    uint8_t sk[16] = {0};
    emv_term_sk_derive_ac(ac_mk, 0x0001, sk);

    uint8_t arqc[8] = {0};
    emv_term_retail_mac_3des(sk, cdol1, sizeof(cdol1), arqc);

    uint8_t arc[2] = {'0', '0'};
    uint8_t arpc[16] = {0};
    size_t arpc_len = 0;
    if (!emv_term_arpc_compute(EMV_ARPC_CVN18, sk, arqc, 8, arc, 2, arpc, &arpc_len) || arpc_len != 8) {
        if (verbose) {
            PrintAndLogEx(ERR, "ARPC CVN18 compute failed");
        }
        return 1;
    }

    if (verbose) {
        PrintAndLogEx(SUCCESS, "ARPC CVN18 compute OK (%s)", sprint_hex(arpc, arpc_len));
    }
    return 0;
}

static int test_host_keys_load(bool verbose) {
    char *path = NULL;
    if (searchFile(&path, RESOURCES_SUBDIR, "host_sim_interac", ".json", false) == PM3_SUCCESS ||
        searchFile(&path, "client/resources", "host_sim_interac", ".json", false) == PM3_SUCCESS ||
        searchFile(&path, "docs/emv-terminal-emulator/examples", "host_sim_interac", ".json", false) == PM3_SUCCESS) {
        if (verbose) {
            PrintAndLogEx(WARNING, "host_sim_interac.json not found - skip keys load test");
        }
        return 0;
    }

    emv_term_host_keys_t keys;
    int res = emv_term_host_keys_load(&keys, path);
    free(path);
    if (res) {
        if (verbose) {
            PrintAndLogEx(ERR, "Host keys load failed");
        }
        return 1;
    }
    if (keys.ac_master_key_len != 16) {
        return 1;
    }
    if (verbose) {
        PrintAndLogEx(SUCCESS, "Host keys JSON load OK (scheme=%s)", keys.scheme);
    }
    return 0;
}

int exec_terminal_host_test(bool verbose) {
    if (test_sk_derive(verbose)) {
        return 1;
    }
    if (test_arqc_roundtrip(verbose)) {
        return 1;
    }
    if (test_arpc_cvn18(verbose)) {
        return 1;
    }
    if (test_host_keys_load(verbose)) {
        return 1;
    }
    return 0;
}
