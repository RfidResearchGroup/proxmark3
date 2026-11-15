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
// ITSO (UK) parser for MIFARE DESFire dumps
//-----------------------------------------------------------------------------

#include "parseitso.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "commonutil.h"         // MemBeToUint2byte
#include "ui.h"                 // PrintAndLogEx
#include "util.h"               // sprint_hex_inrow
#include "parsetransit.h"

#define ITSO_SHELL_MIN_LEN      16
#define ITSO_ISRN_DIGITS        18

// All ISRNs carry the ITSO issuer identification number
#define ITSO_IIN                "633597"

static const desfire_dump_app_t *itso_find_app(const desfire_dump_t *dump) {
    if (dump == NULL) {
        return NULL;
    }
    for (uint8_t i = 0; i < dump->appcount && i < DESFIRE_MAX_APP_COUNT; i++) {
        if (dump->app[i].aid == ITSO_AID) {
            return &dump->app[i];
        }
    }
    return NULL;
}

static const desfire_dump_file_t *itso_find_file(const desfire_dump_app_t *app, uint8_t fid) {
    for (uint8_t i = 0; i < app->filecount && i < DESFIRE_MAX_FILE_COUNT; i++) {
        if (app->files[i].num == fid) {
            return &app->files[i];
        }
    }
    return NULL;
}

// ISRN is BCD from the fifth nibble on, false when it is not ITSO's
static bool itso_isrn_str(const uint8_t *d, char *out, size_t outlen) {
    char digits[ITSO_ISRN_DIGITS + 1];
    for (int i = 0; i < ITSO_ISRN_DIGITS; i++) {
        int nib = 4 + i;
        uint8_t v = (nib & 1) ? (d[nib >> 1] & 0x0F) : (d[nib >> 1] >> 4);
        if (v > 9) {
            return false;
        }
        digits[i] = (char)('0' + v);
    }
    digits[ITSO_ISRN_DIGITS] = '\0';
    if (strncmp(digits, ITSO_IIN, strlen(ITSO_IIN)) != 0) {
        return false;
    }
    snprintf(out, outlen, "%.6s %.4s %.4s %.4s", digits, digits + 6, digits + 10, digits + 14);
    return true;
}

transit_id_t itso_identify(const transit_mfdes_info_t *info) {
    return (transit_mfdes_info_has_aid(info, ITSO_AID)) ? TRANSIT_ID_MATCH : TRANSIT_ID_NONE;
}

bool is_valid_itso_card(const desfire_dump_t *dump) {
    transit_mfdes_info_t info;
    transit_mfdes_info_from_dump(dump, &info);
    return itso_identify(&info) == TRANSIT_ID_MATCH;
}

int itso_parser_parse(const desfire_dump_t *dump) {

    const desfire_dump_app_t *app = itso_find_app(dump);
    if (app == NULL) {
        return PM3_EINVARG;
    }

    transit_print_header("ITSO");
    transit_print_kv("Scheme", "ITSO smartcard, United Kingdom");

    const desfire_dump_file_t *f = itso_find_file(app, ITSO_FID_SHELL);
    if (f == NULL || f->read_ok == false || f->data == NULL || f->datalen < ITSO_SHELL_MIN_LEN) {
        PrintAndLogEx(HINT, "Hint: Use `" _YELLOW_("hf mfdes dump --no-auth") "`");
        return PM3_SUCCESS;
    }

    char isrn[32];
    if (itso_isrn_str(f->data, isrn, sizeof(isrn)) == false) {
        transit_print_kv("Shell", "%s", sprint_hex_inrow(f->data, ITSO_SHELL_MIN_LEN));
        PrintAndLogEx(INFO, "No ITSO ISRN where one is expected");
        return PM3_SUCCESS;
    }

    transit_print_kv("ISRN", _YELLOW_("%s"), isrn);

    // EN 1545 date stamp
    char buf[16];
    transit_date_str(buf, sizeof(buf), TRANSIT_DAYS_TO_1997 + MemBeToUint2byte(f->data + 14));
    transit_print_kv("Expiry", "%s", buf);
    return PM3_SUCCESS;
}

int itso_selftest(void) {

    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "Testing ITSO decode");

    // synthetic shell, expiry day 0x2710 = 2024-05-19
    static uint8_t shell[32] = {
        0x13, 0x10, 0x63, 0x35, 0x97, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x30, 0x00, 0x00, 0x27, 0x10
    };

    bool ok = true;
    char buf[32] = {0};
    ok &= transit_check("ISRN decoded", itso_isrn_str(shell, buf, sizeof(buf)), true);
    ok &= transit_check_str("ISRN", buf, "633597 1234 5678 9012");
    transit_date_str(buf, sizeof(buf), TRANSIT_DAYS_TO_1997 + MemBeToUint2byte(shell + 14));
    ok &= transit_check_str("expiry", buf, "2024-05-19");

    uint8_t other[16] = { 0x13, 0x10, 0x63, 0x35, 0x98 };
    ok &= transit_check("other IIN rejected", itso_isrn_str(other, buf, sizeof(buf)), false);

    desfire_dump_t *dump = calloc(1, sizeof(desfire_dump_t));
    if (dump == NULL) {
        return PM3_EMALLOC;
    }
    dump->appcount = 1;
    dump->app[0].aid = ITSO_AID;
    dump->app[0].filecount = 1;
    dump->app[0].files[0].num = ITSO_FID_SHELL;
    dump->app[0].files[0].read_ok = true;
    dump->app[0].files[0].data = shell;
    dump->app[0].files[0].datalen = sizeof(shell);
    ok &= transit_check("detected", is_valid_itso_card(dump), true);
    ok &= transit_mfdes_check_identify("identify", dump, "ITSO", TRANSIT_ID_MATCH);
    if (ok) {
        itso_parser_parse(dump);
    }
    dump->app[0].aid = 0x000001;
    ok &= transit_mfdes_check_identify("not identified", dump, "ITSO", TRANSIT_ID_NONE);
    free(dump);

    return transit_selftest_result("ITSO", ok);
}
