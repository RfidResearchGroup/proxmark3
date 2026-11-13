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
// myki (Melbourne) parser for MIFARE DESFire dumps
//-----------------------------------------------------------------------------

#include "parsemyki.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "commonutil.h"         // MemLeToUint4byte
#include "ui.h"                 // PrintAndLogEx
#include "parsetransit.h"

// Every card number starts with 308425
#define MYKI_PREFIX             308425

static const desfire_dump_app_t *myki_find_app(const desfire_dump_t *dump, uint32_t aid) {
    if (dump == NULL) {
        return NULL;
    }
    for (uint8_t i = 0; i < dump->appcount && i < DESFIRE_MAX_APP_COUNT; i++) {
        if (dump->app[i].aid == aid) {
            return &dump->app[i];
        }
    }
    return NULL;
}

static const desfire_dump_file_t *myki_find_file(const desfire_dump_app_t *app, uint8_t fid) {
    for (uint8_t i = 0; i < app->filecount && i < DESFIRE_MAX_FILE_COUNT; i++) {
        if (app->files[i].num == fid) {
            return &app->files[i];
        }
    }
    return NULL;
}

// Luhn check digit for a string of decimal digits
static int myki_luhn(const char *s) {
    int sum = 0;
    size_t n = strlen(s);
    for (size_t i = 0; i < n; i++) {
        int d = s[n - 1 - i] - '0';
        if ((i & 1) == 0) {
            d *= 2;
            if (d > 9) {
                d -= 9;
            }
        }
        sum += d;
    }
    return (10 - (sum % 10)) % 10;
}

// 15 digit card number, false when the file does not carry one
static bool myki_serial_str(const uint8_t *d, char *out, size_t outlen) {
    uint32_t s1 = MemLeToUint4byte(d);
    uint32_t s2 = MemLeToUint4byte(d + 4);
    if (s1 != MYKI_PREFIX || s2 > 99999999) {
        return false;
    }
    char digits[16];
    snprintf(digits, sizeof(digits), "%06u%08u", s1, s2);
    snprintf(out, outlen, "%s%d", digits, myki_luhn(digits));
    return true;
}

transit_id_t myki_identify(const transit_mfdes_info_t *info) {
    return (transit_mfdes_info_has_aid(info, MYKI_AID_1) && transit_mfdes_info_has_aid(info, MYKI_AID_2)) ? TRANSIT_ID_MATCH : TRANSIT_ID_NONE;
}

bool is_valid_myki_card(const desfire_dump_t *dump) {
    transit_mfdes_info_t info;
    transit_mfdes_info_from_dump(dump, &info);
    return myki_identify(&info) == TRANSIT_ID_MATCH;
}

int myki_parser_parse(const desfire_dump_t *dump) {

    if (is_valid_myki_card(dump) == false) {
        return PM3_EINVARG;
    }

    transit_print_header("myki");
    transit_print_kv("Issuer", "Public Transport Victoria, Melbourne");

    const desfire_dump_file_t *f = myki_find_file(myki_find_app(dump, MYKI_AID_1), MYKI_FID_SERIAL);
    if (f == NULL || f->read_ok == false || f->data == NULL || f->datalen < 8) {
        PrintAndLogEx(HINT, "Hint: Use `" _YELLOW_("hf mfdes dump --no-auth") "`");
        return PM3_SUCCESS;
    }

    char serial[24];
    if (myki_serial_str(f->data, serial, sizeof(serial))) {
        transit_print_kv("Serial", _YELLOW_("%s"), serial);
    } else {
        transit_print_kv("Serial", "not a myki number");
    }
    PrintAndLogEx(INFO, "Balance and trips are in files that need the operator keys");
    return PM3_SUCCESS;
}

int myki_selftest(void) {

    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "Testing myki decode");

    // Metrodroid MykiTest mocked data
    static uint8_t file[16] = {
        0xC9, 0xB4, 0x04, 0x00, 0x4E, 0x61, 0xBC, 0x00
    };

    bool ok = true;
    char serial[24] = {0};
    ok &= transit_check("serial decoded", myki_serial_str(file, serial, sizeof(serial)), true);
    ok &= transit_check_str("serial", serial, "308425123456780");

    uint8_t bad[8] = { 0xC9, 0xB4, 0x04, 0x01 };
    ok &= transit_check("wrong prefix rejected", myki_serial_str(bad, serial, sizeof(serial)), false);

    desfire_dump_t *dump = calloc(1, sizeof(desfire_dump_t));
    if (dump == NULL) {
        return PM3_EMALLOC;
    }
    dump->appcount = 2;
    dump->app[0].aid = MYKI_AID_1;
    dump->app[0].filecount = 1;
    dump->app[0].files[0].num = MYKI_FID_SERIAL;
    dump->app[0].files[0].read_ok = true;
    dump->app[0].files[0].data = file;
    dump->app[0].files[0].datalen = sizeof(file);
    dump->app[1].aid = MYKI_AID_2;
    ok &= transit_check("detected", is_valid_myki_card(dump), true);
    ok &= transit_mfdes_check_identify("identify", dump, "myki", TRANSIT_ID_MATCH);
    if (ok) {
        myki_parser_parse(dump);
    }
    dump->appcount = 1;
    ok &= transit_check("one AID only rejected", is_valid_myki_card(dump), false);
    ok &= transit_mfdes_check_identify("not identified", dump, "myki", TRANSIT_ID_NONE);
    free(dump);

    return transit_selftest_result("myki", ok);
}
