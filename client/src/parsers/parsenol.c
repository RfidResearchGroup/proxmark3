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
// nol (Dubai) parser for MIFARE DESFire dumps
//-----------------------------------------------------------------------------

#include "parsenol.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "commonutil.h"         // MemBeToUint2byte
#include "ui.h"                 // PrintAndLogEx
#include "parsetransit.h"

// serial bits 61..92, card type at byte 12
#define NOL_SERIAL_MIN_LEN      14

static const desfire_dump_app_t *nol_find_app(const desfire_dump_t *dump, uint32_t aid) {
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

static const desfire_dump_file_t *nol_find_file(const desfire_dump_app_t *app, uint8_t fid) {
    for (uint8_t i = 0; i < app->filecount && i < DESFIRE_MAX_FILE_COUNT; i++) {
        if (app->files[i].num == fid) {
            return &app->files[i];
        }
    }
    return NULL;
}

static const char *nol_type_str(uint16_t type) {
    switch (type) {
        case 0x4d5:
            return "Silver";
        case 0x4d9:
            return "Red";
        default:
            return "unknown";
    }
}

static void nol_serial_str(const uint8_t *d, char *out, size_t outlen) {
    uint32_t s = (uint32_t)transit_bits_be(d, NOL_SERIAL_MIN_LEN, 61, 32);
    snprintf(out, outlen, "%03u %03u %04u", (s / 10000000U) % 1000U, (s / 10000U) % 1000U, s % 10000U);
}

transit_id_t nol_identify(const transit_mfdes_info_t *info) {
    return (transit_mfdes_info_has_aid(info, NOL_AID_TRANSIT) && transit_mfdes_info_has_aid(info, NOL_AID_SERIAL)) ? TRANSIT_ID_MATCH : TRANSIT_ID_NONE;
}

bool is_valid_nol_card(const desfire_dump_t *dump) {
    transit_mfdes_info_t info;
    transit_mfdes_info_from_dump(dump, &info);
    return nol_identify(&info) == TRANSIT_ID_MATCH;
}

int nol_parser_parse(const desfire_dump_t *dump) {

    if (is_valid_nol_card(dump) == false) {
        return PM3_EINVARG;
    }

    transit_print_header("nol");
    transit_print_kv("Issuer", "Roads and Transport Authority, Dubai");

    const desfire_dump_file_t *f = nol_find_file(nol_find_app(dump, NOL_AID_SERIAL), NOL_FID_SERIAL);
    if (f == NULL || f->read_ok == false || f->data == NULL || f->datalen < NOL_SERIAL_MIN_LEN) {
        PrintAndLogEx(HINT, "Hint: Use `" _YELLOW_("hf mfdes dump --no-auth") "`");
        return PM3_SUCCESS;
    }

    char buf[24];
    nol_serial_str(f->data, buf, sizeof(buf));
    transit_print_kv("Serial", _YELLOW_("%s"), buf);
    uint16_t type = MemBeToUint2byte(f->data + 12);
    transit_print_kv("Card type", "%s ( %03X )", nol_type_str(type), type);
    PrintAndLogEx(INFO, "Balance and trips are in files that need the operator keys");
    return PM3_SUCCESS;
}

int nol_selftest(void) {

    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "Testing nol decode");

    // synthetic file, serial 1234567890 at bit 61, silver card
    uint8_t file[64] = {0};
    transit_set_bits_be(file, sizeof(file), 61, 32, 1234567890);
    file[12] = 0x04;
    file[13] = 0xd5;

    bool ok = true;
    char buf[24];
    nol_serial_str(file, buf, sizeof(buf));
    ok &= transit_check_str("serial", buf, "123 456 7890");
    ok &= transit_check_str("type", nol_type_str(MemBeToUint2byte(file + 12)), "Silver");

    desfire_dump_t *dump = calloc(1, sizeof(desfire_dump_t));
    if (dump == NULL) {
        return PM3_EMALLOC;
    }
    dump->appcount = 2;
    dump->app[0].aid = NOL_AID_TRANSIT;
    dump->app[1].aid = NOL_AID_SERIAL;
    dump->app[1].filecount = 1;
    dump->app[1].files[0].num = NOL_FID_SERIAL;
    dump->app[1].files[0].read_ok = true;
    dump->app[1].files[0].data = file;
    dump->app[1].files[0].datalen = sizeof(file);
    ok &= transit_check("detected", is_valid_nol_card(dump), true);
    ok &= transit_mfdes_check_identify("identify", dump, "nol", TRANSIT_ID_MATCH);
    if (ok) {
        nol_parser_parse(dump);
    }
    dump->app[0].aid = 0x000001;
    ok &= transit_check("FFFFFF alone rejected", is_valid_nol_card(dump), false);
    ok &= transit_mfdes_check_identify("not identified", dump, "nol", TRANSIT_ID_NONE);
    free(dump);

    return transit_selftest_result("nol", ok);
}
