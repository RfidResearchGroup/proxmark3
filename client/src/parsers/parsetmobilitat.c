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
// T-Mobilitat (Barcelona) parser for MIFARE DESFire dumps
//-----------------------------------------------------------------------------

#include "parsetmobilitat.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "commonutil.h"         // MemBeToUint4byte
#include "ui.h"                 // PrintAndLogEx
#include "util.h"               // sprint_hex_inrow
#include "parsetransit.h"

// Historical bytes open with this tag on T-Mobilitat cards
static const uint8_t tmobilitat_hist_tag[] = { 0x2A, 0x26 };

// Historical bytes of the ATS, NULL when there are none
static const uint8_t *tmobilitat_hist(const iso14a_card_select_t *card, uint8_t *len) {
    *len = 0;
    if (card->ats_len < 2) {
        return NULL;
    }
    uint8_t tl = card->ats[0];
    uint8_t t0 = card->ats[1];
    uint8_t pos = 2;
    pos += ((t0 & 0x10) ? 1 : 0) + ((t0 & 0x20) ? 1 : 0) + ((t0 & 0x40) ? 1 : 0);
    if (tl > card->ats_len || pos >= tl) {
        return NULL;
    }
    *len = tl - pos;
    return card->ats + pos;
}

// Two check letters, DNI style
static void tmobilitat_control(uint32_t n, char *out) {
    static const char table[] = "TRWAGMYFPDXBNJZSQVHLCKE";
    uint32_t r = n % 23;
    uint32_t q = n / 23;
    out[0] = table[(q + r + 1) % 23];
    out[1] = table[r];
    out[2] = '\0';
}

static void tmobilitat_number_str(uint32_t n, char *out, size_t outlen) {
    char ctl[3];
    tmobilitat_control(n, ctl);
    snprintf(out, outlen, "%03u %03u %03u%s", (n / 1000000) % 1000, (n / 1000) % 1000, n % 1000, ctl);
}

bool is_valid_tmobilitat_card(const desfire_dump_t *dump) {
    if (dump == NULL) {
        return false;
    }
    bool aid = false;
    for (uint8_t i = 0; i < dump->appcount && i < DESFIRE_MAX_APP_COUNT; i++) {
        if (dump->app[i].aid == TMOBILITAT_AID) {
            aid = true;
            break;
        }
    }
    uint8_t hlen = 0;
    const uint8_t *h = tmobilitat_hist(&dump->card_info, &hlen);
    return aid && h != NULL && hlen >= 6 && memcmp(h, tmobilitat_hist_tag, sizeof(tmobilitat_hist_tag)) == 0;
}

int tmobilitat_parser_parse(const desfire_dump_t *dump) {

    if (is_valid_tmobilitat_card(dump) == false) {
        return PM3_EINVARG;
    }

    uint8_t hlen = 0;
    const uint8_t *h = tmobilitat_hist(&dump->card_info, &hlen);

    char buf[32];
    tmobilitat_number_str(MemBeToUint4byte(h + hlen - 4), buf, sizeof(buf));

    transit_print_header("T-Mobilitat");
    transit_print_kv("Issuer", "ATM, Barcelona area");
    transit_print_kv("Card number", _YELLOW_("%s"), buf);
    transit_print_kv("Historical", "%s", sprint_hex_inrow(h, hlen));
    PrintAndLogEx(INFO, "Balance and trips are in files that need the operator keys");
    return PM3_SUCCESS;
}

int tmobilitat_selftest(void) {

    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "Testing T-Mobilitat decode");

    bool ok = true;
    char buf[32];
    tmobilitat_number_str(123456789, buf, sizeof(buf));
    ok &= transit_check_str("card number", buf, "123 456 789GB");

    desfire_dump_t *dump = calloc(1, sizeof(desfire_dump_t));
    if (dump == NULL) {
        return PM3_EMALLOC;
    }
    // synthetic ATS, TL T0 TA TB TC then historical bytes ending in 075BCD15
    const uint8_t ats[] = { 0x0D, 0x78, 0x77, 0x71, 0x02, 0x2A, 0x26, 0x01, 0x02, 0x07, 0x5B, 0xCD, 0x15 };
    memcpy(dump->card_info.ats, ats, sizeof(ats));
    dump->card_info.ats_len = sizeof(ats);
    dump->appcount = 1;
    dump->app[0].aid = TMOBILITAT_AID;

    uint8_t hlen = 0;
    const uint8_t *h = tmobilitat_hist(&dump->card_info, &hlen);
    ok &= transit_check("historical length", hlen, 8);
    ok &= transit_check("number", (h != NULL) ? MemBeToUint4byte(h + hlen - 4) : 0, 123456789);
    ok &= transit_check("detected", is_valid_tmobilitat_card(dump), true);
    if (ok) {
        tmobilitat_parser_parse(dump);
    }

    // Ljubljana Urbana shares the AID
    dump->card_info.ats[5] = 0x80;
    ok &= transit_check("other ATS rejected", is_valid_tmobilitat_card(dump), false);
    free(dump);

    return transit_selftest_result("T-Mobilitat", ok);
}
