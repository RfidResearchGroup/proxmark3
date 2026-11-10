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
// Podorozhnik / Plantain (Saint Petersburg) parser for MIFARE Classic dumps
//-----------------------------------------------------------------------------

#include "parseplantain.h"

#include <stdio.h>
#include <string.h>

#include "commonutil.h"             // MemLeToUint4byte
#include "ui.h"                     // PrintAndLogEx
#include "parsetransit.h"
#include "parsetransitmfc.h"

#define PLANTAIN_S4_KEY_A       0xE56AC127DD45
#define PLANTAIN_S4_KEY_B       0x19FC84A3784B
#define PLANTAIN_S5_KEY_A       0x77DABC9825E1
#define PLANTAIN_S5_KEY_B       0x9764FEC3154A

// 2010-01-01, minutes count in Moscow local time
#define PLANTAIN_DAYS_TO_2010   14610

#define PLANTAIN_TRANSPORT_METRO        1
#define PLANTAIN_TRANSPORT_BUS_MOBILE   3
#define PLANTAIN_TRANSPORT_BUS          4
#define PLANTAIN_TRANSPORT_SHARED_TAXI  7

typedef struct {
    int32_t balance;            // kopecks
    uint32_t topup_time;        // minutes since 2010
    uint8_t topup_agency;
    uint16_t topup_machine;
    uint32_t topup_amount;

    uint32_t trip_time;
    uint8_t trip_transport;
    uint16_t trip_validator;
    uint32_t trip_fare;
    uint8_t subway_trips;
    uint8_t ground_trips;
    uint8_t extra_count;
    uint32_t extra_times[2];
} plantain_t;

static uint32_t plantain_le(const uint8_t *p, uint8_t n) {
    uint32_t v = 0;
    for (uint8_t i = n; i > 0; i--) {
        v = (v << 8) | p[i - 1];
    }
    return v;
}

static void plantain_time_str(char *out, size_t outlen, uint32_t mins) {
    transit_datetime_str(out, outlen, ((int64_t)PLANTAIN_DAYS_TO_2010 * 86400) + ((int64_t)mins * 60));
}

bool is_valid_plantain_card(const uint8_t *dump, size_t dumplen) {
    if (transit_mfc_block(dump, dumplen, 5, 3) == NULL) {
        return false;
    }
    bool s4 = transit_mfc_has_key(dump, dumplen, 4, PLANTAIN_S4_KEY_A) || transit_mfc_has_key(dump, dumplen, 4, PLANTAIN_S4_KEY_B);
    bool s5 = transit_mfc_has_key(dump, dumplen, 5, PLANTAIN_S5_KEY_A) || transit_mfc_has_key(dump, dumplen, 5, PLANTAIN_S5_KEY_B);
    return s4 && s5;
}

static void plantain_decode(const uint8_t *dump, size_t dumplen, plantain_t *p) {
    memset(p, 0, sizeof(*p));

    // sector 4 blocks 0 and 1 are copies
    const uint8_t *b = transit_mfc_block(dump, dumplen, 4, 0);
    p->balance = (int32_t)MemLeToUint4byte(b);
    b = transit_mfc_block(dump, dumplen, 4, 2);
    p->topup_time = plantain_le(b + 2, 3);
    p->topup_agency = b[5];
    p->topup_machine = (uint16_t)plantain_le(b + 6, 2);
    p->topup_amount = plantain_le(b + 8, 3);

    const uint8_t *b0 = transit_mfc_block(dump, dumplen, 5, 0);
    const uint8_t *b1 = transit_mfc_block(dump, dumplen, 5, 1);
    const uint8_t *b2 = transit_mfc_block(dump, dumplen, 5, 2);
    p->trip_time = plantain_le(b0, 3);
    p->trip_transport = b0[3];
    p->trip_validator = (uint16_t)plantain_le(b0 + 4, 2);
    p->trip_fare = plantain_le(b0 + 6, 4);

    // blocks 1 and 2 are usually equal, take the counters of the newer one
    uint32_t t1 = plantain_le(b1 + 2, 3);
    uint32_t t2 = plantain_le(b2 + 2, 3);
    const uint8_t *cnt = (t2 > t1) ? b2 : b1;
    p->subway_trips = cnt[0];
    p->ground_trips = cnt[1];

    if (t1 != p->trip_time) {
        p->extra_times[p->extra_count++] = t1;
    }
    if (t2 != p->trip_time && t2 != t1) {
        p->extra_times[p->extra_count++] = t2;
    }
}

// 9643 3078 + block 0 bytes 0..6 little endian, 17 digits, then a Luhn digit
static void plantain_serial_str(char *out, size_t outlen, const uint8_t *blk0) {
    uint64_t v = 0;
    for (uint8_t i = 7; i > 0; i--) {
        v = (v << 8) | blk0[i - 1];
    }
    char d[32];
    snprintf(d, sizeof(d), "96433078%017" PRIu64, v);

    // Luhn over the 25 digits, doubling from the rightmost
    int sum = 0;
    size_t n = strlen(d);
    for (size_t i = 0; i < n; i++) {
        int x = d[n - 1 - i] - '0';
        if ((i & 1) == 0) {
            x *= 2;
            if (x > 9) {
                x -= 9;
            }
        }
        sum += x;
    }
    int luhn = (10 - (sum % 10)) % 10;
    snprintf(out, outlen, "%.4s %.4s %.4s %.4s %.4s %.4s %.1s%d", d, d + 4, d + 8, d + 12, d + 16, d + 20, d + 24, luhn);
}

static const char *plantain_transport_str(uint8_t transport, uint16_t validator) {
    switch (transport) {
        case PLANTAIN_TRANSPORT_METRO:
            // misconfigured validators show up as metro, station 0
            return (validator == 0) ? "bus" : "metro";
        case PLANTAIN_TRANSPORT_BUS:
        case PLANTAIN_TRANSPORT_BUS_MOBILE:
            return "bus";
        case PLANTAIN_TRANSPORT_SHARED_TAXI:
            return "shared taxi";
        default:
            return "unknown";
    }
}

int plantain_parser_parse(const uint8_t *dump, size_t dumplen) {
    if (is_valid_plantain_card(dump, dumplen) == false) {
        return PM3_EINVARG;
    }

    plantain_t p;
    plantain_decode(dump, dumplen, &p);

    char buf[64];
    transit_print_header("Podorozhnik");
    plantain_serial_str(buf, sizeof(buf), transit_mfc_block(dump, dumplen, 0, 0));
    transit_print_kv("Card number", _YELLOW_("%s"), buf);
    transit_money_str(buf, sizeof(buf), p.balance, 2, "RUB");
    transit_print_kv("Balance", _YELLOW_("%s"), buf);
    transit_print_kv("Metro trips", "%u", p.subway_trips);
    transit_print_kv("Ground trips", "%u", p.ground_trips);

    if (p.trip_time != 0) {
        char fare[24];
        plantain_time_str(buf, sizeof(buf), p.trip_time);
        transit_money_str(fare, sizeof(fare), p.trip_fare, 2, "RUB");
        if (p.trip_transport == PLANTAIN_TRANSPORT_METRO && p.trip_validator != 0) {
            transit_print_kv("Last trip", "%s  metro, station %u gate %u, fare %s", buf,
                             p.trip_validator >> 6, p.trip_validator & 0x3F, fare);
        } else {
            transit_print_kv("Last trip", "%s  %s, validator %u, fare %s", buf,
                             plantain_transport_str(p.trip_transport, p.trip_validator), p.trip_validator, fare);
        }
    }
    for (uint8_t i = 0; i < p.extra_count; i++) {
        plantain_time_str(buf, sizeof(buf), p.extra_times[i]);
        transit_print_kv("Trip", "%s", buf);
    }
    if (p.topup_time != 0) {
        char amount[24];
        plantain_time_str(buf, sizeof(buf), p.topup_time);
        transit_money_str(amount, sizeof(amount), p.topup_amount, 2, "RUB");
        transit_print_kv("Last top-up", "%s  %s, agency %u, machine %u", buf, amount, p.topup_agency, p.topup_machine);
    }
    PrintAndLogEx(INFO, "Times are Moscow local time");
    return PM3_SUCCESS;
}

// Synthetic card built from the Metrodroid layout
int plantain_selftest(void) {
    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "Testing Podorozhnik decode");

    uint8_t dump[1024] = {0};
    const uint8_t blk0[16] = { 0x04, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x88, 0x44, 0x00, 0xC8, 0x20, 0x00, 0x00, 0x00, 0x16 };
    memcpy(dump, blk0, sizeof(blk0));
    transit_mfc_set_key(dump, sizeof(dump), 4, false, PLANTAIN_S4_KEY_A);
    transit_mfc_set_key(dump, sizeof(dump), 5, true, PLANTAIN_S5_KEY_B);

    uint8_t *s4 = dump + (16 * 16);
    uint8_t *s5 = dump + (20 * 16);
    // balance 123.45, top-up of 100.00 at minute 0x0ABCDE by agency 1 machine 0x1234
    const uint8_t s4b0[] = { 0x39, 0x30, 0x00, 0x00 };
    const uint8_t s4b2[] = { 0x00, 0x00, 0xDE, 0xBC, 0x0A, 0x01, 0x34, 0x12, 0x10, 0x27, 0x00 };
    memcpy(s4, s4b0, sizeof(s4b0));
    memcpy(s4 + 32, s4b2, sizeof(s4b2));
    // trip at minute 0x0ABCE0 by metro, validator 0x0105, fare 50.00
    const uint8_t s5b0[] = { 0xE0, 0xBC, 0x0A, 0x01, 0x05, 0x01, 0x88, 0x13, 0x00, 0x00 };
    const uint8_t s5b1[] = { 0x03, 0x02, 0xE0, 0xBC, 0x0A };
    const uint8_t s5b2[] = { 0x02, 0x02, 0xD0, 0xBC, 0x0A };
    memcpy(s5, s5b0, sizeof(s5b0));
    memcpy(s5 + 16, s5b1, sizeof(s5b1));
    memcpy(s5 + 32, s5b2, sizeof(s5b2));

    bool ok = transit_check("detected", is_valid_plantain_card(dump, sizeof(dump)), 1);

    plantain_t p;
    plantain_decode(dump, sizeof(dump), &p);
    ok &= transit_check("balance", (uint64_t)p.balance, 12345);
    ok &= transit_check("top-up time", p.topup_time, 0x0ABCDE);
    ok &= transit_check("top-up agency", p.topup_agency, 1);
    ok &= transit_check("top-up machine", p.topup_machine, 0x1234);
    ok &= transit_check("top-up amount", p.topup_amount, 10000);
    ok &= transit_check("trip time", p.trip_time, 0x0ABCE0);
    ok &= transit_check("trip validator", p.trip_validator, 0x0105);
    ok &= transit_check("trip fare", p.trip_fare, 5000);
    ok &= transit_check("metro trips", p.subway_trips, 3);
    ok &= transit_check("ground trips", p.ground_trips, 2);
    ok &= transit_check("detached trips", p.extra_count, 1);

    char buf[64];
    plantain_time_str(buf, sizeof(buf), 0);
    ok &= transit_check_str("epoch", buf, "2010-01-01 00:00:00");
    plantain_serial_str(buf, sizeof(buf), blk0);
    // 0x66554433221104 = 28804199028494596, Luhn digit 0
    ok &= transit_check_str("card number", buf, "9643 3078 2880 4199 0284 9459 60");

    transit_mfc_set_key(dump, sizeof(dump), 5, true, 0xFFFFFFFFFFFF);
    ok &= transit_check("wrong sector 5 key rejected", is_valid_plantain_card(dump, sizeof(dump)), 0);

    return transit_selftest_result("Podorozhnik", ok);
}
