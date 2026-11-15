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
// EN 1545 structure walker and Calypso helpers shared by the Calypso parsers
//-----------------------------------------------------------------------------

#include "parsecalypso.h"

#include <stdio.h>
#include <string.h>

#include "commonutil.h"         // ARRAYLEN, MemBeToUint4byte
#include "ui.h"                 // PrintAndLogEx
#include "util.h"               // sprint_hex_inrow

//-----------------------------------------------------------------------------
// Walker
//-----------------------------------------------------------------------------

static void en1545_store(en1545_parsed_t *out, const char *name, uint8_t idx, size_t off, uint16_t bits, uint64_t value) {
    if (out->count >= EN1545_MAX_VALUES) {
        return;
    }
    en1545_value_t *v = &out->v[out->count++];
    v->name = name;
    v->idx = idx;
    v->off = (uint16_t)off;
    v->bits = bits;
    v->value = value;
}

static size_t en1545_walk(const uint8_t *buf, size_t buflen, size_t off, const en1545_field_t *f, uint8_t idx, en1545_parsed_t *out) {
    size_t total = buflen * 8;

    switch (f->kind) {
        case EN1545_K_INT: {
            if (f->bits > 0 && off + f->bits <= total) {
                uint64_t v = (f->bits <= 64) ? transit_bits_be(buf, buflen, off, (uint8_t)f->bits) : 0;
                en1545_store(out, f->name, idx, off, f->bits, v);
            }
            return off + f->bits;
        }
        case EN1545_K_BITMAP: {
            if (off + f->nsub > total) {
                return off + f->nsub;
            }
            uint64_t mask = transit_bits_be(buf, buflen, off, f->nsub);
            off += f->nsub;
            for (uint8_t i = 0; i < f->nsub; i++) {
                if ((mask >> i) & 1) {
                    off = en1545_walk(buf, buflen, off, &f->sub[i], idx, out);
                }
            }
            return off;
        }
        case EN1545_K_CONTAINER: {
            for (uint8_t i = 0; i < f->nsub; i++) {
                off = en1545_walk(buf, buflen, off, &f->sub[i], idx, out);
            }
            return off;
        }
        case EN1545_K_REPEAT: {
            if (off + f->bits > total) {
                return off + f->bits;
            }
            uint64_t cnt = transit_bits_be(buf, buflen, off, (uint8_t)f->bits);
            off += f->bits;
            for (uint64_t i = 0; i < cnt && off < total; i++) {
                off = en1545_walk(buf, buflen, off, f->sub, (uint8_t)i, out);
            }
            return off;
        }
    }
    return off;
}

size_t en1545_parse(const uint8_t *buf, size_t buflen, size_t off, const en1545_field_t *f, en1545_parsed_t *out) {
    memset(out, 0, sizeof(*out));
    if (buf == NULL || f == NULL) {
        return off;
    }
    return en1545_walk(buf, buflen, off, f, 0, out);
}

bool en1545_get(const en1545_parsed_t *p, const char *name, uint8_t idx, uint64_t *value) {
    for (uint8_t i = 0; i < p->count; i++) {
        if (p->v[i].idx == idx && strcmp(p->v[i].name, name) == 0) {
            if (value != NULL) {
                *value = p->v[i].value;
            }
            return true;
        }
    }
    return false;
}

uint64_t en1545_get_or(const en1545_parsed_t *p, const char *name, uint8_t idx, uint64_t def) {
    uint64_t v = def;
    (void)en1545_get(p, name, idx, &v);
    return v;
}

void en1545_date_str(char *out, size_t outlen, uint64_t days) {
    if (days == 0) {
        snprintf(out, outlen, "-");
        return;
    }
    transit_date_str(out, outlen, (int32_t)days + TRANSIT_DAYS_TO_1997);
}

void en1545_datetime_str(char *out, size_t outlen, uint64_t days, uint64_t minutes) {
    if (days == 0 && minutes == 0) {
        snprintf(out, outlen, "-");
        return;
    }
    char d[16];
    transit_date_str(d, sizeof(d), (int32_t)days + TRANSIT_DAYS_TO_1997);
    snprintf(out, outlen, "%s %02u:%02u", d, (unsigned)((minutes / 60) % 24), (unsigned)(minutes % 60));
}

//-----------------------------------------------------------------------------
// Intercode ticketing environment, holder part left out
//-----------------------------------------------------------------------------

static const en1545_field_t env_data[] = {
    EN1545_INT("EnvCardStatus", 1),
    EN1545_INT("EnvExtra", 0),
};

static const en1545_field_t env_bitmap[] = {
    EN1545_INT("EnvNetworkId", 24),
    EN1545_INT("EnvApplicationIssuerId", 8),
    EN1545_INT("EnvApplicationValidityEndDate", 14),
    EN1545_INT("EnvPayMethod", 11),
    EN1545_INT("EnvAuthenticator", 16),
    EN1545_INT("EnvSelectList", 32),
    EN1545_CONTAINER(env_data),
};

static const en1545_field_t env_fields[] = {
    EN1545_INT("EnvVersionNumber", 6),
    EN1545_BITMAP(env_bitmap),
};

const en1545_field_t calypso_intercode_env = EN1545_CONTAINER(env_fields);

//-----------------------------------------------------------------------------
// Calypso helpers
//-----------------------------------------------------------------------------

uint32_t calypso_intercode_network(const transit_calypso_card_t *card) {
    if (card == NULL || card->env.len < 5) {
        return 0;
    }
    // version 6 bits and a 7 bit bitmap whose lowest bit is the network id
    if ((transit_bits_be(card->env.data, card->env.len, 6, 7) & 1) == 0) {
        return 0;
    }
    return (uint32_t)transit_bits_be(card->env.data, card->env.len, 13, 24);
}

bool calypso_record_empty(const transit_calypso_record_t *rec) {
    return (rec == NULL || rec->len == 0 || transit_is_zero(rec->data, rec->len));
}

bool calypso_contract_counter(const transit_calypso_card_t *card, uint8_t recno, uint32_t *value) {
    if (card == NULL || recno == 0 || recno > 4) {
        return false;
    }
    // counters file 2069 holds three bytes per contract
    if (card->counters.len >= (recno * 3)) {
        *value = (uint32_t)transit_bits_be(card->counters.data, card->counters.len, (recno - 1) * 24, 24);
        return true;
    }
    const transit_calypso_record_t *own = &card->contract_counters[recno - 1];
    if (own->len >= 3) {
        *value = (uint32_t)transit_bits_be(own->data, own->len, 0, 24);
        return true;
    }
    return false;
}

const char *calypso_transport_str(uint8_t transport) {
    static const char *names[] = {
        "unspecified", "urban bus", "interurban bus", "metro", "tram", "train",
        "ferry", "toll", "parking", "taxi", "high speed train", "rural bus",
        "express train", "para transit", "self drive", "coach"
    };
    return (transport < ARRAYLEN(names)) ? names[transport] : "other";
}

const char *calypso_event_action_str(uint8_t action) {
    switch (action) {
        case 0x1:
            return "entry";
        case 0x2:
            return "exit";
        case 0x3:
            return "validation";
        case 0x4:
            return "inspection";
        case 0x5:
            return "test validation";
        case 0x6:
            return "entry (interchange)";
        case 0x7:
            return "exit (interchange)";
        case 0x9:
            return "validation cancelled";
        case 0xA:
            return "entry (public road)";
        case 0xB:
            return "exit (public road)";
        case 0xD:
            return "distribution";
        case 0xF:
            return "invalidation";
        default:
            return "unknown";
    }
}

bool calypso_icc_card_number(const transit_calypso_card_t *card, char *out, size_t outlen) {
    if (card == NULL || card->icc.len < 20) {
        return false;
    }
    const uint8_t *d = card->icc.data;

    // OuRA! prints ten hex digits from byte 20, skipping the first nibble
    if (calypso_intercode_network(card) == 0x250502 && card->icc.len >= 26) {
        char hex[13];
        snprintf(hex, sizeof(hex), "%s", sprint_hex_inrow(d + 20, 6));
        snprintf(out, outlen, "%.10s", hex + 1);
        return true;
    }

    uint32_t num = MemBeToUint4byte(d + 16);
    if (num == 0) {
        num = MemBeToUint4byte(d);
    }
    if (num == 0) {
        return false;
    }
    snprintf(out, outlen, "%u", num);
    return true;
}

void calypso_print_serial(const transit_calypso_card_t *card, bool use_icc) {
    char num[16];
    if (use_icc && calypso_icc_card_number(card, num, sizeof(num))) {
        transit_print_kv("Card number", _YELLOW_("%s"), num);
        return;
    }
    if (card->has_serial == false) {
        return;
    }
    transit_print_kv("Serial", _YELLOW_("%s") "  ( %u )", sprint_hex_inrow(card->serial, sizeof(card->serial)),
                     (uint32_t)transit_bits_be(card->serial, sizeof(card->serial), 32, 32));
}

//-----------------------------------------------------------------------------
// Walker self test
//-----------------------------------------------------------------------------

static const en1545_field_t st_rep_item[] = {
    EN1545_INT("A", 4),
    EN1545_INT("B", 3),
};

static const en1545_field_t st_rep_bm[] = {
    EN1545_BITMAP(st_rep_item),
};

static const en1545_field_t st_fields[] = {
    EN1545_INT("Head", 5),
    EN1545_REPEAT(2, st_rep_bm),
    EN1545_INT("Wide", 100),
    EN1545_INT("Tail", 8),
};

static const en1545_field_t st_struct = EN1545_CONTAINER(st_fields);

bool en1545_selftest(void) {
    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "Testing EN 1545 walker");

    // Head=0x15, two repeats: (A=0x9) and (B=0x5), wide field skipped, Tail=0xC3
    uint8_t buf[20] = {0};
    size_t off = 0;
    transit_set_bits_be(buf, sizeof(buf), off, 5, 0x15);
    off += 5;
    transit_set_bits_be(buf, sizeof(buf), off, 2, 2);
    off += 2;
    transit_set_bits_be(buf, sizeof(buf), off, 2, 0x1);     // bitmap: A only
    off += 2;
    transit_set_bits_be(buf, sizeof(buf), off, 4, 0x9);
    off += 4;
    transit_set_bits_be(buf, sizeof(buf), off, 2, 0x2);     // bitmap: B only
    off += 2;
    transit_set_bits_be(buf, sizeof(buf), off, 3, 0x5);
    off += 3 + 100;
    transit_set_bits_be(buf, sizeof(buf), off, 8, 0xC3);
    off += 8;

    en1545_parsed_t p;
    size_t end = en1545_parse(buf, sizeof(buf), 0, &st_struct, &p);

    bool ok = true;
    ok &= transit_check("walker end offset", end, off);
    ok &= transit_check("Head", en1545_get_or(&p, "Head", 0, 0xFF), 0x15);
    ok &= transit_check("repeat 0 A", en1545_get_or(&p, "A", 0, 0xFF), 0x9);
    ok &= transit_check("repeat 0 has no B", en1545_get(&p, "B", 0, NULL), false);
    ok &= transit_check("repeat 1 B", en1545_get_or(&p, "B", 1, 0xFF), 0x5);
    ok &= transit_check("wide field marked", en1545_get(&p, "Wide", 0, NULL), true);
    ok &= transit_check("Tail", en1545_get_or(&p, "Tail", 0, 0xFF), 0xC3);

    // truncated: tail no longer fits and must not be stored
    (void)en1545_parse(buf, 15, 0, &st_struct, &p);
    ok &= transit_check("truncated tail dropped", en1545_get(&p, "Tail", 0, NULL), false);
    return ok;
}
