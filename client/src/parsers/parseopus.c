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
// Opus (Montreal / Quebec) Calypso parser
//-----------------------------------------------------------------------------

#include "parseopus.h"

#include <stdio.h>
#include <string.h>

#include "ui.h"                 // PrintAndLogEx
#include "parsecalypso.h"

//-----------------------------------------------------------------------------
// Layouts, the unknown fields are only there to keep the offsets right
//-----------------------------------------------------------------------------

static const en1545_field_t oc_dates[] = {
    EN1545_INT("ContractStartDate", 14),
    EN1545_INT("ContractEndDate", 14),
};

static const en1545_field_t oc_tail[] = {
    EN1545_INT("ContractUnknownB", 17),
    EN1545_INT("ContractSaleDate", 14),
    EN1545_INT("ContractSaleTime", 11),
    EN1545_INT("ContractUnknownC", 36),
    EN1545_INT("ContractStatus", 8),
    EN1545_INT("ContractUnknownD", 36),
};

static const en1545_field_t oc_bitmap[] = {
    EN1545_INT("ContractProvider", 8),
    EN1545_INT("ContractTariff", 16),
    EN1545_BITMAP(oc_dates),
    EN1545_CONTAINER(oc_tail),
};

static const en1545_field_t oc_fields[] = {
    EN1545_INT("ContractUnknownA", 3),
    EN1545_BITMAP(oc_bitmap),
};

static const en1545_field_t opus_contract = EN1545_CONTAINER(oc_fields);

static const en1545_field_t oe_data[] = {
    EN1545_INT("EventFirstStampDate", 14),
    EN1545_INT("EventFirstStampTime", 11),
    EN1545_INT("EventDataSimulation", 1),
    EN1545_INT("EventUnknownF", 4),
    EN1545_INT("EventUnknownG", 4),
    EN1545_INT("EventUnknownH", 4),
    EN1545_INT("EventUnknownI", 4),
};

static const en1545_field_t oe_bitmap[] = {
    EN1545_INT("EventUnknownA", 8),
    EN1545_INT("EventUnknownB", 8),
    EN1545_INT("EventServiceProvider", 8),
    EN1545_INT("EventUnknownC", 16),
    EN1545_INT("EventRouteNumber", 16),
    EN1545_INT("EventUnknownD", 16),
    EN1545_INT("EventUnknownE", 16),
    EN1545_INT("EventContractPointer", 5),
    EN1545_BITMAP(oe_data),
};

static const en1545_field_t oe_fields[] = {
    EN1545_INT("EventDate", 14),
    EN1545_INT("EventTime", 11),
    EN1545_INT("EventUnknownX", 19),
    EN1545_BITMAP(oe_bitmap),
};

static const en1545_field_t opus_event = EN1545_CONTAINER(oe_fields);

static const char *opus_tariff_str(uint64_t tariff) {
    switch (tariff) {
        case 0xB1:
            return "monthly subscription";
        case 0xB2:
        case 0xC9:
            return "weekly subscription";
        case 0x1C7:
            return "single trips";
        default:
            return "unknown";
    }
}

//-----------------------------------------------------------------------------
// Printing
//-----------------------------------------------------------------------------

static void opus_print_contract(const transit_calypso_card_t *card, uint8_t recno) {
    en1545_parsed_t c;
    const transit_calypso_record_t *rec = &card->contracts[recno - 1];
    (void)en1545_parse(rec->data, rec->len, 0, &opus_contract, &c);

    char label[24];
    char buf[32];
    char buf2[32];
    uint64_t v;

    uint64_t tariff = en1545_get_or(&c, "ContractTariff", 0, 0);
    snprintf(label, sizeof(label), "Contract %u", recno);
    transit_print_kv(label, "tariff " _YELLOW_("%03" PRIX64) " ( %s ), provider %" PRIu64, tariff,
                     opus_tariff_str(tariff), en1545_get_or(&c, "ContractProvider", 0, 0));

    bool has_end = en1545_get(&c, "ContractEndDate", 0, &v);
    if (en1545_get(&c, "ContractStartDate", 0, &v) || has_end) {
        en1545_date_str(buf, sizeof(buf), en1545_get_or(&c, "ContractStartDate", 0, 0));
        en1545_date_str(buf2, sizeof(buf2), en1545_get_or(&c, "ContractEndDate", 0, 0));
        transit_print_kv("  Validity", _YELLOW_("%s") " .. " _YELLOW_("%s"), buf, buf2);
    }
    if (en1545_get(&c, "ContractSaleDate", 0, &v)) {
        en1545_datetime_str(buf, sizeof(buf), v, en1545_get_or(&c, "ContractSaleTime", 0, 0));
        transit_print_kv("  Sold", "%s", buf);
    }
    if (en1545_get(&c, "ContractStatus", 0, &v)) {
        transit_print_kv("  Status", "%02" PRIX64, v);
    }

    // a counter without an end date is a trip count
    uint32_t ctr;
    if (calypso_contract_counter(card, recno, &ctr)) {
        if (en1545_get_or(&c, "ContractEndDate", 0, 0) == 0) {
            transit_print_kv("  Trips left", _GREEN_("%u"), ctr);
        } else {
            transit_print_kv("  Counter", "%06X", ctr);
        }
    }
}

static void opus_print_event(const transit_calypso_card_t *card, uint8_t n) {
    en1545_parsed_t e;
    (void)en1545_parse(card->events[n].data, card->events[n].len, 0, &opus_event, &e);

    char when[32];
    char label[16];
    en1545_datetime_str(when, sizeof(when), en1545_get_or(&e, "EventDate", 0, 0), en1545_get_or(&e, "EventTime", 0, 0));
    snprintf(label, sizeof(label), "Event %u", n + 1);
    transit_print_kv(label, _YELLOW_("%s") "  provider %" PRIu64 ", route %" PRIu64 ", contract %" PRIu64, when,
                     en1545_get_or(&e, "EventServiceProvider", 0, 0), en1545_get_or(&e, "EventRouteNumber", 0, 0),
                     en1545_get_or(&e, "EventContractPointer", 0, 0));

    uint64_t v;
    if (en1545_get(&e, "EventFirstStampDate", 0, &v)) {
        en1545_datetime_str(when, sizeof(when), v, en1545_get_or(&e, "EventFirstStampTime", 0, 0));
        transit_print_kv("  First stamp", "%s", when);
    }
}

bool is_valid_opus_card(const transit_calypso_card_t *card) {
    return calypso_intercode_network(card) == OPUS_NETWORK_ID;
}

int opus_parser_parse(const transit_calypso_card_t *card) {
    if (is_valid_opus_card(card) == false) {
        return PM3_EINVARG;
    }

    transit_print_header("Opus (Montreal / Quebec)");
    calypso_print_serial(card, true);

    en1545_parsed_t env;
    (void)en1545_parse(card->env.data, card->env.len, 0, &calypso_intercode_env, &env);
    char buf[32];
    transit_print_kv("Env version", "%" PRIu64, en1545_get_or(&env, "EnvVersionNumber", 0, 0));
    transit_print_kv("Network", "%06X", OPUS_NETWORK_ID);
    uint64_t v;
    if (en1545_get(&env, "EnvApplicationValidityEndDate", 0, &v)) {
        en1545_date_str(buf, sizeof(buf), v);
        transit_print_kv("Valid until", _YELLOW_("%s"), buf);
    }

    for (uint8_t i = 0; i < card->contract_count && i < TRANSIT_CALYPSO_MAX_CONTRACTS; i++) {
        if (calypso_record_empty(&card->contracts[i]) == false) {
            opus_print_contract(card, i + 1);
        }
    }
    for (uint8_t i = 0; i < card->event_count && i < TRANSIT_CALYPSO_MAX_EVENTS; i++) {
        if (calypso_record_empty(&card->events[i]) == false) {
            opus_print_event(card, i);
        }
    }
    return PM3_SUCCESS;
}

//-----------------------------------------------------------------------------
// Self test, records built from the layouts above
//-----------------------------------------------------------------------------

int opus_selftest(void) {
    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "Testing Opus decode");

    transit_calypso_card_t card;
    memset(&card, 0, sizeof(card));

    // env: version 1, bitmap {network}
    card.env.len = TRANSIT_CALYPSO_REC_LEN;
    transit_set_bits_be(card.env.data, card.env.len, 0, 6, 1);
    transit_set_bits_be(card.env.data, card.env.len, 6, 7, 0x01);
    transit_set_bits_be(card.env.data, card.env.len, 13, 24, OPUS_NETWORK_ID);

    // contract: 3 unknown bits, bitmap {provider, tariff}, no dates -> trip counter
    transit_calypso_record_t *c = &card.contracts[0];
    c->len = TRANSIT_CALYPSO_REC_LEN;
    size_t off = 3;
    transit_set_bits_be(c->data, c->len, off, 4, 0x3);
    off += 4;
    transit_set_bits_be(c->data, c->len, off, 8, 2);
    off += 8;
    transit_set_bits_be(c->data, c->len, off, 16, 0x1C7);
    card.contract_count = 1;

    card.counters.len = TRANSIT_CALYPSO_REC_LEN;
    transit_set_bits_be(card.counters.data, card.counters.len, 0, 24, 9);

    // event: 2023-11-15 17:45, bitmap {provider, route, contract pointer}
    transit_calypso_record_t *e = &card.events[0];
    e->len = TRANSIT_CALYPSO_REC_LEN;
    off = 0;
    transit_set_bits_be(e->data, e->len, off, 14, 9814);
    off += 14;
    transit_set_bits_be(e->data, e->len, off, 11, 1065);
    off += 11 + 19;
    transit_set_bits_be(e->data, e->len, off, 9, (1u << 2) | (1u << 4) | (1u << 7));
    off += 9;
    transit_set_bits_be(e->data, e->len, off, 8, 2);
    off += 8;
    transit_set_bits_be(e->data, e->len, off, 16, 747);
    off += 16;
    transit_set_bits_be(e->data, e->len, off, 5, 1);
    card.event_count = 1;

    bool ok = true;
    ok &= transit_check("detect", is_valid_opus_card(&card), true);

    en1545_parsed_t cp;
    (void)en1545_parse(c->data, c->len, 0, &opus_contract, &cp);
    ok &= transit_check("contract provider", en1545_get_or(&cp, "ContractProvider", 0, 0), 2);
    ok &= transit_check("contract tariff", en1545_get_or(&cp, "ContractTariff", 0, 0), 0x1C7);
    ok &= transit_check("no end date", en1545_get(&cp, "ContractEndDate", 0, NULL), false);

    en1545_parsed_t ep;
    (void)en1545_parse(e->data, e->len, 0, &opus_event, &ep);
    char buf[32];
    en1545_datetime_str(buf, sizeof(buf), en1545_get_or(&ep, "EventDate", 0, 0), en1545_get_or(&ep, "EventTime", 0, 0));
    ok &= transit_check_str("event time", buf, "2023-11-15 17:45");
    ok &= transit_check("event route", en1545_get_or(&ep, "EventRouteNumber", 0, 0), 747);
    ok &= transit_check("event contract ptr", en1545_get_or(&ep, "EventContractPointer", 0, 0), 1);

    // no ICC record, the FCI serial is used instead
    ok &= transit_check("no icc, no card number", calypso_icc_card_number(&card, buf, sizeof(buf)), false);

    // an Intercode card must not be taken for Opus
    transit_set_bits_be(card.env.data, card.env.len, 13, 24, 0x250901);
    ok &= transit_check("rejects Navigo env", is_valid_opus_card(&card), false);
    transit_set_bits_be(card.env.data, card.env.len, 13, 24, OPUS_NETWORK_ID);

    if (ok) {
        ok &= (opus_parser_parse(&card) == PM3_SUCCESS);
    }
    return transit_selftest_result("Opus", ok);
}
