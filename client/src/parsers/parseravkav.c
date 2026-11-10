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
// Rav-Kav (Israel) Calypso parser
//-----------------------------------------------------------------------------

#include "parseravkav.h"

#include <stdio.h>
#include <string.h>

#include "ui.h"                 // PrintAndLogEx
#include "parsecalypso.h"

// Event and contract times are seconds since 1997-01-01 UTC
#define RAVKAV_SECS_TO_1997     ((int64_t)TRANSIT_DAYS_TO_1997 * 86400)

#define RAVKAV_EVENT_CANCELLED  9

//-----------------------------------------------------------------------------
// Layouts
//-----------------------------------------------------------------------------

// Holder birth date and id number follow, left out on purpose
static const en1545_field_t rk_env_fields[] = {
    EN1545_INT("EnvVersionNumber", 3),
    EN1545_INT("EnvNetworkId", 20),
    EN1545_INT("EnvUnknownA", 26),
    EN1545_INT("EnvApplicationIssueDate", 14),
    EN1545_INT("EnvApplicationValidityEndDate", 14),
    EN1545_INT("EnvPayMethod", 3),
    EN1545_INT("HolderBirthDate", 32),
    EN1545_INT("EnvUnknownB", 44),
    EN1545_INT("HolderIdNumber", 30),
};

static const en1545_field_t ravkav_env = EN1545_CONTAINER(rk_env_fields);

static const en1545_field_t rk_c_bitmap[] = {
    EN1545_INT("ContractUnknownA", 5),
    EN1545_INT("ContractRestrictCode", 5),
    EN1545_INT("ContractRestrictDuration", 6),
    EN1545_INT("ContractEndDate", 14),
    EN1545_INT("ContractDuration", 8),
    EN1545_INT("ContractUnknownB", 32),
    EN1545_INT("ContractUnknownC", 6),
    EN1545_INT("ContractUnknownD", 32),
    EN1545_INT("ContractUnknownE", 32),
};

static const en1545_field_t rk_c_fields[] = {
    EN1545_INT("ContractVersion", 3),
    EN1545_INT("ContractStartDate", 14),
    EN1545_INT("ContractProvider", 8),
    EN1545_INT("ContractTariff", 11),
    EN1545_INT("ContractSaleDate", 14),
    EN1545_INT("ContractSaleDevice", 12),
    EN1545_INT("ContractSaleNumber", 10),
    EN1545_INT("ContractInterchange", 1),
    EN1545_BITMAP(rk_c_bitmap),
};

static const en1545_field_t ravkav_contract = EN1545_CONTAINER(rk_c_fields);

static const en1545_field_t rk_e_loc[] = {
    EN1545_INT("EventLocationId", 16),
    EN1545_INT("EventRouteNumber", 16),
    EN1545_INT("EventStopEnRoute", 8),
    EN1545_INT("EventUnknownA", 12),
    EN1545_INT("EventVehicleId", 14),
    EN1545_INT("EventUnknownB", 4),
    EN1545_INT("EventUnknownC", 8),
};

static const en1545_field_t rk_e_fare[] = {
    EN1545_INT("EventRouteSystem", 10),
    EN1545_INT("EventFareCode", 8),
    EN1545_INT("EventPriceAmount", 16),
};

static const en1545_field_t rk_e_ext[] = {
    EN1545_CONTAINER(rk_e_fare),
    EN1545_INT("EventUnknownD", 32),
    EN1545_INT("EventUnknownE", 32),
};

static const en1545_field_t rk_e_fields[] = {
    EN1545_INT("EventVersion", 3),
    EN1545_INT("EventServiceProvider", 8),
    EN1545_INT("EventContractPointer", 4),
    EN1545_INT("EventCode", 8),
    EN1545_INT("EventDateTime", 30),
    EN1545_INT("EventTransferFlag", 1),
    EN1545_INT("EventFirstStampDateTime", 30),
    EN1545_INT("EventContractPrefs", 32),
    EN1545_BITMAP(rk_e_loc),
    EN1545_BITMAP(rk_e_ext),
};

static const en1545_field_t ravkav_event = EN1545_CONTAINER(rk_e_fields);

//-----------------------------------------------------------------------------
// Printing
//-----------------------------------------------------------------------------

static void ravkav_secs_str(char *out, size_t outlen, uint64_t secs) {
    if (secs == 0) {
        snprintf(out, outlen, "-");
        return;
    }
    transit_datetime_str(out, outlen, (int64_t)secs + RAVKAV_SECS_TO_1997);
}

// Tariff bits 6..8 say what the contract counter holds
static uint8_t ravkav_counter_use(uint64_t tariff) {
    return (uint8_t)((tariff >> 6) & 0x7);
}

static void ravkav_print_contract(const transit_calypso_card_t *card, uint8_t recno) {
    en1545_parsed_t c;
    const transit_calypso_record_t *rec = &card->contracts[recno - 1];
    (void)en1545_parse(rec->data, rec->len, 0, &ravkav_contract, &c);

    char label[24];
    char buf[32];
    char buf2[32];
    uint64_t v;

    uint64_t tariff = en1545_get_or(&c, "ContractTariff", 0, 0);
    snprintf(label, sizeof(label), "Contract %u", recno);
    transit_print_kv(label, "tariff " _YELLOW_("%" PRIu64) "%s, provider %" PRIu64, tariff,
                     (tariff == 641) ? " ( generic trips )" : "", en1545_get_or(&c, "ContractProvider", 0, 0));

    en1545_date_str(buf, sizeof(buf), en1545_get_or(&c, "ContractStartDate", 0, 0));
    if (en1545_get(&c, "ContractEndDate", 0, &v)) {
        en1545_date_str(buf2, sizeof(buf2), v);
        transit_print_kv("  Validity", _YELLOW_("%s") " .. " _YELLOW_("%s"), buf, buf2);
    } else {
        transit_print_kv("  Valid from", _YELLOW_("%s"), buf);
    }
    en1545_date_str(buf, sizeof(buf), en1545_get_or(&c, "ContractSaleDate", 0, 0));
    transit_print_kv("  Sold", "%s, device %" PRIu64 ", sale %" PRIu64, buf,
                     en1545_get_or(&c, "ContractSaleDevice", 0, 0), en1545_get_or(&c, "ContractSaleNumber", 0, 0));

    uint32_t ctr;
    if (calypso_contract_counter(card, recno, &ctr)) {
        uint8_t use = ravkav_counter_use(tariff);
        if (use == 3) {
            transit_money_str(buf, sizeof(buf), ctr, 2, "ILS");
            transit_print_kv("  Balance", _GREEN_("%s"), buf);
        } else if (use == 2) {
            transit_print_kv("  Trips left", _GREEN_("%u"), ctr);
        } else {
            transit_print_kv("  Counter", "%06X", ctr);
        }
    }
}

static void ravkav_print_event(const transit_calypso_card_t *card, uint8_t n) {
    en1545_parsed_t e;
    (void)en1545_parse(card->events[n].data, card->events[n].len, 0, &ravkav_event, &e);

    uint64_t code = en1545_get_or(&e, "EventCode", 0, 0);
    if ((code & 0x0F) == RAVKAV_EVENT_CANCELLED) {
        return;
    }

    char when[32];
    char label[16];
    ravkav_secs_str(when, sizeof(when), en1545_get_or(&e, "EventDateTime", 0, 0));
    snprintf(label, sizeof(label), "Event %u", n + 1);
    transit_print_kv(label, _YELLOW_("%s") " UTC  %s, provider %" PRIu64 ", contract %" PRIu64, when,
                     calypso_event_action_str(code & 0x0F), en1545_get_or(&e, "EventServiceProvider", 0, 0),
                     en1545_get_or(&e, "EventContractPointer", 0, 0));

    uint64_t v;
    if (en1545_get(&e, "EventRouteNumber", 0, &v)) {
        transit_print_kv("  Route", "%" PRIu64, v);
    }
    if (en1545_get(&e, "EventLocationId", 0, &v)) {
        transit_print_kv("  Location", "%" PRIu64, v);
    }
    if (en1545_get(&e, "EventPriceAmount", 0, &v)) {
        char buf[32];
        transit_money_str(buf, sizeof(buf), (int64_t)v, 2, "ILS");
        transit_print_kv("  Price", "%s", buf);
    }
}

bool is_valid_ravkav_card(const transit_calypso_card_t *card) {
    if (card == NULL || card->env.len < 3) {
        return false;
    }
    uint32_t net = (uint32_t)transit_bits_be(card->env.data, card->env.len, 3, 20);
    return (net >> 8) == RAVKAV_COUNTRY_ISRAEL;
}

int ravkav_parser_parse(const transit_calypso_card_t *card) {
    if (is_valid_ravkav_card(card) == false) {
        return PM3_EINVARG;
    }

    en1545_parsed_t env;
    (void)en1545_parse(card->env.data, card->env.len, 0, &ravkav_env, &env);

    transit_print_header("Rav-Kav (Israel)");
    calypso_print_serial(card, false);

    char buf[32];
    transit_print_kv("Env version", "%" PRIu64, en1545_get_or(&env, "EnvVersionNumber", 0, 0));
    transit_print_kv("Network", "%05" PRIX64, en1545_get_or(&env, "EnvNetworkId", 0, 0));
    en1545_date_str(buf, sizeof(buf), en1545_get_or(&env, "EnvApplicationIssueDate", 0, 0));
    transit_print_kv("Issued", "%s", buf);
    en1545_date_str(buf, sizeof(buf), en1545_get_or(&env, "EnvApplicationValidityEndDate", 0, 0));
    transit_print_kv("Valid until", _YELLOW_("%s"), buf);
    transit_print_kv("Card type", "%s", (en1545_get_or(&env, "HolderIdNumber", 0, 0) != 0) ? "personal" : "anonymous");

    for (uint8_t i = 0; i < card->contract_count && i < TRANSIT_CALYPSO_MAX_CONTRACTS; i++) {
        if (calypso_record_empty(&card->contracts[i]) == false) {
            ravkav_print_contract(card, i + 1);
        }
    }
    for (uint8_t i = 0; i < card->event_count && i < TRANSIT_CALYPSO_MAX_EVENTS; i++) {
        if (calypso_record_empty(&card->events[i]) == false) {
            ravkav_print_event(card, i);
        }
    }
    return PM3_SUCCESS;
}

//-----------------------------------------------------------------------------
// Self test, records built from the layouts above
//-----------------------------------------------------------------------------

int ravkav_selftest(void) {
    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "Testing Rav-Kav decode");

    transit_calypso_card_t card;
    memset(&card, 0, sizeof(card));

    // env: version 1, network 37602, issued 2020-01-01, valid to 2026-01-01
    card.env.len = TRANSIT_CALYPSO_REC_LEN;
    transit_set_bits_be(card.env.data, card.env.len, 0, 3, 1);
    transit_set_bits_be(card.env.data, card.env.len, 3, 20, 0x37602);
    transit_set_bits_be(card.env.data, card.env.len, 49, 14, 8400);
    transit_set_bits_be(card.env.data, card.env.len, 63, 14, 10592);

    // contract: stored value, tariff counter use 3
    transit_calypso_record_t *c = &card.contracts[0];
    c->len = TRANSIT_CALYPSO_REC_LEN;
    transit_set_bits_be(c->data, c->len, 3, 14, 9800);
    transit_set_bits_be(c->data, c->len, 17, 8, 3);
    transit_set_bits_be(c->data, c->len, 25, 11, (3u << 6) | 1);
    card.contract_count = 1;

    // Rav-Kav has no 2069, the purse sits in the contract's own counter 202A
    card.contract_counters[0].len = TRANSIT_CALYPSO_REC_LEN;
    transit_set_bits_be(card.contract_counters[0].data, card.contract_counters[0].len, 0, 24, 4250);

    // event: entry at 2023-11-15 06:30:00 UTC, bitmap {route}, price 5.50
    transit_calypso_record_t *e = &card.events[0];
    e->len = TRANSIT_CALYPSO_REC_LEN;
    size_t off = 3;
    transit_set_bits_be(e->data, e->len, off, 8, 3);
    off += 8;
    transit_set_bits_be(e->data, e->len, off, 4, 1);
    off += 4;
    transit_set_bits_be(e->data, e->len, off, 8, 0x01);
    off += 8;
    transit_set_bits_be(e->data, e->len, off, 30, (9814ull * 86400) + (6 * 3600) + (30 * 60));
    off += 30 + 1 + 30 + 32;
    transit_set_bits_be(e->data, e->len, off, 7, 0x02);
    off += 7;
    transit_set_bits_be(e->data, e->len, off, 16, 480);
    off += 16;
    transit_set_bits_be(e->data, e->len, off, 3, 0x01);
    off += 3 + 10 + 8;
    transit_set_bits_be(e->data, e->len, off, 16, 550);
    card.event_count = 1;

    bool ok = true;
    ok &= transit_check("detect", is_valid_ravkav_card(&card), true);
    ok &= transit_calypso_check_identify("identify", &card, "Rav-Kav", TRANSIT_ID_MATCH);

    en1545_parsed_t env;
    (void)en1545_parse(card.env.data, card.env.len, 0, &ravkav_env, &env);
    char buf[32];
    en1545_date_str(buf, sizeof(buf), en1545_get_or(&env, "EnvApplicationValidityEndDate", 0, 0));
    ok &= transit_check_str("env validity end", buf, "2026-01-01");

    en1545_parsed_t cp;
    (void)en1545_parse(c->data, c->len, 0, &ravkav_contract, &cp);
    ok &= transit_check("counter use", ravkav_counter_use(en1545_get_or(&cp, "ContractTariff", 0, 0)), 3);
    ok &= transit_check("contract provider", en1545_get_or(&cp, "ContractProvider", 0, 0), 3);

    en1545_parsed_t ep;
    (void)en1545_parse(e->data, e->len, 0, &ravkav_event, &ep);
    ravkav_secs_str(buf, sizeof(buf), en1545_get_or(&ep, "EventDateTime", 0, 0));
    ok &= transit_check_str("event time", buf, "2023-11-15 06:30:00");
    ok &= transit_check("event route", en1545_get_or(&ep, "EventRouteNumber", 0, 0), 480);
    ok &= transit_check("event price", en1545_get_or(&ep, "EventPriceAmount", 0, 0), 550);

    uint32_t ctr = 0;
    ok &= transit_check("own counter used", calypso_contract_counter(&card, 1, &ctr), true);
    ok &= transit_check("own counter value", ctr, 4250);
    ok &= transit_check("no counter for 2", calypso_contract_counter(&card, 2, &ctr), false);

    // 2069 wins when both are present
    transit_calypso_card_t both = card;
    both.counters.len = TRANSIT_CALYPSO_REC_LEN;
    transit_set_bits_be(both.counters.data, both.counters.len, 0, 24, 77);
    (void)calypso_contract_counter(&both, 1, &ctr);
    ok &= transit_check("2069 first", ctr, 77);

    // a French Intercode environment must not match
    transit_calypso_card_t fr;
    memset(&fr, 0, sizeof(fr));
    fr.env.len = TRANSIT_CALYPSO_REC_LEN;
    transit_set_bits_be(fr.env.data, fr.env.len, 0, 6, 1);
    transit_set_bits_be(fr.env.data, fr.env.len, 6, 7, 0x01);
    transit_set_bits_be(fr.env.data, fr.env.len, 13, 24, 0x250901);
    ok &= transit_check("rejects Navigo env", is_valid_ravkav_card(&fr), false);
    ok &= transit_calypso_check_identify("not identified", &fr, "Rav-Kav", TRANSIT_ID_NONE);

    if (ok) {
        ok &= (ravkav_parser_parse(&card) == PM3_SUCCESS);
    }
    return transit_selftest_result("Rav-Kav", ok);
}
