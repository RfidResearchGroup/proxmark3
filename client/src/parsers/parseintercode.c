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
// Intercode (French Calypso networks) parser, Navigo included
//-----------------------------------------------------------------------------

#include "parseintercode.h"

#include <stdio.h>
#include <string.h>

#include "commonutil.h"         // ARRAYLEN
#include "ui.h"                 // PrintAndLogEx
#include "parsecalypso.h"

// Navigo service providers whose metro / tram locations are sector + station
#define NAVIGO_PROVIDER_SNCF    2
#define NAVIGO_PROVIDER_RATP    3

//-----------------------------------------------------------------------------
// Layouts
//-----------------------------------------------------------------------------

static const en1545_field_t ev_data[] = {
    EN1545_INT("EventFirstStampDate", 14),
    EN1545_INT("EventFirstStampTime", 11),
    EN1545_INT("EventDataSimulation", 1),
    EN1545_INT("EventDataTrip", 2),
    EN1545_INT("EventDataRouteDirection", 2),
};

static const en1545_field_t ev_bitmap[] = {
    EN1545_INT("EventDisplayData", 8),
    EN1545_INT("EventNetworkId", 24),
    EN1545_INT("EventCode", 8),
    EN1545_INT("EventResult", 8),
    EN1545_INT("EventServiceProvider", 8),
    EN1545_INT("EventNotOkCounter", 8),
    EN1545_INT("EventSerialNumber", 24),
    EN1545_INT("EventDestination", 16),
    EN1545_INT("EventLocationId", 16),
    EN1545_INT("EventLocationGate", 8),
    EN1545_INT("EventDevice", 16),
    EN1545_INT("EventRouteNumber", 16),
    EN1545_INT("EventRouteVariant", 8),
    EN1545_INT("EventJourneyRun", 16),
    EN1545_INT("EventVehicleId", 16),
    EN1545_INT("EventVehiculeClass", 8),
    EN1545_INT("EventLocationType", 5),
    EN1545_INT("EventEmployee", 240),
    EN1545_INT("EventLocationReference", 16),
    EN1545_INT("EventJourneyInterchanges", 8),
    EN1545_INT("EventPeriodJourneys", 16),
    EN1545_INT("EventTotalJourneys", 16),
    EN1545_INT("EventJourneyDistance", 16),
    EN1545_INT("EventPriceAmount", 16),
    EN1545_INT("EventPriceUnit", 16),
    EN1545_INT("EventContractPointer", 5),
    EN1545_INT("EventAuthenticator", 16),
    EN1545_BITMAP(ev_data),
};

static const en1545_field_t ev_fields[] = {
    EN1545_INT("EventDate", 14),
    EN1545_INT("EventTime", 11),
    EN1545_BITMAP(ev_bitmap),
};

static const en1545_field_t intercode_event = EN1545_CONTAINER(ev_fields);

static const en1545_field_t cl_item[] = {
    EN1545_INT("ContractsNetworkId", 24),
    EN1545_INT("ContractsTariff", 16),
    EN1545_INT("ContractsPointer", 5),
};

static const en1545_field_t cl_bitmap[] = {
    EN1545_BITMAP(cl_item),
};

static const en1545_field_t intercode_contract_list = EN1545_REPEAT(4, cl_bitmap);

// Contract type FF, the full Intercode layout
static const en1545_field_t ff_customer[] = {
    EN1545_INT("ContractCustomerProfile", 6),
    EN1545_INT("ContractCustomerNumber", 32),
};
static const en1545_field_t ff_passenger[] = {
    EN1545_INT("ContractPassengerClass", 8),
    EN1545_INT("ContractPassengerTotal", 8),
};
static const en1545_field_t ff_restrict[] = {
    EN1545_INT("ContractRestrictStart", 11),
    EN1545_INT("ContractRestrictEnd", 11),
    EN1545_INT("ContractRestrictDay", 8),
    EN1545_INT("ContractRestrictTimeCode", 8),
    EN1545_INT("ContractRestrictCode", 8),
    EN1545_INT("ContractRestrictProduct", 16),
    EN1545_INT("ContractRestrictLocation", 16),
};
static const en1545_field_t ff_validity[] = {
    EN1545_INT("ContractStartDate", 14),
    EN1545_INT("ContractStartTime", 11),
    EN1545_INT("ContractEndDate", 14),
    EN1545_INT("ContractEndTime", 11),
    EN1545_INT("ContractDuration", 8),
    EN1545_INT("ContractLimitDate", 14),
    EN1545_INT("ContractZones", 8),
    EN1545_INT("ContractJourneys", 16),
    EN1545_INT("ContractPeriodJourneys", 16),
};
static const en1545_field_t ff_journey[] = {
    EN1545_INT("ContractOrigin1", 16),
    EN1545_INT("ContractDestination1", 16),
    EN1545_INT("ContractRouteNumbers", 16),
    EN1545_INT("ContractRouteVariants", 8),
    EN1545_INT("ContractRun", 16),
    EN1545_INT("ContractVia1", 16),
    EN1545_INT("ContractDistance", 16),
    EN1545_INT("ContractInterchange", 8),
};
static const en1545_field_t ff_sale[] = {
    EN1545_INT("ContractSaleDate", 14),
    EN1545_INT("ContractSaleTime", 11),
    EN1545_INT("ContractSaleAgent", 8),
    EN1545_INT("ContractSaleDevice", 16),
};
static const en1545_field_t ff_fields[] = {
    EN1545_INT("ContractNetworkId", 24),
    EN1545_INT("ContractProvider", 8),
    EN1545_INT("ContractTariff", 16),
    EN1545_INT("ContractSerialNumber", 32),
    EN1545_BITMAP(ff_customer),
    EN1545_BITMAP(ff_passenger),
    EN1545_INT("ContractVehiculeClassAllowed", 6),
    EN1545_INT("ContractPaymentPointer", 32),
    EN1545_INT("ContractPayMethod", 11),
    EN1545_INT("ContractServices", 16),
    EN1545_INT("ContractPriceAmount", 16),
    EN1545_INT("ContractPriceUnit", 16),
    EN1545_BITMAP(ff_restrict),
    EN1545_BITMAP(ff_validity),
    EN1545_BITMAP(ff_journey),
    EN1545_BITMAP(ff_sale),
    EN1545_INT("ContractStatus", 8),
    EN1545_INT("ContractLoyaltyPoints", 16),
    EN1545_INT("ContractAuthenticator", 16),
    EN1545_INT("ContractExtra", 0),
};
static const en1545_field_t contract_ff = EN1545_BITMAP(ff_fields);

// Types 20 and 46 share a common head and a bitmap of optional parts
static const en1545_field_t cm_dates[] = {
    EN1545_INT("ContractStartDate", 14),
    EN1545_INT("ContractEndDate", 14),
};
static const en1545_field_t c_ovd1[] = {
    EN1545_INT("ContractOrigin1", 16),
    EN1545_INT("ContractVia1", 16),
    EN1545_INT("ContractDestination1", 16),
};
static const en1545_field_t c_od2[] = {
    EN1545_INT("ContractOrigin2", 16),
    EN1545_INT("ContractDestination2", 16),
};
static const en1545_field_t c_sale[] = {
    EN1545_INT("ContractSaleDate", 14),
    EN1545_INT("ContractSaleDevice", 16),
    EN1545_INT("ContractSaleAgent", 8),
};
static const en1545_field_t c_pay[] = {
    EN1545_INT("ContractPayMethod", 11),
    EN1545_INT("ContractPriceAmount", 16),
    EN1545_INT("ContractReceiptDelivered", 1),
};
static const en1545_field_t c_period[] = {
    EN1545_INT("ContractEndPeriod", 14),
    EN1545_INT("ContractSoldPeriod", 6),
};
static const en1545_field_t c_sold[] = {
    EN1545_INT("ContractSold", 8),
    EN1545_INT("ContractDebitSold", 5),
};

static const en1545_field_t t20_extra[] = {
    EN1545_CONTAINER(c_ovd1),
    EN1545_CONTAINER(c_od2),
    EN1545_INT("ContractZones", 16),
    EN1545_CONTAINER(c_sale),
    EN1545_CONTAINER(c_pay),
    EN1545_INT("ContractPassengerTotal", 6),
    EN1545_CONTAINER(c_period),
    EN1545_CONTAINER(c_sold),
    EN1545_INT("ContractVehiculeClassAllowed", 4),
    EN1545_INT("LinkedContract", 5),
};

static const en1545_field_t t46_extra[] = {
    EN1545_CONTAINER(c_ovd1),
    EN1545_CONTAINER(c_od2),
    EN1545_INT("ContractZones", 16),
    EN1545_CONTAINER(c_sale),
    EN1545_CONTAINER(c_pay),
    EN1545_INT("ContractPassengerTotal", 6),
    EN1545_CONTAINER(c_period),
    EN1545_CONTAINER(c_sold),
    EN1545_INT("ContractVehiculeClassAllowed", 4),
    EN1545_INT("LinkedContract", 5),
    EN1545_INT("ContractStartTime", 11),
    EN1545_INT("ContractEndTime", 11),
    EN1545_INT("ContractDataEndInhibitionDate", 14),
    EN1545_INT("ContractDataValidityLimitDate", 14),
    EN1545_INT("ContractDataGeoLine", 28),
    EN1545_INT("ContractJourneys", 16),
    EN1545_INT("ContractDataSaleSecureDevice", 32),
};

#define INTERCODE_COMMON_HEAD \
    EN1545_INT("ContractProvider", 8), \
    EN1545_INT("ContractTariff", 16), \
    EN1545_INT("ContractSerialNumber", 32), \
    EN1545_INT("ContractPassengerClass", 8), \
    EN1545_BITMAP(cm_dates), \
    EN1545_INT("ContractStatus", 8)

static const en1545_field_t t20_fields[] = { INTERCODE_COMMON_HEAD, EN1545_BITMAP(t20_extra) };
static const en1545_field_t t46_fields[] = { INTERCODE_COMMON_HEAD, EN1545_BITMAP(t46_extra) };
static const en1545_field_t tother_fields[] = { INTERCODE_COMMON_HEAD, EN1545_INT("ContractData", 0) };

static const en1545_field_t contract_20 = EN1545_BITMAP(t20_fields);
static const en1545_field_t contract_46 = EN1545_BITMAP(t46_fields);
static const en1545_field_t contract_other = EN1545_BITMAP(tother_fields);

//-----------------------------------------------------------------------------
// Names
//-----------------------------------------------------------------------------

typedef struct {
    uint32_t id;
    const char *name;
} intercode_name_t;

static const intercode_name_t intercode_networks[] = {
    { 0x250000, "Pass Pass (Hauts-de-France)" },
    { 0x250064, "TaM (Montpellier)" },
    { 0x250502, "OuRA! (Auvergne-Rhone-Alpes)" },
    { 0x250901, "Navigo (Ile-de-France)" },
    { 0x250908, "KorriGo (Bretagne)" },
    { 0x250916, "Tisseo (Toulouse)" },
    { 0x250920, "Envibus (Sophia Antipolis)" },
    { 0x250921, "TransGironde (Gironde)" },
};

static const intercode_name_t navigo_tariffs[] = {
    { 0, "Navigo Mois" },
    { 1, "Navigo Semaine" },
    { 2, "Navigo Annuel" },
    { 3, "Navigo Jour" },
    { 5, "Imagine R Etudiant" },
    { 4096, "Liberte+" },
    { 16384, "Navigo Mois 75%" },
    { 16385, "Navigo Semaine 75%" },
    { 20480, "Ticket t+" },
    { 20488, "Metro-Train-RER" },
    { 32771, "Solidarite gratuite" },
};

// Paris metro sectors, the station id is local to its sector
static const char *navigo_sectors[] = {
    NULL, "Cite", "Rennes", "Villette", "Montparnasse", "Nation", "Saint-Lazare", "Auteuil",
    "Republique", "Austerlitz", "Invalides", "Sentier", "Ile Saint-Louis", "Daumesnil",
    "Italie", "Denfert", "Felix Faure", "Passy", "Etoile", "Clichy - Saint Ouen",
    "Montmartre", "Lafayette", "Buttes Chaumont", "Belleville", "Pere Lachaise",
    "Charenton", "Ivry - Villejuif", "Vanves", "Issy", "Levallois", "Pereire", "Pigalle"
};

static const char *intercode_lookup(const intercode_name_t *t, size_t n, uint32_t id) {
    for (size_t i = 0; i < n; i++) {
        if (t[i].id == id) {
            return t[i].name;
        }
    }
    return NULL;
}

static const char *intercode_contract_status_str(uint64_t status) {
    switch (status) {
        case 0x00:
            return "valid, never used";
        case 0x01:
            return "valid, used";
        case 0x03:
            return "renewal required";
        case 0x0D:
            return "not validable";
        case 0x13:
            return "blocked";
        case 0x3F:
            return "suspended";
        case 0x58:
            return "invalid";
        case 0x7F:
            return "refunded";
        case 0xFF:
            return "erasable";
        default:
            return "unknown";
    }
}

//-----------------------------------------------------------------------------
// Printing
//-----------------------------------------------------------------------------

static void intercode_print_env(const transit_calypso_card_t *card) {
    en1545_parsed_t env;
    (void)en1545_parse(card->env.data, card->env.len, 0, &calypso_intercode_env, &env);

    char buf[32];
    uint64_t v;
    transit_print_kv("Env version", "%" PRIu64, en1545_get_or(&env, "EnvVersionNumber", 0, 0));
    if (en1545_get(&env, "EnvNetworkId", 0, &v)) {
        transit_print_kv("Network", "%06" PRIX64, v);
    }
    if (en1545_get(&env, "EnvApplicationIssuerId", 0, &v)) {
        transit_print_kv("Issuer", "%" PRIu64, v);
    }
    if (en1545_get(&env, "EnvApplicationValidityEndDate", 0, &v)) {
        en1545_date_str(buf, sizeof(buf), v);
        transit_print_kv("Valid until", _YELLOW_("%s"), buf);
    }
    if (en1545_get(&env, "EnvPayMethod", 0, &v)) {
        transit_print_kv("Pay method", "%" PRIu64, v);
    }
}

// Remaining trips per Metrodroid IntercodeSubscription
static bool intercode_trips(const en1545_parsed_t *c, bool navigo, bool has_ctr, uint32_t ctr, uint32_t *left, uint32_t *total) {
    uint64_t sold = en1545_get_or(c, "ContractSold", 0, 0);
    uint64_t debit = en1545_get_or(c, "ContractDebitSold", 0, 0);
    uint64_t journeys = en1545_get_or(c, "ContractJourneys", 0, 0);

    if (sold != 0 && debit != 0) {
        if (has_ctr == false) {
            return false;
        }
        *left = ctr / (uint32_t)debit;
        *total = (uint32_t)(sold / debit);
        return true;
    }
    if (journeys == 0 || has_ctr == false) {
        return false;
    }
    if (navigo) {
        // counter: 6 bit count then 18 bit relative first stamp
        *left = ctr >> 18;
        *total = (uint32_t)(journeys & 0xFFF);
    } else {
        *left = ctr;
        *total = (uint32_t)journeys;
    }
    return true;
}

// Zone bitmask, lowest bit is zone 1, as "1,2,5"
static void intercode_zones_str(char *out, size_t outlen, uint64_t mask) {
    size_t n = 0;
    for (uint8_t z = 0; z < 16 && n + 4 < outlen; z++) {
        if (((mask >> z) & 1) == 0) {
            continue;
        }
        uint8_t zone = z + 1;
        if (n > 0) {
            out[n++] = ',';
        }
        if (zone >= 10) {
            out[n++] = (char)('0' + (zone / 10));
        }
        out[n++] = (char)('0' + (zone % 10));
    }
    if (outlen > 0) {
        out[n] = '\0';
    }
}

static void intercode_print_contract(const transit_calypso_card_t *card, uint8_t recno, const en1545_parsed_t *list, bool navigo) {
    const transit_calypso_record_t *rec = &card->contracts[recno - 1];

    // the contract list names the layout through its tariff, Navigo cards use FF
    uint8_t type = 0xFF;
    bool listed = false;
    for (uint8_t i = 0; i < 4; i++) {
        uint64_t ptr;
        if (en1545_get(list, "ContractsPointer", i, &ptr) && ptr == recno) {
            uint64_t t;
            if (en1545_get(list, "ContractsTariff", i, &t)) {
                type = (uint8_t)((t >> 4) & 0xFF);
                listed = true;
            }
            break;
        }
    }

    const en1545_field_t *layout = &contract_ff;
    if (type == 0x20) {
        layout = &contract_20;
    } else if (type == 0x46) {
        layout = &contract_46;
    } else if (type != 0xFF) {
        layout = &contract_other;
    }

    en1545_parsed_t c;
    (void)en1545_parse(rec->data, rec->len, 0, layout, &c);

    char label[24];
    char buf[48];
    char buf2[48];
    uint64_t v, w;

    uint64_t tariff = en1545_get_or(&c, "ContractTariff", 0, 0);
    const char *tname = navigo ? intercode_lookup(navigo_tariffs, ARRAYLEN(navigo_tariffs), (uint32_t)tariff) : NULL;
    snprintf(label, sizeof(label), "Contract %u", recno);
    transit_print_kv(label, "tariff " _YELLOW_("%" PRIu64) " ( %s )  layout %02X%s", tariff,
                     tname ? tname : "unknown", type, listed ? "" : ", not in contract list");

    if (en1545_get(&c, "ContractProvider", 0, &v)) {
        transit_print_kv("  Provider", "%" PRIu64, v);
    }
    if (en1545_get(&c, "ContractSerialNumber", 0, &v)) {
        transit_print_kv("  Serial", "%" PRIu64, v);
    }
    if (en1545_get(&c, "ContractStartDate", 0, &v)) {
        en1545_date_str(buf, sizeof(buf), v);
        en1545_date_str(buf2, sizeof(buf2), en1545_get_or(&c, "ContractEndDate", 0, 0));
        transit_print_kv("  Validity", _YELLOW_("%s") " .. " _YELLOW_("%s"), buf, buf2);
    } else if (en1545_get(&c, "ContractEndDate", 0, &v)) {
        en1545_date_str(buf, sizeof(buf), v);
        transit_print_kv("  Valid until", _YELLOW_("%s"), buf);
    }
    if (en1545_get(&c, "ContractZones", 0, &v) && v != 0) {
        intercode_zones_str(buf, sizeof(buf), v);
        transit_print_kv("  Zones", "%s", buf);
    }
    if (en1545_get(&c, "ContractPriceAmount", 0, &v)) {
        transit_money_str(buf, sizeof(buf), (int64_t)v, 2, "EUR");
        transit_print_kv("  Price", "%s", buf);
    }
    if (en1545_get(&c, "ContractSaleDate", 0, &v)) {
        en1545_date_str(buf, sizeof(buf), v);
        transit_print_kv("  Sold", "%s, agent %" PRIu64 ", device %" PRIu64, buf,
                         en1545_get_or(&c, "ContractSaleAgent", 0, 0), en1545_get_or(&c, "ContractSaleDevice", 0, 0));
    }
    if (en1545_get(&c, "ContractStatus", 0, &v)) {
        transit_print_kv("  Status", "%02" PRIX64 " ( %s )", v, intercode_contract_status_str(v));
    }
    if (en1545_get(&c, "ContractOrigin1", 0, &v) && en1545_get(&c, "ContractDestination1", 0, &w)) {
        transit_print_kv("  Route", "%" PRIu64 " -> %" PRIu64, v, w);
    }

    uint32_t ctr = 0, left = 0, total = 0;
    bool has_ctr = calypso_contract_counter(card, recno, &ctr);
    if (intercode_trips(&c, navigo, has_ctr, ctr, &left, &total)) {
        transit_print_kv("  Trips", _GREEN_("%u") " of %u left", left, total);
    } else if (has_ctr && ctr != 0) {
        transit_print_kv("  Counter", "%06X", ctr);
    }
}

static void intercode_print_event(const transit_calypso_card_t *card, uint8_t n, bool navigo) {
    en1545_parsed_t e;
    (void)en1545_parse(card->events[n].data, card->events[n].len, 0, &intercode_event, &e);

    char when[32];
    char where[64];
    char label[16];
    uint64_t code = en1545_get_or(&e, "EventCode", 0, 0);
    uint64_t provider = en1545_get_or(&e, "EventServiceProvider", 0, 0);
    uint8_t transport = (uint8_t)(code >> 4);

    en1545_datetime_str(when, sizeof(when), en1545_get_or(&e, "EventDate", 0, 0), en1545_get_or(&e, "EventTime", 0, 0));

    where[0] = '\0';
    uint64_t loc;
    if (en1545_get(&e, "EventLocationId", 0, &loc)) {
        uint32_t sector = (uint32_t)(loc >> 9);
        if (navigo && (provider == NAVIGO_PROVIDER_RATP || provider == NAVIGO_PROVIDER_SNCF) && (transport == 3 || transport == 4)) {
            const char *sname = (sector < ARRAYLEN(navigo_sectors)) ? navigo_sectors[sector] : NULL;
            snprintf(where, sizeof(where), ", sector %u ( %s ) station %u", sector,
                     sname ? sname : "unknown", (uint32_t)((loc >> 4) & 0x1F));
        } else {
            snprintf(where, sizeof(where), ", location %" PRIu64, loc);
        }
    }

    snprintf(label, sizeof(label), "Event %u", n + 1);
    transit_print_kv(label, _YELLOW_("%s") "  %s %s, provider %" PRIu64 "%s", when,
                     calypso_transport_str(transport), calypso_event_action_str(code & 0x0F), provider, where);

    uint64_t v;
    if (en1545_get(&e, "EventRouteNumber", 0, &v)) {
        transit_print_kv("  Route", "%" PRIu64, v);
    }
    if (en1545_get(&e, "EventContractPointer", 0, &v)) {
        transit_print_kv("  Contract", "%" PRIu64, v);
    }
    if (en1545_get(&e, "EventResult", 0, &v) && v != 0) {
        transit_print_kv("  Result", "%02" PRIX64, v);
    }
    if (en1545_get(&e, "EventPriceAmount", 0, &v)) {
        char buf[32];
        transit_money_str(buf, sizeof(buf), (int64_t)v, 2, "EUR");
        transit_print_kv("  Price", "%s", buf);
    }
}

static int intercode_print(const transit_calypso_card_t *card, bool navigo) {
    uint32_t net = calypso_intercode_network(card);
    const char *name = intercode_lookup(intercode_networks, ARRAYLEN(intercode_networks), net);

    char title[64];
    if (name != NULL) {
        snprintf(title, sizeof(title), "%s", name);
    } else {
        snprintf(title, sizeof(title), "Intercode network %06X", net);
    }
    transit_print_header(title);
    calypso_print_serial(card, true);
    intercode_print_env(card);

    en1545_parsed_t list;
    (void)en1545_parse(card->contract_list.data, card->contract_list.len, 0, &intercode_contract_list, &list);

    for (uint8_t i = 0; i < card->contract_count && i < TRANSIT_CALYPSO_MAX_CONTRACTS; i++) {
        if (calypso_record_empty(&card->contracts[i]) == false) {
            intercode_print_contract(card, i + 1, &list, navigo);
        }
    }
    for (uint8_t i = 0; i < card->event_count && i < TRANSIT_CALYPSO_MAX_EVENTS; i++) {
        if (calypso_record_empty(&card->events[i]) == false) {
            intercode_print_event(card, i, navigo);
        }
    }
    return PM3_SUCCESS;
}

//-----------------------------------------------------------------------------
// Entry points
//-----------------------------------------------------------------------------

bool is_valid_navigo_card(const transit_calypso_card_t *card) {
    return calypso_intercode_network(card) == INTERCODE_NETWORK_NAVIGO;
}

int navigo_parser_parse(const transit_calypso_card_t *card) {
    if (is_valid_navigo_card(card) == false) {
        return PM3_EINVARG;
    }
    return intercode_print(card, true);
}

bool is_valid_intercode_card(const transit_calypso_card_t *card) {
    uint32_t net = calypso_intercode_network(card);
    return ((net >> 12) == INTERCODE_COUNTRY_FRANCE) && (net != INTERCODE_NETWORK_NAVIGO);
}

int intercode_parser_parse(const transit_calypso_card_t *card) {
    if (is_valid_intercode_card(card) == false) {
        return PM3_EINVARG;
    }
    return intercode_print(card, false);
}

//-----------------------------------------------------------------------------
// Self tests, records built from the layouts above
//-----------------------------------------------------------------------------

// env: version 1, bitmap {network, validity end}
static void intercode_build_env(transit_calypso_record_t *r, uint32_t net, uint16_t end) {
    memset(r, 0, sizeof(*r));
    r->len = TRANSIT_CALYPSO_REC_LEN;
    transit_set_bits_be(r->data, r->len, 0, 6, 1);
    transit_set_bits_be(r->data, r->len, 6, 7, 0x05);
    transit_set_bits_be(r->data, r->len, 13, 24, net);
    transit_set_bits_be(r->data, r->len, 37, 14, end);
}

static bool intercode_selftest_common(bool navigo) {
    transit_calypso_card_t card;
    memset(&card, 0, sizeof(card));

    uint32_t net = navigo ? INTERCODE_NETWORK_NAVIGO : 0x250916;
    intercode_build_env(&card.env, net, 10000);

    // contract list entry 0: bitmap {tariff, pointer}, tariff 0x0FF0 -> layout FF, pointer 1
    transit_calypso_record_t *cl = &card.contract_list;
    cl->len = TRANSIT_CALYPSO_REC_LEN;
    size_t off = 0;
    transit_set_bits_be(cl->data, cl->len, off, 4, 1);
    off += 4;
    transit_set_bits_be(cl->data, cl->len, off, 3, 0x6);
    off += 3;
    transit_set_bits_be(cl->data, cl->len, off, 16, 0x0FF0);
    off += 16;
    transit_set_bits_be(cl->data, cl->len, off, 5, 1);

    // contract FF: bitmap {provider, tariff, validity}, validity {start, end, journeys}
    transit_calypso_record_t *c = &card.contracts[0];
    c->len = TRANSIT_CALYPSO_REC_LEN;
    off = 0;
    transit_set_bits_be(c->data, c->len, off, 20, (1u << 1) | (1u << 2) | (1u << 13));
    off += 20;
    transit_set_bits_be(c->data, c->len, off, 8, 3);
    off += 8;
    transit_set_bits_be(c->data, c->len, off, 16, 20480);
    off += 16;
    transit_set_bits_be(c->data, c->len, off, 9, (1u << 0) | (1u << 2) | (1u << 7));
    off += 9;
    transit_set_bits_be(c->data, c->len, off, 14, 9800);
    off += 14;
    transit_set_bits_be(c->data, c->len, off, 14, 9830);
    off += 14;
    transit_set_bits_be(c->data, c->len, off, 16, 10);
    card.contract_count = 1;

    // counter for contract 1: 7 trips left
    card.counters.len = TRANSIT_CALYPSO_REC_LEN;
    transit_set_bits_be(card.counters.data, card.counters.len, 0, 24, navigo ? (7u << 18) : 7u);

    // event: 2023-11-15 08:30, bitmap {code, provider, location, contract pointer}
    transit_calypso_record_t *e = &card.events[0];
    e->len = TRANSIT_CALYPSO_REC_LEN;
    off = 0;
    transit_set_bits_be(e->data, e->len, off, 14, 9814);
    off += 14;
    transit_set_bits_be(e->data, e->len, off, 11, 510);
    off += 11;
    transit_set_bits_be(e->data, e->len, off, 28, (1u << 2) | (1u << 4) | (1u << 8) | (1u << 25));
    off += 28;
    transit_set_bits_be(e->data, e->len, off, 8, 0x31);
    off += 8;
    transit_set_bits_be(e->data, e->len, off, 8, NAVIGO_PROVIDER_RATP);
    off += 8;
    transit_set_bits_be(e->data, e->len, off, 16, (8u << 9) | (5u << 4));
    off += 16;
    transit_set_bits_be(e->data, e->len, off, 5, 1);
    card.event_count = 1;

    bool ok = true;
    ok &= transit_check("network id", calypso_intercode_network(&card), net);
    ok &= transit_check("navigo detect", is_valid_navigo_card(&card), navigo);
    ok &= transit_check("intercode detect", is_valid_intercode_card(&card), navigo == false);
    ok &= transit_calypso_check_identify("navigo identify", &card, "Navigo", navigo ? TRANSIT_ID_MATCH : TRANSIT_ID_NONE);
    ok &= transit_calypso_check_identify("intercode identify", &card, "Intercode", navigo ? TRANSIT_ID_NONE : TRANSIT_ID_MATCH);

    en1545_parsed_t env;
    (void)en1545_parse(card.env.data, card.env.len, 0, &calypso_intercode_env, &env);
    char buf[32];
    en1545_date_str(buf, sizeof(buf), en1545_get_or(&env, "EnvApplicationValidityEndDate", 0, 0));
    ok &= transit_check_str("env validity end", buf, "2024-05-19");

    en1545_parsed_t list;
    (void)en1545_parse(cl->data, cl->len, 0, &intercode_contract_list, &list);
    ok &= transit_check("list pointer", en1545_get_or(&list, "ContractsPointer", 0, 0), 1);

    en1545_parsed_t cp;
    (void)en1545_parse(c->data, c->len, 0, &contract_ff, &cp);
    ok &= transit_check("contract tariff", en1545_get_or(&cp, "ContractTariff", 0, 0), 20480);
    en1545_date_str(buf, sizeof(buf), en1545_get_or(&cp, "ContractEndDate", 0, 0));
    ok &= transit_check_str("contract end", buf, "2023-12-01");
    intercode_zones_str(buf, sizeof(buf), 0x801F);
    ok &= transit_check_str("zones", buf, "1,2,3,4,5,16");

    uint32_t ctr = 0, left = 0, total = 0;
    bool has = calypso_contract_counter(&card, 1, &ctr);
    ok &= transit_check("trips decoded", intercode_trips(&cp, navigo, has, ctr, &left, &total), true);
    ok &= transit_check("trips left", left, 7);
    ok &= transit_check("trips total", total, 10);

    en1545_parsed_t ep;
    (void)en1545_parse(e->data, e->len, 0, &intercode_event, &ep);
    en1545_datetime_str(buf, sizeof(buf), en1545_get_or(&ep, "EventDate", 0, 0), en1545_get_or(&ep, "EventTime", 0, 0));
    ok &= transit_check_str("event time", buf, "2023-11-15 08:30");
    ok &= transit_check("event location", en1545_get_or(&ep, "EventLocationId", 0, 0), (8u << 9) | (5u << 4));
    ok &= transit_check("event contract ptr", en1545_get_or(&ep, "EventContractPointer", 0, 0), 1);

    // card number from ICC bytes 16..19, falling back to bytes 0..3
    card.icc.len = TRANSIT_CALYPSO_REC_LEN;
    transit_set_bits_be(card.icc.data, card.icc.len, 0, 32, 87654321);
    ok &= transit_check("icc number fallback", calypso_icc_card_number(&card, buf, sizeof(buf)), true);
    ok &= transit_check_str("icc bytes 0..3", buf, "87654321");
    transit_set_bits_be(card.icc.data, card.icc.len, 128, 32, 12345678);
    (void)calypso_icc_card_number(&card, buf, sizeof(buf));
    ok &= transit_check_str("icc bytes 16..19", buf, "12345678");

    if (ok) {
        ok &= (intercode_print(&card, navigo) == PM3_SUCCESS);
    }
    return ok;
}

int navigo_selftest(void) {
    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "Testing Navigo decode");
    bool ok = en1545_selftest();
    ok &= intercode_selftest_common(true);
    return transit_selftest_result("Navigo", ok);
}

int intercode_selftest(void) {
    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "Testing Intercode decode");
    return transit_selftest_result("Intercode", intercode_selftest_common(false));
}
