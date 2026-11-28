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
// EMV core functions
//-----------------------------------------------------------------------------

#include "emvcore.h"
#include <string.h>
#include "commonutil.h"     // ARRAYLEN
#include "comms.h"          // DropField
#include "cmdparser.h"
#include "cmdsmartcard.h"   // ExchangeAPDUSC
#include "ui.h"
#include "cmdhf14a.h"
#include "cmdhf14b.h"
#include "dol.h"
#include "emv_tags.h"
#include "emvjson.h"
#include "util_posix.h"
#include "protocols.h"      // ISO7816 APDU return codes

// Got from here. Thanks!
// https://eftlab.co.uk/index.php/site-map/knowledge-base/211-emv-aid-rid-pix
static const char *PSElist [] = {
    "325041592E5359532E4444463031", // 2PAY.SYS.DDF01 - Visa Proximity Payment System Environment - PPSE
    "315041592E5359532E4444463031"  // 1PAY.SYS.DDF01 - Visa Payment System Environment - PSE
};

const char *TransactionTypeStr[] = {
    "MSD",
    "VSDC",
    "qVCDCMCHIP",
    "CDA"
};

typedef struct {
    enum CardPSVendor vendor;
    const char *aid;
} AIDList_t;

static const AIDList_t AIDlist [] = {
    // Visa International
    { CV_VISA, "A00000000305076010" },           // VISA ELO Credit
    { CV_VISA, "A0000000031010" },               // VISA Debit/Credit (Classic)
    { CV_VISA, "A000000003101001" },             // VISA Credit
    { CV_VISA, "A000000003101002" },             // VISA Debit
    { CV_VISA, "A0000000032010" },               // VISA Electron
    { CV_VISA, "A0000000032020" },               // VISA
    { CV_VISA, "A0000000033010" },               // VISA Interlink
    { CV_VISA, "A0000000034010" },               // VISA Specific
    { CV_VISA, "A0000000035010" },               // VISA Specific
    { CV_VISA, "A0000000036010" },               // Domestic Visa Cash Stored Value
    { CV_VISA, "A0000000036020" },               // International Visa Cash Stored Value
    { CV_VISA, "A0000000038002" },               // VISA Auth, VisaRemAuthen EMV-CAP (DPA)
    { CV_VISA, "A0000000038010" },               // VISA Plus
    { CV_VISA, "A0000000039010" },               // VISA Loyalty
    { CV_VISA, "A000000003999910" },             // VISA Proprietary ATM
    // Visa USA
    { CV_VISA, "A000000098" },                   // Debit Card
    { CV_VISA, "A0000000980848" },               // Debit Card
    // Mastercard International
    { CV_MASTERCARD, "A00000000401" },           // MasterCard PayPass
    { CV_MASTERCARD, "A0000000041010" },         // MasterCard Credit
    { CV_MASTERCARD, "A00000000410101213" },     // MasterCard Credit
    { CV_MASTERCARD, "A00000000410101215" },     // MasterCard Credit
    { CV_MASTERCARD, "A0000000042010" },         // MasterCard Specific
    { CV_MASTERCARD, "A0000000043010" },         // MasterCard Specific
    { CV_MASTERCARD, "A0000000043060" },         // Maestro (Debit)
    { CV_MASTERCARD, "A000000004306001" },       // Maestro (Debit)
    { CV_MASTERCARD, "A0000000044010" },         // MasterCard Specific
    { CV_MASTERCARD, "A0000000045010" },         // MasterCard Specific
    { CV_MASTERCARD, "A0000000046000" },         // Cirrus
    { CV_MASTERCARD, "A0000000048002" },         // SecureCode Auth EMV-CAP
    { CV_MASTERCARD, "A0000000049999" },         // MasterCard PayPass
    { CV_MASTERCARD, "B012345678" },             // Maestro TEST Used for development
    // American Express
    { CV_AMERICANEXPRESS, "A000000025" },
    { CV_AMERICANEXPRESS, "A0000000250000" },
    { CV_AMERICANEXPRESS, "A00000002501" },
    { CV_AMERICANEXPRESS, "A000000025010402" },
    { CV_AMERICANEXPRESS, "A000000025010701" },
    { CV_AMERICANEXPRESS, "A000000025010801" },
    // Groupement des Cartes Bancaires "CB"
    { CV_CB, "A0000000421010" },                 // Cartes Bancaire EMV Card
    { CV_CB, "A0000000422010" },
    { CV_CB, "A0000000423010" },
    { CV_CB, "A0000000424010" },
    { CV_CB, "A0000000425010" },
    // JCB CO., LTD.
    { CV_JCB, "A00000006510" },                  // JCB
    { CV_JCB, "A0000000651010" },                // JCB J Smart Credit
    // Switch Card Services Ltd.
    { CV_SWITCH, "A0000000050001" },             // Maestro UK
    { CV_SWITCH, "A0000000050002" },             // Solo
    // Diners Club International Ltd.
    { CV_DINERS, "A0000001523010" },             // Discover, Pulse D Pas Discover Card
    { CV_DINERS, "A0000001524010" },             // Discover, Discover Debit Common Card
    // Other
    { CV_OTHER, "A00000002401" },                // Midland Bank Plc - Self Service
    { CV_OTHER, "A0000000291010" },              // LINK Interchange Network Ltd - Link / American Express
    { CV_OTHER, "A00000006900" },                // Société Européenne de Monnaie Electronique SEME - Moneo
    { CV_OTHER, "A000000077010000021000000000003B" },  // Oberthur Technologies France - Visa AEPN
    { CV_OTHER, "A0000001211010" },              // PBS Danmark A/S - Denmark - Dankort (VISA GEM Vision) - Danish domestic debit card
    { CV_OTHER, "A0000001410001" },              // Associazione Bancaria Italiana - Italy - PagoBANCOMAT - CoGeBan Consorzio BANCOMAT (Italian domestic debit card)
    { CV_OTHER, "A0000001544442" },              // Banricompras Debito - Banrisul - Banco do Estado do Rio Grande do SUL - S.A.
    { CV_OTHER, "A000000172950001" },            // Financial Information Service Co. Ltd. - Taiwan - BAROC Financial Application Taiwan- The Bankers Association of the Republic of China
    { CV_OTHER, "A0000001850002" },              // Post Office Limited - United Kingdom - UK Post Office Account card
    { CV_OTHER, "A0000002281010" },              // Saudi Arabian Monetary Agency (SAMA) - Kingdom of Saudi Arabia - SPAN (M/Chip) - SPAN2 (Saudi Payments Network) - Saudi Arabia domestic credit/debit card (Saudi Arabia Monetary Agency)
    { CV_OTHER, "A0000002282010" },              // Saudi Arabian Monetary Agency (SAMA) - Kingdom of Saudi Arabia - SPAN (VIS) - SPAN2 (Saudi Payments Network) - Saudi Arabia domestic credit/debit card (Saudi Arabia Monetary Agency)
    { CV_OTHER, "A0000002771010" },              // Interac Association - Canada - INTERAC - Canadian domestic credit/debit card
    { CV_OTHER, "A00000031510100528" },          // Currence Holding/PIN BV - The Netherlands- Currence PuC
    { CV_OTHER, "A0000003156020" },              // Currence Holding/PIN BV - The Netherlands - Chipknip
    { CV_OTHER, "A0000003591010028001" },        // Euro Alliance of Payment Schemes s.c.r.l. (EAPS) - Belgium - Girocard EAPS - ZKA (Germany)
    { CV_OTHER, "A0000003710001" },              // Verve - Nigeria - InterSwitch Verve Card - Nigerian local switch company
    { CV_OTHER, "A0000004540010" },              // eTranzact - Nigeria - Etranzact Genesis Card - Nigerian local switch company
    { CV_OTHER, "A0000004540011" },              // eTranzact - Nigeria - Etranzact Genesis Card 2 - Nigerian local switch company
    { CV_OTHER, "A0000004766C" },                // Google - United States - GOOGLE_PAYMENT_AID
    { CV_OTHER, "A0000005241010" },              // RuPay - India - RuPay - RuPay (India)
    { CV_OTHER, "A0000006723010" },              // TROY - Turkey - TROY chip credit card - Turkey's Payment Method
    { CV_OTHER, "A0000006723020" },              // TROY - Turkey - TROY chip debit card - Turkey's Payment Method
    { CV_OTHER, "A0000007705850" },              // Indian Oil Corporation Limited - India - XTRAPOWER Fleet Card Program - Indian Oil’s Pre Paid Program
    { CV_OTHER, "D27600002545500100" },          // ZKA - Germany - Girocard - ZKA Girocard (Geldkarte) (Germany)
    { CV_OTHER, "D4100000030001" },              // KS X 6923/6924 (T-Money, South Korea and Snapper+, Wellington, New Zealand)
    { CV_OTHER, "D5280050218002" },              // The Netherlands - ? - (Netherlands)
    { CV_OTHER, "D5780000021010" },              // Bankaxept    Norway  Bankaxept   Norwegian domestic debit card
    { CV_OTHER, "F0000000030001" },              // BRADESCO - Brazilian Bank Banco Bradesco
    { CV_OTHER, "A0000008381010" },              // SL Resekort - Swedish domestic transportation card with payment
};

enum CardPSVendor GetCardPSVendor(uint8_t *AID, size_t AIDlen) {
    char buf[100] = {0};
    if (AIDlen < 1)
        return CV_NA;

    hex_to_buffer((uint8_t *)buf, AID, AIDlen, sizeof(buf) - 1, 0, 0, true);

    for (int i = 0; i < ARRAYLEN(AIDlist); i ++) {
        if (strncmp(AIDlist[i].aid, buf, strlen(AIDlist[i].aid)) == 0) {
            return AIDlist[i].vendor;
        }
    }

    return CV_NA;
}

static void emv_print_cb(void *data, const struct tlv *tlv, int level, bool is_leaf) {
    emv_tag_dump(tlv, level);
    if (is_leaf && tlv->len > 24) {
        print_buffer(tlv->value, tlv->len, level);
    }
}

bool TLVPrintFromBuffer(uint8_t *data, int datalen) {
    struct tlvdb *t = tlvdb_parse_multi(data, datalen);
    if (t) {
        PrintAndLogEx(INFO, "-------------------- " _CYAN_("TLV decoded") " --------------------");

        tlvdb_visit(t, emv_print_cb, NULL, 0);
        tlvdb_free(t);
        return true;
    } else {
        PrintAndLogEx(WARNING, "TLV ERROR: Can't parse response as TLV tree.");
    }
    return false;
}

void TLVPrintFromTLVLev(struct tlvdb *tlv, int level) {
    if (tlv == NULL)
        return;

    tlvdb_visit(tlv, emv_print_cb, NULL, level);
}

void TLVPrintFromTLV(struct tlvdb *tlv) {
    TLVPrintFromTLVLev(tlv, 0);
}

void TLVPrintAIDlistFromSelectTLV(struct tlvdb *tlv) {
    PrintAndLogEx(INFO, "|------------------+--------+-------------------------|");
    PrintAndLogEx(INFO, "|    AID           |Priority| Name                    |");
    PrintAndLogEx(INFO, "|------------------+--------+-------------------------|");

    struct tlvdb *ttmp = tlvdb_find(tlv, 0x6f);
    if (ttmp == NULL)
        PrintAndLogEx(INFO, "|                         none                        |");

    while (ttmp) {
        const struct tlv *tgAID = tlvdb_get_inchild(ttmp, 0x84, NULL);
        const struct tlv *tgName = tlvdb_get_inchild(ttmp, 0x50, NULL);
        const struct tlv *tgPrio = tlvdb_get_inchild(ttmp, 0x87, NULL);
        if (!tgAID) {
            break;
        }
        PrintAndLogEx(INFO, "| %s|   %s  | %s|",
                      sprint_hex_inrow_ex(tgAID->value, tgAID->len, 16),
                      (tgPrio && tgPrio->len) ? sprint_hex(tgPrio->value, 1) : "   ",
                      (tgName) ? sprint_ascii_ex(tgName->value, tgName->len, 24) : "                        ");

        ttmp = tlvdb_find_next(ttmp, 0x6f);
    }

    PrintAndLogEx(INFO, "|------------------+--------+-------------------------|");
}

struct tlvdb *GetPANFromTrack2(const struct tlv *track2) {
    char track2Hex[200] = {0};
    uint8_t PAN[100] = {0};
    int PANlen = 0;
    char *tmp = track2Hex;

    if (!track2 || !track2->value || track2->len == 0 ||
            track2->len > (sizeof(track2Hex) - 1) / 2)
        return NULL;

    for (size_t i = 0; i < track2->len; ++i, tmp += 2)
        snprintf(tmp, sizeof(track2Hex) - (tmp - track2Hex), "%02x", (unsigned int)track2->value[i]);

    char *separator = strchr(track2Hex, 'd');
    if (!separator || separator == track2Hex)
        return NULL;
    size_t posD = separator - track2Hex;

    track2Hex[posD] = 0;
    if (strlen(track2Hex) % 2) {
        track2Hex[posD] = 'F';
        track2Hex[posD + 1] = '\0';
    }

    param_gethex_to_eol(track2Hex, 0, PAN, sizeof(PAN), &PANlen);

    return tlvdb_fixed(0x5a, PANlen, PAN);
}

struct tlvdb *GetdCVVRawFromTrack2(const struct tlv *track2) {
    char track2Hex[200] = {0};
    char dCVVHex[100] = {0};
    uint8_t dCVV[100] = {0};
    int dCVVlen = 0;
    const int PINlen = 5; // must calculated from 9F67 MSD Offset but i have not seen this tag)
    char *tmp = track2Hex;

    if (!track2 || !track2->value || track2->len == 0 ||
            track2->len > (sizeof(track2Hex) - 1) / 2)
        return NULL;

    for (size_t i = 0; i < track2->len; ++i, tmp += 2)
        snprintf(tmp, sizeof(track2Hex) - (tmp - track2Hex), "%02x", (unsigned int)track2->value[i]);

    char *separator = strchr(track2Hex, 'd');
    if (!separator || separator - track2Hex < 5)
        return NULL;
    size_t posD = separator - track2Hex;
    size_t track2HexLen = strlen(track2Hex);
    if (posD + PINlen + 15 > track2HexLen)
        return NULL;

    memset(dCVVHex, '0', 32);
    // ATC
    memcpy(dCVVHex + 0, track2Hex + posD + PINlen + 11, 4);
    // PAN 5 hex
    memcpy(dCVVHex + 4, track2Hex, 5);
    // expire date
    memcpy(dCVVHex + 9, track2Hex + posD + 1, 4);
    // service code
    memcpy(dCVVHex + 13, track2Hex + posD + 5, 3);

    param_gethex_to_eol(dCVVHex, 0, dCVV, sizeof(dCVV), &dCVVlen);

    return tlvdb_fixed(0x02, dCVVlen, dCVV);
}

typedef int (*emv_exchange_fn)(void *, bool, sAPDU_t, bool, uint16_t, uint8_t *, size_t, size_t *, uint16_t *);

static int emv_exchange_chained(emv_exchange_fn exchange, void *context, bool activate,
                                 sAPDU_t apdu, bool include_le, uint16_t initial_le, uint8_t *result, size_t capacity,
                                 size_t *length, uint16_t *sw) {
    if (!exchange || !result || !length || !sw || !capacity || (apdu.Lc && !apdu.data))
        return PM3_EINVARG;
    *length = 0;
    *sw = 0;
    size_t total = 0, chains = 0;
    uint16_t le = initial_le;
    bool corrected = false;
    for (size_t exchanges = 0; exchanges < 34; exchanges++) {
        uint8_t chunk[APDU_RES_LEN];
        size_t chunk_len = 0;
        *sw = 0;
        int res = exchange(context, activate, apdu, include_le, le, chunk, sizeof(chunk), &chunk_len, sw);
        activate = false;
        if (res != PM3_SUCCESS && res != 5 && res != PM3_EAPDU_FAIL)
            return res;
        if (chunk_len > sizeof(chunk))
            return PM3_EOVFLOW;
        if ((*sw >> 8) == 0x6c) {
            if (corrected || chunk_len)
                return PM3_EWRONGANSWER;
            corrected = true;
            include_le = true;
            le = (*sw & 0xff) ? (*sw & 0xff) : 0x100;
            continue;
        }
        if (chunk_len > capacity - total)
            return PM3_EOVFLOW;
        if (chunk_len)
            memcpy(result + total, chunk, chunk_len);
        total += chunk_len;
        if ((*sw >> 8) != 0x61) {
            *length = total;
            return *sw == ISO7816_OK ? PM3_SUCCESS : PM3_EAPDU_FAIL;
        }
        if (++chains > 16 || total >= capacity)
            return PM3_EOVFLOW;
        le = (*sw & 0xff) ? (*sw & 0xff) : 0x100;
        apdu = (sAPDU_t) {0x00, 0xc0, 0x00, 0x00, 0, NULL};
        include_le = true;
        corrected = false;
    }
    return PM3_EOVFLOW;
}

static int emv_exchange_device(void *context, bool activate, sAPDU_t apdu, bool include_le,
                                uint16_t le, uint8_t *result, size_t capacity, size_t *length, uint16_t *sw) {
    size_t encoded_length = 4 + (apdu.Lc ? 1 + (size_t)apdu.Lc : 0) + (include_le ? 1 : 0);
    if (encoded_length > APDU_RES_LEN) return PM3_EOVFLOW;
    Iso7816CommandChannel channel = *(Iso7816CommandChannel *)context;
    return Iso7816ExchangeEx(channel, activate, true, apdu, include_le, le, result, capacity, length, sw);
}

static int emv_select_exchange(emv_exchange_fn exchange, void *context, bool activate, bool contact,
                                uint8_t *aid, size_t aid_len, uint8_t *response, size_t capacity,
                                size_t *length, uint16_t *sw) {
    sAPDU_t apdu = {0, 0xa4, 4, 0, aid_len, aid};
    int res = emv_exchange_chained(exchange, context, activate, apdu, !contact, 0,
                                    response, capacity, length, sw);
    // Contact T=1 needs case 4; preserve the case-3 path used by T=0 readers.
    if (contact && res == PM3_EAPDU_FAIL && (*sw == 0x6700 || *sw == 0x6f00))
        res = emv_exchange_chained(exchange, context, false, apdu, true, 0,
                                    response, capacity, length, sw);
    return res;
}

typedef struct {
    uint8_t ins;
    uint16_t le, sw;
    size_t length;
    int result;
} emv_transport_step_t;

typedef struct {
    const emv_transport_step_t *steps;
    size_t count, calls;
    bool matched, endless, contact_select;
} emv_transport_fixture_t;

static int emv_exchange_fixture(void *context, bool activate, sAPDU_t apdu, bool include_le,
                                 uint16_t le, uint8_t *result, size_t capacity, size_t *length, uint16_t *sw) {
    emv_transport_fixture_t *fixture = context;
    size_t call = fixture->calls++;
    if (fixture->endless) {
        *sw = 0x6101;
        *length = 0;
        return PM3_SUCCESS;
    }
    if (call >= fixture->count) {
        fixture->matched = false;
        return PM3_ESOFT;
    }
    const emv_transport_step_t *step = fixture->steps + call;
    bool expected_le = !(fixture->contact_select && call == 0);
    fixture->matched &= apdu.INS == step->ins && le == step->le && include_le == expected_le && activate == (call == 0);
    if (apdu.INS == 0xc0)
        fixture->matched &= apdu.CLA == 0 && apdu.Lc == 0;
    *length = step->length;
    *sw = step->sw;
    if (*length <= capacity)
        memset(result, (int)(call + 1), *length);
    return step->result;
}

int EMVTransportSelfTests(void) {
    static const struct {
        const char *name;
        emv_transport_step_t steps[4];
        size_t count, capacity, length;
        int result;
    } cases[] = {
        {"ordinary response", {{0xca, 0, 0x9000, 2, 0}}, 1, 512, 2, 0},
        {"6C correction", {{0xca, 0, 0x6c02, 0, 5}, {0xca, 2, 0x9000, 2, 0}}, 2, 512, 2, 0},
        {"6C00 means 256", {{0xca, 0, 0x6c00, 0, 0}, {0xca, 256, 0x9000, 256, 0}}, 2, 512, 256, 0},
        {"61 collection", {{0xca, 0, 0x6102, 1, 0}, {0xc0, 2, 0x9000, 2, 0}}, 2, 512, 3, 0},
        {"6100 means 256", {{0xca, 0, 0x6100, 0, 0}, {0xc0, 256, 0x9000, 256, 0}}, 2, 512, 256, 0},
        {"GET RESPONSE length correction", {{0xca, 0, 0x6102, 1, 0}, {0xc0, 2, 0x6c01, 0, 5}, {0xc0, 1, 0x9000, 1, 0}}, 3, 512, 2, 0},
        {"repeated 6C bounded", {{0xca, 0, 0x6c02, 0, 0}, {0xca, 2, 0x6c02, 0, 0}}, 2, 512, 0, PM3_EWRONGANSWER},
        {"transport failure preserves error", {{0xca, 0, 0x6c02, 0, PM3_ETIMEOUT}}, 1, 512, 0, PM3_ETIMEOUT},
        {"truncated response", {{0xca, 0, 0, 0, 200}}, 1, 512, 0, 200},
        {"reported chunk too large", {{0xca, 0, 0x9000, APDU_RES_LEN + 1, 0}}, 1, 512, 0, PM3_EOVFLOW},
        {"append capacity", {{0xca, 0, 0x6102, 1, 0}, {0xc0, 2, 0x9000, 2, 0}}, 2, 2, 0, PM3_EOVFLOW},
        {"exact capacity", {{0xca, 0, 0x9000, 2, 0}}, 1, 2, 2, 0},
        {"no capacity for next response", {{0xca, 0, 0x6101, 2, 0}}, 1, 2, 0, PM3_EOVFLOW},
        {"6C response cannot carry data", {{0xca, 0, 0x6c02, 1, 0}}, 1, 512, 0, PM3_EWRONGANSWER},
        {"card warning payload", {{0xca, 0, 0x6281, 2, 5}}, 1, 512, 2, PM3_EAPDU_FAIL},
        {"failure after partial response", {{0xca, 0, 0x6101, 1, 0}, {0xc0, 1, 0, 0, PM3_ERFTRANS}}, 2, 512, 0, PM3_ERFTRANS},
    };
    size_t failures = 0;
    for (size_t i = 0; i < ARRAYLEN(cases); i++) {
        emv_transport_fixture_t fixture = {cases[i].steps, cases[i].count, 0, true, false, false};
        uint8_t data[514];
        memset(data, 0xa5, sizeof(data));
        size_t len = 0;
        uint16_t sw;
        int res = emv_exchange_chained(emv_exchange_fixture, &fixture, true,
                                        (sAPDU_t) {0x80, 0xca, 0x9f, 0x36, 0, NULL}, true, 0,
                                        data + 1, cases[i].capacity, &len, &sw);
        bool passed = res == cases[i].result && len == cases[i].length && fixture.matched &&
                      fixture.calls == fixture.count && data[0] == 0xa5 && data[cases[i].capacity + 1] == 0xa5;
        size_t offset = 0;
        for (size_t step = 0; len && step < cases[i].count; step++) {
            if ((cases[i].steps[step].sw >> 8) == 0x6c) continue;
            for (size_t byte = 0; byte < cases[i].steps[step].length; byte++) {
                passed &= offset < len && data[offset + 1] == step + 1;
                offset++;
            }
        }
        failures += !passed;
        PrintAndLogEx(passed ? SUCCESS : FAILED, "Transport test %s ( %s )", cases[i].name, passed ? "ok" : "fail");
    }
    emv_transport_fixture_t endless = {NULL, 0, 0, true, true, false};
    uint8_t data[512];
    size_t len;
    uint16_t sw;
    int res = emv_exchange_chained(emv_exchange_fixture, &endless, true,
                                    (sAPDU_t) {0x80, 0xca, 0, 0, 0, NULL}, true, 0, data, sizeof(data), &len, &sw);
    failures += !(res == PM3_EOVFLOW && endless.calls == 17 && len == 0);
    uint8_t oversized[255] = {0};
    Iso7816CommandChannel channel = CC_CONTACT;
    failures += emv_exchange_device(&channel, false, (sAPDU_t) {0x80, 0xae, 0, 0, 255, oversized},
                                      true, 0, data, sizeof(data), &len, &sw) != PM3_EOVFLOW;
    static const struct {
        emv_transport_step_t steps[2];
        size_t count;
        bool contact;
        int result;
    } selections[] = {
        {{{0xa4, 0, 0x9000, 2, 0}}, 1, true, 0},
        {{{0xa4, 0, 0x6700, 0, 5}, {0xa4, 0, 0x9000, 2, 0}}, 2, true, 0},
        {{{0xa4, 0, 0x6f00, 0, 5}, {0xa4, 0, 0x9000, 2, 0}}, 2, true, 0},
        {{{0xa4, 0, 0x6102, 0, 0}, {0xc0, 2, 0x9000, 2, 0}}, 2, true, 0},
        {{{0xa4, 0, 0x6c02, 0, 5}, {0xa4, 2, 0x9000, 2, 0}}, 2, true, 0},
        {{{0xa4, 0, 0x9000, 2, 0}}, 1, false, 0},
        {{{0xa4, 0, 0x6700, 0, 5}, {0xa4, 0, 0x6700, 0, 5}}, 2, true, PM3_EAPDU_FAIL},
        {{{0xa4, 0, 0x6700, 0, PM3_ETIMEOUT}}, 1, true, PM3_ETIMEOUT},
    };
    for (size_t i = 0; i < ARRAYLEN(selections); i++) {
        emv_transport_fixture_t fixture = {selections[i].steps, selections[i].count, 0, true, false, selections[i].contact};
        uint8_t aid[5] = {0xa0, 0, 0, 0, 3};
        res = emv_select_exchange(emv_exchange_fixture, &fixture, true, selections[i].contact,
                                  aid, sizeof(aid), data, sizeof(data), &len, &sw);
        bool passed = res == selections[i].result && fixture.matched && fixture.calls == fixture.count;
        failures += !passed;
        PrintAndLogEx(passed ? SUCCESS : FAILED, "SELECT transport test %zu ( %s )", i + 1, passed ? "ok" : "fail");
    }
    PrintAndLogEx(failures ? FAILED : SUCCESS, "Transport tests: %zu cases, %zu failures", ARRAYLEN(cases) + 2 + ARRAYLEN(selections), failures);
    return failures ? PM3_ESOFT : PM3_SUCCESS;
}

// Book 3 sections 10.9-10.11. This is the contact completion sequence;
// contactless kernels have their own online completion rules.
static bool emv_script_apdu(const struct tlv *command, sAPDU_t *apdu, bool *include_le, uint16_t *le) {
    if (!command || command->len < 4 || command->len > APDU_RES_LEN)
        return false;
    const uint8_t *p = command->value;
    *apdu = (sAPDU_t) {p[0], p[1], p[2], p[3], 0, NULL};
    *include_le = false;
    *le = 0;
    if (command->len == 4)
        return true;
    if (command->len == 5) {
        *include_le = true;
        *le = p[4] ? p[4] : 256;
        return true;
    }
    size_t lc = p[4];
    if (!lc || (command->len != lc + 5 && command->len != lc + 6))
        return false;
    apdu->Lc = lc;
    apdu->data = (uint8_t *)p + 5;
    if (command->len == lc + 6) {
        *include_le = true;
        *le = p[5 + lc] ? p[5 + lc] : 256;
    }
    return true;
}

static int emv_issuer_validate(const struct tlvdb *issuer, bool unavailable, size_t *scripts) {
    *scripts = 0;
    size_t arcs = 0, authentications = 0;
    if (unavailable)
        return issuer ? PM3_EINVARG : PM3_SUCCESS;
    for (const struct tlvdb *node = issuer; node; node = node->next) {
        const struct tlv *t = &node->tag;
        if (t->tag == 0x8a) {
            if (++arcs != 1 || t->len != 2)
                return PM3_EINVARG;
            for (size_t i = 0; i < 2; i++)
                if (!((t->value[i] >= '0' && t->value[i] <= '9') ||
                      (t->value[i] >= 'A' && t->value[i] <= 'Z')))
                    return PM3_EINVARG;
        } else if (t->tag == 0x91) {
            if (++authentications != 1 || t->len < 8 || t->len > 16)
                return PM3_EINVARG;
        } else if (t->tag == 0x71 || t->tag == 0x72) {
            // Local resource limit, not a limit on script-template length.
            if (++*scripts > 32)
                return PM3_EOVFLOW;
            size_t commands = 0, identifiers = 0;
            for (const struct tlvdb *child = node->children; child; child = child->next) {
                if (child->tag.tag == 0x9f18) {
                    if (++identifiers > 1 || commands || child->tag.len != 4)
                        return PM3_EINVARG;
                } else if (child->tag.tag == 0x86) {
                    sAPDU_t apdu;
                    bool include_le;
                    uint16_t le;
                    if (!emv_script_apdu(&child->tag, &apdu, &include_le, &le))
                        return PM3_EINVARG;
                    commands++;
                } else {
                    return PM3_EINVARG;
                }
            }
            if (!commands)
                return PM3_EINVARG;
        } else {
            return PM3_EINVARG;
        }
    }
    return arcs == 1 ? PM3_SUCCESS : PM3_EINVARG;
}

static bool emv_dol_has(const struct tlv *dol, tlv_tag_t tag, size_t minimum) {
    if (!dol) return false;
    const uint8_t *p = dol->value;
    size_t left = dol->len;
    while (left) {
        struct tlv t;
        if (!dol_parse_tl(&p, &left, &t)) return false;
        if (t.tag == tag && t.len >= minimum) return true;
    }
    return false;
}

static bool emv_completion_set(struct tlvdb *db, tlv_tag_t tag, size_t len, const uint8_t *value) {
    // The transaction has a stable, non-data root; replacement must not free it.
    if (db->tag.tag == tag) return false;
    tlvdb_change_or_add_node(db, tag, len, value);
    const struct tlv *t = tlvdb_get(db, tag, NULL);
    return t && t->len == len && (!len || !memcmp(t->value, value, len));
}

static bool emv_completion_flags(struct tlvdb *db, const uint8_t *tvr, const uint8_t *tsi) {
    return emv_completion_set(db, 0x95, 5, tvr) && emv_completion_set(db, 0x9b, 2, tsi);
}

static int emv_run_scripts(emv_exchange_fn exchange, void *context, const struct tlvdb *issuer,
                            tlv_tag_t stage, uint8_t tvr[5], uint8_t tsi[2],
                            uint8_t results[160], size_t *results_len, bool *failed) {
    for (const struct tlvdb *script = issuer; script; script = script->next) {
        if (script->tag.tag != stage) continue;
        uint8_t entry[5] = {0x20, 0, 0, 0, 0};
        size_t sequence = 0;
        tsi[0] |= 0x04;
        for (const struct tlvdb *command = script->children; command; command = command->next) {
            if (command->tag.tag == 0x9f18) {
                memcpy(entry + 1, command->tag.value, 4);
                continue;
            }
            sAPDU_t apdu;
            bool include_le;
            uint16_t le, sw;
            uint8_t response[APDU_RES_LEN];
            size_t length;
            if (!emv_script_apdu(&command->tag, &apdu, &include_le, &le))
                return PM3_EINVARG;
            sequence++;
            int res = emv_exchange_chained(exchange, context, false, apdu, include_le, le,
                                            response, sizeof(response), &length, &sw);
            if (res != PM3_SUCCESS && res != PM3_EAPDU_FAIL)
                return res;
            uint8_t sw1 = sw >> 8;
            if (sw1 != 0x90 && sw1 != 0x62 && sw1 != 0x63) {
                tvr[4] |= stage == 0x71 ? 0x20 : 0x10;
                entry[0] = 0x10 | (sequence > 15 ? 15 : sequence);
                *failed = true;
                break;
            }
        }
        memcpy(results + *results_len, entry, sizeof(entry));
        *results_len += sizeof(entry);
    }
    return PM3_SUCCESS;
}

static int emv_final_ac(const uint8_t *response, size_t length, uint16_t first_atc, bool approve) {
    struct tlvdb *db = tlvdb_parse(response, length);
    if (!db) return PM3_EWRONGANSWER;
    const struct tlv *outer = &db->tag, *cid = NULL, *atc = NULL, *ac = NULL;
    uint8_t format1_cid[1], format1_atc[2];
    struct tlv cid1 = {0x9f27, 1, format1_cid}, atc1 = {0x9f36, 2, format1_atc};
    bool valid = true;
    if (outer->tag == 0x80 && outer->len >= 11 && outer->len <= 43) {
        format1_cid[0] = outer->value[0];
        memcpy(format1_atc, outer->value + 1, 2);
        cid = &cid1;
        atc = &atc1;
    } else if (outer->tag == 0x77) {
        for (const struct tlvdb *child = db->children; child; child = child->next) {
            const struct tlv *t = &child->tag;
            if (t->tag == 0x9f27) { if (cid) valid = false; cid = t; }
            if (t->tag == 0x9f36) { if (atc) valid = false; atc = t; }
            if (t->tag == 0x9f26) { if (ac) valid = false; ac = t; }
        }
        valid &= ac && ac->len == 8;
    } else {
        valid = false;
    }
    valid &= cid && cid->len == 1 && atc && atc->len == 2;
    if (valid) {
        uint8_t type = cid->value[0] & EMVAC_AC_MASK;
        valid = (type == EMVAC_AAC || (approve && type == EMVAC_TC)) &&
                (((uint16_t)atc->value[0] << 8) | atc->value[1]) == first_atc;
    }
    tlvdb_free(db);
    return valid ? PM3_SUCCESS : PM3_EWRONGANSWER;
}

static int emv_complete(emv_exchange_fn exchange, void *context, struct tlvdb *transaction,
                         const struct tlvdb *issuer, uint16_t first_atc, bool unavailable, bool approve,
                         uint8_t *response, size_t capacity, size_t *length, uint16_t *sw) {
    if (!transaction || !response || !length || !sw || !capacity || (unavailable && approve))
        return PM3_EINVARG;
    *length = 0;
    *sw = 0;
    size_t scripts;
    int res = emv_issuer_validate(issuer, unavailable, &scripts);
    if (res) return res;
    const struct tlv *aip = tlvdb_get(transaction, 0x82, NULL);
    const struct tlv *cdol = tlvdb_get(transaction, 0x8d, NULL);
    const struct tlv *cid = tlvdb_get(transaction, 0x9f27, NULL);
    const struct tlv *counter = tlvdb_get(transaction, 0x9f36, NULL);
    if (!aip || aip->len != 2 || !cdol || !cdol->len || !cid || cid->len != 1 ||
            (cid->value[0] & EMVAC_AC_MASK) != EMVAC_ARQC || !counter || counter->len != 2 ||
            (((uint16_t)counter->value[0] << 8) | counter->value[1]) != first_atc)
        return PM3_EINVARG;
    const struct tlv *authentication = tlvdb_get(issuer, 0x91, NULL);
    if (authentication && !(aip->value[0] & 0x04) &&
            !emv_dol_has(cdol, 0x91, authentication->len))
        return PM3_EINVARG;
    uint8_t tvr[5] = {0}, tsi[2] = {0};
    const struct tlv *old_tvr = tlvdb_get(transaction, 0x95, NULL), *old_tsi = tlvdb_get(transaction, 0x9b, NULL);
    if ((old_tvr && old_tvr->len != 5) || (old_tsi && old_tsi->len != 2))
        return PM3_EINVARG;
    if (old_tvr) memcpy(tvr, old_tvr->value, 5);
    if (old_tsi) memcpy(tsi, old_tsi->value, 2);
    const uint8_t unable_arc[] = {'Z', '3'};
    const struct tlv *arc = tlvdb_get(issuer, 0x8a, NULL);
    if (!emv_completion_set(transaction, 0x8a, 2, unavailable ? unable_arc : arc->value) ||
            (authentication && !emv_completion_set(transaction, 0x91, authentication->len, authentication->value)))
        return PM3_EMALLOC;
    // Validate CDOL2 before sending any authentication or script commands.
    struct tlv *data = dol_process(cdol, transaction, 1);
    if (!data || data->len > APDU_RES_LEN - 6) { free(data); return PM3_EINVARG; }
    free(data);
    // There must never be a retry of authentication, scripts or final AC after
    // an uncertain transport result. The caller must start a new transaction.
    uint8_t consumed = EMVAC_AAC;
    if (!emv_completion_set(transaction, 0x9f27, 1, &consumed)) return PM3_EMALLOC;
    bool failed = false;
    if (authentication && (aip->value[0] & 0x04)) {
        uint8_t auth_response[APDU_RES_LEN];
        size_t auth_length;
        uint16_t auth_sw;
        tsi[0] |= 0x10;
        res = emv_exchange_chained(exchange, context, false,
                (sAPDU_t) {0x00, 0x82, 0, 0, authentication->len, (uint8_t *)authentication->value},
                false, 0, auth_response, sizeof(auth_response), &auth_length, &auth_sw);
        if (res != PM3_SUCCESS && res != PM3_EAPDU_FAIL) return res;
        if (auth_sw != ISO7816_OK) { tvr[4] |= 0x40; failed = true; approve = false; }
    }
    uint8_t script_results[160];
    size_t script_results_len = 0;
    res = emv_run_scripts(exchange, context, issuer, 0x71, tvr, tsi, script_results, &script_results_len, &failed);
    if (res) return res;
    if (!emv_completion_flags(transaction, tvr, tsi)) return PM3_EMALLOC;
    // Updating the tree may relocate a node; obtain CDOL2 again.
    data = dol_process(tlvdb_get(transaction, 0x8d, NULL), transaction, 1);
    if (!data || data->len > APDU_RES_LEN - 6) { free(data); return PM3_EINVARG; }
    res = emv_exchange_chained(exchange, context, false,
            (sAPDU_t) {0x80, 0xae, approve ? EMVAC_TC : EMVAC_AAC, 0, data->len, (uint8_t *)data->value},
            true, 0, response, capacity, length, sw);
    free(data);
    if (res) return res;
    res = emv_final_ac(response, *length, first_atc, approve);
    if (res) return res;
    res = emv_run_scripts(exchange, context, issuer, 0x72, tvr, tsi, script_results, &script_results_len, &failed);
    if (!emv_completion_flags(transaction, tvr, tsi)) return PM3_EMALLOC;
    if (script_results_len && !emv_completion_set(transaction, 0x9f5b, script_results_len, script_results))
        return PM3_EMALLOC;
    return res ? res : failed ? PM3_EPARTIAL : PM3_SUCCESS;
}

int EMVCompleteTransaction(Iso7816CommandChannel channel, struct tlvdb *transaction,
                           const struct tlvdb *issuer, uint16_t first_atc, bool unavailable, bool approve,
                           uint8_t *response, size_t capacity, size_t *length, uint16_t *sw) {
    if (channel != CC_CONTACT) return PM3_EINVARG;
    return emv_complete(emv_exchange_device, &channel, transaction, issuer, first_atc,
                        unavailable, approve, response, capacity, length, sw);
}

typedef struct {
    const uint8_t *instructions;
    size_t count, calls;
    uint16_t auth_sw, before_sw, after_sw;
    uint8_t final_cid;
    uint16_t final_atc;
    uint8_t expected_p1, expected_tvr;
    bool matched, format2, duplicate, unavailable;
    int transport_error;
} emv_completion_fixture_t;

static int emv_completion_fixture(void *context, bool activate, sAPDU_t apdu, bool include_le,
                                   uint16_t le, uint8_t *result, size_t capacity, size_t *length, uint16_t *sw) {
    emv_completion_fixture_t *f = context;
    size_t call = f->calls++;
    f->matched &= !activate && call < f->count && f->instructions[call] == apdu.INS;
    *length = 0;
    *sw = 0x9000;
    if (f->transport_error) return f->transport_error;
    if (apdu.INS == 0x82) {
        f->matched &= !include_le && apdu.Lc == 8;
        *sw = f->auth_sw;
    } else if (apdu.INS == 0xda) {
        f->matched &= !include_le && apdu.Lc == 0;
        *sw = f->before_sw;
    } else if (apdu.INS == 0xdc) {
        f->matched &= include_le && le == 256 && apdu.Lc == 0;
        *sw = f->after_sw;
    } else if (apdu.INS == 0xae) {
        f->matched &= include_le && le == 0 && apdu.P1 == f->expected_p1 && apdu.Lc >= 9;
        if (apdu.Lc >= 9)
            f->matched &= apdu.data[0] == (f->unavailable ? 'Z' : '0') &&
                          apdu.data[1] == (f->unavailable ? '3' : '0') && apdu.data[6] == f->expected_tvr;
        if (apdu.Lc == 17) {
            const uint8_t authentication[] = {1, 2, 3, 4, 5, 6, 7, 8};
            f->matched &= !memcmp(apdu.data + 9, authentication, sizeof(authentication));
        }
        uint8_t payload[] = {0x80, 11, f->final_cid, f->final_atc >> 8, f->final_atc & 255,
                             1, 2, 3, 4, 5, 6, 7, 8};
        uint8_t format2[] = {0x77, 20, 0x9f, 0x27, 1, f->final_cid,
                            0x9f, 0x36, 2, f->final_atc >> 8, f->final_atc & 255,
                            0x9f, 0x26, 8, 1, 2, 3, 4, 5, 6, 7, 8,
                            0x9f, 0x27, 1, f->final_cid};
        if (f->duplicate) format2[1] += 4;
        *length = f->format2 ? (f->duplicate ? 26 : 22) : sizeof(payload);
        if (capacity < *length) return PM3_EOVFLOW;
        memcpy(result, f->format2 ? format2 : payload, *length);
    } else {
        f->matched = false;
    }
    return *sw == 0x9000 ? PM3_SUCCESS : PM3_EAPDU_FAIL;
}

int EMVCompletionSelfTests(void) {
    static const uint8_t context_data[] = {
        0x01, 0,
        0x82, 2, 4, 0, 0x8d, 6, 0x8a, 2, 0x95, 5, 0x9b, 2,
        0x9f, 0x27, 1, 0x80, 0x9f, 0x36, 2, 0, 1
    };
    // ARC, issuer authentication data, before/after scripts. No live keys.
    static const uint8_t issuer_data[] = {
        0x8a, 2, '0', '0', 0x91, 8, 1, 2, 3, 4, 5, 6, 7, 8,
        0x71, 13, 0x9f, 0x18, 4, 1, 2, 3, 4, 0x86, 4, 0, 0xda, 0, 0,
        0x72, 7, 0x86, 5, 0, 0xdc, 0, 0, 0
    };
    static const uint8_t sequence[] = {0x82, 0xda, 0xae, 0xdc};
    size_t failures = 0;
    for (size_t i = 0; i < 17; i++) {
        struct tlvdb *db = tlvdb_parse_multi(context_data, sizeof(context_data));
        struct tlvdb *issuer = tlvdb_parse_multi(issuer_data, sizeof(issuer_data));
        emv_completion_fixture_t f = {sequence, 4, 0, 0x9000, 0x9000, 0x9000,
                                      EMVAC_TC, 1, EMVAC_TC, 0, true, false, false, false, 0};
        int expected = PM3_SUCCESS;
        size_t expected_calls = 4;
        if (i == 1) { f.auth_sw = 0x6300; f.expected_p1 = EMVAC_AAC; f.final_cid = EMVAC_AAC; f.expected_tvr = 0x40; expected = PM3_EPARTIAL; }
        if (i == 2) { f.before_sw = 0x6985; f.expected_tvr = 0x20; expected = PM3_EPARTIAL; }
        if (i == 3) { f.after_sw = 0x6985; expected = PM3_EPARTIAL; }
        if (i == 4) { f.before_sw = 0x6281; f.after_sw = 0x63c1; }
        if (i == 5) { f.final_cid = EMVAC_ARQC; expected = PM3_EWRONGANSWER; expected_calls = 3; }
        if (i == 6) { f.final_atc = 2; expected = PM3_EWRONGANSWER; expected_calls = 3; }
        if (i == 7) { f.format2 = true; }
        if (i == 8) { f.format2 = true; f.duplicate = true; expected = PM3_EWRONGANSWER; expected_calls = 3; }
        if (i == 9) { f.transport_error = PM3_ETIMEOUT; expected = PM3_ETIMEOUT; expected_calls = 1; }
        if (i == 10) { uint8_t aip[2] = {0}; tlvdb_change_or_add_node(db, 0x82, 2, aip); expected = PM3_EINVARG; expected_calls = 0; }
        if (i == 11) { uint8_t malformed[] = {0x9f}; tlvdb_change_or_add_node(db, 0x8d, 1, malformed); expected = PM3_EINVARG; expected_calls = 0; }
        if (i == 12) { tlvdb_free(issuer); issuer = NULL; f.instructions = sequence + 2; f.count = 1; f.expected_p1 = 0; f.final_cid = 0; f.unavailable = true; expected_calls = 1; }
        if (i == 13) {
            tlvdb_free(issuer);
            const uint8_t invalid[] = {0x8a, 1, '0'};
            issuer = tlvdb_parse_multi(invalid, sizeof(invalid));
            expected = PM3_EINVARG; expected_calls = 0;
        }
        if (i == 14) { f.expected_p1 = EMVAC_AAC; expected = PM3_EWRONGANSWER; expected_calls = 3; }
        if (i == 15) {
            uint8_t aip[2] = {0}, combined[] = {0x8a, 2, 0x95, 5, 0x9b, 2, 0x91, 8};
            tlvdb_change_or_add_node(db, 0x82, 2, aip);
            tlvdb_change_or_add_node(db, 0x8d, sizeof(combined), combined);
            f.instructions = sequence + 1; f.count = 3; expected_calls = 3;
        }
        if (i == 16) {
            tlvdb_free(issuer);
            issuer = tlvdb_parse_multi(issuer_data, 4);
            f.instructions = sequence + 2; f.count = 1; expected_calls = 1;
        }
        uint8_t response[256];
        size_t length;
        uint16_t sw;
        int res = emv_complete(emv_completion_fixture, &f, db, issuer, 1, i == 12, i != 12 && i != 14,
                                response, sizeof(response), &length, &sw);
        bool passed = db && (issuer || i == 12) && f.matched && res == expected && f.calls == expected_calls;
        if (i == 0 || i == 2 || i == 3 || i == 4) {
            const struct tlv *results = tlvdb_get(db, 0x9f5b, NULL), *tvr = tlvdb_get(db, 0x95, NULL);
            passed &= results && results->len == 10 && results->value[0] == (i == 2 ? 0x11 : 0x20) &&
                      results->value[5] == (i == 3 ? 0x11 : 0x20) && sw == 0x9000 && tvr &&
                      tvr->value[4] == (i == 2 ? 0x20 : i == 3 ? 0x10 : 0);
        }
        if (expected_calls) {
            size_t calls = f.calls;
            passed &= emv_complete(emv_completion_fixture, &f, db, issuer, 1, i == 12, false,
                                    response, sizeof(response), &length, &sw) == PM3_EINVARG && f.calls == calls;
        }
        failures += !passed;
        PrintAndLogEx(passed ? SUCCESS : FAILED, "Completion test %zu ( %s )", i + 1, passed ? "ok" : "fail");
        tlvdb_free(db);
        tlvdb_free(issuer);
    }
    // Validate every prefix before any side effect; a prefix ending after ARC
    // is itself a valid response, while a truncated authentication/script is not.
    for (size_t len = 1; len < sizeof(issuer_data); len++) {
        struct tlvdb *issuer = tlvdb_parse_multi(issuer_data, len);
        size_t count;
        bool boundary = len == 4 || len == 14 || len == 29;
        bool valid = issuer && emv_issuer_validate(issuer, false, &count) == PM3_SUCCESS;
        failures += valid != boundary;
        tlvdb_free(issuer);
    }
    uint8_t large_script[140] = {0x8a, 2, '0', '0', 0x71, 0x81, 133, 0x86, 0x81, 130, 0, 0xda, 0, 0, 125};
    struct tlvdb *large = tlvdb_parse_multi(large_script, sizeof(large_script));
    size_t script_count;
    failures += !(large && emv_issuer_validate(large, false, &script_count) == PM3_SUCCESS && script_count == 1);
    tlvdb_free(large);
    large_script[14] = 126; // Inconsistent Lc, despite a valid outer TLV.
    large = tlvdb_parse_multi(large_script, sizeof(large_script));
    failures += !(large && emv_issuer_validate(large, false, &script_count) == PM3_EINVARG);
    tlvdb_free(large);
    PrintAndLogEx(failures ? FAILED : SUCCESS, "Completion tests: 17 flows, long scripts and issuer-response truncations, %zu failures", failures);
    return failures ? PM3_ESOFT : PM3_SUCCESS;
}

static int EMVExchangeEx(Iso7816CommandChannel channel, bool ActivateField, bool LeaveFieldON, sAPDU_t apdu, bool IncludeLe, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw, struct tlvdb *tlv) {
    if (!Result || !ResultLen || !sw || MaxResultLen == 0)
        return PM3_EINVARG;
    if ((channel != CC_CONTACTLESS && channel != CC_CONTACT) || (apdu.Lc && !apdu.data))
        return PM3_EINVARG;

    *ResultLen = 0;
    *sw = 0;

    // A SELECT is the first command in every EMV flow. Make the common case
    // reliable even when the caller omitted the legacy `-s` switch.
    if (channel == CC_CONTACTLESS && GetISODEPState() == ISODEP_INACTIVE)
        ActivateField = true;

    // Keep the transport active until status-word chaining and Le correction
    // are complete. Honour LeaveFieldON once the logical APDU is complete.
    int res = emv_exchange_chained(emv_exchange_device, &channel, ActivateField, apdu, IncludeLe, 0,
                                    Result, MaxResultLen, ResultLen, sw);

    if (!LeaveFieldON)
        DropFieldEx(channel);

    // add to tlv tree
    if ((res == PM3_SUCCESS) && tlv && *ResultLen) {
        struct tlvdb *t = tlvdb_parse_multi(Result, *ResultLen);
        if (t)
            tlvdb_add(tlv, t);
    }
    return res;
}

int EMVExchange(Iso7816CommandChannel channel, bool LeaveFieldON, sAPDU_t apdu, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw, struct tlvdb *tlv) {
    return EMVExchangeEx(channel, false, LeaveFieldON, apdu, false,
                         Result, MaxResultLen, ResultLen, sw, tlv);
}

int EMVSelect(Iso7816CommandChannel channel, bool ActivateField, bool LeaveFieldON, uint8_t *AID, size_t AIDLen, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw, struct tlvdb *tlv) {
    if (!AID || AIDLen < 5 || AIDLen > 16 || (channel != CC_CONTACT && channel != CC_CONTACTLESS))
        return PM3_EINVARG;
    if (channel == CC_CONTACTLESS && GetISODEPState() == ISODEP_INACTIVE) ActivateField = true;
    int res = emv_select_exchange(emv_exchange_device, &channel, ActivateField, channel == CC_CONTACT,
                                  AID, AIDLen, Result, MaxResultLen, ResultLen, sw);
    if (!LeaveFieldON) DropFieldEx(channel);
    if (!res && tlv && *ResultLen) {
        struct tlvdb *t = tlvdb_parse_multi(Result, *ResultLen);
        if (t) tlvdb_add(tlv, t);
    }
    return res;
}

int EMVSelectPSE(Iso7816CommandChannel channel, bool ActivateField, bool LeaveFieldON, uint8_t PSENum, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw) {
    uint8_t buf[APDU_AID_LEN] = {0};
    int len = 0;
    switch (PSENum) {
        case 1:
            param_gethex_to_eol(PSElist[1], 0, buf, sizeof(buf), &len);
            break;
        case 2:
            param_gethex_to_eol(PSElist[0], 0, buf, sizeof(buf), &len);
            break;
        default:
            return -1;
    }
    return EMVSelect(channel, ActivateField, LeaveFieldON, buf, len, Result, MaxResultLen, ResultLen, sw, NULL);
}

static int EMVSelectWithRetry(Iso7816CommandChannel channel, bool ActivateField, bool LeaveFieldON, uint8_t *AID, size_t AIDLen, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw, struct tlvdb *tlv) {
    int retrycnt = 0;
    int res = 0;
    do {
        res = EMVSelect(channel, ActivateField || retrycnt > 0, true, AID, AIDLen,
                        Result, MaxResultLen, ResultLen, sw, tlv);

        // retry if error and not returned sw error
        if (res && res != PM3_EAPDU_FAIL) {
            if (++retrycnt < 3) {
                continue;
            } else {
                // card select error, proxmark error
                if (res == 1) {
                    PrintAndLogEx(WARNING, "exiting...");
                    return 1;
                }

                PrintAndLogEx(FAILED, "Retry failed [%s]. Skipped...", sprint_hex_inrow(AID, AIDLen));
                return res;
            }
        }
    } while (res && res != PM3_EAPDU_FAIL);

    return res;
}

static int EMVCheckAID(Iso7816CommandChannel channel, bool decodeTLV, struct tlvdb *tlvdbelm, struct tlvdb *tlv) {
    uint8_t data[APDU_RES_LEN] = {0};
    size_t datalen = 0;
    int res = 0;
    uint16_t sw = 0;

    while (tlvdbelm) {
        const struct tlv *tgAID = tlvdb_get_inchild(tlvdbelm, 0x4f, NULL);
        if (tgAID) {
            res = EMVSelectWithRetry(channel, false, true, (uint8_t *)tgAID->value, tgAID->len, data, sizeof(data), &datalen, &sw, tlv);

            // if returned sw error
            if (res == PM3_EAPDU_FAIL) {
                // next element
                tlvdbelm = tlvdb_find_next(tlvdbelm, 0x61);
                continue;
            }

            if (res)
                break;

            // all is ok
            if (decodeTLV) {
                PrintAndLogEx(SUCCESS, "%s:", sprint_hex_inrow(tgAID->value, tgAID->len));
                TLVPrintFromBuffer(data, datalen);
            }
        }
        tlvdbelm = tlvdb_find_next(tlvdbelm, 0x61);
    }
    return res;
}

int EMVSearchPSE(Iso7816CommandChannel channel, bool ActivateField, bool LeaveFieldON, uint8_t PSENum, bool decodeTLV, struct tlvdb *tlv) {
    uint8_t data[APDU_RES_LEN] = {0};
    size_t datalen = 0;
    uint16_t sw = 0;
    int res;
    const char *PSE_or_PPSE = PSENum == 1 ? "PSE" : "PPSE";

    // select PPSE
    res = EMVSelectPSE(channel, ActivateField, true, PSENum, data, sizeof(data), &datalen, &sw);

    if (!res) {
        if (sw != ISO7816_OK) {
            PrintAndLogEx(FAILED, "Select PSE error. APDU error: %04x.", sw);
            return 1;
        }

        struct tlvdb *t = tlvdb_parse_multi(data, datalen);
        if (t) {
            bool fileFound = false;
            // PSE/PPSE with SFI
            struct tlvdb *tsfi = tlvdb_find_path(t, (tlv_tag_t[]) {0x6f, 0xa5, 0x88, 0x00});
            if (tsfi) {
                uint8_t sfidata[0x11][APDU_RES_LEN];
                size_t sfidatalen[0x11] = {0};
                uint8_t sfin = 0;
                tlv_get_uint8(tlvdb_get_tlv(tsfi), &sfin);
                PrintAndLogEx(INFO, "* PPSE get SFI: 0x%02x.", sfin);

                for (uint8_t ui = 0x01; ui <= 0x10; ui++) {
                    PrintAndLogEx(INFO, "* * Get SFI: 0x%02x. num: 0x%02x", sfin, ui);
                    res = EMVReadRecord(channel, true, sfin, ui, sfidata[ui], APDU_RES_LEN, &sfidatalen[ui], &sw, NULL);

                    // end of records
                    if (sw == 0x6a83) {
                        sfidatalen[ui] = 0;
                        PrintAndLogEx(INFO, "* * PPSE get SFI. End of records.");
                        break;
                    }

                    // error catch!
                    if (sw != ISO7816_OK) {
                        sfidatalen[ui] = 0;
                        PrintAndLogEx(FAILED, "PPSE get Error. APDU error: %04x.", sw);
                        break;
                    }

                    if (decodeTLV) {
                        TLVPrintFromBuffer(sfidata[ui], sfidatalen[ui]);
                    }
                }

                for (uint8_t ui = 0x01; ui <= 0x10; ui++) {
                    if (sfidatalen[ui]) {

                        struct tlvdb *tsfi_a = tlvdb_parse_multi(sfidata[ui], sfidatalen[ui]);
                        if (tsfi_a) {
                            struct tlvdb *tsfitmp = tlvdb_find_path(tsfi_a, (tlv_tag_t[]) {0x70, 0x61, 0x00});
                            if (!tsfitmp) {
                                PrintAndLogEx(FAILED, "SFI 0x%02zu doesn't have any records.", sfidatalen[ui]);
                                continue;
                            }
                            res = EMVCheckAID(channel, decodeTLV, tsfitmp, tlv);
                            fileFound = true;
                        }
                        tlvdb_free(tsfi_a);
                    }
                }
            }


            // PSE/PPSE plain (wo SFI)
            struct tlvdb *ttmp = tlvdb_find_path(t, (tlv_tag_t[]) {0x6f, 0xa5, 0xbf0c, 0x61, 0x00});
            if (ttmp) {
                res = EMVCheckAID(channel, decodeTLV, ttmp, tlv);
                fileFound = true;
            }

            if (!fileFound)
                PrintAndLogEx(FAILED, "PPSE doesn't have any records.");

            tlvdb_free(t);
        } else {
            PrintAndLogEx(WARNING, "%s ERROR: Can't get TLV from response.", PSE_or_PPSE);
        }
    } else {
        PrintAndLogEx(ERR, "%s ERROR: Can't select PPSE AID. Error: %d", PSE_or_PPSE, res);
    }

    if (!LeaveFieldON)
        DropFieldEx(channel);

    return res;
}

int EMVSearch(Iso7816CommandChannel channel, bool ActivateField, bool LeaveFieldON, bool decodeTLV, struct tlvdb *tlv, bool verbose) {
    uint8_t aidbuf[APDU_AID_LEN] = {0};
    int aidlen = 0;
    uint8_t data[APDU_RES_LEN] = {0};
    size_t datalen = 0;
    uint16_t sw = 0;

    int retrycnt = 0;
    for (int i = 0; i < ARRAYLEN(AIDlist); i ++) {

        if (kbd_enter_pressed()) {
            PrintAndLogEx(WARNING, "\naborted via keyboard!");
            break;
        }

        param_gethex_to_eol(AIDlist[i].aid, 0, aidbuf, sizeof(aidbuf), &aidlen);
        int res = EMVSelect(channel, (i == 0) ? ActivateField : false, true, aidbuf, aidlen, data, sizeof(data), &datalen, &sw, tlv);
        // retry if error and not returned sw error
        if (res && res != PM3_EAPDU_FAIL) {
            if (++retrycnt < 3) {
                i--;
            } else {
                // (1) - card select error, (4) reply timeout, (200) - result length = 0
                if (res == 1 || res == 4 || res == 200) {
                    if (LeaveFieldON == false)
                        DropFieldEx(channel);

                    if (verbose) {
                        PrintAndLogEx(WARNING, "exiting...");
                    }
                    return 1;
                }

                retrycnt = 0;
                if (verbose) {
                    PrintAndLogEx(FAILED, "Retry failed [%s]. Skipped...", AIDlist[i].aid);
                }
            }
            continue;
        }
        retrycnt = 0;

        if (res)
            continue;

        if (!datalen)
            continue;

        if (decodeTLV) {
            PrintAndLogEx(SUCCESS, "%s", AIDlist[i].aid);
            TLVPrintFromBuffer(data, datalen);
        }
    }

    if (LeaveFieldON == false) {
        DropFieldEx(channel);
    }

    return 0;
}

int EMVSelectApplication(struct tlvdb *tlv, uint8_t *AID, size_t *AIDlen) {
    if (!tlv || !AID || !AIDlen)
        return PM3_EINVARG;

    // Low nibble: 1 is highest; zero or absent means no priority assigned.
    unsigned prio = 17;

    *AIDlen = 0;

    struct tlvdb *ttmp = tlvdb_find(tlv, 0x6f);
    if (!ttmp)
        return 1;

    while (ttmp) {
        const struct tlv *tgAID = tlvdb_get_inchild(ttmp, 0x84, NULL);
        const struct tlv *tgPrio = tlvdb_get_inchild(ttmp, 0x87, NULL);

        if (!tgAID) {
            ttmp = tlvdb_find_next(ttmp, 0x6f);
            continue;
        }
        if (tgAID->len < 5 || tgAID->len > 16) {
            PrintAndLogEx(WARNING, "Ignoring application with invalid AID length %zu", tgAID->len);
            ttmp = tlvdb_find_next(ttmp, 0x6f);
            continue;
        }

        unsigned pt = 16;
        if (tgPrio && tgPrio->len == 1) {
            unsigned priority = tgPrio->value[0] & 0x0f;
            if (priority)
                pt = priority;
        } else if (tgPrio) {
            PrintAndLogEx(WARNING, "Ignoring malformed Application Priority Indicator");
        }
        if (pt < prio) {
            prio = pt;
            memcpy(AID, tgAID->value, tgAID->len);
            *AIDlen = tgAID->len;
        }

        ttmp = tlvdb_find_next(ttmp, 0x6f);
    }

    return *AIDlen ? PM3_SUCCESS : PM3_ESOFT;
}

int EMVGPO(Iso7816CommandChannel channel, bool LeaveFieldON, uint8_t *PDOL, size_t PDOLLen, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw, struct tlvdb *tlv) {
    if (PDOLLen > 0xff || (PDOLLen && !PDOL))
        return PM3_EINVARG;
    return EMVExchangeEx(channel, false, LeaveFieldON, (sAPDU_t) {0x80, 0xa8, 0x00, 0x00, PDOLLen, PDOL}, true, Result, MaxResultLen, ResultLen, sw, tlv);
}

int EMVReadRecord(Iso7816CommandChannel channel, bool LeaveFieldON, uint8_t SFI, uint8_t SFIrec, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw, struct tlvdb *tlv) {
    if (SFI == 0 || SFI > 30 || SFIrec == 0)
        return PM3_EINVARG;
    int res = EMVExchangeEx(channel, false, true, (sAPDU_t) {0x00, 0xb2, SFIrec, (SFI << 3) | 0x04, 0, NULL}, true, Result, MaxResultLen, ResultLen, sw, tlv);
    if (res == PM3_EAPDU_FAIL && sw && (*sw == 0x6700 || *sw == 0x6f00)) {
        PrintAndLogEx(INFO, ">>> trying to reissue command without Le...");
        res = EMVExchangeEx(channel, false, LeaveFieldON, (sAPDU_t) {0x00, 0xb2, SFIrec, (SFI << 3) | 0x04, 0, NULL}, false, Result, MaxResultLen, ResultLen, sw, tlv);
    } else if (!LeaveFieldON)
        DropFieldEx(channel);
    return res;
}

int EMVGetData(Iso7816CommandChannel channel, bool LeaveFieldON, uint16_t foo, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw, struct tlvdb *tlv) {
    return EMVExchangeEx(channel, false, LeaveFieldON, (sAPDU_t) {0x80, 0xCA, ((foo >> 8) & 0xFF), (foo & 0xFF), 0, NULL}, true, Result, MaxResultLen, ResultLen, sw, tlv);
}

int EMVExternalAuthenticate(Iso7816CommandChannel channel, bool LeaveFieldON, uint8_t *IssuerAuthData, size_t IssuerAuthDataLen, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw) {
    if (!IssuerAuthData || IssuerAuthDataLen < 8 || IssuerAuthDataLen > 16)
        return PM3_EINVARG;
    return EMVExchangeEx(channel, false, LeaveFieldON,
                         (sAPDU_t) {0x00, 0x82, 0x00, 0x00, IssuerAuthDataLen, IssuerAuthData},
                         false, Result, MaxResultLen, ResultLen, sw, NULL);
}

int EMVAC(Iso7816CommandChannel channel, bool LeaveFieldON, uint8_t RefControl, uint8_t *CDOL, size_t CDOLLen, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw, struct tlvdb *tlv) {
    if (CDOLLen > 0xff || (CDOLLen && !CDOL))
        return PM3_EINVARG;
    return EMVExchangeEx(channel, false, LeaveFieldON, (sAPDU_t) {0x80, 0xae, RefControl, 0x00, CDOLLen, CDOL}, true, Result, MaxResultLen, ResultLen, sw, tlv);
}

static int emv_challenge_exchange(emv_exchange_fn exchange, void *context, bool activate,
                                   uint8_t *result, size_t capacity, size_t *length, uint16_t *sw) {
    uint8_t cla = 0x00;
    int res = emv_exchange_chained(exchange, context, activate, (sAPDU_t) {0, 0x84, 0, 0, 0, NULL},
                                    true, 0, result, capacity, length, sw);
    // Some applications expose this read-only instruction only in class 80.
    if (res == PM3_EAPDU_FAIL && (*sw == 0x6e00 || *sw == 0x6d00)) {
        PrintAndLogEx(INFO, "GET CHALLENGE: CLA 00/INS 84 unsupported; trying CLA 80");
        cla = 0x80;
        res = emv_exchange_chained(exchange, context, false, (sAPDU_t) {cla, 0x84, 0, 0, 0, NULL},
                                    true, 0, result, capacity, length, sw);
    }
    if (res == PM3_EAPDU_FAIL && (*sw == 0x6700 || *sw == 0x6f00)) {
        PrintAndLogEx(INFO, "GET CHALLENGE: retrying without Le");
        res = emv_exchange_chained(exchange, context, false, (sAPDU_t) {cla, 0x84, 0, 0, 0, NULL},
                                    false, 0, result, capacity, length, sw);
    }
    if (!res && *length != 4 && *length != 8) return PM3_EWRONGANSWER;
    return res;
}

int EMVGenerateChallenge(Iso7816CommandChannel channel, bool LeaveFieldON, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw, struct tlvdb *tlv) {
    (void)tlv; // A random challenge is not BER-TLV data.
    if (channel != CC_CONTACTLESS && channel != CC_CONTACT) return PM3_EINVARG;
    int res = emv_challenge_exchange(emv_exchange_device, &channel,
                                    channel == CC_CONTACTLESS && GetISODEPState() == ISODEP_INACTIVE,
                                    Result, MaxResultLen, ResultLen, sw);
    if (!LeaveFieldON) DropFieldEx(channel);
    return res;
}

typedef struct {
    uint16_t statuses[3];
    uint8_t classes[3];
    bool include_le[3];
    size_t count, calls, response_len;
    bool passed;
    int error;
} emv_challenge_fixture_t;

static int emv_challenge_fixture(void *context, bool activate, sAPDU_t apdu, bool include_le,
                                  uint16_t le, uint8_t *result, size_t capacity, size_t *length, uint16_t *sw) {
    emv_challenge_fixture_t *f = context;
    size_t i = f->calls++;
    if (i >= f->count) { f->passed = false; return PM3_ESOFT; }
    f->passed &= !activate && apdu.INS == 0x84 && apdu.CLA == f->classes[i] && !apdu.Lc &&
                 include_le == f->include_le[i] && le == 0;
    *sw = f->statuses[i];
    *length = *sw == 0x9000 ? f->response_len : 0;
    if (*length > capacity) return PM3_EOVFLOW;
    memset(result, 0xa5, *length);
    return f->error ? f->error : *sw == 0x9000 ? PM3_SUCCESS : PM3_EAPDU_FAIL;
}

int EMVChallengeSelfTests(void) {
    static const struct {emv_challenge_fixture_t fixture; int result;} cases[] = {
        {{{0x9000}, {0}, {true}, 1, 0, 8, true, 0}, 0},
        {{{0x6d00, 0x9000}, {0, 0x80}, {true, true}, 2, 0, 8, true, 0}, 0},
        {{{0x6e00, 0x9000}, {0, 0x80}, {true, true}, 2, 0, 4, true, 0}, 0},
        {{{0x6d00, 0x6700, 0x9000}, {0, 0x80, 0x80}, {true, true, false}, 3, 0, 4, true, 0}, 0},
        {{{0x6700, 0x9000}, {0, 0}, {true, false}, 2, 0, 8, true, 0}, 0},
        {{{0x6d00, 0x6d00}, {0, 0x80}, {true, true}, 2, 0, 8, true, 0}, PM3_EAPDU_FAIL},
        {{{0x6d00}, {0}, {true}, 1, 0, 8, true, PM3_ETIMEOUT}, PM3_ETIMEOUT},
        {{{0x9000}, {0}, {true}, 1, 0, 3, true, 0}, PM3_EWRONGANSWER},
    };
    size_t failures = 0;
    for (size_t i = 0; i < ARRAYLEN(cases); i++) {
        emv_challenge_fixture_t fixture = cases[i].fixture;
        uint8_t response[16];
        size_t length;
        uint16_t sw;
        int res = emv_challenge_exchange(emv_challenge_fixture, &fixture, false,
                                          response, sizeof(response), &length, &sw);
        bool passed = res == cases[i].result && fixture.passed && fixture.calls == fixture.count;
        failures += !passed;
        PrintAndLogEx(passed ? SUCCESS : FAILED, "Challenge test %zu ( %s )", i + 1, passed ? "ok" : "fail");
    }
    PrintAndLogEx(failures ? FAILED : SUCCESS, "Challenge tests: %zu cases, %zu failures", ARRAYLEN(cases), failures);
    return failures ? PM3_ESOFT : PM3_SUCCESS;
}

int EMVInternalAuthenticate(Iso7816CommandChannel channel, bool LeaveFieldON, uint8_t *DDOL, size_t DDOLLen, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw, struct tlvdb *tlv) {
    if (DDOLLen > 0xff || (DDOLLen && !DDOL))
        return PM3_EINVARG;
    return EMVExchangeEx(channel, false, LeaveFieldON, (sAPDU_t) {0x00, 0x88, 0x00, 0x00, DDOLLen, DDOL}, true, Result, MaxResultLen, ResultLen, sw, tlv);
}

int MSCComputeCryptoChecksum(Iso7816CommandChannel channel, bool LeaveFieldON, uint8_t *UDOL, uint8_t UDOLlen, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw, struct tlvdb *tlv) {
    int res = EMVExchangeEx(channel, false, true, (sAPDU_t) {0x80, 0x2a, 0x8e, 0x80, UDOLlen, UDOL}, true, Result, MaxResultLen, ResultLen, sw, tlv);
    if (res == PM3_EAPDU_FAIL && sw && (*sw == 0x6700 || *sw == 0x6f00)) {
        PrintAndLogEx(INFO, ">>> trying to reissue command without Le...");
        res = EMVExchangeEx(channel, false, LeaveFieldON, (sAPDU_t) {0x80, 0x2a, 0x8e, 0x80, UDOLlen, UDOL}, false, Result, MaxResultLen, ResultLen, sw, tlv);
    } else if (!LeaveFieldON)
        DropFieldEx(channel);
    return res;
}

// Authentication
struct emv_pk *get_ca_pk(struct tlvdb *db) {
    const struct tlv *df_tlv = tlvdb_get(db, 0x84, NULL);
    const struct tlv *caidx_tlv = tlvdb_get(db, 0x8f, NULL);

    if (!df_tlv || !caidx_tlv || df_tlv->len < 6 || caidx_tlv->len != 1)
        return NULL;

    PrintAndLogEx(INFO, "CA public key index 0x%0x", caidx_tlv->value[0]);
    return emv_pk_get_ca_pk(df_tlv->value, caidx_tlv->value[0]);
}

int trSDA(struct tlvdb *tlv) {

    struct emv_pk *pk = get_ca_pk(tlv);
    if (!pk) {
        PrintAndLogEx(ERR, "Error: Key not found, exiting");
        return 2;
    }

    struct emv_pk *issuer_pk = emv_pki_recover_issuer_cert(pk, tlv);
    if (!issuer_pk) {
        emv_pk_free(pk);
        PrintAndLogEx(ERR, "Error: Issuer certificate not found, exiting");
        return 2;
    }

    PrintAndLogEx(SUCCESS, "Issuer Public key recovered  RID " _YELLOW_("%s") " IDX " _YELLOW_("%02hhx") " CSN " _YELLOW_("%s"),
                  sprint_hex(issuer_pk->rid, 5),
                  issuer_pk->index,
                  sprint_hex(issuer_pk->serial, 3)
                 );

    const struct tlv *sda_tlv = tlvdb_get(tlv, 0x21, NULL);
    if (!sda_tlv || sda_tlv->len < 1) {
        emv_pk_free(issuer_pk);
        emv_pk_free(pk);
        PrintAndLogEx(WARNING, "Can't find input list for Offline Data Authentication, exiting");
        return 3;
    }

    struct tlvdb *dac_db = emv_pki_recover_dac(issuer_pk, tlv, sda_tlv);
    if (dac_db) {
        const struct tlv *dac_tlv = tlvdb_get(dac_db, 0x9f45, NULL);
        PrintAndLogEx(INFO, "SDA verified ( %s ) (Data Authentication Code: %02hhx:%02hhx)", _GREEN_("ok"), dac_tlv->value[0], dac_tlv->value[1]);
        tlvdb_add(tlv, dac_db);
    } else {
        emv_pk_free(issuer_pk);
        emv_pk_free(pk);
        PrintAndLogEx(ERR, "SSAD verify error");
        return 4;
    }

    emv_pk_free(issuer_pk);
    emv_pk_free(pk);
    return 0;
}

static const unsigned char default_ddol_value[] = {0x9f, 0x37, 0x04};
static struct tlv default_ddol_tlv = {.tag = 0x9f49, .len = 3, .value = default_ddol_value };

int trDDA(Iso7816CommandChannel channel, bool decodeTLV, struct tlvdb *tlv) {
    struct emv_pk *pk = get_ca_pk(tlv);
    if (!pk) {
        PrintAndLogEx(ERR, "Error: Key not found, exiting");
        return 2;
    }

    const struct tlv *sda_tlv = tlvdb_get(tlv, 0x21, NULL);
    /* if (!sda_tlv || sda_tlv->len < 1) { it may be 0!!!!
            emv_pk_free(pk);
            PrintAndLogEx(ERR, "Error: Can't find input list for Offline Data Authentication, exiting");
            return 3;
        }
    */
    struct emv_pk *issuer_pk = emv_pki_recover_issuer_cert(pk, tlv);
    if (!issuer_pk) {
        emv_pk_free(pk);
        PrintAndLogEx(ERR, "Error: Issuer certificate not found, exiting");
        return 2;
    }

    PrintAndLogEx(SUCCESS, "Issuer Public key recovered  RID " _YELLOW_("%s") " IDX " _YELLOW_("%02hhx") " CSN " _YELLOW_("%s"),
                  sprint_hex(issuer_pk->rid, 5),
                  issuer_pk->index,
                  sprint_hex(issuer_pk->serial, 3)
                 );

    struct emv_pk *icc_pk = emv_pki_recover_icc_cert(issuer_pk, tlv, sda_tlv);
    if (!icc_pk) {
        emv_pk_free(pk);
        emv_pk_free(issuer_pk);
        PrintAndLogEx(ERR, "Error: ICC certificate not found, exiting");
        return 2;
    }

    PrintAndLogEx(SUCCESS, "ICC Public key recovered. RID " _YELLOW_("%s") " IDX " _YELLOW_("%02hhx") " CSN " _YELLOW_("%s"),
                  sprint_hex(icc_pk->rid, 5),
                  icc_pk->index,
                  sprint_hex(icc_pk->serial, 3)
                 );

    if (tlvdb_get(tlv, 0x9f2d, NULL)) {
        struct emv_pk *icc_pe_pk = emv_pki_recover_icc_pe_cert(issuer_pk, tlv);
        if (!icc_pe_pk) {
            PrintAndLogEx(WARNING, "WARNING: ICC PE Public key recover error");
        } else {
            PrintAndLogEx(SUCCESS, "ICC PE Public key recovered. RID " _YELLOW_("%s") " IDX " _YELLOW_("%02hhx") " CSN " _YELLOW_("%s"),
                          sprint_hex(icc_pe_pk->rid, 5),
                          icc_pe_pk->index,
                          sprint_hex(icc_pe_pk->serial, 3)
                         );
        }
    } else {
        PrintAndLogEx(INFO, "ICC PE Public Key (PIN Encipherment Public Key Certificate) not found.\n");
    }

    // 9F4B: Signed Dynamic Application Data
    const struct tlv *sdad_tlv = tlvdb_get(tlv, 0x9f4b, NULL);
    // DDA with internal authenticate OR fDDA with filled 0x9F4B tag (GPO result)
    // EMV kernel3 v2.4, contactless book C-3, C.1., page 147
    if (sdad_tlv) {
        PrintAndLogEx(INFO, "* * Got Signed Dynamic Application Data (9F4B) form GPO. Maybe fDDA...");

        struct tlvdb *atc_db = emv_pki_recover_atc_ex(icc_pk, tlv, true);
        if (!atc_db) {
            PrintAndLogEx(ERR, "Error: Can't recover IDN (ICC Dynamic Number)");
            emv_pk_free(pk);
            emv_pk_free(issuer_pk);
            emv_pk_free(icc_pk);
            return 8;
        }

        // 9f36 Application Transaction Counter (ATC)
        const struct tlv *atc_tlv = tlvdb_get(atc_db, 0x9f36, NULL);
        if (atc_tlv) {
            PrintAndLogEx(INFO, "ATC (Application Transaction Counter) [%zu] %s", atc_tlv->len, sprint_hex_inrow(atc_tlv->value, atc_tlv->len));

            const struct tlv *core_atc_tlv = tlvdb_get(tlv, 0x9f36, NULL);
            if (tlv_equal(core_atc_tlv, atc_tlv)) {
                PrintAndLogEx(SUCCESS, "ATC check OK.");
                PrintAndLogEx(SUCCESS, "fDDA (fast DDA) verified OK.");
            } else {
                PrintAndLogEx(WARNING, "Error: fDDA verified, but ATC in the certificate and ATC in the record not the same.");
            }
        } else {
            PrintAndLogEx(WARNING, "ERROR: fDDA (fast DDA) verify error");
            emv_pk_free(pk);
            emv_pk_free(issuer_pk);
            emv_pk_free(icc_pk);
            tlvdb_free(atc_db);
            return 9;
        }
        tlvdb_free(atc_db);

    } else {
        uint8_t buf[APDU_RES_LEN] = {0};
        size_t len = 0;
        uint16_t sw = 0;
        struct tlvdb *dac_db = emv_pki_recover_dac(issuer_pk, tlv, sda_tlv);
        if (dac_db) {
            const struct tlv *dac_tlv = tlvdb_get(dac_db, 0x9f45, NULL);
            PrintAndLogEx(INFO, "SDAD verified ( %s ) (Data Authentication Code: %02hhx:%02hhx)\n", _GREEN_("ok"), dac_tlv->value[0], dac_tlv->value[1]);
            tlvdb_add(tlv, dac_db);
        } else {
            PrintAndLogEx(ERR, "Error: SSAD verify error");
            emv_pk_free(pk);
            emv_pk_free(issuer_pk);
            emv_pk_free(icc_pk);
            return 4;
        }

        PrintAndLogEx(INFO, "* Calc DDOL");
        const struct tlv *ddol_tlv = tlvdb_get(tlv, 0x9f49, NULL);
        if (!ddol_tlv) {
            ddol_tlv = &default_ddol_tlv;
            PrintAndLogEx(INFO, "DDOL [9f49] not found. Using default DDOL");
        }

        struct tlv *ddol_data_tlv = dol_process(ddol_tlv, tlv, 0);
        if (!ddol_data_tlv) {
            PrintAndLogEx(ERR, "Error: Can't create DDOL TLV");
            emv_pk_free(pk);
            emv_pk_free(issuer_pk);
            emv_pk_free(icc_pk);
            return 5;
        }

        PrintAndLogEx(INFO, "DDOL data[%zu]: %s", ddol_data_tlv->len, sprint_hex(ddol_data_tlv->value, ddol_data_tlv->len));

        PrintAndLogEx(INFO, "* Internal Authenticate");
        int res = EMVInternalAuthenticate(channel, true, (uint8_t *)ddol_data_tlv->value, ddol_data_tlv->len, buf, sizeof(buf), &len, &sw, NULL);
        if (res) {
            PrintAndLogEx(ERR, "Internal Authenticate error(%d): %4x, exiting..", res, sw);
            free(ddol_data_tlv);
            emv_pk_free(pk);
            emv_pk_free(issuer_pk);
            emv_pk_free(icc_pk);
            return 6;
        }

        struct tlvdb *dda_db = NULL;
        if (buf[0] == 0x80) {
            if (len < 3) {
                PrintAndLogEx(WARNING, "Warning: Internal Authenticate format1 parsing error. length=%zu", len);
            } else {
                // parse response 0x80
                struct tlvdb *t80 = tlvdb_parse_multi(buf, len);
                const struct tlv *t80tlv = tlvdb_get_tlv(t80);

                // 9f4b Signed Dynamic Application Data
                dda_db = tlvdb_fixed(0x9f4b, t80tlv->len, t80tlv->value);
                tlvdb_add(tlv, dda_db);

                tlvdb_free(t80);

                if (decodeTLV) {
                    PrintAndLogEx(INFO, "* * Decode response format 1:");
                    TLVPrintFromTLV(dda_db);
                }
            }
        } else {
            dda_db = tlvdb_parse_multi(buf, len);
            if (!dda_db) {
                PrintAndLogEx(ERR, "Error: Can't parse Internal Authenticate result as TLV");
                free(ddol_data_tlv);
                emv_pk_free(pk);
                emv_pk_free(issuer_pk);
                emv_pk_free(icc_pk);
                return 7;
            }
            tlvdb_add(tlv, dda_db);

            if (decodeTLV)
                TLVPrintFromTLV(dda_db);
        }

        struct tlvdb *idn_db = emv_pki_recover_idn_ex(icc_pk, dda_db, ddol_data_tlv, true);
        free(ddol_data_tlv);
        if (!idn_db) {
            PrintAndLogEx(ERR, "Error: Can't recover IDN (ICC Dynamic Number)");
            tlvdb_free(dda_db);
            emv_pk_free(pk);
            emv_pk_free(issuer_pk);
            emv_pk_free(icc_pk);
            return 8;
        }
        tlvdb_free(dda_db);

        // 9f4c ICC Dynamic Number
        const struct tlv *idn_tlv = tlvdb_get(idn_db, 0x9f4c, NULL);
        if (idn_tlv) {
            PrintAndLogEx(INFO, "IDN (ICC Dynamic Number) [%zu] %s", idn_tlv->len, sprint_hex_inrow(idn_tlv->value, idn_tlv->len));
            PrintAndLogEx(INFO, "DDA verified OK.");
            tlvdb_add(tlv, idn_db);
            tlvdb_free(idn_db);
        } else {
            PrintAndLogEx(ERR, "DDA verify error");
            tlvdb_free(idn_db);

            emv_pk_free(pk);
            emv_pk_free(issuer_pk);
            emv_pk_free(icc_pk);
            return 9;
        }
    }

    emv_pk_free(pk);
    emv_pk_free(issuer_pk);
    emv_pk_free(icc_pk);
    return 0;
}

int trCDA(struct tlvdb *tlv, struct tlvdb *ac_tlv, struct tlv *pdol_data_tlv, struct tlv *ac_data_tlv) {

    struct emv_pk *pk = get_ca_pk(tlv);
    if (!pk) {
        PrintAndLogEx(ERR, "Error: Key not found, exiting");
        return 2;
    }

    const struct tlv *sda_tlv = tlvdb_get(tlv, 0x21, NULL);
    if (!sda_tlv || sda_tlv->len < 1) {
        PrintAndLogEx(ERR, "Error: Can't find input list for Offline Data Authentication, exiting");
        emv_pk_free(pk);
        return 3;
    }

    struct emv_pk *issuer_pk = emv_pki_recover_issuer_cert(pk, tlv);
    if (!issuer_pk) {
        PrintAndLogEx(ERR, "Error: Issuer certificate not found, exiting");
        emv_pk_free(pk);
        return 2;
    }

    PrintAndLogEx(SUCCESS, "Issuer Public key recovered  RID " _YELLOW_("%s") " IDX " _YELLOW_("%02hhx") " CSN " _YELLOW_("%s"),
                  sprint_hex(issuer_pk->rid, 5),
                  issuer_pk->index,
                  sprint_hex(issuer_pk->serial, 3)
                 );

    struct emv_pk *icc_pk = emv_pki_recover_icc_cert(issuer_pk, tlv, sda_tlv);
    if (!icc_pk) {
        PrintAndLogEx(ERR, "Error: ICC certificate not found, exiting");
        emv_pk_free(pk);
        emv_pk_free(issuer_pk);
        return 2;
    }

    PrintAndLogEx(SUCCESS, "ICC Public key recovered. RID " _YELLOW_("%s") " IDX " _YELLOW_("%02hhx") " CSN " _YELLOW_("%s"),
                  sprint_hex(icc_pk->rid, 5),
                  icc_pk->index,
                  sprint_hex(icc_pk->serial, 3)
                 );

    // Signed Static Application Data (SSAD) check
    const struct tlv *ssad_tlv = tlvdb_get(tlv, 0x93, NULL);
    if (ssad_tlv && ssad_tlv->len > 1) {
        struct tlvdb *dac_db = emv_pki_recover_dac(issuer_pk, tlv, sda_tlv);
        if (dac_db) {
            const struct tlv *dac_tlv = tlvdb_get(dac_db, 0x9f45, NULL);
            PrintAndLogEx(SUCCESS, "Signed Static Application Data (SSAD) verified ( %s ) (%02hhx:%02hhx)", _GREEN_("ok"), dac_tlv->value[0], dac_tlv->value[1]);
            tlvdb_add(tlv, dac_db);
        } else {
            PrintAndLogEx(ERR, "Error: Signed Static Application Data (SSAD) verify error");
            emv_pk_free(pk);
            emv_pk_free(issuer_pk);
            emv_pk_free(icc_pk);
            return 4;
        }
    }

    PrintAndLogEx(INFO, "* * Check Signed Dynamic Application Data (SDAD)");
    struct tlvdb *idn_db = emv_pki_perform_cda_ex(icc_pk, tlv, ac_tlv,
                                                  pdol_data_tlv, // pdol
                                                  ac_data_tlv,   // cdol1
                                                  NULL,          // cdol2
                                                  true);
    if (idn_db) {
        const struct tlv *idn_tlv = tlvdb_get(idn_db, 0x9f4c, NULL);
        PrintAndLogEx(INFO, "IDN (ICC Dynamic Number) [%zu] %s", idn_tlv->len, sprint_hex_inrow(idn_tlv->value, idn_tlv->len));
        PrintAndLogEx(SUCCESS, "CDA verified ( %s )", _GREEN_("ok"));
        tlvdb_add(tlv, idn_db);
    } else {
        PrintAndLogEx(ERR, "ERROR: CDA verify error");
    }

    emv_pk_free(pk);
    emv_pk_free(issuer_pk);
    emv_pk_free(icc_pk);
    return 0;
}

int RecoveryCertificates(struct tlvdb *tlvRoot, json_t *root) {
    struct emv_pk *pk = get_ca_pk(tlvRoot);
    if (!pk) {
        PrintAndLogEx(ERR, "ERROR: Key not found, exiting");
        return 1;
    }

    struct emv_pk *issuer_pk = emv_pki_recover_issuer_cert(pk, tlvRoot);
    if (!issuer_pk) {
        emv_pk_free(pk);
        PrintAndLogEx(WARNING, "WARNING: Issuer certificate not found, exiting");
        return 2;
    }

    PrintAndLogEx(SUCCESS, "Issuer Public key recovered  RID " _YELLOW_("%s") " IDX " _YELLOW_("%02hhx") " CSN " _YELLOW_("%s"),
                  sprint_hex(issuer_pk->rid, 5),
                  issuer_pk->index,
                  sprint_hex(issuer_pk->serial, 3)
                 );

    JsonSaveBufAsHex(root, "$.ApplicationData.RID", issuer_pk->rid, 5);

    char *issuer_pk_c = emv_pk_dump_pk(issuer_pk);
    JsonSaveStr(root, "$.ApplicationData.IssuerPublicKeyDec", issuer_pk_c);
    JsonSaveBufAsHex(root, "$.ApplicationData.IssuerPublicKeyModulus", issuer_pk->modulus, issuer_pk->mlen);
    free(issuer_pk_c);

    const struct tlv *sda_tlv = tlvdb_get(tlvRoot, 0x21, NULL);
    struct emv_pk *icc_pk = emv_pki_recover_icc_cert(issuer_pk, tlvRoot, sda_tlv);
    if (!icc_pk) {
        emv_pk_free(pk);
        emv_pk_free(issuer_pk);
        PrintAndLogEx(WARNING, "WARNING: ICC certificate not found, exiting");
        return 2;
    }

    PrintAndLogEx(SUCCESS, "ICC Public key recovered     RID " _YELLOW_("%s") " IDX " _YELLOW_("%02hhx") " CSN " _YELLOW_("%s"),
                  sprint_hex(icc_pk->rid, 5),
                  icc_pk->index,
                  sprint_hex(icc_pk->serial, 3)
                 );

    char *icc_pk_c = emv_pk_dump_pk(icc_pk);
    JsonSaveStr(root, "$.ApplicationData.ICCPublicKeyDec", icc_pk_c);
    JsonSaveBufAsHex(root, "$.ApplicationData.ICCPublicKeyModulus", icc_pk->modulus, icc_pk->mlen);
    free(icc_pk_c);
    return 0;
}
