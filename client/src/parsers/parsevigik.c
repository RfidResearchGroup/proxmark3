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
// VIGIK PACS parser for MIFARE Classic dumps
//-----------------------------------------------------------------------------

#include "parsevigik.h"

#include <stdlib.h>
#include <ctype.h>              // isdigit
#include <string.h>

#include "commonutil.h"
#include "ui.h"                 // PrintAndLogEx
#include "util.h"
#include "protocols.h"          // MFBLOCK_SIZE
#include "mifare/mad.h"
#include "mifare/mifare4.h"        // mfFirstBlockOfSector
#include "mifare/mifaredefault.h"  // MIFARE_KEY_SIZE
#include "mbedtls/bignum.h"

#define VIGIK_SIG_LEN      128     // RSA 1024, the signature on the card
#define VIGIK_MSG_SLOTS     64     // message byte slots in an ISO 9796-1 block
#define VIGIK_MSG_PAD        8     // leading zero bytes of the signed message


static const vigik_pk_t vigik_rsa_pk[] = {
    {"La Poste Service Universel", 0x07AA, "AB9953CBFCCD9375B6C028ADBAB7584BED15B9CA037FADED9765996F9EA1AB983F3041C90DA3A198804FF90D5D872A96A4988F91F2243B821E01C5021E3ED4E1BA83B7CFECAB0E766D8563164DE0B2412AE4E6EA63804DF5C19C7AA78DC14F608294D732D7C8C67A88C6F84C0F2E3FAFAE34084349E11AB5953AC68729D07715"},
    {"La Poste Service Universel", 0x07AA, "1577D02987C63A95B51AE149430834AEAF3F2E0F4CF8C6887AC6C8D732D79482604FC18DA77A9CC1F54D8063EAE6E42A41B2E04D1663856D760EABECCFB783BAE1D43E1E02C5011E823B24F2918F98A4962A875D0DF94F8098A1A30DC941303F98ABA19E6F996597EDAD7F03CAB915ED4B58B7BAAD28C0B67593CDFCCB5399AB"},

    {"La Poste Autres Services", 0x07AB, "A6D99B8D902893B04F3F8DE56CB6BF24338FEE897C1BCE6DFD4EBD05B7B1A07FD2EB564BB4F7D35DBFE0A42966C2C137AD156E3DAB62904592BCA20C0BC7B8B1E261EF82D53F52D203843566305A49A22062DECC38C2FE3864CAD08E79219487651E2F79F1C9392B48CAFE1BFFAFF4802AE451E7A283E55A4026AD1E82DF1A15"},
    {"La Poste Autres Services", 0x07AB, "151adf821ead26405ae583a2e751e42a80f4afff1bfeca482b39c9f1792f1e65879421798ed0ca6438fec238ccde6220a2495a3066358403d2523fd582ef61e2b1b8c70b0ca2bc92459062ab3d6e15ad37c1c26629a4e0bf5dd3f7b44b56ebd27fa0b1b705bd4efd6dce1b7c89ee8f3324bfb66ce58d3f4fb09328908d9bd9a6"},

    {"France Telecom", 0x07AC, "B35193DBD2F88A21CDCFFF4BF84F7FC036A991A363DCB3E802407A5E5879DC2127EECFC520779E79E911394882482C87D09A88B0711CBC2973B77FFDAE40EA0001F595072708C558B484AB89D02BCBCB971FF1B80371C0BE30CB13661078078BB68EBCCA524B9DD55EBF7D47D9355AFC95511350CC1103A5DEE847868848B235"},
    {"France Telecom", 0x07AC, "35b248888647e8dea50311cc50135195fc5a35d9477dbf5ed59d4b52cabc8eb68b0778106613cb30bec07103b8f11f97cbcb2bd089ab84b458c508270795f50100ea40aefd7fb77329bc1c71b0889ad0872c4882483911e9799e7720c5cfee2721dc79585e7a4002e8b3dc63a391a936c07f4ff84bffcfcd218af8d2db9351b3"},

    {"EDF-GDF", 0x07AD, "C44DBCD92F9DCF42F4902A87335DBB35D2FF530CDB09814CFA1F4B95A1BD018D099BC6AB69F667B4922AE1ED826E72951AA3E0EAAA7D49A695F04F8CDAAE2D18D10D25BD529CBB05ABF070DC7C041EC35C2BA7F58CC4C349983CC6E11A5CBE828FB8ECBC26F08E1094A6B44C8953C8E1BAFD214DF3E69F430A98CCC75C03669D"},
    {"EDF-GDF", 0x07AD, "9d66035cc7cc980a439fe6f34d21fdbae1c853894cb4a694108ef026bcecb88f82be5c1ae1c63c9849c3c48cf5a72b5cc31e047cdc70f0ab05bb9c52bd250dd1182daeda8c4ff095a6497daaeae0a31a95726e82ede12a92b467f669abc69b098d01bda1954b1ffa4c8109db0c53ffd235bb5d33872a90f442cf9d2fd9bc4dc4"},
    {NULL, 0, NULL}
};

const char *vigik_get_service(uint16_t service_code) {
    for (int i = 0; i < ARRAYLEN(vigik_rsa_pk); ++i)
        if (service_code == vigik_rsa_pk[i].code)
            return vigik_rsa_pk[i].desc;

    //No match, return default
    return vigik_rsa_pk[ARRAYLEN(vigik_rsa_pk) - 1].desc;
}


// ISO 9796-1 shadow permutation. Each message byte is stored next to its shadow,
// which is what gives the scheme its redundancy.
static const uint8_t vigik_iso9796_pi[16] = {
    0x0E, 0x03, 0x05, 0x08, 0x09, 0x04, 0x02, 0x0F,
    0x00, 0x0D, 0x0B, 0x06, 0x07, 0x0A, 0x0C, 0x01
};

static uint8_t vigik_shadow(uint8_t b) {
    return (uint8_t)((vigik_iso9796_pi[b >> 4] << 4) | vigik_iso9796_pi[b & 0x0F]);
}

// Recover the message an ISO 9796-1 signature carries, checking the redundancy on
// the way. `sig` is the signature as it sits on the card, `modulus` the public key
// to try. On success msg holds msglen bytes.
//
// Rabin, so v = 2 and squaring the signature gives the block back. Which of the
// four candidates is the block is decided by the format itself: an ISO 9796-1
// block always ends in the nibble 6.
static int vigik_iso9796_recover(const uint8_t *sig, const char *modulus, uint8_t *msg, size_t *msglen) {

    uint8_t n[VIGIK_SIG_LEN] = {0};
    int dl = 0;
    param_gethex_to_eol(modulus, 0, n, sizeof(n), &dl);
    if (dl != VIGIK_SIG_LEN) {
        return PM3_EINVARG;
    }

    uint8_t rev[VIGIK_SIG_LEN] = {0};
    reverse_array_copy(sig, VIGIK_SIG_LEN, rev);

    mbedtls_mpi N, S, E, J, cand, tmp;
    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&S);
    mbedtls_mpi_init(&E);
    mbedtls_mpi_init(&J);
    mbedtls_mpi_init(&cand);
    mbedtls_mpi_init(&tmp);

    mbedtls_mpi_read_binary(&N, n, sizeof(n));
    mbedtls_mpi_read_binary(&S, rev, sizeof(rev));
    mbedtls_mpi_add_int(&E, &E, 2);

    uint8_t f[VIGIK_SIG_LEN] = {0};
    bool got_block = false;

    if (mbedtls_mpi_cmp_mpi(&S, &N) < 0) {

        mbedtls_mpi_exp_mod(&J, &S, &E, &N, NULL);

        for (uint8_t c = 0; c < 4 && got_block == false; c++) {

            switch (c) {
                case 0:
                    mbedtls_mpi_copy(&cand, &J);
                    break;
                case 1:
                    mbedtls_mpi_sub_mpi(&cand, &N, &J);
                    break;
                case 2:
                    mbedtls_mpi_mul_int(&cand, &J, 2);
                    break;
                default:
                    mbedtls_mpi_sub_mpi(&tmp, &N, &J);
                    mbedtls_mpi_mul_int(&cand, &tmp, 2);
                    break;
            }

            if (mbedtls_mpi_bitlen(&cand) > (VIGIK_SIG_LEN * 8)) {
                continue;
            }

            uint8_t low = 0;
            for (uint8_t b = 0; b < 4; b++) {
                low |= (uint8_t)(mbedtls_mpi_get_bit(&cand, b) << b);
            }

            if (low != 0x06) {
                continue;
            }

            if (mbedtls_mpi_write_binary(&cand, f, sizeof(f)) == 0) {
                got_block = true;
            }
        }
    }

    mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&S);
    mbedtls_mpi_free(&E);
    mbedtls_mpi_free(&J);
    mbedtls_mpi_free(&cand);
    mbedtls_mpi_free(&tmp);

    if (got_block == false) {
        return PM3_ESOFT;
    }

    // Every byte pair has to be a message byte next to its shadow. Exactly three
    // are allowed not to be: the leading pair carries the bit that keeps the block
    // below n, one marks how long the message is, and the last holds the forced 6.
    size_t broken[4] = {0};
    size_t brokencnt = 0;
    for (size_t i = 0; i < VIGIK_SIG_LEN; i += 2) {
        if (vigik_shadow(f[i + 1]) != f[i]) {
            if (brokencnt < ARRAYLEN(broken)) {
                broken[brokencnt] = i;
            }
            brokencnt++;
        }
    }

    if (brokencnt != 3 || broken[0] != 0 || broken[2] != (VIGIK_SIG_LEN - 2)) {
        return PM3_ESOFT;
    }

    size_t z = VIGIK_MSG_SLOTS - (broken[1] / 2);
    if (z == 0 || z > (VIGIK_MSG_SLOTS - 1)) {
        return PM3_ESOFT;
    }

    uint8_t stream[VIGIK_MSG_SLOTS] = {0};
    for (size_t i = 0; i < VIGIK_SIG_LEN; i += 2) {
        stream[i / 2] = f[i + 1];
    }

    // The message is repeated to fill the block, the first slot belonging to the
    // truncated tail of the run before it. Where a second copy fits, it has to
    // agree with the first.
    if (((1 + (2 * z)) <= VIGIK_MSG_SLOTS) && (memcmp(stream + 1, stream + 1 + z, z) != 0)) {
        return PM3_ESOFT;
    }

    reverse_array_copy(stream + 1, (int)z, msg);
    *msglen = z;
    return PM3_SUCCESS;
}

// The five byte dates are year since 1900, then month, day, hour, minute.
// Print the raw bytes with the date spelled out beside them, and leave the
// decoded form off when the bytes cannot be a date at all.
static void vigik_print_date(const char *label, const uint8_t *v) {

    bool sane = ((v[1] >= 1) && (v[1] <= 12) &&
                 (v[2] >= 1) && (v[2] <= 31) &&
                 (v[3] <= 23) && (v[4] <= 59));

    if (sane) {
        PrintAndLogEx(INFO, "%s %s ( " _YELLOW_("%04u-%02u-%02u %02u:%02u") " )",
                      label, sprint_hex_inrow(v, 5),
                      1900 + v[0], v[1], v[2], v[3], v[4]);
    } else {
        PrintAndLogEx(INFO, "%s %s", label, sprint_hex_inrow(v, 5));
    }
}

// What a VIGIK signature covers: the UID the card has to keep, the service it
// belongs to, and the window it is good for.
static size_t vigik_expected_msg(const mfc_vigik_t *d, uint8_t *out) {

    size_t len = 0;
    memset(out, 0, VIGIK_MSG_PAD);
    len += VIGIK_MSG_PAD;

    memcpy(out + len, d->b0, 4);                // UID
    len += 4;

    Uint4byteToMemLe(out + len, d->service_code);
    len += 4;

    out[len++] = d->key_version;
    out[len++] = d->services_counter;

    memcpy(out + len, d->slot_access_date, sizeof(d->slot_access_date));
    len += sizeof(d->slot_access_date);

    Uint2byteToMemLe(out + len, d->slot_dst_duration);
    len += 2;
    return len;
}

int vigik_verify(mfc_vigik_t *d) {

    if (d == NULL) {
        return PM3_EINVARG;
    }

    uint8_t expected[VIGIK_MSG_SLOTS] = {0};
    size_t expectedlen = vigik_expected_msg(d, expected);

    for (uint8_t i = 0; i < ARRAYLEN(vigik_rsa_pk); i++) {

        if (vigik_rsa_pk[i].desc == NULL) {
            break;
        }

        uint8_t msg[VIGIK_MSG_SLOTS] = {0};
        size_t msglen = 0;
        if (vigik_iso9796_recover(d->rsa_signature, vigik_rsa_pk[i].n, msg, &msglen) != PM3_SUCCESS) {
            continue;
        }

        PrintAndLogEx(INFO, "--- " _CYAN_("Signature") " ------------------------------");
        PrintAndLogEx(INFO, "Signed by.......... " _YELLOW_("%s"), vigik_rsa_pk[i].desc);
        PrintAndLogEx(INFO, "Scheme............. ISO 9796-1, RSA 1024, v=2");
        PrintAndLogEx(INFO, "Recovered.......... %s", sprint_hex_inrow(msg, msglen));

        if ((msglen != expectedlen) || (memcmp(msg, expected, msglen) != 0)) {
            PrintAndLogEx(INFO, "Card fields........ %s", sprint_hex_inrow(expected, expectedlen));
            PrintAndLogEx(FAILED, "Signature verification: " _RED_("card data does not match the signature"));
            return PM3_ESOFT;
        }

        PrintAndLogEx(INFO, "  UID.............. %s", sprint_hex_inrow(msg + VIGIK_MSG_PAD, 4));
        PrintAndLogEx(INFO, "  Service code..... 0x%04X", (uint16_t)d->service_code);
        PrintAndLogEx(INFO, "  Key version...... %u", d->key_version);
        PrintAndLogEx(INFO, "  Services counter. %u", d->services_counter);
        vigik_print_date("  Access date......", d->slot_access_date);
        PrintAndLogEx(INFO, "  DST duration..... %u", d->slot_dst_duration);

        // The service code on the card says which service issued it, so it should
        // name the key that just verified. Where it does not, the table pairs a
        // description with the wrong modulus - say so rather than quietly
        // reporting the wrong issuer.
        if (vigik_rsa_pk[i].code != (uint16_t)d->service_code) {
            PrintAndLogEx(WARNING, "Card says service 0x%04X but the key that verified is listed as 0x%04X ( %s )",
                          (uint16_t)d->service_code, vigik_rsa_pk[i].code, vigik_rsa_pk[i].desc);
        }

        PrintAndLogEx(SUCCESS, "Signature verification: " _GREEN_("successful"));
        return PM3_SUCCESS;
    }

    PrintAndLogEx(FAILED, "Signature verification: " _RED_("no public key recovered a valid block"));
    return PM3_ESOFT;
}

// An expired VIGIK service badge, published for study in
// armsrc/Standalone/hf_colin.c. Signed by La Poste Service Universel.
static const uint8_t vigik_selftest_card[] = {
    0x12, 0x1C, 0x7F, 0x73, 0x02, 0x08, 0x04, 0x00, 0x01, 0xFA, 0x33, 0xF5,
    0xCB, 0x2D, 0x02, 0x1D, 0x44, 0x00, 0x10, 0x49, 0x16, 0x49, 0x16, 0x49,
    0x16, 0x49, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x0F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xAA, 0x07, 0x00, 0x00, 0x21, 0x02, 0x08, 0x00,
    0x00, 0x74, 0x0C, 0x11, 0x06, 0x00, 0xAF, 0x13, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x01, 0x74, 0x0C, 0x11, 0x08, 0x22, 0x00, 0x00,
    0x24, 0xE5, 0x72, 0xB9, 0x23, 0xA3, 0xD2, 0x43, 0xB4, 0x02, 0xD6, 0x0C,
    0xAB, 0x57, 0x69, 0x56, 0x21, 0x6D, 0x65, 0x01, 0xFC, 0x86, 0x18, 0xB6,
    0xC4, 0x26, 0x76, 0x25, 0x11, 0xAC, 0x2D, 0xEE, 0x25, 0xBF, 0x4C, 0xEC,
    0x36, 0x18, 0xD0, 0xBA, 0xB3, 0xA6, 0xE9, 0x21, 0x0D, 0x88, 0x77, 0x46,
    0x0F, 0xBC, 0x41, 0xA5, 0xD9, 0x53, 0x98, 0xE7, 0x6A, 0x1B, 0x20, 0x29,
    0xE8, 0xEA, 0x97, 0x35, 0x08, 0x8B, 0xA2, 0xCE, 0x73, 0x26, 0x53, 0xD0,
    0xC1, 0x14, 0x75, 0x96, 0xAF, 0xCF, 0x94, 0xD7, 0x77, 0xB4, 0xD9, 0x1F,
    0x04, 0x42, 0x18, 0x22, 0x73, 0xA2, 0x9D, 0xEA, 0xF7, 0xA2, 0xD0, 0x95,
    0x4C, 0xEE, 0x71, 0x58, 0x66, 0xE5, 0x08, 0xCD, 0xBC, 0x95, 0xC6, 0x40,
    0xEC, 0x9D, 0x1E, 0x58, 0xE8, 0x00, 0x45, 0x7C, 0xF8, 0xB0, 0x79, 0x41,
    0x4E, 0x1B, 0x45, 0xDD, 0x3E, 0x6C, 0x93, 0x17,
};

int vigik_selftest(void) {

    PrintAndLogEx(INFO, "Testing VIGIK ISO 9796-1 signature recovery");

    if (sizeof(vigik_selftest_card) != sizeof(mfc_vigik_t)) {
        PrintAndLogEx(FAILED, "  vector is %zu bytes, struct is %zu ( " _RED_("fail") " )",
                      sizeof(vigik_selftest_card), sizeof(mfc_vigik_t));
        return PM3_ESOFT;
    }

    mfc_vigik_t card;
    memcpy(&card, vigik_selftest_card, sizeof(card));

    uint8_t expected[VIGIK_MSG_SLOTS] = {0};
    size_t expectedlen = vigik_expected_msg(&card, expected);

    uint8_t msg[VIGIK_MSG_SLOTS] = {0};
    size_t msglen = 0;
    int res = PM3_ESOFT;

    for (uint8_t i = 0; i < ARRAYLEN(vigik_rsa_pk); i++) {
        if (vigik_rsa_pk[i].desc == NULL) {
            break;
        }
        if (vigik_iso9796_recover(card.rsa_signature, vigik_rsa_pk[i].n, msg, &msglen) == PM3_SUCCESS) {
            PrintAndLogEx(INFO, "  recovered against.. %s", vigik_rsa_pk[i].desc);
            res = PM3_SUCCESS;
            break;
        }
    }

    if (res != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "  no public key recovered a valid block ( " _RED_("fail") " )");
        return PM3_ESOFT;
    }

    PrintAndLogEx(INFO, "  recovered.......... %s", sprint_hex_inrow(msg, msglen));
    PrintAndLogEx(INFO, "  card fields........ %s", sprint_hex_inrow(expected, expectedlen));

    if ((msglen != expectedlen) || (memcmp(msg, expected, msglen) != 0)) {
        PrintAndLogEx(FAILED, "  recovered message does not match the card ( " _RED_("fail") " )");
        return PM3_ESOFT;
    }

    PrintAndLogEx(SUCCESS, "VIGIK signature selftest ( " _GREEN_("ok") " )");
    return PM3_SUCCESS;
}

int vigik_annotate(mfc_vigik_t *d) {
    if (d == NULL)
        return PM3_EINVARG;

    PrintAndLogEx(INFO, "Manufacture......... %s", sprint_hex_inrow(d->b0, sizeof(d->b0)));
    PrintAndLogEx(INFO, "MAD................. %s", sprint_hex_inrow(d->mad, sizeof(d->mad)));
    PrintAndLogEx(INFO, "Counters............ %u", d->counters);
    PrintAndLogEx(INFO, "rtf................. %s", sprint_hex_inrow(d->rtf, sizeof(d->rtf)));
    PrintAndLogEx(INFO, "Service code........ 0x%08x / %u  - " _YELLOW_("%s"), d->service_code, d->service_code, vigik_get_service(d->service_code));
    PrintAndLogEx(INFO, "Info flag........... %u -", d->info_flag); // ,  sprint_bin(d->info_flag, 1));
    PrintAndLogEx(INFO, "Key version......... %u", d->key_version);
    PrintAndLogEx(INFO, "PTR Counter......... %u", d->ptr_counter);
    PrintAndLogEx(INFO, "Counter num......... %u", d->counter_num);
    vigik_print_date("Slot access date....", d->slot_access_date);
    PrintAndLogEx(INFO, "Slot dst duration... %u", d->slot_dst_duration);
    PrintAndLogEx(INFO, "Other Slots......... %s", sprint_hex_inrow(d->other_slots, sizeof(d->other_slots)));
    PrintAndLogEx(INFO, "Services counter.... %u", d->services_counter);
    vigik_print_date("Loading date........", d->loading_date);
    PrintAndLogEx(INFO, "Reserved null....... %u", d->reserved_null);
    PrintAndLogEx(INFO, "----------------------------------------------------------------");
    PrintAndLogEx(INFO, "");
    vigik_verify(d);
    PrintAndLogEx(INFO, "----------------------------------------------------------------");
    PrintAndLogEx(INFO, "");
    return PM3_SUCCESS;

}

typedef struct vigik_schema_s {
    const char *name;
    uint64_t key_a[16];
    uint64_t key_b[16];
    int (*decode)(const uint8_t *dump, size_t dumplen);
} vigik_schema_t;

static int vigik_print_urmet_captiv(const uint8_t *dump, size_t dumplen);

static const vigik_schema_t vigik_schemas[] = {
    {
        "Noralsy",
        {
            0x414c41524f4eULL, 0x414c41524f4eULL, 0x414c41524f4eULL, 0x414c41524f4eULL,
            0x414c41524f4eULL, 0x414c41524f4eULL, 0x414c41524f4eULL, 0x414c41524f4eULL,
            0x414c41524f4eULL, 0x414c41524f4eULL, 0x414c41524f4eULL, 0x414c41524f4eULL,
            0x414c41524f4eULL, 0x414c41524f4eULL, 0x414c41524f4eULL, 0x414c41524f4eULL
        },
        {
            0x424c41524f4eULL, 0x424c41524f4eULL, 0x424c41524f4eULL, 0x424c41524f4eULL,
            0x424c41524f4eULL, 0x424c41524f4eULL, 0x424c41524f4eULL, 0x424c41524f4eULL,
            0x424c41524f4eULL, 0x424c41524f4eULL, 0x424c41524f4eULL, 0x424c41524f4eULL,
            0x424c41524f4eULL, 0x424c41524f4eULL, 0x424c41524f4eULL, 0x424c41524f4eULL
        },
        NULL
    },
    {
        "Urmet Captiv",
        {
            0x8829da9daf76ULL, 0x8829da9daf76ULL, 0x8829da9daf76ULL, 0x8829da9daf76ULL,
            0x8829da9daf76ULL, 0x8829da9daf76ULL, 0x8829da9daf76ULL, 0x8829da9daf76ULL,
            0x8829da9daf76ULL, 0x8829da9daf76ULL, 0x8829da9daf76ULL, 0x8829da9daf76ULL,
            0x8829da9daf76ULL, 0x8829da9daf76ULL, 0x8829da9daf76ULL, 0x8829da9daf76ULL
        },
        {
            0x8829da9daf76ULL, 0x8829da9daf76ULL, 0x8829da9daf76ULL, 0x8829da9daf76ULL,
            0x8829da9daf76ULL, 0x8829da9daf76ULL, 0x8829da9daf76ULL, 0x8829da9daf76ULL,
            0x8829da9daf76ULL, 0x8829da9daf76ULL, 0x8829da9daf76ULL, 0x8829da9daf76ULL,
            0x8829da9daf76ULL, 0x8829da9daf76ULL, 0x8829da9daf76ULL, 0x8829da9daf76ULL
        },
        vigik_print_urmet_captiv
    },
    {
        "VIGIK service badge",
        {
            0xa0a1a2a3a4a5ULL, 0x314b49474956ULL, 0x314b49474956ULL, 0x314b49474956ULL,
            0x314b49474956ULL, VIGIK_KEY_ANY, VIGIK_KEY_ANY, VIGIK_KEY_ANY,
            VIGIK_KEY_ANY, VIGIK_KEY_ANY, VIGIK_KEY_ANY, VIGIK_KEY_ANY,
            VIGIK_KEY_ANY, VIGIK_KEY_ANY, VIGIK_KEY_ANY, VIGIK_KEY_ANY
        },
        {
            VIGIK_KEY_ANY, VIGIK_KEY_ANY, VIGIK_KEY_ANY, VIGIK_KEY_ANY,
            VIGIK_KEY_ANY, VIGIK_KEY_ANY, VIGIK_KEY_ANY, VIGIK_KEY_ANY,
            VIGIK_KEY_ANY, VIGIK_KEY_ANY, VIGIK_KEY_ANY, VIGIK_KEY_ANY,
            VIGIK_KEY_ANY, VIGIK_KEY_ANY, VIGIK_KEY_ANY, VIGIK_KEY_ANY
        },
        NULL
    },
};

// Key A or key B out of a sector trailer, VIGIK_KEY_ANY when the dump is short
static uint64_t vigik_sector_key(const uint8_t *dump, size_t dumplen, uint8_t sector, bool keyb) {
    size_t trailer = (mfFirstBlockOfSector(sector) + mfNumBlocksPerSector(sector) - 1) * MFBLOCK_SIZE;
    if (trailer + MFBLOCK_SIZE > dumplen) {
        return VIGIK_KEY_ANY;
    }
    const uint8_t *p = dump + trailer + (keyb ? 10 : 0);
    uint64_t key = 0;
    for (uint8_t i = 0; i < MIFARE_KEY_SIZE; i++) {
        key = (key << 8) | p[i];
    }
    return key;
}

static const vigik_schema_t *vigik_detect_schema_entry(const uint8_t *dump, size_t dumplen) {

    if (dump == NULL) {
        return NULL;
    }

    for (size_t i = 0; i < ARRAYLEN(vigik_schemas); i++) {

        const vigik_schema_t *schema = &vigik_schemas[i];
        bool match = true;

        for (uint8_t s = 0; s < 16 && match; s++) {

            if ((schema->key_a[s] != VIGIK_KEY_ANY) && (schema->key_a[s] != vigik_sector_key(dump, dumplen, s, false))) {
                match = false;
            }

            if ((schema->key_b[s] != VIGIK_KEY_ANY) && (schema->key_b[s] != vigik_sector_key(dump, dumplen, s, true))) {
                match = false;
            }
        }

        if (match) {
            return schema;
        }
    }
    return NULL;
}

const char *vigik_detect_schema(const uint8_t *dump, size_t dumplen) {
    const vigik_schema_t *schema = vigik_detect_schema_entry(dump, dumplen);
    return (schema != NULL) ? schema->name : NULL;
}

// --------------------------------------------------------------- Urmet Captiv
#define URMET_DIGITS_OFF    5
#define URMET_DIGITS_LEN    11

static bool urmet_all_digits(const uint8_t *p, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (isdigit(p[i]) == 0) {
            return false;
        }
    }
    return true;
}

static int vigik_print_urmet_captiv(const uint8_t *dump, size_t dumplen) {

    if (dumplen < MFBLOCK_SIZE * 3) {
        return PM3_EINVARG;
    }

    const uint8_t *b1 = dump + MFBLOCK_SIZE;
    const uint8_t *b2 = dump + (2 * MFBLOCK_SIZE);

    PrintAndLogEx(INFO, "Header............. %s", sprint_hex_inrow(b1, URMET_DIGITS_OFF));

    if (urmet_all_digits(b1 + URMET_DIGITS_OFF, URMET_DIGITS_LEN)) {
        char num[URMET_DIGITS_LEN + 1] = {0};
        memcpy(num, b1 + URMET_DIGITS_OFF, URMET_DIGITS_LEN);
        PrintAndLogEx(INFO, "Number............. " _YELLOW_("%s") "%s"
                    , num
                    , (strspn(num, "0") == URMET_DIGITS_LEN) ? "  ( all zero, unset )" : ""
                );
    } else {
        PrintAndLogEx(INFO, "Number............. %s  ( not ASCII digits )", sprint_hex_inrow(b1 + URMET_DIGITS_OFF, URMET_DIGITS_LEN));
    }

    PrintAndLogEx(INFO, "Marker............. %s", sprint_hex_inrow(b2, 2));
    PrintAndLogEx(INFO, "Data............... layout " _YELLOW_("not decoded"));

    int shown = 0;
    for (uint8_t s = 1; s < 16; s++) {

        for (uint8_t b = 0; b < 3; b++) {

            size_t off = (mfFirstBlockOfSector(s) + b) * MFBLOCK_SIZE;
            if (off + MFBLOCK_SIZE > dumplen) {
                continue;
            }

            const uint8_t *p = dump + off;
            bool empty = true;
            for (uint8_t k = 0; k < MFBLOCK_SIZE; k++) {
                if (p[k]) {
                    empty = false;
                    break;
                }
            }
            if (empty == false) {
                PrintAndLogEx(INFO, "  sector %2u blk %u.. %s", s, b, sprint_hex_inrow(p, MFBLOCK_SIZE));
                shown++;
            }
        }
    }

    if (shown == 0) {
        PrintAndLogEx(INFO, "  every sector past 0 is empty, card not personalised");
    }

    PrintAndLogEx(INFO, "Keys............... one key r/w every block");
    return PM3_SUCCESS;
}

bool is_valid_vigik_card(const uint8_t *dump, size_t dumplen) {
    if (dump == NULL || dumplen < sizeof(mad1_sector_t)) {
        return false;
    }
    if (DetectHID((const mad1_sector_t *)dump, VIGIK_MAD_AID) > -1) {
        return true;
    }
    return (vigik_detect_schema(dump, dumplen) != NULL);
}

int vigik_parser_parse(const uint8_t *dump, size_t dumplen) {

    if (is_valid_vigik_card(dump, dumplen) == false) {
        return PM3_EINVARG;
    }

    const mad1_sector_t *s0 = (const mad1_sector_t *)dump;

    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, _CYAN_("VIGIK PACS detected"));

    const char *schema = vigik_detect_schema(dump, dumplen);
    if (schema != NULL) {
        PrintAndLogEx(SUCCESS, "System............. " _YELLOW_("%s"), schema);
    }

    if (DetectHID(s0, VIGIK_MAD_AID) < 0) {
        const vigik_schema_t *entry = vigik_detect_schema_entry(dump, dumplen);
        if (entry != NULL && entry->decode != NULL) {
            return entry->decode(dump, dumplen);
        }
        PrintAndLogEx(INFO, "No MAD on this card, structure " _YELLOW_("not decoded"));
        return PM3_SUCCESS;
    }

    mad_entry_list_t mad_list = {0};
    int res = MADDecode(s0, NULL, &mad_list, false, true);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "can't decode MAD");
        return res;
    }

    union {
        uint8_t *bytes;
        mfc_vigik_t *vigik;
    } d;

    d.bytes = calloc(dumplen, sizeof(uint8_t));
    if (d.bytes == NULL) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        return PM3_EMALLOC;
    }

    uint16_t dlen = 0;
    memcpy(d.bytes + dlen, dump, MFBLOCK_SIZE * 3);
    dlen += MFBLOCK_SIZE * 3;

    for (size_t i = 0; i < mad_list.len; i++) {

        if (VIGIK_MAD_AID == mad_list.entries[i].aid || VIGIK_MAD_AID_ALT == mad_list.entries[i].aid) {

            uint32_t offset = mad_list.entries[i].sector * MFBLOCK_SIZE * 4;

            if (offset + (MFBLOCK_SIZE * 3) > dumplen) {
                continue;
            }
            memcpy(d.bytes + dlen, dump + offset, MFBLOCK_SIZE * 3);
            dlen += MFBLOCK_SIZE * 3;
        }
    }

    vigik_annotate(d.vigik);
    free(d.bytes);
    return PM3_SUCCESS;
}
