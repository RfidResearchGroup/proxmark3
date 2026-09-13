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
#include <string.h>

#include "commonutil.h"
#include "ui.h"                 // PrintAndLogEx
#include "util.h"
#include "protocols.h"          // MFBLOCK_SIZE
#include "mifare/mad.h"
#include "mifare/mifare4.h"        // mfFirstBlockOfSector
#include "mifare/mifaredefault.h"  // MIFARE_KEY_SIZE
#include "mbedtls/bignum.h"

static const vigik_pk_t vigik_rsa_pk[] = {
    {"La Poste Service Universel", 0x07AA, "AB9953CBFCCD9375B6C028ADBAB7584BED15B9CA037FADED9765996F9EA1AB983F3041C90DA3A198804FF90D5D872A96A4988F91F2243B821E01C5021E3ED4E1BA83B7CFECAB0E766D8563164DE0B2412AE4E6EA63804DF5C19C7AA78DC14F608294D732D7C8C67A88C6F84C0F2E3FAFAE34084349E11AB5953AC68729D07715"},
    {"La Poste Service Universel", 0x07AA, "1577D02987C63A95B51AE149430834AEAF3F2E0F4CF8C6887AC6C8D732D79482604FC18DA77A9CC1F54D8063EAE6E42A41B2E04D1663856D760EABECCFB783BAE1D43E1E02C5011E823B24F2918F98A4962A875D0DF94F8098A1A30DC941303F98ABA19E6F996597EDAD7F03CAB915ED4B58B7BAAD28C0B67593CDFCCB5399AB"},

    {"La Poste Autres Services", 0x07AB, "A6D99B8D902893B04F3F8DE56CB6BF24338FEE897C1BCE6DFD4EBD05B7B1A07FD2EB564BB4F7D35DBFE0A42966C2C137AD156E3DAB62904592BCA20C0BC7B8B1E261EF82D53F52D203843566305A49A22062DECC38C2FE3864CAD08E79219487651E2F79F1C9392B48CAFE1BFFAFF4802AE451E7A283E55A4026AD1E82DF1A15"},
    {"La Poste Autres Services", 0x07AB, "151adf821ead26405ae583a2e751e42a80f4afff1bfeca482b39c9f1792f1e65879421798ed0ca6438fec238ccde6220a2495a3066358403d2523fd582ef61e2b1b8c70b0ca2bc92459062ab3d6e15ad37c1c26629a4e0bf5dd3f7b44b56ebd27fa0b1b705bd4efd6dce1b7c89ee8f3324bfb66ce58d3f4fb09328908d9bd9a6"},

    {"France Telecom", 0x07AC, "C44DBCD92F9DCF42F4902A87335DBB35D2FF530CDB09814CFA1F4B95A1BD018D099BC6AB69F667B4922AE1ED826E72951AA3E0EAAA7D49A695F04F8CDAAE2D18D10D25BD529CBB05ABF070DC7C041EC35C2BA7F58CC4C349983CC6E11A5CBE828FB8ECBC26F08E1094A6B44C8953C8E1BAFD214DF3E69F430A98CCC75C03669D"},
    {"France Telecom", 0x07AC, "9d66035cc7cc980a439fe6f34d21fdbae1c853894cb4a694108ef026bcecb88f82be5c1ae1c63c9849c3c48cf5a72b5cc31e047cdc70f0ab05bb9c52bd250dd1182daeda8c4ff095a6497daaeae0a31a95726e82ede12a92b467f669abc69b098d01bda1954b1ffa4c8109db0c53ffd235bb5d33872a90f442cf9d2fd9bc4dc4"},

    {"EDF-GDF", 0x07AD, "B35193DBD2F88A21CDCFFF4BF84F7FC036A991A363DCB3E802407A5E5879DC2127EECFC520779E79E911394882482C87D09A88B0711CBC2973B77FFDAE40EA0001F595072708C558B484AB89D02BCBCB971FF1B80371C0BE30CB13661078078BB68EBCCA524B9DD55EBF7D47D9355AFC95511350CC1103A5DEE847868848B235"},
    {"EDF-GDF", 0x07AD, "35b248888647e8dea50311cc50135195fc5a35d9477dbf5ed59d4b52cabc8eb68b0778106613cb30bec07103b8f11f97cbcb2bd089ab84b458c508270795f50100ea40aefd7fb77329bc1c71b0889ad0872c4882483911e9799e7720c5cfee2721dc79585e7a4002e8b3dc63a391a936c07f4ff84bffcfcd218af8d2db9351b3"},
    {NULL, 0, NULL}
};

const char *vigik_get_service(uint16_t service_code) {
    for (int i = 0; i < ARRAYLEN(vigik_rsa_pk); ++i)
        if (service_code == vigik_rsa_pk[i].code)
            return vigik_rsa_pk[i].desc;

    //No match, return default
    return vigik_rsa_pk[ARRAYLEN(vigik_rsa_pk) - 1].desc;
}


int vigik_verify(mfc_vigik_t *d) {
#define PUBLIC_VIGIK_KEYLEN 128

    // iso9796
    // Exponent V = 2
    // n = The public modulus n is the product of the secret prime factors p and q. Its length is 1024 bits.

    if (g_debugMode == DEBUG) {
        PrintAndLogEx(INFO, "Raw");
        print_hex_noascii_break((uint8_t *)d, sizeof(*d) - sizeof(d->rsa_signature), MFBLOCK_SIZE * 2);

        PrintAndLogEx(INFO, "Raw signature");
        print_hex_noascii_break(d->rsa_signature, sizeof(d->rsa_signature), MFBLOCK_SIZE * 2);
    }

    /*
        int dl = 0;

            param_gethex_to_eol("1C07D46DA3849326D24B3468BD76673F4F3C41827DC413E81E4F3C7804FAC727213059B21D047510D6432448643A92EBFC67FBEDDAB468D13D948B172F5EBC79A0E3FEFDFAF4E81FC7108E070F1E3CD0", 0, signature, PUBLIC_VIGIK_KEYLEN, &dl);

        param_gethex_to_eol("1AB86FE0C17FFFFE4379D5E15A4B2FAFFEFCFA0F1F3F7FA03E7DDDF1E3C78FFFB1F0E23F7FFF51584771C5C18307FEA36CA74E60AA6B0409ACA66A9EC155F4E9112345708A2B8457E722608EE1157408", 0, signature, PUBLIC_VIGIK_KEYLEN, &dl);
        signature_len = dl;
        */

    uint8_t rev_sig[128];
    reverse_array_copy(d->rsa_signature, sizeof(d->rsa_signature), rev_sig);

    PrintAndLogEx(INFO, "Raw signature reverse");
    print_hex_noascii_break(rev_sig, sizeof(d->rsa_signature), MFBLOCK_SIZE * 2);

    // t = 0xBC  = Implicitly known
    // t = 0xCC  = look at byte before to determine hash function
    // uint8_t T[] = {0x33, 0xCC};

    // Success decrypt would mean  0x4b BB ... BB BA padding
    // padding, message,  hash, 8 bits or 16 bits

    // signature = h( C || M1 || h(M2) )
    // 1024 - 786 - 160 - 16 -1
    // salt C
    // message M = 96 bytes,  768 bits
    // sha1 hash H = 20 bytes, 160 bits
    // padding = 20 bytes, 96 bits

    uint8_t i;
    bool is_valid = false;

    for (i = 0; i < ARRAYLEN(vigik_rsa_pk); i++) {
        if (vigik_rsa_pk[i].desc == NULL) {
            break;
        }

        mbedtls_mpi RN, E;
        mbedtls_mpi_init(&RN);

        // exponent 2 = even
        mbedtls_mpi_init(&E);
        mbedtls_mpi_add_int(&E, &E, 2);

        int dl = 0;
        uint8_t n[PUBLIC_VIGIK_KEYLEN];
        memset(n, 0, sizeof(n));
        param_gethex_to_eol(vigik_rsa_pk[i].n, 0, n, PUBLIC_VIGIK_KEYLEN, &dl);

        // convert
        mbedtls_mpi N, s, sqr, res;
        mbedtls_mpi_init(&N);
        mbedtls_mpi_init(&s);
        mbedtls_mpi_init(&sqr);
        mbedtls_mpi_init(&res);

        mbedtls_mpi_read_binary(&N, (const unsigned char *)n, PUBLIC_VIGIK_KEYLEN);

        //mbedtls_mpi_read_binary(&s, (const unsigned char*)signature, signature_len);
        mbedtls_mpi_read_binary(&s, (const unsigned char *)rev_sig, sizeof(d->rsa_signature));

        // check is sign < (N/2)

        mbedtls_mpi n_2;
        mbedtls_mpi_init(&n_2);
        mbedtls_mpi_copy(&n_2, &N);
        mbedtls_mpi_shift_r(&n_2, 1);
        bool is_less = (mbedtls_mpi_cmp_mpi(&s, &n_2) > 0) ? false : true;
        PrintAndLogEx(DEBUG, "z < (N/2) ..... %s", (is_less) ? _GREEN_("YES") : _RED_("NO"));
        mbedtls_mpi_free(&n_2);


        if (is_less) {
            mbedtls_mpi_exp_mod(&sqr, &s, &E, &N, &RN);
        } else {
            continue;
        }

        /*
            if v is even and
            ⎯ if J* mod 8 = 1, then f* = n–J*.
            ⎯ if J* mod 8 = 4, then f* = J*,
            ⎯ if J* mod 8 = 6, then f* = 2J*,
            ⎯ if J* mod 8 = 7, then f* = 2(n–J*),
        */
        uint8_t b2 = mbedtls_mpi_get_bit(&sqr, 2);
        uint8_t b1 = mbedtls_mpi_get_bit(&sqr, 1);
        uint8_t b0 = mbedtls_mpi_get_bit(&sqr, 0);
        uint8_t lsb = (b2 << 2) | (b1 << 1) | b0;

        /*
        //1
        mbedtls_mpi_sub_mpi(&res, &N, &sqr);
        mbedtls_mpi_write_file( "[=] 1... ", &res, 16, NULL );
        // 4
        mbedtls_mpi_copy(&res, &sqr);
        mbedtls_mpi_write_file( "[=] 4... ", &res, 16, NULL );
        // 6
        mbedtls_mpi_mul_int(&res, &sqr, 2);
        mbedtls_mpi_write_file( "[=] 6... ", &res, 16, NULL );
        // 7
        mbedtls_mpi foo;
        mbedtls_mpi_init(&foo);
        mbedtls_mpi_sub_mpi(&foo, &N, &sqr);
        mbedtls_mpi_mul_int(&res, &foo, 2);
        mbedtls_mpi_free(&foo);
        mbedtls_mpi_write_file( "[=] 7... ", &res, 16, NULL );
        */

        switch (lsb) {
            case 1: {
                mbedtls_mpi_sub_mpi(&res, &N, &sqr);
                break;
            }
            case 4: {
                mbedtls_mpi_copy(&res, &sqr);
                break;
            }
            case 6: {
                mbedtls_mpi_mul_int(&res, &sqr, 2);
                break;
            }
            case 7: {
                mbedtls_mpi foo2;
                mbedtls_mpi_init(&foo2);
                mbedtls_mpi_sub_mpi(&foo2, &N, &sqr);
                mbedtls_mpi_mul_int(&res, &foo2, 2);
                mbedtls_mpi_free(&foo2);
                break;
            }
            default: {
                continue;
            }
        }

        PrintAndLogEx(DEBUG, "LSB............ " _GREEN_("%u"), lsb);
        if (g_debugMode == DEBUG) {
            mbedtls_mpi_write_file("[=] N.............. ", &N, 16, NULL);
            mbedtls_mpi_write_file("[=] signature...... ", &s, 16, NULL);
            mbedtls_mpi_write_file("[=] square mod n... ", &sqr, 16, NULL);
            mbedtls_mpi_write_file("[=] n-fs........... ", &res, 16, NULL);
        }


        uint8_t nfs[128] = {0};
        mbedtls_mpi_write_binary(&res, nfs, sizeof(nfs));

        // xor 0xDC01
        int count_zero = 0;
        for (int x = 0; x < sizeof(nfs); x += 2) {
            nfs[x] ^= 0xDC;
            nfs[x + 1] ^= 0x01;

            if (nfs[x] == 0x00)
                count_zero++;
            if (nfs[x + 1] == 0x00)
                count_zero++;
        }

        if (count_zero > 10)  {
            PrintAndLogEx(INFO, "");
            PrintAndLogEx(INFO, "Message XORED");
            print_hex_noascii_break(nfs, sizeof(nfs), 32);
            PrintAndLogEx(INFO, "\n");
            is_valid = true;
            break;
        }

        /*
        if (bar == 0) {
            typedef struct vigik_rsa_s {
                uint8_t rsa[127];
                uint8_t hash;
            } vigik_rsa_t;

            vigik_rsa_t ts;
            memcpy(&ts, nfs, sizeof(ts));

            if ( ts.hash == 0xCC ) {
                PrintAndLogEx(INFO, "Hash byte... 0x%02X", ts.hash);
                switch(ts.rsa[126]) {
                    case 0x11:
                        PrintAndLogEx(INFO, "Hash algo ( 0x%02X ) - SHA1");
                        break;
                    case 0x22:
                        PrintAndLogEx(INFO, "Hash algo ( 0x%02X ) - RIPEMD");
                        break;
                    case 0x33:
                        PrintAndLogEx(INFO, "Hash algo ( 0x%02X ) - SHA1");
                        break;
                    default:
                        PrintAndLogEx(INFO, "Hash algo ( 0x%02X ) - " _RED_("err"));
                        break;
                }
            } else if ( ts.hash == 0xBC) {
                PrintAndLogEx(INFO, "Hash byte... 0x%02X - " _GREEN_("implict"), ts.hash);
            } else {
                PrintAndLogEx(INFO, "Hash byte... 0x%02x - " _RED_("err"), ts.hash);
            }

            PrintAndLogEx(INFO, "Message w padding");
            print_hex_noascii_break(ts.rsa, sizeof(ts.rsa) - 20, 32);
        }
        */

        mbedtls_mpi_free(&N);
        mbedtls_mpi_free(&s);
        mbedtls_mpi_free(&res);
        mbedtls_mpi_free(&RN);
        mbedtls_mpi_free(&E);
    }

    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Tag Signature"));
    PrintAndLogEx(INFO, "RSA: 1024bit");

    if (is_valid == false || i == ARRAYLEN(vigik_rsa_pk)) {
        PrintAndLogEx(INFO, "Signature:");
        print_hex_noascii_break(d->rsa_signature, sizeof(d->rsa_signature),  MFBLOCK_SIZE * 2);
        PrintAndLogEx(SUCCESS, "Signature verification: " _RED_("failed"));
        return PM3_ESOFT;
    }

    PrintAndLogEx(INFO, "Signature public key name: " _YELLOW_("%s"), vigik_rsa_pk[i].desc);
    PrintAndLogEx(INFO, "Signature public key value:");
    PrintAndLogEx(INFO, "%.64s", vigik_rsa_pk[i].n);
    PrintAndLogEx(INFO, "%.64s", vigik_rsa_pk[i].n + 64);
    PrintAndLogEx(INFO, "%.64s", vigik_rsa_pk[i].n + 128);
    PrintAndLogEx(INFO, "%.64s", vigik_rsa_pk[i].n + 192);

    PrintAndLogEx(INFO, "Signature:");
    print_hex_noascii_break(d->rsa_signature, sizeof(d->rsa_signature),  MFBLOCK_SIZE * 2);

    PrintAndLogEx(SUCCESS, "Signature verification: " _GREEN_("successful"));

    return PM3_SUCCESS;
}

int vigik_annotate(mfc_vigik_t *d) {
    if (d == NULL)
        return PM3_EINVARG;

    PrintAndLogEx(INFO, "Manufacture......... %s", sprint_hex(d->b0, sizeof(d->b0)));
    PrintAndLogEx(INFO, "MAD................. %s", sprint_hex(d->mad, sizeof(d->mad)));
    PrintAndLogEx(INFO, "Counters............ %u", d->counters);
    PrintAndLogEx(INFO, "rtf................. %s", sprint_hex(d->rtf, sizeof(d->rtf)));
    PrintAndLogEx(INFO, "Service code........ 0x%08x / %u  - " _YELLOW_("%s"), d->service_code, d->service_code, vigik_get_service(d->service_code));
    PrintAndLogEx(INFO, "Info flag........... %u -", d->info_flag); // ,  sprint_bin(d->info_flag, 1));
    PrintAndLogEx(INFO, "Key version......... %u", d->key_version);
    PrintAndLogEx(INFO, "PTR Counter......... %u", d->ptr_counter);
    PrintAndLogEx(INFO, "Counter num......... %u", d->counter_num);
    PrintAndLogEx(INFO, "Slot access date.... %s", sprint_hex(d->slot_access_date, sizeof(d->slot_access_date)));
    PrintAndLogEx(INFO, "Slot dst duration... %u", d->slot_dst_duration);
    PrintAndLogEx(INFO, "Other Slots......... %s", sprint_hex(d->other_slots, sizeof(d->other_slots)));
    PrintAndLogEx(INFO, "Services counter.... %u", d->services_counter);
    PrintAndLogEx(INFO, "Loading date........ %s", sprint_hex(d->loading_date, sizeof(d->loading_date)));
    PrintAndLogEx(INFO, "Reserved null....... %u", d->reserved_null);
    PrintAndLogEx(INFO, "----------------------------------------------------------------");
    PrintAndLogEx(INFO, "");
    vigik_verify(d);
    PrintAndLogEx(INFO, "----------------------------------------------------------------");
    PrintAndLogEx(INFO, "");
    return PM3_SUCCESS;

}

// Key layouts of the VIGIK family building access systems. Every one of these
// ships the same keys on every card, so matching the whole set identifies the
// system outright - no guessing from the payload. Sourced from the schemas in
// armsrc/Standalone/hf_colin.c, with the Hexact sector 15 key B measured on a
// card here; hf_colin.c leaves that slot empty.
typedef struct {
    const char *name;
    uint64_t key_a[16];
    uint64_t key_b[16];
} vigik_schema_t;

static const vigik_schema_t vigik_schemas[] = {
    {
        "Infineon / Hexact / COGELEC / Intratone",
        {
            0x484558414354ULL, 0x484558414354ULL, 0x484558414354ULL, 0x484558414354ULL,
            0x484558414354ULL, 0x484558414354ULL, 0x484558414354ULL, 0x484558414354ULL,
            0x484558414354ULL, 0x484558414354ULL, 0x484558414354ULL, 0x484558414354ULL,
            0x484558414354ULL, 0x484558414354ULL, 0x484558414354ULL, 0x484558414354ULL
        },
        {
            0xa22ae129c013ULL, 0x49fae4e3849fULL, 0x38fcf33072e0ULL, 0x8ad5517b4b18ULL,
            0x509359f131b1ULL, 0x6c78928e1317ULL, 0xaa0720018738ULL, 0xa6cac2886412ULL,
            0x62d0c424ed8eULL, 0xe64a986a5d94ULL, 0x8fa1d601d0a2ULL, 0x89347350bd36ULL,
            0x66d2b7dc39efULL, 0x6bc1e1ae547dULL, 0x22729a9bd40fULL, 0x484558414354ULL
        }
    },
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
        }
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
        }
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
            0x010203040506ULL, 0x010203040506ULL, 0x010203040506ULL, 0x010203040506ULL,
            0x010203040506ULL, VIGIK_KEY_ANY, VIGIK_KEY_ANY, VIGIK_KEY_ANY,
            VIGIK_KEY_ANY, VIGIK_KEY_ANY, VIGIK_KEY_ANY, VIGIK_KEY_ANY,
            VIGIK_KEY_ANY, VIGIK_KEY_ANY, VIGIK_KEY_ANY, VIGIK_KEY_ANY
        }
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

const char *vigik_detect_schema(const uint8_t *dump, size_t dumplen) {

    if (dump == NULL) {
        return NULL;
    }

    for (size_t i = 0; i < ARRAYLEN(vigik_schemas); i++) {

        const vigik_schema_t *schema = &vigik_schemas[i];
        bool match = true;

        for (uint8_t s = 0; s < 16 && match; s++) {

            if (schema->key_a[s] != VIGIK_KEY_ANY &&
                    schema->key_a[s] != vigik_sector_key(dump, dumplen, s, false)) {
                match = false;
            }

            if (schema->key_b[s] != VIGIK_KEY_ANY &&
                    schema->key_b[s] != vigik_sector_key(dump, dumplen, s, true)) {
                match = false;
            }
        }

        if (match) {
            return schema->name;
        }
    }
    return NULL;
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

    // Only the deployments that publish a MAD can be taken apart any further.
    // The others keep the same structure somewhere else on the card, and where
    // that is has not been worked out, so say so instead of printing nonsense.
    if (DetectHID(s0, VIGIK_MAD_AID) < 0) {
        PrintAndLogEx(INFO, "No MAD on this card, structure " _YELLOW_("not decoded"));
        return PM3_SUCCESS;
    }

    mad_entry_list_t mad_list = {0};
    int res = MADDecode(s0, NULL, &mad_list, false, true);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "can't decode MAD");
        return res;
    }

    // The VIGIK structure is the data blocks of sector 0 followed by the data
    // blocks of every sector the MAD hands to the VIGIK application.
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
