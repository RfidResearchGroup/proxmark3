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
// RKF travel card parser for MIFARE Classic dumps
//-----------------------------------------------------------------------------

#include "parserkf.h"

#include <stdio.h>                  // snprintf
#include <string.h>

#include "commonutil.h"             // ARRAYLEN
#include "crc.h"                   // CRC8Mad
#include "ui.h"                     // PrintAndLogEx
#include "util.h"                   // sprint_hex_inrow
#include "mifare/mifaredefault.h"   // MFBLOCK_SIZE
#include "mifare/mifare4.h"         // mfFirstBlockOfSector

#define RKF_SECTORS         16
#define RKF_BLOCK_BITS      128

// The last byte of a block that carries no MAC authenticator is a checksum, so
// a data element group spanning blocks sees only 120 bits per block
#define RKF_USABLE_BITS     120

// Fixed positions of the travel card support layer
#define RKF_CMI_SECTOR       0
#define RKF_CMI_BLOCK        0
#define RKF_TCCI_BLOCK       1
#define RKF_TCAS_BLOCK       2
#define RKF_TCDI_SECTOR      1

// Directory AID values with a fixed meaning, RKF-0022 section 8.2
#define RKF_AID_FREE        0x000
#define RKF_AID_DEFECTIVE   0x001
#define RKF_AID_RESERVED    0x002
#define RKF_AID_TCAS2       0x005
#define RKF_AID_TCDI        0x006
#define RKF_AID_TCEL        0x00A
#define RKF_AID_TCPU        0x00B
#define RKF_AID_TCPU_DATA   0x00C

// Directory PIX value marking a continuation sector, RKF-0022 section 8.3
#define RKF_PIX_CONT        0x001

// Data element group identifiers, RKF-0022 section 8.1
#define RKF_ID_TCEL_RECORD  0x84
#define RKF_ID_TCPU_STATIC  0x85
#define RKF_ID_TCTI_HEADER  0x86
#define RKF_ID_TCCO_HEADER  0x87
#define RKF_ID_DYN_MULTI    0x88
#define RKF_ID_MANDATORY    0x89
#define RKF_ID_DYN_SINGLE   0x8A
#define RKF_ID_MAC          0x93
#define RKF_ID_PRICE        0x94
#define RKF_ID_ISSUER       0x95
#define RKF_ID_TCCO_PERIOD  0x96
#define RKF_ID_VAL_DISTANCE 0x97
#define RKF_ID_VAL_ROUTE    0x98
#define RKF_ID_VAL_ZONE     0x99
#define RKF_ID_TCCO_ISSUING 0x9A
#define RKF_ID_CUSTOMER     0x9B
#define RKF_ID_CLASS        0x9C
#define RKF_ID_TCTI_PERIOD  0x9D
#define RKF_ID_TCTI_ISSUING 0x9E
#define RKF_ID_VALIDATION   0x9F
#define RKF_ID_TCDB         0xA1
#define RKF_ID_TCCP         0xA2
#define RKF_ID_TCST         0xA3

// Days from 1970-01-01 to the DateCompact epoch of 1997-01-01
#define RKF_DAYS_TO_1997    9862
// Days from 1970-01-01 to the DateTime epoch of 2000-01-01
#define RKF_DAYS_TO_2000    10957

#define RKF_LABEL           "%-18s"

//-----------------------------------------------------------------------------
// Bit access
//
// RKF-0022 section 7.4.1: the bits of byte 0 precede the bits of byte 1, and
// within a byte the least significant bit comes first. An unsigned number is
// read with its least significant bit first.
//-----------------------------------------------------------------------------

static uint64_t rkf_bits(const uint8_t *buf, uint16_t off, uint8_t len) {
    uint64_t v = 0;
    for (uint8_t k = 0; k < len; k++) {
        uint16_t b = off + k;
        if ((buf[b >> 3] >> (b & 7)) & 1) {
            v |= (uint64_t)1 << k;
        }
    }
    return v;
}

static void rkf_set_bits(uint8_t *buf, uint16_t off, uint8_t len, uint64_t v) {
    for (uint8_t k = 0; k < len; k++) {
        uint16_t b = off + k;
        if ((v >> k) & 1) {
            buf[b >> 3] |= (uint8_t)(1 << (b & 7));
        } else {
            buf[b >> 3] &= (uint8_t)~(1 << (b & 7));
        }
    }
}

// Twos complement, the sign living in the last bit of the section
static int32_t rkf_signed(uint64_t v, uint8_t len) {
    if (v & ((uint64_t)1 << (len - 1))) {
        return (int32_t)(v - ((uint64_t)1 << len));
    }
    return (int32_t)v;
}

// A run of data blocks holding one or more application elements. Bit p of the
// run lives in data block p / 120 at bit p % 120, so the checksum byte of every
// block is stepped over, per RKF-0022 section 7.4.1. Sector trailers are not
// part of the run.
typedef struct {
    const uint8_t *dump;
    size_t dumplen;
    uint8_t sector;
    uint8_t nblocks;
} rkf_run_t;

static const uint8_t *rkf_block(const uint8_t *dump, size_t dumplen, uint8_t sector, uint8_t block);
static uint8_t rkf_data_blocks(uint8_t sector);

static const uint8_t *rkf_run_block(const rkf_run_t *run, uint8_t idx) {
    uint8_t s = run->sector;
    while (idx >= rkf_data_blocks(s)) {
        idx -= rkf_data_blocks(s);
        s++;
    }
    return rkf_block(run->dump, run->dumplen, s, idx);
}

static uint64_t rkf_run_bits(const rkf_run_t *run, uint16_t off, uint8_t len) {
    uint64_t v = 0;
    for (uint8_t k = 0; k < len; k++) {

        uint16_t p = off + k;
        uint8_t idx = (uint8_t)(p / RKF_USABLE_BITS);
        if (idx >= run->nblocks) {
            break;
        }

        const uint8_t *blk = rkf_run_block(run, idx);
        if (blk == NULL) {
            break;
        }

        uint16_t b = p % RKF_USABLE_BITS;
        if ((blk[b >> 3] >> (b & 7)) & 1) {
            v |= (uint64_t)1 << k;
        }
    }
    return v;
}

// Only used to build the self test card, which keeps its run inside one sector
static void rkf_run_set_bits(uint8_t *base, uint16_t off, uint8_t len, uint64_t v) {
    for (uint8_t k = 0; k < len; k++) {
        uint16_t p = off + k;
        uint16_t blk = p / RKF_USABLE_BITS;
        rkf_set_bits(base, (uint16_t)((p % RKF_USABLE_BITS) + (blk * RKF_BLOCK_BITS)), 1, (v >> k) & 1);
    }
}

//-----------------------------------------------------------------------------
// Value decoding
//-----------------------------------------------------------------------------

static void rkf_civil_from_days(int32_t z, int *year, unsigned *month, unsigned *day) {
    z += 719468;
    int32_t era = ((z >= 0) ? z : (z - 146096)) / 146097;
    uint32_t doe = (uint32_t)(z - (era * 146097));
    uint32_t yoe = (doe - (doe / 1460) + (doe / 36524) - (doe / 146096)) / 365;
    int32_t y = (int32_t)yoe + (era * 400);
    uint32_t doy = doe - ((365 * yoe) + (yoe / 4) - (yoe / 100));
    uint32_t mp = ((5 * doy) + 2) / 153;
    *day = doy - (((153 * mp) + 2) / 5) + 1;
    *month = (mp < 10) ? (mp + 3) : (mp - 9);
    *year = y + ((*month <= 2) ? 1 : 0);
}

// DateCompact, day 0 is 1 January 1997
static void rkf_date_str(uint16_t v, char *out, size_t outlen) {
    int y;
    unsigned m, d;
    rkf_civil_from_days((int32_t)v + RKF_DAYS_TO_1997, &y, &m, &d);
    snprintf(out, outlen, "%04d-%02u-%02u", y, m, d);
}

// TimeCompact, 'hhhhhmmmmmmsssss' with a 2 second resolution
static void rkf_time_str(uint16_t v, char *out, size_t outlen) {
    uint8_t h = (v >> 11) & 0x1F;
    uint8_t m = (v >> 5) & 0x3F;
    uint8_t s = (v & 0x1F) * 2;

    if (h > 23 || m > 59) {
        snprintf(out, outlen, "%04X invalid", v);
        return;
    }
    snprintf(out, outlen, "%02u:%02u:%02u", h, m, s);
}

// DateTime, minute 1 is 0:01 on 1 January 2000
static void rkf_datetime_str(uint32_t v, char *out, size_t outlen) {
    int y;
    unsigned m, d;
    rkf_civil_from_days((int32_t)(v / 1440) + RKF_DAYS_TO_2000, &y, &m, &d);
    snprintf(out, outlen, "%04d-%02u-%02u %02u:%02u", y, m, d, (v % 1440) / 60, (v % 1440) % 60);
}

// DateMonth11, month 1 is January 1900
static void rkf_month11_str(uint16_t v, char *out, size_t outlen) {
    if (v == 0) {
        snprintf(out, outlen, "undefined");
        return;
    }
    snprintf(out, outlen, "%04u-%02u", 1900 + ((v - 1) / 12), ((v - 1) % 12) + 1);
}

// DateMonth8, month 1 is January 2000
static void rkf_month8_str(uint16_t v, char *out, size_t outlen) {
    if (v == 0) {
        snprintf(out, outlen, "undefined");
        return;
    }
    snprintf(out, outlen, "%04u-%02u", 2000 + ((v - 1) / 12), ((v - 1) % 12) + 1);
}

static const char *rkf_currency_name(uint16_t code) {
    switch (code) {
        case 208:
            return "DKK";
        case 246:
            return "FIM";
        case 352:
            return "ISK";
        case 578:
            return "NOK";
        case 752:
            return "SEK";
        case 826:
            return "GBP";
        case 840:
            return "USD";
        case 978:
            return "EUR";
        default:
            return NULL;
    }
}

// CurrencyUnit is BCD(4) coded 'xyyy', x the unit and yyy the ISO 4217 currency
static void rkf_currency_str(uint16_t cu, char *out, size_t outlen) {
    uint8_t unit = (cu >> 12) & 0x0F;
    uint16_t code = (((cu >> 8) & 0x0F) * 100) + (((cu >> 4) & 0x0F) * 10) + (cu & 0x0F);
    const char *name = rkf_currency_name(code);

    const char *scale;
    switch (unit) {
        case 0:
            scale = "main unit";
            break;
        case 1:
            scale = "1/10 of main unit";
            break;
        case 2:
            scale = "1/100 of main unit";
            break;
        case 9:
            scale = "1/2 of main unit";
            break;
        default:
            scale = "provider specific unit";
            break;
    }

    if (name) {
        snprintf(out, outlen, "%s, %s", name, scale);
    } else {
        snprintf(out, outlen, "currency %03u, %s", code, scale);
    }
}

// Money amounts are stored in the unit named by CardCurrencyUnit of TCCI
static void rkf_money_str(int32_t v, uint16_t cu, char *out, size_t outlen) {
    uint8_t unit = (cu >> 12) & 0x0F;
    uint16_t code = (((cu >> 8) & 0x0F) * 100) + (((cu >> 4) & 0x0F) * 10) + (cu & 0x0F);
    const char *name = rkf_currency_name(code);
    char cur[8];

    if (name) {
        snprintf(cur, sizeof(cur), "%s", name);
    } else {
        snprintf(cur, sizeof(cur), "%03u", code);
    }

    const char *sign = (v < 0) ? "-" : "";
    uint32_t a = (uint32_t)((v < 0) ? -(int64_t)v : v);

    switch (unit) {
        case 1:
            snprintf(out, outlen, "%s%u.%01u %s", sign, a / 10, a % 10, cur);
            break;
        case 2:
            snprintf(out, outlen, "%s%u.%02u %s", sign, a / 100, a % 100, cur);
            break;
        case 9:
            snprintf(out, outlen, "%s%u.%s %s", sign, a / 2, (a % 2) ? "5" : "0", cur);
            break;
        default:
            snprintf(out, outlen, "%s%u %s", sign, a, cur);
            break;
    }
}

// Status values are chosen so the ASCII character is itself the signal
static const char *rkf_status_name(uint8_t s) {
    switch (s) {
        case 0x00:
            return "undefined";
        case 0x01:
            return "ok, enabled";
        case 0x21:
            return "disabled, action pending";
        case 0x3F:
            return "temporarily disabled";
        case 0x58:
            return "not ok, disabled";
        default:
            return "unknown";
    }
}

static const char *rkf_sector_status_name(uint8_t s) {
    switch (s) {
        case 1:
            return "AT1/AT5, 1st dynamic element current";
        case 2:
            return "AT1/AT5, 2nd dynamic element current";
        case 3:
            return "AT2";
        default:
            return "undefined";
    }
}

static const char *rkf_passenger_type_name(uint8_t t) {
    switch (t) {
        case 0:
            return "unspecified";
        case 1:
            return "adult";
        case 2:
            return "child";
        case 3:
            return "student";
        case 4:
            return "old age pensioner";
        default:
            return (t >= 32) ? "PTA specific" : "RFU";
    }
}

static const char *rkf_passenger_class_name(uint8_t c) {
    switch (c) {
        case 1:
            return "first class";
        case 2:
            return "second class";
        case 3:
            return "provider specific";
        default:
            return "not specified";
    }
}

static const char *rkf_validation_model_name(uint8_t m) {
    switch (m) {
        case 1:
            return "ci/co";
        case 2:
            return "ci-dest";
        case 3:
            return "RFU";
        default:
            return "undefined";
    }
}

static const char *rkf_validation_status_name(uint8_t s) {
    switch (s) {
        case 1:
            return "open, after check-in";
        case 2:
            return "closed, after check-out";
        case 3:
            return "RFU";
        default:
            return "undefined";
    }
}

static const char *rkf_supplement_status_name(uint8_t s) {
    switch (s) {
        case 1:
            return "counting from origin";
        case 2:
            return "accumulating distance";
        case 3:
            return "counting and accumulating";
        default:
            return "not counting";
    }
}

static const char *rkf_mac_alg_name(uint8_t a) {
    return (a == 0) ? "DES-MAC" : "RFU";
}

// AID owners, RKF-0019 2.00 edition B section 5
static const struct {
    uint16_t aid;
    const char *name;
} rkf_aid_owners[] = {
    {0x064, "Stockholms Lans Landsting"},
    {0x065, "SL - Storstockholms Lokaltrafik AB"},
    {0x066, "SL Flygbussar AB"},
    {0x067, "Waxholms Angfartygs AB"},
    {0x06E, "Lanstrafiken i Vasterbotten AB"},
    {0x06F, "Umea Lokaltrafik AB"},
    {0x078, "Lanstrafiken i Norrbotten AB"},
    {0x079, "Lulea Lokaltrafik AB"},
    {0x082, "Upplands Lokaltrafik AB"},
    {0x083, "Uppsalabuss AB"},
    {0x08C, "LTS - Lanstrafiken Sormland AB"},
    {0x096, "Ostgotatrafiken AB"},
    {0x097, "Norrkopings Kommun"},
    {0x0A0, "Jonkopings Lanstrafik AB"},
    {0x0AA, "Lanstrafiken Kronoberg"},
    {0x0B4, "Kalmar Lans Trafik AB"},
    {0x0BE, "Gotlands Kommun, Kollektivtrafiken"},
    {0x0BF, "Destination Gotland"},
    {0x0C8, "Blekingetrafiken"},
    {0x0DD, "Helsingborgs Kommun"},
    {0x0DE, "Lunds kommun"},
    {0x0E0, "Skanetrafiken"},
    {0x0E6, "Hallandstrafiken AB"},
    {0x0F0, "Vasttrafik"},
    {0x10E, "Varmlandstrafik AB"},
    {0x10F, "Karlstads kommun"},
    {0x118, "LTO - Lanstrafiken Orebro AB"},
    {0x122, "Vastmanlands Lokaltrafik AB"},
    {0x12C, "Dalatrafik, AB"},
    {0x136, "X-Trafik AB"},
    {0x137, "Gavle Kommun"},
    {0x140, "Vasternorrlands lans Trafik AB"},
    {0x14A, "Lanstrafiken i Jamtlands Lan AB"},
    {0x1F4, "SJ"},
    {0x1F5, "TIM - Trafik i Malardalen"},
    {0x3E9, "AS Oslo Sporveier"},
    {0x3EA, "Norges Statsbaner"},
    {0x3EB, "SL - Stor-Oslo Lokaltrafikk A.S."},
    {0x7D1, "HUR - Hovedstadens Udviklingsraad"},
    {0x7D2, "DSB"},
    {0x7D3, "OSS/Metro"},
    {0x7D4, "STS"},
    {0x7D5, "VT"},
};

// The block an AID falls in when no owner is registered for it, RKF-0019
static const char *rkf_aid_range(uint16_t aid) {
    if (aid <= 0x063) {
        return "system value";
    }
    if (aid <= 0x1F3) {
        return "Swedish PTA, county or municipal";
    }
    if (aid <= 0x3E7) {
        return "Swedish PTA, national or regional";
    }
    if (aid <= 0x7CF) {
        return "Norwegian PTA";
    }
    if (aid <= 0xBB7) {
        return "Danish PTA";
    }
    return "reserved";
}

static const char *rkf_aid_name(uint16_t aid) {
    switch (aid) {
        case RKF_AID_FREE:
            return "sector free";
        case RKF_AID_DEFECTIVE:
            return "sector defective";
        case RKF_AID_RESERVED:
            return "sector reserved";
        case RKF_AID_TCAS2:
            return "TCAS (2), applications status";
        case RKF_AID_TCDI:
            return "TCDI, directory";
        case RKF_AID_TCEL:
            return "TCEL, event log";
        case RKF_AID_TCPU:
            return "TCPU, purse";
        case RKF_AID_TCPU_DATA:
            return "PTA area bound to the purse";
        default:
            break;
    }

    for (size_t i = 0; i < ARRAYLEN(rkf_aid_owners); i++) {
        if (rkf_aid_owners[i].aid == aid) {
            return rkf_aid_owners[i].name;
        }
    }

    if (aid >= 0x020 && aid <= 0x02F) {
        return "test and validation";
    }
    return rkf_aid_range(aid);
}

// Event codes and the event data layout each one uses, RKF-0023 section 3.4.2
typedef enum {
    RKF_EVD_NONE = 0,
    RKF_EVD_A,      // pointer and price
    RKF_EVD_B,      // ticket pointer and contract pointer
    RKF_EVD_C,      // ticket pointer and PTA specific data
    RKF_EVD_D,      // money amount
} rkf_evdata_t;

static const struct {
    uint8_t code;
    rkf_evdata_t kind;
    const char *name;
} rkf_event_codes[] = {
    {0x00, RKF_EVD_NONE, "undefined"},
    {0x01, RKF_EVD_A, "purchase of TCTI using TCPU"},
    {0x02, RKF_EVD_A, "purchase of TCCO using TCPU"},
    {0x03, RKF_EVD_A, "purchase of TCTI, other payment"},
    {0x04, RKF_EVD_A, "purchase of TCCO, other payment"},
    {0x05, RKF_EVD_B, "TCTI issued by a TCCO"},
    {0x06, RKF_EVD_C, "validation of TCTI / TCCO"},
    {0x07, RKF_EVD_C, "extension of TCTI / TCCO"},
    {0x08, RKF_EVD_D, "charge of the TCPU"},
    {0x09, RKF_EVD_C, "TCTI removed"},
    {0x0A, RKF_EVD_C, "TCCO removed"},
    {0x0B, RKF_EVD_C, "TCPU removed"},
    {0x0C, RKF_EVD_C, "TCST-ci/co removed"},
    {0x0D, RKF_EVD_C, "TCCP removed"},
    {0x0E, RKF_EVD_C, "TCDB removed"},
    {0x0F, RKF_EVD_C, "TCRE removed"},
    {0x16, RKF_EVD_A, "card initialised"},
    {0x17, RKF_EVD_C, "application object created"},
    {0x18, RKF_EVD_A, "application object repurchased"},
    {0x19, RKF_EVD_C, "TCCO activated"},
    {0x1A, RKF_EVD_A, "purchase of paper ticket using TCPU"},
    {0x1B, RKF_EVD_C, "check-in validation of TCST-ci/co"},
    {0x1C, RKF_EVD_C, "check-out validation of TCST-ci/co"},
    {0x1D, RKF_EVD_C, "control validation"},
    {0x1E, RKF_EVD_C, "supplement validation"},
    {0x1F, RKF_EVD_D, "charge of the TCPU using autoload"},
};

static rkf_evdata_t rkf_event_kind(uint8_t code, const char **name) {
    for (size_t i = 0; i < ARRAYLEN(rkf_event_codes); i++) {
        if (rkf_event_codes[i].code == code) {
            *name = rkf_event_codes[i].name;
            return rkf_event_codes[i].kind;
        }
    }
    *name = (code >= 0x30) ? "PTA specific" : "RFU";
    return RKF_EVD_NONE;
}

//-----------------------------------------------------------------------------
// Block access
//-----------------------------------------------------------------------------

static const uint8_t *rkf_block(const uint8_t *dump, size_t dumplen, uint8_t sector, uint8_t block) {
    size_t off = (size_t)(mfFirstBlockOfSector(sector) + block) * MFBLOCK_SIZE;
    if (off + MFBLOCK_SIZE > dumplen) {
        return NULL;
    }
    return dump + off;
}

// RKF-0022 section 7.7.1: every byte of a block feeds the checksum except the
// checksum byte itself. The "standard CRC-8" it names is CRC-8/MIFARE-MAD.
static bool rkf_checksum_ok(const uint8_t *blk) {
    uint8_t d[MFBLOCK_SIZE - 1];
    memcpy(d, blk, sizeof(d));
    return ((uint8_t)CRC8Mad(d, sizeof(d)) == blk[MFBLOCK_SIZE - 1]);
}

static const char *rkf_checksum_str(const uint8_t *blk) {
    return rkf_checksum_ok(blk) ? _GREEN_("ok") : _RED_("fail");
}

static uint8_t rkf_sector_count(size_t dumplen) {
    if (dumplen >= MIFARE_4K_MAX_BYTES) {
        return 40;
    }
    if (dumplen >= MIFARE_2K_MAX_BYTES) {
        return 32;
    }
    if (dumplen >= MIFARE_1K_MAX_BYTES) {
        return RKF_SECTORS;
    }
    return (uint8_t)(dumplen / (4 * MFBLOCK_SIZE));
}

// Data blocks of a sector, the trailer excluded
static uint8_t rkf_data_blocks(uint8_t sector) {
    return (uint8_t)(mfNumBlocksPerSector(sector) - 1);
}

// The specification fixes TCAS (1) at S0:B2, but a card may carry the support
// layer elsewhere, so fall back to a scan for the identifier.
static bool rkf_find_tcas(const uint8_t *dump, size_t dumplen, uint8_t skip_sector,
                          uint8_t skip_block, uint8_t *sector, uint8_t *block) {

    uint8_t nsectors = rkf_sector_count(dumplen);

    for (uint8_t s = 0; s < nsectors; s++) {
        for (uint8_t b = 0; b < rkf_data_blocks(s); b++) {

            if (s == skip_sector && b == skip_block) {
                continue;
            }

            const uint8_t *blk = rkf_block(dump, dumplen, s, b);
            if (blk == NULL) {
                continue;
            }

            uint8_t version = (uint8_t)rkf_bits(blk, 8, 6);
            if (blk[0] == RKF_TCAS_IDENTIFIER && version > 0 && version < 16) {
                *sector = s;
                *block = b;
                return true;
            }
        }
    }
    return false;
}

// RKF-0022 7.3.4 places the MAC authenticator in the last bits of the last
// block. On every card tested the algorithm and key identifiers sit immediately
// before it, so the final 24 bits of a MACed object are
// MACAlgorithmIdentifier(2) | MACKeyIdentifier(6) | MACAuthenticator16(16).
static void rkf_read_mac(const uint8_t *buf, uint16_t nbits, uint8_t *alg, uint8_t *key, uint16_t *mac) {
    *alg = (uint8_t)rkf_bits(buf, nbits - 24, 2);
    *key = (uint8_t)rkf_bits(buf, nbits - 22, 6);
    *mac = (uint16_t)rkf_bits(buf, nbits - 16, 16);
}

static void rkf_print_aid(const char *label, uint16_t aid) {
    PrintAndLogEx(INFO, RKF_LABEL " " _YELLOW_("0x%03X") "  ( %s )", label, aid, rkf_aid_name(aid));
}

static void rkf_print_mac(uint8_t alg, uint8_t key, uint16_t mac) {

    // DES-MAC is the only algorithm the specification defines, so anything else
    // means these bits are not the MAC trio on this card
    if (alg != 0) {
        PrintAndLogEx(INFO, RKF_LABEL " %04X, algorithm %u  ( " _YELLOW_("not a defined algorithm") " )",
                      "MAC", mac, alg);
        PrintAndLogEx(INFO, RKF_LABEL "   " _YELLOW_("the MAC trio is not at the expected offsets here"), "");
        return;
    }

    PrintAndLogEx(INFO, RKF_LABEL " %04X, algorithm %u ( %s ), key id %u",
                  "MAC", mac, alg, rkf_mac_alg_name(alg), key);
}

//-----------------------------------------------------------------------------
// Detection
//-----------------------------------------------------------------------------

bool is_valid_rkf_card(const uint8_t *dump, size_t dumplen) {

    if (dump == NULL || dumplen < MIFARE_1K_MAX_BYTES) {
        return false;
    }

    // TCCI is always the second block of sector 0. Its MADInfoByte is 0 because
    // the travel card does not use a MAD, and its CardProvider must be an AID
    // that RKF-0019 has handed to a transport authority.
    const uint8_t *tcci = rkf_block(dump, dumplen, RKF_CMI_SECTOR, RKF_TCCI_BLOCK);
    if (tcci == NULL || tcci[0] != 0x00 || tcci[1] != 0x00) {
        return false;
    }

    uint8_t version = (uint8_t)rkf_bits(tcci, 16, 6);
    uint16_t provider = (uint16_t)rkf_bits(tcci, 22, 12);

    if (version == 0 || provider < 0x064 || provider > 0x0BB7) {
        return false;
    }

    // and the card must carry an applications status block somewhere
    uint8_t s, b;
    return rkf_find_tcas(dump, dumplen, 0xFF, 0xFF, &s, &b);
}

//-----------------------------------------------------------------------------
// Card issuer and travel card support layer
//-----------------------------------------------------------------------------

static void rkf_print_cmi(const uint8_t *blk) {

    uint32_t csn = (uint32_t)rkf_bits(blk, 0, 32);
    uint8_t chk = (uint8_t)rkf_bits(blk, 32, 8);
    uint8_t calc = blk[0] ^ blk[1] ^ blk[2] ^ blk[3];

    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("CMI, card manufacturer information") " ---");
    PrintAndLogEx(INFO, RKF_LABEL " " _YELLOW_("%08X") "  ( %s )", "Card serial no", csn, sprint_hex_inrow(blk, 4));
    PrintAndLogEx(INFO, RKF_LABEL " %02X  ( %s )", "Check byte", chk,
                  (chk == calc) ? _GREEN_("ok") : _RED_("fail"));
    PrintAndLogEx(INFO, RKF_LABEL " %s", "Manufacturer data", sprint_hex_inrow(blk + 5, 11));
}

typedef struct {
    uint16_t mad_info;
    uint8_t card_version;
    uint16_t card_provider;
    uint16_t validity_end;
    uint8_t card_status;
    uint16_t currency_unit;
    uint8_t event_log_version;
    uint8_t mac_alg;
    uint8_t mac_key;
    uint16_t mac;
} rkf_tcci_t;

static void rkf_read_tcci(const uint8_t *blk, rkf_tcci_t *t) {
    t->mad_info = (uint16_t)rkf_bits(blk, 0, 16);
    t->card_version = (uint8_t)rkf_bits(blk, 16, 6);
    t->card_provider = (uint16_t)rkf_bits(blk, 22, 12);
    t->validity_end = (uint16_t)rkf_bits(blk, 34, 14);
    t->card_status = (uint8_t)rkf_bits(blk, 48, 8);
    t->currency_unit = (uint16_t)rkf_bits(blk, 56, 16);
    t->event_log_version = (uint8_t)rkf_bits(blk, 72, 6);
    rkf_read_mac(blk, RKF_BLOCK_BITS, &t->mac_alg, &t->mac_key, &t->mac);
}

static void rkf_print_tcci(const rkf_tcci_t *t) {

    char buf[32];

    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("TCCI, card information") " ---");
    PrintAndLogEx(INFO, RKF_LABEL " %u  ( %s )", "MAD info byte", t->mad_info,
                  (t->mad_info == 0) ? "MAD not available" : "unknown");
    PrintAndLogEx(INFO, RKF_LABEL " %u%s", "Card version", t->card_version,
                  (t->card_version == 2) ? "" : _YELLOW_("  ( RKF-0022/0023 describe version 2 )"));
    rkf_print_aid("Card provider", t->card_provider);

    rkf_date_str(t->validity_end, buf, sizeof(buf));
    PrintAndLogEx(INFO, RKF_LABEL " " _YELLOW_("%s"), "Valid until", buf);

    PrintAndLogEx(INFO, RKF_LABEL " %02X  ( %s )", "Card status", t->card_status,
                  rkf_status_name(t->card_status));

    rkf_currency_str(t->currency_unit, buf, sizeof(buf));
    PrintAndLogEx(INFO, RKF_LABEL " %04X  ( %s )", "Currency unit", t->currency_unit, buf);

    PrintAndLogEx(INFO, RKF_LABEL " %u", "Event log version", t->event_log_version);
    rkf_print_mac(t->mac_alg, t->mac_key, t->mac);
}

typedef struct {
    uint8_t identifier;
    uint8_t version;
    uint8_t sector_status[RKF_SECTORS];
    uint8_t transaction_no;
    uint8_t event_log_record;
    uint8_t log_area;
    uint8_t log_pointer[8];
    uint8_t mac_alg;
    uint8_t mac_key;
    uint16_t mac;
} rkf_tcas_t;

static const char *rkf_log_slot(const rkf_tcas_t *t, uint8_t sector) {
    static const char *slot[] = {
        "current ticket", "previous ticket", "log ticket 1", "log ticket 2",
        "log ticket 3", "log ticket 4", "log ticket 5", "log ticket 6"
    };
    for (uint8_t i = 0; i < ARRAYLEN(slot); i++) {
        if (t->log_pointer[i] == sector) {
            return slot[i];
        }
    }
    return "not referenced by TCAS";
}

static void rkf_read_tcas(const uint8_t *blk, rkf_tcas_t *t) {
    t->identifier = (uint8_t)rkf_bits(blk, 0, 8);
    t->version = (uint8_t)rkf_bits(blk, 8, 6);
    for (uint8_t s = 0; s < RKF_SECTORS; s++) {
        t->sector_status[s] = (uint8_t)rkf_bits(blk, 14 + (2 * s), 2);
    }
    t->transaction_no = (uint8_t)rkf_bits(blk, 46, 8);
    t->event_log_record = (uint8_t)rkf_bits(blk, 54, 4);
    t->log_area = (uint8_t)rkf_bits(blk, 58, 4);
    for (uint8_t i = 0; i < 8; i++) {
        t->log_pointer[i] = (uint8_t)rkf_bits(blk, 62 + (4 * i), 4);
    }
    rkf_read_mac(blk, RKF_BLOCK_BITS, &t->mac_alg, &t->mac_key, &t->mac);
}

static void rkf_print_tcas(const rkf_tcas_t *t, uint8_t instance, uint8_t sector, uint8_t block) {

    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("TCAS (%u), applications status") " --- S%u:B%u",
                  instance, sector, block);
    PrintAndLogEx(INFO, RKF_LABEL " %02X  ( %s )", "Identifier", t->identifier,
                  (t->identifier == RKF_TCAS_IDENTIFIER) ? _GREEN_("ok") : _RED_("fail"));
    PrintAndLogEx(INFO, RKF_LABEL " %u", "Version", t->version);
    PrintAndLogEx(INFO, RKF_LABEL " %u", "Transaction no", t->transaction_no);
    PrintAndLogEx(INFO, RKF_LABEL " %u", "Event log record", t->event_log_record);

    if (t->log_area == 0) {
        PrintAndLogEx(INFO, RKF_LABEL " none", "Ticket/log area");
    } else {
        PrintAndLogEx(INFO, RKF_LABEL " first sector %u", "Ticket/log area", t->log_area);
        for (uint8_t i = 0; i < ARRAYLEN(t->log_pointer); i++) {
            if (t->log_pointer[i] != 0) {
                PrintAndLogEx(INFO, RKF_LABEL "   sector %2u  ( %s )", "", t->log_pointer[i],
                              rkf_log_slot(t, t->log_pointer[i]));
            }
        }
    }

    rkf_print_mac(t->mac_alg, t->mac_key, t->mac);

    uint8_t defined = 0;
    for (uint8_t s = 0; s < RKF_SECTORS; s++) {
        if (t->sector_status[s] != 0) {
            defined++;
        }
    }

    PrintAndLogEx(INFO, RKF_LABEL " %u of %u sectors defined", "Sector status", defined, RKF_SECTORS);
    for (uint8_t s = 0; s < RKF_SECTORS; s++) {
        if (t->sector_status[s] != 0) {
            PrintAndLogEx(INFO, RKF_LABEL "   sector %2u  %u  ( %s )", "", s,
                          t->sector_status[s], rkf_sector_status_name(t->sector_status[s]));
        }
    }
}

// The directory covers sectors 1..15, five entries to a block
static void rkf_read_tcdi(const uint8_t *dump, size_t dumplen, uint16_t *aid, uint16_t *pix) {

    for (uint8_t s = 1; s < RKF_SECTORS; s++) {
        aid[s] = RKF_AID_FREE;
        pix[s] = 0;
    }

    for (uint8_t b = 0; b < 3; b++) {
        const uint8_t *blk = rkf_block(dump, dumplen, RKF_TCDI_SECTOR, b);
        if (blk == NULL) {
            continue;
        }
        for (uint8_t i = 0; i < 5; i++) {
            uint8_t s = 1 + (5 * b) + i;
            aid[s] = (uint16_t)rkf_bits(blk, 24 * i, 12);
            pix[s] = (uint16_t)rkf_bits(blk, (24 * i) + 12, 12);
        }
    }
}

static void rkf_print_tcdi(const uint8_t *dump, size_t dumplen, const uint16_t *aid, const uint16_t *pix) {

    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("TCDI, directory") " ---");
    PrintAndLogEx(INFO, " sector | AID  | PIX  | interpretation");
    PrintAndLogEx(INFO, "--------+------+------+---------------------------------------------");

    for (uint8_t s = 1; s < RKF_SECTORS; s++) {

        const char *what;
        if (pix[s] == RKF_PIX_CONT && aid[s] > RKF_AID_RESERVED) {
            what = "continuation of the preceding sector";
        } else {
            what = rkf_aid_name(aid[s]);
        }

        PrintAndLogEx(INFO, "   %2u   | %03X  | %03X  | %s", s, aid[s], pix[s], what);
    }

    PrintAndLogEx(INFO, "--------+------+------+---------------------------------------------");

    char line[96] = {0};
    for (uint8_t b = 0; b < 3; b++) {
        const uint8_t *blk = rkf_block(dump, dumplen, RKF_TCDI_SECTOR, b);
        if (blk) {
            str_append(line, sizeof(line), "%02X ( %s ) ", blk[MFBLOCK_SIZE - 1], rkf_checksum_str(blk));
        }
    }
    PrintAndLogEx(INFO, RKF_LABEL " %s", "Checksums", line);
}

//-----------------------------------------------------------------------------
// TCPU, purse
//-----------------------------------------------------------------------------

static void rkf_print_tcpu(const uint8_t *dump, size_t dumplen, uint8_t sector,
                           uint8_t current, uint16_t cu) {

    char buf[40];

    const uint8_t *st = rkf_block(dump, dumplen, sector, 0);
    if (st == NULL) {
        return;
    }

    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("TCPU, purse") " --- sector %u", sector);

    uint8_t version = (uint8_t)rkf_bits(st, 8, 6);

    PrintAndLogEx(INFO, RKF_LABEL " %02X, version %u", "Identifier",
                  (uint8_t)rkf_bits(st, 0, 8), version);
    rkf_print_aid("Purse provider", (uint16_t)rkf_bits(st, 14, 12));
    PrintAndLogEx(INFO, RKF_LABEL " " _YELLOW_("%08X"), "Purse serial no", (uint32_t)rkf_bits(st, 26, 32));

    rkf_date_str((uint16_t)rkf_bits(st, 58, 14), buf, sizeof(buf));
    PrintAndLogEx(INFO, RKF_LABEL " %s", "Start date", buf);

    uint8_t dp = (uint8_t)rkf_bits(st, 72, 4);
    PrintAndLogEx(INFO, RKF_LABEL " %u  ( %s )", "Data pointer", dp,
                  (dp == 0) ? "unused" : "PTA area sector");

    rkf_money_str(rkf_signed(rkf_bits(st, 76, 24), 24), cu, buf, sizeof(buf));
    PrintAndLogEx(INFO, RKF_LABEL " %s", "Minimum value", buf);

    rkf_money_str(rkf_signed(rkf_bits(st, 100, 24), 24), cu, buf, sizeof(buf));
    PrintAndLogEx(INFO, RKF_LABEL " %s", "Autoload value", buf);

    for (uint8_t b = 1; b <= 2; b++) {

        const uint8_t *dy = rkf_block(dump, dumplen, sector, b);
        if (dy == NULL) {
            continue;
        }

        bool live = (current == b);
        PrintAndLogEx(INFO, "  " _CYAN_("dynamic data (%u)") " %s", b,
                      live ? _GREEN_("<- current") : "");

        PrintAndLogEx(INFO, RKF_LABEL "   %u", "  Transaction no", (uint16_t)rkf_bits(dy, 0, 16));

        // version 4 drops EndDate and moves Value up against the transaction
        // number; the rest of the block is not known
        if (version == 4) {

            rkf_money_str(rkf_signed(rkf_bits(dy, 16, 24), 24), cu, buf, sizeof(buf));
            PrintAndLogEx(INFO, RKF_LABEL "   " _YELLOW_("%s"), "  Value", buf);
            PrintAndLogEx(INFO, RKF_LABEL "   %s  " _YELLOW_("not decoded"), "  Bits 40..103",
                          sprint_hex_inrow(dy + 5, 8));

            uint8_t valg, vkey;
            uint16_t vmac;
            rkf_read_mac(dy, RKF_BLOCK_BITS, &valg, &vkey, &vmac);
            PrintAndLogEx(INFO, RKF_LABEL "   %04X, algorithm %u, key id %u", "  MAC", vmac, valg, vkey);
            continue;
        }

        rkf_date_str((uint16_t)rkf_bits(dy, 16, 14), buf, sizeof(buf));
        PrintAndLogEx(INFO, RKF_LABEL "   %s", "  End date", buf);

        rkf_money_str(rkf_signed(rkf_bits(dy, 30, 24), 24), cu, buf, sizeof(buf));
        PrintAndLogEx(INFO, RKF_LABEL "   " _YELLOW_("%s"), "  Value", buf);

        uint8_t status = (uint8_t)rkf_bits(dy, 54, 8);
        PrintAndLogEx(INFO, RKF_LABEL "   %02X  ( %s )", "  Status", status, rkf_status_name(status));

        rkf_money_str((int32_t)rkf_bits(dy, 62, 20), cu, buf, sizeof(buf));
        PrintAndLogEx(INFO, RKF_LABEL "   %s", "  Deposit", buf);

        uint8_t al = (uint8_t)rkf_bits(dy, 82, 2);
        PrintAndLogEx(INFO, RKF_LABEL "   %u  ( %s )", "  Autoload", al,
                      (al == 1) ? "enabled" : ((al == 0) ? "disabled" : "RFU"));

        PrintAndLogEx(INFO, RKF_LABEL "   %04X, algorithm %u, key id %u", "  MAC",
                      (uint16_t)rkf_bits(dy, 112, 16),
                      (uint8_t)rkf_bits(dy, 84, 2),
                      (uint8_t)rkf_bits(dy, 86, 6));
    }
}

//-----------------------------------------------------------------------------
// TCEL, event log
//-----------------------------------------------------------------------------

static void rkf_print_event_record(const uint8_t *blk, uint8_t record, bool newest, uint16_t cu) {

    char date[16], time[16], buf[40];

    uint8_t id = (uint8_t)rkf_bits(blk, 0, 8);
    uint8_t code = (uint8_t)rkf_bits(blk, 90, 6);
    uint32_t data = (uint32_t)rkf_bits(blk, 96, 24);

    const char *name = NULL;
    rkf_evdata_t kind = rkf_event_kind(code, &name);

    if (code == 0) {
        PrintAndLogEx(INFO, "  record %-2u  " _YELLOW_("unused") "  ( event code 00, checksum %02X %s )",
                      record, blk[MFBLOCK_SIZE - 1], rkf_checksum_ok(blk) ? "ok" : "not set");
        return;
    }
    (void)id;

    rkf_date_str((uint16_t)rkf_bits(blk, 8, 14), date, sizeof(date));
    rkf_time_str((uint16_t)rkf_bits(blk, 22, 16), time, sizeof(time));

    PrintAndLogEx(INFO, "  record %-2u  %s %s  %02X %s %s", record, date, time, code, name,
                  newest ? _GREEN_("<- most recent") : "");
    PrintAndLogEx(INFO, RKF_LABEL "   AID 0x%03X ( %s ), device %04X, device txn %u", "",
                  (uint16_t)rkf_bits(blk, 38, 12),
                  rkf_aid_name((uint16_t)rkf_bits(blk, 38, 12)),
                  (uint16_t)rkf_bits(blk, 50, 16),
                  (uint32_t)rkf_bits(blk, 66, 24));

    switch (kind) {
        case RKF_EVD_A:
            rkf_money_str((int32_t)((data >> 4) & 0xFFFFF), cu, buf, sizeof(buf));
            PrintAndLogEx(INFO, RKF_LABEL "   sector %u, price %s", "", data & 0x0F, buf);
            break;
        case RKF_EVD_B:
            PrintAndLogEx(INFO, RKF_LABEL "   ticket sector %u, contract sector %u", "",
                          data & 0x0F, (data >> 4) & 0x0F);
            break;
        case RKF_EVD_C:
            PrintAndLogEx(INFO, RKF_LABEL "   ticket sector %u, PTA data %05X", "",
                          data & 0x0F, (data >> 4) & 0xFFFFF);
            break;
        case RKF_EVD_D:
            rkf_money_str(rkf_signed(data, 24), cu, buf, sizeof(buf));
            PrintAndLogEx(INFO, RKF_LABEL "   amount %s", "", buf);
            break;
        case RKF_EVD_NONE:
        default:
            PrintAndLogEx(INFO, RKF_LABEL "   event data %06X", "", data);
            break;
    }

    PrintAndLogEx(INFO, RKF_LABEL "   checksum %02X ( %s )", "",
                  blk[MFBLOCK_SIZE - 1], rkf_checksum_str(blk));
}

static void rkf_print_tcel(const uint8_t *dump, size_t dumplen, uint8_t sector,
                           uint8_t nsectors, uint8_t newest, uint16_t cu) {

    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("TCEL, event log") " --- sector %u..%u",
                  sector, sector + nsectors - 1);

    for (uint8_t s = 0; s < nsectors; s++) {
        for (uint8_t b = 0; b < 3; b++) {
            const uint8_t *blk = rkf_block(dump, dumplen, sector + s, b);
            if (blk) {
                uint8_t record = (3 * s) + b;
                rkf_print_event_record(blk, record, (record == newest), cu);
            }
        }
    }
}

//-----------------------------------------------------------------------------
// Fixed layout application objects
//-----------------------------------------------------------------------------

static void rkf_print_subgroup(const uint8_t *buf, uint16_t off, uint8_t n) {
    for (uint8_t i = 0; i < n; i++) {
        uint8_t type = (uint8_t)rkf_bits(buf, off + (14 * i), 8);
        uint8_t total = (uint8_t)rkf_bits(buf, off + (14 * i) + 8, 6);
        if (total != 0) {
            PrintAndLogEx(INFO, RKF_LABEL "   %u x %s ( type %u )", "", total,
                          rkf_passenger_type_name(type), type);
        }
    }
}

static void rkf_print_tcdb(const uint8_t *dump, size_t dumplen, uint8_t sector, uint8_t current) {

    char buf[32];

    const uint8_t *st = rkf_block(dump, dumplen, sector, 0);
    if (st == NULL) {
        return;
    }

    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("TCDB, discount basis") " --- sector %u", sector);
    PrintAndLogEx(INFO, RKF_LABEL " %02X, version %u", "Identifier",
                  (uint8_t)rkf_bits(st, 0, 8), (uint8_t)rkf_bits(st, 8, 6));
    rkf_print_aid("Provider", (uint16_t)rkf_bits(st, 14, 12));
    PrintAndLogEx(INFO, RKF_LABEL " %u, %u, %u", "Discount types",
                  (uint8_t)rkf_bits(st, 26, 8),
                  (uint8_t)rkf_bits(st, 34, 8),
                  (uint8_t)rkf_bits(st, 42, 8));

    for (uint8_t b = 1; b <= 2; b++) {

        const uint8_t *dy = rkf_block(dump, dumplen, sector, b);
        if (dy == NULL) {
            continue;
        }

        PrintAndLogEx(INFO, "  " _CYAN_("dynamic data (%u)") " %s", b,
                      (current == b) ? _GREEN_("<- current") : "");

        uint8_t status = (uint8_t)rkf_bits(dy, 0, 8);
        PrintAndLogEx(INFO, RKF_LABEL "   %02X  ( %s )", "  Status", status, rkf_status_name(status));

        rkf_month8_str((uint8_t)rkf_bits(dy, 8, 8), buf, sizeof(buf));
        PrintAndLogEx(INFO, RKF_LABEL "   %s", "  First month", buf);

        for (uint8_t i = 0; i < 3; i++) {
            uint16_t off = 16 + (29 * i);
            PrintAndLogEx(INFO, RKF_LABEL "   block %u  counters %u / %u, levels %u %u %u", "", i + 1,
                          (uint8_t)rkf_bits(dy, off, 8),
                          (uint16_t)rkf_bits(dy, off + 8, 12),
                          (uint8_t)rkf_bits(dy, off + 20, 3),
                          (uint8_t)rkf_bits(dy, off + 23, 3),
                          (uint8_t)rkf_bits(dy, off + 26, 3));
        }

        uint8_t alg, key;
        uint16_t mac;
        rkf_read_mac(dy, RKF_BLOCK_BITS, &alg, &key, &mac);
        PrintAndLogEx(INFO, RKF_LABEL "   %04X, algorithm %u, key id %u", "  MAC", mac, alg, key);
    }
}

static void rkf_print_tccp(const uint8_t *dump, size_t dumplen, uint8_t sector) {

    char buf[32];
    uint8_t d[2 * MFBLOCK_SIZE];

    const uint8_t *b0 = rkf_block(dump, dumplen, sector, 0);
    const uint8_t *b1 = rkf_block(dump, dumplen, sector, 1);
    if (b0 == NULL || b1 == NULL) {
        return;
    }
    memcpy(d, b0, MFBLOCK_SIZE);
    memcpy(d + MFBLOCK_SIZE, b1, MFBLOCK_SIZE);

    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("TCCP, customer profile") " --- sector %u", sector);
    PrintAndLogEx(INFO, RKF_LABEL " %02X, version %u", "Identifier",
                  (uint8_t)rkf_bits(d, 0, 8), (uint8_t)rkf_bits(d, 8, 6));
    rkf_print_aid("Provider", (uint16_t)rkf_bits(d, 14, 12));

    uint8_t status = (uint8_t)rkf_bits(d, 26, 8);
    PrintAndLogEx(INFO, RKF_LABEL " %02X  ( %s )", "Status", status, rkf_status_name(status));
    PrintAndLogEx(INFO, RKF_LABEL " " _YELLOW_("%010llu"), "Customer no",
                  (unsigned long long)rkf_bits(d, 34, 34));

    uint8_t pclass = (uint8_t)rkf_bits(d, 68, 2);
    PrintAndLogEx(INFO, RKF_LABEL " %u  ( %s )", "Passenger class", pclass,
                  rkf_passenger_class_name(pclass));
    rkf_print_subgroup(d, 70, 3);

    PrintAndLogEx(INFO, RKF_LABEL " %u", "Validation level", (uint8_t)rkf_bits(d, 112, 2));

    rkf_month11_str((uint16_t)rkf_bits(d, 114, 11), buf, sizeof(buf));
    PrintAndLogEx(INFO, RKF_LABEL " %s", "Birth month", buf);

    PrintAndLogEx(INFO, RKF_LABEL " %u", "Language", (uint8_t)rkf_bits(d, 125, 4));
    PrintAndLogEx(INFO, RKF_LABEL " %02X", "Dialogue prefs", (uint8_t)rkf_bits(d, 129, 8));
    rkf_print_aid("Subscr. company", (uint16_t)rkf_bits(d, 137, 12));
    PrintAndLogEx(INFO, RKF_LABEL " %u", "Subscr. type", (uint8_t)rkf_bits(d, 149, 8));
    uint8_t alg, key;
    uint16_t mac;
    rkf_read_mac(d, 2 * RKF_BLOCK_BITS, &alg, &key, &mac);
    rkf_print_mac(alg, key, mac);
}

static void rkf_print_tcst(const uint8_t *dump, size_t dumplen, uint8_t sector,
                           uint16_t cu, const char *role) {

    char buf[40];
    uint8_t d[3 * MFBLOCK_SIZE];

    for (uint8_t b = 0; b < 3; b++) {
        const uint8_t *p = rkf_block(dump, dumplen, sector, b);
        if (p == NULL) {
            return;
        }
        memcpy(d + (b * MFBLOCK_SIZE), p, MFBLOCK_SIZE);
    }

    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("TCST-ci/co, special ticket") " --- sector %u ( %s )", sector, role);
    PrintAndLogEx(INFO, RKF_LABEL " %02X, version %u", "Identifier",
                  (uint8_t)rkf_bits(d, 0, 8), (uint8_t)rkf_bits(d, 8, 6));
    rkf_print_aid("Provider", (uint16_t)rkf_bits(d, 14, 12));
    PrintAndLogEx(INFO, RKF_LABEL " 0x%03X", "PIX", (uint16_t)rkf_bits(d, 26, 12));

    uint8_t status = (uint8_t)rkf_bits(d, 38, 8);
    PrintAndLogEx(INFO, RKF_LABEL " %02X  ( %s )", "Status", status, rkf_status_name(status));

    uint8_t pclass = (uint8_t)rkf_bits(d, 46, 2);
    PrintAndLogEx(INFO, RKF_LABEL " %u  ( %s )", "Passenger class", pclass,
                  rkf_passenger_class_name(pclass));
    rkf_print_subgroup(d, 48, 3);

    PrintAndLogEx(INFO, RKF_LABEL " %s, %s", "Validation",
                  rkf_validation_model_name((uint8_t)rkf_bits(d, 90, 2)),
                  rkf_validation_status_name((uint8_t)rkf_bits(d, 92, 2)));
    PrintAndLogEx(INFO, RKF_LABEL " %u", "Validation level", (uint8_t)rkf_bits(d, 94, 2));

    rkf_money_str((int32_t)rkf_bits(d, 96, 20), cu, buf, sizeof(buf));
    PrintAndLogEx(INFO, RKF_LABEL " " _YELLOW_("%s") ", modification level %u", "Price",
                  buf, (uint8_t)rkf_bits(d, 116, 6));

    rkf_datetime_str((uint32_t)rkf_bits(d, 148, 24), buf, sizeof(buf));
    PrintAndLogEx(INFO, RKF_LABEL " AID 0x%03X place %u at %s", "Origin",
                  (uint16_t)rkf_bits(d, 122, 12), (uint16_t)rkf_bits(d, 134, 14), buf);
    PrintAndLogEx(INFO, RKF_LABEL " AID 0x%03X place %u, +%u min", "Furthest",
                  (uint16_t)rkf_bits(d, 172, 12), (uint16_t)rkf_bits(d, 184, 14),
                  (uint16_t)rkf_bits(d, 198, 10));
    PrintAndLogEx(INFO, RKF_LABEL " AID 0x%03X place %u, +%u min", "Destination",
                  (uint16_t)rkf_bits(d, 208, 12), (uint16_t)rkf_bits(d, 220, 14),
                  (uint16_t)rkf_bits(d, 234, 10));

    uint8_t sup = (uint8_t)rkf_bits(d, 244, 2);
    PrintAndLogEx(INFO, RKF_LABEL " %u ( %s ), type %u, AID 0x%03X place %u, distance %u", "Supplement",
                  sup, rkf_supplement_status_name(sup),
                  (uint8_t)rkf_bits(d, 246, 6),
                  (uint16_t)rkf_bits(d, 252, 12),
                  (uint16_t)rkf_bits(d, 264, 14),
                  (uint16_t)rkf_bits(d, 278, 12));

    PrintAndLogEx(INFO, RKF_LABEL " AID 0x%03X place %u, +%u min", "Latest control",
                  (uint16_t)rkf_bits(d, 290, 12), (uint16_t)rkf_bits(d, 302, 14),
                  (uint16_t)rkf_bits(d, 316, 10));

    uint8_t alg, key;
    uint16_t mac;
    rkf_read_mac(d, 3 * RKF_BLOCK_BITS, &alg, &key, &mac);
    rkf_print_mac(alg, key, mac);
}

//-----------------------------------------------------------------------------
// TCTI / TCCO, a chain of identifier prefixed data element groups
//-----------------------------------------------------------------------------

// Total size of each group in bits, identifier byte included, RKF-0023 3.4.3
static uint8_t rkf_group_size(uint8_t id) {
    switch (id) {
        case RKF_ID_TCTI_HEADER:
        case RKF_ID_TCCO_HEADER:
        case RKF_ID_VALIDATION:
            return 14;
        case RKF_ID_DYN_MULTI:
            return 20;
        case RKF_ID_MANDATORY:
            return 88;
        case RKF_ID_DYN_SINGLE:
            return 8;
        case RKF_ID_MAC:
        case RKF_ID_VAL_ROUTE:
            return 32;
        case RKF_ID_PRICE:
            return 28;
        case RKF_ID_ISSUER:
            return 12;
        case RKF_ID_TCCO_PERIOD:
            return 114;
        case RKF_ID_VAL_DISTANCE:
            return 142;
        case RKF_ID_VAL_ZONE:
            return 34;
        case RKF_ID_TCCO_ISSUING:
            return 54;
        case RKF_ID_CUSTOMER:
            return 42;
        case RKF_ID_CLASS:
            return 52;
        case RKF_ID_TCTI_PERIOD:
            return 68;
        case RKF_ID_TCTI_ISSUING:
            return 38;
        default:
            return 0;
    }
}

static void rkf_print_group(const rkf_run_t *run, uint16_t off, uint8_t id, uint16_t cu) {

    char a[16], b[16], c[16], d[16];

    switch (id) {

        case RKF_ID_TCTI_HEADER:
            PrintAndLogEx(INFO, RKF_LABEL " version %u", "  TCTI header",
                          (uint8_t)rkf_run_bits(run, off + 8, 6));
            break;

        case RKF_ID_TCCO_HEADER:
            PrintAndLogEx(INFO, RKF_LABEL " version %u", "  TCCO header",
                          (uint8_t)rkf_run_bits(run, off + 8, 6));
            break;

        case RKF_ID_DYN_MULTI:
            PrintAndLogEx(INFO, RKF_LABEL " transaction no %u", "  Dynamic info",
                          (uint16_t)rkf_run_bits(run, off + 8, 12));
            break;

        case RKF_ID_DYN_SINGLE:
            PrintAndLogEx(INFO, RKF_LABEL " single block", "  Dynamic info");
            break;

        case RKF_ID_MANDATORY: {
            uint16_t aid = (uint16_t)rkf_run_bits(run, off + 8, 12);
            uint8_t status = (uint8_t)rkf_run_bits(run, off + 80, 8);
            PrintAndLogEx(INFO, RKF_LABEL " AID 0x%03X ( %s ), PIX 0x%03X", "  Mandatory",
                          aid, rkf_aid_name(aid), (uint16_t)rkf_run_bits(run, off + 20, 12));
            PrintAndLogEx(INFO, RKF_LABEL "   sale device %04X, serial " _YELLOW_("%08X") ", status %02X ( %s )", "",
                          (uint16_t)rkf_run_bits(run, off + 32, 16),
                          (uint32_t)rkf_run_bits(run, off + 48, 32),
                          status, rkf_status_name(status));
            break;
        }

        case RKF_ID_MAC: {
            // the authenticator is the last 16 bits of the block, past the checksum position
            const uint8_t *last = rkf_run_block(run, (uint8_t)(off / RKF_USABLE_BITS));
            if (last == NULL) {
                break;
            }
            uint8_t alg, key;
            uint16_t mac;
            rkf_read_mac(last, RKF_BLOCK_BITS, &alg, &key, &mac);
            PrintAndLogEx(INFO, RKF_LABEL " %04X, algorithm %u ( %s ), key id %u", "  MAC",
                          mac, alg, rkf_mac_alg_name(alg), key);
            break;
        }

        case RKF_ID_PRICE:
            rkf_money_str((int32_t)rkf_run_bits(run, off + 8, 20), cu, a, sizeof(a));
            PrintAndLogEx(INFO, RKF_LABEL " " _YELLOW_("%s"), "  Price", a);
            break;

        case RKF_ID_ISSUER:
            PrintAndLogEx(INFO, RKF_LABEL " sector %u", "  Issued by",
                          (uint8_t)rkf_run_bits(run, off + 8, 4));
            break;

        case RKF_ID_TCCO_PERIOD:
            rkf_date_str((uint16_t)rkf_run_bits(run, off + 8, 14), a, sizeof(a));
            rkf_time_str((uint16_t)rkf_run_bits(run, off + 22, 16), b, sizeof(b));
            rkf_date_str((uint16_t)rkf_run_bits(run, off + 38, 14), c, sizeof(c));
            rkf_time_str((uint16_t)rkf_run_bits(run, off + 52, 16), d, sizeof(d));
            PrintAndLogEx(INFO, RKF_LABEL " " _YELLOW_("%s %s") " .. " _YELLOW_("%s %s"),
                          "  TCCO validity", a, b, c, d);
            rkf_date_str((uint16_t)rkf_run_bits(run, off + 76, 14), a, sizeof(a));
            PrintAndLogEx(INFO, RKF_LABEL "   duration %u, first use by %s, %u journeys", "",
                          (uint8_t)rkf_run_bits(run, off + 68, 8), a,
                          (uint8_t)rkf_run_bits(run, off + 90, 8));
            PrintAndLogEx(INFO, RKF_LABEL "   not valid on days %02X, time codes %02X", "",
                          (uint8_t)rkf_run_bits(run, off + 98, 8),
                          (uint8_t)rkf_run_bits(run, off + 106, 8));
            break;

        case RKF_ID_TCTI_PERIOD:
            rkf_date_str((uint16_t)rkf_run_bits(run, off + 8, 14), a, sizeof(a));
            rkf_time_str((uint16_t)rkf_run_bits(run, off + 22, 16), b, sizeof(b));
            rkf_date_str((uint16_t)rkf_run_bits(run, off + 38, 14), c, sizeof(c));
            rkf_time_str((uint16_t)rkf_run_bits(run, off + 52, 16), d, sizeof(d));
            PrintAndLogEx(INFO, RKF_LABEL " " _YELLOW_("%s %s") " .. " _YELLOW_("%s %s"),
                          "  TCTI validity", a, b, c, d);
            break;

        case RKF_ID_VAL_DISTANCE:
            PrintAndLogEx(INFO, RKF_LABEL " AID 0x%03X place %u -> AID 0x%03X place %u", "  Distance",
                          (uint16_t)rkf_run_bits(run, off + 8, 12),
                          (uint16_t)rkf_run_bits(run, off + 20, 14),
                          (uint16_t)rkf_run_bits(run, off + 34, 12),
                          (uint16_t)rkf_run_bits(run, off + 46, 14));
            PrintAndLogEx(INFO, RKF_LABEL "   distance %u, run %u, interchanges %u", "",
                          (uint16_t)rkf_run_bits(run, off + 60, 12),
                          (uint16_t)rkf_run_bits(run, off + 72, 12),
                          (uint8_t)rkf_run_bits(run, off + 136, 6));
            PrintAndLogEx(INFO, RKF_LABEL "   via AID 0x%03X place %u, AID 0x%03X place %u", "",
                          (uint16_t)rkf_run_bits(run, off + 84, 12),
                          (uint16_t)rkf_run_bits(run, off + 96, 14),
                          (uint16_t)rkf_run_bits(run, off + 110, 12),
                          (uint16_t)rkf_run_bits(run, off + 122, 14));
            break;

        case RKF_ID_VAL_ROUTE:
            PrintAndLogEx(INFO, RKF_LABEL " AID 0x%03X route %u", "  Route",
                          (uint16_t)rkf_run_bits(run, off + 8, 12),
                          (uint16_t)rkf_run_bits(run, off + 20, 12));
            break;

        case RKF_ID_VAL_ZONE:
            PrintAndLogEx(INFO, RKF_LABEL " AID 0x%03X zone %u", "  Zone",
                          (uint16_t)rkf_run_bits(run, off + 8, 12),
                          (uint16_t)rkf_run_bits(run, off + 20, 14));
            break;

        case RKF_ID_TCCO_ISSUING:
            rkf_date_str((uint16_t)rkf_run_bits(run, off + 24, 14), a, sizeof(a));
            rkf_time_str((uint16_t)rkf_run_bits(run, off + 38, 16), b, sizeof(b));
            PrintAndLogEx(INFO, RKF_LABEL " %u journeys issued, %u in period, last %s %s", "  TCCO issuing",
                          (uint8_t)rkf_run_bits(run, off + 8, 8),
                          (uint8_t)rkf_run_bits(run, off + 16, 8), a, b);
            break;

        case RKF_ID_TCTI_ISSUING:
            rkf_date_str((uint16_t)rkf_run_bits(run, off + 8, 14), a, sizeof(a));
            rkf_time_str((uint16_t)rkf_run_bits(run, off + 22, 16), b, sizeof(b));
            PrintAndLogEx(INFO, RKF_LABEL " last validation %s %s", "  TCTI issuing", a, b);
            break;

        case RKF_ID_CUSTOMER:
            PrintAndLogEx(INFO, RKF_LABEL " " _YELLOW_("%010llu"), "  Customer no",
                          (unsigned long long)rkf_run_bits(run, off + 8, 34));
            break;

        case RKF_ID_CLASS: {
            uint8_t pclass = (uint8_t)rkf_run_bits(run, off + 8, 2);
            PrintAndLogEx(INFO, RKF_LABEL " %s", "  Class", rkf_passenger_class_name(pclass));
            for (uint8_t i = 0; i < 3; i++) {
                uint8_t type = (uint8_t)rkf_run_bits(run, off + 10 + (14 * i), 8);
                uint8_t total = (uint8_t)rkf_run_bits(run, off + 18 + (14 * i), 6);
                if (total != 0) {
                    PrintAndLogEx(INFO, RKF_LABEL "   %u x %s ( type %u )", "", total,
                                  rkf_passenger_type_name(type), type);
                }
            }
            break;
        }

        case RKF_ID_VALIDATION:
            PrintAndLogEx(INFO, RKF_LABEL " %s, %s, level %u", "  Validation",
                          rkf_validation_model_name((uint8_t)rkf_run_bits(run, off + 8, 2)),
                          rkf_validation_status_name((uint8_t)rkf_run_bits(run, off + 10, 2)),
                          (uint8_t)rkf_run_bits(run, off + 12, 2));
            break;

        default:
            break;
    }
}

// Walk the identifier chain over a run of sectors. An element ends at the MAC
// group, which the specification pins to the last block of the element, so the
// next element starts at the following block boundary.
static bool rkf_block_is_blank(const uint8_t *blk) {
    for (uint8_t i = 0; i < MFBLOCK_SIZE; i++) {
        if (blk[i] != 0x00 && blk[i] != 0xFF) {
            return false;
        }
    }
    return true;
}

static void rkf_print_chain(const uint8_t *dump, size_t dumplen, uint8_t sector,
                            uint8_t nsectors, uint16_t aid, uint16_t pix, uint16_t cu) {

    if (rkf_block(dump, dumplen, sector, 0) == NULL) {
        return;
    }

    uint8_t total = 0;
    for (uint8_t k = 0; k < nsectors; k++) {
        total += rkf_data_blocks(sector + k);
    }

    rkf_run_t run = { .dump = dump, .dumplen = dumplen, .sector = sector, .nblocks = total };

    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("application object") " --- sector %u..%u, AID 0x%03X ( %s ), PIX 0x%03X",
                  sector, sector + nsectors - 1, aid, rkf_aid_name(aid), pix);

    uint16_t off = 0;
    uint8_t element = 1;
    bool started = false;

    while (off < (uint16_t)run.nblocks * RKF_USABLE_BITS) {

        uint8_t id = (uint8_t)rkf_run_bits(&run, off, 8);
        uint8_t size = rkf_group_size(id);

        if (size == 0 || (off + size) > ((uint16_t)run.nblocks * RKF_USABLE_BITS)) {
            // not a group, resume at the next block boundary
            uint16_t blk = off / RKF_USABLE_BITS;
            if (off % RKF_USABLE_BITS == 0) {
                const uint8_t *raw = rkf_run_block(&run, (uint8_t)blk);
                if (raw != NULL && rkf_block_is_blank(raw) == false) {
                    PrintAndLogEx(INFO, "  block %u  " _YELLOW_("not decoded") "  %s  checksum ( %s )", blk,
                                  sprint_hex_inrow(raw, MFBLOCK_SIZE), rkf_checksum_str(raw));
                }
            }
            blk++;
            if (blk >= run.nblocks) {
                break;
            }
            off = blk * RKF_USABLE_BITS;
            started = false;
            continue;
        }

        if (started == false) {
            PrintAndLogEx(INFO, "  " _CYAN_("element %u") " from block %u", element, off / RKF_USABLE_BITS);
            element++;
            started = true;
        }

        rkf_print_group(&run, off, id, cu);

        if (id == RKF_ID_MAC) {
            uint16_t blk = (off / RKF_USABLE_BITS) + 1;
            if (blk >= run.nblocks) {
                break;
            }
            off = blk * RKF_USABLE_BITS;
            started = false;
            continue;
        }

        off += size;
    }
}

//-----------------------------------------------------------------------------
// Top level
//-----------------------------------------------------------------------------

static void rkf_print_application(const uint8_t *dump, size_t dumplen, uint8_t sector,
                                  uint8_t nsectors, uint16_t aid, uint16_t pix,
                                  const rkf_tcas_t *tcas, uint16_t cu) {

    const uint8_t *first = rkf_block(dump, dumplen, sector, 0);
    uint8_t id = (first != NULL) ? first[0] : 0;
    uint8_t status = (sector < RKF_SECTORS) ? tcas->sector_status[sector] : 0;

    switch (id) {
        case RKF_ID_TCPU_STATIC:
            rkf_print_tcpu(dump, dumplen, sector, status, cu);
            break;
        case RKF_ID_TCDB:
            rkf_print_tcdb(dump, dumplen, sector, status);
            break;
        case RKF_ID_TCCP:
            rkf_print_tccp(dump, dumplen, sector);
            break;
        case RKF_ID_TCST:
            for (uint8_t k = 0; k < nsectors; k++) {
                rkf_print_tcst(dump, dumplen, sector + k, cu, rkf_log_slot(tcas, sector + k));
            }
            break;
        case RKF_ID_TCEL_RECORD:
            rkf_print_tcel(dump, dumplen, sector, nsectors, tcas->event_log_record, cu);
            break;
        default:
            rkf_print_chain(dump, dumplen, sector, nsectors, aid, pix, cu);
            break;
    }
}

// A card is free to leave the directory empty, so when it names no application
// object, fall back to the identifiers of RKF-0022 section 8.1.
static uint8_t rkf_scan_applications(const uint8_t *dump, size_t dumplen,
                                     const rkf_tcas_t *tcas, uint16_t cu,
                                     uint8_t tcas_sector) {

    uint8_t nsectors = rkf_sector_count(dumplen);
    uint8_t found = 0;

    for (uint8_t s = RKF_TCDI_SECTOR + 1; s < nsectors; s++) {

        if (s == tcas_sector) {
            continue;
        }

        const uint8_t *blk = rkf_block(dump, dumplen, s, 0);
        if (blk == NULL) {
            continue;
        }

        uint8_t id = blk[0];
        if (id != RKF_ID_TCPU_STATIC && id != RKF_ID_TCDB && id != RKF_ID_TCCP &&
                id != RKF_ID_TCST && id != RKF_ID_TCEL_RECORD &&
                id != RKF_ID_TCTI_HEADER && id != RKF_ID_TCCO_HEADER) {
            continue;
        }

        // an object runs on while the following sectors open with the same id
        uint8_t n = 1;
        while ((s + n) < nsectors && (s + n) != tcas_sector) {
            const uint8_t *nxt = rkf_block(dump, dumplen, s + n, 0);
            if (nxt == NULL || nxt[0] != id) {
                break;
            }
            n++;
        }

        rkf_print_application(dump, dumplen, s, n, 0, 0, tcas, cu);
        found++;
        s += (n - 1);
    }
    return found;
}

int rkf_parser_parse(const uint8_t *dump, size_t dumplen) {

    if (is_valid_rkf_card(dump, dumplen) == false) {
        return PM3_EINVARG;
    }

    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("RKF travel card") " ------------------------");
    PrintAndLogEx(INFO, "Resekortsforeningen i Norden, type CL-1");

    const uint8_t *cmi = rkf_block(dump, dumplen, RKF_CMI_SECTOR, RKF_CMI_BLOCK);
    if (cmi) {
        rkf_print_cmi(cmi);
    }

    rkf_tcci_t tcci = {0};
    const uint8_t *p = rkf_block(dump, dumplen, RKF_CMI_SECTOR, RKF_TCCI_BLOCK);
    if (p) {
        rkf_read_tcci(p, &tcci);
        rkf_print_tcci(&tcci);
    }

    uint16_t aid[RKF_SECTORS] = {0};
    uint16_t pix[RKF_SECTORS] = {0};
    rkf_read_tcdi(dump, dumplen, aid, pix);

    rkf_tcas_t tcas1 = {0};
    rkf_tcas_t tcas2 = {0};
    bool have_tcas2 = false;

    // The specification fixes TCAS (1) at S0:B2 and puts TCAS (2) in the first
    // block of the sector the directory marks with AID 05 H, but a card is free
    // to carry the support layer elsewhere, so both are located by scan.
    uint8_t s1 = 0, b1 = 0;
    if (rkf_find_tcas(dump, dumplen, 0xFF, 0xFF, &s1, &b1)) {
        p = rkf_block(dump, dumplen, s1, b1);
        rkf_read_tcas(p, &tcas1);
        rkf_print_tcas(&tcas1, 1, s1, b1);

        uint8_t s2 = 0, b2 = 0;
        if (rkf_find_tcas(dump, dumplen, s1, b1, &s2, &b2)) {
            p = rkf_block(dump, dumplen, s2, b2);
            rkf_read_tcas(p, &tcas2);
            rkf_print_tcas(&tcas2, 2, s2, b2);
            have_tcas2 = true;
        }
    }

    if (have_tcas2) {
        bool same = (memcmp(&tcas1, &tcas2, sizeof(rkf_tcas_t)) == 0);
        PrintAndLogEx(INFO, "");
        PrintAndLogEx(INFO, RKF_LABEL " %s", "TCAS instances",
                      same ? _GREEN_("identical")
                      : _YELLOW_("differ"));
        if (same == false) {
            PrintAndLogEx(INFO, RKF_LABEL "   RKF-0022 4.3.4.2 reads a difference as an interrupted write,", "");
            PrintAndLogEx(INFO, RKF_LABEL "   and takes the first consistent instance", "");
        }
    }

    rkf_print_tcdi(dump, dumplen, aid, pix);

    uint8_t decoded = 0;

    // Walk the directory. A sector with PIX 01 H continues the preceding
    // application object, RKF-0022 section 7.5 rule 10.
    for (uint8_t s = 1; s < RKF_SECTORS; s++) {

        if (aid[s] <= RKF_AID_RESERVED || aid[s] == RKF_AID_TCDI || aid[s] == RKF_AID_TCAS2) {
            continue;
        }
        if (pix[s] == RKF_PIX_CONT) {
            continue;
        }

        uint8_t n = 1;
        while ((s + n) < RKF_SECTORS && aid[s + n] == aid[s] && pix[s + n] == RKF_PIX_CONT) {
            n++;
        }

        decoded++;

        switch (aid[s]) {
            case RKF_AID_TCEL:
                rkf_print_tcel(dump, dumplen, s, n, tcas1.event_log_record, tcci.currency_unit);
                break;

            case RKF_AID_TCPU:
                rkf_print_tcpu(dump, dumplen, s, tcas1.sector_status[s], tcci.currency_unit);
                break;

            case RKF_AID_TCPU_DATA:
                PrintAndLogEx(INFO, "");
                PrintAndLogEx(INFO, "--- " _CYAN_("PTA area bound to the purse") " --- sector %u, "
                              _YELLOW_("PTA specific"), s);
                for (uint8_t b = 0; b < 3; b++) {
                    const uint8_t *blk = rkf_block(dump, dumplen, s, b);
                    if (blk) {
                        PrintAndLogEx(INFO, "  block %u  %s", b, sprint_hex_inrow(blk, MFBLOCK_SIZE));
                    }
                }
                break;

            default:
                rkf_print_application(dump, dumplen, s, n, aid[s], pix[s], &tcas1, tcci.currency_unit);
                break;
        }

        s += (n - 1);
    }

    if (tcci.card_version != 2) {
        PrintAndLogEx(INFO, "");
        PrintAndLogEx(WARNING, "Card reports version %u. The application layouts below are the",
                      tcci.card_version);
        PrintAndLogEx(WARNING, "version 2 layouts of RKF-0023, so field positions may not hold.");
    }

    if (decoded == 0) {
        PrintAndLogEx(INFO, "");
        PrintAndLogEx(INFO, "Directory names no application object, scanning for identifiers");
        decoded = rkf_scan_applications(dump, dumplen, &tcas1, tcci.currency_unit, s1);
        if (decoded == 0) {
            PrintAndLogEx(INFO, "none found");
        }
    }

    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "MAC values are not checked. RKF-0019 holds the MAC key in its edition A,");
    PrintAndLogEx(INFO, "which was only distributed to transport authorities and their suppliers");
    return PM3_SUCCESS;
}

//-----------------------------------------------------------------------------
// Self test
//-----------------------------------------------------------------------------

#define RKF_T_CSN           0x11223344
#define RKF_T_PROVIDER      0x0E0
#define RKF_T_VALID_END     10956       // 2026-12-31
#define RKF_T_CURRENCY      0x0752      // SEK, main unit
#define RKF_T_TXN           0x5A
#define RKF_T_PURSE_SERIAL  0xDEADBEEF
#define RKF_T_PURSE_VALUE   (-12345)
#define RKF_T_DEPOSIT       6000
#define RKF_T_CUSTOMER      1234567890ULL
#define RKF_T_TICKET_SERIAL 0xCAFEBABE

#define RKF_T_SEC_PURSE     2
#define RKF_T_SEC_TCEL      3
#define RKF_T_SEC_TCAS2     5
#define RKF_T_SEC_TICKET    6

static uint8_t *rkf_test_block(uint8_t *dump, uint8_t sector, uint8_t block) {
    return dump + ((size_t)(mfFirstBlockOfSector(sector) + block) * MFBLOCK_SIZE);
}

static void rkf_set_checksum(uint8_t *blk) {
    uint8_t d[MFBLOCK_SIZE - 1];
    memcpy(d, blk, sizeof(d));
    blk[MFBLOCK_SIZE - 1] = (uint8_t)CRC8Mad(d, sizeof(d));
}

static void rkf_set_dir(uint8_t *dump, uint8_t sector, uint16_t aid, uint16_t pix) {
    uint8_t b = (sector - 1) / 5;
    uint8_t i = (sector - 1) % 5;
    uint8_t *blk = rkf_test_block(dump, RKF_TCDI_SECTOR, b);
    rkf_set_bits(blk, 24 * i, 12, aid);
    rkf_set_bits(blk, (24 * i) + 12, 12, pix);
}

static void rkf_build_selftest_card(uint8_t *dump) {

    memset(dump, 0, MIFARE_1K_MAX_BYTES);

    // CMI, the manufacturer block, check byte over the serial
    uint8_t *blk = rkf_test_block(dump, 0, RKF_CMI_BLOCK);
    rkf_set_bits(blk, 0, 32, RKF_T_CSN);
    rkf_set_bits(blk, 32, 8, blk[0] ^ blk[1] ^ blk[2] ^ blk[3]);
    memset(blk + 5, 0xA5, 11);

    // TCCI
    blk = rkf_test_block(dump, 0, RKF_TCCI_BLOCK);
    rkf_set_bits(blk, 0, 16, 0);
    rkf_set_bits(blk, 16, 6, 2);
    rkf_set_bits(blk, 22, 12, RKF_T_PROVIDER);
    rkf_set_bits(blk, 34, 14, RKF_T_VALID_END);
    rkf_set_bits(blk, 48, 8, 0x01);
    rkf_set_bits(blk, 56, 16, RKF_T_CURRENCY);
    rkf_set_bits(blk, 72, 6, 1);
    rkf_set_bits(blk, 78, 2, 0);
    rkf_set_bits(blk, 80, 6, 3);
    rkf_set_bits(blk, 112, 16, 0x1234);

    // TCDI
    rkf_set_dir(dump, 1, RKF_AID_TCDI, 0x000);
    rkf_set_dir(dump, RKF_T_SEC_PURSE, RKF_AID_TCPU, 0x000);
    rkf_set_dir(dump, RKF_T_SEC_TCEL, RKF_AID_TCEL, 0x000);
    rkf_set_dir(dump, RKF_T_SEC_TCEL + 1, RKF_AID_TCEL, RKF_PIX_CONT);
    rkf_set_dir(dump, RKF_T_SEC_TCAS2, RKF_AID_TCAS2, 0x000);
    rkf_set_dir(dump, RKF_T_SEC_TICKET, RKF_T_PROVIDER, 0x064);
    rkf_set_dir(dump, RKF_T_SEC_TICKET + 1, RKF_T_PROVIDER, RKF_PIX_CONT);

    for (uint8_t b = 0; b < 3; b++) {
        rkf_set_checksum(rkf_test_block(dump, RKF_TCDI_SECTOR, b));
    }

    // TCAS, both instances identical
    uint8_t tcas[MFBLOCK_SIZE] = {0};
    rkf_set_bits(tcas, 0, 8, RKF_TCAS_IDENTIFIER);
    rkf_set_bits(tcas, 8, 6, 2);
    rkf_set_bits(tcas, 14 + (2 * RKF_T_SEC_PURSE), 2, 2);
    rkf_set_bits(tcas, 14 + (2 * RKF_T_SEC_TICKET), 2, 1);
    rkf_set_bits(tcas, 46, 8, RKF_T_TXN);
    rkf_set_bits(tcas, 54, 4, 4);
    rkf_set_bits(tcas, 58, 4, 0);
    rkf_set_bits(tcas, 94, 2, 0);
    rkf_set_bits(tcas, 96, 6, 3);
    rkf_set_bits(tcas, 112, 16, 0xBEEF);
    memcpy(rkf_test_block(dump, 0, RKF_TCAS_BLOCK), tcas, MFBLOCK_SIZE);
    memcpy(rkf_test_block(dump, RKF_T_SEC_TCAS2, 0), tcas, MFBLOCK_SIZE);

    // TCPU static and both dynamic blocks
    blk = rkf_test_block(dump, RKF_T_SEC_PURSE, 0);
    rkf_set_bits(blk, 0, 8, RKF_ID_TCPU_STATIC);
    rkf_set_bits(blk, 8, 6, 2);
    rkf_set_bits(blk, 14, 12, RKF_T_PROVIDER);
    rkf_set_bits(blk, 26, 32, RKF_T_PURSE_SERIAL);
    rkf_set_bits(blk, 58, 14, 8000);
    rkf_set_bits(blk, 72, 4, 0);
    rkf_set_bits(blk, 76, 24, 1000);
    rkf_set_bits(blk, 100, 24, 20000);

    for (uint8_t b = 1; b <= 2; b++) {
        blk = rkf_test_block(dump, RKF_T_SEC_PURSE, b);
        rkf_set_bits(blk, 0, 16, 0x0100 + b);
        rkf_set_bits(blk, 16, 14, RKF_T_VALID_END);
        rkf_set_bits(blk, 30, 24, (uint32_t)(RKF_T_PURSE_VALUE) & 0xFFFFFF);
        rkf_set_bits(blk, 54, 8, 0x01);
        rkf_set_bits(blk, 62, 20, RKF_T_DEPOSIT);
        rkf_set_bits(blk, 82, 2, 1);
        rkf_set_bits(blk, 112, 16, 0xABCD);
    }

    // TCEL, one charge record in slot 4
    blk = rkf_test_block(dump, RKF_T_SEC_TCEL + 1, 1);
    rkf_set_bits(blk, 0, 8, RKF_ID_TCEL_RECORD);
    rkf_set_bits(blk, 8, 14, 10000);
    rkf_set_bits(blk, 22, 16, (13u << 11) | (45u << 5) | 15u);
    rkf_set_bits(blk, 38, 12, RKF_T_PROVIDER);
    rkf_set_bits(blk, 50, 16, 0x0042);
    rkf_set_bits(blk, 66, 24, 987654);
    rkf_set_bits(blk, 90, 6, 0x08);
    rkf_set_bits(blk, 96, 24, 5000);
    rkf_set_checksum(blk);

    // A ticket. The static element spans blocks 0 and 1 because its customer
    // number crosses the checksum byte of block 0; the dynamic element then has
    // to start at the next block boundary and is closed by the MAC group.
    blk = rkf_test_block(dump, RKF_T_SEC_TICKET, 0);
    rkf_run_set_bits(blk, 0, 8, RKF_ID_TCTI_HEADER);
    rkf_run_set_bits(blk, 8, 6, 2);
    rkf_run_set_bits(blk, 14, 8, RKF_ID_MANDATORY);
    rkf_run_set_bits(blk, 22, 12, RKF_T_PROVIDER);
    rkf_run_set_bits(blk, 34, 12, 0x064);
    rkf_run_set_bits(blk, 46, 16, 0x0042);
    rkf_run_set_bits(blk, 62, 32, RKF_T_TICKET_SERIAL);
    rkf_run_set_bits(blk, 94, 8, 0x01);
    rkf_run_set_bits(blk, 102, 8, RKF_ID_CUSTOMER);
    rkf_run_set_bits(blk, 110, 34, RKF_T_CUSTOMER);

    rkf_run_set_bits(blk, 240, 8, RKF_ID_DYN_SINGLE);
    rkf_run_set_bits(blk, 248, 8, RKF_ID_TCTI_PERIOD);
    rkf_run_set_bits(blk, 256, 14, 10000);
    rkf_run_set_bits(blk, 270, 16, (6u << 11) | (30u << 5));
    rkf_run_set_bits(blk, 286, 14, 10001);
    rkf_run_set_bits(blk, 300, 16, (23u << 11) | (59u << 5) | 29u);
    rkf_run_set_bits(blk, 316, 8, RKF_ID_MAC);
    rkf_run_set_bits(blk, 324, 2, 0);
    rkf_run_set_bits(blk, 326, 6, 3);
    rkf_set_bits(rkf_test_block(dump, RKF_T_SEC_TICKET, 2), 112, 16, 0x5AA5);
}

static bool rkf_check(const char *what, uint64_t got, uint64_t want) {
    bool ok = (got == want);
    PrintAndLogEx(INFO, "  %-24s %12llu  ( %s )", what, (unsigned long long)got,
                  ok ? _GREEN_("ok") : _RED_("fail"));
    return ok;
}

static bool rkf_check_str(const char *what, const char *got, const char *want) {
    bool ok = (strcmp(got, want) == 0);
    PrintAndLogEx(INFO, "  %-24s %12s  ( %s )", what, got, ok ? _GREEN_("ok") : _RED_("fail"));
    return ok;
}

int rkf_selftest(void) {

    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "Testing RKF travel card decode");

    uint8_t dump[MIFARE_1K_MAX_BYTES];
    rkf_build_selftest_card(dump);

    if (is_valid_rkf_card(dump, sizeof(dump)) == false) {
        PrintAndLogEx(FAILED, "  card not recognised ( " _RED_("fail") " )");
        return PM3_ESOFT;
    }

    bool ok = true;
    char buf[40];

    const uint8_t *cmi = rkf_block(dump, sizeof(dump), 0, RKF_CMI_BLOCK);
    ok &= rkf_check("card serial", rkf_bits(cmi, 0, 32), RKF_T_CSN);
    ok &= rkf_check("check byte", rkf_bits(cmi, 32, 8),
                    (uint64_t)(cmi[0] ^ cmi[1] ^ cmi[2] ^ cmi[3]));

    rkf_tcci_t tcci;
    rkf_read_tcci(rkf_block(dump, sizeof(dump), 0, RKF_TCCI_BLOCK), &tcci);
    ok &= rkf_check("card provider", tcci.card_provider, RKF_T_PROVIDER);
    ok &= rkf_check("currency unit", tcci.currency_unit, RKF_T_CURRENCY);

    rkf_date_str(tcci.validity_end, buf, sizeof(buf));
    ok &= rkf_check_str("valid until", buf, "2026-12-31");

    rkf_currency_str(tcci.currency_unit, buf, sizeof(buf));
    ok &= rkf_check_str("currency", buf, "SEK, main unit");

    rkf_tcas_t tcas1, tcas2;
    rkf_read_tcas(rkf_block(dump, sizeof(dump), 0, RKF_TCAS_BLOCK), &tcas1);
    rkf_read_tcas(rkf_block(dump, sizeof(dump), RKF_T_SEC_TCAS2, 0), &tcas2);
    ok &= rkf_check("tcas identifier", tcas1.identifier, RKF_TCAS_IDENTIFIER);
    ok &= rkf_check("tcas transaction no", tcas1.transaction_no, RKF_T_TXN);
    ok &= rkf_check("tcas event record", tcas1.event_log_record, 4);
    ok &= rkf_check("tcas purse status", tcas1.sector_status[RKF_T_SEC_PURSE], 2);
    ok &= rkf_check("tcas instances equal", (memcmp(&tcas1, &tcas2, sizeof(tcas1)) == 0), 1);

    uint16_t aid[RKF_SECTORS], pix[RKF_SECTORS];
    rkf_read_tcdi(dump, sizeof(dump), aid, pix);
    ok &= rkf_check("dir sector 1 aid", aid[1], RKF_AID_TCDI);
    ok &= rkf_check("dir purse aid", aid[RKF_T_SEC_PURSE], RKF_AID_TCPU);
    ok &= rkf_check("dir event log aid", aid[RKF_T_SEC_TCEL], RKF_AID_TCEL);
    ok &= rkf_check("dir continuation pix", pix[RKF_T_SEC_TCEL + 1], RKF_PIX_CONT);
    ok &= rkf_check("dir ticket aid", aid[RKF_T_SEC_TICKET], RKF_T_PROVIDER);

    const uint8_t *purse = rkf_block(dump, sizeof(dump), RKF_T_SEC_PURSE, 0);
    ok &= rkf_check("purse serial", rkf_bits(purse, 26, 32), RKF_T_PURSE_SERIAL);

    const uint8_t *dyn = rkf_block(dump, sizeof(dump), RKF_T_SEC_PURSE, 2);
    int32_t value = rkf_signed(rkf_bits(dyn, 30, 24), 24);
    ok &= rkf_check("purse value negative", (value == RKF_T_PURSE_VALUE), 1);
    rkf_money_str(value, tcci.currency_unit, buf, sizeof(buf));
    ok &= rkf_check_str("purse value", buf, "-12345 SEK");
    ok &= rkf_check("purse deposit", rkf_bits(dyn, 62, 20), RKF_T_DEPOSIT);

    const uint8_t *ev = rkf_block(dump, sizeof(dump), RKF_T_SEC_TCEL + 1, 1);
    ok &= rkf_check("event identifier", rkf_bits(ev, 0, 8), RKF_ID_TCEL_RECORD);
    ok &= rkf_check("event code", rkf_bits(ev, 90, 6), 0x08);
    ok &= rkf_check("event device txn", rkf_bits(ev, 66, 24), 987654);
    ok &= rkf_check("event checksum", rkf_checksum_ok(ev), 1);
    ok &= rkf_check("directory checksum", rkf_checksum_ok(rkf_block(dump, sizeof(dump), RKF_TCDI_SECTOR, 0)), 1);

    // RKF-0022 7.7.1 "standard CRC-8" is CRC-8/MIFARE-MAD: a block of 15 zero
    // bytes checksums to 0B, as seen on real cards
    uint8_t zeros[MFBLOCK_SIZE] = {0};
    zeros[MFBLOCK_SIZE - 1] = 0x0B;
    ok &= rkf_check("crc8 of 15 zero bytes", rkf_checksum_ok(zeros), 1);
    rkf_time_str((uint16_t)rkf_bits(ev, 22, 16), buf, sizeof(buf));
    ok &= rkf_check_str("event time", buf, "13:45:30");

    // The customer number of the ticket crosses the block boundary, stepping
    // over the checksum byte of block 0
    rkf_run_t run = { .dump = dump, .dumplen = sizeof(dump), .sector = RKF_T_SEC_TICKET, .nblocks = 6 };
    ok &= rkf_check("ticket header id", rkf_run_bits(&run, 0, 8), RKF_ID_TCTI_HEADER);
    ok &= rkf_check("ticket serial", rkf_run_bits(&run, 62, 32), RKF_T_TICKET_SERIAL);
    ok &= rkf_check("ticket customer no", rkf_run_bits(&run, 110, 34), RKF_T_CUSTOMER);
    ok &= rkf_check("dynamic element id", rkf_run_bits(&run, 240, 8), RKF_ID_DYN_SINGLE);
    ok &= rkf_check("ticket validity id", rkf_run_bits(&run, 248, 8), RKF_ID_TCTI_PERIOD);
    ok &= rkf_check("ticket mac id", rkf_run_bits(&run, 316, 8), RKF_ID_MAC);

    rkf_date_str((uint16_t)rkf_run_bits(&run, 256, 14), buf, sizeof(buf));
    ok &= rkf_check_str("ticket valid from", buf, "2024-05-19");
    rkf_time_str((uint16_t)rkf_run_bits(&run, 270, 16), buf, sizeof(buf));
    ok &= rkf_check_str("ticket valid from", buf, "06:30:00");
    rkf_date_str((uint16_t)rkf_run_bits(&run, 286, 14), buf, sizeof(buf));
    ok &= rkf_check_str("ticket valid to", buf, "2024-05-20");
    rkf_time_str((uint16_t)rkf_run_bits(&run, 300, 16), buf, sizeof(buf));
    ok &= rkf_check_str("ticket valid to", buf, "23:59:58");
    ok &= rkf_check("ticket mac value",
                    rkf_bits(rkf_block(dump, sizeof(dump), RKF_T_SEC_TICKET, 2), 112, 16), 0x5AA5);

    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "Decoding the self test card");
    rkf_parser_parse(dump, sizeof(dump));

    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "RKF self test ( %s )", ok ? _GREEN_("ok") : _RED_("fail"));
    return ok ? PM3_SUCCESS : PM3_ESOFT;
}
