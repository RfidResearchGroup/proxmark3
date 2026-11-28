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
// JavaCard / GlobalPlatform static lookup tables:
//   - Known factory-default key sets
//   - IC fabricator codes and card fingerprint signatures (CPLC, OS ID, ATS)
//   - Well-known Security Domain / application AIDs
//
// Format: Plain C arrays for zero-dependency, fast lookup.
//         Add new entries at the bottom of each section.
//-----------------------------------------------------------------------------

#ifndef CMDHFJAVACARD_DB_H__
#define CMDHFJAVACARD_DB_H__

#include <stdint.h>
#include <stddef.h>
#include <string.h>

//=============================================================================
// Known factory-default key sets
//=============================================================================

// SCP type flags stored in gp_default_key_t.scp_flags
#define GP_DB_SCP02    0x02
#define GP_DB_SCP03    0x04
#define GP_DB_SCP_ANY  0x06

typedef struct {
    const char   *name;         // human-readable label
    uint8_t       key[16];      // 16-byte master key
    uint8_t       scp_flags;    // GP_DB_SCP02 | GP_DB_SCP03
    const char   *notes;        // optional notes
} gp_default_key_t;

// Keys are the same value for ENC / MAC / DEK unless notes say otherwise.
// Every candidate is checked offline against the card cryptogram returned by a
// single INITIALIZE UPDATE, so the list never causes failed EXTERNAL AUTHENTICATE
// attempts. Keep each key value exactly once.
static const gp_default_key_t GP_DEFAULT_KEYS[] = {
    // ── Most common GlobalPlatform test keys ──────────────────────────────
    {
        "GP Test Key (404142...4F)",
        { 0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,
          0x48,0x49,0x4A,0x4B,0x4C,0x4D,0x4E,0x4F },
        GP_DB_SCP_ANY,
        "GP/GPPro test key; NXP JCOP2/JCOP3/JCOP4 SCP02+SCP03 factory default"
    },
    {
        "Shifted GP Test Key (434445...52)",
        { 0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4A,
          0x4B,0x4C,0x4D,0x4E,0x4F,0x50,0x51,0x52 },
        GP_DB_SCP_ANY,
        "Default test key variant reported as the 434445 key"
    },
    {
        "All-Zeros Key",
        { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
          0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 },
        GP_DB_SCP_ANY,
        "Factory blank / test key (also seen on Infineon samples)"
    },
    {
        "All-Ones Key (FF..FF)",
        { 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
          0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF },
        GP_DB_SCP_ANY,
        "Some older cards shipped with 0xFF default"
    },
    // ── Gemalto / Thales ──────────────────────────────────────────────────
    {
        "Gemalto sample key (GEMXPRESSOSAMPLE)",
        { 0x47,0x45,0x4D,0x58,0x50,0x52,0x45,0x53,
          0x53,0x4F,0x53,0x41,0x4D,0x50,0x4C,0x45 },
        GP_DB_SCP02,
        "ASCII 'GEMXPRESSOSAMPLE': Gemalto/Thales GemXpresso / IDCore sample cards"
    },
    // ── G+D (Giesecke+Devrient) ───────────────────────────────────────────
    {
        "G+D StarSign CUT Test Key",
        { 0x47,0x2B,0x44,0x00,0x00,0x00,0x00,0x00,
          0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 },
        GP_DB_SCP02,
        "G+D StarSign CUT sample cards"
    },
    // ── STMicroelectronics ────────────────────────────────────────────────
    {
        "ST33 Default Key",
        { 0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,
          0x39,0x30,0x31,0x32,0x33,0x34,0x35,0x36 },
        GP_DB_SCP02,
        "ST33 / Topaz based cards (numeric ASCII pattern)"
    },
    // ── Generic sequential key pattern ────────────────────────────────────
    {
        "Sequential Key (010203...10)",
        { 0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
          0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10 },
        GP_DB_SCP_ANY,
        "Common alternative test pattern"
    },
};

#define GP_DEFAULT_KEYS_COUNT  (sizeof(GP_DEFAULT_KEYS) / sizeof(GP_DEFAULT_KEYS[0]))

//=============================================================================
// IC Fabricator lookup (CPLC bytes [0..1])
//=============================================================================

typedef struct {
    uint16_t     fab_id;    // IC Fabricator code (big-endian)
    const char  *name;      // Manufacturer name
} gp_ic_fabricator_t;

static const gp_ic_fabricator_t GP_IC_FABRICATORS[] = {
    { 0x3060, "Renesas / Hitachi" },
    { 0x4090, "Infineon Technologies" },
    { 0x4180, "Atmel" },
    { 0x4250, "Samsung Semiconductor" },
    { 0x4790, "NXP Semiconductors" },
    { 0x4856, "Hitachi" },
    { 0x4981, "STMicroelectronics" },
    { 0x5044, "OKI / Lapis" },
    { 0x524B, "Renesas" },
    { 0x6761, "G+D (Giesecke+Devrient)" },
    { 0x6E47, "Gemalto (now Thales)" },
    { 0x7370, "Sagem Morpho" },
    { 0x8100, "Infineon Technologies" },
};

#define GP_IC_FABRICATORS_COUNT  (sizeof(GP_IC_FABRICATORS) / sizeof(GP_IC_FABRICATORS[0]))

static inline const char *gp_ic_fabricator_name(uint16_t fab_id) {
    for (size_t i = 0; i < GP_IC_FABRICATORS_COUNT; i++) {
        if (GP_IC_FABRICATORS[i].fab_id == fab_id)
            return GP_IC_FABRICATORS[i].name;
    }
    return NULL;
}

//=============================================================================
// Card fingerprint signatures
//=============================================================================
//
// Sources (observed values only, nothing extrapolated):
//   [J] JCAlgTest profile database, github.com/crocs-muni/jcalgtest_results
//       (javacard/Profiles/results: CPLC fields of ~95 real cards)
//   [P] pcsc-tools smartcard_list.txt (L. Rousseau): contactless ATRs
//       3B 8n 80 01 <historical bytes> TCK carry the ATS historical bytes
//   [N] NIST CMVP security policies (Gemalto: 4790/5081 = NXP P5CC081)
//   [H] verified on hardware with this tool
//
// One IC type usually runs several products (NXP D321 = J3R110/150/180/200).
// The OS release date/level separates e.g. JCOP 2.4.1 from 2.4.2 R2/R3 on the
// same chip, and the OS ID names the OS vendor independently of the silicon
// (Gemalto 1291 was seen on Infineon, NXP and Samsung chips).

#define GP_SIG_IC   0x01   // ic_type must match
#define GP_SIG_OS   0x02   // os_id must match
#define GP_SIG_REL  0x04   // os_date and os_level must match

typedef struct {
    uint16_t    fab_id;     // CPLC IC fabricator
    uint16_t    ic_type;    // CPLC IC type
    uint16_t    os_id;      // CPLC operating system identifier
    uint16_t    os_date;    // CPLC OS release date
    uint16_t    os_level;   // CPLC OS release level
    uint8_t     match;      // GP_SIG_* fields compared in addition to fab_id
    const char *platform;   // short platform name
    const char *notes;      // products / OS release observed with this signature
} gp_card_signature_t;

#define GP_SIG_FULL (GP_SIG_IC | GP_SIG_OS | GP_SIG_REL)
#define GP_SIG_CHIP_OS (GP_SIG_IC | GP_SIG_OS)

static const gp_card_signature_t GP_CARD_SIGNATURES[] = {
    // ---- NXP JCOP 4 (SmartMX3) ------------------------------------ [J][P][H]
    { 0x4790, 0xD321, 0x4700, 0, 0, GP_SIG_CHIP_OS, "NXP JCOP4 P71D321",
      "JCOP 4 (JC 3.0.5): J3R110 / J3R150 / J3R180 / J3R200, SecID and EMV variants" },
    { 0x4790, 0xD600, 0x4700, 0, 0, GP_SIG_CHIP_OS, "NXP JCOP4 P71D600", "JCOP 4 on P71D600: J3R452" },
    { 0x4790, 0x6B64, 0x4700, 0xE4D8, 0x0300, GP_SIG_FULL, "NXP JCOP (SmartMX2)",
      "JCOP on SmartMX2, product not identified" },
    // ---- NXP JCOP 3 (SmartMX2 P60) -------------------------------------- [J]
    { 0x4790, 0x0503, 0x8211, 0x6351, 0x0302, GP_SIG_FULL, "NXP JCOP3 P60",
      "JCOP 3 (JC 3.0.4): J3H145 / J3H145G, SecID P60, SCP03 RSA4K" },
    { 0x4790, 0x0503, 0, 0, 0, GP_SIG_IC, "NXP JCOP3 P60", "J3H family (OS release not in database)" },
    // ---- NXP JCOP 2.4.x (SmartMX P5) ------------------------------------ [J]
    { 0x4790, 0x5167, 0x4791, 0x0078, 0x3400, GP_SIG_FULL, "NXP JCOP 2.4.1", "JCOP 31 v2.4.1 72K / CJ2A081 (JC 2.2.2)" },
    { 0x4790, 0x5167, 0x4791, 0x2081, 0x3B00, GP_SIG_FULL, "NXP JCOP 2.4.2 R2", "J2D081 (JC 3.0.1)" },
    { 0x4790, 0x5167, 0x4791, 0x2348, 0x4000, GP_SIG_FULL, "NXP JCOP 2.4.2 R3", "J2E081 (JC 3.0.1)" },
    { 0x4790, 0x5168, 0x4791, 0x0078, 0x3400, GP_SIG_FULL, "NXP JCOP 2.4.1", "J3A081 (JC 2.2.2)" },
    { 0x4790, 0x5168, 0x4791, 0x2348, 0x4000, GP_SIG_FULL, "NXP JCOP 2.4.2 R3", "J3E081 (JC 3.0.1), also sold as Feitian K9" },
    { 0x4790, 0x5074, 0x4791, 0x2348, 0x4000, GP_SIG_FULL, "NXP JCOP 2.4.2 R3", "JCOP 21 v2.4.2 R3" },
    { 0x4790, 0x5075, 0x4791, 0x2081, 0x3B00, GP_SIG_FULL, "NXP JCOP 2.4.2 R2", "145K class (seen as Fidesmo card)" },
    { 0x4790, 0x5075, 0x4791, 0x2348, 0x4000, GP_SIG_FULL, "NXP JCOP 2.4.2 R3", "J3E145 (JC 3.0.1)" },
    { 0x4790, 0x5040, 0x4791, 0x8102, 0x3100, GP_SIG_FULL, "NXP JCOP 2.4.1", "J3A080 / CJ3A081 (JC 2.2.2)" },
    { 0x4790, 0x5038, 0x4791, 0x8102, 0x3100, GP_SIG_FULL, "NXP JCOP 2.4.1", "J2A080 80K (JC 2.2.2)" },
    { 0x4790, 0x5038, 0x4791, 0x0078, 0x3300, GP_SIG_FULL, "NXP JCOP 2.4.1", "J2A080 (earlier OS release)" },
    { 0x4790, 0x5037, 0x4791, 0x8102, 0x3100, GP_SIG_FULL, "NXP JCOP 2.4.1", "J3A040 (JC 2.2.2)" },
    // ---- NXP JCOP 2.2 / 2.3 --------------------------------------------- [J]
    { 0x4790, 0x5015, 0x4051, 0x5158, 0x2400, GP_SIG_FULL, "NXP JCOP 2.2", "JCOP 21 / JCOP 31 v2.2 36K" },
    { 0x4790, 0x5015, 0x4791, 0x7351, 0x2E00, GP_SIG_FULL, "NXP JCOP 2.3.2", "JCOP 31 v2.3.2" },
    { 0x4790, 0x5017, 0x4051, 0x6138, 0x2700, GP_SIG_FULL, "NXP JCOP 2.2.1", "JCOP 41 v2.2.1 72K" },
    { 0x4790, 0x5106, 0x4051, 0x7095, 0x2B00, GP_SIG_FULL, "NXP JCOP 2.3.1", "JCOP 10.18 v2.3.1" },
    // ---- Third-party OS on NXP silicon --------------------------------- [J][N]
    { 0x4790, 0x5081, 0x1291, 0, 0, GP_SIG_CHIP_OS, "Gemalto on NXP P5CC081", "Gemalto IDCore 10" },
    { 0x4790, 0x5022, 0x1671, 0, 0, GP_SIG_CHIP_OS, "G+D Sm@rtCafe on NXP", "G+D Sm@rtCafe Expert 3.2 72K" },
    // ---- Infineon -------------------------------------------------------- [J]
    { 0x4090, 0x3411, 0x4090, 0, 0, GP_SIG_CHIP_OS, "Infineon SECORA ID X", "SECORA ID X (JC 3.0.5)" },
    { 0x4090, 0x1912, 0x4090, 0, 0, GP_SIG_CHIP_OS, "Infineon SPA1-1", "seen as ThothTrust edition" },
    { 0x4090, 0x7805, 0x4091, 0x2013, 0x0110, GP_SIG_FULL, "Infineon SLE78", "SLE78 JavaCard OS (PIVKey C980, Omni Ring)" },
    { 0x4090, 0x6656, 0x4091, 0, 0, GP_SIG_CHIP_OS, "Infineon JTOP", "JTOP V2 16K" },
    { 0x4090, 0x7794, 0x86AA, 0, 0, GP_SIG_CHIP_OS, "Feitian JavaCOS on Infineon", "JavaCOS A40 / A40CR / FTJCOS" },
    { 0x4090, 0x7892, 0x86AA, 0, 0, GP_SIG_CHIP_OS, "Feitian JavaCOS on Infineon", "JavaCOS A22 / A22CR / JavaSD" },
    { 0x4090, 0x7897, 0x1291, 0, 0, GP_SIG_CHIP_OS, "Gemalto on Infineon", "seen as Czech eID" },
    { 0x4090, 0x6162, 0x1671, 0, 0, GP_SIG_CHIP_OS, "G+D Sm@rtCafe on Infineon", "G+D Sm@rtCafe Expert 4.x" },
    { 0x4090, 0x6172, 0x2041, 0, 0, GP_SIG_CHIP_OS, "Axalto Cyberflex", "Cyberflex Palmera V4" },
    { 0x4090, 0x0062, 0x0011, 0, 0, GP_SIG_CHIP_OS, "Axalto Cyberflex", "Cyberflex 32" },
    { 0x4090, 0x6622, 0x1291, 0, 0, GP_SIG_CHIP_OS, "Gemplus GemXpresso", "GXP Lite Generic" },
    { 0x4090, 0x6640, 0x1291, 0, 0, GP_SIG_CHIP_OS, "Gemplus GemXpresso", "GXP R3" },
    { 0x4090, 0x6642, 0x1291, 0, 0, GP_SIG_CHIP_OS, "Gemplus GemXpresso", "GXP E64 PK / R3 r32 (TOP IM/IS GX3)" },
    { 0x8100, 0x7412, 0x8100, 0, 0, GP_SIG_CHIP_OS, "Infineon SECORA Connect", "SECORA Connect S (seen as Fidesmo)" },
    // ---- Other silicon --------------------------------------------------- [J]
    { 0x4180, 0x010B, 0x8211, 0, 0, GP_SIG_CHIP_OS, "Athena IDProtect", "Athena IDProtect on Atmel (JC 2.2)" },
    { 0x4180, 0x8872, 0x8231, 0, 0, GP_SIG_CHIP_OS, "Oberthur Cosmo", "Cosmo v7 on Atmel" },
    { 0x4830, 0x7732, 0x8231, 0, 0, GP_SIG_CHIP_OS, "IDEMIA Cosmo", "Cosmo Fly v5.8" },
    { 0x2050, 0x5000, 0x4041, 0, 0, GP_SIG_CHIP_OS, "Oberthur ID-One Cosmo", "ID-One Cosmo 64 v5.4 / CosmoDual 72K" },
    { 0x4250, 0x3072, 0x1291, 0, 0, GP_SIG_CHIP_OS, "Gemalto on Samsung", "GemXpresso R4 72K / TOP IM GX4" },
    { 0x4070, 0x5072, 0x1291, 0, 0, GP_SIG_CHIP_OS, "Gemalto", "TwinGCX4 72K" },
    { 0x4220, 0x4501, 0x1981, 0, 0, GP_SIG_CHIP_OS, "Axalto Cyberflex", "Cyberflex Palmera V3" },
    { 0x0005, 0x0045, 0xD001, 0, 0, GP_SIG_CHIP_OS, "G+D Sm@rtCafe 7", "Sm@rtCafe 7.0" },
    { 0x0005, 0x0056, 0xD001, 0, 0, GP_SIG_CHIP_OS, "G+D Sm@rtCafe 7", "Sm@rtCafe 7.0 215K, StarSign Crypto USB token" },
    { 0x0003, 0x0307, 0xA006, 0, 0, GP_SIG_CHIP_OS, "G+D Sm@rtCafe", "Sm@rtCafe Expert 64" },
    { 0x008C, 0x0089, 0, 0, 0, GP_SIG_IC, "Tongxin THD89", "THD89 JavaCard (ThothTrust T101, J100, CodeWav)" },
    { 0x008C, 0x0000, 0x867C, 0, 0, GP_SIG_CHIP_OS, "Feitian", "Feitian H19CR" },
    { 0x5354, 0x0033, 0x25C3, 0, 0, GP_SIG_CHIP_OS, "Feitian", "Feitian D11CR" },
    { 0x5343, 0x002B, 0x8331, 0, 0, GP_SIG_CHIP_OS, "SmartJac", "SMAOT500B" },
    // ---- Fabricator-only fallbacks ---------------------------------------
    { 0x4790, 0, 0, 0, 0, 0, "NXP SmartMX", "NXP silicon, IC type not in database" },
    { 0x4090, 0, 0, 0, 0, 0, "Infineon", "Infineon silicon, IC type not in database" },
    { 0x8100, 0, 0, 0, 0, 0, "Infineon", "Infineon silicon, IC type not in database" },
    { 0x4250, 0, 0, 0, 0, 0, "Samsung", "Samsung silicon, IC type not in database" },
    { 0x4180, 0, 0, 0, 0, 0, "Atmel", "Atmel silicon, IC type not in database" },
};

#define GP_CARD_SIGNATURES_COUNT  (sizeof(GP_CARD_SIGNATURES) / sizeof(GP_CARD_SIGNATURES[0]))

// Most specific match wins: release (4) > OS (2) > IC type (1) > fabricator only (0).
static inline const gp_card_signature_t *gp_card_signature_lookup(uint16_t fab, uint16_t ic, uint16_t os,
                                                                   uint16_t os_date, uint16_t os_level) {
    const gp_card_signature_t *best = NULL;
    for (size_t i = 0; i < GP_CARD_SIGNATURES_COUNT; i++) {
        const gp_card_signature_t *s = &GP_CARD_SIGNATURES[i];
        if (s->fab_id != fab) continue;
        if ((s->match & GP_SIG_IC) && s->ic_type != ic) continue;
        if ((s->match & GP_SIG_OS) && s->os_id != os) continue;
        if ((s->match & GP_SIG_REL) && (s->os_date != os_date || s->os_level != os_level)) continue;
        if (best == NULL || s->match > best->match) best = s;
    }
    return best;
}

// OS identifier -> OS vendor; only IDs seen consistently for one OS vendor.
typedef struct {
    uint16_t    os_id;
    const char *os;
} gp_os_id_t;

static const gp_os_id_t GP_OS_IDS[] = {
    { 0x4700, "NXP JCOP 4" },                     // [J][H] on D321 and D600
    { 0x4791, "NXP JCOP 2.x" },                   // [J]
    { 0x4051, "NXP JCOP 2.x (early)" },           // [J]
    { 0x1291, "Gemplus / Gemalto (Thales)" },     // [J][N] on Infineon, NXP, Samsung
    { 0x1671, "G+D Sm@rtCafe Expert" },           // [J] on Infineon and NXP
    { 0xD001, "G+D Sm@rtCafe 7" },                // [J]
    { 0x86AA, "Feitian JavaCOS" },                // [J]
    { 0x8231, "Oberthur / IDEMIA Cosmo" },        // [J] on two fabricators
    { 0x4041, "Oberthur ID-One Cosmo" },          // [J]
    { 0x4091, "Infineon JavaCard OS" },           // [J]
};

static inline const char *gp_os_id_name(uint16_t os_id) {
    for (size_t i = 0; i < sizeof(GP_OS_IDS) / sizeof(GP_OS_IDS[0]); i++)
        if (GP_OS_IDS[i].os_id == os_id) return GP_OS_IDS[i].os;
    return NULL;
}

// ATS historical-byte prefixes [P][H]; the longest matching prefix wins.
// Several are vendor defaults shared across generations: they narrow the
// family and are cross-checked against CPLC, never trusted alone.
typedef struct {
    uint8_t     len;
    uint8_t     bytes[16];
    const char *meaning;
} gp_hist_signature_t;

static const gp_hist_signature_t GP_HIST_SIGNATURES[] = {
    { 8,  "\x00\x73\xC8\x40\x00\x00\x90\x00",     "NXP JCOP default (JCOP 2.x to JCOP 4; not version specific)" },
    { 5,  "\x80\x73\xC8\x21\x10",                 "NXP JCOP 4 / SmartMX3 P71 family" },
    { 9,  "\x00\x31\xC1\x73\xC8\x40\x00\x52\xA5", "NXP SmartMX3 P71" },
    { 10, "\x00\x31\xC1\x73\xC8\x40\x00\x00\x90\x00", "NXP PN65 embedded secure element" },
    { 7,  "\x00\x31\xC1\x73\xC8\x21\x10",         "G+D Sm@rtCafe on NXP (wearable)" },
    { 4,  "\x80\x31\xC1\x52",                     "IDEMIA Cosmo V8" },
    { 4,  "\x00\x31\xC1\x64",                     "IDEMIA Cosmo v8.1 / NXP SmartMX" },
    { 5,  "\x80\x31\x80\x65\xB0",                 "Gemalto / Thales (GemXpresso, IDPrime)" },
    { 8,  "\x80\x31\x80\x65\xB0\x07\x02\x02",     "NXP JCOP30" },
    { 7,  "\x80\x91\xE1\x31\x80\x65\xB0",         "Gemalto / Thales IDCore, IDPrime PIV, TOP DM" },
    { 7,  "\x80\x91\x00\x31\x80\x65\xB0",         "Thales IDCore 3230" },
    { 5,  "\x80\x31\x80\x66\xB0",                 "Thales IDPrime" },
    { 5,  "\x80\x31\x80\x66\xB1",                 "Gemalto Optelio" },
    { 6,  "\x80\xF9\xA0\x00\x00\x03",             "NXP JCOP3 SecID P60 (PIV AID in historical bytes)" },
    { 6,  "\x90\x67\x46\x4A\x00\x68",             "Feitian JavaCard" },
    { 6,  "\x00\x66\x46\x53\x05\x10",             "Feitian JavaCOS A40" },
    { 11, "\x80\x73\xC0\x21\xC0\x57YubiK",        "Yubico YubiKey 5 NFC" },
    // ASCII historical bytes
    { 4,  "JCOP",       "NXP JCOP" },
    { 6,  "PVJCOP",     "NXP JCOP (pre-personalised)" },
    { 3,  "J3R",        "NXP JCOP 4 J3Rxxx" },
    { 3,  "J3A",        "NXP JCOP J3A" },
    { 7,  "PV_J3A0",    "NXP JCOP J3A0xx" },
    { 5,  "ACOSJ",      "ACS ACOSJ" },
    { 7,  "FIDESMO",    "Fidesmo card" },
    { 10, "YubikeyNEO", "Yubico YubiKey NEO" },
    { 8,  "Polaris ",   "ThothTrust THETAKey / CodeWav (Tongxin THD89)" },
    { 5,  "SCE60",      "G+D Sm@rtCafe Expert 6.0" },
    { 4,  "sfte",       "G+D Sm@rtCafe Expert 3.2" },
    { 5,  "D11CR",      "Feitian D11CR (javacard.pro)" },
    { 8,  "Coinkite",   "Coinkite Satscard" },
    { 8,  "fIFXBS2G",   "Infineon Blockchain Security 2Go" },
    { 7,  "RFIDIOt",    "RFIDIOt-personalised JCOP / Sm@rtCafe" },
};

static inline const gp_hist_signature_t *gp_hist_signature_lookup(const uint8_t *hist, size_t len) {
    const gp_hist_signature_t *best = NULL;
    for (size_t i = 0; i < sizeof(GP_HIST_SIGNATURES) / sizeof(GP_HIST_SIGNATURES[0]); i++) {
        const gp_hist_signature_t *s = &GP_HIST_SIGNATURES[i];
        if (s->len > len || memcmp(hist, s->bytes, s->len) != 0) continue;
        if (best == NULL || s->len > best->len) best = s;
    }
    return best;
}

//=============================================================================
// Well-known GlobalPlatform / JavaCard application AIDs
//=============================================================================

typedef struct {
    uint8_t      aid[16];
    uint8_t      aid_len;
    const char  *name;
    const char  *description;
} gp_known_aid_t;

static const gp_known_aid_t GP_KNOWN_AIDS[] = {
    // ── GlobalPlatform ISDs ───────────────────────────────────────────────
    { { 0xA0,0x00,0x00,0x01,0x51,0x00,0x00,0x00 }, 8,
      "GP ISD",        "GlobalPlatform Issuer Security Domain" },
    { { 0xA0,0x00,0x00,0x00,0x03,0x00,0x00,0x00 }, 8,
      "GP ISD (VISA)", "GlobalPlatform ISD (VISA RID)" },

    // ── EMV / Payment ─────────────────────────────────────────────────────
    { { 0xA0,0x00,0x00,0x00,0x03,0x10,0x10 }, 7,
      "Visa Credit/Debit",   "Visa International Credit/Debit" },
    { { 0xA0,0x00,0x00,0x00,0x03,0x20,0x10 }, 7,
      "Visa Electron",       "Visa Electron" },
    { { 0xA0,0x00,0x00,0x00,0x04,0x10,0x10 }, 7,
      "Mastercard",          "Mastercard International" },
    { { 0xA0,0x00,0x00,0x00,0x04,0x30,0x60 }, 7,
      "Maestro",             "Maestro Debit" },
    { { 0xA0,0x00,0x00,0x00,0x65,0x10,0x10 }, 7,
      "JCB",                 "Japan Credit Bureau" },
    { { 0xA0,0x00,0x00,0x00,0x25,0x01 },       6,
      "Amex",                "American Express" },
    { { 0xA0,0x00,0x00,0x00,0x29,0x10,0x10 }, 7,
      "Discover",            "Discover Card" },

    // ── FIDO / PIV / OpenPGP ──────────────────────────────────────────────
    { { 0xA0,0x00,0x00,0x06,0x47,0x2F,0x00,0x01 }, 8,
      "FIDO U2F",     "FIDO Universal 2nd Factor" },
    { { 0xA0,0x00,0x00,0x06,0x47,0x2F,0x00,0x02 }, 8,
      "FIDO2/WebAuthn","FIDO2 / WebAuthn authenticator" },
    { { 0xA0,0x00,0x00,0x03,0x08,0x00,0x00,0x10,0x00,0x01 }, 10,
      "PIV (NIST)",   "NIST SP 800-73 Personal Identity Verification" },
    { { 0xD2,0x76,0x00,0x01,0x24,0x01 }, 6,
      "OpenPGP",      "OpenPGP Card v2/v3" },

    // ── Transport / Transit ───────────────────────────────────────────────
    { { 0xA0,0x00,0x00,0x00,0x79,0x01 }, 6,
      "InterAC",         "Interac (Canada)" },

    // ── Health / Identity ─────────────────────────────────────────────────
    { { 0xE8,0x28,0xBD,0x08,0x0F,0xA0,0x00,0x00,0x01,0x67,0x45,0x53,0x49,0x47,0x4E }, 15,
      "ESIGN (Germany)", "German eSign / electronic signature" },
    { { 0xA0,0x00,0x00,0x00,0x18,0x43,0x4D }, 7,
      "ICAO eMRTD",  "ICAO Machine-Readable Travel Document" },

    // ── NXP / Mifare applets ──────────────────────────────────────────────
    { { 0xD2,0x76,0x00,0x00,0x85,0x01,0x00 }, 7,
      "NXP MIFARE",  "NXP MIFARE application" },
    { { 0xA0,0x00,0x00,0x00,0x04,0x60,0x00 }, 7,
      "Mastercard PayPass", "Mastercard PayPass / Contactless" },
    { { 0xA0,0x00,0x00,0x00,0x03,0x10,0x10,0x01 }, 8,
      "Visa payWave", "Visa payWave Contactless" },

    // ── JavaCard framework ────────────────────────────────────────────────
    { { 0xA0,0x00,0x00,0x00,0x62,0x00,0x01,0x08,0x00,0x01 }, 10,
      "JavaCard API",     "JavaCard Framework 3.x API" },
    { { 0xA0,0x00,0x00,0x00,0x62,0x01,0x01 }, 7,
      "javacard.framework", "Java Card framework package" },
    { { 0xA0,0x00,0x00,0x01,0x51,0x53,0x50 }, 7,
      "GP SSD package",    "GlobalPlatform Security Domain executable load file" },
};

#define GP_KNOWN_AIDS_COUNT  (sizeof(GP_KNOWN_AIDS) / sizeof(GP_KNOWN_AIDS[0]))

// Return name of a well-known AID, or NULL if not found.
// Performs prefix matching (longest matching entry wins).
static inline const char *gp_known_aid_name(const uint8_t *aid, size_t aid_len) {
    const char *best = NULL;
    size_t best_len = 0;
    for (size_t i = 0; i < GP_KNOWN_AIDS_COUNT; i++) {
        size_t elen = GP_KNOWN_AIDS[i].aid_len;
        if (aid_len >= elen && memcmp(aid, GP_KNOWN_AIDS[i].aid, elen) == 0) {
            if (elen > best_len) {
                best_len = elen;
                best = GP_KNOWN_AIDS[i].name;
            }
        }
    }
    return best;
}

#endif // CMDHFJAVACARD_DB_H__
