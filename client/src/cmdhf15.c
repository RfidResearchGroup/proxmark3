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
// High frequency ISO15693 commands
//-----------------------------------------------------------------------------
// There are three basic operation modes, depending on which device (proxmark/pc)
// the signal processing, (de)modulation, transmission protocol and logic is done.
// Mode 1:
// All steps are done on the proxmark, the output of the commands is returned via
// USB-debug-print commands.
// Mode 2:
// The protocol is done on the PC, passing only Iso15693 data frames via USB. This
// allows direct communication with a tag on command level
// Mode 3:
// The proxmark just samples the antenna and passes this "analog" data via USB to
// the client. Signal Processing & decoding is done on the pc. This is the slowest
// variant, but offers the possibility to analyze the waveforms directly.
#include "cmdhf15.h"
#include <ctype.h>
#include "cmdparser.h"         // command_t
#include "commonutil.h"        // ARRAYLEN
#include "comms.h"             // clearCommandBuffer
#include "cmdtrace.h"
#include "iso15693tools.h"     // ISO15693 error codes etc
#include "protocols.h"         // ISO15693 command set
#include "crypto/libpcrypto.h"
#include "graph.h"
#include "crc16.h"             // iso15 crc
#include "cmddata.h"           // getsamples
#include "fileutils.h"         // pm3_save_dump
#include "cliparser.h"
#include "util_posix.h"        // msleep

#define FrameSOF                Iso15693FrameSOF
#define Logic0                  Iso15693Logic0
#define Logic1                  Iso15693Logic1
#define FrameEOF                Iso15693FrameEOF
#define CARD_MEMORY_SIZE        4096
#define HF15_UID_LENGTH         8

#ifndef Crc15
# define Crc15(data, len)       Crc16ex(CRC_15693, (data), (len))
#endif
#ifndef CheckCrc15
# define CheckCrc15(data, len)  check_crc(CRC_15693, (data), (len))
#endif
#ifndef AddCrc15
#define AddCrc15(data, len)     compute_crc(CRC_15693, (data), (len), (data)+(len), (data)+(len)+1)
#endif

typedef struct {
    uint8_t lock;
    uint8_t block[4];
} t15memory_t;

// structure and database for uid -> tagtype lookups
typedef struct {
    uint64_t uid;
    uint64_t mask; // how many MSB bits used, or mask itself if larger than 64
    const char *desc;
} productName_t;

static const productName_t uidmapping[] = {

    // UID, #significant Bits, "Vendor(+Product)"
    { 0xE001000000000000LL, 16, "Motorola UK" },

    // E0 02 xx
    //   02 = ST Microelectronics
    //   XX = IC id (Chip ID Family)
    { 0xE002000000000000LL, 16, "ST Microelectronics SA France" },
    { 0xE002050000000000LL, 24, "ST Microelectronics; LRI64   [IC id = 05]"},
    { 0xE002080000000000LL, 24, "ST Microelectronics; LRI2K   [IC id = 08]"},
    { 0xE0020A0000000000LL, 24, "ST Microelectronics; LRIS2K  [IC id = 10]"},
    { 0xE002440000000000LL, 24, "ST Microelectronics; LRIS64K [IC id = 68]"},

    { 0xE003000000000000LL, 16, "Hitachi, Ltd Japan" },

    // E0 04 xx
    //   04 = Manufacturer code (Philips/NXP)
    //   XX = IC id (Chip ID Family)
    //I-Code SLI SL2 ICS20 [IC id = 01 + bit35 set to 0 + bit36 set to 0]
    //I-Code SLIX          [IC id = 01 + bit35 set to 0 + bit36 set to 1]
    //I-Code SLIX2         [IC id = 01 + bit35 set to 1 + bit36 set to 0]
    //I-Code SLI-S         [IC id = 02 + bit36 set to 0]
    //I-Code SLIX-S        [IC id = 02 + bit36 set to 1]
    //I-Code SLI-L         [IC id = 03 + bit36 set to 0]
    //I-Code SLIX-L        [IC id = 03 + bit36 set to 1]
    { 0xE004000000000000LL, 16, "NXP Semiconductors Germany (Philips)" },
    { 0xE004010000000000LL, 24, "NXP(Philips); IC SL2 ICS20/ICS21(SLI) ICS2002/ICS2102(SLIX) ICS2602(SLIX2)" },
    { 0xE004011800000000LL, 0xFFFFFF1800000000LL, "NXP(Philips); IC NTP53x2/NTP5210/NTA5332(NTAG 5)" },
    { 0xE004010000000000LL, 0xFFFFFF1800000000LL, "NXP(Philips); IC SL2 ICS20/ICS21(SLI)" },
    { 0xE004011000000000LL, 0xFFFFFF1800000000LL, "NXP(Philips); IC SL2 ICS2002/ICS2102(SLIX)" },
    { 0xE004010800000000LL, 0xFFFFFF1800000000LL, "NXP(Philips); IC SL2 ICS2602(SLIX2)" },
    { 0xE004020000000000LL, 0xFFFFFF1000000000LL, "NXP(Philips); IC SL2 ICS53/ICS54(SLI-S)" },
    { 0xE004021000000000LL, 0xFFFFFF1000000000LL, "NXP(Philips); ICS5302/ICS5402(SLIX-S)" },
    { 0xE004030000000000LL, 0xFFFFFF1000000000LL, "NXP(Philips); IC SL2 ICS50/ICS51(SLI-L)" },
    { 0xE004031000000000LL, 0xFFFFFF1000000000LL, "NXP(Philips); ICS5002/ICS5102(SLIX-L)" },

    // E0 05 XX .. .. ..
    //   05 = Manufacturer code (Infineon)
    //   XX = IC id (Chip ID Family)
    { 0xE005000000000000LL, 16, "Infineon Technologies AG Germany" },
    { 0xE005A10000000000LL, 24, "Infineon; SRF55V01P [IC id = 161] plain mode 1kBit"},
    { 0xE005A80000000000LL, 24, "Infineon; SRF55V01P [IC id = 168] pilot series 1kBit"},
    { 0xE005400000000000LL, 24, "Infineon; SRF55V02P [IC id = 64]  plain mode 2kBit"},
    { 0xE005000000000000LL, 24, "Infineon; SRF55V10P [IC id = 00]  plain mode 10KBit"},
    { 0xE005500000000000LL, 24, "Infineon; SRF55V02S [IC id = 80]  secure mode 2kBit"},
    { 0xE005100000000000LL, 24, "Infineon; SRF55V10S [IC id = 16]  secure mode 10KBit"},
    { 0xE0051E0000000000LL, 23, "Infineon; SLE66r01P [IC id = 3x = My-d Move or My-d move NFC]"},
    { 0xE005200000000000LL, 21, "Infineon; SLE66r01P [IC id = 3x = My-d Move or My-d move NFC]"},

    { 0xE006000000000000LL, 16, "Cylink USA" },


    // E0 07 xx
    //   07 = Texas Instruments
    //   XX = from bit 41 to bit 43 = product configuration - from bit 44 to bit 47 IC id (Chip ID Family)
    //Tag IT RFIDType-I Plus, 2kBit, TI Inlay
    //Tag-it HF-I Plus Inlay             [IC id = 00] -> b'0000 000 2kBit
    //Tag-it HF-I Plus Chip              [IC id = 64] -> b'1000 000 2kBit
    //Tag-it HF-I Standard Chip / Inlays [IC id = 96] -> b'1100 000 256Bit
    //Tag-it HF-I Pro Chip / Inlays      [IC id = 98] -> b'1100 010 256Bit, Password protection
    { 0xE007000000000000LL, 16, "Texas Instrument France" },
    { 0xE007000000000000LL, 20, "Texas Instrument; Tag-it HF-I Plus Inlay; 64x32bit" },
    { 0xE007100000000000LL, 20, "Texas Instrument; Tag-it HF-I Plus Chip; 64x32bit" },
    { 0xE007800000000000LL, 23, "Texas Instrument; Tag-it HF-I Plus (RF-HDT-DVBB tag or Third Party Products)" },
    { 0xE007C00000000000LL, 23, "Texas Instrument; Tag-it HF-I Standard; 8x32bit" },
    { 0xE007C40000000000LL, 23, "Texas Instrument; Tag-it HF-I Pro; 8x23bit; password" },

    { 0xE008000000000000LL, 16, "Fujitsu Limited Japan" },
    { 0xE009000000000000LL, 16, "Matsushita Electronics Corporation, Semiconductor Company Japan" },
    { 0xE00A000000000000LL, 16, "NEC Japan" },
    { 0xE00B000000000000LL, 16, "Oki Electric Industry Co. Ltd Japan" },
    { 0xE00C000000000000LL, 16, "Toshiba Corp. Japan" },
    { 0xE00D000000000000LL, 16, "Mitsubishi Electric Corp. Japan" },
    { 0xE00E000000000000LL, 16, "Samsung Electronics Co. Ltd Korea" },
    { 0xE00F000000000000LL, 16, "Hynix / Hyundai, Korea" },
    { 0xE010000000000000LL, 16, "LG-Semiconductors Co. Ltd Korea" },
    { 0xE011000000000000LL, 16, "Emosyn-EM Microelectronics USA" },

    { 0xE012000000000000LL, 16, "HID Corporation" },
    { 0xE012000000000000LL, 16, "INSIDE Technology France" },
    { 0xE013000000000000LL, 16, "ORGA Kartensysteme GmbH Germany" },
    { 0xE014000000000000LL, 16, "SHARP Corporation Japan" },
    { 0xE015000000000000LL, 16, "ATMEL France" },

    { 0xE016000000000000LL, 16, "EM Microelectronic-Marin SA Switzerland (Skidata)"},
    { 0xE016040000000000LL, 24, "EM-Marin SA (Skidata Keycard-eco); EM4034 [IC id = 01] (Read/Write - no AFI)"},
    { 0xE0160C0000000000LL, 24, "EM-Marin SA (Skidata); EM4035 [IC id = 03] (Read/Write - replaced by 4233)"},
    { 0xE016100000000000LL, 24, "EM-Marin SA (Skidata); EM4135 [IC id = 04] (Read/Write - replaced by 4233) 36x64bit start page 13"},
    { 0xE016140000000000LL, 24, "EM-Marin SA (Skidata); EM4036 [IC id = 05] 28pF"},
    { 0xE016180000000000LL, 24, "EM-Marin SA (Skidata); EM4006 [IC id = 06] (Read Only)"},
    { 0xE0161C0000000000LL, 24, "EM-Marin SA (Skidata); EM4133 [IC id = 07] 23,5pF (Read/Write)"},
    { 0xE016200000000000LL, 24, "EM-Marin SA (Skidata); EM4033 [IC id = 08] 23,5pF (Read Only - no AFI / no DSFID / no security blocks)"},
    { 0xE016240000000000LL, 24, "EM-Marin SA (Skidata); EM4233 [IC id = 09] 23,5pF CustomerID-102"},
    { 0xE016280000000000LL, 24, "EM-Marin SA (Skidata); EM4233 SLIC [IC id = 10] 23,5pF (1Kb flash memory - not provide High Security mode and QuietStorage feature)" },
    { 0xE0163C0000000000LL, 24, "EM-Marin SA (Skidata); EM4237 [IC id = 15] 23,5pF"},
    { 0xE0167C0000000000LL, 24, "EM-Marin SA (Skidata); EM4233 [IC id = 31] 95pF"},
    { 0xE016940000000000LL, 24, "EM-Marin SA (Skidata); EM4036 [IC id = 37] 95pF  51x64bit "},
    { 0xE0169c0000000000LL, 24, "EM-Marin SA (Skidata); EM4133 [IC id = 39] 95pF (Read/Write)" },
    { 0xE016A80000000000LL, 24, "EM-Marin SA (Skidata); EM4233 SLIC [IC id = 42] 97pF" },
    { 0xE016BC0000000000LL, 24, "EM-Marin SA (Skidata); EM4237 [IC id = 47] 97pF" },

    { 0xE017000000000000LL, 16, "KSW Microtec GmbH Germany" },
    { 0xE018000000000000LL, 16, "ZMD AG Germany" },
    { 0xE019000000000000LL, 16, "XICOR, Inc. USA" },
    { 0xE01A000000000000LL, 16, "Sony Corporation Japan Identifier Company Country" },
    { 0xE01B000000000000LL, 16, "Malaysia Microelectronic Solutions Sdn. Bhd Malaysia" },
    { 0xE01C000000000000LL, 16, "Emosyn USA" },
    { 0xE01D000000000000LL, 16, "Shanghai Fudan Microelectronics Co. Ltd. P.R. China" },
    { 0xE01E000000000000LL, 16, "Magellan Technology Pty Limited Australia" },
    { 0xE01F000000000000LL, 16, "Melexis NV BO Switzerland" },
    { 0xE020000000000000LL, 16, "Renesas Technology Corp. Japan" },
    { 0xE021000000000000LL, 16, "TAGSYS France" },
    { 0xE022000000000000LL, 16, "Transcore USA" },
    { 0xE023000000000000LL, 16, "Shanghai belling corp., ltd. China" },
    { 0xE024000000000000LL, 16, "Masktech Germany Gmbh Germany" },
    { 0xE025000000000000LL, 16, "Innovision Research and Technology Plc UK" },
    { 0xE026000000000000LL, 16, "Hitachi ULSI Systems Co., Ltd. Japan" },
    { 0xE027000000000000LL, 16, "Cypak AB Sweden" },
    { 0xE028000000000000LL, 16, "Ricoh Japan" },
    { 0xE029000000000000LL, 16, "ASK France" },
    { 0xE02A000000000000LL, 16, "Unicore Microsystems, LLC Russian Federation" },
    { 0xE02B000000000000LL, 16, "Dallas Semiconductor/Maxim USA" },
    { 0xE02C000000000000LL, 16, "Impinj, Inc. USA" },
    { 0xE02D000000000000LL, 16, "RightPlug Alliance USA" },
    { 0xE02E000000000000LL, 16, "Broadcom Corporation USA" },
    { 0xE02F000000000000LL, 16, "MStar Semiconductor, Inc Taiwan, ROC" },
    { 0xE030000000000000LL, 16, "BeeDar Technology Inc. USA" },
    { 0xE031000000000000LL, 16, "RFIDsec Denmark" },
    { 0xE032000000000000LL, 16, "Schweizer Electronic AG Germany" },
    { 0xE033000000000000LL, 16, "AMIC Technology Corp Taiwan" },
    { 0xE034000000000000LL, 16, "Mikron JSC Russia" },
    { 0xE035000000000000LL, 16, "Fraunhofer Institute for Photonic Microsystems Germany" },
    { 0xE036000000000000LL, 16, "IDS Microchip AG Switzerland" },
    { 0xE037000000000000LL, 16, "Kovio USA" },
    { 0xE038000000000000LL, 16, "HMT Microelectronic Ltd Switzerland Identifier Company Country" },
    { 0xE039000000000000LL, 16, "Silicon Craft Technology Thailand" },
    { 0xE03A000000000000LL, 16, "Advanced Film Device Inc. Japan" },
    { 0xE03B000000000000LL, 16, "Nitecrest Ltd UK" },
    { 0xE03C000000000000LL, 16, "Verayo Inc. USA" },
    { 0xE03D000000000000LL, 16, "HID Global USA" },
    { 0xE03E000000000000LL, 16, "Productivity Engineering Gmbh Germany" },
    { 0xE03F000000000000LL, 16, "Austriamicrosystems AG (reserved) Austria" },
    { 0xE040000000000000LL, 16, "Gemalto SA France" },
    { 0xE041000000000000LL, 16, "Renesas Electronics Corporation Japan" },
    { 0xE042000000000000LL, 16, "3Alogics Inc Korea" },
    { 0xE043000000000000LL, 16, "Top TroniQ Asia Limited Hong Kong" },
    { 0xE044000000000000LL, 16, "Gentag Inc (USA) USA" },
    { 0, 0, "no tag-info available" } // must be the last entry
};

static int CmdHF15Help(const char *Cmd);

static int nxp_15693_print_signature(uint8_t *uid, uint8_t *signature) {

#define PUBLIC_ECDA_KEYLEN 33
    const ecdsa_publickey_t nxp_15693_public_keys[] = {
        {"NXP Mifare Classic MFC1C14_x", "044F6D3F294DEA5737F0F46FFEE88A356EED95695DD7E0C27A591E6F6F65962BAF"},
        {"Manufacturer Mifare Classic MFC1C14_x", "046F70AC557F5461CE5052C8E4A7838C11C7A236797E8A0730A101837C004039C2"},
        {"NXP ICODE DNA, ICODE SLIX2", "048878A2A2D3EEC336B4F261A082BD71F9BE11C4E2E896648B32EFA59CEA6E59F0"},
        {"NXP Public key", "04A748B6A632FBEE2C0897702B33BEA1C074998E17B84ACA04FF267E5D2C91F6DC"},
        {"NXP Ultralight Ev1", "0490933BDCD6E99B4E255E3DA55389A827564E11718E017292FAF23226A96614B8"},
        {"NXP NTAG21x (2013)", "04494E1A386D3D3CFE3DC10E5DE68A499B1C202DB5B132393E89ED19FE5BE8BC61"},
        {"MIKRON Public key", "04f971eda742a4a80d32dcf6a814a707cc3dc396d35902f72929fdcd698b3468f2"},
        {"VivoKey Spark1 Public key", "04d64bb732c0d214e7ec580736acf847284b502c25c0f7f2fa86aace1dada4387a"},
    };
    /*
        uint8_t nxp_15693_public_keys[][PUBLIC_ECDA_KEYLEN] = {
            // ICODE SLIX2 / DNA
            {
                0x04, 0x88, 0x78, 0xA2, 0xA2, 0xD3, 0xEE, 0xC3,
                0x36, 0xB4, 0xF2, 0x61, 0xA0, 0x82, 0xBD, 0x71,
                0xF9, 0xBE, 0x11, 0xC4, 0xE2, 0xE8, 0x96, 0x64,
                0x8B, 0x32, 0xEF, 0xA5, 0x9C, 0xEA, 0x6E, 0x59, 0xF0
            },
            // unknown. Needs identification
            {
                0x04, 0x4F, 0x6D, 0x3F, 0x29, 0x4D, 0xEA, 0x57,
                0x37, 0xF0, 0xF4, 0x6F, 0xFE, 0xE8, 0x8A, 0x35,
                0x6E, 0xED, 0x95, 0x69, 0x5D, 0xD7, 0xE0, 0xC2,
                0x7A, 0x59, 0x1E, 0x6F, 0x6F, 0x65, 0x96, 0x2B, 0xAF
            },
            // unknown. Needs identification
            {
                0x04, 0xA7, 0x48, 0xB6, 0xA6, 0x32, 0xFB, 0xEE,
                0x2C, 0x08, 0x97, 0x70, 0x2B, 0x33, 0xBE, 0xA1,
                0xC0, 0x74, 0x99, 0x8E, 0x17, 0xB8, 0x4A, 0xCA,
                0x04, 0xFF, 0x26, 0x7E, 0x5D, 0x2C, 0x91, 0xF6, 0xDC
            },
            // manufacturer public key
            {
                0x04, 0x6F, 0x70, 0xAC, 0x55, 0x7F, 0x54, 0x61,
                0xCE, 0x50, 0x52, 0xC8, 0xE4, 0xA7, 0x83, 0x8C,
                0x11, 0xC7, 0xA2, 0x36, 0x79, 0x7E, 0x8A, 0x07,
                0x30, 0xA1, 0x01, 0x83, 0x7C, 0x00, 0x40, 0x39, 0xC2
            },
            // MIKRON public key.
            {
                0x04, 0xf9, 0x71, 0xed, 0xa7, 0x42, 0xa4, 0xa8,
                0x0d, 0x32, 0xdc, 0xf6, 0xa8, 0x14, 0xa7, 0x07,
                0xcc, 0x3d, 0xc3, 0x96, 0xd3, 0x59, 0x02, 0xf7,
                0x29, 0x29, 0xfd, 0xcd, 0x69, 0x8b, 0x34, 0x68, 0xf2
            }
        };
    */

    uint8_t revuid[8] = {0};
    reverse_array_copy(uid, sizeof(revuid), revuid);

    uint8_t revsign[32] = {0};
    reverse_array_copy(signature, sizeof(revsign), revsign);

    uint8_t i;
    int reason = 0;
    bool is_valid = false;
    for (i = 0; i < ARRAYLEN(nxp_15693_public_keys); i++) {

        int dl = 0;
        uint8_t key[PUBLIC_ECDA_KEYLEN];
        param_gethex_to_eol(nxp_15693_public_keys[i].value, 0, key, PUBLIC_ECDA_KEYLEN, &dl);

        int res = ecdsa_signature_r_s_verify(MBEDTLS_ECP_DP_SECP128R1, key, uid, 8, signature, 32, false);
        is_valid = (res == 0);
        if (is_valid) {
            reason = 1;
            break;
        }

        // try with sha256
        res = ecdsa_signature_r_s_verify(MBEDTLS_ECP_DP_SECP128R1, key, uid, 8, signature, 32, true);
        is_valid = (res == 0);
        if (is_valid) {
            reason = 2;
            break;
        }

        // try with reversed uid / signature
        res = ecdsa_signature_r_s_verify(MBEDTLS_ECP_DP_SECP128R1, key, revuid, sizeof(revuid), revsign, sizeof(revsign), false);
        is_valid = (res == 0);
        if (is_valid) {
            reason = 3;
            break;
        }


        // try with sha256
        res = ecdsa_signature_r_s_verify(MBEDTLS_ECP_DP_SECP128R1, key, revuid, sizeof(revuid), revsign, sizeof(revsign), true);
        is_valid = (res == 0);
        if (is_valid) {
            reason = 4;
            break;
        }
    }

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Tag Signature"));
    if (is_valid == false || i == ARRAYLEN(nxp_15693_public_keys)) {
        PrintAndLogEx(INFO, "    Elliptic curve parameters: NID_secp128r1");
        PrintAndLogEx(INFO, "             TAG IC Signature: %s", sprint_hex_inrow(signature, 32));
        PrintAndLogEx(SUCCESS, "       Signature verification: " _RED_("failed"));
        return PM3_ESOFT;
    }

    PrintAndLogEx(INFO, " IC signature public key name: " _GREEN_("%s"), nxp_15693_public_keys[i].desc);
    PrintAndLogEx(INFO, "IC signature public key value: %s", nxp_15693_public_keys[i].value);
    PrintAndLogEx(INFO, "    Elliptic curve parameters: NID_secp128r1");
    PrintAndLogEx(INFO, "             TAG IC Signature: %s", sprint_hex_inrow(signature, 32));
    PrintAndLogEx(SUCCESS, "       Signature verification: " _GREEN_("successful"));
    switch (reason) {
        case 1:
            PrintAndLogEx(INFO, "                  Params used: UID and signature, plain");
            break;
        case 2:
            PrintAndLogEx(INFO, "                  Params used: UID and signature, SHA256");
            break;
        case 3:
            PrintAndLogEx(INFO, "                  Params used: reversed UID and signature, plain");
            break;
        case 4:
            PrintAndLogEx(INFO, "                  Params used: reversed UID and signature, SHA256");
            break;
    }
    return PM3_SUCCESS;
}

// get a product description based on the UID
// uid[8] tag uid
// returns description of the best match
static const char *getTagInfo_15(uint8_t *uid) {
    if (uid == NULL) {
        return "";
    }

    uint64_t myuid, mask;
    int i = 0, best = -1;
    memcpy(&myuid, uid, sizeof(uint64_t));
    while (uidmapping[i].mask > 0) {
        if (uidmapping[i].mask > 64) {
            mask = uidmapping[i].mask;
        } else {
            mask = (~0ULL) << (64 - uidmapping[i].mask);
        }
        if ((myuid & mask) == uidmapping[i].uid) {
            if (best == -1) {
                best = i;
            } else {
                if (uidmapping[i].mask > uidmapping[best].mask) {
                    best = i;
                }
            }
        }
        i++;
    }

    if (best >= 0)
        return uidmapping[best].desc;
    return uidmapping[i].desc;
}

// return a clear-text message to an errorcode
static const char *TagErrorStr(uint8_t error) {
    switch (error) {
        case 0x01:
            return "The command is not supported";
        case 0x02:
            return "The command is not recognized";
        case 0x03:
            return "The option is not supported.";
        case 0x0f:
            return "Unknown error.";
        case 0x10:
            return "The specified block is not available (doesn't exist).";
        case 0x11:
            return "The specified block is already -locked and thus cannot be locked again";
        case 0x12:
            return "The specified block is locked and its content cannot be changed.";
        case 0x13:
            return "The specified block was not successfully programmed.";
        case 0x14:
            return "The specified block was not successfully locked.";
        default:
            return "Reserved for Future Use or Custom command error.";
    }
}

// fast method to just read the UID of a tag (collision detection not supported)
//  *buf should be large enough to fit the 64bit uid
// returns 1 if succeeded
static int getUID(bool loop, uint8_t *buf) {

    uint8_t data[5];
    data[0] = ISO15_REQ_SUBCARRIER_SINGLE | ISO15_REQ_DATARATE_HIGH | ISO15_REQ_INVENTORY | ISO15_REQINV_SLOT1;
    data[1] = ISO15693_INVENTORY;
    data[2] = 0; // mask length

    AddCrc15(data, 3);

    // params
    uint8_t fast = 1;
    uint8_t reply = 1;

    int res = PM3_ESOFT;

    do {
        clearCommandBuffer();
        SendCommandMIX(CMD_HF_ISO15693_COMMAND, sizeof(data), fast, reply, data, sizeof(data));
        PacketResponseNG resp;
        if (WaitForResponseTimeout(CMD_HF_ISO15693_COMMAND, &resp, 2000)) {

            if (resp.status == PM3_SUCCESS && resp.length >= 12 && CheckCrc15(resp.data.asBytes, 12)) {

                if (buf) {
                    memcpy(buf, resp.data.asBytes + 2, 8);
                }

                DropField();

                PrintAndLogEx(NORMAL, "");
                PrintAndLogEx(SUCCESS, " UID: " _GREEN_("%s"), iso15693_sprintUID(NULL, buf));
                PrintAndLogEx(SUCCESS, "TYPE: " _YELLOW_("%s"), getTagInfo_15(buf));

                res = PM3_SUCCESS;

                if (loop == false) {
                    break;
                }
            }
        }
    } while (loop && kbd_enter_pressed() == false);

    DropField();
    return res;
}

// used with 'hf search'
bool readHF15Uid(bool loop, bool verbose) {
    uint8_t uid[8] = {0};
    if (getUID(loop, uid) != PM3_SUCCESS) {
        if (verbose) PrintAndLogEx(WARNING, "no tag found");
        return false;
    }
    return true;
}

// adds 6
static uint8_t arg_add_default(void *at[]) {
    at[0] = arg_param_begin;
    at[1] = arg_str0("u", "uid", "<hex>", "full UID, 8 bytes");
    at[2] = arg_lit0(NULL, "ua", "unaddressed mode");
    at[3] = arg_lit0("*", NULL, "scan for tag");
    at[4] = arg_lit0("2", NULL, "use slower '1 out of 256' mode");
    at[5] = arg_lit0("o", "opt", "set OPTION Flag (needed for TI)");
    return 6;
}
static uint16_t arg_get_raw_flag(uint8_t uidlen, bool unaddressed, bool scan, bool add_option) {
    uint16_t flags = 0;
    if (unaddressed) {
        // unaddressed mode may not be supported by all vendors
        flags |= (ISO15_REQ_SUBCARRIER_SINGLE | ISO15_REQ_DATARATE_HIGH | ISO15_REQ_NONINVENTORY);
    }
    if (uidlen == 8) {
        flags |= (ISO15_REQ_SUBCARRIER_SINGLE | ISO15_REQ_DATARATE_HIGH | ISO15_REQ_NONINVENTORY | ISO15_REQ_ADDRESS);
    }
    if (scan) {
        flags |= (ISO15_REQ_SUBCARRIER_SINGLE | ISO15_REQ_DATARATE_HIGH | ISO15_REQ_NONINVENTORY | ISO15_REQ_ADDRESS);
    }
    if (add_option) {
        flags |= (ISO15_REQ_OPTION);
    }
    return flags;
}

// Mode 3
static int CmdHF15Demod(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf 15 demod",
                  "Tries to demodulate / decode ISO-15693, from downloaded samples.\n"
                  "Gather samples with 'hf 15 samples' / 'hf 15 sniff'",
                  "hf 15 demod\n");

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);

    // The sampling rate is 106.353 ksps/s, for T = 18.8 us
    int i, j;
    int max = 0, maxPos = 0;
    int skip = 4;

    if (g_GraphTraceLen < 1000) {
        PrintAndLogEx(FAILED, "Too few samples in GraphBuffer. Need more than 1000");
        PrintAndLogEx(HINT, "Run " _YELLOW_("`hf 15 samples`") " to collect and download data");
        return PM3_ESOFT;
    }

    // First, correlate for SOF
    for (i = 0; i < 1000; i++) {
        int corr = 0;
        for (j = 0; j < ARRAYLEN(FrameSOF); j += skip) {
            corr += FrameSOF[j] * g_GraphBuffer[i + (j / skip)];
        }
        if (corr > max) {
            max = corr;
            maxPos = i;
        }
    }

    PrintAndLogEx(INFO, "SOF at %d, correlation %zu", maxPos, max / (ARRAYLEN(FrameSOF) / skip));

    i = maxPos + ARRAYLEN(FrameSOF) / skip;
    int k = 0;
    uint8_t outBuf[2048] = {0};
    memset(outBuf, 0, sizeof(outBuf));
    uint8_t mask = 0x01;
    for (;;) {
        int corr0 = 0, corr1 = 0, corrEOF = 0;
        for (j = 0; j < ARRAYLEN(Logic0); j += skip) {
            corr0 += Logic0[j] * g_GraphBuffer[i + (j / skip)];
        }
        for (j = 0; j < ARRAYLEN(Logic1); j += skip) {
            corr1 += Logic1[j] * g_GraphBuffer[i + (j / skip)];
        }
        for (j = 0; j < ARRAYLEN(FrameEOF); j += skip) {
            corrEOF += FrameEOF[j] * g_GraphBuffer[i + (j / skip)];
        }
        // Even things out by the length of the target waveform.
        corr0 *= 4;
        corr1 *= 4;

        if (corrEOF > corr1 && corrEOF > corr0) {
            PrintAndLogEx(INFO, "EOF at %d", i);
            break;
        } else if (corr1 > corr0) {
            i += ARRAYLEN(Logic1) / skip;
            outBuf[k] |= mask;
        } else {
            i += ARRAYLEN(Logic0) / skip;
        }

        mask <<= 1;
        if (mask == 0) {
            k++;
            mask = 0x01;
        }

        if ((i + (int)ARRAYLEN(FrameEOF)) >= g_GraphTraceLen) {
            PrintAndLogEx(INFO, "ran off end!");
            break;
        }

        if (k > 2048) {
            PrintAndLogEx(INFO, "ran out of buffer");
            break;
        }
    }

    if (mask != 0x01) {
        PrintAndLogEx(WARNING, "Warning, uneven octet! (discard extra bits!)");
        PrintAndLogEx(INFO, "   mask = %02x", mask);
    }

    if (k == 0) {
        return PM3_SUCCESS;
    }

    i = 0;
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "Got %d octets, decoded as following", k);
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(SUCCESS, " idx | data");
    PrintAndLogEx(SUCCESS, "-----+-------------------------------------------------");
    if (k / 16 > 0) {
        for (; i < k; i += 16) {
            PrintAndLogEx(SUCCESS, " %3i | %s", i, sprint_hex(outBuf + i, 16));
        }
    }

    uint8_t mod = (k % 16);
    if (mod > 0) {
        PrintAndLogEx(SUCCESS, " %3i | %s", i, sprint_hex(outBuf + i, mod));
    }
    PrintAndLogEx(SUCCESS, "-----+-------------------------------------------------");
    if (k > 2) {
        PrintAndLogEx(SUCCESS, "--> CRC %04x", Crc15(outBuf, k - 2));
    }
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}

// * Acquire Samples as Reader (enables carrier, sends inquiry)
//helptext
static int CmdHF15Samples(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf 15 samples",
                  "Acquire samples as Reader (enables carrier, send inquiry\n"
                  "and download it to graphbuffer.  Try 'hf 15 demod'  to try to demodulate/decode signal",
                  "hf 15 samples");

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);

    clearCommandBuffer();
    SendCommandNG(CMD_HF_ISO15693_ACQ_RAW_ADC, NULL, 0);

    getSamples(0, true);

    PrintAndLogEx(HINT, "Try `" _YELLOW_("hf 15 demod") "` to decode signal");
    return PM3_SUCCESS;
}

static int NxpTestEAS(uint8_t *uid) {
    uint8_t fast = 1;
    uint8_t reply = 1;
    PacketResponseNG resp;
    uint16_t reqlen = 0;
    uint8_t req[PM3_CMD_DATA_SIZE] = {0};

    req[reqlen++] |= ISO15_REQ_SUBCARRIER_SINGLE | ISO15_REQ_DATARATE_HIGH | ISO15_REQ_NONINVENTORY | ISO15_REQ_ADDRESS;
    req[reqlen++] = ISO15693_EAS_ALARM;
    req[reqlen++] = 0x04; // IC manufacturer code
    memcpy(req + 3, uid, 8); // add UID
    reqlen += 8;

    AddCrc15(req,  reqlen);
    reqlen += 2;

    clearCommandBuffer();
    SendCommandMIX(CMD_HF_ISO15693_COMMAND, reqlen, fast, reply, req, reqlen);

    if (WaitForResponseTimeout(CMD_HF_ISO15693_COMMAND, &resp, 2000) == false) {
        PrintAndLogEx(DEBUG, "iso15693 timeout");
    } else {
        PrintAndLogEx(INFO, "");
        if (resp.length < 2) {
            PrintAndLogEx(INFO, "  EAS (Electronic Article Surveillance) is not active");
        } else {
            uint8_t *recv = resp.data.asBytes;

            if (!(recv[0] & ISO15_RES_ERROR)) {
                PrintAndLogEx(INFO, "  EAS (Electronic Article Surveillance) is active.");
                PrintAndLogEx(INFO, "  EAS sequence: %s", sprint_hex(recv + 1, 32));
            }
        }
    }
    return PM3_SUCCESS;
}

static int NxpCheckSig(uint8_t *uid) {
    uint8_t fast = 1;
    uint8_t reply = 1;
    PacketResponseNG resp;
    uint16_t reqlen = 0;
    uint8_t req[PM3_CMD_DATA_SIZE] = {0};

    // Check if we can also read the signature
    req[reqlen++] |= ISO15_REQ_SUBCARRIER_SINGLE | ISO15_REQ_DATARATE_HIGH | ISO15_REQ_NONINVENTORY | ISO15_REQ_ADDRESS;
    req[reqlen++] = ISO15693_READ_SIGNATURE;
    req[reqlen++] = 0x04; // IC manufacturer code
    memcpy(req + 3, uid, 8); // add UID
    reqlen += 8;

    AddCrc15(req,  reqlen);
    reqlen += 2;

    clearCommandBuffer();
    SendCommandMIX(CMD_HF_ISO15693_COMMAND, reqlen, fast, reply, req, reqlen);

    if (WaitForResponseTimeout(CMD_HF_ISO15693_COMMAND, &resp, 2000) == false) {
        PrintAndLogEx(DEBUG, "iso15693 timeout");
        DropField();
        return PM3_ETIMEOUT;
    }

    DropField();

    if (resp.length < 2) {
        PrintAndLogEx(WARNING, "iso15693 card doesn't answer to READ SIGNATURE command");
        return PM3_EWRONGANSWER;
    }

    uint8_t *recv = resp.data.asBytes;

    if ((recv[0] & ISO15_RES_ERROR) == ISO15_RES_ERROR) {
        PrintAndLogEx(ERR, "iso15693 card returned error %i: %s", recv[0], TagErrorStr(recv[0]));
        return PM3_EWRONGANSWER;
    }

    uint8_t signature[32] = {0x00};
    memcpy(signature, recv + 1, sizeof(signature));

    nxp_15693_print_signature(uid, signature);
    return PM3_SUCCESS;
}

// Get NXP system information from SLIX2 tag/VICC
static int NxpSysInfo(uint8_t *uid) {

    if (uid == NULL) {
        return PM3_EINVARG;
    }

    uint8_t req[PM3_CMD_DATA_SIZE] = {0};
    uint8_t fast = 1;
    uint8_t reply = 1;
    uint16_t reqlen = 0;

    req[reqlen++] |= ISO15_REQ_SUBCARRIER_SINGLE | ISO15_REQ_DATARATE_HIGH | ISO15_REQ_NONINVENTORY | ISO15_REQ_ADDRESS;
    req[reqlen++] = ISO15693_GET_NXP_SYSTEM_INFO;
    req[reqlen++] = 0x04; // IC manufacturer code
    memcpy(req + 3, uid, 8); // add UID
    reqlen += 8;

    AddCrc15(req,  reqlen);
    reqlen += 2;

    PacketResponseNG resp;
    clearCommandBuffer();
    SendCommandMIX(CMD_HF_ISO15693_COMMAND, reqlen, fast, reply, req, reqlen);
    if (WaitForResponseTimeout(CMD_HF_ISO15693_COMMAND, &resp, 2000) == false) {
        PrintAndLogEx(DEBUG, "iso15693 timeout");
        DropField();
        return PM3_ETIMEOUT;
    }

    DropField();

    if (resp.status == PM3_ETEAROFF) {
        return resp.status;
    }

    if (resp.length < 2) {
        PrintAndLogEx(WARNING, "iso15693 card doesn't answer to NXP systeminfo command");
        return PM3_EWRONGANSWER;
    }

    uint8_t *recv = resp.data.asBytes;

    if ((recv[0] & ISO15_RES_ERROR) == ISO15_RES_ERROR) {
        PrintAndLogEx(ERR, "iso15693 card returned error %i: %s", recv[0], TagErrorStr(recv[0]));
        return PM3_EWRONGANSWER;
    }

    bool support_signature = (recv[5] & 0x01);
    bool support_easmode = (recv[4] & 0x04);

    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("NXP Sysinfo"));
    PrintAndLogEx(INFO, "  raw... %s", sprint_hex(recv, 8));
    PrintAndLogEx(INFO, "    " _CYAN_("Password protection configuration:"));
    PrintAndLogEx(INFO, "      * Page L read%s password protected", ((recv[2] & 0x01) ? "" : _GREEN_(" not")));
    PrintAndLogEx(INFO, "      * Page L write%s password protected", ((recv[2] & 0x02) ? "" : _GREEN_(" not")));
    PrintAndLogEx(INFO, "      * Page H read%s password protected", ((recv[2] & 0x10) ? "" : _GREEN_(" not")));
    PrintAndLogEx(INFO, "      * Page H write%s password protected", ((recv[2] & 0x20) ? "" : _GREEN_(" not")));

    PrintAndLogEx(INFO, "    " _CYAN_("Lock bits:"));
    // AFI lock bit
    PrintAndLogEx(INFO, "      * AFI%s locked", ((recv[3] & 0x01) ? "" : _GREEN_(" not")));

    // EAS lock bit
    PrintAndLogEx(INFO, "      * EAS%s locked", ((recv[3] & 0x02) ? "" : _GREEN_(" not")));

    // DSFID lock bit
    PrintAndLogEx(INFO, "      * DSFID%s locked", ((recv[3] & 0x03) ? "" : _GREEN_(" not")));

    // Password protection pointer address and access conditions lock bit
    PrintAndLogEx(INFO, "      * Password protection configuration%s locked", ((recv[3] & 0x04) ? "" : _GREEN_(" not")));

    PrintAndLogEx(INFO, "    " _CYAN_("Features:"));
    PrintAndLogEx(INFO, "      * User memory password protection%s supported", ((recv[4] & 0x01) ? "" : " not"));
    PrintAndLogEx(INFO, "      * Counter feature%s supported", ((recv[4] & 0x02) ? "" : " not"));
    PrintAndLogEx(INFO, "      * EAS ID%s supported by EAS ALARM command", support_easmode ? "" : " not");
    PrintAndLogEx(INFO, "      * EAS password protection%s supported", ((recv[4] & 0x08) ? "" : " not"));
    PrintAndLogEx(INFO, "      * AFI password protection%s supported", ((recv[4] & 0x10) ? "" : " not"));
    PrintAndLogEx(INFO, "      * Extended mode%s supported by INVENTORY READ command", ((recv[4] & 0x20) ? "" : " not"));
    PrintAndLogEx(INFO, "      * EAS selection%s supported by extended mode in INVENTORY READ command", ((recv[4] & 0x40) ? "" : " not"));
    PrintAndLogEx(INFO, "      * READ SIGNATURE command%s supported", support_signature ? "" : " not");
    PrintAndLogEx(INFO, "      * Password protection for READ SIGNATURE command%s supported", ((recv[5] & 0x02) ? "" : " not"));
    PrintAndLogEx(INFO, "      * STAY QUIET PERSISTENT command%s supported", ((recv[5] & 0x04) ? "" : " not"));
    PrintAndLogEx(INFO, "      * ENABLE PRIVACY command%s supported", ((recv[5] & 0x10) ? "" : " not"));
    PrintAndLogEx(INFO, "      * DESTROY command%s supported", ((recv[5] & 0x20) ? "" : " not"));
    PrintAndLogEx(INFO, "      * Additional 32 bits feature flags are%s transmitted", ((recv[7] & 0x80) ? "" : " not"));

    if (support_easmode) {
        NxpTestEAS(uid);
    }

    if (support_signature) {
        NxpCheckSig(uid);
    }

    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}

/**
 * Commandline handling: HF15 CMD SYSINFO
 * get system information from tag/VICC
 */
static int CmdHF15Info(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf 15 info",
                  "Uses the optional command `get_systeminfo` 0x2B to try and extract information",
                  "hf 15 info\n"
                  "hf 15 info -*\n"
                  "hf 15 info -u E011223344556677"
                 );

    void *argtable[6 + 1] = {};
    uint8_t arglen = arg_add_default(argtable);
    argtable[arglen++] = arg_param_end;

    CLIExecWithReturn(ctx, Cmd, argtable, true);

    uint8_t uid[8];
    int uidlen = 0;
    CLIGetHexWithReturn(ctx, 1, uid, &uidlen);
    bool unaddressed = arg_get_lit(ctx, 2);
    bool scan = arg_get_lit(ctx, 3);
    int fast = (arg_get_lit(ctx, 4) == false);
    bool add_option = arg_get_lit(ctx, 5);

    CLIParserFree(ctx);

    // sanity checks
    if ((scan + unaddressed + uidlen) > 1) {
        PrintAndLogEx(WARNING, "Select only one option /scan/unaddress/uid");
        return PM3_EINVARG;
    }

    // default fallback to scan for tag.
    if (unaddressed == false && uidlen != 8) {
        scan = true;
    }

    // request to be sent to device/card
    uint16_t flags = arg_get_raw_flag(uidlen, unaddressed, scan, add_option);
    uint8_t req[PM3_CMD_DATA_SIZE] = {flags, ISO15693_GET_SYSTEM_INFO};
    uint16_t reqlen = 2;

    if (scan) {
        if (getUID(false, uid) != PM3_SUCCESS) {
            PrintAndLogEx(WARNING, "no tag found");
            return PM3_EINVARG;
        }
        uidlen = 8;
    }

    if (uidlen == 8) {
        // add UID (scan, uid)
        memcpy(req + reqlen, uid, sizeof(uid));
        reqlen += sizeof(uid);
    }
    PrintAndLogEx(SUCCESS, "Using UID... " _GREEN_("%s"), iso15693_sprintUID(NULL, uid));


    AddCrc15(req,  reqlen);
    reqlen += 2;

    uint8_t read_response = 1;
    PacketResponseNG resp;
    clearCommandBuffer();
    SendCommandMIX(CMD_HF_ISO15693_COMMAND, reqlen, fast, read_response, req, reqlen);
    if (WaitForResponseTimeout(CMD_HF_ISO15693_COMMAND, &resp, 2000) == false) {
        PrintAndLogEx(WARNING, "iso15693 timeout");
        DropField();
        return PM3_ETIMEOUT;
    }

    DropField();

    if (resp.status == PM3_ETEAROFF) {
        return resp.status;
    }
    if (resp.length < 2) {
        PrintAndLogEx(WARNING, "iso15693 card doesn't answer to systeminfo command (%d)", resp.length);
        return PM3_EWRONGANSWER;
    }

    uint8_t *data = resp.data.asBytes;

    if ((data[0] & ISO15_RES_ERROR) == ISO15_RES_ERROR) {
        PrintAndLogEx(ERR, "iso15693 card returned error %i: %s", data[0], TagErrorStr(data[0]));
        return PM3_EWRONGANSWER;
    }

    memcpy(uid, data + 2, sizeof(uid));
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Tag Information") " ---------------------------");
    PrintAndLogEx(SUCCESS, "      TYPE: " _YELLOW_("%s"), getTagInfo_15(data + 2));
    PrintAndLogEx(SUCCESS, "       UID: " _GREEN_("%s"), iso15693_sprintUID(NULL, uid));
    PrintAndLogEx(SUCCESS, "   SYSINFO: %s", sprint_hex(data, resp.length - 2));

    // DSFID
    if (data[1] & 0x01)
        PrintAndLogEx(SUCCESS, "     - DSFID supported        [0x%02X]", data[10]);
    else
        PrintAndLogEx(SUCCESS, "     - DSFID not supported");

    // AFI
    if (data[1] & 0x02)
        PrintAndLogEx(SUCCESS, "     - AFI   supported        [0x%02X]", data[11]);
    else
        PrintAndLogEx(SUCCESS, "     - AFI   not supported");

    // IC reference
    if (data[1] & 0x08)
        PrintAndLogEx(SUCCESS, "     - IC reference supported [0x%02X]", data[14]);
    else
        PrintAndLogEx(SUCCESS, "     - IC reference not supported");

    // memory
    if (data[1] & 0x04) {
        PrintAndLogEx(SUCCESS, "     - Tag provides info on memory layout (vendor dependent)");
        uint8_t blocks = data[12] + 1;
        uint8_t size = (data[13] & 0x1F);
        PrintAndLogEx(SUCCESS, "           %u (or %u) bytes/blocks x %u blocks", size + 1, size, blocks);
    } else {
        PrintAndLogEx(SUCCESS, "     - Tag does not provide information on memory layout");
    }

    // Check if SLIX2 and attempt to get NXP System Information
    PrintAndLogEx(DEBUG, "Byte 6 :: %02x   Byte 7 :: %02x   Byte 8 :: %02x", data[6], data[7], data[8]);
    // SLIX2 uses xxx0 1xxx format on data[6] of UID
    uint8_t nxp_version = data[6] & 0x18;
    PrintAndLogEx(DEBUG, "NXP Version: %02x", nxp_version);
    if (data[8] == 0x04 && data[7] == 0x01 && nxp_version == 0x08) {
        PrintAndLogEx(DEBUG, "SLIX2 Detected, getting NXP System Info");
        return NxpSysInfo(uid);
    } else if (data[8] == 0x04 && data[7] == 0x01 && nxp_version == 0x18) { //If it is an NTAG 5
        PrintAndLogEx(DEBUG, "NTAG 5 Detected, getting NXP System Info");
        return NxpSysInfo(uid);
    } else if (data[8] == 0x04 && (data[7] == 0x01 || data[7] == 0x02 || data[7] == 0x03)) { //If SLI, SLIX, SLIX-l, or SLIX-S check EAS status
        PrintAndLogEx(DEBUG, "SLI, SLIX, SLIX-L, or SLIX-S Detected checking EAS status");
        return NxpTestEAS(uid);
    }

    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}

// Sniff Activity without enabling carrier
static int CmdHF15Sniff(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf 15 sniff",
                  "Sniff activity without enabling carrier",
                  "hf 15 sniff\n");

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);

    PacketResponseNG resp;
    clearCommandBuffer();
    SendCommandNG(CMD_HF_ISO15693_SNIFF, NULL, 0);

    WaitForResponse(CMD_HF_ISO15693_SNIFF, &resp);

    PrintAndLogEx(HINT, "Try `" _YELLOW_("hf 15 list") "` to view captured tracelog");
    PrintAndLogEx(HINT, "Try `" _YELLOW_("trace save -h") "` to save tracelog for later analysing");
    return PM3_SUCCESS;
}

static int CmdHF15Reader(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf 15 reader",
                  "Act as a ISO-15693 reader.  Look for ISO-15693 tags until Enter or the pm3 button is pressed\n",
                  "hf 15 reader\n"
                  "hf 15 reader -@   -> Continuous mode");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("@", NULL, "continuous reader mode"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool cm = arg_get_lit(ctx, 1);
    CLIParserFree(ctx);

    if (cm) {
        PrintAndLogEx(INFO, "press " _GREEN_("`Enter`") " to exit");
    }
    readHF15Uid(cm, true);
    return PM3_SUCCESS;
}

static int hf15EmlClear(void) {
    clearCommandBuffer();
    SendCommandNG(CMD_HF_ISO15693_EML_CLEAR, NULL, 0);
    PacketResponseNG resp;
    WaitForResponse(CMD_HF_ISO15693_EML_CLEAR, &resp);
    return PM3_SUCCESS;
}

static int hf15EmlSetMem(uint8_t *data, uint8_t count, size_t offset) {
    struct p {
        uint32_t offset;
        uint8_t count;
        uint8_t data[];
    } PACKED;

    size_t size = count;
    if (size > (PM3_CMD_DATA_SIZE - sizeof(struct p))) {
        return PM3_ESOFT;
    }

    size_t paylen = sizeof(struct p) + size;
    struct p *payload = calloc(1, paylen);

    payload->offset = offset;
    payload->count = count;
    memcpy(payload->data, data, size);

    clearCommandBuffer();
    SendCommandNG(CMD_HF_ISO15693_EML_SETMEM, (uint8_t *)payload, paylen);
    free(payload);
    return PM3_SUCCESS;
}

static int CmdHF15ELoad(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf 15 eload",
                  "Load memory image from file to be used with 'hf 15 sim'",
                  "hf 15 eload -f hf-15-01020304.bin\n"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_str1("f", "file", "<fn>", "filename of image"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE];
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);
    CLIParserFree(ctx);

    uint8_t *data = NULL;
    size_t bytes_read = 0;
    int res = pm3_load_dump(filename, (void **)&data, &bytes_read, CARD_MEMORY_SIZE);
    if (res != PM3_SUCCESS) {
        return res;
    }

    if (bytes_read > CARD_MEMORY_SIZE) {
        PrintAndLogEx(FAILED, "Memory image too large.");
        free(data);
        return PM3_EINVARG;
    }
    if (bytes_read == 0) {
        PrintAndLogEx(FAILED, "Memory image empty.");
        free(data);
        return PM3_EINVARG;
    }

    PrintAndLogEx(INFO, "Clearing emulator memory");
    fflush(stdout);
    hf15EmlClear();

    PrintAndLogEx(INFO, "Uploading to emulator memory");
    PrintAndLogEx(INFO, "." NOLF);

    // fast push mode
    g_conn.block_after_ACK = true;

    int chuncksize = 64;
    size_t offset = 0;

    while (bytes_read > 0) {
        if (bytes_read <= chuncksize) {
            // Disable fast mode on last packet
            g_conn.block_after_ACK = false;
        }

        int tosend = MIN(chuncksize, bytes_read);
        if (hf15EmlSetMem(data + offset, tosend, offset) != PM3_SUCCESS) {
            PrintAndLogEx(FAILED, "Can't set emulator memory at offest: %zu / 0x%zx", offset, offset);
            free(data);
            return PM3_ESOFT;
        }
        PrintAndLogEx(NORMAL, "." NOLF);
        fflush(stdout);

        offset += tosend;
        bytes_read -= tosend;
    }
    free(data);
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(SUCCESS, "uploaded " _YELLOW_("%zu") " bytes to emulator memory", offset);

    PrintAndLogEx(HINT, "You are ready to simulate. See " _YELLOW_("`hf 15 sim -h`"));
    PrintAndLogEx(INFO, "Done!");
    return PM3_SUCCESS;
}

static int CmdHF15ESave(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf 15 esave",
                  "Save emulator memory into three files (BIN/EML/JSON) ",
                  "hf 15 esave -f hf-15-01020304"
                  "hf 15 esave -b 8 -c 42 -f hf-15-01020304"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_str1("f", "file", "<fn>", "filename of dump"),
        arg_int0("b", "blocksize", "<dec>", "block size, defaults to 4"),
        arg_int0("c", "count", "<dec>", "number of blocks to export, defaults to all"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE];
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);
    int blocksize = arg_get_int_def(ctx, 2, 4);
    int count = arg_get_int_def(ctx, 3, -1);
    CLIParserFree(ctx);

    int bytes = CARD_MEMORY_SIZE;
    if (count > 0 && count * blocksize <= bytes) {
        bytes = count * blocksize;
    }

    // reserve memory
    uint8_t *dump = calloc(bytes, sizeof(uint8_t));
    if (dump == NULL) {
        PrintAndLogEx(WARNING, "Fail, cannot allocate memory");
        return PM3_EMALLOC;
    }

    PrintAndLogEx(INFO, "Downloading %u bytes from emulator memory", bytes);
    if (!GetFromDevice(BIG_BUF_EML, dump, bytes, 0, NULL, 0, NULL, 2500, false)) {
        PrintAndLogEx(WARNING, "Fail, transfer from device time-out");
        free(dump);
        return PM3_ETIMEOUT;
    }

    pm3_save_dump(filename, dump, bytes, jsf15, blocksize);
    free(dump);
    return PM3_SUCCESS;
}

static void print_hrule(int blocksize) {
    char dashes[] = "------------------------------------------------------------";
    PrintAndLogEx(INFO, "-----+%.*s-+-%.*s-", 3 * blocksize, dashes, blocksize, dashes);
}

static void print_blocks_15693(uint8_t *data, uint16_t bytes, int blocksize) {
    int blocks = bytes / blocksize;
    PrintAndLogEx(NORMAL, "");
    print_hrule(blocksize);
    char spaces[] = "                                                            ";
    PrintAndLogEx(INFO, " blk | data %.*s| ascii", MAX(0, 3 * blocksize - 5), spaces);
    print_hrule(blocksize);
    for (int i = 0; i < blocks; i++) {
        PrintAndLogEx(INFO, "%4d | %s ", i, sprint_hex_ascii(data + (i * blocksize), blocksize));

    }
    if (bytes % blocksize != 0)  {
        // If there is something left over print it too
        // This will have a broken layout, but should not happen anyway
        PrintAndLogEx(INFO, "%4d | %s ", blocks, sprint_hex_ascii(data + (blocks * blocksize),
                                                                  bytes % blocksize));
    }
    print_hrule(blocksize);
    PrintAndLogEx(NORMAL, "");
}

static int CmdHF15EView(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf 15 eview",
                  "It displays emulator memory",
                  "hf 15 eview\n"
                  "hf 15 eview -b 8 -c 60\n"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_int0("b", "blocksize", "<dec>", "block size, defaults to 4"),
        arg_int0("c", "count", "<dec>", "number of blocks to display, defaults to all"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    int blocksize = arg_get_int_def(ctx, 1, 4);
    int count = arg_get_int_def(ctx, 2, -1);
    CLIParserFree(ctx);

    int bytes = CARD_MEMORY_SIZE;
    if (count > 0 && count * blocksize <= bytes) {
        bytes = count * blocksize;
    }

    uint8_t *dump = calloc(bytes, sizeof(uint8_t));
    if (dump == NULL) {
        PrintAndLogEx(WARNING, "Fail, cannot allocate memory");
        return PM3_EMALLOC;
    }

    PrintAndLogEx(INFO, "Downloading %u bytes from emulator memory", bytes);
    if (!GetFromDevice(BIG_BUF_EML, dump, bytes, 0, NULL, 0, NULL, 2500, false)) {
        PrintAndLogEx(WARNING, "Fail, transfer from device time-out");
        free(dump);
        return PM3_ETIMEOUT;
    }

    print_blocks_15693(dump, bytes, blocksize);
    free(dump);
    return PM3_SUCCESS;
}

// Simulation is still not working very good
// helptext
static int CmdHF15Sim(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf 15 sim",
                  "Simulate a ISO-15693 tag\n",
                  "hf 15 sim -u E011223344556677");

    void *argtable[] = {
        arg_param_begin,
        arg_str1("u", "uid", "<8b hex>", "UID eg E011223344556677"),
        arg_int0("b", "blocksize", "<dec>", "block size, defaults to 4"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    struct {
        uint8_t uid[8];
        uint8_t block_size;
    } PACKED payload;

    int uidlen = 0;
    CLIGetHexWithReturn(ctx, 1, payload.uid, &uidlen);
    if (uidlen != 8) {
        PrintAndLogEx(WARNING, "UID must include 16 HEX symbols");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    payload.block_size = arg_get_int_def(ctx, 2, 4);
    CLIParserFree(ctx);

    PrintAndLogEx(SUCCESS, "Starting simulating UID " _YELLOW_("%s"), iso15693_sprintUID(NULL, payload.uid));
    PrintAndLogEx(INFO, "Press " _YELLOW_("`pm3-button`") " to abort simulation");

    PacketResponseNG resp;
    clearCommandBuffer();
    SendCommandNG(CMD_HF_ISO15693_SIMULATE, (uint8_t *)&payload, sizeof(payload));
    WaitForResponse(CMD_HF_ISO15693_SIMULATE, &resp);
    PrintAndLogEx(INFO, "Done!");
    return PM3_SUCCESS;
}

// finds the AFI (Application Family Identifier) of a card, by trying all values
// (There is no standard way of reading the AFI, although some tags support this)
// helptext
static int CmdHF15FindAfi(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf 15 findafi",
                  "This command attempts to brute force AFI of an ISO-15693 tag\n"
                  "Estimated execution time is around 2 minutes",
                  "hf 15 findafi");

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);

    PrintAndLogEx(INFO, "click " _GREEN_("pm3 button") " or press " _GREEN_("Enter") " to exit");
    clearCommandBuffer();
    PacketResponseNG resp;
    SendCommandMIX(CMD_HF_ISO15693_FINDAFI, strtol(Cmd, NULL, 0), 0, 0, NULL, 0);

    uint32_t timeout = 0;
    for (;;) {

        if (kbd_enter_pressed()) {
            SendCommandNG(CMD_BREAK_LOOP, NULL, 0);
            PrintAndLogEx(DEBUG, "User aborted");
            msleep(300);
            break;
        }

        if (WaitForResponseTimeout(CMD_HF_ISO15693_FINDAFI, &resp, 2000)) {
            if (resp.status == PM3_EOPABORTED) {
                PrintAndLogEx(DEBUG, "Button pressed, user aborted");
            }
            break;
        }

        // should be done in about 2 minutes
        if (timeout > 180) {
            PrintAndLogEx(WARNING, "\nNo response from Proxmark3. Aborting...");
            break;
        }
        timeout++;
    }

    DropField();
    PrintAndLogEx(INFO, "Done");
    return PM3_SUCCESS;
}

// Writes the AFI (Application Family Identifier) of a card
static int CmdHF15WriteAfi(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf 15 writeafi",
                  "Write AFI on card",
                  "hf 15 writeafi -* --afi 12\n"
                  "hf 15 writeafi -u E011223344556677 --afi 12 -p 0F0F0F0F"
                 );

    void *argtable[5] = {};
    argtable[0] = arg_param_begin;
    argtable[1] = arg_str0("u", "uid", "<hex>", "full UID, 8 bytes");
    argtable[2] = arg_int1(NULL, "afi", "<dec>", "AFI number (0-255)");
    argtable[3] = arg_str0("p", "pwd", "<hex>", "optional AFI/EAS password");
    argtable[4] = arg_param_end;

    CLIExecWithReturn(ctx, Cmd, argtable, true);

    struct {
        uint8_t pwd[4];
        bool use_pwd;
        uint8_t uid[8];
        bool use_uid;
        uint8_t afi;
    } PACKED payload;

    int uidlen = 0;
    CLIGetHexWithReturn(ctx, 1, payload.uid, &uidlen);

    payload.afi = arg_get_int_def(ctx, 2, 0);

    int pwdlen;
    CLIGetHexWithReturn(ctx, 3, payload.pwd, &pwdlen);

    CLIParserFree(ctx);

    payload.use_pwd = false;
    if (pwdlen == 4) {
        payload.use_pwd = true;
    }

    payload.use_uid = false;
    if (uidlen == 8) {
        payload.use_uid = true;
    }

    // sanity checks
    if (uidlen != 0 && uidlen != 8) {
        PrintAndLogEx(WARNING, "uid must be 8 hex bytes if provided");
        return PM3_EINVARG;
    }

    if (pwdlen > 0 && pwdlen != 4) {
        PrintAndLogEx(WARNING, "password must be 4 hex bytes if provided");
        return PM3_ESOFT;
    }

    PacketResponseNG resp;
    clearCommandBuffer();
    SendCommandNG(CMD_HF_ISO15693_WRITE_AFI, (uint8_t *)&payload, sizeof(payload));
    if (WaitForResponseTimeout(CMD_HF_ISO15693_WRITE_AFI, &resp, 2000) == false) {
        PrintAndLogEx(WARNING, "timeout while waiting for reply");
        DropField();
        return PM3_ESOFT;
    }

    switch (resp.status) {
        case PM3_ETIMEOUT: {
            PrintAndLogEx(WARNING, "no tag found");
            break;
        }
        case PM3_EWRONGANSWER: {
            PrintAndLogEx(WARNING, "error writing AFI");
            break;
        }
        case PM3_SUCCESS: {
            PrintAndLogEx(SUCCESS, "Wrote AFI 0x%02X", payload.afi);
            break;
        }
    }
    return resp.status;
}

// Writes the DSFID (Data Storage Format Identifier) of a card
static int CmdHF15WriteDsfid(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf 15 writedsfid",
                  "Write DSFID on card",
                  "hf 15 writedsfid -* --dsfid 12\n"
                  "hf 15 writedsfid -u E011223344556677 --dsfid 12"
                 );

    void *argtable[6 + 2] = {};
    uint8_t arglen = arg_add_default(argtable);
    argtable[arglen++] = arg_int1(NULL, "dsfid", "<dec>", "DSFID number (0-255)");
    argtable[arglen++] = arg_param_end;

    CLIExecWithReturn(ctx, Cmd, argtable, false);

    uint8_t uid[8];
    int uidlen = 0;
    CLIGetHexWithReturn(ctx, 1, uid, &uidlen);
    bool unaddressed = arg_get_lit(ctx, 2);
    bool scan = arg_get_lit(ctx, 3);
    int fast = (arg_get_lit(ctx, 4) == false);
    bool add_option = arg_get_lit(ctx, 5);

    int dsfid = arg_get_int_def(ctx, 6, 0);
    CLIParserFree(ctx);

    // sanity checks
    if ((scan + unaddressed + uidlen) > 1) {
        PrintAndLogEx(WARNING, "Select only one option /scan/unaddress/uid");
        return PM3_EINVARG;
    }

    // request to be sent to device/card
    uint16_t flags = arg_get_raw_flag(uidlen, unaddressed, scan, add_option);
    uint8_t req[16] = {flags, ISO15693_WRITE_DSFID};
    // enforce, since we are writing
    req[0] |= ISO15_REQ_OPTION;
    uint16_t reqlen = 2;

    if (unaddressed == false) {
        if (scan) {
            if (getUID(false, uid) != PM3_SUCCESS) {
                PrintAndLogEx(WARNING, "no tag found");
                return PM3_EINVARG;
            }
            uidlen = 8;
        }

        if (uidlen == 8) {
            // add UID (scan, uid)
            memcpy(req + reqlen, uid, sizeof(uid));
            reqlen += sizeof(uid);
        }
        PrintAndLogEx(SUCCESS, "Using UID... " _GREEN_("%s"), iso15693_sprintUID(NULL, uid));
    }

    // dsfid
    req[reqlen++] = (uint8_t)dsfid;

    AddCrc15(req, reqlen);
    reqlen += 2;


    // arg: len, speed, recv?
    // arg0 (datalen,  cmd len?  .arg0 == crc?)
    // arg1 (speed == 0 == 1 of 256,  == 1 == 1 of 4 )
    // arg2 (recv == 1 == expect a response)
    uint8_t read_respone = 1;

    PrintAndLogEx(DEBUG, "cmd %s", sprint_hex(req, reqlen));
    PacketResponseNG resp;
    clearCommandBuffer();
    SendCommandMIX(CMD_HF_ISO15693_COMMAND, reqlen, fast, read_respone, req, reqlen);

    if (WaitForResponseTimeout(CMD_HF_ISO15693_COMMAND, &resp, 2000) == false) {
        PrintAndLogEx(ERR, "iso15693 timeout");
        DropField();
        return PM3_ETIMEOUT;
    }

    DropField();
    if (resp.status == PM3_ETEAROFF) {
        return resp.status;
    }

    uint8_t *data = resp.data.asBytes;

    if ((data[0] & ISO15_RES_ERROR) == ISO15_RES_ERROR) {
        PrintAndLogEx(ERR, "iso15693 card returned error %i: %s", data[0], TagErrorStr(data[0]));
        return PM3_EWRONGANSWER;
    }

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(SUCCESS, "Wrote DSFID 0x%02X", dsfid);
    return PM3_SUCCESS;
}

// Reads all memory pages
// need to write to file
static int CmdHF15Dump(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf 15 dump",
                  "This command dumps the contents of a ISO-15693 tag and save it to file",
                  "hf 15 dump\n"
                  "hf 15 dump -*\n"
                  "hf 15 dump -u E011223344556677 -f hf-15-my-dump.bin"
                 );

    void *argtable[6 + 2] = {};
    uint8_t arglen = arg_add_default(argtable);
    argtable[arglen++] = arg_str0("f", "file", "<fn>", "filename of dump"),
                         argtable[arglen++] = arg_param_end;

    CLIExecWithReturn(ctx, Cmd, argtable, true);

    uint8_t uid[8];
    int uidlen = 0;
    CLIGetHexWithReturn(ctx, 1, uid, &uidlen);
    bool unaddressed = arg_get_lit(ctx, 2);
    bool scan = arg_get_lit(ctx, 3);
    int fast = (arg_get_lit(ctx, 4) == false);
    bool add_option = arg_get_lit(ctx, 5);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 6), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);

    CLIParserFree(ctx);

    // sanity checks
    if ((scan + unaddressed + uidlen) > 1) {
        PrintAndLogEx(WARNING, "Select only one option /scan/unaddress/uid");
        return PM3_EINVARG;
    }

    // default fallback to scan for tag.
    // overriding unaddress parameter :)
    if (uidlen != 8) {
        scan = true;
    }

    // request to be sent to device/card
    uint16_t flags = arg_get_raw_flag(uidlen, unaddressed, scan, add_option);
    uint8_t req[13] = {flags, ISO15693_READBLOCK};
    uint16_t reqlen = 2;

    if (scan) {
        if (getUID(false, uid) != PM3_SUCCESS) {
            PrintAndLogEx(WARNING, "no tag found");
            return PM3_EINVARG;
        }
        uidlen = 8;
    }

    if (uidlen == 8) {
        // add UID (scan, uid)
        memcpy(req + reqlen, uid, sizeof(uid));
        reqlen += sizeof(uid);
    }
    PrintAndLogEx(SUCCESS, "Using UID... " _GREEN_("%s"), iso15693_sprintUID(NULL, uid));

    // detect blocksize from card :)

    PrintAndLogEx(SUCCESS, "Reading memory from tag UID " _YELLOW_("%s"), iso15693_sprintUID(NULL, uid));

    int blocknum = 0;
    // memory.
    t15memory_t mem[256];

    uint8_t data[256 * 4] = {0};
    memset(data, 0, sizeof(data));

    for (int retry = 0; (retry < 5 && blocknum < 0x100); retry++) {

        req[10] = blocknum;
        AddCrc15(req, 11);

        // arg: len, speed, recv?
        // arg0 (datalen,  cmd len?  .arg0 == crc?)
        // arg1 (speed == 0 == 1 of 256,  == 1 == 1 of 4 )
        // arg2 (recv == 1 == expect a response)
        uint8_t read_respone = 1;
        PacketResponseNG resp;
        clearCommandBuffer();
        SendCommandMIX(CMD_HF_ISO15693_COMMAND, sizeof(req), fast, read_respone, req, sizeof(req));

        if (WaitForResponseTimeout(CMD_HF_ISO15693_COMMAND, &resp, 2000)) {

            if (resp.status == PM3_ETEAROFF) {
                continue;
            }
            if (resp.length < 2) {
                PrintAndLogEx(NORMAL, "");
                PrintAndLogEx(FAILED, "iso15693 command failed");
                continue;
            }

            uint8_t *recv = resp.data.asBytes;

            if (CheckCrc15(recv, resp.length) == false) {
                PrintAndLogEx(NORMAL, "");
                PrintAndLogEx(FAILED, "crc ( " _RED_("fail") " )");
                continue;
            }

            if ((recv[0] & ISO15_RES_ERROR) == ISO15_RES_ERROR) {
                PrintAndLogEx(NORMAL, "");
                PrintAndLogEx(FAILED, "Tag returned Error %i: %s", recv[1], TagErrorStr(recv[1]));
                break;
            }

            mem[blocknum].lock = resp.data.asBytes[0];
            memcpy(mem[blocknum].block, resp.data.asBytes + 1, 4);
            memcpy(data + (blocknum * 4), resp.data.asBytes + 1, 4);

            retry = 0;
            blocknum++;

            PrintAndLogEx(INPLACE, "blk %3d", blocknum);
        }
    }

    DropField();

    PrintAndLogEx(NORMAL, "\n");
    PrintAndLogEx(INFO, "block#   | data         |lck| ascii");
    PrintAndLogEx(INFO, "---------+--------------+---+----------");
    for (int i = 0; i < blocknum; i++) {
        char lck[16] = {0};
        if (mem[i].lock) {
            snprintf(lck, sizeof(lck), _RED_("%d"), mem[i].lock);
        } else {
            snprintf(lck, sizeof(lck), "%d", mem[i].lock);
        }
        PrintAndLogEx(INFO, "%3d/0x%02X | %s | %s | %s"
                      , i
                      , i
                      , sprint_hex(mem[i].block, 4)
                      , lck
                      , sprint_ascii(mem[i].block, 4)
                     );
    }
    PrintAndLogEx(NORMAL, "");

    // user supplied filename ?
    if (strlen(filename) < 1) {
        char *fptr = filename;
        PrintAndLogEx(INFO, "Using UID as filename");
        fptr += snprintf(fptr, sizeof(filename), "hf-15-");
        FillFileNameByUID(fptr, SwapEndian64(uid, sizeof(uid), 8), "-dump", sizeof(uid));
    }

    size_t datalen = blocknum * 4;
    pm3_save_dump(filename, data, datalen, jsf15, 4);
    return PM3_SUCCESS;
}

static int CmdHF15List(const char *Cmd) {
    return CmdTraceListAlias(Cmd, "hf 15", "15");
}

static int CmdHF15Raw(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf 15 raw",
                  "Sends raw bytes over ISO-15693 to card",
                  "hf 15 raw -c -d 260100    --> add crc\n"
                  "hf 15 raw -krc -d 260100  --> add crc, keep field on, skip response"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("2", NULL, "use slower '1 out of 256' mode"),
        arg_lit0("c",  "crc", "calculate and append CRC"),
        arg_lit0("k",  NULL, "keep signal field ON after receive"),
        arg_lit0("r",  NULL, "do not read response"),
        arg_str1("d", "data", "<hex>", "raw bytes to send"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    int fast = (arg_get_lit(ctx, 1) == false);
    bool crc = arg_get_lit(ctx, 2);
    bool keep_field_on = arg_get_lit(ctx, 3);
    bool read_respone = (arg_get_lit(ctx, 4) == false);
    int datalen = 0;
    uint8_t data[300];
    CLIGetHexWithReturn(ctx, 5, data, &datalen);
    CLIParserFree(ctx);

    if (crc) {
        AddCrc15(data, datalen);
        datalen += 2;
    }

    // arg: len, speed, recv?
    // arg0 (datalen,  cmd len?  .arg0 == crc?)
    // arg1 (speed == 0 == 1 of 256,  == 1 == 1 of 4 )
    // arg2 (recv == 1 == expect a response)
    PacketResponseNG resp;
    clearCommandBuffer();
    SendCommandMIX(CMD_HF_ISO15693_COMMAND, datalen, fast, read_respone, data, datalen);

    if (read_respone) {
        if (WaitForResponseTimeout(CMD_HF_ISO15693_COMMAND, &resp, 2000)) {
            if (resp.status == PM3_ETEAROFF) {
                DropField();
                return resp.status;
            }
            if (resp.length < 2) {
                PrintAndLogEx(WARNING, "command failed");
            } else {
                PrintAndLogEx(SUCCESS, "received %i octets", resp.length);
                PrintAndLogEx(SUCCESS, "%s", sprint_hex(resp.data.asBytes, resp.length));
            }
        } else {
            PrintAndLogEx(WARNING, "timeout while waiting for reply");
        }
    }

    if (keep_field_on == false) {
        DropField();
    }
    return PM3_SUCCESS;
}

/**
 * Commandline handling: HF15 CMD READMULTI
 * Read multiple blocks at once (not all tags support this)
 */
static int CmdHF15Readmulti(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf 15 rdmulti",
                  "Read multiple pages on a ISO-15693 tag ",
                  "hf 15 rdmulti -* -b 1 --cnt 6                   -> read 6 blocks\n"
                  "hf 15 rdmulti -u E011223344556677 -b 12 --cnt 3 -> read three blocks"
                 );

    void *argtable[6 + 3] = {};
    uint8_t arglen = arg_add_default(argtable);
    argtable[arglen++] = arg_int1("b", NULL, "<dec>", "first page number (0-255)");
    argtable[arglen++] = arg_int1(NULL, "cnt", "<dec>", "number of pages (1-6)");
    argtable[arglen++] = arg_param_end;

    CLIExecWithReturn(ctx, Cmd, argtable, false);

    uint8_t uid[HF15_UID_LENGTH];
    int uidlen = 0;
    CLIGetHexWithReturn(ctx, 1, uid, &uidlen);
    bool uid_set = (uidlen == HF15_UID_LENGTH) ? true : false;

    bool unaddressed = arg_get_lit(ctx, 2);
    bool scan = (arg_get_lit(ctx, 3) || (!uid_set && !unaddressed)) ? true : false; //Default fallback to scan for tag. Overriding unaddressed parameter.
    int fast = (arg_get_lit(ctx, 4) == false);
    bool add_option = arg_get_lit(ctx, 5);

    int block = arg_get_int_def(ctx, 6, 0);
    int blockcnt = arg_get_int_def(ctx, 7, 0);

    CLIParserFree(ctx);

    // sanity checks
    if (blockcnt > 6) {
        PrintAndLogEx(WARNING, "Page count must be 6 or less (%d)", blockcnt);
        return PM3_EINVARG;
    }

    if ((scan + unaddressed + uid_set) > 1) {
        PrintAndLogEx(WARNING, "Select only one option /scan/unaddress/uid");
        return PM3_EINVARG;
    }

    // request to be sent to device/card
    uint16_t flags = arg_get_raw_flag(uidlen, unaddressed, scan, add_option);
    uint8_t req[PM3_CMD_DATA_SIZE] = {flags, ISO15693_READ_MULTI_BLOCK};
    uint16_t reqlen = 2;

    if (unaddressed == false) {
        if (scan) {
            if (getUID(false, uid) != PM3_SUCCESS) {
                PrintAndLogEx(WARNING, "no tag found");
                return PM3_EINVARG;
            }
        } else {
            reverse_array(uid, HF15_UID_LENGTH);
        }
        // add UID (scan, uid)
        memcpy(req + reqlen, uid, HF15_UID_LENGTH);
        reqlen += HF15_UID_LENGTH;

        PrintAndLogEx(SUCCESS, "Using UID... " _GREEN_("%s"), iso15693_sprintUID(NULL, uid));
    }
    // add OPTION flag, in order to get lock-info
    req[0] |= ISO15_REQ_OPTION;

    // 0 means 1 page,
    // 1 means 2 pages, ...
    if (blockcnt > 0) blockcnt--;

    req[reqlen++] = block;
    req[reqlen++] = blockcnt;

    AddCrc15(req, reqlen);
    reqlen += 2;

    uint8_t read_respone = 1;
    PacketResponseNG resp;
    clearCommandBuffer();
    SendCommandMIX(CMD_HF_ISO15693_COMMAND, reqlen, fast, read_respone, req, reqlen);

    if (WaitForResponseTimeout(CMD_HF_ISO15693_COMMAND, &resp, 2000) == false) {
        PrintAndLogEx(FAILED, "iso15693 card timeout");
        DropField();
        return PM3_ETIMEOUT;
    }

    DropField();

    if (resp.status == PM3_ETEAROFF) {
        return resp.status;
    }

    if (resp.length < 2) {
        PrintAndLogEx(FAILED, "iso15693 card readmulti failed");
        return PM3_EWRONGANSWER;
    }

    uint8_t *data = resp.data.asBytes;

    if (CheckCrc15(data, resp.length) == false) {
        PrintAndLogEx(FAILED, "crc ( " _RED_("fail") " )");
        return PM3_ESOFT;
    }

    if ((data[0] & ISO15_RES_ERROR) ==  ISO15_RES_ERROR) {
        PrintAndLogEx(FAILED, "iso15693 card returned error %i: %s", data[0], TagErrorStr(data[0]));
        return PM3_EWRONGANSWER;
    }

    // skip status byte
    int start = 1;
    int stop = (blockcnt + 1) * 5;
    int currblock = block;

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, " #       | data         |lck| ascii");
    PrintAndLogEx(INFO, "---------+--------------+---+----------");

    for (int i = start; i < stop; i += 5) {
        char lck[16] = {0};
        if (data[i]) {
            snprintf(lck, sizeof(lck), _RED_("%d"), data[i]);
        } else {
            snprintf(lck, sizeof(lck), "%d", data[i]);
        }
        PrintAndLogEx(INFO, "%3d/0x%02X | %s | %s | %s", currblock, currblock, sprint_hex(data + i + 1, 4), lck, sprint_ascii(data + i + 1, 4));
        currblock++;
    }
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}

/**
 * Commandline handling: HF15 CMD READ
 * Reads a single Block
 */
static int CmdHF15Readblock(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf 15 rdbl",
                  "Read page on ISO-15693 tag",
                  "hf 15 rdbl -* -b 12\n"
                  "hf 15 rdbl -u E011223344556677 -b 12"
                 );

    void *argtable[6 + 2] = {};
    uint8_t arglen = arg_add_default(argtable);
    argtable[arglen++] = arg_int1("b", "blk", "<dec>", "page number (0-255)");
    argtable[arglen++] = arg_param_end;

    CLIExecWithReturn(ctx, Cmd, argtable, false);

    uint8_t uid[HF15_UID_LENGTH];
    int uidlen = 0;
    CLIGetHexWithReturn(ctx, 1, uid, &uidlen);
    bool uid_set = (uidlen == HF15_UID_LENGTH) ? true : false;

    bool unaddressed = arg_get_lit(ctx, 2);
    bool scan = (arg_get_lit(ctx, 3) || (!uid_set && !unaddressed)) ? true : false; //Default fallback to scan for tag. Overriding unaddressed parameter.
    int fast = (arg_get_lit(ctx, 4) == false);
    bool add_option = arg_get_lit(ctx, 5);

    int block = arg_get_int_def(ctx, 6, 0);
    CLIParserFree(ctx);

    // sanity checks
    if ((scan + unaddressed + uid_set) > 1) {
        PrintAndLogEx(WARNING, "Select only one option /scan/unaddress/uid");
        return PM3_EINVARG;
    }

    // request to be sent to device/card
    uint16_t flags = arg_get_raw_flag(uidlen, unaddressed, scan, add_option);
    uint8_t req[PM3_CMD_DATA_SIZE] = {flags, ISO15693_READBLOCK};
    uint16_t reqlen = 2;

    if (unaddressed == false) {
        // default fallback to scan for tag.
        // overriding unaddress parameter :)
        if (scan) {
            if (getUID(false, uid) != PM3_SUCCESS) {
                PrintAndLogEx(WARNING, "no tag found");
                return PM3_EINVARG;
            }
        } else {
            reverse_array(uid, HF15_UID_LENGTH);
        }
        // add UID (scan, uid)
        memcpy(req + reqlen, uid, HF15_UID_LENGTH);
        reqlen += HF15_UID_LENGTH;

        PrintAndLogEx(SUCCESS, "Using UID... " _GREEN_("%s"), iso15693_sprintUID(NULL, uid));
    }
    // add OPTION flag, in order to get lock-info
    req[0] |= ISO15_REQ_OPTION;

    req[reqlen++] = (uint8_t)block;

    AddCrc15(req, reqlen);
    reqlen += 2;

    // arg: len, speed, recv?
    // arg0 (datalen,  cmd len?  .arg0 == crc?)
    // arg1 (speed == 0 == 1 of 256,  == 1 == 1 of 4 )
    // arg2 (recv == 1 == expect a response)
    uint8_t read_respone = 1;
    PacketResponseNG resp;
    clearCommandBuffer();
    SendCommandMIX(CMD_HF_ISO15693_COMMAND, reqlen, fast, read_respone, req, reqlen);

    if (WaitForResponseTimeout(CMD_HF_ISO15693_COMMAND, &resp, 2000) == false) {
        PrintAndLogEx(ERR, "iso15693 timeout");
        DropField();
        return PM3_ETIMEOUT;
    }

    DropField();

    if (resp.status == PM3_ETEAROFF) {
        return resp.status;
    }
    if (resp.length < 2) {
        PrintAndLogEx(ERR, "iso15693 command failed");
        return PM3_EWRONGANSWER;
    }

    uint8_t *data = resp.data.asBytes;

    if (CheckCrc15(data, resp.length) == false) {
        PrintAndLogEx(FAILED, "crc ( " _RED_("fail") " )");
        return PM3_ESOFT;
    }

    if ((data[0] & ISO15_RES_ERROR) == ISO15_RES_ERROR) {
        PrintAndLogEx(ERR, "iso15693 card returned error %i: %s", data[0], TagErrorStr(data[0]));
        return PM3_EWRONGANSWER;
    }

    // print response
    char lck[16] = {0};
    if (data[1]) {
        snprintf(lck, sizeof(lck), _RED_("%d"), data[1]);
    } else {
        snprintf(lck, sizeof(lck), "%d", data[1]);
    }
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "      #%3d  |lck| ascii", block);
    PrintAndLogEx(INFO, "------------+---+------");
    PrintAndLogEx(INFO, "%s| %s | %s", sprint_hex(data + 2, resp.length - 4), lck, sprint_ascii(data + 2, resp.length - 4));
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}

static int hf_15_write_blk(bool verbose, bool fast, uint8_t *req, uint8_t reqlen) {

    uint8_t read_response = 1;
    clearCommandBuffer();
    SendCommandMIX(CMD_HF_ISO15693_COMMAND, reqlen, fast, read_response, req, reqlen);
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_HF_ISO15693_COMMAND, &resp, 2000) == false) {
        PrintAndLogEx(FAILED, "iso15693 card timeout, data may be written anyway");
        DropField();
        return PM3_ETIMEOUT;
    }

    DropField();
    if (resp.status == PM3_ETEAROFF) {
        return resp.status;
    }

    if (resp.length < 2) {
        if (verbose) {
            PrintAndLogEx(FAILED, "iso15693 command failed");
        }
        return PM3_EWRONGANSWER;
    }

    uint8_t *recv = resp.data.asBytes;
    if (CheckCrc15(recv, resp.length) == false) {
        if (verbose) {
            PrintAndLogEx(FAILED, "crc ( " _RED_("fail") " )");
        }
        return PM3_ESOFT;
    }

    if ((recv[0] & ISO15_RES_ERROR) == ISO15_RES_ERROR) {
        if (verbose) {
            PrintAndLogEx(ERR, "iso15693 card returned error %i: %s", recv[0], TagErrorStr(recv[0]));
        }
        return PM3_EWRONGANSWER;
    }
    return PM3_SUCCESS;
}

/**
 * Commandline handling: HF15 CMD WRITE
 * Writes a single Block - might run into timeout, even when successful
 */
static int CmdHF15Write(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf 15 wrbl",
                  "Write block on ISO-15693 tag",
                  "hf 15 wrbl -* -b 12 -d AABBCCDD\n"
                  "hf 15 wrbl -u E011223344556677 -b 12 -d AABBCCDD"
                 );

    void *argtable[6 + 4] = {};
    uint8_t arglen = arg_add_default(argtable);
    argtable[arglen++] = arg_int1("b", "blk", "<dec>", "page number (0-255)");
    argtable[arglen++] = arg_str1("d", "data", "<hex>", "data, 4 bytes");
    argtable[arglen++] = arg_lit0("v", "verbose", "verbose output");
    argtable[arglen++] = arg_param_end;
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    uint8_t uid[HF15_UID_LENGTH];
    int uidlen = 0;
    CLIGetHexWithReturn(ctx, 1, uid, &uidlen);
    bool uid_set = (uidlen == HF15_UID_LENGTH) ? true : false;

    bool unaddressed = arg_get_lit(ctx, 2);
    bool scan = (arg_get_lit(ctx, 3) || (!uid_set && !unaddressed)) ? true : false; //Default fallback to scan for tag. Overriding unaddressed parameter.
    int fast = (arg_get_lit(ctx, 4) == false);
    bool add_option = arg_get_lit(ctx, 5);

    int block = arg_get_int_def(ctx, 6, 0);
    uint8_t d[4];
    int dlen = 0;
    CLIGetHexWithReturn(ctx, 7, d, &dlen);

    bool verbose = arg_get_lit(ctx, 8);
    CLIParserFree(ctx);

    // sanity checks
    if ((scan + unaddressed + uid_set) > 1) {
        PrintAndLogEx(WARNING, "Select only one option /scan/unaddress/uid");
        return PM3_EINVARG;
    }

    if (dlen != 4) {
        PrintAndLogEx(WARNING, "expected data, 4 bytes, got %d", dlen);
        return PM3_EINVARG;
    }

    // default fallback to scan for tag.
    // overriding unaddress parameter :)

    // request to be sent to device/card
    uint16_t flags = arg_get_raw_flag(uidlen, unaddressed, scan, add_option);
    uint8_t req[17] = {flags, ISO15693_WRITEBLOCK};

    // enforce, since we are writing
    req[0] |= ISO15_REQ_OPTION;
    uint16_t reqlen = 2;

    if (unaddressed == false) {
        if (scan) {
            if (getUID(false, uid) != PM3_SUCCESS) {
                PrintAndLogEx(WARNING, "no tag found");
                return PM3_EINVARG;
            }
        } else {
            reverse_array(uid, HF15_UID_LENGTH);
        }
        // add UID (scan, uid)
        memcpy(req + reqlen, uid, HF15_UID_LENGTH);
        reqlen += HF15_UID_LENGTH;

        PrintAndLogEx(SUCCESS, "Using UID... " _GREEN_("%s"), iso15693_sprintUID(NULL, uid));
    }

    req[reqlen++] = (uint8_t)block;
    memcpy(req + reqlen, d, sizeof(d));
    reqlen += sizeof(d);

    AddCrc15(req, reqlen);
    reqlen += 2;

    PrintAndLogEx(INFO, "iso15693 writing to page %02d (0x%02X) | data [ %s ] ", block, block, sprint_hex(req, reqlen));

    int res = hf_15_write_blk(verbose, fast, req, reqlen);
    if (res == PM3_SUCCESS)
        PrintAndLogEx(SUCCESS, "Write ( " _GREEN_("ok") " )");
    else
        PrintAndLogEx(FAILED, "Write ( " _RED_("fail") " )");

    return PM3_SUCCESS;
}

static int CmdHF15Restore(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf 15 restore",
                  "This command restore the contents of a dump file onto a ISO-15693 tag",
                  "hf 15 restore\n"
                  "hf 15 restore -*\n"
                  "hf 15 restore -u E011223344556677 -f hf-15-my-dump.bin"
                 );

    void *argtable[6 + 5] = {};
    uint8_t arglen = arg_add_default(argtable);
    argtable[arglen++] = arg_str0("f", "file", "<fn>", "filename of dump"),
                         argtable[arglen++] = arg_int0("r", "retry", "<dec>", "number of retries (def 3)"),
                                              argtable[arglen++] = arg_int0(NULL, "bs", "<dec>", "block size (def 4)"),
                                                      argtable[arglen++] = arg_lit0("v", "verbose", "verbose output");
    argtable[arglen++] = arg_param_end;
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    uint8_t uid[8];
    int uidlen = 0;
    CLIGetHexWithReturn(ctx, 1, uid, &uidlen);
    bool unaddressed = arg_get_lit(ctx, 2);
    bool scan = arg_get_lit(ctx, 3);
    int fast = (arg_get_lit(ctx, 4) == false);
    bool add_option = arg_get_lit(ctx, 5);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 6), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);
    uint32_t retries = arg_get_u32_def(ctx, 7, 3);
    int blocksize = arg_get_int_def(ctx, 8, 4);
    bool verbose = arg_get_lit(ctx, 9);
    CLIParserFree(ctx);

    // sanity checks
    if ((scan + unaddressed + uidlen) > 1) {
        PrintAndLogEx(WARNING, "Select only one option /scan/unaddress/uid");
        return PM3_EINVARG;
    }
    if (fnlen == 0) {
        PrintAndLogEx(WARNING, "please provide a filename");
        return PM3_EINVARG;
    }

    // default fallback to scan for tag.
    // overriding unaddress parameter :)
    if (uidlen != 8) {
        scan = true;
    }

    // request to be sent to device/card
    uint16_t flags = arg_get_raw_flag(uidlen, unaddressed, scan, add_option);
    uint8_t req[17] = {flags, ISO15693_WRITEBLOCK};
    // enforce, since we are writing
    req[0] |= ISO15_REQ_OPTION;
    uint16_t reqlen = 2;

    if (unaddressed == false) {
        if (scan) {
            if (getUID(false, uid) != PM3_SUCCESS) {
                PrintAndLogEx(WARNING, "no tag found");
                return PM3_EINVARG;
            }
            uidlen = 8;
        }

        if (uidlen == 8) {
            // add UID (scan, uid)
            memcpy(req + reqlen, uid, sizeof(uid));
            reqlen += sizeof(uid);
        }
        PrintAndLogEx(SUCCESS, "Using UID... " _GREEN_("%s"), iso15693_sprintUID(NULL, uid));
    } else {
        PrintAndLogEx(SUCCESS, "Using unaddressed mode");
    }
    PrintAndLogEx(INFO, "Using block size... %d", blocksize);


    // read dump file
    uint8_t *dump = NULL;
    size_t bytes_read = 0;
    // 4bytes * 256 blocks.  Should be enough..
    int res = pm3_load_dump(filename, (void **)&dump, &bytes_read, (4 * 256));
    if (res != PM3_SUCCESS) {
        return res;
    }

    if ((bytes_read % blocksize) != 0) {
        PrintAndLogEx(WARNING, "datalen %zu isn't dividable with blocksize %d", bytes_read, blocksize);
        free(dump);
        return PM3_ESOFT;
    }

    PrintAndLogEx(INFO, "restoring data blocks");
    PrintAndLogEx(INFO, "." NOLF);
    fflush(stdout);

    int retval = PM3_SUCCESS;
    size_t bytes = 0;
    uint16_t i = 0;
    while (bytes < bytes_read) {

        req[reqlen] = i;
        // copy over the data to the request
        memcpy(req + reqlen + 1, dump + bytes, blocksize);
        AddCrc15(req, reqlen + 1 + blocksize);

        uint32_t tried = 0;
        for (tried = 0; tried < retries; tried++) {

            retval = hf_15_write_blk(verbose, fast, req, (reqlen + 1 + blocksize + 2));
            if (retval == PM3_SUCCESS) {
                PrintAndLogEx(NORMAL, "." NOLF);
                fflush(stdout);
                break;
            }
        }

        if (tried >= retries) {
            free(dump);
            PrintAndLogEx(NORMAL, "");
            PrintAndLogEx(FAILED, "restore failed. Too many retries.");
            return retval;
        }
        bytes += blocksize;
        i++;
    }
    free(dump);

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "done");
    PrintAndLogEx(HINT, "try `" _YELLOW_("hf 15 dump") "` to read your card to verify");
    return PM3_SUCCESS;
}

/**
 * Commandline handling: HF15 CMD CSETUID
 * Set UID for magic Chinese card
 */
static int CmdHF15CSetUID(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf 15 csetuid",
                  "Set UID for magic Chinese card (only works with such cards)\n",
                  "hf 15 csetuid -u E011223344556677");

    void *argtable[] = {
        arg_param_begin,
        arg_str1("u", "uid", "<8b hex>", "UID eg E011223344556677"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    struct {
        uint8_t uid[8];
    } PACKED payload;

    int uidlen = 0;
    CLIGetHexWithReturn(ctx, 1, payload.uid, &uidlen);
    CLIParserFree(ctx);

    if (uidlen != 8) {
        PrintAndLogEx(WARNING, "UID must include 16 HEX symbols got ");
        return PM3_EINVARG;
    }

    if (payload.uid[0] != 0xE0) {
        PrintAndLogEx(WARNING, "UID must begin with the byte " _YELLOW_("E0"));
        return PM3_EINVARG;
    }

    PrintAndLogEx(SUCCESS, "reverse input UID " _YELLOW_("%s"), iso15693_sprintUID(NULL, payload.uid));

    PrintAndLogEx(INFO, "getting current card details...");
    uint8_t carduid[8] = {0x00};
    if (getUID(false, carduid) != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "no tag found");
        return PM3_ESOFT;
    }

    PrintAndLogEx(INFO, "updating tag uid...");

    PacketResponseNG resp;
    clearCommandBuffer();
    SendCommandNG(CMD_HF_ISO15693_CSETUID, (uint8_t *)&payload, sizeof(payload));
    if (WaitForResponseTimeout(CMD_HF_ISO15693_CSETUID, &resp, 2000) == false) {
        PrintAndLogEx(WARNING, "timeout while waiting for reply");
        DropField();
        return PM3_ESOFT;
    }

    PrintAndLogEx(INFO, "getting updated card details...");

    if (getUID(false, carduid) != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "no tag found");
        return PM3_ESOFT;
    }

    // reverse cardUID to compare
    uint8_t revuid[8] = {0};
    reverse_array_copy(carduid, sizeof(carduid), revuid);

    if (memcmp(revuid, payload.uid, 8) != 0) {
        PrintAndLogEx(FAILED, "setting new UID ( " _RED_("fail") " )");
        return PM3_ESOFT;
    } else {
        PrintAndLogEx(SUCCESS, "setting new UID ( " _GREEN_("ok") " )");
        return PM3_SUCCESS;
    }
}

static int CmdHF15SlixEASEnable(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf 15 slixeasenable",
                  "Enable EAS mode on SLIX ISO-15693 tag",
                  "hf 15 slixeasenable -p 0F0F0F0F");

    void *argtable[] = {
        arg_param_begin,
        arg_str0("p", "pwd", "<hex>", "optional password, 8 hex bytes"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    struct {
        uint8_t pwd[4];
        bool usepwd;
    } PACKED payload;
    int pwdlen = 0;

    int ret_pwdparse = CLIParamHexToBuf(arg_get_str(ctx, 1), payload.pwd, 4, &pwdlen);
    if ((pwdlen > 0 && pwdlen != 4) || ret_pwdparse != 0) {
        PrintAndLogEx(WARNING, "password must be 4 hex bytes if provided");
        CLIParserFree(ctx);
        return PM3_ESOFT;
    }

    CLIParserFree(ctx);

    if (pwdlen > 0) {
        PrintAndLogEx(INFO, "Trying to enable EAS mode using password " _GREEN_("%s")
                      , sprint_hex_inrow(payload.pwd, sizeof(payload.pwd))
                     );
        payload.usepwd = true;
    } else {
        PrintAndLogEx(INFO, "Trying to enable EAS mode without using a password");
        payload.usepwd = false;
    }


    PacketResponseNG resp;
    clearCommandBuffer();
    SendCommandNG(CMD_HF_ISO15693_SLIX_ENABLE_EAS, (uint8_t *)&payload, sizeof(payload));
    if (WaitForResponseTimeout(CMD_HF_ISO15693_SLIX_ENABLE_EAS, &resp, 2000) == false) {
        PrintAndLogEx(WARNING, "timeout while waiting for reply");
        DropField();
        return PM3_ESOFT;
    }

    switch (resp.status) {
        case PM3_ETIMEOUT: {
            PrintAndLogEx(WARNING, "no tag found");
            break;
        }
        case PM3_EWRONGANSWER: {
            if (pwdlen > 0) {
                PrintAndLogEx(WARNING, "the password provided was not accepted");
            } else {
                PrintAndLogEx(WARNING, "either a password is required or EAS mode is locked");
            }
            break;
        }
        case PM3_SUCCESS: {
            PrintAndLogEx(SUCCESS, "EAS mode is now enabled ( " _GREEN_("ok") " ) ");
            break;
        }
    }
    return resp.status;
}

static int CmdHF15SlixEASDisable(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf 15 slixeasdisable",
                  "Disable EAS mode on SLIX ISO-15693 tag",
                  "hf 15 slixeasdisable -p 0F0F0F0F");

    void *argtable[] = {
        arg_param_begin,
        arg_str0("p", "pwd", "<hex>", "optional password, 8 hex bytes"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    struct {
        uint8_t pwd[4];
        bool usepwd;

    } PACKED payload;
    int pwdlen = 0;

    int ret_pwdparse = CLIParamHexToBuf(arg_get_str(ctx, 1), payload.pwd, 4, &pwdlen);
    CLIParserFree(ctx);

    if ((pwdlen > 0 && pwdlen != 4) || ret_pwdparse != 0) {
        PrintAndLogEx(WARNING, "password must be 4 hex bytes if provided");
        return PM3_ESOFT;
    }

    if (pwdlen > 0) {
        PrintAndLogEx(INFO, "Trying to disable EAS mode using password " _GREEN_("%s")
                      , sprint_hex_inrow(payload.pwd, sizeof(payload.pwd))
                     );
        payload.usepwd = true;
    } else {
        PrintAndLogEx(INFO, "Trying to enable EAS mode without using a password");
        payload.usepwd = false;
    }

    PacketResponseNG resp;
    clearCommandBuffer();
    SendCommandNG(CMD_HF_ISO15693_SLIX_DISABLE_EAS, (uint8_t *)&payload, sizeof(payload));
    if (WaitForResponseTimeout(CMD_HF_ISO15693_SLIX_DISABLE_EAS, &resp, 2000) == false) {
        PrintAndLogEx(WARNING, "timeout while waiting for reply");
        DropField();
        return PM3_ESOFT;
    }

    switch (resp.status) {
        case PM3_ETIMEOUT: {
            PrintAndLogEx(WARNING, "no tag found");
            break;
        }
        case PM3_EWRONGANSWER: {
            if (pwdlen > 0) {
                PrintAndLogEx(WARNING, "the password provided was not accepted");
            } else {
                PrintAndLogEx(WARNING, "either a password is required or EAS mode is locked");
            }
            break;
        }
        case PM3_SUCCESS: {
            PrintAndLogEx(SUCCESS, "EAS mode is now disabled ( " _GREEN_("ok") " ) ");
            break;
        }
    }
    return resp.status;
}

static int CmdHF15SlixDisable(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf 15 slixprivacydisable",
                  "Disable privacy mode on SLIX ISO-15693 tag",
                  "hf 15 slixdisable -p 0F0F0F0F");

    void *argtable[] = {
        arg_param_begin,
        arg_str1("p", "pwd", "<hex>", "password, 8 hex bytes"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    struct {
        uint8_t pwd[4];
    } PACKED payload;
    int pwdlen = 0;
    CLIGetHexWithReturn(ctx, 1, payload.pwd, &pwdlen);
    CLIParserFree(ctx);

    PrintAndLogEx(INFO, "Trying to disabling privacy mode using password " _GREEN_("%s")
                  , sprint_hex_inrow(payload.pwd, sizeof(payload.pwd))
                 );

    PacketResponseNG resp;
    clearCommandBuffer();
    SendCommandNG(CMD_HF_ISO15693_SLIX_DISABLE_PRIVACY, (uint8_t *)&payload, sizeof(payload));
    if (WaitForResponseTimeout(CMD_HF_ISO15693_SLIX_DISABLE_PRIVACY, &resp, 2000) == false) {
        PrintAndLogEx(WARNING, "timeout while waiting for reply");
        DropField();
        return PM3_ESOFT;
    }

    switch (resp.status) {
        case PM3_ETIMEOUT: {
            PrintAndLogEx(WARNING, "no tag found");
            break;
        }
        case PM3_EWRONGANSWER: {
            PrintAndLogEx(WARNING, "password was not accepted");
            break;
        }
        case PM3_SUCCESS: {
            PrintAndLogEx(SUCCESS, "privacy mode is now disabled ( " _GREEN_("ok") " ) ");
            break;
        }
    }
    return resp.status;
}

static int CmdHF15SlixEnable(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf 15 slixprivacyenable",
                  "Enable privacy mode on SLIX ISO-15693 tag",
                  "hf 15 slixenable -p 0F0F0F0F");

    void *argtable[] = {
        arg_param_begin,
        arg_str1("p", "pwd", "<hex>", "password, 8 hex bytes"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    struct {
        uint8_t pwd[4];
    } PACKED payload;
    int pwdlen = 0;
    CLIGetHexWithReturn(ctx, 1, payload.pwd, &pwdlen);
    CLIParserFree(ctx);

    PrintAndLogEx(INFO, "Trying to enable privacy mode using password " _GREEN_("%s")
                  , sprint_hex_inrow(payload.pwd, sizeof(payload.pwd))
                 );

    PacketResponseNG resp;
    clearCommandBuffer();
    SendCommandNG(CMD_HF_ISO15693_SLIX_ENABLE_PRIVACY, (uint8_t *)&payload, sizeof(payload));
    if (WaitForResponseTimeout(CMD_HF_ISO15693_SLIX_ENABLE_PRIVACY, &resp, 2000) == false) {
        PrintAndLogEx(WARNING, "timeout while waiting for reply");
        DropField();
        return PM3_ESOFT;
    }

    switch (resp.status) {
        case PM3_ETIMEOUT: {
            PrintAndLogEx(WARNING, "no tag found");
            break;
        }
        case PM3_EWRONGANSWER: {
            PrintAndLogEx(WARNING, "password was not accepted");
            break;
        }
        case PM3_SUCCESS: {
            PrintAndLogEx(SUCCESS, "privacy mode is now enabled ( " _GREEN_("ok") " ) ");
            break;
        }
    }
    return resp.status;
}

static int CmdHF15SlixWritePassword(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf 15 slixwritepwd",
                  "Write a password on a SLIX family ISO-15693 tag.n"
                  "Some tags do not support all different password types.",
                  "hf 15 slixwritepwd -t READ -o 00000000 -n 12131415");

    void *argtable[] = {
        arg_param_begin,
        arg_str1("t", "type", "<read|write|privacy|destroy|easafi>", "which password field to write to"),
        arg_str0("o", "old", "<hex>", "old password (if present), 8 hex bytes"),
        arg_str1("n", "new", "<hex>", "new password, 8 hex bytes"),
        arg_param_end
    };

    CLIExecWithReturn(ctx, Cmd, argtable, false);

    struct {
        uint8_t old_pwd[4];
        uint8_t new_pwd[4];
        uint8_t pwd_id;
    } PACKED payload;
    int pwdlen = 0;

    CLIGetHexWithReturn(ctx, 2, payload.old_pwd, &pwdlen);

    if (pwdlen > 0 && pwdlen != 4) {
        PrintAndLogEx(WARNING, "old password must be 4 hex bytes if provided");
        CLIParserFree(ctx);
        return PM3_ESOFT;
    }

    CLIGetHexWithReturn(ctx, 3, payload.new_pwd, &pwdlen);

    if (pwdlen != 4) {
        PrintAndLogEx(WARNING, "new password must be 4 hex bytes");
        CLIParserFree(ctx);
        return PM3_ESOFT;
    }

    int vlen = 0;
    char value[10];
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)value, sizeof(value), &vlen);
    CLIParserFree(ctx);

    if (vlen > 0) {
        if (strcmp(value, "read") == 0) {
            PrintAndLogEx(SUCCESS, "Selected read pass");
            payload.pwd_id = 0x01;
        } else if (strcmp(value, "write") == 0) {
            PrintAndLogEx(SUCCESS, "Selected write pass");
            payload.pwd_id = 0x02;
        } else if (strcmp(value, "privacy") == 0) {
            PrintAndLogEx(SUCCESS, "Selected privacy pass");
            payload.pwd_id = 0x04;
        } else if (strcmp(value, "destroy") == 0) {
            PrintAndLogEx(SUCCESS, "Selected destroy pass");
            payload.pwd_id = 0x08;
        } else if (strcmp(value, "easafi") == 0) {
            PrintAndLogEx(SUCCESS, "Selected easafi pass");
            payload.pwd_id = 0x10;
        } else {
            PrintAndLogEx(ERR, "t argument must be 'read', 'write', 'privacy', 'destroy', or 'easafi'");
            return PM3_EINVARG;
        }
    }

    PrintAndLogEx(INFO, "Trying to write " _YELLOW_("%s") " as " _YELLOW_("%s") " password"
                  , sprint_hex_inrow(payload.new_pwd, sizeof(payload.new_pwd)), value);

    PacketResponseNG resp;
    clearCommandBuffer();
    SendCommandNG(CMD_HF_ISO15693_SLIX_WRITE_PWD, (uint8_t *)&payload, sizeof(payload));
    if (WaitForResponseTimeout(CMD_HF_ISO15693_SLIX_WRITE_PWD, &resp, 2000) == false) {
        PrintAndLogEx(WARNING, "timeout while waiting for reply");
        DropField();
        return PM3_ESOFT;
    }

    switch (resp.status) {
        case PM3_ETIMEOUT: {
            PrintAndLogEx(WARNING, "no tag found");
            break;
        }
        case PM3_EWRONGANSWER: {
            PrintAndLogEx(WARNING, "password was not accepted");
            break;
        }
        case PM3_SUCCESS: {
            PrintAndLogEx(SUCCESS, "password written ( " _GREEN_("ok") " ) ");
            break;
        }
    }
    return resp.status;
}

static int CmdHF15AFIPassProtect(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf 15 passprotectafi",
                  "This command enables the password protect of AFI.\n"
                  "*** OBS!  This action can not be undone! ***",
                  "hf 15 passprotectafi -p 00000000 --force");

    void *argtable[] = {
        arg_param_begin,
        arg_str1("p", "pwd", "<hex>", "EAS/AFI password, 8 hex bytes"),
        arg_lit0(NULL, "force", "Force execution of command (irreversible) "),
        arg_param_end
    };

    CLIExecWithReturn(ctx, Cmd, argtable, true);

    struct {
        uint8_t pwd[4];
    } PACKED payload;
    int pwdlen = 0;

    CLIGetHexWithReturn(ctx, 1, payload.pwd, &pwdlen);

    bool force = arg_get_lit(ctx, 2);
    CLIParserFree(ctx);

    if (pwdlen != 4) {
        PrintAndLogEx(WARNING, "password must be 4 hex bytes");
        return PM3_ESOFT;
    }

    if (force == false) {
        PrintAndLogEx(WARNING, "Use `--force` flag to override. OBS! Irreversable command");
        return PM3_ESOFT;
    }

    PrintAndLogEx(INFO, "Trying to enable AFI password protection...");

    PacketResponseNG resp;
    clearCommandBuffer();
    SendCommandNG(CMD_HF_ISO15693_SLIX_PASS_PROTECT_AFI, (uint8_t *)&payload, sizeof(payload));
    if (WaitForResponseTimeout(CMD_HF_ISO15693_SLIX_PASS_PROTECT_AFI, &resp, 2000) == false) {
        PrintAndLogEx(WARNING, "timeout while waiting for reply");
        DropField();
        return PM3_ESOFT;
    }

    switch (resp.status) {
        case PM3_ETIMEOUT: {
            PrintAndLogEx(WARNING, "no tag found");
            break;
        }
        case PM3_EWRONGANSWER: {
            PrintAndLogEx(WARNING, "error enabling AFI password protection");
            break;
        }
        case PM3_SUCCESS: {
            PrintAndLogEx(SUCCESS, "AFI password protected ( " _GREEN_("ok") " ) ");
            break;
        }
    }
    return resp.status;

}

static int CmdHF15EASPassProtect(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf 15 passprotecteas",
                  "This command enables the password protect of EAS.\n"
                  "*** OBS!  This action can not be undone! ***",
                  "hf 15 passprotecteas -p 00000000 --force");

    void *argtable[] = {
        arg_param_begin,
        arg_str1("p", "pwd", "<hex>", "EAS/AFI password, 8 hex bytes"),
        arg_lit0(NULL, "force", "Force execution of command (irreversible) "),
        arg_param_end
    };

    CLIExecWithReturn(ctx, Cmd, argtable, true);

    struct {
        uint8_t pwd[4];
    } PACKED payload;
    int pwdlen = 0;

    CLIGetHexWithReturn(ctx, 1, payload.pwd, &pwdlen);

    bool force = arg_get_lit(ctx, 2);
    CLIParserFree(ctx);

    if (pwdlen != 4) {
        PrintAndLogEx(WARNING, "password must be 4 hex bytes");
        return PM3_ESOFT;
    }

    if (force == false) {
        PrintAndLogEx(WARNING, "Use `--force` flag to override. OBS! Irreversable command");
        return PM3_ESOFT;
    }

    PrintAndLogEx(INFO, "Trying to enable EAS password protection...");

    PacketResponseNG resp;
    clearCommandBuffer();
    SendCommandNG(CMD_HF_ISO15693_SLIX_PASS_PROTECT_EAS, (uint8_t *)&payload, sizeof(payload));
    if (WaitForResponseTimeout(CMD_HF_ISO15693_SLIX_PASS_PROTECT_EAS, &resp, 2000) == false) {
        PrintAndLogEx(WARNING, "timeout while waiting for reply");
        DropField();
        return PM3_ESOFT;
    }

    switch (resp.status) {
        case PM3_ETIMEOUT: {
            PrintAndLogEx(WARNING, "no tag found");
            break;
        }
        case PM3_EWRONGANSWER: {
            PrintAndLogEx(WARNING, "error enabling EAS password protection");
            break;
        }
        case PM3_SUCCESS: {
            PrintAndLogEx(SUCCESS, "EAS password protected ( " _GREEN_("ok") " ) ");
            break;
        }
    }
    return resp.status;
}

static int CmdHF15View(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf 15 view",
                  "Print a ISO-15693 tag dump file (bin/eml/json)",
                  "hf 15 view -f hf-iclass-AA162D30F8FF12F1-dump.bin\n"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_str1("f", "file", "<fn>",  "filename of dump (bin/eml/json)"),
//        arg_lit0("z", "dense", "dense dump output style"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE];
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);
//    bool dense_output = g_session.dense_output || arg_get_lit(ctx, 2);
    CLIParserFree(ctx);

    // read dump file
    uint8_t *dump = NULL;
    size_t bytes_read = CARD_MEMORY_SIZE;
    int res = pm3_load_dump(filename, (void **)&dump, &bytes_read, CARD_MEMORY_SIZE);
    if (res != PM3_SUCCESS) {
        return res;
    }

    PrintAndLogEx(NORMAL, "");
    print_blocks_15693(dump, bytes_read, 4);

    free(dump);
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",                CmdHF15Help,              AlwaysAvailable, "This help"},
    {"list",                CmdHF15List,              AlwaysAvailable, "List ISO-15693 history"},
    {"-----------",         CmdHF15Help,              AlwaysAvailable, "----------------------- " _CYAN_("general") " -----------------------"},
    {"demod",               CmdHF15Demod,             AlwaysAvailable, "Demodulate ISO-15693 from tag"},
    {"dump",                CmdHF15Dump,              IfPm3Iso15693,   "Read all memory pages of an ISO-15693 tag, save to file"},
    {"info",                CmdHF15Info,              IfPm3Iso15693,   "Tag information"},
    {"sniff",               CmdHF15Sniff,             IfPm3Iso15693,   "Sniff ISO-15693 traffic"},
    {"raw",                 CmdHF15Raw,               IfPm3Iso15693,   "Send raw hex data to tag"},
    {"rdbl",                CmdHF15Readblock,         IfPm3Iso15693,   "Read a block"},
    {"rdmulti",             CmdHF15Readmulti,         IfPm3Iso15693,   "Reads multiple blocks"},
    {"reader",              CmdHF15Reader,            IfPm3Iso15693,   "Act like an ISO-15693 reader"},
    {"restore",             CmdHF15Restore,           IfPm3Iso15693,   "Restore from file to all memory pages of an ISO-15693 tag"},
    {"samples",             CmdHF15Samples,           IfPm3Iso15693,   "Acquire samples as reader (enables carrier, sends inquiry)"},
    {"view",                CmdHF15View,              AlwaysAvailable, "Display content from tag dump file"},
    {"wrbl",                CmdHF15Write,             IfPm3Iso15693,   "Write a block"},
    {"-----------",         CmdHF15Help,              IfPm3Iso15693,   "--------------------- " _CYAN_("simulation") " ----------------------"},
    {"sim",                 CmdHF15Sim,               IfPm3Iso15693,   "Fake an ISO-15693 tag"},
    {"eload",               CmdHF15ELoad,             IfPm3Iso15693,   "Load image file into emulator to be used by 'sim' command"},
    {"esave",               CmdHF15ESave,             IfPm3Iso15693,   "Save emulator memory into image file"},
    {"eview",               CmdHF15EView,             IfPm3Iso15693,   "View emulator memory"},
    {"-----------",         CmdHF15Help,              IfPm3Iso15693,   "------------------------ " _CYAN_("SLIX") " -------------------------"},
    {"slixwritepwd",        CmdHF15SlixWritePassword, IfPm3Iso15693,   "Writes a password on a SLIX ISO-15693 tag"},
    {"slixeasdisable",      CmdHF15SlixEASDisable,    IfPm3Iso15693,   "Disable EAS mode on SLIX ISO-15693 tag"},
    {"slixeasenable",       CmdHF15SlixEASEnable,     IfPm3Iso15693,   "Enable EAS mode on SLIX ISO-15693 tag"},
    {"slixprivacydisable",  CmdHF15SlixDisable,       IfPm3Iso15693,   "Disable privacy mode on SLIX ISO-15693 tag"},
    {"slixprivacyenable",   CmdHF15SlixEnable,        IfPm3Iso15693,   "Enable privacy mode on SLIX ISO-15693 tag"},
    {"passprotectafi",      CmdHF15AFIPassProtect,    IfPm3Iso15693,   "Password protect AFI - Cannot be undone"},
    {"passprotecteas",      CmdHF15EASPassProtect,    IfPm3Iso15693,   "Password protect EAS - Cannot be undone"},
    {"-----------",         CmdHF15Help,              IfPm3Iso15693,  "-------------------------- " _CYAN_("afi") " ------------------------"},
    {"findafi",             CmdHF15FindAfi,           IfPm3Iso15693,   "Brute force AFI of an ISO-15693 tag"},
    {"writeafi",            CmdHF15WriteAfi,          IfPm3Iso15693,   "Writes the AFI on an ISO-15693 tag"},
    {"writedsfid",          CmdHF15WriteDsfid,        IfPm3Iso15693,   "Writes the DSFID on an ISO-15693 tag"},
    {"-----------",         CmdHF15Help,              IfPm3Iso15693,  "------------------------- " _CYAN_("magic") " -----------------------"},
    {"csetuid",             CmdHF15CSetUID,           IfPm3Iso15693,   "Set UID for magic card"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHF15Help(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdHF15(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}
