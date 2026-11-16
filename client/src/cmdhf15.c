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
#include "cmdparser.h"          // command_t
#include "commonutil.h"         // ARRAYLEN
#include "comms.h"              // clearCommandBuffer
#include "cmdtrace.h"
#include "iso15693tools.h"      // ISO15693 error codes etc
#include "protocols.h"          // ISO15693 command set
#include "crypto/libpcrypto.h"
#include "graph.h"
#include "crc16.h"              // iso15 crc
#include "cmddata.h"            // getsamples
#include "fileutils.h"          // pm3_save_dump_json, convert_15_dump_format
#include "cliparser.h"
#include "util_posix.h"         // msleep
#include "iso15.h"              // typedef structs / enum
#include "crypto/originality.h"

#define FrameSOF                Iso15693FrameSOF
#define Logic0                  Iso15693Logic0
#define Logic1                  Iso15693Logic1
#define FrameEOF                Iso15693FrameEOF

#ifndef ISO15_ERROR_HANDLING_RESPONSE
#define ISO15_ERROR_HANDLING_RESPONSE { \
    if (resp.status == PM3_ETEAROFF) { \
        return resp.status; \
    } \
    if (resp.length < 2) { \
        PrintAndLogEx(ERR, "iso15693 command failed"); \
        return PM3_EWRONGANSWER; \
    } \
}
#endif

// returns from the calling function on anything but PM3_SUCCESS.
// iso15_error_handling_card_response() must be in scope at the point of use
#ifndef ISO15_ERROR_HANDLING_CARD_RESPONSE
#define ISO15_ERROR_HANDLING_CARD_RESPONSE(data, len) { \
    int res_card_ = iso15_error_handling_card_response((data), (len)); \
    if (res_card_ != PM3_SUCCESS) { \
        return res_card_; \
    } \
}
#endif

typedef struct {
    uint8_t lock;
    uint8_t block[8];
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
    { 0xe002230000000000LL, 24, "ST Microelectronics; ST25TV02K"},
    { 0xe002230000000000LL, 24, "ST Microelectronics; ST25TV512"},
    { 0xe002080000000000LL, 24, "ST Microelectronics; ST25TV02KC"},
    { 0xe002080000000000LL, 24, "ST Microelectronics; ST25TV512C"},
    { 0xe002350000000000LL, 24, "ST Microelectronics; ST25TV04K-P"},
    { 0xe002480000000000LL, 24, "ST Microelectronics; ST25TV16K"},
    { 0xe002480000000000LL, 24, "ST Microelectronics; ST25TV64K"},

    /*
    ST25TV02K    0xe0 02 23
    ST25TV512    0xe0 02 23
    ST25TV02KC    0xe00208
    ST25TV512C    0xe00208
    ST25TV04K-P    0xe00235
    ST25TV16K    0xe00248
    ST25TV64K    0xe00248
    */

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
    { 0xE004010000000000LL, 24, "NXP (Philips); IC SL2 ICS20/ICS21 (SLI) ICS2002/ICS2102 (SLIX) ICS2602 (SLIX2)" },
    { 0xE004011800000000LL, 0xFFFFFF1800000000LL, "NXP (Philips); IC NTP53x2/NTP5210/NTA5332 " AEND "( " _CYAN_("NTAG 5") " )" },
    { 0xE004010000000000LL, 0xFFFFFF1800000000LL, "NXP (Philips); IC SL2 ICS20/ICS21 " AEND "( " _CYAN_("SLI") " )" },
    { 0xE004011000000000LL, 0xFFFFFF1800000000LL, "NXP (Philips); IC SL2 ICS2002/ICS2102 " AEND "( " _CYAN_("SLIX") " )" },
    { 0xE004010800000000LL, 0xFFFFFF1800000000LL, "NXP (Philips); IC SL2 ICS2602 " AEND "( " _CYAN_("SLIX2") " )" },
    { 0xE004011800000000LL, 0xFFFFFF1800000000LL, "NXP (Philips); ICODE DNA"},
    { 0xE004012000000000LL, 0xFFFFFF7800000000LL, "NXP (Philips); ICODE 3"},
    { 0xE004020000000000LL, 0xFFFFFF1000000000LL, "NXP (Philips); IC SL2 ICS53/ICS54 " AEND "( " _CYAN_("SLI-S") " )" },
    { 0xE004021000000000LL, 0xFFFFFF1000000000LL, "NXP (Philips); ICS5302/ICS5402 " AEND "( " _CYAN_("SLIX-S") " )" },
    { 0xE004030000000000LL, 0xFFFFFF1000000000LL, "NXP (Philips); IC SL2 ICS50/ICS51 " AEND "( " _CYAN_("SLI-L") " )" },
    { 0xE004031000000000LL, 0xFFFFFF1000000000LL, "NXP (Philips); ICS5002/ICS5102 " AEND "( " _CYAN_("SLIX-L") " )" },

    // E0 05 XX .. .. ..
    //   05 = Manufacturer code (Infineon)
    //   XX = IC id (Chip ID Family)
    { 0xE005000000000000LL, 16, "Infineon Technologies AG Germany" },
    { 0xE005A10000000000LL, 24, "Infineon; SRF55V01P [IC id = 161] plain mode 1kBit"},
    { 0xE005A80000000000LL, 24, "Infineon; SRF55V01P [IC id = 168] pilot series 1kBit"},
    { 0xE005400000000000LL, 24, "Infineon; SRF55V02P [IC id = 64] plain mode 2kBit"},
    { 0xE005000000000000LL, 24, "Infineon; SRF55V10P [IC id = 00] plain mode 10KBit"},
    { 0xE005500000000000LL, 24, "Infineon; SRF55V02S [IC id = 80] secure mode 2kBit"},
    { 0xE005100000000000LL, 24, "Infineon; SRF55V10S [IC id = 16] secure mode 10KBit"},
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
    { 0xE016780000000000LL, 24, "EM-Marin SA (Skidata); EM4425 Echo V (dual tech)"},
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

    int reason = 0;
    int index = originality_check_verify(uid, 8, signature, 32, PK_15);
    if (index >= 0) {
        reason = 1;
    } else {
        // try with sha256
        index = originality_check_verify_ex(uid, 8, signature, 32, PK_15, false, true);
        if (index >= 0) {
            reason = 2;
        } else {
            // try with reversed uid / signature
            index = originality_check_verify_ex(uid, 8, signature, 32, PK_15, true, false);
            if (index >= 0) {
                reason = 3;
            } else {
                // try with sha256 and reversed uid / signature
                index = originality_check_verify_ex(uid, 8, signature, 32, PK_15, true, true);
                if (index >= 0) {
                    reason = 4;
                }
            }
        }
    }

    int ret = originality_check_print(signature, 32, index);
    if (ret != PM3_SUCCESS) {
        return ret;
    }

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
static void printTagInfo_15(const uint8_t *uid) {
    if (uid == NULL) {
        return;
    }

    uint64_t myuid, mask;
    int i = 0, best = -1;
    memcpy(&myuid, uid, sizeof(uint64_t));
    // find first best match
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
    if (best >= 0) {
        i = 0;
        while (uidmapping[i].mask > 0) {
            if (uidmapping[i].mask > 64) {
                mask = uidmapping[i].mask;
            } else {
                mask = (~0ULL) << (64 - uidmapping[i].mask);
            }
            if (((myuid & mask) == uidmapping[i].uid) && (uidmapping[i].mask == uidmapping[best].mask)) {
                PrintAndLogEx(SUCCESS, "TYPE MATCH " _YELLOW_("%s"), uidmapping[i].desc);
            }
            i++;
        }
    } else {
        PrintAndLogEx(SUCCESS, "TYPE...... " _YELLOW_("%s"), uidmapping[i].desc);
    }

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


static void iso15_print_card_error(const uint8_t *d) {
    PrintAndLogEx(ERR, "iso15693 card returned error %i: %s", d[1], TagErrorStr(d[1]));
}

static int iso15_error_handling_card_response(uint8_t *d, uint16_t n) {
    if (check_crc(CRC_15693, d, n) == false) {
        PrintAndLogEx(FAILED, "crc ( " _RED_("fail") " )");
        return PM3_ECRC;
    }

    if ((d[0] & ISO15_RES_ERROR) == ISO15_RES_ERROR) {
        if (d[1] == 0x0F || d[1] == 0x10) {
            return PM3_EOUTOFBOUND;
        }

        iso15_print_card_error(d);
        return PM3_EWRONGANSWER;
    }

    return PM3_SUCCESS;
}

// hf 15 info requests: also report the 0F and 10 errors that block reads take as the end of the memory
static int iso15_info_error_handling(uint8_t *d, uint16_t n) {
    int res = iso15_error_handling_card_response(d, n);
    if (res == PM3_EOUTOFBOUND) {
        iso15_print_card_error(d);
    }
    return res;
}

// shortest GET SYSTEM INFORMATION answer that can carry the optional fields
// the info flags announce: flags, info flags, UID, those fields, CRC
static uint16_t iso15_sysinfo_min_len(uint8_t info_flags) {
    return 2 + ISO15693_UID_LENGTH + 2
           + ((info_flags & 0x01) ? 1 : 0)
           + ((info_flags & 0x02) ? 1 : 0)
           + ((info_flags & 0x04) ? 2 : 0)
           + ((info_flags & 0x08) ? 1 : 0);
}

// true when the layout fits iso15_tag_t, see ISO15693_TAG_MAX_* in iso15.h.
// prints the offending values itself, the caller does its own cleanup
static bool iso15_tag_size_ok(const iso15_tag_t *tag) {
    if ((tag->pagesCount > ISO15693_TAG_MAX_PAGES) ||
            ((tag->pagesCount * tag->bytesPerPage) > ISO15693_TAG_MAX_SIZE) ||
            (tag->pagesCount == 0) ||
            (tag->bytesPerPage == 0)) {

        PrintAndLogEx(FAILED, "Tag size error: pagesCount=%d, bytesPerPage=%d",
                      tag->pagesCount,
                      tag->bytesPerPage
                     );
        return false;
    }

    return true;
}


// fast method to just read the UID of a tag (collision detection not supported)
//  *buf should be large enough to fit the 64bit uid
//  fast: true for high-speed (1 out of 4), false for low-speed (1 out of 256)
// returns 1 if succeeded
static int getUID(bool fast, bool verbose, bool loop, uint8_t *buf) {

    uint8_t approxlen = 5;
    iso15_raw_cmd_t *packet = (iso15_raw_cmd_t *)calloc(1, sizeof(iso15_raw_cmd_t) + approxlen);
    if (packet == NULL) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        return PM3_EMALLOC;
    }

    // params
    packet->raw[packet->rawlen++] = ISO15_REQ_SUBCARRIER_SINGLE | ISO15_REQ_DATARATE_HIGH | ISO15_REQ_INVENTORY | ISO15_REQINV_SLOT1;
    packet->raw[packet->rawlen++] = ISO15693_INVENTORY;
    packet->raw[packet->rawlen++] = 0; // mask length

    AddCrc15(packet->raw, 3);
    packet->rawlen += 2;

    packet->flags = (ISO15_CONNECT | ISO15_READ_RESPONSE);
    if (fast) {
        packet->flags |= ISO15_HIGH_SPEED;
    }

    int res = PM3_ESOFT;
    do {
        clearCommandBuffer();
        SendCommandNG(CMD_HF_ISO15693_COMMAND, (uint8_t *)packet, ISO15_RAW_LEN(packet->rawlen));
        PacketResponseNG resp;
        if (WaitForResponseTimeout(CMD_HF_ISO15693_COMMAND, &resp, 2000)) {

            if (resp.status == PM3_SUCCESS && resp.length >= 12 && CheckCrc15(resp.data.asBytes, 12)) {

                if (buf) {
                    memcpy(buf, resp.data.asBytes + 2, 8);
                }

                if (verbose) {
                    PrintAndLogEx(NORMAL, "");
                    PrintAndLogEx(SUCCESS, "UID.... " _GREEN_("%s"), iso15693_sprintUID(NULL, buf));
                    PrintAndLogEx(SUCCESS, "DSFID.. %02X", resp.data.asBytes[1]);
                    printTagInfo_15(buf);
                    PrintAndLogEx(NORMAL, "");
                }
                res = PM3_SUCCESS;

                if (loop == false) {
                    break;
                }
            }
        }
    } while (loop && kbd_enter_pressed() == false);

    free(packet);
    return res;
}

// used with 'hf search'
bool readHF15Uid(bool loop, bool verbose) {
    uint8_t uid[ISO15693_UID_LENGTH] = {0};
    if (getUID(true, verbose, loop, uid) != PM3_SUCCESS) {
        return false;
    }
    return true;
}

// Per-slot result for 16-slot inventory
typedef struct {
    uint8_t slot;
    uint8_t status;      // 0=empty, 1=valid, 2=collision (CRC fail)
    uint8_t data[ISO15693_MAX_SLOT_RESPONSE];
    uint8_t data_len;
} iso15_inventory_result_t;

// Performs a 16-slot (or 1-slot) inventory round with arbitrary command bytes.
// raw_cmd: full ISO 15693 command bytes (flags + cmd_code + params), WITHOUT CRC
// raw_len: length of raw_cmd
// add_crc: whether to append CRC15
// fast: true for high-speed (1 out of 4), false for low-speed (1 out of 256)
// keep_field_on: if true, keep RF field active after command (for multi-round tree walking)
// results: caller-provided array of iso15_inventory_result_t[16]
// num_found: output - number of slots with valid (CRC-OK) responses
// Returns PM3_SUCCESS or error code
static int perform_iso15_inventory(
    const uint8_t *raw_cmd,
    uint16_t raw_len,
    bool add_crc,
    bool fast,
    bool keep_field_on,
    iso15_inventory_result_t *results,
    uint8_t *num_found
) {
    *num_found = 0;
    memset(results, 0, sizeof(iso15_inventory_result_t) * ISO15693_MAX_SLOTS);

    uint16_t cmdlen = raw_len + (add_crc ? 2 : 0);
    iso15_raw_cmd_t *packet = (iso15_raw_cmd_t *)calloc(1, sizeof(iso15_raw_cmd_t) + cmdlen);
    if (packet == NULL) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        return PM3_EMALLOC;
    }

    memcpy(packet->raw, raw_cmd, raw_len);
    packet->rawlen = raw_len;
    if (add_crc) {
        AddCrc15(packet->raw, raw_len);
        packet->rawlen += 2;
    }
    packet->flags = ISO15_CONNECT | ISO15_READ_RESPONSE;
    if (fast) {
        packet->flags |= ISO15_HIGH_SPEED;
    }
    if (keep_field_on) {
        packet->flags |= ISO15_NO_DISCONNECT;
    }

    // Determine if this is a 16-slot request
    bool is_inventory = (raw_cmd[0] & ISO15_REQ_INVENTORY) != 0;
    bool is_16slot = is_inventory && ((raw_cmd[0] & ISO15_REQINV_SLOT1) == 0);
    uint8_t num_slots = is_16slot ? 16 : 1;

    clearCommandBuffer();
    SendCommandNG(CMD_HF_ISO15693_COMMAND, (uint8_t *)packet, ISO15_RAW_LEN(packet->rawlen));
    free(packet);

    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_HF_ISO15693_COMMAND, &resp, 4000)) {
        PrintAndLogEx(WARNING, "timeout while waiting for reply");
        return PM3_ETIMEOUT;
    }
    if (resp.status != PM3_SUCCESS) {
        return resp.status;
    }

    if (is_16slot) {
        // Parse multi-slot response (iso15_inventory_response_t format)
        if (resp.length < 1 + (num_slots * 2)) {
            PrintAndLogEx(WARNING, "response too short for 16-slot inventory");
            return PM3_ESOFT;
        }

        iso15_inventory_response_t *inv = (iso15_inventory_response_t *)resp.data.asBytes;
        uint16_t offset = 0;

        for (uint8_t s = 0; s < num_slots; s++) {
            results[s].slot = s;
            results[s].status = inv->slots[s].status;
            results[s].data_len = inv->slots[s].len;

            if (inv->slots[s].len > 0 && inv->slots[s].len <= sizeof(results[s].data)) {
                memcpy(results[s].data, inv->data + offset, inv->slots[s].len);
                offset += inv->slots[s].len;

                // Validate CRC to distinguish valid response from collision
                if (inv->slots[s].status == 1) {
                    if (inv->slots[s].len >= 4 && CheckCrc15(results[s].data, inv->slots[s].len)) {
                        (*num_found)++;
                    } else {
                        results[s].status = 2; // CRC fail = collision
                    }
                }
            }
        }
    } else {
        // Single-slot: parse as normal single response
        results[0].slot = 0;
        if (resp.length >= 12 && CheckCrc15(resp.data.asBytes, resp.length)) {
            results[0].status = 1;
            results[0].data_len = MIN(resp.length, sizeof(results[0].data));
            memcpy(results[0].data, resp.data.asBytes, results[0].data_len);
            (*num_found)++;
        } else if (resp.length > 0) {
            results[0].status = 2; // got data but CRC failed
            results[0].data_len = MIN(resp.length, sizeof(results[0].data));
            memcpy(results[0].data, resp.data.asBytes, results[0].data_len);
        } else {
            results[0].status = 0;
            results[0].data_len = 0;
        }
    }

    return PM3_SUCCESS;
}

// adds 6
static uint8_t arg_add_default(void *at[]) {
    at[0] = arg_param_begin;
    at[1] = arg_str0("u", "uid", "<hex>", "full UID (8 hex bytes)");
    at[2] = arg_lit0(NULL, "ua", "unaddressed mode");
    at[3] = arg_lit0("*", NULL, "scan for tag");
    at[4] = arg_lit0("2", NULL, "use slower '1 out of 256' mode");
    at[5] = arg_lit0("o", "opt", "set OPTION Flag (needed for TI)");
    return 6;
}
static uint16_t arg_get_raw_flag(uint8_t uidlen, bool unaddressed, bool scan, bool add_option) {
    uint16_t flags = 0;
    ;
    if (uidlen == 8 || scan || unaddressed) {
        flags = (ISO15_REQ_SUBCARRIER_SINGLE | ISO15_REQ_DATARATE_HIGH | ISO15_REQ_NONINVENTORY);
    }
    if ((!unaddressed) || scan) {
        flags |= ISO15_REQ_ADDRESS;
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
        PrintAndLogEx(FAILED, "Too few samples in GraphBuffer");
        PrintAndLogEx(HINT, "Hint: Try `" _YELLOW_("hf 15 samples") "` to collect and download data");
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
    uint8_t mask = 0x01;

    uint8_t outBuf[2048] = {0};
    memset(outBuf, 0, sizeof(outBuf));

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
        PrintAndLogEx(WARNING, "Warning, discarding extra bits!");
        PrintAndLogEx(INFO, "   mask = %02x", mask);
    }

    if (k == 0) {
        return PM3_SUCCESS;
    }

    i = 0;
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "Got %d bytes, decoded as following", k);
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

    PrintAndLogEx(HINT, "Hint: Try `" _YELLOW_("hf 15 demod") "` to decode signal");
    PrintAndLogEx(INFO, "Done!");
    return PM3_SUCCESS;
}

static int NxpTestEAS(const uint8_t *uid, bool fast) {

    if (uid == NULL) {
        return PM3_EINVARG;
    }

    uint8_t approxlen = 3 + ISO15693_UID_LENGTH + 2;
    iso15_raw_cmd_t *packet = (iso15_raw_cmd_t *)calloc(1, sizeof(iso15_raw_cmd_t) + approxlen);
    if (packet == NULL) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        return PM3_EMALLOC;
    }

    // params
    packet->raw[packet->rawlen++] = (ISO15_REQ_SUBCARRIER_SINGLE | ISO15_REQ_DATARATE_HIGH | ISO15_REQ_NONINVENTORY | ISO15_REQ_ADDRESS);
    packet->raw[packet->rawlen++] = ISO15693_EAS_ALARM;
    packet->raw[packet->rawlen++] = 0x04; // IC manufacturer code

    memcpy(packet->raw + packet->rawlen, uid, ISO15693_UID_LENGTH); // add UID
    packet->rawlen += ISO15693_UID_LENGTH;

    AddCrc15(packet->raw,  packet->rawlen);
    packet->rawlen += 2;

    packet->flags = (ISO15_CONNECT | ISO15_READ_RESPONSE);
    if (fast) {
        packet->flags |= ISO15_HIGH_SPEED;
    }

    clearCommandBuffer();
    SendCommandNG(CMD_HF_ISO15693_COMMAND, (uint8_t *)packet, ISO15_RAW_LEN(packet->rawlen));
    free(packet);
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_HF_ISO15693_COMMAND, &resp, 2000) == false) {
        PrintAndLogEx(DEBUG, "iso15693 timeout");
        return PM3_ETIMEOUT;
    }

    if (resp.status == PM3_ETEAROFF) {
        return resp.status;
    }

    // a SLIX with the EAS mode disabled sends no answer (PM3_ETIMEOUT, or PM3_EPARTIAL on noise)
    if (resp.length < 2) {
        PrintAndLogEx(INFO, "");
        PrintAndLogEx(INFO, _CYAN_(" EAS"));
        PrintAndLogEx(INFO, "    EAS (Electronic Article Surveillance) is not active");
        return PM3_SUCCESS;
    }

    uint8_t *d = resp.data.asBytes;

    int res = iso15_info_error_handling(d, resp.length);
    if (res != PM3_SUCCESS) {
        return res;
    }

    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, _CYAN_(" EAS"));

    // flags, 32 byte EAS sequence, CRC
    if (resp.length < (1 + 32 + 2)) {
        PrintAndLogEx(FAILED, "    EAS answer too short ( %d bytes )", resp.length);
        return PM3_EWRONGANSWER;
    }

    PrintAndLogEx(INFO, "  EAS (Electronic Article Surveillance) is active.");
    PrintAndLogEx(INFO, "  EAS sequence...");
    PrintAndLogEx(INFO, "  %s", sprint_hex(d + 1, 16));
    PrintAndLogEx(INFO, "  %s", sprint_hex(d + 1 + 16, 16));
    return PM3_SUCCESS;
}

static int NxpCheckSig(uint8_t *uid, bool fast) {

    if (uid == NULL) {
        return PM3_EINVARG;
    }

    uint8_t approxlen = 3 + ISO15693_UID_LENGTH + 2;
    iso15_raw_cmd_t *packet = (iso15_raw_cmd_t *)calloc(1, sizeof(iso15_raw_cmd_t) + approxlen);
    if (packet == NULL) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        return PM3_EMALLOC;
    }

    // params
    // Check if we can also read the signature
    packet->raw[packet->rawlen++] = (ISO15_REQ_SUBCARRIER_SINGLE | ISO15_REQ_DATARATE_HIGH | ISO15_REQ_NONINVENTORY | ISO15_REQ_ADDRESS);
    packet->raw[packet->rawlen++] = ISO15693_READ_SIGNATURE;
    packet->raw[packet->rawlen++] = 0x04; // IC manufacturer code

    memcpy(packet->raw + packet->rawlen, uid, ISO15693_UID_LENGTH); // add UID
    packet->rawlen += ISO15693_UID_LENGTH;

    AddCrc15(packet->raw,  packet->rawlen);
    packet->rawlen += 2;

    packet->flags = (ISO15_CONNECT | ISO15_READ_RESPONSE);
    if (fast) {
        packet->flags |= ISO15_HIGH_SPEED;
    }

    clearCommandBuffer();
    SendCommandNG(CMD_HF_ISO15693_COMMAND, (uint8_t *)packet, ISO15_RAW_LEN(packet->rawlen));
    free(packet);
    PacketResponseNG resp;

    if (WaitForResponseTimeout(CMD_HF_ISO15693_COMMAND, &resp, 2000) == false) {
        PrintAndLogEx(DEBUG, "iso15693 timeout");
        return PM3_ETIMEOUT;
    }

    if (resp.length < 2) {
        PrintAndLogEx(WARNING, "iso15693 card doesn't answer to READ SIGNATURE command");
        return PM3_EWRONGANSWER;
    }

    uint8_t *d = resp.data.asBytes;

    int res = iso15_info_error_handling(d, resp.length);
    if (res != PM3_SUCCESS) {
        return res;
    }

    uint8_t signature[32] = {0x00};
    memcpy(signature, d + 1, sizeof(signature));

    nxp_15693_print_signature(uid, signature);
    return PM3_SUCCESS;
}

// Get NXP system information from SLIX2 tag/VICC
static int NxpSysInfo(uint8_t *uid, bool fast) {

    if (uid == NULL) {
        return PM3_EINVARG;
    }

    uint8_t approxlen = 13;
    iso15_raw_cmd_t *packet = (iso15_raw_cmd_t *)calloc(1, sizeof(iso15_raw_cmd_t) + approxlen);
    if (packet == NULL) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        return PM3_EMALLOC;
    }

    // params
    packet->raw[packet->rawlen++] = (ISO15_REQ_SUBCARRIER_SINGLE | ISO15_REQ_DATARATE_HIGH | ISO15_REQ_NONINVENTORY | ISO15_REQ_ADDRESS);
    packet->raw[packet->rawlen++] = ISO15693_GET_NXP_SYSTEM_INFO;
    packet->raw[packet->rawlen++] = 0x04; // IC manufacturer code

    memcpy(packet->raw + 3, uid, 8); // add UID
    packet->rawlen += ISO15693_UID_LENGTH;

    AddCrc15(packet->raw,  packet->rawlen);
    packet->rawlen += 2;

    packet->flags = (ISO15_CONNECT | ISO15_READ_RESPONSE);
    if (fast) {
        packet->flags |= ISO15_HIGH_SPEED;
    }

    clearCommandBuffer();
    SendCommandNG(CMD_HF_ISO15693_COMMAND, (uint8_t *)packet, ISO15_RAW_LEN(packet->rawlen));
    free(packet);
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_HF_ISO15693_COMMAND, &resp, 2000) == false) {
        PrintAndLogEx(DEBUG, "iso15693 timeout");
        return PM3_ETIMEOUT;
    }

    if (resp.length < 2) {
        PrintAndLogEx(WARNING, "iso15693 card doesn't answer to NXP systeminfo command");
        return PM3_EWRONGANSWER;
    }

    uint8_t *d = resp.data.asBytes;

    int res = iso15_info_error_handling(d, resp.length);
    if (res != PM3_SUCCESS) {
        return res;
    }

    bool support_signature = (d[5] & 0x01);
    bool support_easmode = (d[4] & 0x04);

    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("NXP Sysinfo"));
    PrintAndLogEx(INFO, "    Raw............ %s", sprint_hex(d, 8));
    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, _CYAN_(" Password protection configuration"));

    PrintAndLogEx(INFO, "    Page prot. ptr. " _YELLOW_("%d"), d[1]);

    PrintAndLogEx(INFO, "    Page L read.... %s"
                  , (d[2] & 0x01) ?  _RED_("password") : _GREEN_("no password")
                 );

    PrintAndLogEx(INFO, "    Page L write... %s"
                  , (d[2] & 0x02) ?  _RED_("password") : _GREEN_("no password")
                 );

    PrintAndLogEx(INFO, "    Page H read.... %s"
                  , (d[2] & 0x10) ?  _RED_("password") : _GREEN_("no password")
                 );

    PrintAndLogEx(INFO, "    Page H write... %s"
                  , (d[2] & 0x20) ?  _RED_("password") : _GREEN_("no password")
                 );

    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, _CYAN_(" Lock bits"));

    // AFI lock bit
    PrintAndLogEx(INFO, "    AFI............ %s"
                  , (d[3] & 0x01) ? _RED_("locked") : _GREEN_("unlocked")
                 );

    // EAS lock bit
    PrintAndLogEx(INFO, "    EAS............ %s"
                  , (d[3] & 0x02) ? _RED_("locked") : _GREEN_("unlocked")
                 );

    // DSFID lock bit
    PrintAndLogEx(INFO, "    DSFID.......... %s"
                  , (d[3] & 0x04) ? _RED_("locked") : _GREEN_("unlocked")
                 );

    // Password protection pointer address and access conditions lock bit
    PrintAndLogEx(INFO, "    Password protection configuration... %s"
                  , (d[3] & 0x08) ? _RED_("locked") : _GREEN_("unlocked")
                 );

    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, _CYAN_(" Features"));
    PrintAndLogEx(INFO, "    User memory password protection%s supported", ((d[4] & 0x01) ? "" : " not"));
    PrintAndLogEx(INFO, "    Counter feature%s supported", ((d[4] & 0x02) ? "" : " not"));
    PrintAndLogEx(INFO, "    EAS ID%s supported by EAS ALARM command", support_easmode ? "" : " not");
    PrintAndLogEx(INFO, "    EAS password protection%s supported", ((d[4] & 0x08) ? "" : " not"));
    PrintAndLogEx(INFO, "    AFI password protection%s supported", ((d[4] & 0x10) ? "" : " not"));
    PrintAndLogEx(INFO, "    Extended mode%s supported by INVENTORY READ command", ((d[4] & 0x20) ? "" : " not"));
    PrintAndLogEx(INFO, "    EAS selection%s supported by extended mode in INVENTORY READ command", ((d[4] & 0x40) ? "" : " not"));
    PrintAndLogEx(INFO, "    READ SIGNATURE command%s supported", support_signature ? "" : " not");
    PrintAndLogEx(INFO, "    Password protection for READ SIGNATURE command%s supported", ((d[5] & 0x02) ? "" : " not"));
    PrintAndLogEx(INFO, "    STAY QUIET PERSISTENT command%s supported", ((d[5] & 0x04) ? "" : " not"));
    PrintAndLogEx(INFO, "    ENABLE PRIVACY command%s supported", ((d[5] & 0x10) ? "" : " not"));
    PrintAndLogEx(INFO, "    DESTROY command%s supported", ((d[5] & 0x20) ? "" : " not"));
    PrintAndLogEx(INFO, "    Additional 32 bits feature flags are%s transmitted", ((d[7] & 0x80) ? "" : " not"));

    if (support_easmode) {
        NxpTestEAS(uid, fast);
    }

    if (support_signature) {
        NxpCheckSig(uid, fast);
    }

    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}

static int StCheckSig(uint8_t *uid, bool fast) {
    // request to be sent to device/card
    uint16_t approxlen = 2 + ISO15693_UID_LENGTH + 1 + 2;
    iso15_raw_cmd_t *packet = (iso15_raw_cmd_t *)calloc(1, sizeof(iso15_raw_cmd_t) + approxlen);
    if (packet == NULL) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        return PM3_EMALLOC;
    }

    // ISO15693 Protocol params
    packet->raw[packet->rawlen++] = arg_get_raw_flag(ISO15693_UID_LENGTH, false, false, false);
    packet->raw[packet->rawlen++] = ISO15693_READBLOCK;

    // add UID (scan, uid)
    memcpy(packet->raw + packet->rawlen, uid, ISO15693_UID_LENGTH);
    packet->rawlen += ISO15693_UID_LENGTH;
    packet->flags = (ISO15_CONNECT | ISO15_READ_RESPONSE | ISO15_NO_DISCONNECT);
    if (fast) {
        packet->flags |= ISO15_HIGH_SPEED;
    }

    uint16_t blkoff = packet->rawlen;
    char signature_hex[65] = {0};

    for (int i = 0; i < 17; i++) {

        // reset rawlength counter
        packet->rawlen = blkoff;

        // block no
        packet->raw[packet->rawlen++] = 0x3F + i;

        // add crc
        AddCrc15(packet->raw,  packet->rawlen);
        packet->rawlen += 2;

        clearCommandBuffer();
        SendCommandNG(CMD_HF_ISO15693_COMMAND, (uint8_t *)packet, ISO15_RAW_LEN(packet->rawlen));
        PacketResponseNG resp;
        if (WaitForResponseTimeout(CMD_HF_ISO15693_COMMAND, &resp, 2000) == false) {
            PrintAndLogEx(DEBUG, "iso15693 timeout");
            free(packet);
            DropField();
            return PM3_ETIMEOUT;
        }

        uint8_t *d = resp.data.asBytes;
        int res = PM3_SUCCESS;
        if (resp.status == PM3_ETEAROFF) {
            res = resp.status;
        } else if (resp.length < 2) {
            PrintAndLogEx(ERR, "iso15693 command failed");
            res = PM3_EWRONGANSWER;
        } else {
            res = iso15_error_handling_card_response(d, resp.length);
        }

        if (res != PM3_SUCCESS) {
            free(packet);
            DropField();
            // error 0F/10 on a signature block: no signature to check
            if (res == PM3_EOUTOFBOUND) {
                PrintAndLogEx(INFO, "No signature, block %u returned error %i: %s", 0x3F + i, d[1], TagErrorStr(d[1]));
                return PM3_SUCCESS;
            }
            return res;
        }

        if (i == 0) {

            if (memcmp(d + 1, "K04S", 4) != 0) {
                // No signature
                PrintAndLogEx(INFO, "No signature, block 63 is not K04S");
                free(packet);
                DropField();
                return PM3_SUCCESS;
            }

        } else {
            memcpy(signature_hex + ((i - 1) * 4), d + 1, 4);
        }
        packet->flags = (ISO15_READ_RESPONSE | ISO15_NO_DISCONNECT);
        if (fast) {
            packet->flags |= ISO15_HIGH_SPEED;
        }
    }

    free(packet);
    DropField();

    uint8_t signature[32] = {0};
    size_t signature_len = 0;
    if (hexstr_to_byte_array(signature_hex, signature, &signature_len) == false) {
        PrintAndLogEx(ERR, "Signature blocks are not a hex string");
        return PM3_ESOFT;
    }

    uint8_t uid_swap[ISO15693_UID_LENGTH];
    reverse_array_copy(uid, ISO15693_UID_LENGTH, uid_swap);

    int index = originality_check_verify_ex(uid_swap, ISO15693_UID_LENGTH, signature, signature_len, PK_ST25TV, false, true);
    PrintAndLogEx(NORMAL, "");
    return originality_check_print(signature, signature_len, index);
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

    void *argtable[6 + 1] = {0};
    uint8_t arglen = arg_add_default(argtable);
    argtable[arglen++] = arg_param_end;

    CLIExecWithReturn(ctx, Cmd, argtable, true);

    uint8_t uid[ISO15693_UID_LENGTH];
    int uidlen = 0;
    CLIGetHexWithReturn(ctx, 1, uid, &uidlen);
    bool unaddressed = arg_get_lit(ctx, 2);
    bool scan = arg_get_lit(ctx, 3);
    bool fast = (arg_get_lit(ctx, 4) == false);
    bool add_option = arg_get_lit(ctx, 5);

    CLIParserFree(ctx);

    // sanity checks
    if ((scan + unaddressed + (uidlen > 0)) > 1) {
        PrintAndLogEx(WARNING, "Select only one option /scan/unaddress/uid");
        return PM3_EINVARG;
    }

    if (uidlen != 0 && uidlen != ISO15693_UID_LENGTH) {
        PrintAndLogEx(WARNING, "UID must include 8 hex bytes, got ( " _RED_("%i") " )", uidlen);
        return PM3_EINVARG;
    }

    // default fallback to scan for tag.
    if (unaddressed == false && uidlen != ISO15693_UID_LENGTH) {
        scan = true;
    }

    // request to be sent to device/card
    // don't know if it has uid added or not.
    //               cmd uid crc
    uint8_t approxlen = 2 + 8 + 2;

    iso15_raw_cmd_t *packet = (iso15_raw_cmd_t *)calloc(1, sizeof(iso15_raw_cmd_t) + approxlen);
    if (packet == NULL) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        return PM3_EMALLOC;
    }

    // ISO15693 protocol params
    packet->raw[packet->rawlen++] = arg_get_raw_flag(uidlen, unaddressed, scan, add_option);
    packet->raw[packet->rawlen++] = ISO15693_GET_SYSTEM_INFO;

    if (unaddressed == false) {
        if (scan) {
            PrintAndLogEx(INFO, "Using scan mode");
            if (getUID(fast, false, false, uid) != PM3_SUCCESS) {
                PrintAndLogEx(WARNING, "no tag found");
                free(packet);
                return PM3_EINVARG;
            }
            uidlen = ISO15693_UID_LENGTH;
        } else {
            reverse_array(uid, ISO15693_UID_LENGTH);
        }

        if (uidlen == ISO15693_UID_LENGTH) {
            // add UID (scan, uid)
            memcpy(packet->raw + packet->rawlen, uid, uidlen);
            packet->rawlen += uidlen;
        }
    } else {
        PrintAndLogEx(INFO, "Using unaddressed mode");
    }

    AddCrc15(packet->raw,  packet->rawlen);
    packet->rawlen += 2;

    // PM3 flags
    packet->flags = (ISO15_CONNECT | ISO15_READ_RESPONSE);
    if (fast) {
        packet->flags |= ISO15_HIGH_SPEED;
    }

    clearCommandBuffer();
    SendCommandNG(CMD_HF_ISO15693_COMMAND, (uint8_t *)packet, ISO15_RAW_LEN(packet->rawlen));
    free(packet);
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_HF_ISO15693_COMMAND, &resp, 2000) == false) {
        PrintAndLogEx(DEBUG, "iso15693 timeout");
        return PM3_ETIMEOUT;
    }

    if (resp.length < 2) {
        PrintAndLogEx(WARNING, "iso15693 card doesn't answer to systeminfo command (%d)", resp.length);
        return PM3_EWRONGANSWER;
    }

    uint8_t *d = resp.data.asBytes;

    int res = iso15_info_error_handling(d, resp.length);
    if (res != PM3_SUCCESS) {
        return res;
    }

    uint16_t need = iso15_sysinfo_min_len(d[1]);
    if (resp.length < need) {
        PrintAndLogEx(WARNING, "iso15693 systeminfo answer too short ( %d bytes, expected %u )", resp.length, need);
        return PM3_EWRONGANSWER;
    }

    memcpy(uid, d + 2, sizeof(uid));

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Tag Information") " ---------------------------");
    PrintAndLogEx(SUCCESS, "UID....... " _GREEN_("%s"), iso15693_sprintUID(NULL, uid));
    printTagInfo_15(d + 2);
    PrintAndLogEx(SUCCESS, "SYSINFO... %s", sprint_hex(d, resp.length - 2));

    // optional fields follow the UID in flag order, only when their flag is set
    uint8_t afi_pos = 10 + (d[1] & 0x01);
    uint8_t mem_pos = afi_pos + ((d[1] & 0x02) ? 1 : 0);
    uint8_t icref_pos = mem_pos + ((d[1] & 0x04) ? 2 : 0);

    // DSFID
    if (d[1] & 0x01)
        PrintAndLogEx(SUCCESS, "DSFID..... 0x%02X", d[10]);
    else
        PrintAndLogEx(SUCCESS, "DSFID not supported");

    // AFI
    if (d[1] & 0x02)
        PrintAndLogEx(SUCCESS, "AFI....... 0x%02X%s", d[afi_pos], (d[afi_pos] == 0x30) ? " ( Secura Key e*Tag )" : "");
    else
        PrintAndLogEx(SUCCESS, "AFI not supported");

    // IC reference
    if (d[1] & 0x08)
        PrintAndLogEx(SUCCESS, "IC ref.... 0x%02X", d[icref_pos]);
    else
        PrintAndLogEx(SUCCESS, "IC ref not supported");

    // memory
    if (d[1] & 0x04) {
        PrintAndLogEx(SUCCESS, "Tag memory layout (vendor dependent)");
        uint16_t blocks = d[mem_pos] + 1;
        uint8_t size = (d[mem_pos + 1] & 0x1F);
        PrintAndLogEx(SUCCESS, "    " _YELLOW_("%u") " ( or " _YELLOW_("%u") " ) bytes/blocks x " _YELLOW_("%u") " blocks", size + 1, size, blocks);
        PrintAndLogEx(SUCCESS, "    " _YELLOW_("%u") " total bytes", ((size + 1) * blocks));
    } else {
        PrintAndLogEx(SUCCESS, "    n/a");
    }

    // Check if SLIX2 and attempt to get NXP System Information
    PrintAndLogEx(DEBUG, "Byte 6 :: %02x   Byte 7 :: %02x   Byte 8 :: %02x", d[6], d[7], d[8]);

    if (d[8] == 0x04) {
        // NXP

        // from: SL2S6002_SDS
        // Bit 37 Bit 36 ICODE Type
        // -------------------------
        // 0      0      ICODE SLI
        // 1      0      ICODE SLIX
        // 0      1      ICODE SLIX2
        // 1      1      ICODE DNA

        // SLIX2 uses xxx0 1xxx format on d[6] of UID
        uint8_t nxp_version = d[6] & 0x18;
        PrintAndLogEx(DEBUG, "NXP Version: %02x", nxp_version);

        // from: SL2S3103
        // Bit 39 Bit 38 Bit 37 Bit 36 ICODE Type
        // --------------------------------------
        // 0      1      0      0      ICODE 3
        // --> it can be mismached with a ICODE SLI, but lets assume Bit 39 & Bit 38 at 0 when ICODE SLI*/DNA...

        if (d[7] == 0x01 && nxp_version == 0x08) {
            PrintAndLogEx(DEBUG, "SLIX2 Detected, getting NXP System Info");
            return NxpSysInfo(uid, fast);
        } else if (d[7] == 0x01 && nxp_version == 0x18) { // If it is an NTAG 5 / ICODE DNA
            PrintAndLogEx(DEBUG, "NTAG 5 / ICODE DNA Detected, getting NXP System Info");
            res = NxpSysInfo(uid, fast);
            PrintAndLogEx(HINT, "Hint: Try `" _YELLOW_("hf 15 implant") "`");
            return res;
        } else if (d[7] == 0x01 && ((d[6] & 0x78) == 0x20)) { // If it is an NTAG ICODE 3
            PrintAndLogEx(DEBUG, "ICODE 3 Detected, getting NXP System Info");
            return NxpSysInfo(uid, fast);
        } else if ((d[7] == 0x01 || d[7] == 0x02 || d[7] == 0x03)) { // If SLI, SLIX, SLIX-l, or SLIX-S check EAS status
            PrintAndLogEx(DEBUG, "SLI, SLIX, SLIX-L, or SLIX-S Detected checking EAS status");
            return NxpTestEAS(uid, fast);
        }
    } else if (d[8] == 0x02) {
        // ST, check d[7]:
        // ST25TV512C/ST25TV02KC  0x08
        // ST25TV512/ST25TV02K    0x23
        // ST25TV04K-P            0x35
        // ST25TV16K/ST25TV64K    0x48
        if (d[7] == 0x08) {
            PrintAndLogEx(DEBUG, "ST25TVxC Detected, getting ST Signature");
            return StCheckSig(uid, fast);
        }
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

    PrintAndLogEx(HINT, "Hint: Try `" _YELLOW_("hf 15 list") "` to view captured tracelog");
    PrintAndLogEx(HINT, "Hint: Try `" _YELLOW_("trace save -h") "` to save tracelog for later analysing");
    PrintAndLogEx(INFO, "Done!");
    return PM3_SUCCESS;
}

// Single 1-slot inventory round with optional AFI and speed control
static int reader_single_tag(bool fast, bool loop, uint8_t *afi_buf, int afi_len) {

    do {
        uint8_t raw_cmd[8] = {0};
        uint16_t raw_len = 0;

        raw_cmd[raw_len] = ISO15_REQ_SUBCARRIER_SINGLE
                           | ISO15_REQ_DATARATE_HIGH
                           | ISO15_REQ_INVENTORY
                           | ISO15_REQINV_SLOT1;
        if (afi_len > 0)
            raw_cmd[raw_len] |= ISO15_REQINV_AFI;
        raw_len++;

        raw_cmd[raw_len++] = ISO15693_INVENTORY;

        if (afi_len > 0)
            raw_cmd[raw_len++] = afi_buf[0];

        raw_cmd[raw_len++] = 0; // mask length = 0

        iso15_inventory_result_t results[ISO15693_MAX_SLOTS] = {{0}};
        uint8_t num_found = 0;

        int res = perform_iso15_inventory(raw_cmd, raw_len, true, fast, false, results, &num_found);
        if (res == PM3_SUCCESS && num_found > 0 && results[0].status == 1 && results[0].data_len >= 12) {
            uint8_t uid[8];
            memcpy(uid, results[0].data + 2, 8);

            PrintAndLogEx(NORMAL, "");
            PrintAndLogEx(SUCCESS, "UID.... " _GREEN_("%s"), iso15693_sprintUID(NULL, uid));
            PrintAndLogEx(SUCCESS, "DSFID.. %02X", results[0].data[1]);
            printTagInfo_15(uid);
            PrintAndLogEx(NORMAL, "");

            if (!loop)
                return PM3_SUCCESS;
        }
    } while (loop && kbd_enter_pressed() == false);

    return PM3_SUCCESS;
}

// 16-slot anti-collision tree walking to discover all tags in the field
// One persistent row per UID ever seen during a continuous `hf 15 reader --all -@`.
typedef struct {
    uint8_t  uid[8];
    uint8_t  dsfid;
    uint64_t last_seen_ms;
    bool     present;
} iso15_seen_tag_t;

// Redraw the presence table in place via cursor-up. Printed with newlines BETWEEN rows but none
// after the last, so the cursor never drops below the bottom row (a trailing newline at the
// screen bottom would scroll and leave the header behind). To refresh, return to the top of the
// block (\r + cursor-up) and clear to end of screen. All printf, so header/data columns align.
static void iso15_render_presence_table(const iso15_seen_tag_t *seen, int n,
                                        bool inplace, bool *first_draw, int *table_lines) {
    if (inplace && (*first_draw == false)) {
        if (*table_lines > 1) {
            PrintAndLogEx(NORMAL, "\r" _CURSOR_UP_ _CLR_EOS_, *table_lines - 1);
        } else {
            PrintAndLogEx(NORMAL, "\r" _CLR_EOS_);
        }
    } else if ((inplace == false) && (*first_draw == false)) {
        PrintAndLogEx(NORMAL, ""); // piped/non-TTY: separate snapshots
    }

    int present = 0;
    for (int i = 0; i < n; i++) {
        if (seen[i].present) present++;
    }
    uint64_t now = msclock();

    const char *c_grn = g_session.supports_colors ? ANSI_GREEN : "";
    const char *c_yel = g_session.supports_colors ? ANSI_YELLOW : "";
    const char *c_off = g_session.supports_colors ? AEND : "";

    int lines = 0;
    PrintAndLogEx(INFO, "hf 15 --all   present %d / %d   " _GREEN_("<Enter>") " to exit", present, n);
    lines++;
    PrintAndLogEx(INFO, "%3s   %-25s    %-5s    %s", "#", "UID", "DSFID", "status");
    lines++;
    PrintAndLogEx(INFO, "%3s   %-25s    %-5s    %s", "---", "-------------------------", "-----", "----------------");
    lines++;
    for (int i = 0; i < n; i++) {
        if (seen[i].present) {
            PrintAndLogEx(INFO, "%3d   %-25s    %02X       %spresent%s"
                          , i + 1
                          , iso15693_sprintUID(NULL, (uint8_t *)seen[i].uid)
                          , seen[i].dsfid
                          , c_grn
                          , c_off
                         );
        } else {
            uint32_t secs = (uint32_t)((now - seen[i].last_seen_ms) / 1000);
            PrintAndLogEx(INFO, "%3d   %-25s    %02X       %sgone%s (%us ago)"
                          , i + 1
                          , iso15693_sprintUID(NULL, (uint8_t *)seen[i].uid)
                          , seen[i].dsfid
                          , c_yel
                          , c_off
                          , secs
                         );
        }
        lines++;
    }
    *table_lines = lines;
    *first_draw = false;
}

static int reader_inventory_all(bool fast, bool loop, uint8_t *afi_buf, int afi_len) {

    typedef struct {
        uint8_t mask[8];
        uint8_t mask_len; // in bits
    } inventory_work_item_t;

#define MAX_WORK_ITEMS 256
#define MAX_FOUND_TAGS 64
#define MAX_SEEN_TAGS  128

    // Persistent across scans in continuous (-@) mode: every UID seen this session.
    iso15_seen_tag_t seen[MAX_SEEN_TAGS];
    int seen_count = 0;
    bool inplace = loop && g_session.stdoutOnTTY;
    bool first_draw = true;
    int table_lines = 0;

    do {
        inventory_work_item_t work_queue[MAX_WORK_ITEMS];
        int work_head = 0;
        int work_tail = 0;

        uint8_t found_uids[MAX_FOUND_TAGS][8];
        uint8_t found_dsfids[MAX_FOUND_TAGS];
        int found_count = 0;

        // Start with empty mask
        memset(&work_queue[0], 0, sizeof(inventory_work_item_t));
        work_tail = 1;

        while (work_head < work_tail && work_head < MAX_WORK_ITEMS) {

            inventory_work_item_t *item = &work_queue[work_head++];

            // Build inventory command with current mask
            uint8_t raw_cmd[16] = {0};
            uint16_t raw_len = 0;

            raw_cmd[raw_len] = ISO15_REQ_SUBCARRIER_SINGLE
                               | ISO15_REQ_DATARATE_HIGH
                               | ISO15_REQ_INVENTORY;
            // 16-slot: do NOT set ISO15_REQINV_SLOT1
            if (afi_len > 0)
                raw_cmd[raw_len] |= ISO15_REQINV_AFI;
            raw_len++;

            raw_cmd[raw_len++] = ISO15693_INVENTORY;

            if (afi_len > 0)
                raw_cmd[raw_len++] = afi_buf[0];

            raw_cmd[raw_len++] = item->mask_len;

            // Copy mask bytes
            uint8_t mask_bytes = (item->mask_len + 7) / 8;
            if (mask_bytes > 0) {
                memcpy(raw_cmd + raw_len, item->mask, mask_bytes);
                raw_len += mask_bytes;
            }

            iso15_inventory_result_t results[ISO15693_MAX_SLOTS] = {{0}};
            uint8_t num_found = 0;

            // Always keep field on during tree walking; we drop it once after the loop
            int res = perform_iso15_inventory(raw_cmd, raw_len, true, fast, true, results, &num_found);
            if (res != PM3_SUCCESS) {
                PrintAndLogEx(DEBUG, "Inventory round failed (mask_len=%d)", item->mask_len);
                continue;
            }

            for (uint8_t s = 0; s < 16; s++) {
                if (results[s].status == 1 && results[s].data_len >= 12) {
                    // Valid response: extract UID (in transmission order, LSB first)
                    uint8_t uid[8];
                    memcpy(uid, results[s].data + 2, 8);

                    // Check for duplicate
                    bool duplicate = false;
                    for (int d = 0; d < found_count; d++) {
                        if (memcmp(found_uids[d], uid, 8) == 0) {
                            duplicate = true;
                            break;
                        }
                    }

                    if (!duplicate && found_count < MAX_FOUND_TAGS) {
                        memcpy(found_uids[found_count], uid, 8);
                        found_dsfids[found_count] = results[s].data[1];
                        found_count++;
                    }
                } else if (results[s].status == 2) {
                    // Collision in this slot - add to work queue with extended mask
                    if (item->mask_len + 4 <= 64 && work_tail < MAX_WORK_ITEMS) {
                        inventory_work_item_t *new_item = &work_queue[work_tail++];
                        memcpy(new_item->mask, item->mask, sizeof(new_item->mask));
                        new_item->mask_len = item->mask_len + 4;

                        // The slot number (0-15) represents the 4 bits that
                        // differentiated this slot. Append slot number to mask.
                        uint8_t bit_pos = item->mask_len;
                        uint8_t byte_pos = bit_pos / 8;
                        uint8_t bit_offset = bit_pos % 8;

                        // Write the 4-bit slot number into the mask at the current position
                        if (byte_pos < 8) {
                            new_item->mask[byte_pos] |= (s << bit_offset) & 0xFF;
                            if (bit_offset > 4 && (byte_pos + 1) < 8) {
                                new_item->mask[byte_pos + 1] |= (s >> (8 - bit_offset)) & 0xFF;
                            }
                        }
                    }
                }
                // status == 0: no response, skip silently
            }

            if (kbd_enter_pressed()) {
                PrintAndLogEx(INFO, "Aborted by user");
                DropField();
                return PM3_SUCCESS;
            }
        }

        // NB: don't DropField() per scan in continuous mode -- it re-inits the field every
        // round (slow, and spams "Setting ISODEP" when APDU logging is on). The next round
        // re-selects anyway, and the field is dropped once when the loop exits.

        if (loop) {
            // Continuous mode: fold this scan into the persistent table and redraw it in place.
            for (int i = 0; i < seen_count; i++) {
                seen[i].present = false;
            }
            for (int j = 0; j < found_count; j++) {
                int idx = -1;
                for (int i = 0; i < seen_count; i++) {
                    if (memcmp(seen[i].uid, found_uids[j], 8) == 0) {
                        idx = i;
                        break;
                    }
                }
                if (idx < 0 && seen_count < MAX_SEEN_TAGS) {
                    idx = seen_count++;
                    memcpy(seen[idx].uid, found_uids[j], 8);
                }
                if (idx >= 0) {
                    seen[idx].dsfid = found_dsfids[j];
                    seen[idx].last_seen_ms = msclock();
                    seen[idx].present = true;
                }
            }
            iso15_render_presence_table(seen, seen_count, inplace, &first_draw, &table_lines);

        } else {
            // Single-shot mode: list what was found.
            if (found_count > 0) {
                PrintAndLogEx(NORMAL, "");
                PrintAndLogEx(SUCCESS, "Found " _GREEN_("%d") " tag(s):", found_count);
                for (int i = 0; i < found_count; i++) {
                    PrintAndLogEx(SUCCESS, "  %2d: UID " _GREEN_("%s") "  DSFID: %02X",
                                  i + 1,
                                  iso15693_sprintUID(NULL, found_uids[i]),
                                  found_dsfids[i]);
                }
                PrintAndLogEx(NORMAL, "");
            } else {
                PrintAndLogEx(WARNING, "No tags found");
            }
        }

    } while (loop && kbd_enter_pressed() == false);

    DropField();
    return PM3_SUCCESS;
}

static int CmdHF15Reader(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf 15 reader",
                  "Act as a ISO-15693 reader. Look for ISO-15693 tags until " _GREEN_("<Enter>") " is pressed\n"
                  "Use --all to perform 16-slot inventory with anti-collision tree walking\n"
                  "to discover all tags in the field.",
                  "hf 15 reader\n"
                  "hf 15 reader -@                -> continuous mode\n"
                  "hf 15 reader --afi 01          -> filter by AFI\n"
                  "hf 15 reader -2                -> slower '1 out of 256' mode\n"
                  "hf 15 reader --all             -> find all tags (16-slot anti-collision)\n"
                  "hf 15 reader --all -@          -> continuously scan for all tags\n"
                  "hf 15 reader --all --afi 01    -> find all tags with AFI filter\n"
                  "hf 15 reader --all -2          -> find all tags, slow mode\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("@", NULL, "continuous reader mode"),
        arg_lit0(NULL, "all", "find all tags using 16-slot anti-collision"),
        arg_str0(NULL, "afi", "<hex>", "Application Family Identifier (1 byte)"),
        arg_lit0("2", NULL, "use slower '1 out of 256' mode"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool loop = arg_get_lit(ctx, 1);
    bool all = arg_get_lit(ctx, 2);

    int afi_len = 0;
    uint8_t afi_buf[1] = {0};
    CLIGetHexWithReturn(ctx, 3, afi_buf, &afi_len);

    bool fast = (arg_get_lit(ctx, 4) == false); // default is fast
    CLIParserFree(ctx);

    if (loop) {
        PrintAndLogEx(INFO, "Press " _GREEN_("<Enter>") " to exit");
    }

    if (all) {
        return reader_inventory_all(fast, loop, afi_buf, afi_len);
    }

    // Single-tag mode: use --afi/-2 aware path if those flags are set,
    // otherwise preserve original behavior via readHF15Uid
    if (afi_len > 0 || !fast) {
        return reader_single_tag(fast, loop, afi_buf, afi_len);
    }

    readHF15Uid(loop, true);
    return PM3_SUCCESS;
}

static void hf15EmlClear(void) {
    clearCommandBuffer();
    SendCommandNG(CMD_HF_ISO15693_EML_CLEAR, NULL, 0);
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_HF_ISO15693_EML_CLEAR, &resp, 2500) == false) {
        PrintAndLogEx(WARNING, "timeout while waiting for reply");
    }
}

static int hf15EmlSetMem(const uint8_t *data, uint16_t count, size_t offset) {
    struct p {
        uint32_t offset;
        uint16_t count;
        uint8_t data[];
    } PACKED;

    if (count > (g_conn.max_cmd_data_size - sizeof(struct p))) {
        return PM3_ESOFT;
    }

    size_t paylen = sizeof(struct p) + count;
    struct p *payload = calloc(1, paylen);
    if (payload == NULL) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        return PM3_EMALLOC;
    }

    payload->offset = offset;
    payload->count = count;
    memcpy(payload->data, data, count);

    clearCommandBuffer();
    SendCommandNG(CMD_HF_ISO15693_EML_SETMEM, (uint8_t *)payload, paylen);
    free(payload);
    return PM3_SUCCESS;
}

static int CmdHF15ELoad(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf 15 eload",
                  "Load memory dump from file to be used with 'hf 15 sim'",
                  "hf 15 eload -f hf-15-01020304.bin\n"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_str1("f", "file", "<fn>", "filename of dump"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE];
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);
    CLIParserFree(ctx);

    iso15_tag_t *tag = NULL;
    size_t bytes_read = 0;
    int res = pm3_load_dump(filename, (void **)&tag, &bytes_read, sizeof(iso15_tag_t));
    if (res != PM3_SUCCESS) {
        return res;
    }

    if (bytes_read == 0) {
        PrintAndLogEx(FAILED, "Memory image empty.");
        free(tag);
        return PM3_EINVARG;
    }

    // a .bin may hold an older struct revision, upgrade it before the checks below
    res = convert_15_dump_format((uint8_t **)&tag, &bytes_read, true);
    if (res != PM3_SUCCESS) {
        free(tag);
        return res;
    }

    if (bytes_read != sizeof(iso15_tag_t)) {
        PrintAndLogEx(FAILED, "Memory image is not matching tag structure.");
        free(tag);
        return PM3_EINVARG;
    }

    if (iso15_tag_size_ok(tag) == false) {
        free(tag);
        return PM3_EINVARG;
    }

    PrintAndLogEx(INFO, "Clearing emulator memory");
    fflush(stdout);
    hf15EmlClear();

    PrintAndLogEx(INFO, "Uploading to emulator memory");
    PrintAndLogEx(INFO, "." NOLF);

    // fast push mode
    g_conn.block_after_ACK = true;

    size_t chuncksize = 256;
    size_t offset = 0;

    while (bytes_read > 0) {
        if (bytes_read <= chuncksize) {
            // Disable fast mode on last packet
            g_conn.block_after_ACK = false;
        }

        uint16_t bytestosend = MIN(chuncksize, bytes_read);
        if (hf15EmlSetMem((uint8_t *)tag + offset, bytestosend, offset) != PM3_SUCCESS) {
            PrintAndLogEx(FAILED, "Can't set emulator memory at offest: %zu / 0x%zx", offset, offset);
            free(tag);
            return PM3_ESOFT;
        }
        PrintAndLogEx(NORMAL, "." NOLF);
        fflush(stdout);

        offset += bytestosend;
        bytes_read -= bytestosend;
    }
    free(tag);
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(SUCCESS, "uploaded " _YELLOW_("%zu") " bytes to emulator memory", offset);

    PrintAndLogEx(HINT, "Hint: Use `" _YELLOW_("hf 15 sim -h") "`");
    PrintAndLogEx(INFO, "Done!");
    return PM3_SUCCESS;
}

static int CmdHF15ESave(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf 15 esave",
                  "Save emulator memory into two files (bin/json) ",
                  "hf 15 esave -f hf-15-01020304"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_str1("f", "file", "<fn>", "Specify a filename for dump file"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE];
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);
    CLIParserFree(ctx);

    int bytes = sizeof(iso15_tag_t);

    // reserve memory
    uint8_t *dump = calloc(bytes, sizeof(uint8_t));
    if (dump == NULL) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        return PM3_EMALLOC;
    }

    PrintAndLogEx(INFO, "Downloading %u bytes from emulator memory", bytes);
    if (GetFromDevice(BIG_BUF_EML, dump, bytes, 0, NULL, 0, NULL, 2500, false) == false) {
        PrintAndLogEx(WARNING, "Fail, transfer from device time-out");
        free(dump);
        return PM3_ETIMEOUT;
    }

    pm3_save_dump_json(filename, dump, bytes, jsf15_v5);

    free(dump);
    return PM3_SUCCESS;
}

static const char dashes[] = "------------------------------------------------------------";
static void print_hrule(int blocksize) {

    int len = MAX(0, 3 * blocksize);
    PrintAndLogEx(INFO, "-----+-%.*s+---+-%.*s-", len, dashes, blocksize, dashes);
}

// for emaulator and dump files we don't have lock info byte available.
static void print_blocks_15693(iso15_tag_t *tag, bool dense_output) {
    uint8_t *d = tag->data;
    int blocksize = tag->bytesPerPage;

    print_hrule(blocksize);

    char spaces[] = "                                                            ";
    PrintAndLogEx(INFO, " blk | data %.*s|lck| ascii", MAX(0, 3 * blocksize - 5), spaces);
    print_hrule(blocksize);

    bool in_repeated_block = false;

    for (int i = 0; i < tag->pagesCount; i++) {

        const uint8_t *blk = d + (i * blocksize);

        // suppress repeating blocks, truncate as such that the first and last block with the same data is shown
        // but the blocks in between are replaced with a single line of "......" if dense_output is enabled
        if (dense_output &&
                (i > 3) &&
                (i < (tag->pagesCount - 1)) &&
                (in_repeated_block == false) &&
                (memcmp(blk, blk - blocksize, blocksize) == 0) &&
                (memcmp(blk, blk + blocksize, blocksize) == 0) &&
                (memcmp(blk, blk + (blocksize * 2), blocksize) == 0)
           ) {
            // we're in a user block that isn't the first user block nor last two user blocks,
            // and the current block data is the same as the previous and next two block
            in_repeated_block = true;
            PrintAndLogEx(INFO, "  ......");
        } else if (in_repeated_block &&
                   (memcmp(blk, blk + blocksize, blocksize) || i == tag->pagesCount)
                  ) {
            // in a repeating block, but the next block doesn't match anymore, or we're at the end block
            in_repeated_block = false;
        }

        if (in_repeated_block == false) {

            char lck[16] = {0};
            if (tag->locks[i]) {
                snprintf(lck, sizeof(lck), _RED_("%d"), tag->locks[i]);
            } else {
                snprintf(lck, sizeof(lck), "%d", tag->locks[i]);
            }

            PrintAndLogEx(INFO, "%4d | %s| %s | %s"
                          , i
                          , sprint_hex(&tag->data[i * tag->bytesPerPage], tag->bytesPerPage)
                          , lck
                          , sprint_ascii(&tag->data[i * tag->bytesPerPage], tag->bytesPerPage)
                         );
        }
    }
}

static void print_tag_15693(iso15_tag_t *tag, bool dense_output, bool verbose) {
    if (verbose) {
        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(INFO, "--- " _CYAN_("Tag Information") " --%.*s", (tag->bytesPerPage * 3), dashes);
        PrintAndLogEx(SUCCESS, "UID....... " _GREEN_("%s"), iso15693_sprintUID(NULL, tag->uid));
        printTagInfo_15(tag->uid);
        PrintAndLogEx(SUCCESS, "DSFID..... 0x%02X", tag->dsfid);
        PrintAndLogEx(SUCCESS, "AFI....... 0x%02X%s", tag->afi, (tag->afi == 0x30) ? " ( Secura Key e*Tag )" : "");
        PrintAndLogEx(SUCCESS, "IC ref.... 0x%02X", tag->ic);
        PrintAndLogEx(SUCCESS, "Tag memory layout (vendor dependent)");
        PrintAndLogEx(SUCCESS, "    " _YELLOW_("%u") " bytes / blocks x " _YELLOW_("%u") " blocks", tag->bytesPerPage, tag->pagesCount);
        PrintAndLogEx(SUCCESS, "    " _YELLOW_("%u") " total bytes", (tag->bytesPerPage * tag->pagesCount));
    }

    PrintAndLogEx(NORMAL, "");

    if ((tag->bytesPerPage == 0) || (tag->pagesCount == 0)) {
        PrintAndLogEx(INFO, "Tag is empty!");
        return;
    }

    PrintAndLogEx(INFO, "--- " _CYAN_("Tag Memory") " -------%.*s", (tag->bytesPerPage * 3), dashes);
    PrintAndLogEx(NORMAL, "");
    print_blocks_15693(tag, dense_output);
    print_hrule(tag->bytesPerPage);
    PrintAndLogEx(NORMAL, "");
}

static int CmdHF15EView(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf 15 eview",
                  "It displays emulator memory",
                  "hf 15 eview\n"
                  "hf 15 eview -z\n"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_lit0("z", "dense", "dense dump output style"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool dense_output = (g_session.dense_output || arg_get_lit(ctx, 1));
    CLIParserFree(ctx);

    int bytes = sizeof(iso15_tag_t);

    // reserve memory
    uint8_t *dump = calloc(bytes, sizeof(uint8_t));
    if (dump == NULL) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        return PM3_EMALLOC;
    }

    PrintAndLogEx(INFO, "Downloading " _YELLOW_("%u") " bytes from emulator memory...", bytes);
    if (GetFromDevice(BIG_BUF_EML, dump, bytes, 0, NULL, 0, NULL, 2500, false) == false) {
        PrintAndLogEx(WARNING, "Fail, transfer from device time-out");
        free(dump);
        return PM3_ETIMEOUT;
    }

    print_tag_15693((iso15_tag_t *)dump, dense_output, true);

    free(dump);
    return PM3_SUCCESS;
}

// Simulation is still not working very good
// helptext
static int CmdHF15Sim(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf 15 sim",
                  "Simulate a ISO-15693 tag\n",
                  "hf 15 sim\n"
                  "hf 15 sim -u E011223344556677");
    void *argtable[] = {
        arg_param_begin,
        arg_str0("u", "uid", "<hex>", "UID, 8 hex bytes"),
        arg_int0("b", "blocksize", "<dec>", "block size (def 4)"),
        arg_int0("t", "timeout", "<dec>", "timeout in ms (def -1, ie. until button press)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    struct {
        uint8_t uid[ISO15693_UID_LENGTH];
        uint8_t block_size;
    } PACKED payload;
    memset(&payload, 0, sizeof(payload));

    int uidlen = 0;
    CLIGetHexWithReturn(ctx, 1, payload.uid, &uidlen);
    payload.block_size = arg_get_int_def(ctx, 2, 4);
    size_t timeout = arg_get_int_def(ctx, 3, -1);
    CLIParserFree(ctx);

    // sanity checks
    if (uidlen != 0 && uidlen != ISO15693_UID_LENGTH) {
        PrintAndLogEx(WARNING, "UID must include 8 hex bytes, got ( " _RED_("%i") " )", uidlen);
        return PM3_EINVARG;
    }

    PacketResponseNG resp;

    // get UID from emulator for printing
    if (uidlen == 0) {

        struct {
            uint32_t offset;
            uint16_t length;
        } PACKED payload_mem;

        payload_mem.offset = 0;
        payload_mem.length = 8;

        clearCommandBuffer();
        SendCommandNG(CMD_HF_ISO15693_EML_GETMEM, (uint8_t *)&payload_mem, sizeof(payload_mem));
        if (WaitForResponseTimeout(CMD_HF_ISO15693_EML_GETMEM, &resp, 2000) == false) {
            PrintAndLogEx(DEBUG, "iso15693 timeout");
            return PM3_ETIMEOUT;
        }

        if (resp.status != PM3_SUCCESS) {
            PrintAndLogEx(WARNING, "Failed to get UID from emulator memory");
            return resp.status;
        }
        PrintAndLogEx(SUCCESS, "Start simulating UID... " _YELLOW_("%s"), iso15693_sprintUID(NULL, resp.data.asBytes));
    }

    PrintAndLogEx(INFO, "Press " _GREEN_("pm3 button") " to abort simulation");

    clearCommandBuffer();
    SendCommandNG(CMD_HF_ISO15693_SIMULATE, (uint8_t *)&payload, sizeof(payload));
    WaitForResponseTimeout(CMD_HF_ISO15693_SIMULATE, &resp, timeout);
    if (timeout != (size_t) - 1) {
        SendCommandNG(CMD_BREAK_LOOP, NULL, 0);
    }
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
        arg_lit0("2", NULL, "use slower '1 out of 256' mode"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool fast = (arg_get_lit(ctx, 1) == false);
    CLIParserFree(ctx);

    PrintAndLogEx(INFO, "Press " _GREEN_("pm3 button") " or " _GREEN_("<Enter>") " to exit");

    struct p {
        uint32_t flags;
    } PACKED packet;

    packet.flags = 0;
    if (fast) {
        packet.flags |= ISO15_HIGH_SPEED;
    }

    clearCommandBuffer();
    SendCommandNG(CMD_HF_ISO15693_FINDAFI, (uint8_t *)&packet, sizeof(struct p));
    PacketResponseNG resp;

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
    PrintAndLogEx(INFO, "Done!");
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

    void *argtable[] = {
        arg_param_begin,
        arg_str0("u", "uid", "<hex>", "full UID, 8 hex bytes"),
        arg_int1(NULL, "afi", "<dec>", "AFI number (0-255)"),
        arg_str0("p", "pwd", "<hex>", "optional AFI/EAS password"),
        arg_param_end
    };

    CLIExecWithReturn(ctx, Cmd, argtable, true);

    struct {
        uint8_t pwd[4];
        bool use_pwd;
        uint8_t uid[ISO15693_UID_LENGTH];
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
    if (uidlen == ISO15693_UID_LENGTH) {
        payload.use_uid = true;
    }

    // sanity checks
    if (uidlen != 0 && uidlen != 8) {
        PrintAndLogEx(WARNING, "uid must be 8 hex bytes, got ( " _RED_("%d") " )", uidlen);
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
            PrintAndLogEx(WARNING, "Writing AFI ( " _RED_("fail") " )");
            break;
        }
        case PM3_SUCCESS: {
            PrintAndLogEx(SUCCESS, "Wrote AFI 0x%02X ( " _GREEN_("ok") " )", payload.afi);
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

    void *argtable[6 + 3] = {0};
    uint8_t arglen = arg_add_default(argtable);
    argtable[arglen++] = arg_int1(NULL, "dsfid", "<dec>", "DSFID number (0-255)");
    argtable[arglen++] = arg_lit0("v", "verbose", "verbose output");
    argtable[arglen++] = arg_param_end;

    CLIExecWithReturn(ctx, Cmd, argtable, false);

    uint8_t uid[ISO15693_UID_LENGTH] = {0};
    int uidlen = 0;
    CLIGetHexWithReturn(ctx, 1, uid, &uidlen);

    bool unaddressed = arg_get_lit(ctx, 2);
    bool scan = arg_get_lit(ctx, 3);
    bool fast = (arg_get_lit(ctx, 4) == false);
    bool add_option = arg_get_lit(ctx, 5);

    int dsfid = arg_get_int_def(ctx, 6, 0);
    bool verbose = arg_get_lit(ctx, 7);
    CLIParserFree(ctx);

    // sanity checks
    if ((scan + unaddressed + (uidlen > 0)) > 1) {
        PrintAndLogEx(WARNING, "Select only one option /scan/unaddress/uid");
        return PM3_EINVARG;
    }

    // request to be sent to device/card
    uint16_t approxlen = 2 + ISO15693_UID_LENGTH + 1 + 2;
    iso15_raw_cmd_t *packet = (iso15_raw_cmd_t *)calloc(1, sizeof(iso15_raw_cmd_t) + approxlen);
    if (packet == NULL) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        return PM3_EMALLOC;
    }

    // params
    packet->raw[packet->rawlen++] = arg_get_raw_flag(uidlen, unaddressed, scan, add_option);
    packet->raw[packet->rawlen++] = ISO15693_WRITE_DSFID;

    if (unaddressed == false) {
        if (scan) {
            PrintAndLogEx(INFO, "Using scan mode");
            if (getUID(fast, verbose, false, uid) != PM3_SUCCESS) {
                PrintAndLogEx(WARNING, "no tag found");
                free(packet);
                return PM3_EINVARG;
            }
            uidlen = ISO15693_UID_LENGTH;
        }

        if (uidlen == ISO15693_UID_LENGTH) {
            // add UID (scan, uid)
            memcpy(packet->raw + packet->rawlen, uid, uidlen);
            packet->rawlen += uidlen;
        }
    } else {
        PrintAndLogEx(INFO, "Using unaddressed mode");
    }

    // dsfid
    packet->raw[packet->rawlen++] = (uint8_t)dsfid;

    AddCrc15(packet->raw,  packet->rawlen);
    packet->rawlen += 2;

    packet->flags = (ISO15_CONNECT | ISO15_READ_RESPONSE | ISO15_LONG_WAIT);
    if (fast) {
        packet->flags |= ISO15_HIGH_SPEED;
    }

    clearCommandBuffer();
    SendCommandNG(CMD_HF_ISO15693_COMMAND, (uint8_t *)packet, ISO15_RAW_LEN(packet->rawlen));
    free(packet);
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_HF_ISO15693_COMMAND, &resp, 2000) == false) {
        PrintAndLogEx(DEBUG, "iso15693 timeout");
        return PM3_ETIMEOUT;
    }

    ISO15_ERROR_HANDLING_RESPONSE

    uint8_t *d = resp.data.asBytes;

    ISO15_ERROR_HANDLING_CARD_RESPONSE(d, resp.length)

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(SUCCESS, "Wrote DSFID 0x%02X ( " _GREEN_("ok") " )", dsfid);
    return PM3_SUCCESS;
}

// Reads all memory pages
// need to write to file
static int CmdHF15Dump(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf 15 dump",
                  "This command dumps the contents of a ISO-15693 tag and saves it to a JSON file.\n"
                  "Writing .bin is no longer supported, the raw struct carries no layout\n"
                  "information. Reading .bin/.eml/.json all still work.",
                  "hf 15 dump\n"
                  "hf 15 dump -*\n"
                  "hf 15 dump -u E011223344556677 -f hf-15-my-dump"
                 );

    void *argtable[6 + 6] = {0};
    uint8_t arglen = arg_add_default(argtable);
    argtable[arglen++] = arg_str0("f", "file", "<fn>", "Specify a filename for dump file");
    argtable[arglen++] = arg_int0(NULL, "bs", "<dec>", "block size (def 4)");
    argtable[arglen++] = arg_lit0(NULL, "ns", "no save to file");
    argtable[arglen++] = arg_lit0("v", "verbose", "verbose output");
    argtable[arglen++] = arg_lit0("z", "dense", "dense dump output style");
    argtable[arglen++] = arg_param_end;

    CLIExecWithReturn(ctx, Cmd, argtable, true);

    uint8_t uid[ISO15693_UID_LENGTH] = {0};
    int uidlen = 0;
    CLIGetHexWithReturn(ctx, 1, uid, &uidlen);

    bool unaddressed = arg_get_lit(ctx, 2);
    bool scan = arg_get_lit(ctx, 3);
    bool fast = (arg_get_lit(ctx, 4) == false);
    bool add_option = arg_get_lit(ctx, 5);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 6), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);

    int blocksize = arg_get_int_def(ctx, 7, 4);
    bool no_save = arg_get_lit(ctx, 8);
    bool verbose = arg_get_lit(ctx, 9);
    bool dense_output = arg_get_lit(ctx, 10);
    CLIParserFree(ctx);

    // sanity checks
    if ((scan + unaddressed + (uidlen > 0)) > 1) {
        PrintAndLogEx(WARNING, "Select only one option /scan/unaddress/uid");
        return PM3_EINVARG;
    }

    if (blocksize < 4) {
        PrintAndLogEx(WARNING, "Blocksize too small, using default 4 bytes");
        blocksize = 4;
    }

    // ISO15693 block size field is 5 bits
    if (blocksize > 32) {
        PrintAndLogEx(WARNING, "Blocksize too large, using maximum 32 bytes");
        blocksize = 32;
    }

    // default fallback to scan for tag.
    if (uidlen != ISO15693_UID_LENGTH && !unaddressed) {
        scan = true;
    }

    // request to be sent to device/card
    uint16_t approxlen = 2 + ISO15693_UID_LENGTH + 1 + 2;
    iso15_raw_cmd_t *packet = (iso15_raw_cmd_t *)calloc(1, sizeof(iso15_raw_cmd_t) + approxlen);
    if (packet == NULL) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        return PM3_EMALLOC;
    }

    // struct of ISO15693 tag memory (new file format)
    iso15_tag_t *tag = (iso15_tag_t *)calloc(1, sizeof(iso15_tag_t));
    if (tag == NULL) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        free(packet);
        return PM3_EMALLOC;
    };

    // ISO15693 Protocol params
    packet->raw[packet->rawlen++] = arg_get_raw_flag(uidlen, unaddressed, scan, add_option);
    packet->raw[packet->rawlen++] = ISO15693_GET_SYSTEM_INFO;

    bool used_uid = false;
    if (unaddressed == false) {
        // default fallback to scan for tag. Overriding unaddress parameter
        if (scan) {
            PrintAndLogEx(INFO, "Using scan mode");
            if (getUID(fast, verbose, false, uid) != PM3_SUCCESS) {
                free(packet);
                free(tag);
                PrintAndLogEx(WARNING, "no tag found");
                return PM3_EINVARG;
            }
        } else {
            reverse_array(uid, ISO15693_UID_LENGTH);
        }
        // add UID (scan, uid)
        memcpy(packet->raw + packet->rawlen, uid, ISO15693_UID_LENGTH);
        packet->rawlen += ISO15693_UID_LENGTH;
        used_uid = true;
    } else {
        PrintAndLogEx(INFO, "Using unaddressed mode");
    }

    AddCrc15(packet->raw,  packet->rawlen);
    packet->rawlen += 2;

    // PM3 params
    packet->flags = (ISO15_CONNECT | ISO15_READ_RESPONSE | ISO15_NO_DISCONNECT);
    if (fast) {
        packet->flags |= ISO15_HIGH_SPEED;
    }

    clearCommandBuffer();
    SendCommandNG(CMD_HF_ISO15693_COMMAND, (uint8_t *)packet, ISO15_RAW_LEN(packet->rawlen));

    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_HF_ISO15693_COMMAND, &resp, 2000) == false) {
        PrintAndLogEx(DEBUG, "iso15693 timeout");
        free(packet);
        free(tag);
        DropField();
        return PM3_ETIMEOUT;
    }

    if (resp.length < 2) {
        PrintAndLogEx(WARNING, "iso15693 card doesn't answer to systeminfo command (%d)", resp.length);
        free(packet);
        free(tag);
        DropField();
        return PM3_EWRONGANSWER;
    }

    uint8_t *d = resp.data.asBytes;
    uint8_t dCpt = 10;

    int res = iso15_error_handling_card_response(d, resp.length);
    if (res == PM3_ECRC) {
        free(tag);
        free(packet);
        DropField();
        return res;
    }

    bool sysinfo_ok = (res == PM3_SUCCESS);
    uint16_t need = iso15_sysinfo_min_len(d[1]);
    if (sysinfo_ok && (resp.length < need)) {
        PrintAndLogEx(WARNING, "systeminfo answer too short ( %d bytes, expected %u ), using defaults", resp.length, need);
        sysinfo_ok = false;
    }

    if (sysinfo_ok) {
        memcpy(tag->uid, d + 2, 8);

        // optional fields follow the UID in flag order, only when their flag is set
        if (d[1] & 0x01) {
            tag->dsfid = d[dCpt++];
        }

        if (d[1] & 0x02) {
            tag->afi = d[dCpt++];
        }

        if (d[1] & 0x04) {
            tag->pagesCount = d[dCpt] + 1;
            // block size in b5-b1, b8-b6 RFU
            tag->bytesPerPage = (d[dCpt + 1] & 0x1F) + 1;
            dCpt += 2;
        } else {
            // Set tag memory layout values (if can't be read in SYSINFO)
            tag->bytesPerPage = blocksize;
            // 128 blocks, fewer when large blocks would not fit
            tag->pagesCount = MIN(128, ISO15693_TAG_MAX_SIZE / blocksize);
        }

        if (d[1] & 0x08) {
            tag->ic = d[dCpt];
        }

    } else {
        tag->uid[0] = 0xE0;
        tag->dsfid = 0;
        tag->afi = 0;
        // Set tag memory layout values (if can't be read in SYSINFO)
        tag->bytesPerPage = blocksize;
        tag->pagesCount = MIN(128, ISO15693_TAG_MAX_SIZE / blocksize);
    }

    if (iso15_tag_size_ok(tag) == false) {
        free(packet);
        free(tag);
        DropField();
        return PM3_EINVARG;
    }

    // add length for blockno (1)
    packet->rawlen++;
    packet->raw[0] |= ISO15_REQ_OPTION; // Add option to dump lock status
    packet->raw[1] = ISO15693_READBLOCK;

    packet->flags = (ISO15_READ_RESPONSE | ISO15_NO_DISCONNECT);
    if (fast) {
        packet->flags |= ISO15_HIGH_SPEED;
    }

    PrintAndLogEx(SUCCESS, "Reading memory");

    int blocknum = 0;
    bool end_of_memory = false;

    for (int retry = 0; (retry < 2 && blocknum < tag->pagesCount); retry++) {
        if (used_uid) {
            packet->raw[10] = (uint8_t)blocknum & 0xFF;
            AddCrc15(packet->raw, 11);
        } else {
            packet->raw[2] = (uint8_t)blocknum & 0xFF;
            AddCrc15(packet->raw, 3);
        }

        clearCommandBuffer();
        SendCommandNG(CMD_HF_ISO15693_COMMAND, (uint8_t *)packet, ISO15_RAW_LEN(packet->rawlen));

        if (WaitForResponseTimeout(CMD_HF_ISO15693_COMMAND, &resp, 2000)) {

            if (resp.length < 2) {
                PrintAndLogEx(NORMAL, "");
                PrintAndLogEx(FAILED, "iso15693 command failed");
                continue;
            }

            d = resp.data.asBytes;

            if (CheckCrc15(d, resp.length) == false) {
                PrintAndLogEx(NORMAL, "");
                PrintAndLogEx(FAILED, "crc ( " _RED_("fail") " )");
                continue;
            }

            if ((d[0] & ISO15_RES_ERROR) == ISO15_RES_ERROR) {

                // heuristic determine end of available memory
                if (d[1] == 0x0F || d[1] == 0x10) {
                    end_of_memory = true;
                    break;
                }

                PrintAndLogEx(NORMAL, "");
                PrintAndLogEx(FAILED, "Tag returned Error %i: %s", d[1], TagErrorStr(d[1]));
                break;
            }

            // flags, lock status, block data, CRC
            if (resp.length != (2 + tag->bytesPerPage + 2)) {
                PrintAndLogEx(NORMAL, "");
                PrintAndLogEx(FAILED, "block %d answer is %d bytes, expected %d for a %u byte block",
                              blocknum, resp.length, 2 + tag->bytesPerPage + 2, tag->bytesPerPage);

                if (resp.length > 4) {
                    PrintAndLogEx(HINT, "Hint: Try `" _YELLOW_("--bs %d") "`", resp.length - 4);
                }

                continue;
            }

            tag->locks[blocknum] = d[1];

            // copy read data
            memcpy(&tag->data[blocknum * tag->bytesPerPage], d + 2, tag->bytesPerPage);

            retry = 0;
            blocknum++;

            PrintAndLogEx(INPLACE, "blk %3d", blocknum);
        }
    }

    free(packet);
    DropField();

    // done reading tag memory

    // The tag has no more blocks than this, the rest of the default range doesn't exist
    if (end_of_memory) {
        tag->pagesCount = blocknum;
    }

    // Anything else that ended the loop early left the remaining blocks unread.  They
    // must not be shown as data, nor saved as a dump
    bool incomplete = (blocknum < tag->pagesCount);
    uint32_t expected = tag->pagesCount;
    if (incomplete) {
        tag->pagesCount = blocknum;
    }

    if (tag->bytesPerPage != blocksize) {
        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(INFO, _YELLOW_("%u") " bytes block length detected, called with " _YELLOW_("%d"), tag->bytesPerPage, blocksize);
        PrintAndLogEx(INFO, "Using %u ...", tag->bytesPerPage);
    }

    print_tag_15693(tag, dense_output, verbose);

    if (incomplete) {
        PrintAndLogEx(WARNING, "Dump " _RED_("incomplete") ", read %d of %u blocks, not saved", blocknum, expected);
        PrintAndLogEx(HINT, "Hint: Reposition the card and try again");
        PrintAndLogEx(NORMAL, "");
        free(tag);
        return PM3_EPARTIAL;
    }

    if (no_save) {
        PrintAndLogEx(INFO, "Called with no save option");
        PrintAndLogEx(NORMAL, "");
        free(tag);
        return PM3_SUCCESS;
    }

    // user supplied filename ?
    if (strlen(filename) < 1) {
        char *fptr = filename;
        PrintAndLogEx(INFO, "Using UID as filename");
        fptr += snprintf(fptr, sizeof(filename), "hf-15-");
        FillFileNameByUID(fptr, SwapEndian64(uid, sizeof(uid), 8), "-dump", sizeof(uid));
    }

    pm3_save_dump_json(filename, (uint8_t *)tag, sizeof(iso15_tag_t), jsf15_v5);

    free(tag);
    return PM3_SUCCESS;
}

static int CmdHF15List(const char *Cmd) {
    return CmdTraceListAlias(Cmd, "hf 15", "15 -c");
}

static int CmdHF15Raw(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf 15 raw",
                  "Sends raw bytes over ISO-15693 to card",
                  "hf 15 raw -ac -d 260100    --> activate, add crc\n"
                  "hf 15 raw -akrc -d 260100  --> activate, add crc, keep field on, skip response"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a", NULL, "activate field"),
        arg_lit0("c", "crc", "calculate and append CRC"),
        arg_lit0("k", NULL, "keep signal field ON after receive"),
        arg_lit0("2", NULL, "use slower '1 out of 256' mode"),
        arg_lit0("r", NULL, "do not read response"),
        arg_str1("d", "data", "<hex>", "raw bytes to send"),
        arg_lit0("w", "wait", "wait longer for response. For writes etc."),
        arg_param_end
    };

    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool activate = arg_get_lit(ctx, 1);
    bool crc = arg_get_lit(ctx, 2);
    bool keep_field_on = arg_get_lit(ctx, 3);
    bool fast = (arg_get_lit(ctx, 4) == false);
    bool read_respone = (arg_get_lit(ctx, 5) == false);

    int datalen = 0;
    uint8_t data[PM3_CMD_DATA_SIZE] = { 0x00 };
    CLIGetHexWithReturn(ctx, 6, data, &datalen);

    bool wait = arg_get_lit(ctx, 7);
    CLIParserFree(ctx);

    // the packet header has to fit too
    int maxlen = g_conn.max_cmd_data_size - sizeof(iso15_raw_cmd_t);
    if (datalen > maxlen) {
        PrintAndLogEx(FAILED, "raw data too long, max %d bytes", maxlen);
        return PM3_EINVARG;
    }

    if (crc) {

        if ((datalen + 2) <= maxlen) {
            AddCrc15(data, datalen);
            datalen += 2;
        } else {
            PrintAndLogEx(FAILED, "raw data too long to add CRC.");
            return PM3_ECRC;
        }
    }

    iso15_raw_cmd_t *packet = (iso15_raw_cmd_t *)calloc(1, sizeof(iso15_raw_cmd_t) + datalen);
    if (packet == NULL) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        return PM3_EMALLOC;
    }

    if (fast) {
        packet->flags |= ISO15_HIGH_SPEED;
    }

    // track that RF field is UP.
    if (keep_field_on) {
        packet->flags |= ISO15_NO_DISCONNECT;
    }

    if (read_respone) {
        packet->flags |= ISO15_READ_RESPONSE;
    }

    if (wait) {
        packet->flags |= ISO15_LONG_WAIT;
    }

    if (activate) {
        packet->flags |= ISO15_CONNECT;
        SetISODEPState(ISODEP_NFCV);
    }

    packet->rawlen = datalen;
    memcpy(packet->raw, data, datalen);

    clearCommandBuffer();
    SendCommandNG(CMD_HF_ISO15693_COMMAND, (uint8_t *)packet, ISO15_RAW_LEN(datalen));
    free(packet);

    // Check if this was a 16-slot inventory request
    bool is_inventory = (datalen > 0) && ((data[0] & ISO15_REQ_INVENTORY) != 0);
    bool is_16slot = is_inventory && ((data[0] & ISO15_REQINV_SLOT1) == 0);

    if (read_respone) {
        PacketResponseNG resp;
        if (WaitForResponseTimeout(CMD_HF_ISO15693_COMMAND, &resp, is_16slot ? 4000 : 2000)) {
            if (resp.status == PM3_ETEAROFF) {
                PrintAndLogEx(INFO, "Tear off triggered");
                return resp.status;
            }

            if (is_16slot && resp.length >= 1 + (16 * sizeof(iso15_slot_result_t))) {
                // Parse 16-slot inventory response
                iso15_inventory_response_t *inv = (iso15_inventory_response_t *)resp.data.asBytes;
                uint16_t offset = 0;
                int found = 0;

                for (uint8_t s = 0; s < inv->slot_count && s < 16; s++) {
                    if (inv->slots[s].status == 1 && inv->slots[s].len > 0) {
                        uint8_t *slot_data = inv->data + offset;

                        if (inv->slots[s].len >= 3 && CheckCrc15(slot_data, inv->slots[s].len)) {
                            // CRC valid - show raw hex (format varies by command)
                            PrintAndLogEx(SUCCESS, "Slot %2d: (%u) %s", s, inv->slots[s].len,
                                          sprint_hex(slot_data, inv->slots[s].len));
                            found++;
                        } else {
                            PrintAndLogEx(INFO, "Slot %2d: " _YELLOW_("collision / CRC fail") " (%u) %s", s,
                                          inv->slots[s].len,
                                          sprint_hex(slot_data, inv->slots[s].len));
                        }
                    }
                    if (inv->slots[s].len > 0)
                        offset += inv->slots[s].len;
                }

                if (found == 0) {
                    PrintAndLogEx(WARNING, "No valid responses in any slot");
                } else {
                    PrintAndLogEx(SUCCESS, "Found %d tag(s) in 16-slot inventory", found);
                }
            } else if (resp.length < 2) {
                PrintAndLogEx(WARNING, "command failed");
            } else {
                PrintAndLogEx(SUCCESS, "(%u) %s", resp.length, sprint_hex(resp.data.asBytes, resp.length));
            }

        } else {
            PrintAndLogEx(WARNING, "timeout while waiting for reply");
        }
    } else {
        // the device replies anyway: read it, or the next command takes it as its own
        PacketResponseNG resp;
        if (WaitForResponseTimeout(CMD_HF_ISO15693_COMMAND, &resp, is_16slot ? 4000 : 2000) == false) {
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

    void *argtable[6 + 5] = {0};
    uint8_t arglen = arg_add_default(argtable);
    argtable[arglen++] = arg_int1("b", NULL, "<dec>", "first page number (0-255)");
    argtable[arglen++] = arg_int1(NULL, "cnt", "<dec>", "number of pages (1-6)");
    argtable[arglen++] = arg_int0(NULL, "bs", "<dec>", "block size (def 4)");
    argtable[arglen++] = arg_lit0("v", "verbose", "verbose output");
    argtable[arglen++] = arg_param_end;

    CLIExecWithReturn(ctx, Cmd, argtable, false);

    uint8_t uid[ISO15693_UID_LENGTH] = {0x00};
    int uidlen = 0;
    CLIGetHexWithReturn(ctx, 1, uid, &uidlen);
    bool uid_set = (uidlen == ISO15693_UID_LENGTH) ? true : false;

    bool unaddressed = arg_get_lit(ctx, 2);
    bool scan = (arg_get_lit(ctx, 3) || (!uid_set && !unaddressed)) ? true : false; //Default fallback to scan for tag. Overriding unaddressed parameter.
    bool fast = (arg_get_lit(ctx, 4) == false);
    bool add_option = arg_get_lit(ctx, 5);

    int blockno = arg_get_int_def(ctx, 6, 0);
    int blockcnt = arg_get_int_def(ctx, 7, 0);
    int blocksize = arg_get_int_def(ctx, 8, 4);
    bool verbose = arg_get_lit(ctx, 9);
    CLIParserFree(ctx);

    // sanity checks
    if (blockcnt > 6) {
        PrintAndLogEx(WARNING, "Page count must be 6 or less, got ( " _RED_("%d") " )", blockcnt);
        return PM3_EINVARG;
    }

    if ((scan + unaddressed + uid_set) > 1) {
        PrintAndLogEx(WARNING, "Select only one option /scan/unaddress/uid");
        return PM3_EINVARG;
    }

    if (blocksize < 4) {
        PrintAndLogEx(WARNING, "Blocksize too small, using default 4 bytes");
        blocksize = 4;
    }

    // enforcing add_option in order to get lock-info
    if (add_option == false) {
        if (verbose) {
            PrintAndLogEx(INFO, "Overriding OPTION param in order to get lock-info response (ENFORCE)");
        }
        add_option = true;
    }

    // request to be sent to device/card
    uint8_t approxlen = 2 + 8 + 2 + 2;
    iso15_raw_cmd_t *packet = (iso15_raw_cmd_t *)calloc(1, sizeof(iso15_raw_cmd_t) + approxlen);
    if (packet == NULL) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        return PM3_EMALLOC;
    }

    // ISO15693 Protocol params
    packet->raw[packet->rawlen++] = arg_get_raw_flag(uidlen, unaddressed, scan, add_option);
    packet->raw[packet->rawlen++] = ISO15693_READ_MULTI_BLOCK;

    if (unaddressed == false) {
        if (scan) {
            PrintAndLogEx(INFO, "Using scan mode");
            if (getUID(fast, verbose, false, uid) != PM3_SUCCESS) {
                free(packet);
                PrintAndLogEx(WARNING, "no tag found");
                return PM3_EINVARG;
            }
        } else {
            reverse_array(uid, ISO15693_UID_LENGTH);
        }
        // add UID (scan, uid)
        memcpy(packet->raw + packet->rawlen, uid, ISO15693_UID_LENGTH);
        packet->rawlen += ISO15693_UID_LENGTH;

    } else {
        PrintAndLogEx(INFO, "Using unaddressed mode");
    }

    if (verbose) {
        PrintAndLogEx(INFO, "Using block size... " _YELLOW_("%d"), blocksize);
    }

    // 0 means 1 page,
    // 1 means 2 pages, ...
    if (blockcnt > 0) {
        blockcnt--;
    }

    packet->raw[packet->rawlen++] = blockno;
    packet->raw[packet->rawlen++] = blockcnt;

    // crc
    AddCrc15(packet->raw,  packet->rawlen);
    packet->rawlen += 2;

    packet->flags = (ISO15_CONNECT | ISO15_READ_RESPONSE);
    if (fast) {
        packet->flags |= ISO15_HIGH_SPEED;
    }

    clearCommandBuffer();
    SendCommandNG(CMD_HF_ISO15693_COMMAND, (uint8_t *)packet, ISO15_RAW_LEN(packet->rawlen));
    free(packet);
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_HF_ISO15693_COMMAND, &resp, 2000) == false) {
        PrintAndLogEx(FAILED, "iso15693 card timeout");
        return PM3_ETIMEOUT;
    }

    ISO15_ERROR_HANDLING_RESPONSE

    uint8_t *d = resp.data.asBytes;

    ISO15_ERROR_HANDLING_CARD_RESPONSE(d, resp.length)

    // 1 byte cmd,  1 lock byte,  4 / 8 bytes block size,  2 crc
    if (resp.length > (1 + ((blockcnt + 1) * (blocksize + 1)) + 2)) {
        PrintAndLogEx(WARNING, "got longer response. Check block size!");
    }

    // skip status byte
    int start = 1;
    int stop = ((blockcnt + 1) * (blocksize + 1));
    int currblock = blockno;

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, " #       | data         |lck| ascii");
    PrintAndLogEx(INFO, "---------+--------------+---+----------");

    for (int i = start; i < stop; i += (blocksize + 1)) {

        char lck[16] = {0};
        if (d[i]) {
            snprintf(lck, sizeof(lck), _RED_("%d"), d[i]);
        } else {
            snprintf(lck, sizeof(lck), "%d", d[i]);
        }

        PrintAndLogEx(INFO, "%3d/0x%02X | %s | %s | %s", currblock, currblock, sprint_hex(d + i + 1, blocksize), lck, sprint_ascii(d + i + 1, blocksize));

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

    void *argtable[6 + 4] = {0};
    uint8_t arglen = arg_add_default(argtable);
    argtable[arglen++] = arg_int1("b", "blk", "<dec>", "page number (0-255)");
    argtable[arglen++] = arg_int0(NULL, "bs", "<dec>", "block size (def 4)");
    argtable[arglen++] = arg_lit0("v", "verbose", "verbose output");
    argtable[arglen++] = arg_param_end;

    CLIExecWithReturn(ctx, Cmd, argtable, false);

    uint8_t uid[ISO15693_UID_LENGTH];
    int uidlen = 0;
    CLIGetHexWithReturn(ctx, 1, uid, &uidlen);
    bool uid_set = (uidlen == ISO15693_UID_LENGTH) ? true : false;

    bool unaddressed = arg_get_lit(ctx, 2);
    bool scan = (arg_get_lit(ctx, 3) || (!uid_set && !unaddressed)) ? true : false; // Default fallback to scan for tag. Overriding unaddressed parameter.
    bool fast = (arg_get_lit(ctx, 4) == false);
    bool add_option = arg_get_lit(ctx, 5);

    int blockno = arg_get_int_def(ctx, 6, 0);
    int blocksize = arg_get_int_def(ctx, 7, 4);

    bool verbose = arg_get_lit(ctx, 8);
    CLIParserFree(ctx);

    // sanity checks
    if ((scan + unaddressed + uid_set) > 1) {
        PrintAndLogEx(WARNING, "Select only one option /scan/unaddress/uid");
        return PM3_EINVARG;
    }

    if (blocksize < 4) {
        PrintAndLogEx(WARNING, "Blocksize too small, using default 4 bytes");
        blocksize = 4;
    }

    // enforcing add_option in order to get lock-info
    if (add_option == false) {
        if (verbose) {
            PrintAndLogEx(INFO, "Overriding OPTION param in order to get lock-info response (ENFORCE)");
        }
        add_option = true;
    }

    // request to be sent to device/card
    uint16_t approxlen = 2 + ISO15693_UID_LENGTH + 1 + 2;
    iso15_raw_cmd_t *packet = (iso15_raw_cmd_t *)calloc(1, sizeof(iso15_raw_cmd_t) + approxlen);
    if (packet == NULL) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        return PM3_EMALLOC;
    }

    // ISO15693 Protocol params
    packet->raw[packet->rawlen++] = arg_get_raw_flag(uidlen, unaddressed, scan, add_option);
    packet->raw[packet->rawlen++] = ISO15693_READBLOCK;

    if (unaddressed == false) {
        // default fallback to scan for tag. Overriding unaddress parameter
        if (scan) {
            PrintAndLogEx(INFO, "Using scan mode");
            if (getUID(fast, verbose, false, uid) != PM3_SUCCESS) {
                free(packet);
                PrintAndLogEx(WARNING, "no tag found");
                return PM3_EINVARG;
            }
        } else {
            reverse_array(uid, ISO15693_UID_LENGTH);
        }
        // add UID (scan, uid)
        memcpy(packet->raw + packet->rawlen, uid, ISO15693_UID_LENGTH);
        packet->rawlen += ISO15693_UID_LENGTH;

    } else {
        PrintAndLogEx(INFO, "Using unaddressed mode");
    }

    if (verbose) {
        PrintAndLogEx(INFO, "Using block size... " _YELLOW_("%d"), blocksize);
    }

    // block no
    packet->raw[packet->rawlen++] = (uint8_t)blockno;

    // crc
    AddCrc15(packet->raw,  packet->rawlen);
    packet->rawlen += 2;

    packet->flags = (ISO15_CONNECT | ISO15_READ_RESPONSE);
    if (fast) {
        packet->flags |= ISO15_HIGH_SPEED;
    }

    clearCommandBuffer();
    SendCommandNG(CMD_HF_ISO15693_COMMAND, (uint8_t *)packet, ISO15_RAW_LEN(packet->rawlen));
    free(packet);
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_HF_ISO15693_COMMAND, &resp, 2000) == false) {
        PrintAndLogEx(DEBUG, "iso15693 timeout");
        return PM3_ETIMEOUT;
    }

    ISO15_ERROR_HANDLING_RESPONSE

    uint8_t *d = resp.data.asBytes;

    ISO15_ERROR_HANDLING_CARD_RESPONSE(d, resp.length)

    // print response
    char lck[16] = {0};
    if (d[1]) {
        snprintf(lck, sizeof(lck), _RED_("%d"), d[1]);
    } else {
        snprintf(lck, sizeof(lck), "%d", d[1]);
    }

    PrintAndLogEx(NORMAL, "");

    uint8_t offset = 2;

    bool got_blocksize8 = (resp.length > 8);

    if (got_blocksize8)  {
        PrintAndLogEx(INFO, "#%3d        |lck| ascii", blockno);
        PrintAndLogEx(INFO, "------------+---+------");
        PrintAndLogEx(INFO, "%s| %s | %s"
                      , sprint_hex(d + offset, 8)
                      , lck
                      , sprint_ascii(d + offset, 8)
                     );
        PrintAndLogEx(INFO, "------------+---+------");

    } else {
        PrintAndLogEx(INFO, "#%3d        |lck| ascii", blockno);
        PrintAndLogEx(INFO, "------------+---+------");
        PrintAndLogEx(INFO, "%s| %s | %s"
                      , sprint_hex(d + offset, 4)
                      , lck
                      , sprint_ascii(d + offset, 4)
                     );
        PrintAndLogEx(INFO, "------------+---+------");
    }

    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}

static int hf_15_write_blk(const uint8_t *pm3flags, uint16_t flags, const uint8_t *uid, bool fast, uint8_t blockno, const uint8_t *data, uint8_t dlen) {

    // request to be sent to device/card
    //   2 + 8 + 1 + (4|8) + 2
    uint8_t approxlen = 21;
    iso15_raw_cmd_t *packet = (iso15_raw_cmd_t *)calloc(1, sizeof(iso15_raw_cmd_t) + approxlen);
    if (packet == NULL) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        return PM3_EMALLOC;
    }

    // ISO15693 protocol params
    packet->raw[packet->rawlen++] = flags;
    packet->raw[packet->rawlen++] = ISO15693_WRITEBLOCK;

    // add UID
    if (uid) {
        memcpy(packet->raw +  packet->rawlen, uid, ISO15693_UID_LENGTH);
        packet->rawlen += ISO15693_UID_LENGTH;
    }

    packet->raw[packet->rawlen++] = blockno;

    memcpy(packet->raw + packet->rawlen, data, dlen);
    packet->rawlen += dlen;

    AddCrc15(packet->raw, packet->rawlen);
    packet->rawlen += 2;

    // PM3 params
    if (pm3flags) {
        packet->flags = *pm3flags;
    } else {
        packet->flags = (ISO15_CONNECT | ISO15_READ_RESPONSE | ISO15_LONG_WAIT);
        if (fast) {
            packet->flags |= ISO15_HIGH_SPEED;
        }
    }

    clearCommandBuffer();
    SendCommandNG(CMD_HF_ISO15693_COMMAND, (uint8_t *)packet, ISO15_RAW_LEN(packet->rawlen));
    free(packet);
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_HF_ISO15693_COMMAND, &resp, 2000) == false) {
        PrintAndLogEx(FAILED, "iso15693 card timeout, data may be written anyway");
        return PM3_ETIMEOUT;
    }

    ISO15_ERROR_HANDLING_RESPONSE

    uint8_t *d = resp.data.asBytes;

    ISO15_ERROR_HANDLING_CARD_RESPONSE(d, resp.length)

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

    void *argtable[6 + 4] = {0};
    uint8_t arglen = arg_add_default(argtable);
    argtable[arglen++] = arg_int1("b", "blk", "<dec>", "page number (0-255)");
    argtable[arglen++] = arg_str1("d", "data", "<hex>", "data, 4 bytes");
    argtable[arglen++] = arg_lit0("v", "verbose", "verbose output");
    argtable[arglen++] = arg_param_end;
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    uint8_t uid[ISO15693_UID_LENGTH];
    int uidlen = 0;
    CLIGetHexWithReturn(ctx, 1, uid, &uidlen);
    bool uid_set = (uidlen == ISO15693_UID_LENGTH) ? true : false;

    bool unaddressed = arg_get_lit(ctx, 2);
    bool scan = (arg_get_lit(ctx, 3) || (!uid_set && !unaddressed)) ? true : false; // Default fallback to scan for tag. Overriding unaddressed parameter.
    bool fast = (arg_get_lit(ctx, 4) == false);
    bool add_option = arg_get_lit(ctx, 5);

    int blockno = arg_get_int_def(ctx, 6, 0);
    uint8_t d[8];
    int dlen = 0;
    CLIGetHexWithReturn(ctx, 7, d, &dlen);

    bool verbose = arg_get_lit(ctx, 8);
    CLIParserFree(ctx);

    // sanity checks
    if ((scan + unaddressed + uid_set) > 1) {
        PrintAndLogEx(WARNING, "Select only one option /scan/unaddress/uid");
        return PM3_EINVARG;
    }

    if ((dlen != 4) && (dlen != 8)) {
        PrintAndLogEx(WARNING, "expected data, 4 or 8 bytes, got " _RED_("%d"), dlen);
        return PM3_EINVARG;
    }

    // default fallback to scan for tag.
    // overriding unaddress parameter :)
    if (unaddressed == false) {
        if (scan) {
            PrintAndLogEx(INFO, "Using scan mode");
            if (getUID(fast, verbose, false, uid) != PM3_SUCCESS) {
                PrintAndLogEx(WARNING, "no tag found");
                return PM3_EINVARG;
            }
        } else {
            reverse_array(uid, ISO15693_UID_LENGTH);
        }
    } else {
        PrintAndLogEx(INFO, "Using unaddressed mode");
    }

    // TI needs OPTION
    if (uid[7] == 0xE0 && uid[6] == 0x07) {
        if (verbose) {
            PrintAndLogEx(INFO, "Overriding OPTION param, writing to TI tag");
        }
        add_option = true;
    }

    uint16_t flags = arg_get_raw_flag(uidlen, unaddressed, scan, add_option);

    int res = hf_15_write_blk(NULL, flags, ((unaddressed) ? NULL : uid), fast, (uint8_t)blockno, d, dlen);

    if (res == PM3_SUCCESS)
        PrintAndLogEx(SUCCESS, "Writing to page %02d (0x%02X) | %s  ( " _GREEN_("ok") " )", blockno, blockno, sprint_hex(d, dlen));
    else
        PrintAndLogEx(FAILED, "Writing to page %02d (0x%02X) | %s  ( " _RED_("fail") " )", blockno, blockno, sprint_hex(d, dlen));

    return res;
}

static int CmdHF15Restore(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf 15 restore",
                  "This command restore the contents of a dump file (bin/eml/json) onto a ISO-15693 tag",
                  "hf 15 restore\n"
                  "hf 15 restore -*\n"
                  "hf 15 restore -u E011223344556677 -f hf-15-my-dump.bin"
                 );

    void *argtable[6 + 4] = {0};
    uint8_t arglen = arg_add_default(argtable);
    argtable[arglen++] = arg_str0("f", "file", "<fn>", "Specify a filename for dump file");
    argtable[arglen++] = arg_int0("r", "retry", "<dec>", "number of retries (def 3)");
    argtable[arglen++] = arg_lit0("v", "verbose", "verbose output");
    argtable[arglen++] = arg_param_end;
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    uint8_t uid[ISO15693_UID_LENGTH];
    int uidlen = 0;
    CLIGetHexWithReturn(ctx, 1, uid, &uidlen);

    bool unaddressed = arg_get_lit(ctx, 2);
    bool scan = arg_get_lit(ctx, 3);
    bool fast = (arg_get_lit(ctx, 4) == false);
    bool add_option = arg_get_lit(ctx, 5);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 6), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);

    uint32_t retries = arg_get_u32_def(ctx, 7, 3);
    bool verbose = arg_get_lit(ctx, 8);
    CLIParserFree(ctx);

    // sanity checks
    if ((scan + unaddressed + (uidlen > 0)) > 1) {
        PrintAndLogEx(WARNING, "Select only one option /scan/unaddress/uid");
        return PM3_EINVARG;
    }

    if (fnlen == 0) {
        PrintAndLogEx(WARNING, "please provide a filename");
        return PM3_EINVARG;
    }

    // default fallback to scan for tag.
    // overriding unaddress parameter :)
    if (uidlen != ISO15693_UID_LENGTH) {
        scan = true;
    }

    if (unaddressed == false) {
        if (scan) {
            PrintAndLogEx(INFO, "Using scan mode");
            if (getUID(fast, verbose, false, uid) != PM3_SUCCESS) {
                PrintAndLogEx(WARNING, "no tag found");
                return PM3_EINVARG;
            }
        } else {
            reverse_array(uid, ISO15693_UID_LENGTH);
        }
    } else {
        PrintAndLogEx(INFO, "Using unaddressed mode");
    }

    // TI needs OPTION
    if (uid[7] == 0xE0 && uid[6] == 0x07) {
        if (verbose) {
            PrintAndLogEx(INFO, "Overriding OPTION param, writing to TI tag");
        }
        add_option = true;
    }

    // read dump file
    iso15_tag_t *tag = NULL;
    size_t bytes_read = 0;
    // blocksize bytes * 256 blocks.  Should be enough
    int res = pm3_load_dump(filename, (void **)&tag, &bytes_read, sizeof(iso15_tag_t));
    if (res != PM3_SUCCESS) {
        return res;
    }

    if (bytes_read == 0) {
        PrintAndLogEx(FAILED, "Memory image empty.");
        free(tag);
        return PM3_EINVARG;
    }

    // a .bin may hold an older struct revision, upgrade it before the checks below
    res = convert_15_dump_format((uint8_t **)&tag, &bytes_read, verbose);
    if (res != PM3_SUCCESS) {
        free(tag);
        return res;
    }

    if (bytes_read != sizeof(iso15_tag_t)) {
        PrintAndLogEx(FAILED, "Memory image is not matching tag structure.");
        free(tag);
        return PM3_EINVARG;
    }

    if (iso15_tag_size_ok(tag) == false) {
        free(tag);
        return PM3_EINVARG;
    }

    PrintAndLogEx(INFO, "Restoring data blocks");

    uint16_t flags = arg_get_raw_flag(uidlen, unaddressed, scan, add_option);

    uint8_t pm3flags = (ISO15_CONNECT | ISO15_READ_RESPONSE | ISO15_LONG_WAIT | ISO15_NO_DISCONNECT);
    if (fast) {
        pm3flags |= ISO15_HIGH_SPEED;
    }

    int retval = PM3_SUCCESS;
    size_t bytes = 0;
    uint16_t i = 0;
    uint8_t *data = calloc(tag->bytesPerPage, sizeof(uint8_t));
    if (data == NULL) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        free(tag);
        return PM3_EMALLOC;
    }
    uint32_t tried;
    while (bytes < (tag->pagesCount * tag->bytesPerPage)) {

        // copy over the data to the request
        memcpy(data, &tag->data[bytes], tag->bytesPerPage);

        for (tried = 0; tried < retries; tried++) {

            retval = hf_15_write_blk(&pm3flags, flags, uid, fast, i, data, tag->bytesPerPage);

            if (retval == PM3_SUCCESS) {
                PrintAndLogEx(INPLACE, "blk %3d", i);

                if (i == 0) {
                    pm3flags = (ISO15_READ_RESPONSE | ISO15_LONG_WAIT | ISO15_NO_DISCONNECT);
                    if (fast) {
                        pm3flags |= ISO15_HIGH_SPEED;
                    }
                }
                break;
            } else if (retval == PM3_EOUTOFBOUND) {
                // we only get this when we reached end of tag memory
                // break out of retry loop
                break;
            }
        }

        if (tried >= retries) {
            free(data);
            free(tag);
            PrintAndLogEx(NORMAL, "");
            PrintAndLogEx(FAILED, "Too many retries (" _RED_("fail") " )");
            DropField();
            return retval;
        }

        bytes += tag->bytesPerPage;
        i++;
    }

    free(data);
    free(tag);
    DropField();

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(HINT, "Hint: Try `" _YELLOW_("hf 15 dump --ns") "` to verify");
    PrintAndLogEx(INFO, "Done!");
    return PM3_SUCCESS;
}

/**
 * Commandline handling: HF15 CMD CSETUID
 * Set UID for magic Chinese card
 */
static int CmdHF15CSetUID(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf 15 csetuid",
                  "Set UID for magic Chinese card (only works with such cards)\n"
                  "Gen1 and V3 probe their backdoor blocks first and refuse to write if they\n"
                  "read back real data, to avoid corrupting a normal (non-magic) tag.\n"
                  "For magic 'V3' tags this writes the UID configuration only and is repeatable;\n"
                  "run `" _YELLOW_("hf 15 cfinalize") "` afterwards to lock the UID permanently.",
                  "hf 15 csetuid -u E011223344556677       -> use gen1 command\n"
                  "hf 15 csetuid -u E011223344556677 --v2  -> use gen2 command\n"
                  "hf 15 csetuid -u E011223344556677 --v3  -> use gen3 (V3) magic tag"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1("u", "uid", "<hex>", "UID, 8 hex bytes"),
        arg_lit0("2", "v2", "Use gen2 magic command"),
        arg_lit0("3", "v3", "Use gen3 (V3) magic tag (repeatable, needs cfinalize)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    struct {
        uint8_t uid[ISO15693_UID_LENGTH];
    } PACKED payload;

    int uidlen = 0;
    CLIGetHexWithReturn(ctx, 1, payload.uid, &uidlen);
    bool use_v2 = arg_get_lit(ctx, 2);
    bool use_v3 = arg_get_lit(ctx, 3);
    CLIParserFree(ctx);

    if (use_v2 && use_v3) {
        PrintAndLogEx(WARNING, "Select only one of " _YELLOW_("--v2") " / " _YELLOW_("--v3"));
        return PM3_EINVARG;
    }

    if (uidlen != ISO15693_UID_LENGTH) {
        PrintAndLogEx(WARNING, "UID must include 8 hex bytes, got " _RED_("%i"), uidlen);
        return PM3_EINVARG;
    }

    if (payload.uid[0] != 0xE0) {
        PrintAndLogEx(WARNING, "UID must begin with the byte " _YELLOW_("E0"));
        return PM3_EINVARG;
    }

    PrintAndLogEx(DEBUG, "Reverse input UID... " _YELLOW_("%s"), iso15693_sprintUID(NULL, payload.uid));

    PrintAndLogEx(INFO, "Get current tag");

    uint8_t carduid[ISO15693_UID_LENGTH] = {0x00};
    if (getUID(true, true, false, carduid) != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "no tag found");
        return PM3_ESOFT;
    }

    PrintAndLogEx(INFO, "Writing...");

    PacketResponseNG resp;
    clearCommandBuffer();

    uint16_t cmd = CMD_HF_ISO15693_CSETUID;
    if (use_v2) {
        cmd = CMD_HF_ISO15693_CSETUID_V2;
    } else if (use_v3) {
        cmd = CMD_HF_ISO15693_CSETUID_V3;
    }

    SendCommandNG(cmd, (uint8_t *)&payload, sizeof(payload));
    if (WaitForResponseTimeout(cmd, &resp, 2000) == false) {
        PrintAndLogEx(WARNING, "timeout while waiting for reply");
        DropField();
        return PM3_ESOFT;
    }

    // Gen1 and V3 identify the tag and verify the new UID on the device, V2 has neither
    if (use_v2 == false) {

        switch (resp.status) {
            case PM3_SUCCESS:
                break;

            case PM3_ETIMEOUT:
                PrintAndLogEx(FAILED, "no tag found");
                return PM3_ESOFT;

            case PM3_EWRONGANSWER:
                if (use_v3) {
                    PrintAndLogEx(FAILED, "tag is not an un-finalized magic " _YELLOW_("V3") " tag");
                    PrintAndLogEx(HINT, "Hint: Signature in not found. Tag might be finalized or not a V3 tag");
                } else {
                    PrintAndLogEx(FAILED, "tag doesn't look like a blank/magic " _YELLOW_("Gen1") " tag ( " _RED_("fail") " )");
                    PrintAndLogEx(HINT, "Hint: Blocks 0x38/0x39/0x3E/0x3F must be unreadable or blank");
                }
                return PM3_ESOFT;

            default:
                PrintAndLogEx(FAILED, "Setting new UID ( " _RED_("fail") " )");
                PrintAndLogEx(NORMAL, "");
                return PM3_ESOFT;
        }
    }

    PrintAndLogEx(INFO, "Verifying...");

    if (getUID(true, true, false, carduid) != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "no tag found");
        return PM3_ESOFT;
    }

    // reverse cardUID to compare
    uint8_t revuid[ISO15693_UID_LENGTH] = {0};
    reverse_array_copy(carduid, sizeof(carduid), revuid);

    if (memcmp(revuid, payload.uid, ISO15693_UID_LENGTH) == 0) {
        PrintAndLogEx(SUCCESS, "Setting new UID ( " _GREEN_("ok") " )");
        PrintAndLogEx(NORMAL, "");
        return PM3_SUCCESS;;
    }

    PrintAndLogEx(FAILED, "Setting new UID ( " _RED_("fail") " )");
    PrintAndLogEx(NORMAL, "");
    return PM3_ESOFT;
}

/**
 * Commandline handling: HF15 CMD CFINALIZE
 * Finalize a magic 'V3' tag - irreversible
 */
static int CmdHF15CFinalize(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf 15 cfinalize",
                  "Finalize a magic ISO15693 'V3' tag.\n"
                  _RED_("This operation is irreversible.") " It locks the UID for good,\n"
                  "clears the configuration blocks and shifts the block numbering. Set it with\n"
                  "`" _YELLOW_("hf 15 csetuid --v3") "` first, then lock it in with this command.",
                  "hf 15 cfinalize -y"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("y", "yes", "Confirm the irreversible finalize operation"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool confirmed = arg_get_lit(ctx, 1);
    CLIParserFree(ctx);

    if (confirmed == false) {
        PrintAndLogEx(WARNING, _RED_("This operation is irreversible!") " The UID is locked and the blocks move.");
        PrintAndLogEx(WARNING, "Add " _YELLOW_("-y") " to confirm and proceed.");
        return PM3_EINVARG;
    }

    PrintAndLogEx(INFO, "Finalizing...");

    PacketResponseNG resp;
    clearCommandBuffer();
    SendCommandNG(CMD_HF_ISO15693_CFINALIZE_V3, NULL, 0);
    if (WaitForResponseTimeout(CMD_HF_ISO15693_CFINALIZE_V3, &resp, 2000) == false) {
        PrintAndLogEx(WARNING, "timeout while waiting for reply");
        DropField();
        return PM3_ESOFT;
    }

    if (resp.status == PM3_ETIMEOUT) {
        PrintAndLogEx(FAILED, "no tag found");
        return PM3_ESOFT;
    }

    if (resp.status == PM3_EWRONGANSWER) {
        PrintAndLogEx(FAILED, "tag is not an un-finalized magic " _YELLOW_("V3") " tag");
        PrintAndLogEx(HINT, "Hint: Signature not found. Tag might be finalized or not a V3 tag");
        return PM3_ESOFT;
    }

    if (resp.status != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "Finalize ( " _RED_("fail") " )");
        PrintAndLogEx(NORMAL, "");
        return PM3_ESOFT;
    }

    PrintAndLogEx(SUCCESS, "Finalize ( " _GREEN_("ok") " )");
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}

static int CmdHF15SlixEASEnable(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf 15 slixeasenable",
                  "Enable EAS mode on SLIX ISO-15693 tag",
                  "hf 15 slixeasenable -p 0F0F0F0F");

    void *argtable[] = {
        arg_param_begin,
        arg_str0("p", "pwd", "<hex>", "optional password, 4 hex bytes"),
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
                PrintAndLogEx(WARNING, "Password provided was not accepted ( " _RED_("fail") " )");
            } else {
                PrintAndLogEx(WARNING, "Either password is required or EAS mode is locked ( " _RED_("fail") " )");
            }
            break;
        }
        case PM3_SUCCESS: {
            PrintAndLogEx(SUCCESS, "EAS mode is enabled ( " _GREEN_("ok") " ) ");
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
        arg_str0("p", "pwd", "<hex>", "optional password, 4 hex bytes"),
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
        PrintAndLogEx(INFO, "Trying to disable EAS mode without using a password");
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
                PrintAndLogEx(WARNING, "Password provided was not accepted ( " _RED_("fail") " )");
            } else {
                PrintAndLogEx(WARNING, "Either password is required or EAS mode is locked ( " _RED_("fail") " )");
            }
            break;
        }
        case PM3_SUCCESS: {
            PrintAndLogEx(SUCCESS, "EAS mode is disabled ( " _GREEN_("ok") " ) ");
            break;
        }
    }
    return resp.status;
}

static int CmdHF15SlixDisable(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf 15 slixprivacydisable",
                  "Disable privacy mode on SLIX ISO-15693 tag",
                  "hf 15 slixprivacydisable -p 0F0F0F0F");

    void *argtable[] = {
        arg_param_begin,
        arg_str1("p", "pwd", "<hex>", "password, 4 hex bytes"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    struct {
        uint8_t pwd[4];
    } PACKED payload;
    int pwdlen = 0;
    CLIGetHexWithReturn(ctx, 1, payload.pwd, &pwdlen);
    CLIParserFree(ctx);

    if (pwdlen != 4) {
        PrintAndLogEx(WARNING, "password must be 4 hex bytes");
        return PM3_ESOFT;
    }

    PrintAndLogEx(INFO, "Trying to disable privacy mode using password " _GREEN_("%s")
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
            PrintAndLogEx(WARNING, "Password was not accepted ( " _RED_("fail") " )");
            break;
        }
        case PM3_SUCCESS: {
            PrintAndLogEx(SUCCESS, "Privacy mode is disabled ( " _GREEN_("ok") " ) ");
            break;
        }
    }
    return resp.status;
}

static int CmdHF15SlixEnable(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf 15 slixprivacyenable",
                  "Enable privacy mode on SLIX ISO-15693 tag",
                  "hf 15 slixprivacyenable -p 0F0F0F0F");

    void *argtable[] = {
        arg_param_begin,
        arg_str1("p", "pwd", "<hex>", "password, 4 hex bytes"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    struct {
        uint8_t pwd[4];
    } PACKED payload;
    int pwdlen = 0;
    CLIGetHexWithReturn(ctx, 1, payload.pwd, &pwdlen);
    CLIParserFree(ctx);

    if (pwdlen != 4) {
        PrintAndLogEx(WARNING, "password must be 4 hex bytes");
        return PM3_ESOFT;
    }

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
            PrintAndLogEx(WARNING, "Password was not accepted ( " _RED_("fail") " )");
            break;
        }
        case PM3_SUCCESS: {
            PrintAndLogEx(SUCCESS, "Privacy mode is enabled ( " _GREEN_("ok") " ) ");
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
        arg_str0("o", "old", "<hex>", "old password (if present), 4 hex bytes"),
        arg_str1("n", "new", "<hex>", "new password, 4 hex bytes"),
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

    PrintAndLogEx(INFO, "Trying to write " _YELLOW_("%s") " as " _YELLOW_("%s") " password", sprint_hex_inrow(payload.new_pwd, sizeof(payload.new_pwd)), value);

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
            PrintAndLogEx(WARNING, "Password was not accepted ( " _RED_("fail") " )");
            break;
        }
        case PM3_SUCCESS: {
            PrintAndLogEx(SUCCESS, "Password written ( " _GREEN_("ok") " ) ");
            break;
        }
    }
    return resp.status;
}

static int CmdHF15SlixProtectPage(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf 15 slixprotectpage",
                  "Defines protection pointer address of user mem and access cond. for pages",
                  "hf 15 slixprotectpage -w deadbeef -p 3 -h 3");

    void *argtable[] = {
        arg_param_begin,
        arg_str0("r", "readpw", "<hex>", "read password, 4 hex bytes"),
        arg_str0("w", "writepw", "<hex>", "write password, 4 hex bytes"),
        arg_int0("p", "ptr", "<dec>", "protection pointer page (0-78), if 0 entire user mem"),
        arg_int1("l", "lo", "<dec>", "page protection flags of lo page (0-None, 1-ReadPR, 2-WritePR)"),
        arg_int1("i", "hi", "<dec>", "page protection flags of hi page (0-None, 1-ReadPR, 2-WritePR)"),
        arg_param_end
    };

    CLIExecWithReturn(ctx, Cmd, argtable, false);

    struct p {
        uint8_t read_pwd[4];
        uint8_t write_pwd[4];
        uint8_t divide_ptr;
        uint8_t prot_status;
    } PACKED payload = {0};
    int pwdlen = 0;

    CLIGetHexWithReturn(ctx, 1, payload.read_pwd, &pwdlen);

    if (pwdlen > 0 && pwdlen != 4) {
        PrintAndLogEx(WARNING, "read password must be 4 hex bytes if provided");
        CLIParserFree(ctx);
        return PM3_ESOFT;
    }

    CLIGetHexWithReturn(ctx, 2, payload.write_pwd, &pwdlen);

    if (pwdlen > 0 && pwdlen != 4) {
        PrintAndLogEx(WARNING, "write password must be 4 hex bytes if provided");
        CLIParserFree(ctx);
        return PM3_ESOFT;
    }

    payload.divide_ptr = (uint8_t)arg_get_int_def(ctx, 3, 0);
    if (payload.divide_ptr > 78) {
        PrintAndLogEx(WARNING, "protection pointer page is invalid, got " _YELLOW_("%d") " expected <= 78", payload.divide_ptr);
        CLIParserFree(ctx);
        return PM3_ESOFT;
    }

    int lo = arg_get_int_def(ctx, 4, 0);
    int hi = arg_get_int_def(ctx, 5, 0);
    CLIParserFree(ctx);

    if (lo > 3 || hi > 3) {
        PrintAndLogEx(WARNING, "page protection flags must be between 0 and 3");
        return PM3_ESOFT;
    }
    payload.prot_status = (uint8_t)(hi << 4) | (uint8_t)lo;

    PrintAndLogEx(INFO, "Trying to set page protection pointer to " _YELLOW_("%d"), payload.divide_ptr);
    PrintAndLogEx(INFO, _YELLOW_("LO") " page access %s%s"
                  , (payload.prot_status & 0x01) ? _RED_("r") : _GREEN_("r")
                  , (payload.prot_status & 0x02) ? _RED_("w") : _GREEN_("w")
                 );
    PrintAndLogEx(INFO, _YELLOW_("HI") " page access %s%s"
                  , (payload.prot_status & 0x10) ? _RED_("r") : _GREEN_("r")
                  , (payload.prot_status & 0x20) ? _RED_("w") : _GREEN_("w"));

    PacketResponseNG resp;
    clearCommandBuffer();
    SendCommandNG(CMD_HF_ISO15693_SLIX_PROTECT_PAGE, (uint8_t *)&payload, sizeof(payload));
    if (WaitForResponseTimeout(CMD_HF_ISO15693_SLIX_PROTECT_PAGE, &resp, 2000) == false) {
        PrintAndLogEx(WARNING, "Timeout while waiting for reply");
        DropField();
        return PM3_ESOFT;
    }

    switch (resp.status) {
        case PM3_ETIMEOUT: {
            PrintAndLogEx(WARNING, "No tag found");
            break;
        }
        case PM3_EWRONGANSWER: {
            PrintAndLogEx(WARNING, "Protection flags were not accepted, locked? ( " _RED_("fail") " )");
            break;
        }
        case PM3_SUCCESS: {
            PrintAndLogEx(SUCCESS, "Page protection written ( " _GREEN_("ok") " ) ");
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
        arg_str1("p", "pwd", "<hex>", "EAS/AFI password, 4 hex bytes"),
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
        PrintAndLogEx(WARNING, "Password must be 4 hex bytes");
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
        PrintAndLogEx(WARNING, "Timeout while waiting for reply");
        DropField();
        return PM3_ESOFT;
    }

    switch (resp.status) {
        case PM3_ETIMEOUT: {
            PrintAndLogEx(WARNING, "No tag found");
            break;
        }
        case PM3_EWRONGANSWER: {
            PrintAndLogEx(WARNING, "Enabling AFI password protection ( " _RED_("fail") " )");
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
        arg_str1("p", "pwd", "<hex>", "EAS/AFI password, 4 hex bytes"),
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
            PrintAndLogEx(WARNING, "Enabling EAS password protection ( " _RED_("fail") " )");
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
                  "hf 15 view -f hf-15-1122334455667788-dump.bin\n"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_str1("f", "file", "<fn>",  "Specify a filename for dump file"),
        arg_lit0("z", "dense", "dense dump output style"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE];
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);
    bool dense_output = (g_session.dense_output || arg_get_lit(ctx, 2));
    CLIParserFree(ctx);

    iso15_tag_t *tag = NULL;
    size_t bytes_read = 0;
    int res = pm3_load_dump(filename, (void **)&tag, &bytes_read, sizeof(iso15_tag_t));
    if (res != PM3_SUCCESS) {
        return res;
    }

    if (bytes_read == 0) {
        PrintAndLogEx(FAILED, "Memory image empty.");
        free(tag);
        return PM3_EINVARG;
    }

    // a .bin may hold an older struct revision, upgrade it before the checks below
    res = convert_15_dump_format((uint8_t **)&tag, &bytes_read, true);
    if (res != PM3_SUCCESS) {
        free(tag);
        return res;
    }

    if (bytes_read != sizeof(iso15_tag_t)) {
        PrintAndLogEx(FAILED, "Memory image is not matching tag structure.");
        free(tag);
        return PM3_EINVARG;
    }

    if (iso15_tag_size_ok(tag) == false) {
        free(tag);
        return PM3_EINVARG;
    }

    print_tag_15693(tag, dense_output, true);

    free(tag);
    return PM3_SUCCESS;
}

static int CmdHF15Wipe(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf 15 wipe",
                  "Wipe a ISO-15693 tag by filled memory with zeros",
                  "hf 15 wipe\n"
                 );
    void *argtable[6 + 3] = {0};
    uint8_t arglen = arg_add_default(argtable);
    argtable[arglen++] = arg_int0(NULL, "bs", "<dec>", "block size (def 4)");
    argtable[arglen++] = arg_lit0("v", "verbose", "verbose output");
    argtable[arglen++] = arg_param_end;
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    uint8_t uid[ISO15693_UID_LENGTH];
    int uidlen = 0;
    CLIGetHexWithReturn(ctx, 1, uid, &uidlen);
    bool uid_set = (uidlen == ISO15693_UID_LENGTH) ? true : false;

    bool unaddressed = arg_get_lit(ctx, 2);
    bool scan = (arg_get_lit(ctx, 3) || (!uid_set && !unaddressed)) ? true : false; // Default fallback to scan for tag. Overriding unaddressed parameter.
    bool fast = (arg_get_lit(ctx, 4) == false);
    bool add_option = arg_get_lit(ctx, 5);

    int blocksize = arg_get_int_def(ctx, 6, 4);
    bool verbose = arg_get_lit(ctx, 7);
    CLIParserFree(ctx);

    // sanity checks
    if ((scan + unaddressed + uid_set) > 1) {
        PrintAndLogEx(WARNING, "Select only one option /scan/unaddress/uid");
        return PM3_EINVARG;
    }

    if (blocksize < 4) {
        PrintAndLogEx(WARNING, "Blocksize too small, using default 4 bytes");
        blocksize = 4;
    }

    // default fallback to scan for tag.
    // overriding unaddress parameter :)
    if (unaddressed == false) {
        if (scan) {
            PrintAndLogEx(INFO, "Using scan mode");
            if (getUID(fast, verbose, false, uid) != PM3_SUCCESS) {
                PrintAndLogEx(WARNING, "no tag found");
                return PM3_EINVARG;
            }
        } else {
            reverse_array(uid, ISO15693_UID_LENGTH);
        }
    } else {
        PrintAndLogEx(INFO, "Using unaddressed mode");
    }

    // TI needs OPTION
    if (uid[7] == 0xE0 && uid[6] == 0x07) {
        if (verbose) {
            PrintAndLogEx(INFO, "Overriding OPTION param, writing to TI tag");
        }
        add_option = true;
    }

    PrintAndLogEx(INFO, "Wiping tag...");

    uint16_t flags = arg_get_raw_flag(uidlen, unaddressed, scan, add_option);
    uint8_t empty[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    uint8_t pm3flags = (ISO15_CONNECT | ISO15_READ_RESPONSE | ISO15_LONG_WAIT | ISO15_NO_DISCONNECT);
    if (fast) {
        pm3flags |= ISO15_HIGH_SPEED;
    }

    for (uint16_t i = 0; i < 0x100; i++) {

        PrintAndLogEx(INPLACE, "blk %3d", i);

        int res = hf_15_write_blk(&pm3flags, flags, ((unaddressed) ? NULL : uid), fast, i, empty, blocksize);
        if (res == PM3_SUCCESS) {
            if (i == 0) {
                pm3flags = (ISO15_READ_RESPONSE | ISO15_LONG_WAIT | ISO15_NO_DISCONNECT);
                if (fast) {
                    pm3flags |= ISO15_HIGH_SPEED;
                }
            }
        } else {
            break;
        }
    }

    DropField();
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "Done!");
    return PM3_SUCCESS;
}

// NTAG 5 link (NTP5332) I2C master + TI TMP112/TMP117/TMP119 sensor implants
// e.g. VivoKey Thermo, Temptress.
// Refs: NXP NTP53x2 datasheet rev 3.3, AN12365, AN12368, TI TMP112/TMP117/TMP119 datasheets.
// Sequence cross-checked with VivoKey ntag5sensor and vkthermo-flipper.
#define NTAG5_CMD_READ_CONFIG       0xC0
#define NTAG5_CMD_WRITE_CONFIG      0xC1
#define NTAG5_CMD_READ_SRAM         0xD2
#define NTAG5_CMD_WRITE_I2C         0xD4
#define NTAG5_CMD_READ_I2C          0xD5

// session registers, NFC block address
#define NTAG5_REG_STATUS            0xA0
#define NTAG5_REG_CONFIG            0xA1
#define NTAG5_REG_EH_CONFIG         0xA7
#define NTAG5_REG_I2C_M_STATUS      0xAD

#define NTAG5_STATUS1_VCC_BOOT_OK   0x80
#define NTAG5_CONFIG1_USE_CASE_MASK 0x30
#define NTAG5_CONFIG1_I2C_MASTER    0x10
#define NTAG5_CONFIG1_SRAM_ENABLED  0x02
#define NTAG5_EH_LOAD_OK            0x80
// EH_TRIGGER must be set on every write
#define NTAG5_EH_TRIGGER            0x08
#define NTAG5_EH_ENABLE             0x01
#define NTAG5_I2C_M_WDT_EXPIRED     0x08
#define NTAG5_I2C_M_TRANS_MASK      0x06
#define NTAG5_I2C_M_ADDR_NAK        0x02
#define NTAG5_I2C_M_DATA_NAK        0x04
#define NTAG5_I2C_M_SUCCESS         0x06
#define NTAG5_I2C_M_BUSY            0x01

#define TMP_REG_TEMP                0x00
#define TMP_REG_CONFIG              0x01
#define TMP_REG_DEVICE_ID           0x0F
#define TMP11X_DID                  0x0117
#define TMP119_REV                  0x2
#define TMP112_CFG_OS               0x8000
#define TMP112_CFG_SD               0x0100
#define TMP117_CFG_DATA_READY       0x2000
#define TMP117_CFG_MOD_ONESHOT      0x0C00
// CONV, AVG, T/nA, POL, DR/Alert
#define TMP117_CFG_KEEP             0x03FC

#define IMPLANT_I2C_ADDR_FIRST      0x48
#define IMPLANT_I2C_ADDR_LAST       0x4B
#define IMPLANT_MAX_SENSORS         (IMPLANT_I2C_ADDR_LAST - IMPLANT_I2C_ADDR_FIRST + 1)

typedef enum {
    TMP_SENSOR_AUTO = 0,
    TMP_SENSOR_TMP112,
    TMP_SENSOR_TMP117,
    TMP_SENSOR_TMP119,
} tmp_sensor_t;

typedef struct {
    uint8_t uid[ISO15693_UID_LENGTH];
    bool field_on;
    bool verbose;
} ntag5_ctx_t;

typedef struct {
    uint8_t addr;
    tmp_sensor_t type;
} tmp_dev_t;

static const char *tmp_sensor_str(tmp_sensor_t t) {
    switch (t) {
        case TMP_SENSOR_TMP112:
            return "TMP112";
        case TMP_SENSOR_TMP117:
            return "TMP117";
        case TMP_SENSOR_TMP119:
            return "TMP119";
        case TMP_SENSOR_AUTO:
        default:
            return "unknown";
    }
}

// TMP117 and TMP119 share DID 117h, TMP119 has Rev 2h. Anything else is taken as TMP112
static tmp_sensor_t tmp_sensor_from_id(uint16_t id) {
    if ((id & 0x0FFF) != TMP11X_DID) {
        return TMP_SENSOR_TMP112;
    }
    return ((id >> 12) == TMP119_REV) ? TMP_SENSOR_TMP119 : TMP_SENSOR_TMP117;
}

static double tmp_raw_to_celsius(tmp_sensor_t t, uint16_t raw) {
    if (t == TMP_SENSOR_TMP112) {
        // 0.0625 C/LSB, left justified. D0 set = extended mode, 13 bit
        if (raw & 0x0001) {
            return (int16_t)(raw & 0xFFF8) / 128.0;
        }
        return (int16_t)(raw & 0xFFF0) / 256.0;
    }
    // 7.8125 mC/LSB
    return (int16_t)raw / 128.0;
}

static double celsius_to_fahrenheit(double c) {
    return (c * 9.0 / 5.0) + 32.0;
}

static bool implant_dbl_eq(double a, double b) {
    double d = a - b;
    return (d < 1e-9 && d > -1e-9);
}

// uid is LSB first. NTAG 5 family, see uidmapping
static bool ntag5_uid_match(const uint8_t *uid) {
    return (uid[7] == 0xE0 && uid[6] == 0x04 && uid[5] == 0x01 && ((uid[4] & 0x18) == 0x18));
}

// Addressed NXP custom command, field kept on between calls.
// out gets the payload without flags and CRC.
static int ntag5_cmd(ntag5_ctx_t *c, uint8_t cmd, const uint8_t *param, uint8_t plen, bool write_alike,
                     uint8_t *out, uint16_t outmax, uint16_t *outlen) {

    if (outlen) {
        *outlen = 0;
    }

    uint16_t len = 3 + ISO15693_UID_LENGTH + plen + 2;
    iso15_raw_cmd_t *packet = (iso15_raw_cmd_t *)calloc(1, sizeof(iso15_raw_cmd_t) + len);
    if (packet == NULL) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        return PM3_EMALLOC;
    }

    packet->raw[packet->rawlen++] = (ISO15_REQ_SUBCARRIER_SINGLE | ISO15_REQ_DATARATE_HIGH | ISO15_REQ_NONINVENTORY | ISO15_REQ_ADDRESS);
    packet->raw[packet->rawlen++] = cmd;
    packet->raw[packet->rawlen++] = 0x04; // IC manufacturer code
    memcpy(packet->raw + packet->rawlen, c->uid, ISO15693_UID_LENGTH);
    packet->rawlen += ISO15693_UID_LENGTH;
    if (plen) {
        memcpy(packet->raw + packet->rawlen, param, plen);
        packet->rawlen += plen;
    }
    AddCrc15(packet->raw, packet->rawlen);
    packet->rawlen += 2;

    // EH needs the field to stay up, only power it up once
    packet->flags = (ISO15_HIGH_SPEED | ISO15_READ_RESPONSE | ISO15_NO_DISCONNECT);
    if (c->field_on == false) {
        packet->flags |= ISO15_CONNECT;
        c->field_on = true;
    }
    if (write_alike) {
        packet->flags |= ISO15_LONG_WAIT;
    }

    if (c->verbose) {
        PrintAndLogEx(INFO, "TX: %s", sprint_hex_inrow(packet->raw, packet->rawlen));
    }

    clearCommandBuffer();
    SendCommandNG(CMD_HF_ISO15693_COMMAND, (uint8_t *)packet, ISO15_RAW_LEN(packet->rawlen));
    free(packet);

    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_HF_ISO15693_COMMAND, &resp, 2000) == false) {
        PrintAndLogEx(DEBUG, "iso15693 timeout");
        return PM3_ETIMEOUT;
    }

    if (resp.status == PM3_ETEAROFF) {
        return resp.status;
    }

    if (resp.length < 3) {
        if (c->verbose) {
            PrintAndLogEx(INFO, "RX: no answer");
        }
        return PM3_ETIMEOUT;
    }

    uint8_t *d = resp.data.asBytes;
    if (c->verbose) {
        PrintAndLogEx(INFO, "RX: %s", sprint_hex_inrow(d, resp.length));
    }

    if (check_crc(CRC_15693, d, resp.length) == false) {
        PrintAndLogEx(DEBUG, "crc fail");
        return PM3_ECRC;
    }

    if ((d[0] & ISO15_RES_ERROR) == ISO15_RES_ERROR) {
        PrintAndLogEx((c->verbose) ? INFO : DEBUG, "cmd %02X, tag error %02X: %s", cmd, d[1], TagErrorStr(d[1]));
        return PM3_EWRONGANSWER;
    }

    if (out && outlen) {
        *outlen = MIN(resp.length - 3, outmax);
        memcpy(out, d + 1, *outlen);
    }
    return PM3_SUCCESS;
}

// session register, one 4 byte block
static int ntag5_read_reg(ntag5_ctx_t *c, uint8_t addr, uint8_t *blk) {
    uint8_t param[] = { addr, 0x00 };
    uint16_t n = 0;
    int res = ntag5_cmd(c, NTAG5_CMD_READ_CONFIG, param, sizeof(param), false, blk, 4, &n);
    if (res == PM3_SUCCESS && n < 4) {
        return PM3_ELENGTH;
    }
    return res;
}

static int ntag5_write_reg(ntag5_ctx_t *c, uint8_t addr, const uint8_t *blk) {
    uint8_t param[5] = { addr };
    memcpy(param + 1, blk, 4);
    int res = ntag5_cmd(c, NTAG5_CMD_WRITE_CONFIG, param, sizeof(param), true, NULL, 0, NULL);
    // reply may be missed while VOUT ramps, caller verifies by reading back
    if (res == PM3_ETIMEOUT) {
        PrintAndLogEx(DEBUG, "no reply to WRITE CONFIG %02X", addr);
        return PM3_SUCCESS;
    }
    return res;
}

// Energy harvesting via session register, AN12365 4.1
static int ntag5_power_up(ntag5_ctx_t *c, uint32_t timeout_ms) {

    uint8_t st[4] = {0};
    uint64_t t0 = msclock();
    int res;
    do {
        res = ntag5_read_reg(c, NTAG5_REG_STATUS, st);
        if (res == PM3_ETEAROFF) {
            return res;
        }
        if (res != PM3_SUCCESS) {
            msleep(20);
        }
    } while (res != PM3_SUCCESS && (msclock() - t0) < timeout_ms);

    if (res != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "no answer from tag");
        return res;
    }

    if (st[1] & NTAG5_STATUS1_VCC_BOOT_OK) {
        PrintAndLogEx(INFO, "VCC already up, energy harvesting active");
        return PM3_SUCCESS;
    }

    uint8_t eh[4] = { NTAG5_EH_TRIGGER, 0x00, 0x00, 0x00 };
    res = ntag5_write_reg(c, NTAG5_REG_EH_CONFIG, eh);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "failed to trigger energy harvesting");
        return res;
    }

    PrintAndLogEx(INPLACE, "Waiting for energy harvesting...");
    bool load_ok = false;
    while ((msclock() - t0) < timeout_ms) {

        if (kbd_enter_pressed()) {
            PrintAndLogEx(NORMAL, "");
            PrintAndLogEx(WARNING, "aborted via keyboard");
            return PM3_EOPABORTED;
        }

        if (ntag5_read_reg(c, NTAG5_REG_EH_CONFIG, eh) == PM3_SUCCESS && (eh[0] & NTAG5_EH_LOAD_OK)) {
            load_ok = true;
            break;
        }
        msleep(50);
    }
    PrintAndLogEx(NORMAL, "");

    if (load_ok == false) {
        PrintAndLogEx(FAILED, "energy harvesting not ready after %u ms, field too weak? Try to reposition or increase `--wait`", timeout_ms);
        return PM3_ETIMEOUT;
    }

    eh[0] = (NTAG5_EH_TRIGGER | NTAG5_EH_ENABLE);
    res = ntag5_write_reg(c, NTAG5_REG_EH_CONFIG, eh);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "failed to enable energy harvesting");
        return res;
    }

    // VCC ramp up is write alike, max 20 ms
    uint64_t t1 = msclock();
    while ((msclock() - t1) < 100) {
        msleep(10);
        if (ntag5_read_reg(c, NTAG5_REG_STATUS, st) == PM3_SUCCESS && (st[1] & NTAG5_STATUS1_VCC_BOOT_OK)) {
            PrintAndLogEx(INFO, "Energy harvesting ( " _GREEN_("ok") " ) after %u ms", (uint32_t)(msclock() - t0));
            return PM3_SUCCESS;
        }
    }

    PrintAndLogEx(WARNING, "VCC_BOOT_OK not set, sensor may be unpowered. Trying anyway");
    return PM3_SUCCESS;
}

static const char *ntag5_i2c_status_str(uint8_t st) {
    if (st & NTAG5_I2C_M_BUSY) {
        return "bus busy";
    }
    if (st & NTAG5_I2C_M_WDT_EXPIRED) {
        return "watchdog expired";
    }
    switch (st & NTAG5_I2C_M_TRANS_MASK) {
        case NTAG5_I2C_M_ADDR_NAK:
            return "address NAK";
        case NTAG5_I2C_M_DATA_NAK:
            return "data NAK";
        case NTAG5_I2C_M_SUCCESS:
            return "ok";
        default:
            return "no transaction";
    }
}

// Poll I2C master status until idle.
// PM3_ENODATA address NAK, PM3_EWRONGANSWER data NAK, PM3_ETIMEOUT busy / WDT
static int ntag5_i2c_wait(ntag5_ctx_t *c, bool check_result) {
    uint8_t st[4] = {0};
    int res = PM3_ETIMEOUT;
    for (uint8_t i = 0; i < 20; i++) {
        res = ntag5_read_reg(c, NTAG5_REG_I2C_M_STATUS, st);
        if (res == PM3_SUCCESS && (st[0] & NTAG5_I2C_M_BUSY) == 0) {
            break;
        }
        res = PM3_ETIMEOUT;
        msleep(5);
    }

    if (res != PM3_SUCCESS) {
        PrintAndLogEx(DEBUG, "I2C master busy / no status");
        return res;
    }

    if (check_result == false) {
        return PM3_SUCCESS;
    }

    PrintAndLogEx(DEBUG, "I2C status %02X ( %s )", st[0], ntag5_i2c_status_str(st[0]));

    if (st[0] & NTAG5_I2C_M_WDT_EXPIRED) {
        return PM3_ETIMEOUT;
    }

    switch (st[0] & NTAG5_I2C_M_TRANS_MASK) {
        case NTAG5_I2C_M_SUCCESS:
            return PM3_SUCCESS;
        case NTAG5_I2C_M_ADDR_NAK:
            return PM3_ENODATA;
        default:
            return PM3_EWRONGANSWER;
    }
}

static int ntag5_i2c_write(ntag5_ctx_t *c, uint8_t addr, const uint8_t *data, uint8_t len) {
    if (len == 0 || len > 8) {
        return PM3_EINVARG;
    }

    int res = ntag5_i2c_wait(c, false);
    if (res != PM3_SUCCESS) {
        return res;
    }

    // param: bit7 = 0 generates STOP, bits 6..0 slave address
    uint8_t param[2 + 8] = { addr & 0x7F, len - 1 };
    memcpy(param + 2, data, len);
    res = ntag5_cmd(c, NTAG5_CMD_WRITE_I2C, param, 2 + len, false, NULL, 0, NULL);
    if (res != PM3_SUCCESS) {
        return res;
    }
    return ntag5_i2c_wait(c, true);
}

static int ntag5_i2c_read(ntag5_ctx_t *c, uint8_t addr, uint8_t *out, uint8_t len) {
    if (len == 0 || len > 8) {
        return PM3_EINVARG;
    }

    uint8_t param[] = { addr & 0x7F, len - 1 };
    int res = ntag5_cmd(c, NTAG5_CMD_READ_I2C, param, sizeof(param), false, NULL, 0, NULL);
    if (res != PM3_SUCCESS) {
        return res;
    }

    res = ntag5_i2c_wait(c, true);
    if (res != PM3_SUCCESS) {
        return res;
    }

    // result lands at SRAM block 0
    uint8_t sram_param[] = { 0x00, ((len + 3) / 4) - 1 };
    uint8_t buf[8] = {0};
    uint16_t n = 0;
    res = ntag5_cmd(c, NTAG5_CMD_READ_SRAM, sram_param, sizeof(sram_param), false, buf, sizeof(buf), &n);
    if (res != PM3_SUCCESS) {
        return res;
    }
    if (n < len) {
        return PM3_ELENGTH;
    }
    memcpy(out, buf, len);
    return PM3_SUCCESS;
}

static int tmp_read_reg(ntag5_ctx_t *c, uint8_t addr, uint8_t reg, uint16_t *val) {
    int res = ntag5_i2c_write(c, addr, &reg, 1);
    if (res != PM3_SUCCESS) {
        return res;
    }
    uint8_t d[2] = {0};
    res = ntag5_i2c_read(c, addr, d, sizeof(d));
    if (res != PM3_SUCCESS) {
        return res;
    }
    *val = MemBeToUint2byte(d);
    return PM3_SUCCESS;
}

static int tmp_write_reg(ntag5_ctx_t *c, uint8_t addr, uint8_t reg, uint16_t val) {
    uint8_t d[3] = { reg, (val >> 8) & 0xFF, val & 0xFF };
    return ntag5_i2c_write(c, addr, d, sizeof(d));
}

// PM3_ENODATA when nothing acks the address
static int tmp_identify(ntag5_ctx_t *c, uint8_t addr, tmp_sensor_t *t) {
    uint16_t id = 0;
    int res = tmp_read_reg(c, addr, TMP_REG_DEVICE_ID, &id);
    if (res == PM3_SUCCESS) {
        *t = tmp_sensor_from_id(id);
        PrintAndLogEx((c->verbose) ? INFO : DEBUG, "0x%02X device id %04X", addr, id);
        return PM3_SUCCESS;
    }

    // TMP112 has no register 0Fh and may NAK the pointer
    if (res == PM3_EWRONGANSWER) {
        *t = TMP_SENSOR_TMP112;
        return PM3_SUCCESS;
    }
    return res;
}

// one-shot conversion, then read the result register
static int tmp_measure(ntag5_ctx_t *c, uint8_t addr, tmp_sensor_t t, uint16_t *raw) {

    uint16_t cfg = 0;
    int res = tmp_read_reg(c, addr, TMP_REG_CONFIG, &cfg);
    if (res != PM3_SUCCESS) {
        return res;
    }

    uint16_t ready_mask;
    uint32_t timeout_ms;
    if (t == TMP_SENSOR_TMP112) {
        // one-shot only starts from shutdown
        if ((cfg & TMP112_CFG_SD) == 0) {
            cfg = (cfg | TMP112_CFG_SD) & ~TMP112_CFG_OS;
            res = tmp_write_reg(c, addr, TMP_REG_CONFIG, cfg);
            if (res != PM3_SUCCESS) {
                return res;
            }
            // let a running conversion finish
            msleep(40);
        }
        res = tmp_write_reg(c, addr, TMP_REG_CONFIG, cfg | TMP112_CFG_SD | TMP112_CFG_OS);
        // OS reads 0 while converting, 1 when done
        ready_mask = TMP112_CFG_OS;
        timeout_ms = 200;
    } else {
        res = tmp_write_reg(c, addr, TMP_REG_CONFIG, (cfg & TMP117_CFG_KEEP) | TMP117_CFG_MOD_ONESHOT);
        ready_mask = TMP117_CFG_DATA_READY;
        // 64 averages take ~1 s
        timeout_ms = 1500;
    }

    if (res != PM3_SUCCESS) {
        return res;
    }

    uint64_t t0 = msclock();
    bool ready = false;
    while ((msclock() - t0) < timeout_ms) {
        msleep(10);
        res = tmp_read_reg(c, addr, TMP_REG_CONFIG, &cfg);
        if (res != PM3_SUCCESS) {
            return res;
        }
        if (cfg & ready_mask) {
            ready = true;
            break;
        }
    }

    if (ready == false) {
        PrintAndLogEx(WARNING, "0x%02X conversion not ready ( config %04X ), reading anyway", addr, cfg);
    }

    return tmp_read_reg(c, addr, TMP_REG_TEMP, raw);
}

static void ntag5_print_i2c_error(uint8_t addr, int res) {
    switch (res) {
        case PM3_ENODATA:
            PrintAndLogEx(FAILED, "I2C 0x%02X address " _RED_("NAK") ", no sensor", addr);
            break;
        case PM3_EWRONGANSWER:
            PrintAndLogEx(FAILED, "I2C 0x%02X data " _RED_("NAK") " or tag error", addr);
            break;
        case PM3_ETIMEOUT:
            PrintAndLogEx(FAILED, "I2C 0x%02X timeout, bus busy or tag lost", addr);
            break;
        default:
            PrintAndLogEx(FAILED, "I2C 0x%02X failed ( %d )", addr, res);
            break;
    }
}

static int implant_selftest(void) {

    PrintAndLogEx(INFO, "======== " _CYAN_("self test") " ===========================================");

    // vectors from the TI datasheet temperature data format tables
    const struct {
        tmp_sensor_t t;
        uint16_t raw;
        double c;
    } conv[] = {
        { TMP_SENSOR_TMP117, 0x7FFF, 255.9921875 },
        { TMP_SENSOR_TMP117, 0x0C80, 25.0 },
        { TMP_SENSOR_TMP117, 0x0001, 0.0078125 },
        { TMP_SENSOR_TMP117, 0x0000, 0.0 },
        { TMP_SENSOR_TMP117, 0xFFFF, -0.0078125 },
        { TMP_SENSOR_TMP117, 0xF380, -25.0 },
        { TMP_SENSOR_TMP119, 0x8000, -256.0 },
        { TMP_SENSOR_TMP112, 0x7FF0, 127.9375 },
        { TMP_SENSOR_TMP112, 0x3200, 50.0 },
        { TMP_SENSOR_TMP112, 0x0010, 0.0625 },
        { TMP_SENSOR_TMP112, 0xFFF0, -0.0625 },
        { TMP_SENSOR_TMP112, 0xE700, -25.0 },
        { TMP_SENSOR_TMP112, 0xC900, -55.0 },
        { TMP_SENSOR_TMP112, 0x4B01, 150.0 },
        { TMP_SENSOR_TMP112, 0xFFF9, -0.0625 },
    };

    const struct {
        uint16_t id;
        tmp_sensor_t t;
    } ids[] = {
        { 0x0117, TMP_SENSOR_TMP117 },
        { 0x1117, TMP_SENSOR_TMP117 },
        { 0x2117, TMP_SENSOR_TMP119 },
        { 0x5000, TMP_SENSOR_TMP112 },
    };

    const struct {
        uint8_t uid[ISO15693_UID_LENGTH];
        bool match;
    } uids[] = {
        { { 0x01, 0x02, 0x03, 0x04, 0x18, 0x01, 0x04, 0xE0 }, true },
        { { 0x01, 0x02, 0x03, 0x04, 0x08, 0x01, 0x04, 0xE0 }, false },
        { { 0x01, 0x02, 0x03, 0x04, 0x18, 0x01, 0x02, 0xE0 }, false },
    };

    bool all_ok = true;

    for (size_t i = 0; i < ARRAYLEN(conv); i++) {
        double c = tmp_raw_to_celsius(conv[i].t, conv[i].raw);
        bool ok = implant_dbl_eq(c, conv[i].c);
        all_ok &= ok;
        PrintAndLogEx(INFO, "%s %04X -> %11.7f C ( %s )", tmp_sensor_str(conv[i].t), conv[i].raw, c, ok ? _GREEN_("ok") : _RED_("fail"));
    }

    for (size_t i = 0; i < ARRAYLEN(ids); i++) {
        tmp_sensor_t t = tmp_sensor_from_id(ids[i].id);
        bool ok = (t == ids[i].t);
        all_ok &= ok;
        PrintAndLogEx(INFO, "device id %04X -> %s ( %s )", ids[i].id, tmp_sensor_str(t), ok ? _GREEN_("ok") : _RED_("fail"));
    }

    for (size_t i = 0; i < ARRAYLEN(uids); i++) {
        bool ok = (ntag5_uid_match(uids[i].uid) == uids[i].match);
        all_ok &= ok;
        PrintAndLogEx(INFO, "uid %s NTAG 5 %s ( %s )", iso15693_sprintUID(NULL, (uint8_t *)uids[i].uid), uids[i].match ? "yes" : "no", ok ? _GREEN_("ok") : _RED_("fail"));
    }

    bool ok = implant_dbl_eq(celsius_to_fahrenheit(37.0), 98.6) && implant_dbl_eq(celsius_to_fahrenheit(-40.0), -40.0);
    all_ok &= ok;
    PrintAndLogEx(INFO, "fahrenheit ( %s )", ok ? _GREEN_("ok") : _RED_("fail"));

    PrintAndLogEx(all_ok ? SUCCESS : FAILED, "Tests ( %s )", all_ok ? _GREEN_("ok") : _RED_("fail"));
    return all_ok ? PM3_SUCCESS : PM3_ESOFT;
}

static int CmdHF15Implant(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf 15 implant",
                  "Read the temperature of an NTAG 5 link (NTP5332) based sensor implant,\n"
                  "e.g. VivoKey Thermo (TMP112/TMP117/TMP119) or Temptress (2x TMP117 at 0x49, 0x4A).\n"
                  "Powers the sensor by energy harvesting and talks I2C through the NTAG 5 link.\n"
                  "Sensors at 0x48-0x4B are found by probing and identified by TMP117/119 device id.",
                  "hf 15 implant\n"
                  "hf 15 implant -n 5 -v\n"
                  "hf 15 implant --dual\n"
                  "hf 15 implant --addr 49 --sensor tmp117\n"
                  "hf 15 implant -u E004011800000000 --wait 5000\n"
                  "hf 15 implant --test"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("u", "uid", "<hex>", "full UID (8 hex bytes)"),
        arg_str0(NULL, "addr", "<hex>", "I2C address of sensor (def probe 48..4B)"),
        arg_str0(NULL, "sensor", "<str>", "sensor type: auto, tmp112, tmp117, tmp119 (def auto)"),
        arg_lit0(NULL, "dual", "Temptress, TMP117 at 0x49 and 0x4A"),
        arg_int0("n", NULL, "<dec>", "number of readings (def 1)"),
        arg_int0(NULL, "wait", "<ms>", "energy harvesting timeout (def 2000)"),
        arg_lit0("v", "verbose", "verbose output, show raw frames"),
        arg_lit0(NULL, "test", "perform self test"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    uint8_t uid[ISO15693_UID_LENGTH] = {0};
    int uidlen = 0;
    CLIGetHexWithReturn(ctx, 1, uid, &uidlen);

    uint8_t addrbuf[1] = {0};
    int addrlen = 0;
    CLIGetHexWithReturn(ctx, 2, addrbuf, &addrlen);
    uint8_t addr = addrbuf[0];

    const CLIParserOption sensor_opts[] = {
        {TMP_SENSOR_AUTO, "auto"},
        {TMP_SENSOR_TMP112, "tmp112"},
        {TMP_SENSOR_TMP117, "tmp117"},
        {TMP_SENSOR_TMP119, "tmp119"},
        {0, NULL},
    };
    int sensor = TMP_SENSOR_AUTO;
    if (CLIGetOptionList(arg_get_str(ctx, 3), sensor_opts, &sensor)) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    bool dual = arg_get_lit(ctx, 4);
    int count = arg_get_int_def(ctx, 5, 1);
    int wait = arg_get_int_def(ctx, 6, 2000);
    bool verbose = arg_get_lit(ctx, 7);
    bool selftest = arg_get_lit(ctx, 8);
    CLIParserFree(ctx);

    if (selftest) {
        return implant_selftest();
    }

    if (IfPm3Iso15693() == false) {
        PrintAndLogEx(WARNING, "Only offline self test is available");
        return PM3_ENOTTY;
    }

    if (uidlen != 0 && uidlen != ISO15693_UID_LENGTH) {
        PrintAndLogEx(WARNING, "UID must be 8 bytes, got " _RED_("%d"), uidlen);
        return PM3_EINVARG;
    }

    if (addrlen && (addr < 0x08 || addr > 0x77)) {
        PrintAndLogEx(WARNING, "I2C address must be 7-bit, 08..77");
        return PM3_EINVARG;
    }

    if (dual && addrlen) {
        PrintAndLogEx(WARNING, "Select only one option --addr/--dual");
        return PM3_EINVARG;
    }

    if (count < 1 || wait < 0) {
        PrintAndLogEx(WARNING, "invalid -n / --wait");
        return PM3_EINVARG;
    }

    ntag5_ctx_t c = { .field_on = false, .verbose = verbose };

    if (uidlen == ISO15693_UID_LENGTH) {
        reverse_array_copy(uid, ISO15693_UID_LENGTH, c.uid);
    } else if (getUID(true, false, false, c.uid) != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, "no tag found");
        return PM3_ENODATA;
    }

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(SUCCESS, "UID....... " _GREEN_("%s"), iso15693_sprintUID(NULL, c.uid));

    if (ntag5_uid_match(c.uid) == false) {
        PrintAndLogEx(FAILED, "Not an NTAG 5 ( UID mismatch )");
        return PM3_EWRONGANSWER;
    }

    // host interface must be I2C master, only NTP5332 has it
    uint8_t cfg[4] = {0};
    int res = ntag5_read_reg(&c, NTAG5_REG_CONFIG, cfg);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "failed to read NTAG 5 session register, not an NTAG 5 link?");
        goto out;
    }

    if ((cfg[1] & NTAG5_CONFIG1_USE_CASE_MASK) != NTAG5_CONFIG1_I2C_MASTER) {
        PrintAndLogEx(FAILED, "NTAG 5 is not in I2C master mode ( CONFIG_1 %02X )", cfg[1]);
        res = PM3_EWRONGANSWER;
        goto out;
    }
    PrintAndLogEx(SUCCESS, "NTAG 5 link in I2C master mode");

    res = ntag5_power_up(&c, wait);
    if (res != PM3_SUCCESS) {
        goto out;
    }

    // SRAM holds the I2C read data
    if (ntag5_read_reg(&c, NTAG5_REG_CONFIG, cfg) == PM3_SUCCESS && (cfg[1] & NTAG5_CONFIG1_SRAM_ENABLED) == 0) {
        PrintAndLogEx(WARNING, "SRAM not accessible ( CONFIG_1 %02X ), I2C reads will likely fail", cfg[1]);
    }

    tmp_dev_t devs[IMPLANT_MAX_SENSORS];
    uint8_t ndevs = 0;

    if (dual) {
        devs[ndevs++] = (tmp_dev_t) { 0x49, (sensor == TMP_SENSOR_AUTO) ? TMP_SENSOR_TMP117 : sensor };
        devs[ndevs++] = (tmp_dev_t) { 0x4A, (sensor == TMP_SENSOR_AUTO) ? TMP_SENSOR_TMP117 : sensor };
    } else {
        uint8_t first = (addrlen) ? addr : IMPLANT_I2C_ADDR_FIRST;
        uint8_t last = (addrlen) ? addr : IMPLANT_I2C_ADDR_LAST;
        for (uint8_t a = first; a <= last; a++) {

            tmp_sensor_t t = TMP_SENSOR_AUTO;
            int ires = tmp_identify(&c, a, &t);
            if (ires == PM3_ENODATA) {
                PrintAndLogEx((verbose) ? INFO : DEBUG, "0x%02X no answer", a);
                continue;
            }
            if (ires != PM3_SUCCESS) {
                ntag5_print_i2c_error(a, ires);
                res = ires;
                goto out;
            }
            if (sensor != TMP_SENSOR_AUTO) {
                t = sensor;
            }
            devs[ndevs++] = (tmp_dev_t) { a, t };
        }
    }

    if (ndevs == 0) {
        PrintAndLogEx(FAILED, "no temperature sensor found on I2C bus");
        res = PM3_ENODATA;
        goto out;
    }

    for (uint8_t i = 0; i < ndevs; i++) {
        PrintAndLogEx(SUCCESS, "Sensor.... " _GREEN_("%s") " at I2C 0x%02X", tmp_sensor_str(devs[i].type), devs[i].addr);
    }
    PrintAndLogEx(NORMAL, "");

    for (int n = 0; n < count; n++) {

        double sum = 0;
        for (uint8_t i = 0; i < ndevs; i++) {
            uint16_t raw = 0;
            res = tmp_measure(&c, devs[i].addr, devs[i].type, &raw);
            if (res != PM3_SUCCESS) {
                ntag5_print_i2c_error(devs[i].addr, res);
                goto out;
            }

            double tc = tmp_raw_to_celsius(devs[i].type, raw);
            sum += tc;
            PrintAndLogEx(SUCCESS, "%s 0x%02X... " _GREEN_("%.2f") " C / " _GREEN_("%.2f") " F  ( raw %04X )"
                          , tmp_sensor_str(devs[i].type)
                          , devs[i].addr
                          , tc
                          , celsius_to_fahrenheit(tc)
                          , raw
                         );
        }

        if (ndevs > 1) {
            double avg = sum / ndevs;
            PrintAndLogEx(SUCCESS, "Average........ " _GREEN_("%.2f") " C / " _GREEN_("%.2f") " F", avg, celsius_to_fahrenheit(avg));
        }

        if (kbd_enter_pressed()) {
            PrintAndLogEx(WARNING, "aborted via keyboard");
            break;
        }
    }
    res = PM3_SUCCESS;

out:
    DropField();
    return res;
}

static command_t CommandTable[] = {
    {"-----------",         CmdHF15Help,              AlwaysAvailable, "----------------------- " _CYAN_("General") " -----------------------"},
    {"help",                CmdHF15Help,              AlwaysAvailable, "This help"},
    {"list",                CmdHF15List,              AlwaysAvailable, "List ISO-15693 history"},
    {"-----------",         CmdHF15Help,              AlwaysAvailable, "----------------------- " _CYAN_("Operations") " -----------------------"},
    {"demod",               CmdHF15Demod,             AlwaysAvailable, "Demodulate ISO-15693 from tag"},
    {"dump",                CmdHF15Dump,              IfPm3Iso15693,   "Read all memory pages of an ISO-15693 tag, save to file"},
    {"implant",             CmdHF15Implant,           AlwaysAvailable, "Read temperature from NTAG 5 link sensor implant"},
    {"info",                CmdHF15Info,              IfPm3Iso15693,   "Tag information"},
    {"sniff",               CmdHF15Sniff,             IfPm3Iso15693,   "Sniff ISO-15693 traffic"},
    {"raw",                 CmdHF15Raw,               IfPm3Iso15693,   "Send raw hex data to tag"},
    {"rdbl",                CmdHF15Readblock,         IfPm3Iso15693,   "Read a block"},
    {"rdmulti",             CmdHF15Readmulti,         IfPm3Iso15693,   "Reads multiple blocks"},
    {"reader",              CmdHF15Reader,            IfPm3Iso15693,   "Act like an ISO-15693 reader"},
    {"restore",             CmdHF15Restore,           IfPm3Iso15693,   "Restore from file to all memory pages of an ISO-15693 tag"},
    {"samples",             CmdHF15Samples,           IfPm3Iso15693,   "Acquire samples as reader (enables carrier, sends inquiry)"},
    {"view",                CmdHF15View,              AlwaysAvailable, "Display content from tag dump file"},
    {"wipe",                CmdHF15Wipe,              IfPm3Iso15693,   "Wipe card to zeros"},
    {"wrbl",                CmdHF15Write,             IfPm3Iso15693,   "Write a block"},
    {"-----------",         CmdHF15Help,              IfPm3Iso15693,   "--------------------- " _CYAN_("Simulation") " ----------------------"},
    {"sim",                 CmdHF15Sim,               IfPm3Iso15693,   "Fake an ISO-15693 tag"},
    {"eload",               CmdHF15ELoad,             IfPm3Iso15693,   "Upload file into emulator memory"},
    {"esave",               CmdHF15ESave,             IfPm3Iso15693,   "Save emulator memory to file"},
    {"eview",               CmdHF15EView,             IfPm3Iso15693,   "View emulator memory"},
    {"-----------",         CmdHF15Help,              IfPm3Iso15693,   "------------------------ " _CYAN_("SLIX") " -------------------------"},
    {"slixwritepwd",        CmdHF15SlixWritePassword, IfPm3Iso15693,   "Writes a password on a SLIX ISO-15693 tag"},
    {"slixeasdisable",      CmdHF15SlixEASDisable,    IfPm3Iso15693,   "Disable EAS mode on SLIX ISO-15693 tag"},
    {"slixeasenable",       CmdHF15SlixEASEnable,     IfPm3Iso15693,   "Enable EAS mode on SLIX ISO-15693 tag"},
    {"slixprivacydisable",  CmdHF15SlixDisable,       IfPm3Iso15693,   "Disable privacy mode on SLIX ISO-15693 tag"},
    {"slixprivacyenable",   CmdHF15SlixEnable,        IfPm3Iso15693,   "Enable privacy mode on SLIX ISO-15693 tag"},
    {"slixprotectpage",     CmdHF15SlixProtectPage,   IfPm3Iso15693,   "Protect pages on SLIX ISO-15693 tag"},
    {"passprotectafi",      CmdHF15AFIPassProtect,    IfPm3Iso15693,   "Password protect AFI - Cannot be undone"},
    {"passprotecteas",      CmdHF15EASPassProtect,    IfPm3Iso15693,   "Password protect EAS - Cannot be undone"},
    {"-----------",         CmdHF15Help,              IfPm3Iso15693,  "-------------------------- " _CYAN_("afi") " ------------------------"},
    {"findafi",             CmdHF15FindAfi,           IfPm3Iso15693,   "Brute force AFI of an ISO-15693 tag"},
    {"writeafi",            CmdHF15WriteAfi,          IfPm3Iso15693,   "Writes the AFI on an ISO-15693 tag"},
    {"writedsfid",          CmdHF15WriteDsfid,        IfPm3Iso15693,   "Writes the DSFID on an ISO-15693 tag"},
    {"-----------",         CmdHF15Help,              IfPm3Iso15693,  "------------------------- " _CYAN_("Magic") " -----------------------"},
    {"csetuid",             CmdHF15CSetUID,           IfPm3Iso15693,   "Set UID for magic card"},
    {"cfinalize",           CmdHF15CFinalize,         IfPm3Iso15693,   "Finalize a magic V3 tag (irreversible)"},
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
