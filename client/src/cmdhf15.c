//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
// Modified 2010-2012 by <adrian -at- atrox.at>
// Modified 2012 by <vsza at vsza.hu>
// Modfified 2018 by <iceman>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
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
#include "cmdparser.h"    // command_t
#include "commonutil.h"   // ARRAYLEN
#include "comms.h"        // clearCommandBuffer
#include "cmdtrace.h"
#include "iso15693tools.h"
#include "crypto/libpcrypto.h"
#include "graph.h"
#include "crc16.h"             // iso15 crc
#include "cmddata.h"           // getsamples
#include "fileutils.h"         // savefileEML
#include "cliparser.h"

#define FrameSOF                Iso15693FrameSOF
#define Logic0                  Iso15693Logic0
#define Logic1                  Iso15693Logic1
#define FrameEOF                Iso15693FrameEOF

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
    int mask; // how many MSB bits used
    const char *desc;
} productName_t;

const productName_t uidmapping[] = {

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
    //I-Code SLI SL2 ICS20 [IC id = 01]
    //I-Code SLI-S         [IC id = 02]
    //I-Code SLI-L         [IC id = 03]
    //I-Code SLIX          [IC id = 01 + bit36 set to 1 (starting from bit0 - different from normal SLI)]
    //I-Code SLIX2         [IC id = 01 + bit35 set to 1 + bit36 set to 0]
    //I-Code SLIX-S        [IC id = 02 + bit36 set to 1]
    //I-Code SLIX-L        [IC id = 03 + bit36 set to 1]
    { 0xE004000000000000LL, 16, "NXP Semiconductors Germany (Philips)" },
    { 0xE004010000000000LL, 24, "NXP(Philips); IC SL2 ICS20/ICS21(SLI) ICS2002/ICS2102(SLIX) ICS2602(SLIX2)" },
    { 0xE004020000000000LL, 24, "NXP(Philips); IC SL2 ICS53/ICS54(SLI-S) ICS5302/ICS5402(SLIX-S)" },
    { 0xE004030000000000LL, 24, "NXP(Philips); IC SL2 ICS50/ICS51(SLI-L) ICS5002/ICS5102(SLIX-L)" },

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

static int usage_15_info(void) {
    PrintAndLogEx(NORMAL, "Uses the optional command 'get_systeminfo' 0x2B to try and extract information\n"
                  "command may fail, depending on tag.\n"
                  "defaults to '1 out of 4' mode\n"
                  "\n"
                  "Usage:  hf 15 info    [options] <uid|s|u|*>\n"
                  "Options:\n"
                  "\t-2        use slower '1 out of 256' mode\n"
                  "\tuid (either): \n"
                  "\t  <8B hex>  full UID eg E011223344556677\n"
                  "\t  u         unaddressed mode\n"
                  "\t  *         scan for tag\n"
                  "Examples:\n"
                  _YELLOW_("\thf 15 info u"));
    return PM3_SUCCESS;
}

static int usage_15_writeafi(void) {
    PrintAndLogEx(NORMAL, "Usage:  hf 15 writeafi <uid|u|*> <afi>\n"
                  "\tuid (either): \n"
                  "\t   <8B hex>  full UID eg E011223344556677\n"
                  "\t   u         unaddressed mode\n"
                  "\t   *         scan for tag\n"
                  "\t   <afi>     AFI number 0-255");
    return PM3_SUCCESS;
}
static int usage_15_writedsfid(void) {
    PrintAndLogEx(NORMAL, "Usage:  hf 15 writedsfid <uid|u|*> <dsfid>\n"
                  "\tuid (either): \n"
                  "\t   <8B hex>  full UID eg E011223344556677\n"
                  "\t   u         unaddressed mode\n"
                  "\t   *         scan for tag\n"
                  "\t   <dsfid>   DSFID number 0-255");
    return PM3_SUCCESS;
}
static int usage_15_dump(void) {
    PrintAndLogEx(NORMAL, "This command dumps the contents of a ISO-15693 tag and save it to file\n"
                  "\n"
                  "Usage: hf 15 dump [h] <f filename> \n"
                  "Options:\n"
                  "\th             this help\n"
                  "\tf <name>      filename,  if no <name> UID will be used as filename\n"
                  "\n"
                  "Example:\n"
                  _YELLOW_("\thf 15 dump f\n")
                  _YELLOW_("\thf 15 dump f mydump"));
    return PM3_SUCCESS;
}
static int usage_15_restore(void) {
    const char *options[][2] = {
        {"h", "this help"},
        {"-2", "use slower '1 out of 256' mode"},
        {"-o", "set OPTION Flag (needed for TI)"},
        {"a", "use addressed mode"},
        {"r <NUM>", "numbers of retries on error, default is 3"},
        {"f <filename>", "load <filename>"},
        {"b <block size>", "block size, default is 4"}
    };
    PrintAndLogEx(NORMAL, "Usage: hf 15 restore [-2] [-o] [h] [r <NUM>] [u <UID>] [f <filename>] [b <block size>]");
    PrintAndLogOptions(options, 7, 3);
    return PM3_SUCCESS;
}
static int usage_15_raw(void) {
    const char *options[][2] = {
        {"-r", "do not read response" },
        {"-2", "use slower '1 out of 256' mode" },
        {"-c", "calculate and append CRC" },
        {"-k", "keep signal field ON after receive" },
        {"", "Tip: turn on debugging for verbose output"},
    };
    PrintAndLogEx(NORMAL, "Usage: hf 15 raw  [-r] [-2] [-k] [-c] <0A 0B 0C ... hex>\n");
    PrintAndLogOptions(options, 4, 3);
    return PM3_SUCCESS;
}
static int usage_15_read(void) {
    PrintAndLogEx(NORMAL, "Usage:  hf 15 rdbl    [options] <uid|s|u|*> <page>\n"
                  "Options:\n"
                  "\t-2        use slower '1 out of 256' mode\n"
                  "\tuid (either): \n"
                  "\t   <8B hex>  full UID eg E011223344556677\n"
                  "\t   u         unaddressed mode\n"
                  "\t   *         scan for tag\n"
                  "\t   <page>    page number 0-255");
    return PM3_SUCCESS;
}
static int usage_15_write(void) {
    PrintAndLogEx(NORMAL, "Usage:  hf 15 wrbl    [options] <uid|s|u|*> <page> <hexdata>\n"
                  "Options:\n"
                  "\t-2        use slower '1 out of 256' mode\n"
                  "\t-o        set OPTION Flag (needed for TI)\n"
                  "\tuid (either): \n"
                  "\t   <8B hex>   full UID eg E011223344556677\n"
                  "\t   u          unaddressed mode\n"
                  "\t   *          scan for tag\n"
                  "\t   <page>     page number 0-255\n"
                  "\t   <hexdata>  data to be written eg AA BB CC DD");
    return PM3_SUCCESS;
}
static int usage_15_readmulti(void) {
    PrintAndLogEx(NORMAL, "Usage:  hf 15 readmulti  [options] <uid|s|u|*> <start> <count>\n"
                  "Options:\n"
                  "\t-2        use slower '1 out of 256' mode\n"
                  "\tuid (either): \n"
                  "\t   <8B hex>  full UID eg E011223344556677\n"
                  "\t   u         unaddressed mode\n"
                  "\t   *         scan for tag\n"
                  "\t   <start>   0-255, page number to start\n"
                  "\t   <count>   1-6, number of pages");
    return PM3_SUCCESS;
}

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
    uint8_t i;
    uint8_t revuid[8];
    for (i = 0; i < sizeof(revuid); i++) {
        revuid[i] = uid[7 - i];
    }
    uint8_t revsign[32];
    for (i = 0; i < sizeof(revsign); i++) {
        revsign[i] = signature[31 - i];
    }

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

    PrintAndLogEx(INFO, " IC signature public key name: %s", nxp_15693_public_keys[i].desc);
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
        mask = (~0ULL) << (64 - uidmapping[i].mask);
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
static bool getUID(bool loop, uint8_t *buf) {

    uint8_t data[5];
    data[0] = ISO15_REQ_SUBCARRIER_SINGLE | ISO15_REQ_DATARATE_HIGH | ISO15_REQ_INVENTORY | ISO15_REQINV_SLOT1;
    data[1] = ISO15_CMD_INVENTORY;
    data[2] = 0; // mask length

    AddCrc15(data, 3);

    // params
    uint8_t fast = 1;
    uint8_t reply = 1;

    while (kbd_enter_pressed() == false) {
        clearCommandBuffer();
        SendCommandMIX(CMD_HF_ISO15693_COMMAND, sizeof(data), fast, reply, data, sizeof(data));
        PacketResponseNG resp;
        if (WaitForResponseTimeout(CMD_ACK, &resp, 2000)) {

            int resplen = resp.oldarg[0];
            if (resplen >= 12 && CheckCrc15(resp.data.asBytes, 12)) {

                if (buf)
                    memcpy(buf, resp.data.asBytes + 2, 8);

                DropField();

                PrintAndLogEx(NORMAL, "");
                PrintAndLogEx(SUCCESS, " UID: " _GREEN_("%s"), iso15693_sprintUID(NULL, buf));
                PrintAndLogEx(SUCCESS, "TYPE: " _YELLOW_("%s"), getTagInfo_15(buf));

                if (loop == false) {
                    return true;
                }
            }
        }
        if (loop == false) {
            break;
        }
    }

    DropField();
    return false;
}

// used with 'hf search'
bool readHF15Uid(bool loop, bool verbose) {
    uint8_t uid[8] = {0};
    if (getUID(loop, uid) == false) {
        if (verbose) PrintAndLogEx(WARNING, "No tag found");
        return false;
    }
    return true;
}

/**
 * parses common HF 15 CMD parameters and prepares some data structures
 * Parameters:
 *  **cmd   command line
 */
static bool prepareHF15Cmd(char **cmd, uint16_t *reqlen, uint8_t *arg1, uint8_t *req, uint8_t iso15cmd) { // reqlen arg0
    int temp;
    uint8_t uid[8] = {0x00};
    uint32_t tmpreqlen = 0;

    // strip
    while (**cmd == ' ' || **cmd == '\t')(*cmd)++;

    if (strstr(*cmd, "-2") == *cmd) {
        *arg1 = 0; // use 1of256
        (*cmd) += 2;
    }

    // strip
    while (**cmd == ' ' || **cmd == '\t')(*cmd)++;

    if (strstr(*cmd, "-o") == *cmd) {
        req[tmpreqlen] = ISO15_REQ_OPTION;
        (*cmd) += 2;
    }

    // strip
    while (**cmd == ' ' || **cmd == '\t')(*cmd)++;

    switch (**cmd) {
        case 0:
            PrintAndLogEx(WARNING, "missing addr");
            return false;
            break;
        case 'u':
        case 'U':
            // unaddressed mode may not be supported by all vendors
            req[tmpreqlen++] |= ISO15_REQ_SUBCARRIER_SINGLE | ISO15_REQ_DATARATE_HIGH | ISO15_REQ_NONINVENTORY;
            req[tmpreqlen++] = iso15cmd;
            break;
        case '*':
            // we scan for the UID ourself
            req[tmpreqlen++] |= ISO15_REQ_SUBCARRIER_SINGLE | ISO15_REQ_DATARATE_HIGH | ISO15_REQ_NONINVENTORY | ISO15_REQ_ADDRESS;
            req[tmpreqlen++] = iso15cmd;

            if (getUID(false, uid) == false) {
                PrintAndLogEx(WARNING, "No tag found");
                return false;
            }
            memcpy(&req[tmpreqlen], uid, sizeof(uid));
            PrintAndLogEx(SUCCESS, "Detected UID " _GREEN_("%s"), iso15693_sprintUID(NULL, uid));
            tmpreqlen += sizeof(uid);
            break;
        default:
            req[tmpreqlen++] |= ISO15_REQ_SUBCARRIER_SINGLE | ISO15_REQ_DATARATE_HIGH | ISO15_REQ_NONINVENTORY | ISO15_REQ_ADDRESS;
            req[tmpreqlen++] = iso15cmd;
            // parse UID
            for (int i = 0; i < 8 && (*cmd)[i * 2] && (*cmd)[i * 2 + 1]; i++) {
                sscanf((char[]) {(*cmd)[i * 2], (*cmd)[i * 2 + 1], 0}, "%X", &temp);
                uid[7 - i] = temp & 0xff;
            }

            PrintAndLogEx(SUCCESS, "Using UID " _GREEN_("%s"), iso15693_sprintUID(NULL, uid));
            memcpy(&req[tmpreqlen], uid, sizeof(uid));
            tmpreqlen +=  sizeof(uid);
            break;
    }
    // skip to next space
    while (**cmd != ' ' && **cmd != '\t')(*cmd)++;
    // skip over the space
    while (**cmd == ' ' || **cmd == '\t')(*cmd)++;

    *reqlen = tmpreqlen;
    return true;
}

// Mode 3
static int CmdHF15Demod(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf 15 demod",
                  "Tries to demodulate / decode ISO15693, from downloaded samples.\n"
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

    if (GraphTraceLen < 1000) {
        PrintAndLogEx(FAILED, "Too few samples in GraphBuffer. Need more than 1000");
        PrintAndLogEx(HINT, "Run " _YELLOW_("`hf 15 samples`") " to collect and download data");
        return PM3_ESOFT;
    }

    // First, correlate for SOF
    for (i = 0; i < 1000; i++) {
        int corr = 0;
        for (j = 0; j < ARRAYLEN(FrameSOF); j += skip) {
            corr += FrameSOF[j] * GraphBuffer[i + (j / skip)];
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
            corr0 += Logic0[j] * GraphBuffer[i + (j / skip)];
        }
        for (j = 0; j < ARRAYLEN(Logic1); j += skip) {
            corr1 += Logic1[j] * GraphBuffer[i + (j / skip)];
        }
        for (j = 0; j < ARRAYLEN(FrameEOF); j += skip) {
            corrEOF += FrameEOF[j] * GraphBuffer[i + (j / skip)];
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

        if ((i + (int)ARRAYLEN(FrameEOF)) >= GraphTraceLen) {
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
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    CLIParserFree(ctx);

    clearCommandBuffer();
    SendCommandNG(CMD_HF_ISO15693_ACQ_RAW_ADC, NULL, 0);

    getSamples(0, true);

    PrintAndLogEx(HINT, "Try `" _YELLOW_("hf 15 demod") "` to decode signal");
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
    req[reqlen++] = ISO15_CMD_GETNXPSYSTEMINFO;
    req[reqlen++] = 0x04; // IC manufacturer code
    memcpy(req + 3, uid, 8); // add UID
    reqlen += 8;

    AddCrc15(req,  reqlen);
    reqlen += 2;

    PacketResponseNG resp;
    clearCommandBuffer();
    SendCommandMIX(CMD_HF_ISO15693_COMMAND, reqlen, fast, reply, req, reqlen);
    if (!WaitForResponseTimeout(CMD_ACK, &resp, 2000)) {
        PrintAndLogEx(WARNING, "iso15693 timeout");
        DropField();
        return PM3_ETIMEOUT;
    }

    DropField();

    int status = resp.oldarg[0];
    if (status == PM3_ETEAROFF) {
        return status;
    }

    if (status < 2) {
        PrintAndLogEx(WARNING, "iso15693 card doesn't answer to NXP systeminfo command");
        return PM3_EWRONGANSWER;
    }

    uint8_t *recv = resp.data.asBytes;

    if ((recv[0] & ISO15_RES_ERROR) == ISO15_RES_ERROR) {
        PrintAndLogEx(ERR, "iso15693 card returned error %i: %s", recv[0], TagErrorStr(recv[0]));
        return PM3_EWRONGANSWER;
    }

    bool support_signature = (recv[5] & 0x01);
    bool support_easmode = (recv[4] & 0x03);

    PrintAndLogEx(INFO, "--------- " _CYAN_("NXP Sysinfo") " ---------");
    PrintAndLogEx(INFO, "  raw : %s", sprint_hex(recv, 8));
    PrintAndLogEx(INFO, "    Password protection configuration:");
    PrintAndLogEx(INFO, "      * Page L read%s password protected", ((recv[2] & 0x01) ? "" : " not"));
    PrintAndLogEx(INFO, "      * Page L write%s password protected", ((recv[2] & 0x02) ? "" : " not"));
    PrintAndLogEx(INFO, "      * Page H read%s password protected", ((recv[2] & 0x08) ? "" : " not"));
    PrintAndLogEx(INFO, "      * Page H write%s password protected", ((recv[2] & 0x20) ? "" : " not"));

    PrintAndLogEx(INFO, "    Lock bits:");
    PrintAndLogEx(INFO, "      * AFI%s locked", ((recv[3] & 0x01) ? "" : " not")); // AFI lock bit
    PrintAndLogEx(INFO, "      * EAS%s locked", ((recv[3] & 0x02) ? "" : " not")); // EAS lock bit
    PrintAndLogEx(INFO, "      * DSFID%s locked", ((recv[3] & 0x03) ? "" : " not")); // DSFID lock bit
    PrintAndLogEx(INFO, "      * Password protection configuration%s locked", ((recv[3] & 0x04) ? "" : " not")); // Password protection pointer address and access conditions lock bit

    PrintAndLogEx(INFO, "    Features:");
    PrintAndLogEx(INFO, "      * User memory password protection%s supported", ((recv[4] & 0x01) ? "" : " not"));
    PrintAndLogEx(INFO, "      * Counter feature%s supported", ((recv[4] & 0x02) ? "" : " not"));
    PrintAndLogEx(INFO, "      * EAS ID%s supported by EAS ALARM command", support_easmode ? "" : " not");
    PrintAndLogEx(INFO, "      * EAS password protection%s supported", ((recv[4] & 0x04) ? "" : " not"));
    PrintAndLogEx(INFO, "      * AFI password protection%s supported", ((recv[4] & 0x10) ? "" : " not"));
    PrintAndLogEx(INFO, "      * Extended mode%s supported by INVENTORY READ command", ((recv[4] & 0x20) ? "" : " not"));
    PrintAndLogEx(INFO, "      * EAS selection%s supported by extended mode in INVENTORY READ command", ((recv[4] & 0x40) ? "" : " not"));
    PrintAndLogEx(INFO, "      * READ SIGNATURE command%s supported", support_signature ? "" : " not");
    PrintAndLogEx(INFO, "      * Password protection for READ SIGNATURE command%s supported", ((recv[5] & 0x02) ? "" : " not"));
    PrintAndLogEx(INFO, "      * STAY QUIET PERSISTENT command%s supported", ((recv[5] & 0x03) ? "" : " not"));
    PrintAndLogEx(INFO, "      * ENABLE PRIVACY command%s supported", ((recv[5] & 0x10) ? "" : " not"));
    PrintAndLogEx(INFO, "      * DESTROY command%s supported", ((recv[5] & 0x20) ? "" : " not"));
    PrintAndLogEx(INFO, "      * Additional 32 bits feature flags are%s transmitted", ((recv[5] & 0x80) ? "" : " not"));

    if (support_easmode) {
        reqlen = 0;
        req[reqlen++] |= ISO15_REQ_SUBCARRIER_SINGLE | ISO15_REQ_DATARATE_HIGH | ISO15_REQ_NONINVENTORY | ISO15_REQ_ADDRESS;
        req[reqlen++] = ISO15_CMD_EASALARM;
        req[reqlen++] = 0x04; // IC manufacturer code
        memcpy(req + 3, uid, 8); // add UID
        reqlen += 8;

        AddCrc15(req,  reqlen);
        reqlen += 2;

        clearCommandBuffer();
        SendCommandMIX(CMD_HF_ISO15693_COMMAND, reqlen, fast, reply, req, reqlen);

        if (!WaitForResponseTimeout(CMD_ACK, &resp, 2000)) {
            PrintAndLogEx(WARNING, "iso15693 timeout");
        } else {
            PrintAndLogEx(NORMAL, "");

            status = resp.oldarg[0];
            if (status < 2) {
                PrintAndLogEx(INFO, "  EAS (Electronic Article Surveillance) is not active");
            } else {
                recv = resp.data.asBytes;

                if (!(recv[0] & ISO15_RES_ERROR)) {
                    PrintAndLogEx(INFO, "  EAS (Electronic Article Surveillance) is active.");
                    PrintAndLogEx(INFO, "  EAS sequence: %s", sprint_hex(recv + 1, 32));
                }
            }
        }
    }

    if (support_signature) {
        // Check if we can also read the signature
        reqlen = 0;
        req[reqlen++] |= ISO15_REQ_SUBCARRIER_SINGLE | ISO15_REQ_DATARATE_HIGH | ISO15_REQ_NONINVENTORY | ISO15_REQ_ADDRESS;
        req[reqlen++] = ISO15_CMD_READSIGNATURE;
        req[reqlen++] = 0x04; // IC manufacturer code
        memcpy(req + 3, uid, 8); // add UID
        reqlen += 8;

        AddCrc15(req,  reqlen);
        reqlen += 2;

        clearCommandBuffer();
        SendCommandMIX(CMD_HF_ISO15693_COMMAND, reqlen, fast, reply, req, reqlen);

        if (!WaitForResponseTimeout(CMD_ACK, &resp, 2000)) {
            PrintAndLogEx(WARNING, "iso15693 timeout");
            DropField();
            return PM3_ETIMEOUT;
        }

        DropField();

        status = resp.oldarg[0];
        if (status < 2) {
            PrintAndLogEx(WARNING, "iso15693 card doesn't answer to READ SIGNATURE command");
            return PM3_EWRONGANSWER;
        }

        recv = resp.data.asBytes;

        if ((recv[0] & ISO15_RES_ERROR) == ISO15_RES_ERROR) {
            PrintAndLogEx(ERR, "iso15693 card returned error %i: %s", recv[0], TagErrorStr(recv[0]));
            return PM3_EWRONGANSWER;
        }

        uint8_t signature[32] = {0x00};
        memcpy(signature, recv + 1, 32);

        nxp_15693_print_signature(uid, signature);
    }

    return PM3_SUCCESS;
}

/**
 * Commandline handling: HF15 CMD SYSINFO
 * get system information from tag/VICC
 */
static int CmdHF15Info(const char *Cmd) {

    char cmdp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) < 1 || cmdp == 'h') return usage_15_info();

    PacketResponseNG resp;
    uint8_t req[PM3_CMD_DATA_SIZE] = {0};
    uint16_t reqlen;
    uint8_t fast = 1;
    uint8_t reply = 1;
    uint8_t uid[8] = {0, 0, 0, 0, 0, 0, 0, 0};

    char cmdbuf[100] = {0};
    char *cmd = cmdbuf;
    strncpy(cmd, Cmd, sizeof(cmdbuf) - 1);

    if (prepareHF15Cmd(&cmd, &reqlen, &fast, req, ISO15_CMD_SYSINFO) == false)
        return PM3_SUCCESS;

    AddCrc15(req,  reqlen);
    reqlen += 2;

    clearCommandBuffer();
    SendCommandMIX(CMD_HF_ISO15693_COMMAND, reqlen, fast, reply, req, reqlen);
    if (!WaitForResponseTimeout(CMD_ACK, &resp, 2000)) {
        PrintAndLogEx(WARNING, "iso15693 timeout");
        DropField();
        return PM3_ETIMEOUT;
    }

    DropField();

    int status = resp.oldarg[0];
    if (status == PM3_ETEAROFF) {
        return status;
    }
    if (status < 2) {
        PrintAndLogEx(WARNING, "iso15693 card doesn't answer to systeminfo command (%d)", status);
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
    PrintAndLogEx(INFO, "-------------------------------------------------------------");
    PrintAndLogEx(SUCCESS, "      TYPE: " _YELLOW_("%s"), getTagInfo_15(data + 2));
    PrintAndLogEx(SUCCESS, "       UID: " _GREEN_("%s"), iso15693_sprintUID(NULL, uid));
    PrintAndLogEx(SUCCESS, "   SYSINFO: %s", sprint_hex(data, status - 2));

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
    PrintAndLogEx(DEBUG, "4 & 08 :: %02x   7 == 1 :: %u   8 == 4 :: %u", data[4], data[7], data[8]);
    if (data[8] == 0x04 && data[7] == 0x01 && data[4] & 0x80) {
        return NxpSysInfo(uid);
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
    PrintAndLogEx(HINT, "Try `" _YELLOW_("trace save h") "` to save tracelog for later analysing");
    return PM3_SUCCESS;
}

static int CmdHF15Reader(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf 15 reader",
                  "Act as a ISO15693 reader.  Look for ISO15693 tags until Enter or the pm3 button is pressed\n",
                  "hf 15 reader\n"
                  "hf 15 reader -1");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("1", "one", "read once"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool read_once = arg_get_lit(ctx, 1);
    CLIParserFree(ctx);

    PrintAndLogEx(INFO, "Starting ISO15 reader mode");
    PrintAndLogEx(INFO, "press " _YELLOW_("`enter`") " to cancel");
    readHF15Uid(!read_once, true);
    return PM3_SUCCESS;
}

// Simulation is still not working very good
// helptext
static int CmdHF15Sim(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf 15 sim",
                  "Simulate a ISO15693 tag\n",
                  "hf 15 sim -u E011223344556677");

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
        PrintAndLogEx(WARNING, "UID must include 16 HEX symbols");
        return PM3_EINVARG;
    }

    PrintAndLogEx(SUCCESS, "Starting simulating UID " _YELLOW_("%s"), iso15693_sprintUID(NULL, payload.uid));
    PrintAndLogEx(INFO, "press " _YELLOW_("`Pm3 button`") " to cancel");

    PacketResponseNG resp;
    clearCommandBuffer();
    SendCommandNG(CMD_HF_ISO15693_SIMULATE, (uint8_t *)&payload, sizeof(payload));
    WaitForResponse(CMD_HF_ISO15693_SIMULATE, &resp);
    return PM3_SUCCESS;
}

// finds the AFI (Application Family Identifier) of a card, by trying all values
// (There is no standard way of reading the AFI, although some tags support this)
// helptext
static int CmdHF15FindAfi(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf 15 findafi",
                  "This command attempts to brute force AFI of an ISO15693 tag\n",
                  "hf 15 findafi");

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    CLIParserFree(ctx);

    PrintAndLogEx(SUCCESS, "press pm3-button to cancel");

    clearCommandBuffer();
    PacketResponseNG resp;
    SendCommandMIX(CMD_HF_ISO15693_FINDAFI, strtol(Cmd, NULL, 0), 0, 0, NULL, 0);

    uint32_t timeout = 0;
    while (!WaitForResponseTimeout(CMD_ACK, &resp, 2000)) {
        timeout++;

        // should be done in about 2 minutes
        if (timeout > 180) {
            PrintAndLogEx(WARNING, "\nNo response from Proxmark3. Aborting...");
            DropField();
            return PM3_ETIMEOUT;
        }
    }

    DropField();
    return resp.status; // PM3_EOPABORTED or PM3_SUCCESS
}

// Writes the AFI (Application Family Identifier) of a card
static int CmdHF15WriteAfi(const char *Cmd) {

    char cmdp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) < 3 || cmdp == 'h')  return usage_15_writeafi();

    // arg: len, speed, recv?
    // arg0 (datalen,  cmd len?  .arg0 == crc?)
    // arg1 (speed == 0 == 1 of 256,  == 1 == 1 of 4 )
    // arg2 (recv == 1 == expect a response)
    uint8_t req[PM3_CMD_DATA_SIZE] = {0};
    uint16_t reqlen = 0;
    uint8_t fast = 1;
    uint8_t reply = 1;

    char cmdbuf[100] = {0};
    char *cmd = cmdbuf;
    strncpy(cmd, Cmd, sizeof(cmdbuf) - 1);

    if (!prepareHF15Cmd(&cmd, &reqlen, &fast, req, ISO15_CMD_WRITEAFI))
        return PM3_SUCCESS;

    req[0] |= ISO15_REQ_OPTION; // Since we are writing

    int afinum = strtol(cmd, NULL, 0);

    req[reqlen++] = (uint8_t)afinum;

    AddCrc15(req, reqlen);
    reqlen += 2;

    PacketResponseNG resp;
    clearCommandBuffer();
    SendCommandMIX(CMD_HF_ISO15693_COMMAND, reqlen, fast, reply, req, reqlen);

    if (!WaitForResponseTimeout(CMD_ACK, &resp, 2000)) {
        PrintAndLogEx(ERR, "iso15693 timeout");
        DropField();
        return PM3_ETIMEOUT;
    }
    DropField();

    int status = resp.oldarg[0];
    if (status == PM3_ETEAROFF) {
        return status;
    }

    uint8_t *data = resp.data.asBytes;

    if ((data[0] & ISO15_RES_ERROR) == ISO15_RES_ERROR) {
        PrintAndLogEx(ERR, "iso15693 card returned error %i: %s", data[0], TagErrorStr(data[0]));
        return PM3_EWRONGANSWER;
    }

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(SUCCESS, "Wrote AFI 0x%02X", afinum);
    return PM3_SUCCESS;
}

// Writes the DSFID (Data Storage Format Identifier) of a card
static int CmdHF15WriteDsfid(const char *Cmd) {

    char cmdp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) < 3 || cmdp == 'h')  return usage_15_writedsfid();

    // arg: len, speed, recv?
    // arg0 (datalen,  cmd len?  .arg0 == crc?)
    // arg1 (speed == 0 == 1 of 256,  == 1 == 1 of 4 )
    // arg2 (recv == 1 == expect a response)
    uint8_t req[PM3_CMD_DATA_SIZE] = {0};
    uint16_t reqlen = 0;
    uint8_t fast = 1;
    uint8_t reply = 1;
    int dsfidnum;

    char cmdbuf[100] = {0};
    char *cmd = cmdbuf;
    strncpy(cmd, Cmd, sizeof(cmdbuf) - 1);

    if (prepareHF15Cmd(&cmd, &reqlen, &fast, req, ISO15_CMD_WRITEDSFID) == false)
        return PM3_SUCCESS;

    req[0] |= ISO15_REQ_OPTION; // Since we are writing

    dsfidnum = strtol(cmd, NULL, 0);

    req[reqlen++] = (uint8_t)dsfidnum;

    AddCrc15(req, reqlen);
    reqlen += 2;

    // PrintAndLogEx(NORMAL, "cmd %s", sprint_hex(req, reqlen) );
    PacketResponseNG resp;
    clearCommandBuffer();
    SendCommandMIX(CMD_HF_ISO15693_COMMAND, reqlen, fast, reply, req, reqlen);

    if (!WaitForResponseTimeout(CMD_ACK, &resp, 2000)) {
        PrintAndLogEx(ERR, "iso15693 timeout");
        DropField();
        return PM3_ETIMEOUT;
    }

    DropField();
    int status = resp.oldarg[0];
    if (status == PM3_ETEAROFF) {
        return status;
    }

    uint8_t *data = resp.data.asBytes;

    if ((data[0] & ISO15_RES_ERROR) == ISO15_RES_ERROR) {
        PrintAndLogEx(ERR, "iso15693 card returned error %i: %s", data[0], TagErrorStr(data[0]));
        return PM3_EWRONGANSWER;
    }

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(SUCCESS, "Wrote DSFID 0x%02X", dsfidnum);
    return PM3_SUCCESS;
}

// Reads all memory pages
// need to write to file
static int CmdHF15Dump(const char *Cmd) {

    uint8_t fileNameLen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    char *fptr = filename;
    bool errors = false;
    uint8_t cmdp = 0;
    uint8_t uid[8] = {0, 0, 0, 0, 0, 0, 0, 0};

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_15_dump();
            case 'f':
                fileNameLen = param_getstr(Cmd, cmdp + 1, filename, FILE_PATH_SIZE);
                cmdp += 2;
                break;
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'\n", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }

    //Validations
    if (errors) return usage_15_dump();

    if (getUID(false, uid) == false) {
        PrintAndLogEx(WARNING, "No tag found.");
        return PM3_ESOFT;
    }

    if (fileNameLen < 1) {
        PrintAndLogEx(INFO, "Using UID as filename");
        fptr += sprintf(fptr, "hf-15-");
        FillFileNameByUID(fptr, SwapEndian64(uid, sizeof(uid), 8), "-dump", sizeof(uid));
    }
    // detect blocksize from card :)

    PrintAndLogEx(SUCCESS, "Reading memory from tag UID " _YELLOW_("%s"), iso15693_sprintUID(NULL, uid));

    int blocknum = 0;
    uint8_t *recv = NULL;

    // memory.
    t15memory_t mem[256];

    uint8_t data[256 * 4] = {0};
    memset(data, 0, sizeof(data));

    PacketResponseNG resp;
    uint8_t req[13];
    req[0] = ISO15_REQ_SUBCARRIER_SINGLE | ISO15_REQ_DATARATE_HIGH | ISO15_REQ_NONINVENTORY | ISO15_REQ_ADDRESS;
    req[1] = ISO15_CMD_READ;

    // copy uid to read command
    memcpy(req + 2, uid, sizeof(uid));

    for (int retry = 0; retry < 5; retry++) {

        req[10] = blocknum;
        AddCrc15(req, 11);

        clearCommandBuffer();
        SendCommandMIX(CMD_HF_ISO15693_COMMAND, sizeof(req), 1, 1, req, sizeof(req));

        if (WaitForResponseTimeout(CMD_ACK, &resp, 2000)) {

            int len = resp.oldarg[0];
            if (len == PM3_ETEAROFF) {
                continue;
            }
            if (len < 2) {
                PrintAndLogEx(FAILED, "iso15693 command failed");
                continue;
            }

            recv = resp.data.asBytes;

            if (CheckCrc15(recv, len) == false) {
                PrintAndLogEx(FAILED, "crc (" _RED_("fail") ")");
                continue;
            }

            if ((recv[0] & ISO15_RES_ERROR) == ISO15_RES_ERROR) {
                PrintAndLogEx(FAILED, "Tag returned Error %i: %s", recv[1], TagErrorStr(recv[1]));
                break;
            }

            mem[blocknum].lock = resp.data.asBytes[0];
            memcpy(mem[blocknum].block, resp.data.asBytes + 1, 4);
            memcpy(data + (blocknum * 4), resp.data.asBytes + 1, 4);

            retry = 0;
            blocknum++;

            PrintAndLogEx(NORMAL, "." NOLF);
            fflush(stdout);
        }
    }

    DropField();

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "block#   | data         |lck| ascii");
    PrintAndLogEx(NORMAL, "---------+--------------+---+----------");
    for (int i = 0; i < blocknum; i++) {
        PrintAndLogEx(NORMAL, "%3d/0x%02X | %s | %d | %s", i, i, sprint_hex(mem[i].block, 4), mem[i].lock, sprint_ascii(mem[i].block, 4));
    }
    PrintAndLogEx(NORMAL, "\n");

    size_t datalen = blocknum * 4;
    saveFile(filename, ".bin", data, datalen);
    saveFileEML(filename, data, datalen, 4);
    saveFileJSON(filename, jsf15, data, datalen, NULL);
    return PM3_SUCCESS;
}

static int CmdHF15List(const char *Cmd) {
    char args[128] = {0};
    if (strlen(Cmd) == 0) {
        snprintf(args, sizeof(args), "-t 15");
    } else {
        strncpy(args, Cmd, sizeof(args) - 1);
    }
    return CmdTraceList(args);
}

static int CmdHF15Raw(const char *Cmd) {

    char cmdp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) < 3 || cmdp == 'h') return usage_15_raw();

    int reply = 1, fast = 1, i = 0;
    bool crc = false, keep_field_on = false;
    char buf[5] = "";
    uint8_t data[100];
    uint32_t datalen = 0, temp;

    // strip
    while (*Cmd == ' ' || *Cmd == '\t') Cmd++;

    while (Cmd[i] != '\0') {
        if (Cmd[i] == ' ' || Cmd[i] == '\t') { i++; continue; }
        if (Cmd[i] == '-') {
            switch (tolower(Cmd[i + 1])) {
                case 'r':
                    reply = 0;
                    break;
                case '2':
                    fast = 0;
                    break;
                case 'c':
                    crc = true;
                    break;
                case 'k':
                    keep_field_on = true;
                    break;
                default:
                    PrintAndLogEx(WARNING, "Invalid option");
                    return PM3_EINVARG;
            }
            i += 2;
            continue;
        }
        if ((Cmd[i] >= '0' && Cmd[i] <= '9') ||
                (Cmd[i] >= 'a' && Cmd[i] <= 'f') ||
                (Cmd[i] >= 'A' && Cmd[i] <= 'F')) {
            buf[strlen(buf) + 1] = 0;
            buf[strlen(buf)] = Cmd[i];
            i++;

            if (strlen(buf) >= 2) {
                sscanf(buf, "%x", &temp);
                data[datalen] = (uint8_t)(temp & 0xff);
                datalen++;
                *buf = 0;
            }
            continue;
        }
        PrintAndLogEx(WARNING, "Invalid char on input");
        return PM3_EINVARG;
    }

    if (crc) {
        AddCrc15(data, datalen);
        datalen += 2;
    }

    PacketResponseNG resp;
    clearCommandBuffer();
    SendCommandMIX(CMD_HF_ISO15693_COMMAND, datalen, fast, reply, data, datalen);

    if (reply) {
        if (WaitForResponseTimeout(CMD_ACK, &resp, 2000)) {
            int len = resp.oldarg[0];
            if (len == PM3_ETEAROFF) {
                DropField();
                return len;
            }
            if (len < 2) {
                PrintAndLogEx(WARNING, "command failed");
            } else {
                PrintAndLogEx(SUCCESS, "received %i octets", len);
                PrintAndLogEx(SUCCESS, "%s", sprint_hex(resp.data.asBytes, len));
            }
        } else {
            PrintAndLogEx(WARNING, "timeout while waiting for reply");
        }
    }

    if (keep_field_on == false)
        DropField();

    return PM3_SUCCESS;
}

/**
 * Commandline handling: HF15 CMD READMULTI
 * Read multiple blocks at once (not all tags support this)
 */
static int CmdHF15Readmulti(const char *Cmd) {

    char cmdp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) < 3 || cmdp == 'h') return usage_15_readmulti();

    uint8_t req[PM3_CMD_DATA_SIZE] = {0};
    uint16_t reqlen = 0;
    uint8_t fast = 1;
    uint8_t reply = 1;

    char cmdbuf[100] = {0};
    char *cmd = cmdbuf;
    strncpy(cmd, Cmd, sizeof(cmdbuf) - 1);

    if (!prepareHF15Cmd(&cmd, &reqlen, &fast, req, ISO15_CMD_READMULTI))
        return PM3_SUCCESS;

    // add OPTION flag, in order to get lock-info
    req[0] |= ISO15_REQ_OPTION;

    // decimal
    uint8_t pagenum = param_get8ex(cmd, 0, 0, 10);
    uint8_t pagecount = param_get8ex(cmd, 1, 0, 10);

    if (pagecount > 6) {
        PrintAndLogEx(WARNING, "Page count must be 6 or less (%d)", pagecount);
        return PM3_EINVARG;
    }

    // 0 means 1 page,
    // 1 means 2 pages, ...
    if (pagecount > 0) pagecount--;

    req[reqlen++] = pagenum;
    req[reqlen++] = pagecount;
    AddCrc15(req, reqlen);
    reqlen += 2;

    PacketResponseNG resp;
    clearCommandBuffer();
    SendCommandMIX(CMD_HF_ISO15693_COMMAND, reqlen, fast, reply, req, reqlen);

    if (!WaitForResponseTimeout(CMD_ACK, &resp, 2000)) {
        PrintAndLogEx(FAILED, "iso15693 card timeout");
        DropField();
        return PM3_ETIMEOUT;
    }

    DropField();

    int status = resp.oldarg[0];
    if (status == PM3_ETEAROFF) {
        return status;
    }

    if (status < 2) {
        PrintAndLogEx(FAILED, "iso15693 card readmulti failed");
        return PM3_EWRONGANSWER;
    }

    uint8_t *data = resp.data.asBytes;

    if (CheckCrc15(data, status) == false) {
        PrintAndLogEx(FAILED, "crc (" _RED_("fail") ")");
        return PM3_ESOFT;
    }

    if ((data[0] & ISO15_RES_ERROR) ==  ISO15_RES_ERROR) {
        PrintAndLogEx(FAILED, "iso15693 card returned error %i: %s", data[0], TagErrorStr(data[0]));
        return PM3_EWRONGANSWER;
    }

    // skip status byte
    int start = 1;
    int stop = (pagecount + 1) * 5;
    int currblock = pagenum;


    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "block#   | data         |lck| ascii");
    PrintAndLogEx(NORMAL, "---------+--------------+---+----------");

    for (int i = start; i < stop; i += 5) {
        PrintAndLogEx(NORMAL, "%3d/0x%02X | %s | %d | %s", currblock, currblock, sprint_hex(data + i + 1, 4), data[i], sprint_ascii(data + i + 1, 4));
        currblock++;
    }

    return PM3_SUCCESS;
}

/**
 * Commandline handling: HF15 CMD READ
 * Reads a single Block
 */
static int CmdHF15Read(const char *Cmd) {

    char cmdp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) < 3 || cmdp == 'h')  return usage_15_read();

    // arg: len, speed, recv?
    // arg0 (datalen,  cmd len?  .arg0 == crc?)
    // arg1 (speed == 0 == 1 of 256,  == 1 == 1 of 4 )
    // arg2 (recv == 1 == expect a response)
    uint8_t req[PM3_CMD_DATA_SIZE] = {0};
    uint16_t reqlen = 0;
    uint8_t fast = 1;
    uint8_t reply = 1;
    int blocknum;
    char cmdbuf[100] = {0};
    char *cmd = cmdbuf;
    strncpy(cmd, Cmd, sizeof(cmdbuf) - 1);

    if (prepareHF15Cmd(&cmd, &reqlen, &fast, req, ISO15_CMD_READ) == false)
        return PM3_SUCCESS;

    // add OPTION flag, in order to get lock-info
    req[0] |= ISO15_REQ_OPTION;

    blocknum = strtol(cmd, NULL, 0);

    req[reqlen++] = (uint8_t)blocknum;

    AddCrc15(req, reqlen);
    reqlen += 2;

    PacketResponseNG resp;
    clearCommandBuffer();
    SendCommandMIX(CMD_HF_ISO15693_COMMAND, reqlen, fast, reply, req, reqlen);

    if (!WaitForResponseTimeout(CMD_ACK, &resp, 2000)) {
        PrintAndLogEx(ERR, "iso15693 timeout");
        DropField();
        return PM3_ETIMEOUT;
    }

    DropField();

    int status = resp.oldarg[0];
    if (status == PM3_ETEAROFF) {
        return status;
    }
    if (status < 2) {
        PrintAndLogEx(ERR, "iso15693 command failed");
        return PM3_EWRONGANSWER;
    }

    uint8_t *data = resp.data.asBytes;

    if (CheckCrc15(data, status) == false) {
        PrintAndLogEx(FAILED, "crc (" _RED_("fail") ")");
        return PM3_ESOFT;
    }

    if ((data[0] & ISO15_RES_ERROR) == ISO15_RES_ERROR) {
        PrintAndLogEx(ERR, "iso15693 card returned error %i: %s", data[0], TagErrorStr(data[0]));
        return PM3_EWRONGANSWER;
    }

    // print response
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "block #%3d  |lck| ascii", blocknum);
    PrintAndLogEx(NORMAL, "------------+---+------");
    PrintAndLogEx(NORMAL, "%s| %d | %s", sprint_hex(data + 2, status - 4), data[1], sprint_ascii(data + 2, status - 4));
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}

/**
 * Commandline handling: HF15 CMD WRITE
 * Writes a single Block - might run into timeout, even when successful
 */
static int CmdHF15Write(const char *Cmd) {

    char cmdp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) < 3 || cmdp == 'h') return usage_15_write();

    uint8_t req[PM3_CMD_DATA_SIZE] = {0};
    uint16_t reqlen = 0;
    uint8_t fast = 1;
    uint8_t reply = 1;
    int pagenum, temp;

    char cmdbuf[100] = {0};
    char *cmd = cmdbuf;
    char *cmd2;

    strncpy(cmd, Cmd, sizeof(cmdbuf) - 1);

    if (prepareHF15Cmd(&cmd, &reqlen, &fast, req, ISO15_CMD_WRITE) == false)
        return PM3_SUCCESS;

    // *cmd -> page num ; *cmd2 -> data
    cmd2 = cmd;
    while (*cmd2 != ' ' && *cmd2 != '\t' && *cmd2) cmd2++;
    *cmd2 = 0;
    cmd2++;

    pagenum = strtol(cmd, NULL, 0);

    req[reqlen++] = (uint8_t)pagenum;

    while (cmd2[0] && cmd2[1]) { // hexdata, read by 2 hexchars
        if (*cmd2 == ' ') {
            cmd2++;
            continue;
        }
        sscanf((char[]) {cmd2[0], cmd2[1], 0}, "%X", &temp);
        req[reqlen++] = temp & 0xff;
        cmd2 += 2;
    }
    AddCrc15(req, reqlen);
    reqlen += 2;

    PrintAndLogEx(INFO, "iso15693 writing to page %02d (0x%02X) | data [ %s ] ", pagenum, pagenum, sprint_hex(req, reqlen));

    PacketResponseNG resp;
    clearCommandBuffer();
    SendCommandMIX(CMD_HF_ISO15693_COMMAND, reqlen, fast, reply, req, reqlen);

    if (!WaitForResponseTimeout(CMD_ACK, &resp, 2000)) {
        PrintAndLogEx(FAILED, "iso15693 card timeout, data may be written anyway");
        DropField();
        return PM3_ETIMEOUT;
    }

    DropField();

    int status = resp.oldarg[0];
    if (status == PM3_ETEAROFF) {
        return status;
    }

    if (status < 2) {
        PrintAndLogEx(FAILED, "iso15693 command failed");
        return PM3_EWRONGANSWER;
    }

    uint8_t *data = resp.data.asBytes;

    if (CheckCrc15(data, status) == false) {
        PrintAndLogEx(FAILED, "crc (" _RED_("fail") ")");
        return PM3_ESOFT;
    }

    if ((data[0] & ISO15_RES_ERROR) == ISO15_RES_ERROR) {
        PrintAndLogEx(ERR, "iso15693 card returned error %i: %s", data[0], TagErrorStr(data[0]));
        return PM3_EWRONGANSWER;
    }

    PrintAndLogEx(SUCCESS, "Write " _GREEN_("OK"));
    return PM3_SUCCESS;
}

static int CmdHF15Restore(const char *Cmd) {

    char newPrefix[60] = {0x00};
    char filename[FILE_PATH_SIZE] = {0x00};
    size_t blocksize = 4;
    uint8_t cmdp = 0, retries = 3;
    bool addressed_mode = false;

    while (param_getchar(Cmd, cmdp) != 0x00) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case '-': {
                char param[3] = "";
                param_getstr(Cmd, cmdp, param, sizeof(param));
                switch (param[1]) {
                    case '2':
                    case 'o':
                        sprintf(newPrefix, " %s", param);
                        break;
                    default:
                        PrintAndLogEx(WARNING, "11 unknown parameter " _YELLOW_("'%s'"), param);
                        return usage_15_restore();
                }
                break;
            }
            case 'f':
                param_getstr(Cmd, cmdp + 1, filename, FILE_PATH_SIZE);
                cmdp++;
                break;
            case 'r':
                retries = param_get8ex(Cmd, cmdp + 1, 3, 10);
                cmdp++;
                break;
            case 'b':
                blocksize = param_get8ex(Cmd, cmdp + 1, 4, 10);
                cmdp++;
                break;
            case 'a':
                addressed_mode = true;
                break;
            case 'h':
                return usage_15_restore();
            default:
                PrintAndLogEx(WARNING, "unknown parameter " _YELLOW_("'%c'"), param_getchar(Cmd, cmdp));
                return usage_15_restore();
        }
        cmdp++;
    }

    PrintAndLogEx(INFO, "blocksize: %zu", blocksize);

    if (!strlen(filename)) {
        PrintAndLogEx(WARNING, "please provide a filename");
        return usage_15_restore();
    }

    uint8_t uid[8] = {0x00};
    if (getUID(false, uid) == false) {
        PrintAndLogEx(WARNING, "no tag found");
        return PM3_ESOFT;
    }

    size_t datalen = 0;
    uint8_t *data = NULL;
    if (loadFile_safe(filename, ".bin", (void **)&data, &datalen) != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, "could not find file " _YELLOW_("%s"), filename);
        return PM3_EFILE;
    }

    if ((datalen % blocksize) != 0) {
        PrintAndLogEx(WARNING, "datalen %zu isn't dividable with blocksize %zu", datalen, blocksize);
        free(data);
        return PM3_ESOFT;
    }

    PrintAndLogEx(INFO, "restoring data blocks");

    int retval = PM3_SUCCESS;
    size_t bytes = 0;
    uint16_t i = 0;
    while (bytes < datalen) {

        uint8_t tried = 0;
        char hex[40] = {0x00};
        char tmpCmd[200] = {0x00};

        if (addressed_mode) {
            char uidhex[17] = {0x00};
            hex_to_buffer((uint8_t *)uidhex, uid, sizeof(uid), sizeof(uidhex) - 1, 0, false, true);
            hex_to_buffer((uint8_t *)hex, data + bytes, blocksize, sizeof(hex) - 1, 0, false, true);
            snprintf(tmpCmd, sizeof(tmpCmd), "%s %s %u %s", newPrefix, uidhex, i, hex);
        } else {
            hex_to_buffer((uint8_t *)hex, data + bytes, blocksize, sizeof(hex) - 1, 0, false, true);
            snprintf(tmpCmd, sizeof(tmpCmd), "%s u %u %s", newPrefix, i, hex);
        }

        PrintAndLogEx(DEBUG, "hf 15 write %s", tmpCmd);

        for (tried = 0; tried < retries; tried++) {
            retval = CmdHF15Write(tmpCmd);
            if (retval == false) {
                break;
            }
        }

        if (tried >= retries) {
            free(data);
            PrintAndLogEx(FAILED, "restore failed. Too many retries.");
            return retval;
        }
        bytes += blocksize;
        i++;
    }
    free(data);
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
    if (getUID(false, carduid) == false) {
        PrintAndLogEx(FAILED, "can't read card UID");
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

    if (getUID(false, carduid) == false) {
        PrintAndLogEx(FAILED, "can't read card UID");
        return PM3_ESOFT;
    }

    // reverse cardUID to compare
    uint8_t revuid[8] = {0};
    uint8_t i = 0;
    while (i < sizeof(revuid)) {
        revuid[i] = carduid[7 - i];
        i++;
    }

    if (memcmp(revuid, payload.uid, 8) != 0) {
        PrintAndLogEx(FAILED, "setting new UID (" _RED_("failed") ")");
        return PM3_ESOFT;
    } else {
        PrintAndLogEx(SUCCESS, "setting new UID (" _GREEN_("ok") ")");
        return PM3_SUCCESS;
    }
}

static command_t CommandTable[] = {
    {"-----------", CmdHF15Help,        AlwaysAvailable, "--------------------- " _CYAN_("General") " ---------------------"},
    {"help",        CmdHF15Help,        AlwaysAvailable, "This help"},
    {"list",        CmdHF15List,        AlwaysAvailable, "List ISO15693 history"},
    {"demod",       CmdHF15Demod,       AlwaysAvailable, "Demodulate ISO15693 from tag"},
    {"dump",        CmdHF15Dump,        IfPm3Iso15693,   "Read all memory pages of an ISO15693 tag, save to file"},
    {"info",        CmdHF15Info,        IfPm3Iso15693,   "Tag information"},
    {"sniff",       CmdHF15Sniff,       IfPm3Iso15693,   "Sniff ISO15693 traffic"},
    {"raw",         CmdHF15Raw,         IfPm3Iso15693,   "Send raw hex data to tag"},
    {"rdbl",        CmdHF15Read,        IfPm3Iso15693,   "Read a block"},
    {"reader",      CmdHF15Reader,      IfPm3Iso15693,   "Act like an ISO15693 reader"},
    {"readmulti",   CmdHF15Readmulti,   IfPm3Iso15693,   "Reads multiple Blocks"},
    {"restore",     CmdHF15Restore,     IfPm3Iso15693,   "Restore from file to all memory pages of an ISO15693 tag"},
    {"samples",     CmdHF15Samples,     IfPm3Iso15693,   "Acquire Samples as Reader (enables carrier, sends inquiry)"},
    {"sim",         CmdHF15Sim,         IfPm3Iso15693,   "Fake an ISO15693 tag"},
    {"wrbl",        CmdHF15Write,       IfPm3Iso15693,   "Write a block"},
    {"-----------", CmdHF15Help,        IfPm3Iso15693,  "----------------------- " _CYAN_("afi") " -----------------------"},
    {"findafi",     CmdHF15FindAfi,     IfPm3Iso15693,   "Brute force AFI of an ISO15693 tag"},
    {"writeafi",    CmdHF15WriteAfi,    IfPm3Iso15693,   "Writes the AFI on an ISO15693 tag"},
    {"writedsfid",  CmdHF15WriteDsfid,  IfPm3Iso15693,   "Writes the DSFID on an ISO15693 tag"},
    {"-----------", CmdHF15Help,        IfPm3Iso15693,  "----------------------- " _CYAN_("magic") " -----------------------"},
    {"csetuid",     CmdHF15CSetUID,     IfPm3Iso15693,   "Set UID for magic Chinese card"},
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
