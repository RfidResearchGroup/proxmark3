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

#ifndef sprintUID
# define sprintUID(target, uid)  Iso15693sprintUID((target), (uid))
#endif
// structure and database for uid -> tagtype lookups
typedef struct {
    uint64_t uid;
    int mask; // how many MSB bits used
    const char *desc;
} productName;

const productName uidmapping[] = {

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
    //I-Code SLIX-S        [IC id = 02 + bit36 set to 1]
    //I-Code SLIX-L        [IC id = 03 + bit36 set to 1]
    { 0xE004000000000000LL, 16, "NXP Semiconductors Germany (Philips)" },
    { 0xE004010000000000LL, 24, "NXP(Philips); IC SL2 ICS20/ICS21(SLI) ICS2002/ICS2102(SLIX)" },
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

// fast method to just read the UID of a tag (collission detection not supported)
//  *buf should be large enough to fit the 64bit uid
// returns 1 if suceeded
static int getUID(uint8_t *buf) {

    PacketResponseNG resp;
    uint8_t data[5];
    data[0] = ISO15_REQ_SUBCARRIER_SINGLE | ISO15_REQ_DATARATE_HIGH | ISO15_REQ_INVENTORY | ISO15_REQINV_SLOT1;
    data[1] = ISO15_CMD_INVENTORY;
    data[2] = 0; // mask length

    AddCrc15(data, 3);

    uint8_t retry;

    // don't give up the at the first try
    for (retry = 0; retry < 3; retry++) {

        clearCommandBuffer();
        SendCommandOLD(CMD_ISO_15693_COMMAND, sizeof(data), 1, 1, data, sizeof(data));

        if (WaitForResponseTimeout(CMD_ACK, &resp, 2000)) {

            uint8_t resplen = resp.oldarg[0];
            if (resplen >= 12 && CheckCrc15(resp.data.asBytes, 12)) {
                memcpy(buf, resp.data.asBytes + 2, 8);
                return 1;
            }
        }
    } // retry

    return 0;
}

// get a product description based on the UID
// uid[8] tag uid
// returns description of the best match
static const char *getTagInfo_15(uint8_t *uid) {
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
            return "The command is not recognised";
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

static int CmdHF15Help(const char *Cmd);

static int usage_15_demod(void) {
    PrintAndLogEx(NORMAL, "Tries to demodulate / decode ISO15693, from downloaded samples.\n"
                  "Gather samples with 'hf 15 read' / 'hf 15 record'");
    return 0;
}
static int usage_15_samples(void) {
    PrintAndLogEx(NORMAL, "Acquire samples as Reader (enables carrier, send inquiry\n"
                  "and download it to graphbuffer.  Try 'hf 15 demod'  to try to demodulate/decode signal");
    return 0;
}
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
                  "\thf 15 info u");
    return 0;
}
static int usage_15_record(void) {
    PrintAndLogEx(NORMAL, "Record activity without enableing carrier");
    return 0;
}
static int usage_15_reader(void) {
    PrintAndLogEx(NORMAL, "This command identifies a ISO 15693 tag\n"
                  "\n"
                  "Usage: hf 15 reader [h]\n"
                  "Options:\n"
                  "\th             this help\n"
                  "\n"
                  "Example:\n"
                  "\thf 15 reader");
    return 0;
}
static int usage_15_sim(void) {
    PrintAndLogEx(NORMAL, "Usage:  hf 15 sim <UID>\n"
                  "\n"
                  "Example:\n"
                  "\thf 15 sim E016240000000000");
    return 0;
}
static int usage_15_findafi(void) {
    PrintAndLogEx(NORMAL, "'hf 15 finafi' This command needs a helptext. Feel free to add one!");
    return 0;
}
static int usage_15_dump(void) {
    PrintAndLogEx(NORMAL, "This command dumps the contents of a ISO-15693 tag and save it to file\n"
                  "\n"
                  "Usage: hf 15 dump [h] <f filname> \n"
                  "Options:\n"
                  "\th             this help\n"
                  "\tf <name>      filename,  if no <name> UID will be used as filename\n"
                  "\n"
                  "Example:\n"
                  "\thf 15 dump f\n"
                  "\thf 15 dump f mydump");
    return 0;
}
static int usage_15_restore(void) {
    const char *options[][2] = {
        {"h", "this help"},
        {"-2", "use slower '1 out of 256' mode"},
        {"-o", "set OPTION Flag (needed for TI)"},
        {"r <NUM>", "numbers of retries on error, default is 3"},
        {"u <UID>", "load hf-15-dump-<UID>.bin"},
        {"f <filename>", "load <filename>"},
        {"b <block size>", "block size, default is 4"}
    };
    PrintAndLogEx(NORMAL, "Usage: hf 15 restore [-2] [-o] [h] [r <NUM>] [u <UID>] [f <filename>] [b <block size>]");
    PrintAndLogOptions(options, 7, 3);
    return 0;
}
static int usage_15_raw(void) {
    const char *options[][2] = {
        {"-r", "do not read response" },
        {"-2", "use slower '1 out of 256' mode" },
        {"-c", "calculate and append CRC" },
        {"", "Tip: turn on debugging for verbose output"},
    };
    PrintAndLogEx(NORMAL, "Usage: hf 15 raw  [-r] [-2] [-c] <0A 0B 0C ... hex>\n");
    PrintAndLogOptions(options, 4, 3);
    return 0;
}
static int usage_15_read(void) {
    PrintAndLogEx(NORMAL, "Usage:  hf 15 read    [options] <uid|s|u|*> <page#>\n"
                  "Options:\n"
                  "\t-2        use slower '1 out of 256' mode\n"
                  "\tuid (either): \n"
                  "\t   <8B hex>  full UID eg E011223344556677\n"
                  "\t   u         unaddressed mode\n"
                  "\t   *         scan for tag\n"
                  "\tpage#:        page number 0-255");
    return 0;
}
static int usage_15_write(void) {
    PrintAndLogEx(NORMAL, "Usage:  hf 15 write    [options] <uid|s|u|*> <page#> <hexdata>\n"
                  "Options:\n"
                  "\t-2        use slower '1 out of 256' mode\n"
                  "\t-o        set OPTION Flag (needed for TI)\n"
                  "\tuid (either): \n"
                  "\t   <8B hex>  full UID eg E011223344556677\n"
                  "\t   u         unaddressed mode\n"
                  "\t   *         scan for tag\n"
                  "\tpage#:        page number 0-255\n"
                  "\thexdata:      data to be written eg AA BB CC DD");
    return 0;
}
static int usage_15_readmulti(void) {
    PrintAndLogEx(NORMAL, "Usage:  hf 15 readmulti  [options] <uid|s|u|*> <start#> <count#>\n"
                  "Options:\n"
                  "\t-2        use slower '1 out of 256' mode\n"
                  "\tuid (either): \n"
                  "\t   <8B hex>  full UID eg E011223344556677\n"
                  "\t   u         unaddressed mode\n"
                  "\t   *         scan for tag\n"
                  "\tstart#:       page number to start 0-255\n"
                  "\tcount#:       number of pages");
    return 0;
}

/**
 * parses common HF 15 CMD parameters and prepares some data structures
 * Parameters:
 *  **cmd   command line
 */
static int prepareHF15Cmd(char **cmd, uint16_t *reqlen, uint8_t *arg1, uint8_t *req, uint8_t iso15cmd) { // reqlen arg0
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
            return 0;
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

            if (!getUID(uid)) {
                PrintAndLogEx(WARNING, "No tag found");
                return 0;
            }
            memcpy(&req[tmpreqlen], uid, sizeof(uid));
            PrintAndLogEx(NORMAL, "Detected UID %s", sprintUID(NULL, uid));
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

            PrintAndLogEx(NORMAL, "Using UID %s", sprintUID(NULL, uid));
            memcpy(&req[tmpreqlen], uid, sizeof(uid));
            tmpreqlen +=  sizeof(uid);
            break;
    }
    // skip to next space
    while (**cmd != ' ' && **cmd != '\t')(*cmd)++;
    // skip over the space
    while (**cmd == ' ' || **cmd == '\t')(*cmd)++;

    *reqlen = tmpreqlen;
    return 1;
}

// Mode 3
//helptext
static int CmdHF15Demod(const char *Cmd) {
    char cmdp = tolower(param_getchar(Cmd, 0));
    if (cmdp == 'h') return usage_15_demod();

    // The sampling rate is 106.353 ksps/s, for T = 18.8 us
    int i, j;
    int max = 0, maxPos = 0;
    int skip = 4;

    if (GraphTraceLen < 1000) return 0;

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

    PrintAndLogEx(NORMAL, "SOF at %d, correlation %d", maxPos, max / (ARRAYLEN(FrameSOF) / skip));

    i = maxPos + ARRAYLEN(FrameSOF) / skip;
    int k = 0;
    uint8_t outBuf[20];
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
            PrintAndLogEx(NORMAL, "EOF at %d", i);
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
            PrintAndLogEx(NORMAL, "ran off end!");
            break;
        }
    }

    if (mask != 0x01) {
        PrintAndLogEx(WARNING, "Error, uneven octet! (discard extra bits!)");
        PrintAndLogEx(NORMAL, "   mask = %02x", mask);
    }
    PrintAndLogEx(NORMAL, "%d octets", k);

    for (i = 0; i < k; i++)
        PrintAndLogEx(NORMAL, "# %2d: %02x ", i, outBuf[i]);

    PrintAndLogEx(NORMAL, "CRC %04x", Crc15(outBuf, k - 2));
    return 0;
}

// * Acquire Samples as Reader (enables carrier, sends inquiry)
//helptext
static int CmdHF15Samples(const char *Cmd) {
    char cmdp = tolower(param_getchar(Cmd, 0));
    if (cmdp == 'h') return usage_15_samples();

    clearCommandBuffer();
    SendCommandNG(CMD_ACQUIRE_RAW_ADC_SAMPLES_ISO_15693, NULL, 0);

    getSamples(0, false);
    return 0;
}

/**
 * Commandline handling: HF15 CMD SYSINFO
 * get system information from tag/VICC
 */
static int CmdHF15Info(const char *Cmd) {

    char cmdp = param_getchar(Cmd, 0);
    if (strlen(Cmd) < 1 || cmdp == 'h' || cmdp == 'H') return usage_15_info();

    PacketResponseNG resp;
    uint8_t *recv;
    uint8_t req[PM3_CMD_DATA_SIZE] = {0};
    uint16_t reqlen;
    uint8_t arg1 = 1;
    char cmdbuf[100] = {0};
    char *cmd = cmdbuf;

    strncpy(cmd, Cmd, sizeof(cmdbuf) - 1);

    if (!prepareHF15Cmd(&cmd, &reqlen, &arg1, req, ISO15_CMD_SYSINFO))
        return 0;

    AddCrc15(req,  reqlen);
    reqlen += 2;

    //PrintAndLogEx(NORMAL, "cmd %s", sprint_hex(req, reqlen) );

    clearCommandBuffer();
    SendCommandOLD(CMD_ISO_15693_COMMAND, reqlen, arg1, 1, req, reqlen);

    if (!WaitForResponseTimeout(CMD_ACK, &resp, 2000)) {
        PrintAndLogEx(WARNING, "iso15693 card select failed");
        return 1;
    }

    uint32_t status = resp.oldarg[0];

    if (status < 2) {
        PrintAndLogEx(WARNING, "iso15693 card doesn't answer to systeminfo command");
        return 1;
    }

    recv = resp.data.asBytes;

    if (recv[0] & ISO15_RES_ERROR) {
        PrintAndLogEx(WARNING, "iso15693 card returned error %i: %s", recv[0], TagErrorStr(recv[0]));
        return 3;
    }

    PrintAndLogEx(NORMAL, "  UID  : %s", sprintUID(NULL, recv + 2));
    PrintAndLogEx(NORMAL, "  TYPE : %s", getTagInfo_15(recv + 2));
    PrintAndLogEx(NORMAL, "  SYSINFO : %s", sprint_hex(recv, status - 2));

    // DSFID
    if (recv[1] & 0x01)
        PrintAndLogEx(NORMAL, "     - DSFID supported        [0x%02X]", recv[10]);
    else
        PrintAndLogEx(NORMAL, "     - DSFID not supported");

    // AFI
    if (recv[1] & 0x02)
        PrintAndLogEx(NORMAL, "     - AFI   supported        [0x%02X]", recv[11]);
    else
        PrintAndLogEx(NORMAL, "     - AFI   not supported");

    // IC reference
    if (recv[1] & 0x08)
        PrintAndLogEx(NORMAL, "     - IC reference supported [0x%02X]", recv[14]);
    else
        PrintAndLogEx(NORMAL, "     - IC reference not supported");

    // memory
    if (recv[1] & 0x04) {
        PrintAndLogEx(NORMAL, "     - Tag provides info on memory layout (vendor dependent)");
        uint8_t blocks = recv[12] + 1;
        uint8_t size = (recv[13] & 0x1F);
        PrintAndLogEx(NORMAL, "           %u (or %u) bytes/blocks x %u blocks", size + 1, size, blocks);
    } else {
        PrintAndLogEx(NORMAL, "     - Tag does not provide information on memory layout");
    }
    PrintAndLogEx(NORMAL, "\n");
    return 0;
}

// Record Activity without enabeling carrier
//helptext
static int CmdHF15Record(const char *Cmd) {
    char cmdp =  tolower(param_getchar(Cmd, 0));
    if (cmdp == 'h') return usage_15_record();

    clearCommandBuffer();
    SendCommandNG(CMD_RECORD_RAW_ADC_SAMPLES_ISO_15693, NULL, 0);
    return 0;
}

static int CmdHF15Reader(const char *Cmd) {
    char cmdp = tolower(param_getchar(Cmd, 0));
    if (cmdp == 'h') return usage_15_reader();

    readHF15Uid(true);
    return 0;
}

// Simulation is still not working very good
// helptext
static int CmdHF15Sim(const char *Cmd) {
    char cmdp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) < 1 || cmdp == 'h') return usage_15_sim();

    uint8_t uid[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    if (param_gethex(Cmd, 0, uid, 16)) {
        PrintAndLogEx(WARNING, "UID must include 16 HEX symbols");
        return 0;
    }

    PrintAndLogEx(SUCCESS, "Starting simulating UID %s", sprint_hex(uid, sizeof(uid)));

    clearCommandBuffer();
    SendCommandOLD(CMD_SIMTAG_ISO_15693, 0, 0, 0, uid, 8);
    return 0;
}

// finds the AFI (Application Family Idendifier) of a card, by trying all values
// (There is no standard way of reading the AFI, allthough some tags support this)
// helptext
static int CmdHF15Afi(const char *Cmd) {
    char cmdp = tolower(param_getchar(Cmd, 0));
    if (cmdp == 'h') return usage_15_findafi();

    PrintAndLogEx(SUCCESS, "press pm3-button to cancel");

    clearCommandBuffer();
    SendCommandMIX(CMD_ISO_15693_FIND_AFI, strtol(Cmd, NULL, 0), 0, 0, NULL, 0);
    return 0;
}

typedef struct {
    uint8_t lock;
    uint8_t block[4];
} t15memory;

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

    if (!getUID(uid)) {
        PrintAndLogEx(WARNING, "No tag found.");
        return 1;
    }

    if (fileNameLen < 1) {

        PrintAndLogEx(INFO, "Using UID as filename");

        fptr += sprintf(fptr, "hf-15-");
        FillFileNameByUID(fptr, uid, "-dump", sizeof(uid));
    }
    // detect blocksize from card :)

    PrintAndLogEx(NORMAL, "Reading memory from tag UID " _YELLOW_("%s"), sprintUID(NULL, uid));

    int blocknum = 0;
    uint8_t *recv = NULL;

    // memory.
    t15memory mem[256];

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
        SendCommandOLD(CMD_ISO_15693_COMMAND, sizeof(req), 1, 1, req, sizeof(req));

        if (WaitForResponseTimeout(CMD_ACK, &resp, 2000)) {

            uint8_t len = resp.oldarg[0];
            if (len < 2) {
                PrintAndLogEx(FAILED, "iso15693 card select failed");
                continue;
            }

            recv = resp.data.asBytes;

            if (!CheckCrc15(recv, len)) {
                PrintAndLogEx(FAILED, "crc fail");
                continue;
            }

            if (recv[0] & ISO15_RES_ERROR) {
                PrintAndLogEx(FAILED, "Tag returned Error %i: %s", recv[1], TagErrorStr(recv[1]));
                break;
            }

            mem[blocknum].lock = resp.data.asBytes[0];
            memcpy(mem[blocknum].block, resp.data.asBytes + 1, 4);
            memcpy(data + (blocknum * 4), resp.data.asBytes + 1, 4);

            retry = 0;
            blocknum++;

            printf(".");
            fflush(stdout);
        }
    }
    PrintAndLogEx(NORMAL, "\n");

    PrintAndLogEx(NORMAL, "block#   | data         |lck| ascii");
    PrintAndLogEx(NORMAL, "---------+--------------+---+----------");
    for (int i = 0; i < blocknum; i++) {
        PrintAndLogEx(NORMAL, "%3d/0x%02X | %s | %d | %s", i, i, sprint_hex(mem[i].block, 4), mem[i].lock, sprint_ascii(mem[i].block, 4));
    }
    PrintAndLogEx(NORMAL, "\n");

    size_t datalen = blocknum * 4;
    saveFileEML(filename, data, datalen, 4);
    saveFile(filename, ".bin", data, datalen);
    return 0;
}

static int CmdHF15List(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    //PrintAndLogEx(WARNING, "Deprecated command, use 'hf list 15' instead");
    CmdTraceList("15");
    return 0;
}

static int CmdHF15Raw(const char *Cmd) {

    char cmdp = param_getchar(Cmd, 0);
    if (strlen(Cmd) < 3 || cmdp == 'h' || cmdp == 'H') return usage_15_raw();

    PacketResponseNG resp;
    int reply = 1, fast = 1, i = 0;
    bool crc = false;
    char buf[5] = "";
    uint8_t data[100];
    uint32_t datalen = 0, temp;

    // strip
    while (*Cmd == ' ' || *Cmd == '\t') Cmd++;

    while (Cmd[i] != '\0') {
        if (Cmd[i] == ' ' || Cmd[i] == '\t') { i++; continue; }
        if (Cmd[i] == '-') {
            switch (Cmd[i + 1]) {
                case 'r':
                case 'R':
                    reply = 0;
                    break;
                case '2':
                    fast = 0;
                    break;
                case 'c':
                case 'C':
                    crc = true;
                    break;
                default:
                    PrintAndLogEx(WARNING, "Invalid option");
                    return 0;
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
        return 0;
    }

    if (crc) {
        AddCrc15(data, datalen);
        datalen += 2;
    }

    clearCommandBuffer();
    SendCommandOLD(CMD_ISO_15693_COMMAND, datalen, fast, reply, data, datalen);

    if (reply) {
        if (WaitForResponseTimeout(CMD_ACK, &resp, 2000)) {
            uint8_t len = resp.oldarg[0];
            PrintAndLogEx(NORMAL, "received %i octets", len);
            PrintAndLogEx(NORMAL, "%s", sprint_hex(resp.data.asBytes, len));
        } else {
            PrintAndLogEx(WARNING, "timeout while waiting for reply.");
        }
    }
    return 0;
}

/**
 * Commandline handling: HF15 CMD READMULTI
 * Read multiple blocks at once (not all tags support this)
 */
static int CmdHF15Readmulti(const char *Cmd) {

    char cmdp = param_getchar(Cmd, 0);
    if (strlen(Cmd) < 3 || cmdp == 'h' || cmdp == 'H') return usage_15_readmulti();

    PacketResponseNG resp;
    uint8_t *recv;
    uint8_t req[PM3_CMD_DATA_SIZE] = {0};
    uint16_t reqlen = 0;
    uint8_t arg1 = 1;
    uint8_t pagenum, pagecount;
    char cmdbuf[100] = {0};
    char *cmd = cmdbuf;
    strncpy(cmd, Cmd, sizeof(cmdbuf) - 1);

    if (!prepareHF15Cmd(&cmd, &reqlen, &arg1, req, ISO15_CMD_READMULTI))
        return 0;

    // add OPTION flag, in order to get lock-info
    req[0] |= ISO15_REQ_OPTION;

    // decimal
    pagenum = param_get8ex(cmd, 0, 0, 10);
    pagecount = param_get8ex(cmd, 1, 0, 10);

    //PrintAndLogEx(NORMAL, "ice %d %d\n", pagenum, pagecount);

    // 0 means 1 page,
    // 1 means 2 pages, ...
    if (pagecount > 0) pagecount--;

    req[reqlen++] = pagenum;
    req[reqlen++] = pagecount;
    AddCrc15(req, reqlen);
    reqlen += 2;

    clearCommandBuffer();
    SendCommandOLD(CMD_ISO_15693_COMMAND, reqlen, arg1, 1, req, reqlen);

    if (!WaitForResponseTimeout(CMD_ACK, &resp, 2000)) {
        PrintAndLogEx(FAILED, "iso15693 card select failed");
        return 1;
    }

    uint32_t status = resp.oldarg[0];
    if (status < 2) {
        PrintAndLogEx(FAILED, "iso15693 card select failed");
        return 1;
    }

    recv = resp.data.asBytes;

    if (!CheckCrc15(recv, status)) {
        PrintAndLogEx(FAILED, "CRC failed");
        return 2;
    }

    if (recv[0] & ISO15_RES_ERROR) {
        PrintAndLogEx(FAILED, "iso15693 card returned error %i: %s", recv[0], TagErrorStr(recv[0]));
        return 3;
    }

    int start = 1;  // skip status byte
    int stop = (pagecount + 1) * 5;
    int currblock = pagenum;
    // print response
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "block#   | data         |lck| ascii");
    PrintAndLogEx(NORMAL, "---------+--------------+---+----------");
    for (int i = start; i < stop; i += 5) {
        PrintAndLogEx(NORMAL, "%3d/0x%02X | %s | %d | %s", currblock, currblock, sprint_hex(recv + i + 1, 4), recv[i], sprint_ascii(recv + i + 1, 4));
        currblock++;
    }

    return 0;
}

/**
 * Commandline handling: HF15 CMD READ
 * Reads a single Block
 */
static int CmdHF15Read(const char *Cmd) {

    char cmdp = param_getchar(Cmd, 0);
    if (strlen(Cmd) < 3 || cmdp == 'h' || cmdp == 'H')  return usage_15_read();

    PacketResponseNG resp;
    uint8_t *recv;

    // arg: len, speed, recv?
    // arg0 (datalen,  cmd len?  .arg0 == crc?)
    // arg1 (speed == 0 == 1 of 256,  == 1 == 1 of 4 )
    // arg2 (recv == 1 == expect a response)
    uint8_t req[PM3_CMD_DATA_SIZE] = {0};
    uint16_t reqlen = 0;
    uint8_t arg1 = 1;
    int blocknum;
    char cmdbuf[100] = {0};
    char *cmd = cmdbuf;
    strncpy(cmd, Cmd, sizeof(cmdbuf) - 1);

    if (!prepareHF15Cmd(&cmd, &reqlen, &arg1, req, ISO15_CMD_READ))
        return 0;

    // add OPTION flag, in order to get lock-info
    req[0] |= ISO15_REQ_OPTION;

    blocknum = strtol(cmd, NULL, 0);

    req[reqlen++] = (uint8_t)blocknum;

    AddCrc15(req, reqlen);
    reqlen += 2;

    clearCommandBuffer();
    SendCommandOLD(CMD_ISO_15693_COMMAND, reqlen, arg1, 1, req, reqlen);

    if (!WaitForResponseTimeout(CMD_ACK, &resp, 2000)) {
        PrintAndLogEx(NORMAL, "iso15693 card select failed");
        return 1;
    }

    uint32_t status = resp.oldarg[0];
    if (status < 2) {
        PrintAndLogEx(NORMAL, "iso15693 card select failed");
        return 1;
    }

    recv = resp.data.asBytes;

    if (!CheckCrc15(recv, status)) {
        PrintAndLogEx(NORMAL, "CRC failed");
        return 2;
    }

    if (recv[0] & ISO15_RES_ERROR) {
        PrintAndLogEx(WARNING, "iso15693 card returned error %i: %s", recv[0], TagErrorStr(recv[0]));
        return 3;
    }

    // print response
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "block #%3d  |lck| ascii", blocknum);
    PrintAndLogEx(NORMAL, "------------+---+------");
    PrintAndLogEx(NORMAL, "%s| %d | %s", sprint_hex(recv + 2, status - 4), recv[1], sprint_ascii(recv + 2, status - 4));
    PrintAndLogEx(NORMAL, "");
    return 0;
}

/**
 * Commandline handling: HF15 CMD WRITE
 * Writes a single Block - might run into timeout, even when successful
 */
static int CmdHF15Write(const char *Cmd) {

    char cmdp = param_getchar(Cmd, 0);
    if (strlen(Cmd) < 3 || cmdp == 'h' || cmdp == 'H') return usage_15_write();

    PacketResponseNG resp;
    uint8_t *recv;
    uint8_t req[PM3_CMD_DATA_SIZE] = {0};
    uint16_t reqlen = 0;
    uint8_t arg1 = 1;
    int pagenum, temp;
    char cmdbuf[100] = {0};
    char *cmd = cmdbuf;
    char *cmd2;

    strncpy(cmd, Cmd, sizeof(cmdbuf) - 1);

    if (!prepareHF15Cmd(&cmd, &reqlen, &arg1, req, ISO15_CMD_WRITE))
        return 0;

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

    PrintAndLogEx(NORMAL, "iso15693 writing to page %02d (0x%02X) | data ", pagenum, pagenum);

    clearCommandBuffer();
    SendCommandOLD(CMD_ISO_15693_COMMAND, reqlen, arg1, 1, req, reqlen);

    if (!WaitForResponseTimeout(CMD_ACK, &resp, 2000)) {
        PrintAndLogEx(FAILED, "iso15693 card timeout, data may be written anyway");
        return 1;
    }

    uint32_t status = resp.oldarg[0];
    if (status < 2) {
        PrintAndLogEx(FAILED, "iso15693 card select failed");
        return 1;
    }

    recv = resp.data.asBytes;

    if (!CheckCrc15(recv, status)) {
        PrintAndLogEx(FAILED, "CRC failed");
        return 2;
    }

    if (recv[0] & ISO15_RES_ERROR) {
        PrintAndLogEx(NORMAL, "iso15693 card returned error %i: %s", recv[0], TagErrorStr(recv[0]));
        return 3;
    }

    PrintAndLogEx(NORMAL, "OK");
    return 0;
}

static int CmdHF15Restore(const char *Cmd) {
    FILE *f;

    uint8_t uid[8] = {0x00};
    char filename[FILE_PATH_SIZE] = {0x00};
    char buff[255] = {0x00};
    size_t blocksize = 4;
    uint8_t cmdp = 0;
    char newCmdPrefix[FILE_PATH_SIZE + 1] = {0x00}, tmpCmd[FILE_PATH_SIZE + 262] = {0x00};
    char param[FILE_PATH_SIZE] = "";
    char hex[255] = "";
    uint8_t retries = 3, i = 0;
    int retval = 0;

    while (param_getchar(Cmd, cmdp) != 0x00) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case '-':
                param_getstr(Cmd, cmdp, param, sizeof(param));
                switch (param[1]) {
                    case '2':
                    case 'o':
                        strncpy(newCmdPrefix, " ", sizeof(newCmdPrefix) - 1);
                        strncat(newCmdPrefix, param, sizeof(newCmdPrefix) - strlen(newCmdPrefix) - 1);
                        break;
                    default:
                        PrintAndLogEx(WARNING, "Unknown parameter '%s'", param);
                        return usage_15_restore();
                }
                break;
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
            case 'u':
                param_getstr(Cmd, cmdp + 1, buff, FILE_PATH_SIZE);
                cmdp++;
                snprintf(filename, sizeof(filename), "hf-15-dump-%s-bin", buff);
                break;
            case 'h':
                return usage_15_restore();
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                return usage_15_restore();
        }
        cmdp++;
    }

    PrintAndLogEx(INFO, "Blocksize: %u", blocksize);

    if (!strlen(filename)) {
        PrintAndLogEx(WARNING, "Please provide a filename");
        return usage_15_restore();
    }

    if ((f = fopen(filename, "rb")) == NULL) {
        PrintAndLogEx(WARNING, "Could not find file %s", filename);
        return 2;
    }

    if (!getUID(uid)) {
        PrintAndLogEx(WARNING, "No tag found");
        fclose(f);
        return 3;
    }

    PrintAndLogEx(INFO, "Restoring data blocks.");

    while (1) {
        uint8_t tried = 0;
        hex[0] = 0x00;
        tmpCmd[0] = 0x00;

        size_t bytes_read = fread(buff, 1, blocksize, f);
        if (bytes_read == 0) {
            PrintAndLogEx(SUCCESS, "File reading done `%s`", filename);
            fclose(f);
            return 0;
        } else if (bytes_read != blocksize) {
            PrintAndLogEx(WARNING, "File reading error (%s), %u bytes read instead of %u bytes.", filename, bytes_read, blocksize);
            fclose(f);
            return 2;
        }

        for (int j = 0; j < blocksize; j++)
            snprintf(hex + j * 2, 3, "%02X", buff[j]);

        for (int j = 0; j < ARRAYLEN(uid); j++)
            snprintf(buff + j * 2, 3, "%02X", uid[j]);

        //TODO: Addressed mode currently not work
        //snprintf(tmpCmd, sizeof(tmpCmd), "%s %s %d %s", newCmdPrefix, buff, i, hex);
        snprintf(tmpCmd, sizeof(tmpCmd), "%s u %u %s", newCmdPrefix, i, hex);
        PrintAndLogEx(DEBUG, "Command to be sent| %s", tmpCmd);

        for (tried = 0; tried < retries; tried++) {
            if (!(retval = CmdHF15Write(tmpCmd))) {
                break;
            }
        }
        if (tried >= retries) {
            fclose(f);
            PrintAndLogEx(FAILED, "Restore failed. Too many retries.");
            return retval;
        }

        i++;
    }
    fclose(f);
    PrintAndLogEx(INFO, "Finish restore");
    return 0;
}

static command_t CommandTable[] = {
    {"help",        CmdHF15Help,        AlwaysAvailable, "This help"},
    {"demod",       CmdHF15Demod,       AlwaysAvailable, "Demodulate ISO15693 from tag"},
    {"dump",        CmdHF15Dump,        IfPm3Iso15693,   "Read all memory pages of an ISO15693 tag, save to file"},
    {"findafi",     CmdHF15Afi,         IfPm3Iso15693,   "Brute force AFI of an ISO15693 tag"},
    {"info",        CmdHF15Info,        IfPm3Iso15693,   "Tag information"},
    {"list",        CmdHF15List,        AlwaysAvailable,   "List ISO15693 history"},
    {"raw",         CmdHF15Raw,         IfPm3Iso15693,   "Send raw hex data to tag"},
    {"reader",      CmdHF15Reader,      IfPm3Iso15693,   "Act like an ISO15693 reader"},
    {"record",      CmdHF15Record,      IfPm3Iso15693,   "Record Samples (ISO15693)"},
    {"restore",     CmdHF15Restore,     IfPm3Iso15693,   "Restore from file to all memory pages of an ISO15693 tag"},
    {"sim",         CmdHF15Sim,         IfPm3Iso15693,   "Fake an ISO15693 tag"},
    {"samples",     CmdHF15Samples,     IfPm3Iso15693,   "Acquire Samples as Reader (enables carrier, sends inquiry)"},
    {"read",        CmdHF15Read,        IfPm3Iso15693,   "Read a block"},
    {"write",       CmdHF15Write,       IfPm3Iso15693,   "Write a block"},
    {"readmulti",   CmdHF15Readmulti,   IfPm3Iso15693,   "Reads multiple Blocks"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHF15Help(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return 0;
}

int CmdHF15(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

// used with 'hf search'
int readHF15Uid(bool verbose) {
    uint8_t uid[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    if (!getUID(uid)) {
        if (verbose) PrintAndLogEx(WARNING, "No tag found.");
        return 0;
    }

    PrintAndLogEx(NORMAL, " UID  : %s", sprintUID(NULL, uid));
    PrintAndLogEx(NORMAL, " TYPE : %s", getTagInfo_15(uid));
    return 1;
}
