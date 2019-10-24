//-----------------------------------------------------------------------------
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency NEDAP tag commands
//-----------------------------------------------------------------------------

#include "cmdlfnedap.h"

#include <string.h>

#include <ctype.h>
#include <stdlib.h>
#include "cmdparser.h"    // command_t
#include "comms.h"
#include "crc16.h"
#include "cmdlft55xx.h" // verifywrite
#include "ui.h"
#include "cmddata.h"
#include "cmdlf.h"
#include "lfdemod.h"

#define FIXED_71    0x71
#define FIXED_40    0x40
#define UNKNOWN_A   0x00
#define UNKNOWN_B   0x00

static int CmdHelp(const char *Cmd);

static int usage_lf_nedap_gen(void) {
    PrintAndLogEx(NORMAL, "generate Nedap bitstream in DemodBuffer");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage: lf nedap generate [h] [s <subtype>] c <code> i <id> [l]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "      h               : This help");
    PrintAndLogEx(NORMAL, "      s <subtype>     : optional, default=5");
    PrintAndLogEx(NORMAL, "      c <code>        : customerCode");
    PrintAndLogEx(NORMAL, "      i <id>          : ID  (max 99999)");
    PrintAndLogEx(NORMAL, "      l               : optional - long (128), default to short (64)");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "       lf nedap generate s 1 c 123 i 12345");
    return PM3_SUCCESS;
}

static int usage_lf_nedap_clone(void) {
    PrintAndLogEx(NORMAL, "clone a Nedap tag to a T55x7 tag.");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage: lf nedap clone [h] [s <subtype>] c <code> i <id> [l]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "      h               : This help");
    PrintAndLogEx(NORMAL, "      s <subtype>     : optional, default=5");
    PrintAndLogEx(NORMAL, "      c <code>        : customerCode");
    PrintAndLogEx(NORMAL, "      i <id>          : ID  (max 99999)");
    PrintAndLogEx(NORMAL, "      l               : optional - long (128), default to short (64)");
//  PrintAndLogEx(NORMAL, "      Q5              : optional - clone to Q5 (T5555) instead of T55x7 chip");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "       lf nedap clone s 1 c 123 i 12345");
    return PM3_SUCCESS;
}

static int usage_lf_nedap_sim(void) {
    PrintAndLogEx(NORMAL, "simulate Nedap card.");
    PrintAndLogEx(NORMAL, "Simulation runs until the button is pressed or another USB command is issued.");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  lf nedap sim [h] [s <subtype>] c <code> i <id> [l]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "      h               : This help");
    PrintAndLogEx(NORMAL, "      s <subtype>     : subtype, default=5");
    PrintAndLogEx(NORMAL, "      c <code>        : customerCode");
    PrintAndLogEx(NORMAL, "      i <id>          : ID  (max 99999)");
    PrintAndLogEx(NORMAL, "      l               : long (128), default to short (64)");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
// TODO proper example?
    PrintAndLogEx(NORMAL, "       lf nedap sim s 1 c 7 i 1337");
    return PM3_SUCCESS;
}

const uint8_t translateTable[10] = {8, 2, 1, 12, 4, 5, 10, 13, 0, 9};
const uint8_t invTranslateTable[16] = {8, 2, 1, 0xff, 4, 5, 0xff, 0xff, 0, 9, 6, 0xff, 3, 7, 0xff, 0xff};
const uint8_t preamble[] = {1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0}; // zero inside

static inline uint32_t bitcount(uint32_t a) {
#if defined __GNUC__
    return __builtin_popcountl(a);
#else
    a = a - ((a >> 1) & 0x55555555);
    a = (a & 0x33333333) + ((a >> 2) & 0x33333333);
    return (((a + (a >> 4)) & 0x0f0f0f0f) * 0x01010101) >> 24;
#endif
}

static uint8_t isEven_64_63(const uint8_t *data) { // 8
    return (bitcount(*(uint32_t *) data) + (bitcount((*(uint32_t *)(data + 4)) & 0xfeffffff))) & 1;
}

//NEDAP demod - ASK/Biphase (or Diphase),  RF/64 with preamble of 1111111110  (always a 128 bit data stream)
static int CmdLFNedapDemod(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far

    uint8_t data[16], buffer[7], r0, r1, r2, r3, r4, r5, idxC1, idxC2, idxC3, idxC4, idxC5, fixed0, fixed1, unk1, unk2, subtype; // 4 bits
    size_t size, offset = 0;
    uint16_t checksum, customerCode; // 12 bits
    uint32_t badgeId; // max 99999

    if (ASKbiphaseDemod("0 64 1 0", false) != PM3_SUCCESS) {
        if (g_debugMode) PrintAndLogEx(DEBUG, "DEBUG: Error - NEDAP: ASK/Biphase Demod failed");
        return PM3_ESOFT;
    }

    size = DemodBufferLen;
    if (!preambleSearch(DemodBuffer, (uint8_t *) preamble, sizeof(preamble), &size, &offset)) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - NEDAP: preamble not found");
        return PM3_ESOFT;
    }

    // set plot
    setDemodBuff(DemodBuffer, size, offset);
    setClockGrid(g_DemodClock, g_DemodStartIdx + (g_DemodClock * offset));

    // sanity checks
    if ((size != 128) && (size != 64)) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - NEDAP: Size not correct: %zu", size);
        return PM3_ESOFT;
    }

    if (bits_to_array(DemodBuffer, size, data) != PM3_SUCCESS) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - NEDAP: bits_to_array error\n");
        return PM3_ESOFT;
    }


    int ret = PM3_SUCCESS;

    // first part

    // parity 1 check
    if (isEven_64_63(data) != (data[7] & 0x01)) {
        PrintAndLogEx(ERR, "Bad parity (%1u)", data[7] & 0x01);
        ret = PM3_ESOFT;
    }

    // header 1 check
    // (1111111110 0 -- zero inside)
    if ((data[0] != 0xFF) && ((data[1] & 0xE0) != 0x80)) {
        PrintAndLogEx(ERR, "Bad header");
        ret = PM3_ESOFT;
    }

    buffer[0] = (data[0] << 7) | (data[1] >> 1);
    buffer[1] = (data[1] << 7) | (data[2] >> 1);
    buffer[2] = (data[2] << 7) | (data[3] >> 1);
    buffer[3] = ((data[4] & 0x1e) << 3) | ((data[5] & 0x1e) >> 1);
    buffer[4] = ((data[6] & 0x1e) << 3) | ((data[7] & 0x1e) >> 1);

    // CHECKSUM
    init_table(CRC_XMODEM);
    checksum = crc16_xmodem(buffer, 5);

    buffer[6] = (data[3] << 7) | ((data[4] & 0xe0) >> 1) | ((data[4] & 0x01) << 3) | ((data[5] & 0xe0) >> 5);
    buffer[5] = (data[5] << 7) | ((data[6] & 0xe0) >> 1) | ((data[6] & 0x01) << 3) | ((data[7] & 0xe0) >> 5);

    bool isValid = (checksum == *(uint16_t *)(buffer + 5));

    subtype = (data[1] & 0x1e) >> 1;
    customerCode = ((data[1] & 0x01) << 11) | (data[2] << 3) | ((data[3] & 0xe0) >> 5);

    if (isValid == false) {
        PrintAndLogEx(ERR, "Checksum : %s (calc 0x%04X != 0x%04X)", _RED_("failed"), checksum, *(uint16_t *)(buffer + 5));
        ret = PM3_ESOFT;
    }

    idxC1 = invTranslateTable[(data[3] & 0x1e) >> 1];
    idxC2 = invTranslateTable[(data[4] & 0x1e) >> 1];
    idxC3 = invTranslateTable[(data[5] & 0x1e) >> 1];
    idxC4 = invTranslateTable[(data[6] & 0x1e) >> 1];
    idxC5 = invTranslateTable[(data[7] & 0x1e) >> 1];

    // validation
    if ((idxC1 != 0xFF) && (idxC2 != 0xFF) && (idxC3 != 0xFF) && (idxC4 != 0xFF) && (idxC5 != 0xFF)) {
        r1 = idxC1;
        r2 = ((10 + idxC2) - (idxC1 + 1)) % 10;
        r3 = ((10 + idxC3) - (idxC2 + 1)) % 10;
        r4 = ((10 + idxC4) - (idxC3 + 1)) % 10;
        r5 = ((10 + idxC5) - (idxC4 + 1)) % 10;

        badgeId = r1 * 10000 + r2 * 1000 + r3 * 100 + r4 * 10 + r5;

        PrintAndLogEx(SUCCESS, "NEDAP Tag Found: Card ID "_YELLOW_("%05u")" subtype: "_YELLOW_("%1u")" customer code: "_YELLOW_("%03x"), badgeId, subtype, customerCode);
        PrintAndLogEx(SUCCESS, "Checksum is %s (0x%04X)",  _GREEN_("OK"), checksum);
        PrintAndLogEx(SUCCESS, "Raw: %s", sprint_hex(data, size / 8));
    } else {
        PrintAndLogEx(ERR, "Invalid idx (1:%02x - 2:%02x - 3:%02x - 4:%02x - 5:%02x)", idxC1, idxC2, idxC3, idxC4, idxC5);
        ret = PM3_ESOFT;
    }

    if (size > 64) {
        // second part
        PrintAndLogEx(DEBUG, "NEDAP Tag, second part found");

        if (isEven_64_63(data + 8) != (data[15] & 0x01)) {
            PrintAndLogEx(ERR, "Bad parity (%1u)", data[15] & 0x01);
            return ret;
        }

        // validation
        if ((data[8] & 0x80)
                && (data[9] & 0x40)
                && (data[10] & 0x20)
                && (data[11] & 0x10)
                && (data[12] & 0x08)
                && (data[13] & 0x04)
                && (data[14] & 0x02)) {
            PrintAndLogEx(ERR, "Bad zeros");
            return ret;
        }

        //
        r4 = (data[8] >> 3) & 0x0F;
        r5 = ((data[8] << 1) & 0x0F) | (data[9] >> 7);
        r2 = (data[9] >> 2) & 0x0F;
        r3 = ((data[9] << 2) & 0x0F) | (data[10] >> 6);
        r0 = ((data[10] >> 1) & 0x0F);
        r1 = ((data[10] << 3) & 0x0F) | (data[11] >> 5);

        fixed0 = ((data[11] << 4) & 0xF0) | (data[12] >> 4);
        fixed1 = ((data[12] << 5) & 0xE0) | (data[13] >> 3);

        unk1 = ((data[13] << 6) & 0xC0) | (data[14] >> 2);
        unk2 = ((data[14] << 7) & 0xC0) | (data[15] >> 1);

        // validation 2
        if (!r0 && (r1 < 10) && (r2 < 10) && (r3 < 10) && (r4 < 10) && (r5 < 10)) {

            badgeId = r1 * 10000 + r2 * 1000 + r3 * 100 + r4 * 10 + r5;
            PrintAndLogEx(SUCCESS, "Second Card Id " _YELLOW_("%05u"), badgeId);

            if ((fixed0 == FIXED_71) && (fixed1 == FIXED_40))
                PrintAndLogEx(DEBUG, "Fixed part {0 = 0x%02x, 1 = 0x%02x}", fixed0, fixed1);
            else
                PrintAndLogEx(DEBUG, "Bad fixed: {0 = 0x%02x (%0x02x), 1 = 0x%02x (%0x02x)}", fixed0, FIXED_71, fixed1, FIXED_40);

            PrintAndLogEx(DEBUG, "Unknown part  {1 = 0x%02x, 2 = 0x%02x}", unk1, unk2);
        } else {
            PrintAndLogEx(ERR, "Bad digits (0:%1x - 1:%1x - 2:%1x - 3:%1x - 4:%1x - 5:%1x)", r0, r1, r2, r3, r4, r5);
            return ret;
        }
    }

    return PM3_SUCCESS;
}

/* Index map                                                      E                                                                              E
 preamble    enc tag type         encrypted uid                   P d    33    d    90    d    04    d    71    d    40    d    45    d    E7    P
 1111111110 00101101000001011010001100100100001011010100110101100 1 0 00110011 0 10010000 0 00000100 0 01110001 0 01000000 0 01000101 0 11100111 1
                                                                         uid2       uid1       uid0         I          I          R           R
 1111111110 00101101000001011010001100100100001011010100110101100 1

 0 00110011
 0 10010000
 0 00000100
 0 01110001
 0 01000000
 0 01000101
 0 11100111
 1

     Tag ID is 049033
     I = Identical on all tags
     R = Random ?
     UID2, UID1, UID0 == card number


configuration
lf t55xx wr b 0 d 00170082

1) uid 049033
lf t55 wr b 1 d FF8B4168
lf t55 wr b 2 d C90B5359
lf t55 wr b 3 d 19A40087
lf t55 wr b 4 d 120115CF

2) uid 001630
lf t55 wr b 1 d FF8B6B20
lf t55 wr b 2 d F19B84A3
lf t55 wr b 3 d 18058007
lf t55 wr b 4 d 1200857C

3) uid 39feff
lf t55xx wr b 1 d ffbfa73e
lf t55xx wr b 2 d 4c0003ff
lf t55xx wr b 3 d ffbfa73e
lf t55xx wr b 4 d 4c0003ff

*/

static int CmdLFNedapRead(const char *Cmd) {
    lf_read(true, 16000);
    return CmdLFNedapDemod(Cmd);
}

static void NedapGen(uint8_t subType, uint16_t customerCode, uint32_t id, bool isLong, uint8_t *data) { // 8 or 16
    uint8_t buffer[7], r1, r2, r3, r4, r5, idxC1, idxC2, idxC3, idxC4, idxC5, i, tmp, carry, id2, id1, id0;
    uint16_t checksum;

    r1 = (uint8_t)(id / 10000);
    r2 = (uint8_t)((id % 10000) / 1000);
    r3 = (uint8_t)((id % 1000) / 100);
    r4 = (uint8_t)((id % 100) / 10);
    r5 = (uint8_t)(id % 10);

    // first part
    idxC1 = r1;
    idxC2 = (idxC1 + 1 + r2) % 10;
    idxC3 = (idxC2 + 1 + r3) % 10;
    idxC4 = (idxC3 + 1 + r4) % 10;
    idxC5 = (idxC4 + 1 + r5) % 10;

    buffer[0] = 0xc0 | (subType & 0x0F);
    buffer[1] = (customerCode & 0x0FF0) >> 4;
    buffer[2] = ((customerCode & 0x000F) << 4) | translateTable[idxC1];
    buffer[3] = (translateTable[idxC2] << 4) | translateTable[idxC3];
    buffer[4] = (translateTable[idxC4] << 4) | translateTable[idxC5];

    // checksum
    init_table(CRC_XMODEM);
    checksum = crc16_xmodem(buffer, 5);

    buffer[6] = ((checksum & 0x000F) << 4) | (buffer[4] & 0x0F);
    buffer[5] = (checksum & 0x00F0) | ((buffer[4] & 0xF0) >> 4);
    buffer[4] = ((checksum & 0x0F00) >> 4) | (buffer[3] & 0x0F);
    buffer[3] = ((checksum & 0xF000) >> 8) | ((buffer[3] & 0xF0) >> 4);

    // carry calc
    for (i = 0, carry = 0; i < sizeof(buffer); i++) {
        tmp = buffer[sizeof(buffer) - 1 - i];
        data[7 - i] = ((tmp & 0x7F) << 1) | carry;
        carry = (tmp & 0x80) >> 7;
    }
    data[0] = 0xFE | carry;
    data[7] |= isEven_64_63(data);

    // second part
    if (isLong) {
        id0 = r1;
        id1 = (r2 << 4) | r3;
        id2 = (r4 << 4) | r5;

        data[8] = (id2 >> 1);
        data[9] = ((id2 & 0x01) << 7) | (id1 >> 2);
        data[10] = ((id1 & 0x03) << 6) | (id0 >> 3);
        data[11] = ((id0 & 0x07) << 5) | (FIXED_71 >> 4);
        data[12] = ((FIXED_71 & 0x0F) << 4) | (FIXED_40 >> 5);
        data[13] = ((FIXED_40 & 0x1F) << 3) | (UNKNOWN_A >> 6);
        data[14] = ((UNKNOWN_A & 0x3F) << 2) | (UNKNOWN_B >> 7);
        data[15] = ((UNKNOWN_B & 0x7F) << 1);
        data[15] |= isEven_64_63(data + 8);
    }
}

static int (*usage_to_be_displayed)(void) = NULL;

static int CmdLfNedapGen(const char *Cmd) {
    uint8_t cmdp = 0, subType = 5, data[16], i, bin[128];
    uint16_t customerCode = 0;
    uint32_t id = 0;
    bool isLong = false, errors = false;

    int (*usage)(void) = usage_lf_nedap_gen;
    if (usage_to_be_displayed != NULL) {
        usage = usage_to_be_displayed;
        usage_to_be_displayed = NULL;
    }

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 's':
                subType = param_get8ex(Cmd, cmdp + 1, 5, 10);
                cmdp += 2;
                break;
            case 'c':
                customerCode = param_get32ex(Cmd, cmdp + 1, 0, 16);
                cmdp += 2;
                break;
            case 'i':
                id = param_get32ex(Cmd, cmdp + 1, 0, 10);
                cmdp += 2;
                break;
            case 'l':
                isLong = true;
                cmdp++;
                break;
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }
    //Validations
    if ((!customerCode) || (!id) || (subType > 0xF) || (customerCode > 0xFFF) || (id > 99999))
        errors = true;

    if (errors || cmdp == 0) {
        usage();
        return PM3_EINVARG;
    }

    PrintAndLogEx(SUCCESS,
                  "Tag - subtype: %1u , customer code: %03x , ID: %05u  | %s"
                  , subType
                  , customerCode
                  , id
                  , isLong ? "(128b)" : "(64b)"
                 );

    NedapGen(subType, customerCode, id, isLong, data);

    for (i = 0; i < (isLong ? 16 : 8); i++)
        num_to_bytebits(data[i], 8, bin + i * 8);

    setDemodBuff(bin, (isLong ? 128 : 64), 0);
    return PM3_SUCCESS;
}

static int CmdLFNedapClone(const char *Cmd) {
    uint8_t max;
    uint32_t blocks[5] = {0};

    char cmdp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) == 0 || cmdp == 'h') return usage_lf_nedap_clone();

    usage_to_be_displayed = usage_lf_nedap_clone;

    int ret = CmdLfNedapGen(Cmd);
    if (ret != PM3_SUCCESS)
        return ret;

    if ((DemodBufferLen != 128) && (DemodBufferLen != 64)) {
        PrintAndLogEx(ERR, "Error with tag bitstream generation.");
        return PM3_ESOFT;
    }

    //CmdPrintDemodBuff("x");

// What we had before in commented code:
    //NEDAP - compat mode, ASK/DIphase, data rate 64, 4 data blocks
    // DI-phase (CDP) T55x7_MODULATION_DIPHASE
//    blocks[0] = T55x7_MODULATION_DIPHASE | T55x7_BITRATE_RF_64 | 7 << T55x7_MAXBLOCK_SHIFT;
//    if (param_getchar(Cmd, 3) == 'Q' || param_getchar(Cmd, 3) == 'q')
//        blocks[0] = T5555_MODULATION_BIPHASE | T5555_INVERT_OUTPUT | T5555_SET_BITRATE(64) | 7 <<T5555_MAXBLOCK_SHIFT;

    if (DemodBufferLen == 64) {
        max = 3;
        blocks[0] = T55X7_NEDAP_64_CONFIG_BLOCK;
    } else {
        max = 5;
        blocks[0] = T55X7_NEDAP_128_CONFIG_BLOCK;
    }

    for (uint8_t i = 1; i < max ; i++) {
        blocks[i] = bytebits_to_byte(DemodBuffer + ((i - 1) * 32), 32);
    }

    PrintAndLogEx(SUCCESS, "Preparing to clone NEDAP to T55x7");
    print_blocks(blocks, max);

    int res = clone_t55xx_tag(blocks, max);
    if (res == PM3_SUCCESS) {
        PrintAndLogEx(INFO, "The block 0 was changed (eXtended) which can be hard to detect.");
        PrintAndLogEx(INFO,  " Configure it manually " _YELLOW_("`lf t55xx config b 64 d BI i 1 o 32`"));
    } else {
        PrintAndLogEx(NORMAL, "");
    }
    return res;
}

static int CmdLFNedapSim(const char *Cmd) {

    char cmdp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) == 0 || cmdp == 'h') return usage_lf_nedap_sim();

    usage_to_be_displayed = usage_lf_nedap_sim;

    int ret = CmdLfNedapGen(Cmd);
    if (ret != PM3_SUCCESS)
        return ret;

    if ((DemodBufferLen != 128) && (DemodBufferLen != 64)) {
        PrintAndLogEx(ERR, "Error with tag bitstream generation.");
        return PM3_ESOFT;
    }

    PrintAndLogEx(SUCCESS, "Simulating NEDAP - Raw");
    CmdPrintDemodBuff("x");

    // NEDAP,  Biphase = 2, clock 64, inverted,  (DIPhase == inverted BIphase)
    lf_asksim_t *payload = calloc(1, sizeof(lf_asksim_t) + DemodBufferLen);
    payload->encoding = 2;
    payload->invert = 1;
    payload->separator = 0;
    payload->clock = 64;
    memcpy(payload->data, DemodBuffer, DemodBufferLen);

    clearCommandBuffer();
    SendCommandNG(CMD_LF_ASK_SIMULATE, (uint8_t *)payload,  sizeof(lf_asksim_t) + DemodBufferLen);
    free(payload);

    PacketResponseNG resp;
    WaitForResponse(CMD_LF_ASK_SIMULATE, &resp);

    PrintAndLogEx(INFO, "Done");
    if (resp.status != PM3_EOPABORTED)
        return resp.status;

    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",     CmdHelp,         AlwaysAvailable, "This help"},
    {"demod",    CmdLFNedapDemod, AlwaysAvailable, "Demodulate Nedap tag from the GraphBuffer"},
    {"generate", CmdLfNedapGen,   AlwaysAvailable, "Generate Nedap bitstream in DemodBuffer"},
    {"read",     CmdLFNedapRead,  IfPm3Lf,         "Attempt to read and extract tag data from the antenna"},
    {"clone",    CmdLFNedapClone, IfPm3Lf,         "Clone Nedap tag to T55x7"},
    {"sim",      CmdLFNedapSim,   IfPm3Lf,         "Simulate Nedap tag"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdLFNedap(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

int demodNedap(void) {
    return CmdLFNedapDemod("");
}

