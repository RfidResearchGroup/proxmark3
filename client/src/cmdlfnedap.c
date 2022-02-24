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
// Low frequency NEDAP tag commands
//-----------------------------------------------------------------------------

#include "cmdlfnedap.h"

#define _GNU_SOURCE
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include "cmdparser.h"    // command_t
#include "comms.h"
#include "crc16.h"
#include "cmdlft55xx.h"   // verify write
#include "ui.h"
#include "cmddata.h"
#include "cmdlf.h"
#include "lfdemod.h"
#include "protocols.h"
#include "cliparser.h"
#include "cmdlfem4x05.h"  // EM defines
#include "commonutil.h"

#define FIXED_71    0x71
#define FIXED_40    0x40
#define UNKNOWN_A   0x00
#define UNKNOWN_B   0x00

static int CmdHelp(const char *Cmd);

static const uint8_t translateTable[10] = {8, 2, 1, 12, 4, 5, 10, 13, 0, 9};
static const uint8_t invTranslateTable[16] = {8, 2, 1, 0xff, 4, 5, 0xff, 0xff, 0, 9, 6, 0xff, 3, 7, 0xff, 0xff};
static const uint8_t preamble[] = {1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0}; // zero inside

static uint8_t isEven_64_63(const uint8_t *data) { // 8
    uint32_t tmp[2];
    memcpy(tmp, data, 8);
    return (bitcount32(tmp[0]) + (bitcount32(tmp[1] & 0xfeffffff))) & 1;
}

//NEDAP demod - ASK/Biphase (or Diphase),  RF/64 with preamble of 1111111110  (always a 128 bit data stream)
int demodNedap(bool verbose) {
    (void) verbose; // unused so far
    uint8_t data[16], buffer[7], subtype; // 4 bits
    size_t size, offset = 0;
    uint16_t checksum, customerCode; // 12 bits
    uint32_t badgeId; // max 99999

    if (ASKbiphaseDemod(0, 64, 1, 0, false) != PM3_SUCCESS) {
        if (g_debugMode) PrintAndLogEx(DEBUG, "DEBUG: Error - NEDAP: ASK/Biphase Demod failed");
        return PM3_ESOFT;
    }

    size = g_DemodBufferLen;
    if (!preambleSearch(g_DemodBuffer, (uint8_t *) preamble, sizeof(preamble), &size, &offset)) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - NEDAP: preamble not found");
        return PM3_ESOFT;
    }

    // set plot
    setDemodBuff(g_DemodBuffer, size, offset);
    setClockGrid(g_DemodClock, g_DemodStartIdx + (g_DemodClock * offset));

    // sanity checks
    if ((size != 128) && (size != 64)) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - NEDAP: Size not correct: %zu", size);
        return PM3_ESOFT;
    }

    if (bits_to_array(g_DemodBuffer, size, data) != PM3_SUCCESS) {
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
    uint16_t checksum2 = (buffer[6] << 8) + buffer[5];
    bool isValid = (checksum == checksum2);

    subtype = (data[1] & 0x1e) >> 1;
    customerCode = ((data[1] & 0x01) << 11) | (data[2] << 3) | ((data[3] & 0xe0) >> 5);

    if (isValid == false) {
        PrintAndLogEx(ERR, "Checksum : %s (calc 0x%04X != 0x%04X)", _RED_("fail"), checksum, checksum2);
        ret = PM3_ESOFT;
    }

    uint8_t idxC1 = invTranslateTable[(data[3] & 0x1e) >> 1];
    uint8_t idxC2 = invTranslateTable[(data[4] & 0x1e) >> 1];
    uint8_t idxC3 = invTranslateTable[(data[5] & 0x1e) >> 1];
    uint8_t idxC4 = invTranslateTable[(data[6] & 0x1e) >> 1];
    uint8_t idxC5 = invTranslateTable[(data[7] & 0x1e) >> 1];

    // validation
    if ((idxC1 != 0xFF) && (idxC2 != 0xFF) && (idxC3 != 0xFF) && (idxC4 != 0xFF) && (idxC5 != 0xFF)) {
        uint8_t r1 = idxC1;
        uint8_t r2 = ((10 + idxC2) - (idxC1 + 1)) % 10;
        uint8_t r3 = ((10 + idxC3) - (idxC2 + 1)) % 10;
        uint8_t r4 = ((10 + idxC4) - (idxC3 + 1)) % 10;
        uint8_t r5 = ((10 + idxC5) - (idxC4 + 1)) % 10;

        badgeId = r1 * 10000 + r2 * 1000 + r3 * 100 + r4 * 10 + r5;

        PrintAndLogEx(SUCCESS, "NEDAP (%s) - ID: " _YELLOW_("%05u") " subtype: " _YELLOW_("%1u")" customer code: " _YELLOW_("%u / 0x%03X") " Raw: " _YELLOW_("%s")
                      , (size == 128) ? "128b" : "64b"
                      , badgeId
                      , subtype
                      , customerCode
                      , customerCode
                      , sprint_hex_inrow(data, size / 8)
                     );
        PrintAndLogEx(DEBUG, "Checksum ( %s ) 0x%04X",  _GREEN_("ok"), checksum);

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
        uint8_t r4 = (data[8] >> 3) & 0x0F;
        uint8_t r5 = ((data[8] << 1) & 0x0F) | (data[9] >> 7);
        uint8_t r2 = (data[9] >> 2) & 0x0F;
        uint8_t r3 = ((data[9] << 2) & 0x0F) | (data[10] >> 6);
        uint8_t r0 = ((data[10] >> 1) & 0x0F);
        uint8_t r1 = ((data[10] << 3) & 0x0F) | (data[11] >> 5);

        uint8_t fixed0 = ((data[11] << 4) & 0xF0) | (data[12] >> 4);
        uint8_t fixed1 = ((data[12] << 5) & 0xE0) | (data[13] >> 3);

        uint8_t unk1 = ((data[13] << 6) & 0xC0) | (data[14] >> 2);
        uint8_t unk2 = ((data[14] << 7) & 0xC0) | (data[15] >> 1);

        // validation 2
        if (!r0 && (r1 < 10) && (r2 < 10) && (r3 < 10) && (r4 < 10) && (r5 < 10)) {

            badgeId = r1 * 10000 + r2 * 1000 + r3 * 100 + r4 * 10 + r5;
            PrintAndLogEx(SUCCESS, "Second Card: " _YELLOW_("%05u"), badgeId);

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

static int CmdLFNedapDemod(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf nedap demod",
                  "Try to find Nedap preamble, if found decode / descramble data",
                  "lf nedap demod"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    return demodNedap(true);
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
lf t55xx wr -b 0 -d 00170082

1) uid 049033
lf t55xx wr -b 1 -d FF8B4168
lf t55xx wr -b 2 -d C90B5359
lf t55xx wr -b 3 -d 19A40087
lf t55xx wr -b 4 -d 120115CF

2) uid 001630
lf t55xx wr -b 1 -d FF8B6B20
lf t55xx wr -b 2 -d F19B84A3
lf t55xx wr -b 3 -d 18058007
lf t55xx wr -b 4 -d 1200857C

3) uid 39feff
lf t55xx wr -b 1 -d ffbfa73e
lf t55xx wr -b 2 -d 4c0003ff
lf t55xx wr -b 3 -d ffbfa73e
lf t55xx wr -b 4 -d 4c0003ff

*/

static int CmdLFNedapReader(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf nedap reader",
                  "read a Nedap tag",
                  "lf nedap reader -@   -> continuous reader mode"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("@", NULL, "optional - continuous reader mode"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool cm = arg_get_lit(ctx, 1);
    CLIParserFree(ctx);

    if (cm) {
        PrintAndLogEx(INFO, "Press " _GREEN_("<Enter>") " to exit");
    }

    do {
        lf_read(false, 16000);
        demodNedap(!cm);
    } while (cm && !kbd_enter_pressed());

    return PM3_SUCCESS;
}

static void NedapGen(uint8_t subType, uint16_t customerCode, uint32_t id, bool isLong, uint8_t *data) { // 8 or 16
    uint8_t buffer[7];

    uint8_t r1 = (uint8_t)(id / 10000);
    uint8_t r2 = (uint8_t)((id % 10000) / 1000);
    uint8_t r3 = (uint8_t)((id % 1000) / 100);
    uint8_t r4 = (uint8_t)((id % 100) / 10);
    uint8_t r5 = (uint8_t)(id % 10);

    // first part
    uint8_t idxC1 = r1;
    uint8_t idxC2 = (idxC1 + 1 + r2) % 10;
    uint8_t idxC3 = (idxC2 + 1 + r3) % 10;
    uint8_t idxC4 = (idxC3 + 1 + r4) % 10;
    uint8_t idxC5 = (idxC4 + 1 + r5) % 10;

    buffer[0] = 0xc0 | (subType & 0x0F);
    buffer[1] = (customerCode & 0x0FF0) >> 4;
    buffer[2] = ((customerCode & 0x000F) << 4) | translateTable[idxC1];
    buffer[3] = (translateTable[idxC2] << 4) | translateTable[idxC3];
    buffer[4] = (translateTable[idxC4] << 4) | translateTable[idxC5];

    // checksum
    init_table(CRC_XMODEM);
    uint16_t checksum = crc16_xmodem(buffer, 5);

    buffer[6] = ((checksum & 0x000F) << 4) | (buffer[4] & 0x0F);
    buffer[5] = (checksum & 0x00F0) | ((buffer[4] & 0xF0) >> 4);
    buffer[4] = ((checksum & 0x0F00) >> 4) | (buffer[3] & 0x0F);
    buffer[3] = ((checksum & 0xF000) >> 8) | ((buffer[3] & 0xF0) >> 4);

    // carry calc
    uint8_t carry = 0;
    for (uint8_t i = 0; i < sizeof(buffer); i++) {
        uint8_t tmp = buffer[sizeof(buffer) - 1 - i];
        data[7 - i] = ((tmp & 0x7F) << 1) | carry;
        carry = (tmp & 0x80) >> 7;
    }
    data[0] = 0xFE | carry;
    data[7] |= isEven_64_63(data);

    // second part
    if (isLong) {
        uint8_t id0 = r1;
        uint8_t id1 = (r2 << 4) | r3;
        uint8_t id2 = (r4 << 4) | r5;

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

static int CmdLFNedapClone(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf nedap clone",
                  "clone a Nedap tag to a T55x7, Q5/T5555 or EM4305/4469 tag.",
                  "lf nedap clone --st 1 --cc 101 --id 1337"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_u64_0(NULL, "st", "<dec>", "optional - sub type (default 5)"),
        arg_u64_1(NULL, "cc", "<dec>", "customer code (0-4095)"),
        arg_u64_1(NULL, "id", "<dec>", "ID (0-99999)"),
        arg_lit0("l", "long", "optional - long (128), default to short (64)"),
        arg_lit0(NULL, "q5", "optional - specify writing to Q5/T5555 tag"),
        arg_lit0(NULL, "em", "optional - specify writing to EM4305/4469 tag"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    uint8_t sub_type = arg_get_u32_def(ctx, 1, 5);
    uint16_t customer_code = arg_get_u32_def(ctx, 2, 0);
    uint32_t id = arg_get_u32_def(ctx, 3, 0);
    bool is_long = arg_get_lit(ctx, 4);
    bool q5 = arg_get_lit(ctx, 5);
    bool em = arg_get_lit(ctx, 6);
    CLIParserFree(ctx);

    // Validations
    if (q5 && em) {
        PrintAndLogEx(FAILED, "Can't specify both Q5 and EM4305 at the same time");
        return PM3_EINVARG;
    }
    if (sub_type > 0xF) {
        PrintAndLogEx(FAILED, "out-of-range, valid subtype is between 0-15");
        return PM3_EINVARG;
    }

    if (customer_code > 0xFFF) {
        PrintAndLogEx(FAILED, "out-of-range, valid customer code is between 0-4095");
        return PM3_EINVARG;
    }

    if (id > 99999) {
        PrintAndLogEx(FAILED, "out-of-range, id max value is 99999");
        return PM3_EINVARG;
    }

    PrintAndLogEx(SUCCESS, "NEDAP (%s) - ID: " _GREEN_("%05u") " subtype: " _GREEN_("%1u") " customer code: " _GREEN_("%u / 0x%03X")
                  , is_long ? "128b" : "64b"
                  , id
                  , sub_type
                  , customer_code
                  , customer_code
                 );


    //NEDAP - compat mode, ASK/DIphase, data rate 64, 4 data blocks
    // DI-phase (CDP) T55x7_MODULATION_DIPHASE
    uint8_t max;
    uint32_t blocks[5] = {0};
    if (is_long) {
        max = 5;
        blocks[0] = T55X7_NEDAP_128_CONFIG_BLOCK;
    } else {
        max = 3;
        blocks[0] = T55X7_NEDAP_64_CONFIG_BLOCK;
    }
    char cardtype[16] = {"T55x7"};

    // Q5
    if (q5) {
        if (is_long) {
            blocks[0] = T5555_FIXED | T5555_MODULATION_BIPHASE | T5555_INVERT_OUTPUT | T5555_SET_BITRATE(64) | 4 << T5555_MAXBLOCK_SHIFT;
        } else {
            blocks[0] = T5555_FIXED | T5555_MODULATION_BIPHASE | T5555_INVERT_OUTPUT | T5555_SET_BITRATE(64) | 2 << T5555_MAXBLOCK_SHIFT;
        }
    }

    // EM4305
    if (em) {
        if (is_long) {
            blocks[0] = EM4305_NEDAP_128_CONFIG_BLOCK;
        } else {
            blocks[0] = EM4305_NEDAP_64_CONFIG_BLOCK;
        }
        snprintf(cardtype, sizeof(cardtype), "EM4305/4469");
    }

    // generate nedap bitstream
    uint8_t data[16];
    NedapGen(sub_type, customer_code, id, is_long, data);

    for (uint8_t i = 1; i < max ; i++) {
        blocks[i] = bytes_to_num(data + ((i - 1) * 4), 4);
    }

    PrintAndLogEx(SUCCESS, "Preparing to clone NEDAP to " _YELLOW_("%s") " tag", cardtype);
    print_blocks(blocks, max);

    int res;
    if (em) {
        res = em4x05_clone_tag(blocks, ARRAYLEN(blocks), 0, false);
    } else {
        res = clone_t55xx_tag(blocks, ARRAYLEN(blocks));
    }

    if (res == PM3_SUCCESS) {
        PrintAndLogEx(INFO, "The block 0 was changed (eXtended) which can be hard to detect.");
        PrintAndLogEx(INFO,  "Configure it manually " _YELLOW_("`lf t55xx config --rate 64 --BI -i -o 32`"));
    } else {
        PrintAndLogEx(NORMAL, "");
    }
    PrintAndLogEx(SUCCESS, "Done");
    PrintAndLogEx(HINT, "Hint: try " _YELLOW_("`lf nedap reader`") " to verify");
    return res;
}

static int CmdLFNedapSim(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf nedap sim",
                  "Enables simulation of NEDAP card with specified card number.\n"
                  "Simulation runs until the button is pressed or another USB command is issued.",
                  "lf nedap sim --st 1 --cc 101 --id 1337"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_u64_0(NULL, "st", "<dec>", "optional - sub type (default 5)"),
        arg_u64_1(NULL, "cc", "<dec>", "customer code (0-4095)"),
        arg_u64_1(NULL, "id", "<dec>", "ID (0-99999)"),
        arg_lit0("l", "long", "optional - long (128), default to short (64)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    uint8_t sub_type = arg_get_u32_def(ctx, 1, 5);
    uint16_t customer_code = arg_get_u32_def(ctx, 2, 0);
    uint32_t id = arg_get_u32_def(ctx, 3, 0);
    bool is_long = arg_get_lit(ctx, 4);
    CLIParserFree(ctx);

    if (sub_type > 0xF) {
        PrintAndLogEx(FAILED, "out-of-range, valid subtype is between 0-15");
        return PM3_EINVARG;
    }

    if (customer_code > 0xFFF) {
        PrintAndLogEx(FAILED, "out-of-range, valid customer code is between 0-4095");
        return PM3_EINVARG;
    }

    if (id > 99999) {
        PrintAndLogEx(FAILED, "out-of-range, id max value is 99999");
        return PM3_EINVARG;
    }

    PrintAndLogEx(SUCCESS, "NEDAP (%s) - ID: " _GREEN_("%05u") " subtype: " _GREEN_("%1u") " customer code: " _GREEN_("%u / 0x%03X")
                  , is_long ? "128b" : "64b"
                  , id
                  , sub_type
                  , customer_code
                  , customer_code
                 );

    // generate nedap bitstream
    uint8_t max = (is_long) ? 16 : 8;
    uint8_t data[16];
    NedapGen(sub_type, customer_code, id, is_long, data);

    uint8_t bs[16 * 8];
    for (uint8_t i = 0; i < max; i++) {
        num_to_bytebits(data[i], 8, bs + i * 8);
    }

    PrintAndLogEx(SUCCESS, "Simulating NEDAP - Raw: " _YELLOW_("%s"), sprint_hex_inrow(data, max));

    // NEDAP,  Biphase = 2, clock 64, inverted,  (DIPhase == inverted BIphase)
    lf_asksim_t *payload = calloc(1, sizeof(lf_asksim_t) + g_DemodBufferLen);
    payload->encoding = 2;
    payload->invert = 1;
    payload->separator = 0;
    payload->clock = 64;
    memcpy(payload->data, bs, (max  *  8));

    clearCommandBuffer();
    SendCommandNG(CMD_LF_ASK_SIMULATE, (uint8_t *)payload,  sizeof(lf_asksim_t) + g_DemodBufferLen);
    free(payload);

    PacketResponseNG resp;
    WaitForResponse(CMD_LF_ASK_SIMULATE, &resp);

    PrintAndLogEx(INFO, "Done");
    if (resp.status != PM3_EOPABORTED)
        return resp.status;

    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",   CmdHelp,          AlwaysAvailable, "This help"},
    {"demod",  CmdLFNedapDemod,  AlwaysAvailable, "demodulate Nedap tag from the GraphBuffer"},
    {"reader", CmdLFNedapReader, IfPm3Lf,         "attempt to read and extract tag data"},
    {"clone",  CmdLFNedapClone,  IfPm3Lf,         "clone Nedap tag to T55x7 or Q5/T5555"},
    {"sim",    CmdLFNedapSim,    IfPm3Lf,         "simulate Nedap tag"},
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
