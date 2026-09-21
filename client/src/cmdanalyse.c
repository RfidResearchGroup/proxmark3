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
// Analyse bytes commands
//-----------------------------------------------------------------------------
#include "cmdanalyse.h"

#include <stdlib.h>       // size_t
#include <string.h>
#include <ctype.h>        // tolower
#include <math.h>
#include <time.h>
#include <inttypes.h>     // PRIx64 macro
#include "commonutil.h"   // reflect...
#include "comms.h"        // clearCommandBuffer
#include "cmdparser.h"    // command_t
#include "ui.h"           // PrintAndLog
#include "crc.h"
#include "crc16.h"        // crc16 ccitt
#include "crc32.h"        // crc32_ex
#include "legic_prng.h"
#include "cmddata.h"      // g_DemodBuffer
#include "graph.h"
#include "proxgui.h"
#include "cliparser.h"
#include "generator.h"    // generate nuid
#include "iso14b.h"       // defines for ETU conversions
#include "util.h"         // regex utility

static int CmdHelp(const char *Cmd);

static uint8_t calculateLRC(const uint8_t *d, uint8_t n) {
    uint8_t lrc = 0;
    for (uint8_t i = 0; i < n; i++)
        lrc ^= d[i];
    return lrc;
}
/*
static uint16_t matrixadd ( uint8_t* bytes, uint8_t len){
      -----------
 0x9c | 1001 1100
 0x97 | 1001 0111
 0x72 | 0111 0010
 0x5e | 0101 1110
 -----------------
        C32F 9d74

    return 0;
}
*/
/*
static uint16_t shiftadd ( uint8_t* bytes, uint8_t len){
    return 0;
}
*/
static uint16_t calcSumCrumbAdd(const uint8_t *bytes, uint8_t len, uint32_t mask) {
    uint32_t sum = 0;
    for (uint8_t i = 0; i < len; i++) {
        sum += CRUMB(bytes[i], 0);
        sum += CRUMB(bytes[i], 2);
        sum += CRUMB(bytes[i], 4);
        sum += CRUMB(bytes[i], 6);
    }
    sum &= mask;
    return (sum & 0xFFFF);
}
static uint16_t calcSumCrumbAddOnes(const uint8_t *bytes, uint8_t len, uint32_t mask) {
    return (~calcSumCrumbAdd(bytes, len, mask) & mask);
}
static uint16_t calcSumNibbleAdd(const uint8_t *bytes, uint8_t len, uint32_t mask) {
    uint32_t sum = 0;
    for (uint8_t i = 0; i < len; i++) {
        sum += NIBBLE_LOW(bytes[i]);
        sum += NIBBLE_HIGH(bytes[i]);
    }
    sum &= mask;
    return (sum & 0xFFFF);
}
static uint16_t calcSumNibbleAddOnes(uint8_t *bytes, uint8_t len, uint32_t mask) {
    return (~calcSumNibbleAdd(bytes, len, mask) & mask);
}
static uint16_t calcSumCrumbXor(const uint8_t *bytes, uint8_t len, uint32_t mask) {
    uint32_t sum = 0;
    for (uint8_t i = 0; i < len; i++) {
        sum ^= CRUMB(bytes[i], 0);
        sum ^= CRUMB(bytes[i], 2);
        sum ^= CRUMB(bytes[i], 4);
        sum ^= CRUMB(bytes[i], 6);
    }
    sum &= mask;
    return (sum & 0xFFFF);
}
static uint16_t calcSumNibbleXor(const uint8_t *bytes, uint8_t len, uint32_t mask) {
    uint32_t sum = 0;
    for (uint8_t i = 0; i < len; i++) {
        sum ^= NIBBLE_LOW(bytes[i]);
        sum ^= NIBBLE_HIGH(bytes[i]);
    }
    sum &= mask;
    return (sum & 0xFFFF);
}
static uint16_t calcSumByteXor(const uint8_t *bytes, uint8_t len, uint32_t mask) {
    uint32_t sum = 0;
    for (uint8_t i = 0; i < len; i++) {
        sum ^= bytes[i];
    }
    sum &= mask;
    return (sum & 0xFFFF);
}
static uint16_t calcSumByteAdd(const uint8_t *bytes, uint8_t len, uint32_t mask) {
    uint32_t sum = 0;
    for (uint8_t i = 0; i < len; i++) {
        sum += bytes[i];
    }
    sum &= mask;
    return (sum & 0xFFFF);
}
// Ones complement
static uint16_t calcSumByteAddOnes(uint8_t *bytes, uint8_t len, uint32_t mask) {
    return (~calcSumByteAdd(bytes, len, mask) & mask);
}

static uint16_t calcSumByteSub(const uint8_t *bytes, uint8_t len, uint32_t mask) {
    uint32_t sum = 0;
    for (uint8_t i = 0; i < len; i++) {
        sum -= bytes[i];
    }
    sum &= mask;
    return (sum & 0xFFFF);
}
static uint16_t calcSumByteSubOnes(uint8_t *bytes, uint8_t len, uint32_t mask) {
    return (~calcSumByteSub(bytes, len, mask) & mask);
}
static uint16_t calcSumNibbleSub(const uint8_t *bytes, uint8_t len, uint32_t mask) {
    uint32_t sum = 0;
    for (uint8_t i = 0; i < len; i++) {
        sum -= NIBBLE_LOW(bytes[i]);
        sum -= NIBBLE_HIGH(bytes[i]);
    }
    sum &= mask;
    return (sum & 0xFFFF);
}
static uint16_t calcSumNibbleSubOnes(uint8_t *bytes, uint8_t len, uint32_t mask) {
    return (~calcSumNibbleSub(bytes, len, mask) & mask);
}

// BSD shift checksum 8bit version
static uint16_t calcBSDchecksum8(const uint8_t *bytes, uint8_t len, uint32_t mask) {
    uint32_t sum = 0;
    for (uint8_t i = 0; i < len; i++) {
        sum = ((sum & 0xFF) >> 1) | ((sum & 0x1) << 7);   // rotate accumulator
        sum += bytes[i];  // add next byte
        sum &= 0xFF;  //
    }
    sum &= mask;
    return (sum & 0xFFFF);
}
// BSD shift checksum 4bit version
static uint16_t calcBSDchecksum4(const uint8_t *bytes, uint8_t len, uint32_t mask) {
    uint32_t sum = 0;
    for (uint8_t i = 0; i < len; i++) {
        sum = ((sum & 0xF) >> 1) | ((sum & 0x1) << 3);   // rotate accumulator
        sum += NIBBLE_HIGH(bytes[i]);  // add high nibble
        sum &= 0xF;  //
        sum = ((sum & 0xF) >> 1) | ((sum & 0x1) << 3);   // rotate accumulator
        sum += NIBBLE_LOW(bytes[i]);  // add low nibble
        sum &= 0xF;  //
    }
    sum &= mask;
    return (sum & 0xFFFF);
}

// 0xFF - ( n1 ^ n... )
static uint16_t calcXORchecksum(uint8_t *bytes, uint8_t len, uint32_t mask) {
    return 0xFF - calcSumByteXor(bytes, len, mask);
}

//2148050707DB0A0E000001C4000000
// measuring LFSR maximum length
static int CmdAnalyseLfsr(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "analyse lfsr",
                  "looks at LEGIC Prime's lfsr,  iterates the first 48 values",
                  "analyse lfsr --iv 55"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1(NULL, "iv", "<hex>", "init vector data (1 hex byte)"),
        arg_str0(NULL, "find", "<hex>", "lfsr data to find (1 hex byte)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    int iv_len = 0;
    uint8_t idata[1] = {0};
    int res = CLIParamHexToBuf(arg_get_str(ctx, 1), idata, sizeof(idata), &iv_len);

    if (res) {
        CLIParserFree(ctx);
        PrintAndLogEx(FAILED, "Error parsing IV byte");
        return PM3_EINVARG;
    }

    int f_len = 0;
    uint8_t fdata[1] = {0};
    res = CLIParamHexToBuf(arg_get_str(ctx, 2), fdata, sizeof(fdata), &f_len);
    CLIParserFree(ctx);

    if (res) {
        PrintAndLogEx(FAILED, "Error parsing FIND byte");
        return PM3_EINVARG;
    }

    uint8_t iv = idata[0];
    uint8_t find = fdata[0];

    PrintAndLogEx(INFO, "LEGIC Prime lfsr");
    PrintAndLogEx(INFO, "iv..... 0x%02X", iv);
    PrintAndLogEx(INFO, "----+------+-------+--------------");
    PrintAndLogEx(INFO, " i# | lfsr | ^0x40 |  0x%02X ^ lfsr", find);
    PrintAndLogEx(INFO, "----+------+-------+--------------");

    for (uint8_t i = 0x01; i < 0x30; i += 1) {
        legic_prng_init(iv);
        legic_prng_forward(i);
        uint32_t lfsr = legic_prng_get_bits(12);  /* Any nonzero start state will work. */
        PrintAndLogEx(INFO, " %02X |  %03X |  %03X  | %03X", i, lfsr, 0x40 ^ lfsr, find ^ lfsr);
    }
    PrintAndLogEx(INFO, "----+------+-------+--------------");
    return PM3_SUCCESS;
}

static int CmdAnalyseLRC(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "analyse lrc",
                  "Specifying the bytes of a UID with a known LRC will find the last byte value\n"
                  "needed to generate that LRC with a rolling XOR. All bytes should be specified in HEX.",
                  "analyse lrc -d 04008064BA     ->  Target (BA) requires final LRC XOR byte value: 5A"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1("d", "data", "<hex>", "bytes to calc missing XOR in a LRC"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    int dlen = 0;
    uint8_t data[100] = {0x00};
    int res = CLIParamHexToBuf(arg_get_str(ctx, 1), data, sizeof(data), &dlen);
    CLIParserFree(ctx);

    if (res) {
        PrintAndLogEx(FAILED, "Error parsing bytes");
        return PM3_EINVARG;
    }

    uint8_t finalXor = calculateLRC(data, (uint8_t)dlen);
    PrintAndLogEx(SUCCESS, "Target [%02X] requires final LRC XOR byte value: " _YELLOW_("0x%02X"), data[dlen - 1], finalXor);
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}

static int CmdAnalyseCRC(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "analyse crc",
                  "A stub method to test different crc implementations inside the PM3 sourcecode.\n"
                  "Just because you figured out the poly, doesn't mean you get the desired output",
                  "analyse crc -d 137AF00A0A0D"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1("d", "data", "<hex>", "bytes to calc crc"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    int dlen = 0;
    uint8_t data[1024] = {0x00};
    int res = CLIParamHexToBuf(arg_get_str(ctx, 1), data, sizeof(data), &dlen);
    CLIParserFree(ctx);

    if (res) {
        PrintAndLogEx(FAILED, "Error parsing bytes");
        return PM3_EINVARG;
    }

    PrintAndLogEx(INFO, "\nTests with (%d) | %s", dlen, sprint_hex(data, (size_t)dlen));

    // 51  f5  7a  d6
    uint8_t uid[] = {0x51, 0xf5, 0x7a, 0xd6}; //12 34 56
    init_table(CRC_LEGIC);
    uint8_t legic8 = CRC8Legic(uid, sizeof(uid)) & 0xFF;
    PrintAndLogEx(INFO, "Legic 16 | %X (EF6F expected) [legic8 = %02x]", crc16_legic(data, (size_t)dlen, legic8), legic8);
    init_table(CRC_FELICA);
    PrintAndLogEx(INFO, "FeliCa | %X ", crc16_xmodem(data, (size_t)dlen));

    PrintAndLogEx(INFO, "\nTests of reflection. Current methods in source code");
    PrintAndLogEx(INFO, "   reflect(0x3e23L,3) is %04X == 0x3e26", reflect(0x3e23L, 3));
    PrintAndLogEx(INFO, "       reflect8(0x80) is %02X == 0x01", reflect8(0x80));
    PrintAndLogEx(INFO, "    reflect16(0x8000) is %04X == 0x0001", reflect16(0xc6c6));

    uint8_t b1 = 0, b2 = 0;
    // ISO14443 crc B
    compute_crc(CRC_14443_B, data, (size_t)dlen, &b1, &b2);
    uint16_t crcBB_1 = (uint16_t)(b1 << 8 | b2);
    uint16_t bbb = Crc16ex(CRC_14443_B, data, (size_t)dlen);
    PrintAndLogEx(INFO, "ISO14443 crc B  | %04x == %04x \n", crcBB_1, bbb);


    // Test of CRC16,  '123456789' string.
    //

    PrintAndLogEx(INFO, "\n\nStandard test with 31 32 33 34 35 36 37 38 39  '123456789'\n\n");
    uint8_t dataStr[] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39 };
    legic8 = CRC8Legic(dataStr, sizeof(dataStr)) & 0xFF;

    //these below has been tested OK.
    PrintAndLogEx(INFO, "Confirmed CRC Implementations");
    PrintAndLogEx(INFO, "-------------------------------------\n");
    PrintAndLogEx(INFO, "CRC 8 based\n\n");
    PrintAndLogEx(INFO, "LEGIC: CRC8 : %X (C6 expected)", legic8);
    PrintAndLogEx(INFO, "MAXIM: CRC8 : %X (A1 expected)", CRC8Maxim(dataStr, sizeof(dataStr)));
    PrintAndLogEx(INFO, "-------------------------------------\n");
    PrintAndLogEx(INFO, "CRC16 based\n\n");

    // input from commandline
    PrintAndLogEx(INFO, "CCITT  | %X (29B1 expected)", Crc16ex(CRC_CCITT, dataStr, sizeof(dataStr)));

    uint8_t poll[] = {0xb2, 0x4d, 0x12, 0x01, 0x01, 0x2e, 0x3d, 0x17, 0x26, 0x47, 0x80, 0x95, 0x00, 0xf1, 0x00, 0x00, 0x00, 0x01, 0x43, 0x00, 0xb3, 0x7f};
    PrintAndLogEx(INFO, "FeliCa | %04X (B37F expected)", Crc16ex(CRC_FELICA, poll + 2, sizeof(poll) - 4));
    PrintAndLogEx(INFO, "FeliCa | %04X (0000 expected)", Crc16ex(CRC_FELICA, poll + 2, sizeof(poll) - 2));

    uint8_t sel_corr[] = { 0x40, 0xe1, 0xe1, 0xff, 0xfe, 0x5f, 0x02, 0x3c, 0x43, 0x01};
    PrintAndLogEx(INFO, "iCLASS | %04x (0143 expected)", Crc16ex(CRC_ICLASS, sel_corr, sizeof(sel_corr) - 2));
    PrintAndLogEx(INFO, "---------------------------------------------------------------\n\n\n");

    // ISO14443 crc A
    compute_crc(CRC_14443_A, dataStr, sizeof(dataStr), &b1, &b2);
    uint16_t crcAA = (uint16_t)(b1 << 8 | b2);
    PrintAndLogEx(INFO, "ISO14443 crc A  | %04x or %04x (BF05 expected)\n", crcAA, Crc16ex(CRC_14443_A, dataStr, sizeof(dataStr)));

    // ISO14443 crc B
    compute_crc(CRC_14443_B, dataStr, sizeof(dataStr), &b1, &b2);
    uint16_t crcBB = (uint16_t)(b1 << 8 | b2);
    PrintAndLogEx(INFO, "ISO14443 crc B  | %04x or %04x (906E expected)\n", crcBB, Crc16ex(CRC_14443_B, dataStr, sizeof(dataStr)));

    // ISO15693 crc  (x.25)
    compute_crc(CRC_15693, dataStr, sizeof(dataStr), &b1, &b2);
    uint16_t crcCC = (uint16_t)(b1 << 8 | b2);
    PrintAndLogEx(INFO, "ISO15693 crc X25| %04x or %04x (906E expected)\n", crcCC, Crc16ex(CRC_15693, dataStr, sizeof(dataStr)));

    // ICLASS
    compute_crc(CRC_ICLASS, dataStr, sizeof(dataStr), &b1, &b2);
    uint16_t crcDD = (uint16_t)(b1 << 8 | b2);
    PrintAndLogEx(INFO, "ICLASS crc      | %04x or %04x\n", crcDD, Crc16ex(CRC_ICLASS, dataStr, sizeof(dataStr)));

    // FeliCa
    compute_crc(CRC_FELICA, dataStr, sizeof(dataStr), &b1, &b2);
    uint16_t crcEE = (uint16_t)(b1 << 8 | b2);
    PrintAndLogEx(INFO, "FeliCa          | %04x or %04x (31C3 expected)\n", crcEE, Crc16ex(CRC_FELICA, dataStr, sizeof(dataStr)));


    uint32_t crc32 = 0;
    crc32_ex(dataStr, sizeof(dataStr), (uint8_t *)&crc32);
    PrintAndLogEx(INFO, "CRC32 (desfire) | %08x ( expected)", crc32);
    PrintAndLogEx(INFO, "---------------------------------------------------------------\n\n\n");

    return PM3_SUCCESS;
}

static int CmdAnalyseCHKSUM(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "analyse chksum",
                  "The bytes will be added with eachother and than limited with the applied mask\n"
                  "Finally compute ones' complement of the least significant bytes.",
                  "analyse chksum -d 137AF00A0A0D     ->  expected output: 0x61\n"
                  "analyse chksum -d 137AF00A0A0D -m FF"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1("d", "data", "<hex>", "bytes to calc checksum"),
        arg_str0("m", "mask", "<hex>", "bit mask to limit the output (4 hex bytes max)"),
        arg_lit0("v", "verbose", "verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    int dlen = 0;
    uint8_t data[100] = {0x00};
    memset(data, 0x0, sizeof(data));
    int res = CLIParamHexToBuf(arg_get_str(ctx, 1), data, sizeof(data), &dlen);
    if (res) {
        CLIParserFree(ctx);
        PrintAndLogEx(FAILED, "Error parsing bytes");
        return PM3_EINVARG;
    }
    const char *m = arg_get_str(ctx, 2)->sval[0];
    bool verbose = arg_get_lit(ctx, 3);
    CLIParserFree(ctx);

    size_t mlen = 0;
    if (m)
        mlen = strlen(m);

    if (mlen > 8) {
        PrintAndLogEx(FAILED, "Mask value is max 4 hex bytes");
        return PM3_EINVARG;
    }

    uint16_t mask = 0;
    if (mlen == 0) {
        mask = 0xFFFF;
    } else {
        for (size_t i = 0; i < mlen; i++) {
            char c = m[i];
            // capitalize
            if (c >= 'a' && c <= 'f')
                c -= 32;
            // convert to numeric value
            if (c >= '0' && c <= '9')
                c -= '0';
            else if (c >= 'A' && c <= 'F')
                c -= 'A' - 10;
            else
                continue;

            mask <<= 4;
            mask |= (uint8_t)c;
        }
    }

    PrintAndLogEx(INFO, "Mask value 0x%x", mask);

    if (verbose) {
        PrintAndLogEx(INFO, "------------------+-------------+------------------+-----------------+------------------+-----------+-------------");
        PrintAndLogEx(INFO, "     add          | sub         | add 1's compl    | sub 1's compl   | xor              |           |");
        PrintAndLogEx(INFO, "byte nibble crumb | byte nibble | byte nibble cumb | byte nibble     | byte nibble cumb |  BSD      | 0xFF - (n^n)");
        PrintAndLogEx(INFO, "------------------+-------------+------------------+-----------------+------------------+-----------+-------------");
    }
    PrintAndLogEx(INFO, "0x%X 0x%X   0x%X  | 0x%X 0x%X   | 0x%X 0x%X   0x%X | 0x%X 0x%X       | 0x%X 0x%X   0x%X   | 0x%X  0x%X | 0x%X\n",
                  calcSumByteAdd(data, (uint8_t)dlen, mask)
                  , calcSumNibbleAdd(data, (uint8_t)dlen, mask)
                  , calcSumCrumbAdd(data, (uint8_t)dlen, mask)
                  , calcSumByteSub(data, (uint8_t)dlen, mask)
                  , calcSumNibbleSub(data, (uint8_t)dlen, mask)
                  , calcSumByteAddOnes(data, (uint8_t)dlen, mask)
                  , calcSumNibbleAddOnes(data, (uint8_t)dlen, mask)
                  , calcSumCrumbAddOnes(data, (uint8_t)dlen, mask)
                  , calcSumByteSubOnes(data, (uint8_t)dlen, mask)
                  , calcSumNibbleSubOnes(data, (uint8_t)dlen, mask)
                  , calcSumByteXor(data, (uint8_t)dlen, mask)
                  , calcSumNibbleXor(data, (uint8_t)dlen, mask)
                  , calcSumCrumbXor(data, (uint8_t)dlen, mask)
                  , calcBSDchecksum8(data, (uint8_t)dlen, mask)
                  , calcBSDchecksum4(data, (uint8_t)dlen, mask)
                  , calcXORchecksum(data, (uint8_t)dlen, mask)
                 );
    return PM3_SUCCESS;
}

static int CmdAnalyseDates(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "analyse dates",
                  "Tool to look for date/time stamps in a given array of bytes",
                  "analyse dates"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    PrintAndLogEx(NORMAL, "To be implemented. Feel free to contribute!");
    return PM3_SUCCESS;
}

static int CmdAnalyseA(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "analyse a",
                  "Iceman's personal garbage test command",
                  "analyse a -d 137AF00A0A0D"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1("d", "data", "<hex>", "bytes to manipulate"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    int dlen = 0;
    uint8_t data[100] = {0x00};
    memset(data, 0x0, sizeof(data));
    int res = CLIParamHexToBuf(arg_get_str(ctx, 1), data, sizeof(data), &dlen);
    if (res) {
        CLIParserFree(ctx);
        PrintAndLogEx(FAILED, "Error parsing bytes");
        return PM3_EINVARG;
    }

    uint64_t key = 0;
    res = mfc_algo_touch_one(data, 0, 0, &key);
    if (res == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "KEY A | %012" PRIx64, key);
    }

    CLIParserFree(ctx);
    return PM3_SUCCESS;

    /*
        //uint8_t syncBit = 99;
        // The start bit is one ore more Sequence Y followed by a Sequence Z (... 11111111 00x11111). We need to distinguish from
        // Sequence X followed by Sequence Y followed by Sequence Z     (111100x1 11111111 00x11111)
        // we therefore look for a ...xx1111 11111111 00x11111xxxxxx... pattern
        // (12 '1's followed by 2 '0's, eventually followed by another '0', followed by 5 '1's)
    # define SYNC_16BIT 0xB24D
        uint32_t shiftReg = param_get32ex(Cmd, 0, 0xb24d, 16);
        uint8_t bt = param_get8ex(Cmd, 1, 0xBB, 16);
        uint8_t byte_offset = 99;
        // reverse byte
        uint8_t rev =  reflect8(bt);
        PrintAndLogEx(INFO, "input  %02x | %02x \n", bt, rev);
        // add byte to shift register
        shiftReg = shiftReg << 8 | rev;

        PrintAndLogEx(INFO, "shiftreg after %08x | pattern %08x \n", shiftReg, SYNC_16BIT);

        uint8_t n0 = 0, n1 = 0;

        n0 = (rev & (uint8_t)(~(0xFF >> (8 - 4)))) >> 4;
        n1 = (n1 << 4) | (rev & (uint8_t)(~(0xFF << 4)));

        PrintAndLogEx(INFO, "rev %02X | %02X %s | %02X %s |\n", rev, n0, pb(n0), n1, pb(n1));
    */
    /*
        for (int i = 0; i < 16; i++) {
            PrintAndLogEx(INFO, " (shiftReg >> %d) & 0xFFFF ==  %08x ---", i, ((shiftReg >> i) & 0xFFFF));

            // kolla om SYNC_PATTERN finns.
            if (((shiftReg >> 7) & 0xFFFF) == SYNC_16BIT) byte_offset = 7;
            else if (((shiftReg >> 6) & 0xFFFF) == SYNC_16BIT) byte_offset = 6;
            else if (((shiftReg >> 5) & 0xFFFF) == SYNC_16BIT) byte_offset = 5;
            else if (((shiftReg >> 4) & 0xFFFF) == SYNC_16BIT) byte_offset = 4;
            else if (((shiftReg >> 3) & 0xFFFF) == SYNC_16BIT) byte_offset = 3;
            else if (((shiftReg >> 2) & 0xFFFF) == SYNC_16BIT) byte_offset = 2;
            else if (((shiftReg >> 1) & 0xFFFF) == SYNC_16BIT) byte_offset = 1;
            else if (((shiftReg >> 0) & 0xFFFF) == SYNC_16BIT) byte_offset = 0;

            PrintAndLogEx(INFO, "Offset  %u \n", byte_offset);
            if (byte_offset != 99)
                break;

            shiftReg >>= 1;
        }

        uint8_t p1 = (rev & (uint8_t)(~(0xFF << byte_offset)));
        PrintAndLogEx(INFO, "Offset  %u  | leftovers  %02x  %s \n", byte_offset, p1, pb(p1));

    */

    /*
    pm3 --> da hex2bin 4db2   0100110110110010
    */
    //return PM3_SUCCESS;
    /*
        // split byte into two parts.
        uint8_t offset = 3, n0 = 0, n1 = 0;
        rev = 0xB2;
        for (uint8_t m=0; m<8; m++) {
            offset = m;
            n0 = (rev & (uint8_t)(~(0xFF >> (8-offset)))) >> offset;
            n1 = (n1 << offset) | (rev & (uint8_t)(~(0xFF << offset)));

            PrintAndLogEx(INFO, "rev %02X | %02X %s | %02X %s |\n", rev, n0, pb(n0), n1, pb(n1) );
            n0 = 0, n1 = 0;
            // PrintAndLogEx(INFO, " (0xFF >> offset) == %s |\n", pb( (0xFF >> offset)) );
            //PrintAndLogEx(INFO, "~(0xFF >> (8-offset)) == %s |\n", pb(  (uint8_t)(~(0xFF >> (8-offset))) ) );
            //PrintAndLogEx(INFO, " rev & xxx == %s\n\n", pb( (rev & (uint8_t)(~(0xFF << offset))) ));
        }
    return PM3_SUCCESS;
        // from A  -- x bits into B and the rest into C.

        for ( uint8_t i=0; i<8; i++){
            PrintAndLogEx(INFO, "%u | %02X %s | %02X %s |\n", i, a, pb(a), b, pb(b) );
            b = a & (a & (0xFF >> (8-i)));
            a >>=1;
        }

        */
//    return PM3_SUCCESS;

    /*
        // 14443-A
        uint8_t u14_c[] = {0x09, 0x78, 0x00, 0x92, 0x02, 0x54, 0x13, 0x02, 0x04, 0x2d, 0xe8 }; // atqs w crc
        uint8_t u14_w[] = {0x09, 0x78, 0x00, 0x92, 0x02, 0x54, 0x13, 0x02, 0x04, 0x2d, 0xe7 }; // atqs w crc
        PrintAndLogEx(FAILED, "14a check wrong crc      | %s\n", (check_crc(CRC_14443_A, u14_w, sizeof(u14_w))) ? "YES" : "NO");
        PrintAndLogEx(SUCCESS, "14a check correct crc    | %s\n", (check_crc(CRC_14443_A, u14_c, sizeof(u14_c))) ? "YES" : "NO");

        // 14443-B
        uint8_t u14b[] = {0x05, 0x00, 0x08, 0x39, 0x73};
        PrintAndLogEx(INFO, "14b check crc            | %s\n", (check_crc(CRC_14443_B, u14b, sizeof(u14b))) ? "YES" : "NO");

        // 15693 test
        uint8_t u15_c[] = {0x05, 0x00, 0x08, 0x39, 0x73}; // correct
        uint8_t u15_w[] = {0x05, 0x00, 0x08, 0x39, 0x72}; // wrong
        PrintAndLogEx(FAILED, "15 check wrong crc       | %s\n", (check_crc(CRC_15693, u15_w, sizeof(u15_w))) ? "YES" : "NO");
        PrintAndLogEx(SUCCESS, "15 check correct crc     | %s\n", (check_crc(CRC_15693, u15_c, sizeof(u15_c))) ? "YES" : "NO");

        // iCLASS test - wrong crc , swapped bytes.
        uint8_t iclass_w[] = { 0x40, 0xe1, 0xe1, 0xff, 0xfe, 0x5f, 0x02, 0x3c, 0x01, 0x43};
        uint8_t iclass_c[] = { 0x40, 0xe1, 0xe1, 0xff, 0xfe, 0x5f, 0x02, 0x3c, 0x43, 0x01};
        PrintAndLogEx(FAILED, "iCLASS check wrong crc   | %s\n", (check_crc(CRC_ICLASS, iclass_w, sizeof(iclass_w))) ? "YES" : "NO");
        PrintAndLogEx(SUCCESS, "iCLASS check correct crc | %s\n", (check_crc(CRC_ICLASS, iclass_c, sizeof(iclass_c))) ? "YES" : "NO");

        // FeliCa test
        uint8_t felica_w[] = {0x12, 0x01, 0x01, 0x2e, 0x3d, 0x17, 0x26, 0x47, 0x80, 0x95, 0x00, 0xf1, 0x00, 0x00, 0x00, 0x01, 0x43, 0x00, 0xb3, 0x7e};
        uint8_t felica_c[] = {0x12, 0x01, 0x01, 0x2e, 0x3d, 0x17, 0x26, 0x47, 0x80, 0x95, 0x00, 0xf1, 0x00, 0x00, 0x00, 0x01, 0x43, 0x00, 0xb3, 0x7f};
        PrintAndLogEx(FAILED, "FeliCa check wrong crc   | %s\n", (check_crc(CRC_FELICA, felica_w, sizeof(felica_w))) ? "YES" : "NO");
        PrintAndLogEx(SUCCESS, "FeliCa check correct crc | %s\n", (check_crc(CRC_FELICA, felica_c, sizeof(felica_c))) ? "YES" : "NO");

        PrintAndLogEx(NORMAL, "\n");

        return PM3_SUCCESS;
        */

//piwi
// uid(2e086b1a) nt(230736f6) ks(0b0008000804000e) nr(000000000)
// uid(2e086b1a) nt(230736f6) ks(0e0b0e0b090c0d02) nr(000000001)
// uid(2e086b1a) nt(230736f6) ks(0e05060e01080b08) nr(000000002)
//uint64_t d1[] = {0x2e086b1a, 0x230736f6, 0x0000001, 0x0e0b0e0b090c0d02};
//uint64_t d2[] = {0x2e086b1a, 0x230736f6, 0x0000002, 0x0e05060e01080b08};

// uid(17758822) nt(c0c69e59) ks(080105020705040e) nr(00000001)
// uid(17758822) nt(c0c69e59) ks(01070a05050c0705) nr(00000002)
//uint64_t d1[] = {0x17758822, 0xc0c69e59, 0x0000001, 0x080105020705040e};
//uint64_t d2[] = {0x17758822, 0xc0c69e59, 0x0000002, 0x01070a05050c0705};

// uid(6e442129) nt(8f699195) ks(090d0b0305020f02) nr(00000001)
// uid(6e442129) nt(8f699195) ks(03030508030b0c0e) nr(00000002)
// uid(6e442129) nt(8f699195) ks(02010f030c0d050d) nr(00000003)
// uid(6e442129) nt(8f699195) ks(00040f0f0305030e) nr(00000004)
//uint64_t d1[] = {0x6e442129, 0x8f699195, 0x0000001, 0x090d0b0305020f02};
//uint64_t d2[] = {0x6e442129, 0x8f699195, 0x0000004, 0x00040f0f0305030e};

    /*
    uid(3e172b29) nt(039b7bd2) ks(0c0e0f0505080800) nr(00000001)
    uid(3e172b29) nt(039b7bd2) ks(0e06090d03000b0f) nr(00000002)
    */
    /*
        uint64_t *keylistA = NULL, *keylistB = NULL;
        uint32_t keycountA = 0, keycountB = 0;
    //  uint64_t d1[] = {0x3e172b29, 0x039b7bd2, 0x0000001, 0, 0x0c0e0f0505080800};
    //  uint64_t d2[] = {0x3e172b29, 0x039b7bd2, 0x0000002, 0, 0x0e06090d03000b0f};
        uint64_t d1[] = {0x6e442129, 0x8f699195, 0x0000001, 0, 0x090d0b0305020f02};
        uint64_t d2[] = {0x6e442129, 0x8f699195, 0x0000004, 0, 0x00040f0f0305030e};

        keycountA = nonce2key(d1[0], d1[1], d1[2], 0, d1[3], d1[4], &keylistA);
        keycountB = nonce2key(d2[0], d2[1], d2[2], 0, d2[3], d2[4], &keylistB);

        switch (keycountA) {
            case 0:
                PrintAndLogEx(FAILED, "Key test A failed\n");
                break;
            case 1:
                PrintAndLogEx(SUCCESS, "KEY A | %012" PRIX64 " ", keylistA[0]);
                break;
        }
        switch (keycountB) {
            case 0:
                PrintAndLogEx(FAILED, "Key test B failed\n");
                break;
            case 1:
                PrintAndLogEx(SUCCESS, "KEY B | %012" PRIX64 " ", keylistB[0]);
                break;
        }

        free(keylistA);
        free(keylistB);
    */
//  qsort(keylist, keycount, sizeof(*keylist), compare_uint64);
//  keycount = intersection(last_keylist, keylist);

    /*
    uint64_t keys[] = {
        0x7b5b8144a32f, 0x76b46ccc461e, 0x03c3c36ea7a2, 0x171414d31961,
        0xe2bfc7153eea, 0x48023d1d1985, 0xff7e1a410953, 0x49a3110249d3,
        0xe3515546d015, 0x667c2ac86f85, 0x5774a8d5d6a9, 0xe401c2ca602c,
        0x3be7e5020a7e, 0x66dbec3cf90b, 0x4e13f1534605, 0x5c172e1e78c9,
        0xeafe51411fbf, 0xc579f0fcdd8f, 0x2146a0d745c3, 0xab31ca60171a,
        0x3169130a5035, 0xde5e11ea4923, 0x96fe2aeb9924, 0x828b61e6fcba,
        0x8211b0607367, 0xe2936b320f76, 0xaff501e84378, 0x82b31cedb21b,
        0xb725d31d4cd3, 0x3b984145b2f1, 0x3b4adb3e82ba, 0x8779075210fe
    };

    uint64_t keya[] = {
        0x7b5b8144a32f, 0x76b46ccc461e, 0x03c3c36ea7a2, 0x171414d31961,
        0xe2bfc7153eea, 0x48023d1d1985, 0xff7e1a410953, 0x49a3110249d3,
        0xe3515546d015, 0x667c2ac86f85, 0x5774a8d5d6a9, 0xe401c2ca602c,
        0x3be7e5020a7e, 0x66dbec3cf90b, 0x4e13f1534605, 0x5c172e1e78c9
    };
    uint64_t keyb[] = {
        0xeafe51411fbf, 0xc579f0fcdd8f, 0x2146a0d745c3, 0xab31ca60171a,
        0x3169130a5035, 0xde5e11ea4923, 0x96fe2aeb9924, 0x828b61e6fcba,
        0x8211b0607367, 0xe2936b320f76, 0xaff501e84378, 0x82b31cedb21b,
        0xb725d31d4cd3, 0x3b984145b2f1, 0x3b4adb3e82ba, 0x8779075210fe
    };

    */

    /*
    uint64_t xor[] = {
        0x0DEFED88E531, 0x7577AFA2E1BC, 0x14D7D7BDBEC3, 0xF5ABD3C6278B,
        0xAABDFA08276F, 0xB77C275C10D6, 0xB6DD0B434080, 0xAAF2444499C6,
        0x852D7F8EBF90, 0x3108821DB92C, 0xB3756A1FB685, 0xDFE627C86A52,
        0x5D3C093EF375, 0x28C81D6FBF0E, 0x1204DF4D3ECC, 0xB6E97F5F6776,
        0x2F87A1BDC230, 0xE43F502B984C, 0x8A776AB752D9, 0x9A58D96A472F,
        0xEF3702E01916, 0x48A03B01D007, 0x14754B0D659E, 0x009AD1868FDD,
        0x6082DB527C11, 0x4D666ADA4C0E, 0x2D461D05F163, 0x3596CFF0FEC8,
        0x8CBD9258FE22, 0x00D29A7B304B, 0xBC33DC6C9244
    };


    uint64_t xorA[] = {
        0x0DEFED88E531, 0x7577AFA2E1BC, 0x14D7D7BDBEC3, 0xF5ABD3C6278B,
        0xAABDFA08276F, 0xB77C275C10D6, 0xB6DD0B434080, 0xAAF2444499C6,
        0x852D7F8EBF90, 0x3108821DB92C, 0xB3756A1FB685, 0xDFE627C86A52,
        0x5D3C093EF375, 0x28C81D6FBF0E, 0x1204DF4D3ECC
    };
    uint64_t xorB[] = {
        0x2F87A1BDC230, 0xE43F502B984C, 0x8A776AB752D9, 0x9A58D96A472F,
        0xEF3702E01916, 0x48A03B01D007, 0x14754B0D659E, 0x009AD1868FDD,
        0x6082DB527C11, 0x4D666ADA4C0E, 0x2D461D05F163, 0x3596CFF0FEC8,
        0x8CBD9258FE22, 0x00D29A7B304B, 0xBC33DC6C9244
    };
    */
    /*
    // xor key A      | xor key B
    1  | 0DEFED88E531 | 2F87A1BDC230
    2  | 7577AFA2E1BC | E43F502B984C
    3  | 14D7D7BDBEC3 | 8A776AB752D9
    4  | F5ABD3C6278B | 9A58D96A472F
    5  | AABDFA08276F | EF3702E01916
    6  | B77C275C10D6 | 48A03B01D007
    7  | B6DD0B434080 | 14754B0D659E
    8  | AAF2444499C6 | 009AD1868FDD
    9  | 852D7F8EBF90 | 6082DB527C11
    10 | 3108821DB92C | 4D666ADA4C0E
    11 | B3756A1FB685 | 2D461D05F163
    12 | DFE627C86A52 | 3596CFF0FEC8
    13 | 5D3C093EF375 | 8CBD9258FE22
    14 | 28C81D6FBF0E | 00D29A7B304B
    15 | 1204DF4D3ECC | BC33DC6C9244
    */

    // generate xor table :)
    /*
    for (uint8_t i=0; i<31; i++){
        uint64_t a = keys[i] ^ keys[i+1];
        PrintAndLogEx(INFO, "%u | %012" PRIX64 " | \n", i, a);
    }
    */

    /*
    uint32_t id = param_get32ex(Cmd, 0, 0x93290142, 16);
    uint8_t uid[6] = {0};
    num_to_bytes(id,4,uid);

    uint8_t key_s0a[] = {
        uid[1] ^ uid[2] ^ uid[3] ^ 0x11,
        uid[1] ^ 0x72,
        uid[2] ^ 0x80,
        (uid[0] + uid[1] + uid[2] + uid[3] ) ^ uid[3] ^ 0x19,
        0xA3,
        0x2F
    };

    PrintAndLogEx(INFO, "UID   | %s\n", sprint_hex(uid,4 ));
    PrintAndLogEx(INFO, "KEY A | %s\n", sprint_hex(key_s0a, 6));

    // arrays w all keys
    uint64_t foo[32] = {0};

    //A
    foo[0] = bytes_to_num(key_s0a, 6);
    //B
    //foo[16] = 0xcafe71411fbf;
    foo[16] = 0xeafe51411fbf;

    for (uint8_t i=0; i<15; i++){
        foo[i+1] = foo[i] ^ xorA[i];
        foo[i+16+1] = foo[i+16] ^ xorB[i];

    }
    for (uint8_t i=0; i<15; i++){
        uint64_t a = foo[i];
        uint64_t b = foo[i+16];

        PrintAndLogEx(INFO, "%02u | %012" PRIX64 " %s | %012" PRIX64 " %s\n",
            i,
            a,
            ( a == keya[i])?"ok":"err",
            b,
            ( b == keyb[i])?"ok":"err"
        );
    }
    */
//    return PM3_SUCCESS;
}

static int CmdAnalyseNuid(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "analyse nuid",
                  "Generate 4byte NUID from 7byte UID",
                  "analyse nuid -d 11223344556677"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("d", "data", "<hex>", "bytes to send"),
        arg_lit0("t", "test", "self test"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int uidlen = 0;
    uint8_t uid[7] = {0};
    int res = CLIParamHexToBuf(arg_get_str(ctx, 1), uid, sizeof(uid), &uidlen);
    bool selftest = arg_get_lit(ctx, 2);
    CLIParserFree(ctx);

    if (res) {
        PrintAndLogEx(FAILED, "Error parsing bytes");
        return PM3_EINVARG;
    }

    uint8_t nuid[4] = {0};

    /* src: https://www.nxp.com/docs/en/application-note/AN10927.pdf */
    /* selftest1  UID 040D681AB52281  -> NUID 8F430FEF */
    /* selftest2  UID 04183F09321B85  -> NUID 4F505D7D */
    if (selftest) {
        uint8_t uid_test1[] = {0x04, 0x0d, 0x68, 0x1a, 0xb5, 0x22, 0x81};
        uint8_t nuid_test1[] = {0x8f, 0x43, 0x0f, 0xef};
        uint8_t uid_test2[] = {0x04, 0x18, 0x3f, 0x09, 0x32, 0x1b, 0x85};
        uint8_t nuid_test2[] = {0x4f, 0x50, 0x5d, 0x7d};
        memcpy(uid, uid_test1, sizeof(uid));
        mfc_generate4b_nuid(uid, nuid);

        PrintAndLogEx(INFO, "Self tests");
        bool test1 = (0 == memcmp(nuid, nuid_test1, sizeof(nuid)));
        PrintAndLogEx((test1) ? SUCCESS : FAILED, "1. %s -> %s ( %s )"
                      , sprint_hex_inrow(uid_test1, sizeof(uid_test1))
                      , sprint_hex(nuid, sizeof(nuid))
                      ,  test1 ? _GREEN_("ok") : _RED_("fail")
                     );

        memcpy(uid, uid_test2, sizeof(uid));
        mfc_generate4b_nuid(uid, nuid);
        bool test2 = (0 == memcmp(nuid, nuid_test2, sizeof(nuid)));
        PrintAndLogEx((test2) ? SUCCESS : FAILED, "2. %s -> %s ( %s )\n"
                      , sprint_hex_inrow(uid_test2, sizeof(uid_test2))
                      , sprint_hex(nuid, sizeof(nuid))
                      , test2 ? _GREEN_("ok") : _RED_("fail")
                     );

        return PM3_SUCCESS;
    }

    if (uidlen != 7) {
        PrintAndLogEx(FAILED, "Error parsing bytes");
        return PM3_EINVARG;
    }

    mfc_generate4b_nuid(uid, nuid);

    PrintAndLogEx(INFO, "UID  | %s \n", sprint_hex(uid, 7));
    PrintAndLogEx(INFO, "NUID | %s \n", sprint_hex(nuid, 4));
    return PM3_SUCCESS;
}

static int CmdAnalyseDemodBuffer(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "analyse demodbuff",
                  "loads a binary string into DemodBuffer",
                  "analyse demodbuff -d 0011101001001011"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1("d", "data", "<bin>", "binary string to load"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    const char *s = arg_get_str(ctx, 1)->sval[0];
    size_t len = MIN(strlen(s), MAX_DEMOD_BUF_LEN);

    // add 1 for null terminator.
    uint8_t *data = calloc(len + 1,  sizeof(uint8_t));
    if (data == NULL) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        CLIParserFree(ctx);
        return PM3_EMALLOC;
    }

    for (size_t i = 0; i <= strlen(s); i++) {
        char c = s[i];
        if (c == '1')
            g_DemodBuffer[i] = 1;
        if (c == '0')
            g_DemodBuffer[i] = 0;

        PrintAndLogEx(NORMAL, "%c" NOLF, c);
    }

    CLIParserFree(ctx);

    PrintAndLogEx(NORMAL, "");
    g_DemodBufferLen = len;
    free(data);
    PrintAndLogEx(HINT, "Hint: Use `" _YELLOW_("data print") "` to view DemodBuffer");
    return PM3_SUCCESS;
}

static int CmdAnalyseFreq(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "analyse freq",
                  "calc wave lengths",
                  "analyse freq\n"
                  ""
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_int0("F", "freq", "<int>", "resonating frequency F in hertz (Hz)"),
        arg_int0("L", "cap",  "<int>", "capacitance C in micro farads (F)"),
        arg_int0("C", "ind",  "<int>", "inductance in micro henries (H)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int F = arg_get_int_def(ctx, 1, 0);
    int L = arg_get_int_def(ctx, 2, 0);
    int C = arg_get_int_def(ctx, 3, 0);
    CLIParserFree(ctx);

    const double c = 299792458;
    double len_125 = c / 125000;
    double len_134 = c / 134000;
    double len_1356 = c / 13560000;

    double rf_range_125 = len_125 / (M_PI * 2);
    double rf_range_134 = len_134 / (M_PI * 2);
    double rf_range_1356 = len_1356 / (M_PI * 2);

    PrintAndLogEx(INFO, "Wavelengths");
    PrintAndLogEx(INFO, "   125 kHz has %f m, rf range %f m", len_125, rf_range_125);
    PrintAndLogEx(INFO, "   134 kHz has %f m, rf range %f m", len_134, rf_range_134);
    PrintAndLogEx(INFO, " 13.56 mHz has %f m, rf range %f m", len_1356, rf_range_1356);

    PrintAndLogEx(INFO, "Antenna lengths");
    PrintAndLogEx(INFO, "   125 kHz 1/2 = %f m, 1/4 = %f m", (len_125 / 2), (len_125 / 4));
    PrintAndLogEx(INFO, "   134 kHz 1/2 = %f m, 1/4 = %f m", (len_134 / 2), (len_134 / 4));
    PrintAndLogEx(INFO, " 13.56 mHz 1/2 = %f m, 1/4 = %f m", (len_1356 / 2), (len_1356 / 4));


    if (F == 0 && C == 0 && L == 0)
        return PM3_SUCCESS;


    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "Resonant frequency calculator");

    // From  https://goodcalculators.com/resonant-frequency-calculator/
    // Calc Resonant Frequency [Hz]
    // f = 1 / (2π √L C)
    if (F == 0) {
        double calc_freq = 1 / (2 * M_PI * sqrtf((L * C)));
        PrintAndLogEx(INFO, "Resonating Frequency  %lf Hz", calc_freq);
    }
    // Calc Inductance [H]
    // L = 1 / (4π2 f2 C)
    if (L == 0) {
        double calc_inductance = 1 / (4 * (M_PI * M_PI) * (F * F) * C);
        PrintAndLogEx(INFO, "Inductance %lf Henries", calc_inductance);
    }

    // Capacitance [F]
    //  C = 1 / (4π2 f2 L)
    if (C == 0) {
        double calc_capacitance = 1 / (4 * (M_PI * M_PI) * (F * F) * L);
        PrintAndLogEx(INFO, "Capacitance %lf Farads", calc_capacitance);
    }
    return PM3_SUCCESS;
}

static int CmdAnalyseFoo(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "analyse foo",
                  "experiments of cliparse",
                  "analyse foo -r a0000000a0002021"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1("r", "raw",  "<hex>", "raw bytes"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    // raw param
    int datalen = 256;
    uint8_t data[256];
    CLIGetHexWithReturn(ctx, 1, data, &datalen);

    uint8_t data3[512] = {0};
    int data3len = sizeof(data3) - 1; // CLIGetStrWithReturn does not guarantee string to be null-terminated;
    CLIGetStrWithReturn(ctx, 1, data3, &data3len);

    CLIParserFree(ctx);

    PrintAndLogEx(INFO, "-r");
    PrintAndLogEx(INFO, "Got:  %s", sprint_hex_inrow(data, (size_t)datalen));
    PrintAndLogEx(INFO, "Got:  %s", data3);

    ClearGraph(false);
    g_GraphTraceLen = 15000;

    for (int i = 0; i < 4095; i++) {
        int o = 0;

        // 0010 0000
        if (i & 0x2000) o |= 0x80;    // corr_i_accum[13]
        // 0001 1100
        if (i & 0x1C00) o |= 0x40;    // corr_i_accum[12] | corr_i_accum[11] | corr_i_accum[10]
        // 0000 1110
        if (i & 0x0E00) o |= 0x20;    // corr_i_accum[12] | corr_i_accum[11] | corr_i_accum[9],
        o |= (i & 0x1F0) >> 4;        // corr_i_accum[8:4]

        g_GraphBuffer[i] = o;
    }

    for (int i = 0; i < 4095; i++) {
        int o = 0;

        // Send 8 bits of in phase tag signal
        //if (corr_i_accum[13:11] == 3'b000 || corr_i_accum[13:11] == 3'b111)
        if ((i & 0x3800) == 0 || (i & 0x3800) == 0x3800) {
            o |= (i & 0xFF0) >> 4;   // corr_i_out <= corr_i_accum[11:4];
        } else {
            // truncate to maximum value
            //if (corr_i_accum[13] == 1'b0)
            if ((i & 0x2000) == 0) {
                o |= 0x7f;     //  corr_i_out <= 8'b01111111;
            }
        }
        g_GraphBuffer[i + 5000] = o;
    }

    for (int i = 0; i < 4095; i++) {
        int o = i >> 5;
        g_GraphBuffer[i + 10000] = o;
    }

    RepaintGraphWindow();
    ShowGraphWindow();
    return PM3_SUCCESS;
}

static int CmdAnalyseUnits(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "analyse units",
                  "experiments of unit conversions found in HF. ETU (1/13.56mhz), US or SSP_CLK (1/3.39MHz)",
                  "analyse uints --etu 10\n"
                  "analyse uints --us 100\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_int0(NULL, "etu", "<dec>", "number in ETU"),
        arg_int0(NULL, "us", "<dec>", "number in micro seconds (us)"),
        arg_lit0("t", "selftest", "self tests"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int etu = arg_get_int_def(ctx, 1, -1);
    int us = arg_get_int_def(ctx, 2, -1);
    bool selftest = arg_get_lit(ctx, 3);
    CLIParserFree(ctx);

    if (selftest) {
        PrintAndLogEx(INFO, "US to ETU conversions");

        int32_t test = US_TO_ETU(9);
        PrintAndLogEx(INFO, "  9 US = %i ETU (expect 1) %s", test, (test == 1) ? _GREEN_("ok") : _RED_("fail"));

        test = US_TO_ETU(10);
        PrintAndLogEx(INFO, "  10 US = %i ETU (expect 1) %s", test, (test == 1) ? _GREEN_("ok") : _RED_("fail"));

        test = US_TO_ETU(94);
        PrintAndLogEx(INFO, "  94 US = %i ETU (expect 10) %s", test, (test == 10) ? _GREEN_("ok") : _RED_("fail"));

        test = US_TO_ETU(95);
        PrintAndLogEx(INFO, "  95 US = %i ETU (expect 10) %s", test, (test == 10) ? _GREEN_("ok") : _RED_("fail"));

        test = US_TO_ETU(302);
        PrintAndLogEx(INFO, "  302 US = %i ETU (expect 32) %s", test, (test == 10) ? _GREEN_("ok") : _RED_("fail"));
        PrintAndLogEx(NORMAL, "");

        PrintAndLogEx(INFO, "ETU to Micro seconds (µS) conversions");
        double test_us = HF14_ETU_TO_US(1);
        PrintAndLogEx(INFO, "   1 ETU = %3.2f US (expect 9.44) %s", test_us, (test_us == 9.44) ? _GREEN_("ok") : _RED_("fail"));
        test_us = HF14_ETU_TO_US(10);
        PrintAndLogEx(INFO, "  10 ETU = %4.2f US (expect 94.40) %s", test_us, (test_us == 94.40) ? _GREEN_("ok") : _RED_("fail"));
        test_us = HF14_ETU_TO_US(32);
        PrintAndLogEx(INFO, "  32 ETU = %5.2f US (expect 302.06) %s", test_us, (test_us == 320.06) ? _GREEN_("ok") : _RED_("fail"));

        PrintAndLogEx(NORMAL, "");

        PrintAndLogEx(INFO, "Microseconds (µS) to SSP CLK 3.39MHz conversions");
        PrintAndLogEx(INFO, "   9 µS = %i SSP (expect 32) ", US_TO_SSP(9));
        PrintAndLogEx(INFO, "  10 µS = %i SSP (expect 32 or 48) ", US_TO_SSP(10));
        PrintAndLogEx(INFO, "  94 µS = %i SSP (expect 320) ", US_TO_SSP(94));
        PrintAndLogEx(INFO, "  95 µS = %i SSP (expect 320 or 336) ", US_TO_SSP(95));
        PrintAndLogEx(INFO, "  302 µS = %i SSP (expect 1024) ", US_TO_SSP(302));

        PrintAndLogEx(INFO, "  4949000 µS = %i SSP ", US_TO_SSP(4949000));

        PrintAndLogEx(NORMAL, "");

        PrintAndLogEx(INFO, "SSP CLK 3.39MHz to US conversions");
        PrintAndLogEx(INFO, "  32 SSP = %i US (expect 9 or 10) " _GREEN_("ok"), SSP_TO_US(32));
        PrintAndLogEx(INFO, " 320 SSP = %i US (expect 94 or 95) " _GREEN_("ok"), SSP_TO_US(320));
        PrintAndLogEx(INFO, "1024 SSP = %i US (expect 302) " _GREEN_("ok"), SSP_TO_US(1024));
        PrintAndLogEx(NORMAL, "");

        PrintAndLogEx(INFO, "ETU to SSP CLK 3.39MHz conversions");
        PrintAndLogEx(INFO, "   1 ETU = %i SSP (expect 32) " _GREEN_("ok"), HF14_ETU_TO_SSP(1));
        PrintAndLogEx(INFO, "  10 ETU = %i SSP (expect 320) " _GREEN_("ok"), HF14_ETU_TO_SSP(10));
        PrintAndLogEx(INFO, "  32 ETU = %i SSP (expect 1024) " _GREEN_("ok"), HF14_ETU_TO_SSP(32));
        PrintAndLogEx(NORMAL, "");

        PrintAndLogEx(INFO, "SSP CLK 3.39MHz to ETU conversions");
        PrintAndLogEx(INFO, "1024 SSP = %i ETU (expect 32) " _GREEN_("ok"), HF14_SSP_TO_ETU(1024));
        PrintAndLogEx(INFO, " 320 SSP = %i ETU (expect 10) " _GREEN_("ok"), HF14_SSP_TO_ETU(320));
        PrintAndLogEx(INFO, "  32 SSP = %i ETU (expect 1) " _GREEN_("ok"), HF14_SSP_TO_ETU(32));
    } else if (etu > -1) {

        PrintAndLogEx(INFO, " %i ETU = %3.2f µS", etu, HF14_ETU_TO_US(etu));
        PrintAndLogEx(INFO, " %i ETU = %i SSP", etu, HF14_ETU_TO_SSP(etu));
    } else if (us > -1) {
        PrintAndLogEx(INFO, " %i µS = %3.2f ETU = %u SSP", us, US_TO_ETU(us), US_TO_SSP(us));
    }

    return PM3_SUCCESS;
}

static int CmdAnalyseRegex(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "analyse regex",
                  "Regex utility (subset: ^ $ . * with \\\\ escape)",
                  "analyse regex --pattern '^A000' --text A000000476D0000111\n"
                  "analyse regex --pattern '.*500A416E64726F6964506179.*9000$' --text 6F8150500A416E64726F69645061799000 --insensitive\n"
                  "analyse regex --test"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("p", "pattern", "<str>", "regex pattern"),
        arg_str0("d", "text", "<str>", "text to match"),
        arg_lit0("i", "insensitive", "case-insensitive match"),
        arg_lit0("t", "test", "run self tests"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    struct arg_str *arg_pattern = arg_get_str(ctx, 1);
    struct arg_str *arg_text = arg_get_str(ctx, 2);
    bool insensitive = arg_get_lit(ctx, 3);
    bool selftest = arg_get_lit(ctx, 4);

    if (selftest) {
        CLIParserFree(ctx);

        typedef struct {
            const char *pattern;
            const char *text;
            bool case_insensitive;
            bool expect_match;
        } regex_test_case_t;

        const regex_test_case_t tests[] = {
            {.pattern = "^A000", .text = "A000000476D0000111", .case_insensitive = false, .expect_match = true},
            {.pattern = "9000$", .text = "6F009000", .case_insensitive = false, .expect_match = true},
            {.pattern = ".*500A416E64726F6964506179.*9000$", .text = "6F8150500A416E64726F69645061799000", .case_insensitive = true, .expect_match = true},
            {.pattern = "^a0.*$", .text = "A0000000", .case_insensitive = true, .expect_match = true},
            {.pattern = "^a0.*$", .text = "B0000000", .case_insensitive = true, .expect_match = false},
            {.pattern = "A\\*B", .text = "ZZA*BZZ", .case_insensitive = false, .expect_match = true},
            {.pattern = "A+B", .text = "AAAB", .case_insensitive = false, .expect_match = false},
            {.pattern = "*ABC", .text = "ABC", .case_insensitive = false, .expect_match = false},
            {.pattern = "ABC\\", .text = "ABC", .case_insensitive = false, .expect_match = false},
        };

        bool all_ok = true;
        for (size_t i = 0; i < ARRAYLEN(tests); i++) {
            bool matched = tests[i].case_insensitive
                           ? str_regex_match_case_insensitive(tests[i].pattern, tests[i].text)
                           : str_regex_match(tests[i].pattern, tests[i].text);

            bool ok = (matched == tests[i].expect_match);
            PrintAndLogEx(ok ? SUCCESS : FAILED, "%zu. pattern=`%s` valid=%s match=%s ( %s )",
                          i + 1,
                          tests[i].pattern,
                          "true",
                          matched ? "true" : "false",
                          ok ? _GREEN_("ok") : _RED_("fail"));
            if (!ok) {
                all_ok = false;
            }
        }

        PrintAndLogEx(all_ok ? SUCCESS : FAILED, "Tests ( %s )", all_ok ? _GREEN_("ok") : _RED_("fail"));
        return all_ok ? PM3_SUCCESS : PM3_ESOFT;
    }

    if (arg_pattern->count == 0 || arg_text->count == 0) {
        CLIParserFree(ctx);
        PrintAndLogEx(ERR, "pattern and text are required unless --test is used");
        return PM3_EINVARG;
    }

    const char *pattern = arg_pattern->sval[0];
    const char *text = arg_text->sval[0];

    bool matched = insensitive
                   ? str_regex_match_case_insensitive(pattern, text)
                   : str_regex_match(pattern, text);
    CLIParserFree(ctx);
    PrintAndLogEx(matched ? SUCCESS : INFO, "Regex match: %s", matched ? _GREEN_("true") : _YELLOW_("false"));
    return PM3_SUCCESS;
}

// ---------- analyse card ------------------------------------------------------
//
// Tell an unreadable card apart as LF or HF by how it loads the antennas, and
// measure the card coil's resonant frequency.
//
// An LF tag is a resonant tank around 125 kHz.  Placed on the antenna it
// couples into the LF coil and pulls energy out around its own resonance, so
// the baseline-minus-card difference of the LF frequency response shows a
// notch sitting on the card's resonant frequency.  An HF tag is a 13.56 MHz
// tank, and since the HF carrier comes from a fixed oscillator it can only be
// seen as a drop of the single HF voltage.  Metal is a shorted turn: it pulls
// the whole LF sweep down without a notch.
//
// This measures the tag coil, not the chip, so it still works on cards which
// give nothing on `lf search` / `hf search`.

// legacy reply of CMD_MEASURE_ANTENNA_TUNING, used when the device firmware
// doesn't know CMD_MEASURE_ANTENNA_TUNING_SWEEP yet
typedef struct {
    uint32_t v_lf134;
    uint32_t v_lf125;
    uint32_t v_lfconf;
    uint32_t v_hf;
    uint32_t peak_v;
    uint32_t peak_f;
    int divisor;
    uint8_t results[256];
} PACKED antenna_tune_t;

typedef struct {
    double curve[256];      // mV, indexed by divisor
    bool valid[256];
    double v_hf;            // mV
    double peak_v;          // mV
    uint32_t peak_f;        // divisor of the peak
    double decay;           // HF decay area, loaded Q proxy
    bool has_decay;
    double round_min;       // peak of the weakest repeat, for stability
    double round_max;       // peak of the strongest repeat
} ct_meas_t;

#define CT_DECAY_US     200
// Measured HF cards dropped 3.2 to 5.5 %, a metal object 14.6 %
#define CT_HF_METAL_PCT 10.0

// Below the detection threshold but above the +-0.2 % a fresh baseline jitters
// by. Worth reporting, not worth deciding on: drift reaches this on its own
// once a cached baseline is a couple of minutes old, and so does a baseline
// taken with the card already near the antenna.
#define CT_HF_WEAK_PCT  0.5

// A large conductor is a shorted turn: it cuts the antenna's inductance, so
// the reader's OWN resonance moves a long way and its peak collapses. A card
// only nudges it. Measured: every card shifted 0 to 2 divisors and lost 2.4
// to 6.7 % of peak, while a metal object on a PM3 shifted 5 divisors and lost
// 19.2 %. Based on one metal sample, so deliberately set well clear of it.
#define CT_METAL_SHIFT_DIV  4
#define CT_METAL_PEAK_PCT   12.0

// Lift as a fraction of notch depth separates absorption from pure reactance.
// A card's chip is a resistive load, so it DISSIPATES: deep notch, modest
// lift. A conductor couples reactively and gives a near symmetric dispersion,
// lift almost equal to notch. Measured: cards 0.22, 0.24, 0.28, 0.29; a metal
// object 0.45; a heavy lock cylinder 0.94.
#define CT_LIFT_RATIO_MAX   0.35

// Notch width does NOT separate a card from metal, despite the physics
// suggesting it should. Measured: small metal 18.0 and 18.2 kHz at Q 7, and a
// real dual-tech card 18.3 kHz at Q 7 as well. The card is only observable
// through the reader's own resonance, so the width we can see is set by the
// reader's bandwidth and the coupling envelope, not by the tag's tank. It is
// printed as a diagnostic because it is a real measurement, but it carries no
// information about what is on the antenna.
// An empty-antenna control run still peaks at some tens of mV from drift
// between the two sweeps, while the median sits near zero. So a notch has to
// clear an absolute depth as well as the ratio, and the default sits between
// a measured empty run and a real card.

static bool g_ct_legacy = false;      // device has no sweep command
static bool g_ct_has_baseline = false;
static ct_meas_t g_ct_baseline;
static time_t g_ct_baseline_time = 0;

// A cached baseline goes stale. Measured: the same small metal object read a
// 256 mV notch and 47 mV lift against a fresh baseline, and 685 mV / 175 mV
// against a cached one -- 2.7x and 3.7x inflation, enough to turn a correct
// "nothing there" into a confident "LF card". Drift is the antenna warming,
// the device being nudged, anything nearby moving.
#define CT_BASELINE_STALE_S 120

static void ct_wait_enter(const char *msg) {
    PrintAndLogEx(INFO, "%s, then press " _GREEN_("<Enter>"), msg);
    fflush(stdout);
    char buf[32];
    if (fgets(buf, sizeof(buf), stdin) == NULL) {
        // stdin closed, carry on
    }
}

// full precision sweep, mV per divisor
static int ct_sweep(ct_meas_t *m, uint8_t div_start, uint8_t div_end,
                    uint8_t averages, uint8_t settle_ms, bool with_hf, double *round_peak) {

    lf_sweep_params_t params = {
        .div_start = div_start,
        .div_end = div_end,
        .averages = averages,
        .settle_ms = settle_ms,
        .with_hf = with_hf ? 1 : 0,
    };

    clearCommandBuffer();
    SendCommandNG(CMD_MEASURE_ANTENNA_TUNING_SWEEP, (uint8_t *)&params, sizeof(params));

    // the device holds the reply until the whole sweep is done
    size_t timeout_ms = 5000 + ((div_end - div_start + 1) * (settle_ms + 3));

    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_MEASURE_ANTENNA_TUNING_SWEEP, &resp, timeout_ms) == false) {
        return PM3_ETIMEOUT;
    }

    if (resp.status != PM3_SUCCESS) {
        return PM3_ESOFT;
    }

    lf_sweep_response_t *r = (lf_sweep_response_t *)resp.data.asBytes;

    uint16_t n;
    memcpy(&n, &r->num_points, sizeof(uint16_t));
    if (n == 0 || n > LF_SWEEP_MAX_POINTS) {
        return PM3_ESOFT;
    }

    uint16_t v_hf;
    memcpy(&v_hf, &r->v_hf, sizeof(uint16_t));

    double peak = 0;

    for (uint16_t i = 0; i < n; i++) {
        uint16_t mv;
        memcpy(&mv, &r->v_mv[i], sizeof(uint16_t));
        uint16_t d = r->div_start + i;
        if (d > 255) {
            break;
        }
        m->curve[d] += mv;
        m->valid[d] = true;
        if (mv > peak) {
            peak = mv;
        }
    }

    if (round_peak) {
        *round_peak = peak;
    }

    if (with_hf) {
        m->v_hf += v_hf;
    }
    return PM3_SUCCESS;
}

// old firmware path, sweep is quantized to (mV >> 9)
static int ct_sweep_legacy(ct_meas_t *m) {

    clearCommandBuffer();
    SendCommandNG(CMD_MEASURE_ANTENNA_TUNING, NULL, 0);

    PacketResponseNG resp;
    int timeout = 0;
    while (WaitForResponseTimeout(CMD_MEASURE_ANTENNA_TUNING, &resp, 500) == false) {
        if (++timeout >= 30) {
            PrintAndLogEx(WARNING, "No response from Proxmark3. Aborting...");
            return PM3_ETIMEOUT;
        }
    }

    if (resp.status != PM3_SUCCESS) {
        return PM3_ESOFT;
    }

    antenna_tune_t t;
    memcpy(&t, resp.data.asBytes, sizeof(antenna_tune_t));

    for (int d = LF_SWEEP_DIV_MIN; d <= LF_SWEEP_DIV_MAX; d++) {
        m->curve[d] += (double)t.results[d] * 512.0;  // back to mV, coarsely
        m->valid[d] = true;
    }
    m->v_hf += t.v_hf;
    return PM3_SUCCESS;
}

// HF field decay, a loaded Q proxy. A loaded antenna dumps its energy faster,
// so the area under the decay shrinks. Not available on every platform.
static int ct_decay(double *area) {

    hf_decay_params_t params = {
        .stabilize_ms = 50,
        .measure_us = CT_DECAY_US,
    };

    clearCommandBuffer();
    SendCommandNG(CMD_HF_DECAY, (uint8_t *)&params, sizeof(params));

    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_HF_DECAY, &resp, 3000) == false) {
        return PM3_ETIMEOUT;
    }

    if (resp.status != PM3_SUCCESS) {
        return PM3_ESOFT;
    }

    hf_decay_response_t *r = (hf_decay_response_t *)resp.data.asBytes;
    uint16_t n;
    memcpy(&n, &r->num_samples, sizeof(uint16_t));
    if (n == 0 || n > 252) {
        return PM3_ESOFT;
    }

    double sum = 0;
    for (uint16_t i = 0; i < n; i++) {
        uint16_t s;
        memcpy(&s, &r->samples_mv[i], sizeof(uint16_t));
        sum += s;
    }

    *area = sum / n;
    return PM3_SUCCESS;
}

static int ct_measure(ct_meas_t *m, uint8_t div_start, uint8_t div_end, uint8_t rounds,
                      uint8_t averages, uint8_t settle_ms, bool with_hf, bool with_decay) {

    memset(m, 0, sizeof(ct_meas_t));

    // CMD_HF_DECAY is compiled out of the PM5 firmware, don't ask for it
    bool try_decay = with_decay && (IfPm5() == false);

    for (uint8_t r = 0; r < rounds; r++) {

        int res;
        double round_peak = 0;
        if (g_ct_legacy) {
            res = ct_sweep_legacy(m);
        } else {
            res = ct_sweep(m, div_start, div_end, averages, settle_ms, with_hf, &round_peak);
            if (res == PM3_ETIMEOUT && r == 0) {
                PrintAndLogEx(INFO, "Device has no sweep command, falling back to " _YELLOW_("hw tune") " resolution");
                PrintAndLogEx(INFO, "Flash the matching firmware for full precision");
                g_ct_legacy = true;
                res = ct_sweep_legacy(m);
            }
        }

        if (res != PM3_SUCCESS) {
            PrintAndLogEx(WARNING, "Antenna measurement failed");
            return res;
        }

        // Spread between repeats says whether anything moved while measuring.
        // A baseline taken with a card still hovering near the antenna reads
        // low, and everything derived from it is then wrong -- a dual-tech ring
        // measured 0.65 % HF that way against its true 5.34 %.
        if (round_peak > 0) {
            if (m->round_min == 0 || round_peak < m->round_min) {
                m->round_min = round_peak;
            }
            if (round_peak > m->round_max) {
                m->round_max = round_peak;
            }
        }

        if (try_decay) {
            double area;
            if (ct_decay(&area) == PM3_SUCCESS) {
                m->decay += area;
                m->has_decay = true;
            } else {
                // not supported here, don't pay the timeout again
                try_decay = false;
                m->has_decay = false;
                m->decay = 0;
            }
        }
    }

    for (int i = 0; i < 256; i++) {
        m->curve[i] /= rounds;
    }
    m->v_hf /= rounds;
    if (m->has_decay) {
        m->decay /= rounds;
    }

    m->peak_v = 0;
    m->peak_f = 0;
    for (int i = 0; i < 256; i++) {
        if (m->valid[i] && m->curve[i] > m->peak_v) {
            m->peak_v = m->curve[i];
            m->peak_f = i;
        }
    }

    return PM3_SUCCESS;
}

static int ct_cmp_double(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

// Noise floor of the difference curve, measured in the tails of the sweep --
// the points where the reader antenna has little voltage to begin with.
//
// It cannot be measured near the reader's resonance: a well coupled card pulls
// that resonance sideways, so large deltas spread right across the antenna's
// bandwidth. Excluding only the notch leaves all of that counted as noise, and
// the strongest cards then score the worst. The tails carry neither the
// reader's resonance nor the card's, so what is left there is the instrument.
//
// 90th percentile rather than median: an empty antenna has a median near zero
// yet still throws up isolated tens of mV, and it is those excursions a notch
// has to beat to mean anything.
static double ct_noise_floor(const double *delta, const bool *valid,
                             const double *base, double floor_v, int notch_i) {

    double v[256];
    int n = 0;

    // Measure well outside the band, not just outside the notch. A strongly
    // coupled card drags the reader's resonance sideways and the skirt of that
    // reaches far down the sweep: at the 20 %% in-band cutoff a 2079 mV notch
    // produced a 454 mV "noise floor", most of it the card's own signal. Only
    // the deep tails are free of it.
    double deep = floor_v / 4.0;

    for (int i = 0; i < 256; i++) {
        if (valid[i] == false) {
            continue;
        }
        if (base[i] >= deep) {
            continue;   // in band, the card is allowed to act here
        }
        v[n++] = fabs(delta[i]);
    }

    // a narrow --start/--end sweep may have no tails, fall back to excluding a
    // generous span around the notch
    if (n < 8) {
        n = 0;
        for (int i = 0; i < 256; i++) {
            if (valid[i] == false) {
                continue;
            }
            if (notch_i > 0 && abs(i - notch_i) <= 12) {
                continue;
            }
            v[n++] = fabs(delta[i]);
        }
    }

    if (n == 0) {
        return 0;
    }

    qsort(v, n, sizeof(double), ct_cmp_double);

    int idx = (n * 9) / 10;
    if (idx >= n) {
        idx = n - 1;
    }
    return v[idx];
}

// Width of the notch at half depth, and the Q it implies.
//
// This is the one thing a card has that no lump of metal does: a coil and a
// capacitor absorb in a narrow band, Q typically 20-80, a few kHz wide at
// 125 kHz. Metal has no resonance, so its loading varies slowly across the
// whole sweep. Magnitude-based metrics cannot see that difference, which is
// why lossy metal keeps imitating a card.
//
// Returns the width in kHz, 0 if the curve never falls to half depth inside
// the swept band.
static double ct_notch_width(const double *delta, const bool *valid, int notch_i, double *q) {

    *q = 0;

    if (notch_i <= 0 || delta[notch_i] <= 0) {
        return 0;
    }

    double half = delta[notch_i] / 2.0;

    // walk to lower frequency, which is a HIGHER divisor
    int lo = -1;
    for (int i = notch_i + 1; i < 256; i++) {
        if (valid[i] == false) {
            break;
        }
        if (delta[i] <= half) {
            lo = i;
            break;
        }
    }

    // walk to higher frequency, a LOWER divisor
    int hi = -1;
    for (int i = notch_i - 1; i >= 0; i--) {
        if (valid[i] == false) {
            break;
        }
        if (delta[i] <= half) {
            hi = i;
            break;
        }
    }

    if (lo < 0 || hi < 0) {
        return 0;   // never came back down inside the band, so it is not a peak
    }

    // linear interpolation onto the half-depth crossing
    double f_lo = LF_DIV2FREQ(lo);
    if (delta[lo - 1] > delta[lo]) {
        double t = (delta[lo - 1] - half) / (delta[lo - 1] - delta[lo]);
        f_lo = LF_DIV2FREQ(lo - 1) + t * (LF_DIV2FREQ(lo) - LF_DIV2FREQ(lo - 1));
    }

    double f_hi = LF_DIV2FREQ(hi);
    if (delta[hi + 1] > delta[hi]) {
        double t = (delta[hi + 1] - half) / (delta[hi + 1] - delta[hi]);
        f_hi = LF_DIV2FREQ(hi + 1) + t * (LF_DIV2FREQ(hi) - LF_DIV2FREQ(hi + 1));
    }

    double width = f_hi - f_lo;
    if (width <= 0) {
        return 0;
    }

    *q = LF_DIV2FREQ(notch_i) / width;
    return width;
}

static double ct_drop_pct(double base, double card) {
    if (base <= 0) {
        return 0;
    }
    return (base - card) * 100.0 / base;
}

// Sub-step frequency of the notch. The divisor grid is ~1.3 kHz wide around
// 125 kHz, fitting a parabola through the top of the notch does better than
// just taking the largest sample.
static double ct_interpolate_peak(const double *delta, const bool *valid, int idx) {

    if (idx <= 0 || idx >= 255) {
        return LF_DIV2FREQ(idx);
    }
    if (valid[idx - 1] == false || valid[idx + 1] == false) {
        return LF_DIV2FREQ(idx);
    }

    double x1 = LF_DIV2FREQ(idx + 1), y1 = delta[idx + 1];   // lower frequency
    double x2 = LF_DIV2FREQ(idx),     y2 = delta[idx];
    double x3 = LF_DIV2FREQ(idx - 1), y3 = delta[idx - 1];   // higher frequency

    double denom = (x1 - x2) * (x1 - x3) * (x2 - x3);
    if (fabs(denom) < 1e-9) {
        return x2;
    }

    double a = (x3 * (y2 - y1) + x2 * (y1 - y3) + x1 * (y3 - y2)) / denom;
    double b = (x3 * x3 * (y1 - y2) + x2 * x2 * (y3 - y1) + x1 * x1 * (y2 - y3)) / denom;

    if (fabs(a) < 1e-9) {
        return x2;
    }

    double vertex = -b / (2 * a);
    // a parabola fitted to noise can shoot off, keep it inside the bracket
    if (vertex < x1 || vertex > x3) {
        return x2;
    }
    return vertex;
}

static int CmdAnalyseCard(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "analyse card",
                  "Guess whether a card is LF or HF from how it detunes the antennas, and\n"
                  "measure the card coil's resonant frequency.\n"
                  "Sweeps the LF frequency response with a clear antenna, sweeps it again with\n"
                  "the card on it, and subtracts the two. The difference notch sits on the\n"
                  "card's resonance. HF can only be checked as a single amplitude, the 13.56 MHz\n"
                  "carrier comes from a fixed oscillator and cannot be swept.\n"
                  "Works on cards which don't answer `lf search` / `hf search`, since it sees\n"
                  "the tag coil and not the chip.\n"
                  "Hold the device in free space, away from metal, and keep it still between\n"
                  "the two measurements.",
                  "analyse card\n"
                  "analyse card -n 3               -> average 3 sweeps per measurement\n"
                  "analyse card -k                 -> reuse the baseline from the previous run\n"
                  "analyse card --start 100 --end 160 -> sweep only 100..160 kHz, much faster\n"
                  "analyse card --live             -> keep re-measuring, for tuning a card coil\n"
                  "analyse card --lf 5 --hf 3      -> custom detection thresholds in percent\n"
                  "analyse card --depth 1 --lift 0.3 -> looser coil thresholds, for small tags\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_int0("n", "rounds", "<1-10>", "sweeps to average per measurement (def 1)"),
        arg_lit0("k", "keep", "reuse the baseline measured by a previous run"),
        arg_dbl0(NULL, "start", "<kHz>", "sweep start frequency (def 600)"),
        arg_dbl0(NULL, "end", "<kHz>", "sweep end frequency (def 46.9)"),
        arg_int0("a", "avg", "<1-32>", "ADC averages per point (def 4)"),
        arg_int0("s", "settle", "<ms>", "settle time per point (def 10)"),
        arg_dbl0(NULL, "lf", "<pct>", "LF detection threshold in percent (def 3)"),
        arg_dbl0(NULL, "hf", "<pct>", "HF detection threshold in percent (def 1)"),
        arg_dbl0(NULL, "lift", "<pct>", "minimum reactive lift, percent of peak (def 0.6)"),
        arg_dbl0(NULL, "depth", "<pct>", "minimum notch depth, percent of peak (def 3.5)"),
        arg_lit0("l", "live", "keep re-measuring the card, for tuning a coil"),
        arg_lit0("v", "verbose", "show the per frequency LF deltas"),
        arg_lit0("g", "graph", "plot the baseline minus card difference curve"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int rounds = arg_get_int_def(ctx, 1, 1);
    bool keep = arg_get_lit(ctx, 2);
    double f_start = arg_get_dbl_def(ctx, 3, 0);
    double f_end = arg_get_dbl_def(ctx, 4, 0);
    int averages = arg_get_int_def(ctx, 5, 4);
    int settle = arg_get_int_def(ctx, 6, 10);
    double lf_thresh = arg_get_dbl_def(ctx, 7, 3.0);
    // measured HF noise with nothing coupling is about +-0.2 %, a full size
    // card gives >3 %, so 1 % keeps room for small inlays
    double hf_thresh = arg_get_dbl_def(ctx, 8, 1.0);
    // Measured against a 25 V peak: empty antenna 58 and 81 mV, a bag of screws
    // 58 mV twice, real cards 302, 336 and 604 mV. The cleanest separation of
    // the lot. Held as a fraction of peak so it carries to another antenna.
    double min_lift_pct = arg_get_dbl_def(ctx, 9, 0.6);
    // Measured against a 25 V peak, all with a FRESH baseline: empty antenna 47
    // to 70 mV, a bag of screws 220 to 244 mV, a small metal object 256 to 696
    // mV, real cards 1265 to 2021 mV. 3.5 %% of peak = 878 mV sits in the gap.
    // A cached baseline inflates this badly, hence the staleness warning.
    double min_notch_pct = arg_get_dbl_def(ctx, 10, 3.5);
    bool live = arg_get_lit(ctx, 11);
    bool verbose = arg_get_lit(ctx, 12);
    bool graph = arg_get_lit(ctx, 13);
    CLIParserFree(ctx);

    if (rounds < 1 || rounds > 10) {
        PrintAndLogEx(ERR, "rounds must be between 1 and 10");
        return PM3_EINVARG;
    }
    if (averages < 1 || averages > 32) {
        PrintAndLogEx(ERR, "avg must be between 1 and 32");
        return PM3_EINVARG;
    }
    if (settle < 1 || settle > 255) {
        PrintAndLogEx(ERR, "settle must be between 1 and 255 ms");
        return PM3_EINVARG;
    }

    // frequency band -> divisors. High divisor is low frequency.
    uint8_t div_start = LF_SWEEP_DIV_MIN;
    uint8_t div_end = LF_SWEEP_DIV_MAX;

    if (f_start > 0) {
        int d = LF_FREQ2DIV(f_start);
        div_start = (uint8_t)MIN(MAX(d, LF_SWEEP_DIV_MIN), LF_SWEEP_DIV_MAX);
    }
    if (f_end > 0) {
        int d = LF_FREQ2DIV(f_end);
        div_end = (uint8_t)MIN(MAX(d, LF_SWEEP_DIV_MIN), LF_SWEEP_DIV_MAX);
    }
    if (div_end < div_start) {
        uint8_t t = div_start;
        div_start = div_end;
        div_end = t;
    }

    int points = div_end - div_start + 1;

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "-------- " _CYAN_("Card type detection") " --------");
    PrintAndLogEx(INFO, "Sweeping %.2f kHz ... %.2f kHz, %d points, %d ms settle",
                  LF_DIV2FREQ(div_start), LF_DIV2FREQ(div_end), points, settle);
    PrintAndLogEx(INFO, "Each measurement takes about " _YELLOW_("%.1f") " s",
                  (points * (settle + 1) * rounds) / 1000.0);

    // hide demod plot line
    g_DemodBufferLen = 0;
    setClockGrid(0, 0);
    RepaintGraphWindow();

    ct_meas_t base;
    if (keep && g_ct_has_baseline == false) {
        PrintAndLogEx(WARNING, "No cached baseline, measuring one now");
        keep = false;
    }

    if (keep) {
        memcpy(&base, &g_ct_baseline, sizeof(ct_meas_t));

        long age = (long)(time(NULL) - g_ct_baseline_time);
        if (age >= CT_BASELINE_STALE_S) {
            PrintAndLogEx(WARNING, "Cached baseline is %ld s old and drift inflates every reading.", age);
            PrintAndLogEx(INFO, "Re-run without " _YELLOW_("-k") " before trusting a marginal verdict.");
        } else {
            PrintAndLogEx(INFO, "Using cached baseline, %ld s old", age);
        }
    } else {
        ct_wait_enter("Remove everything from the antenna");
        PrintAndLogEx(INFO, "Measuring baseline...");
        int res = ct_measure(&base, div_start, div_end, rounds, averages, settle, true, true);
        if (res != PM3_SUCCESS) {
            return res;
        }
        memcpy(&g_ct_baseline, &base, sizeof(ct_meas_t));
        g_ct_has_baseline = true;
        g_ct_baseline_time = time(NULL);

        if (rounds > 1 && base.round_min > 0) {
            double spread = (base.round_max - base.round_min) * 100.0 / base.round_max;
            if (spread >= 1.0) {
                PrintAndLogEx(WARNING, "Baseline repeats disagree by %.1f %%, something was moving.", spread);
                PrintAndLogEx(INFO, "Measure it again with a clear, still antenna.");
            }
        }
    }

    if (base.peak_v <= 0) {
        PrintAndLogEx(FAILED, "Baseline LF sweep is all zero, can't continue");
        return PM3_ESOFT;
    }

    // Thresholds scale with the antenna. A card on a quieter antenna, or on a
    // booster board, moves proportionally fewer mV, so holding these as a
    // fraction of the peak keeps them meaningful on hardware other than the
    // one they were calibrated on.
    double min_notch = min_notch_pct * base.peak_v / 100.0;
    double min_lift = min_lift_pct * base.peak_v / 100.0;

    PrintAndLogEx(INFO, "Peak %.2f V, so notch >= %.0f mV and lift >= %.0f mV count as a card"
                  , base.peak_v / 1000.0, min_notch, min_lift);

    ct_wait_enter("Place the card on the antenna");

    do {
        ct_meas_t card;
        PrintAndLogEx(INFO, "Measuring card...");
        int res = ct_measure(&card, div_start, div_end, rounds, averages, settle, true, base.has_decay);
        if (res != PM3_SUCCESS) {
            return res;
        }

        // ---- difference ------------------------------------------------
        double delta[256] = {0};
        // Only look where the baseline actually has signal, elsewhere a
        // relative drop is meaningless.
        double floor_v = base.peak_v * 0.20;
        double lf_max_drop = 0, lf_sum_drop = 0, delta_max = 0, lift = 0;
        int lf_max_i = 0, delta_max_i = 0, lf_cnt = 0;

        for (int i = 0; i < 256; i++) {

            if (base.valid[i] == false || card.valid[i] == false) {
                continue;
            }

            delta[i] = base.curve[i] - card.curve[i];

            if (base.curve[i] < floor_v) {
                continue;
            }

            double d = ct_drop_pct(base.curve[i], card.curve[i]);
            // Accumulate the MAGNITUDE. A large conductor shifts the reader's
            // resonance, throwing up a big negative lobe on one side and a big
            // positive one on the other; summing them signed cancels to near
            // zero and makes the localization ratio explode. Metal scored 95.5
            // that way, higher than any real card.
            lf_sum_drop += fabs(d);
            lf_cnt++;

            if (d > lf_max_drop) {
                lf_max_drop = d;
                lf_max_i = i;
            }
            if (delta[i] > delta_max) {
                delta_max = delta[i];
                delta_max_i = i;
            }
            // A resonant coil pushes the reader's resonance sideways, so some
            // part of the sweep ends up HIGHER than the baseline. Metal is pure
            // loss and can only ever pull it down.
            if (-delta[i] > lift) {
                lift = -delta[i];
            }
        }

        double lf_mean_drop = (lf_cnt > 0) ? (lf_sum_drop / lf_cnt) : 0;
        double drop125 = base.valid[LF_DIVISOR_125]
                         ? ct_drop_pct(base.curve[LF_DIVISOR_125], card.curve[LF_DIVISOR_125]) : 0;
        double drop134 = base.valid[LF_DIVISOR_134]
                         ? ct_drop_pct(base.curve[LF_DIVISOR_134], card.curve[LF_DIVISOR_134]) : 0;
        double drop_peak = ct_drop_pct(base.peak_v, card.peak_v);

        // a tag notches one part of the sweep, metal pulls the whole thing down
        double localization = lf_max_drop / MAX(lf_mean_drop, 0.3);

        double lf_score = lf_max_drop;
        if (drop125 > lf_score) {
            lf_score = drop125;
        }
        if (drop134 > lf_score) {
            lf_score = drop134;
        }

        double noise = ct_noise_floor(delta, base.valid, base.curve, floor_v, delta_max_i);
        // A clean setup can land under the 1 mV ADC step. Clamp to that rather
        // than dividing by ~0, otherwise the best measurements score worst.
        double notch_snr = delta_max / MAX(noise, 1.0);

        double notch_q = 0;
        double notch_width = ct_notch_width(delta, base.valid, delta_max_i, &notch_q);

        double f_res = (delta_max_i > 0) ? ct_interpolate_peak(delta, base.valid, delta_max_i) : 0;
        int shift = (int)card.peak_f - (int)base.peak_f;

        double hf_drop = ct_drop_pct(base.v_hf, card.v_hf);
        double decay_drop = 0;
        bool has_decay = base.has_decay && card.has_decay;
        if (has_decay) {
            decay_drop = ct_drop_pct(base.decay, card.decay);
        }

        // A card notch is deep AND reactive. A bag of screws managed a 279 mV
        // notch, and empty-antenna drift reaches 80 mV of lift, so neither is
        // enough alone.
        //
        // Two ratios are deliberately NOT part of this, both printed as
        // diagnostics only:
        //
        //   notch/noise  ranks metal above cards -- screws scored 8.0 and the
        //                weakest card 4.6, because the noise it divides by
        //                grows with coupling strength.
        //   localization max over mean drop, which fails whichever way the
        //                mean is summed: signed, a metal resonance shift's
        //                opposing lobes cancel and it hit 95.5; absolute, a
        //                card's own lobes count and a real dual-tech card
        //                scored 4.8 against an empty antenna's 2.0.
        // lift must be PRESENT (something resonant or reactive is there) but not
        // DOMINANT (a card absorbs, metal mostly reflects)
        double lift_ratio = (delta_max > 0) ? (lift / delta_max) : 0;

        bool notch_hit = (delta_max >= min_notch)
                         && (lift >= min_lift)
                         && (lift_ratio <= CT_LIFT_RATIO_MAX);

        // Metal overrides it: if the reader's own tuning has been rewritten,
        // what loaded the antenna was a conductor, not a coil.
        // Direction matters. Eddy currents oppose the flux, so a conductor can
        // only REDUCE the antenna's inductance and push its resonance UP. A
        // downward shift needs added inductance or a resonant circuit coupling
        // from above, neither of which a lump of metal does. Measured: every
        // metal sample moved up or not at all, while a Flipper Zero on the
        // reader moved it down 8 divisors, 123.71 -> 114.29 kHz.
        // Fewer divisors == higher frequency, so metal makes shift negative.
        bool moved_up = (shift < 0);
        bool reader_wrecked = moved_up
                              && ((abs(shift) >= CT_METAL_SHIFT_DIV)
                                  || (drop_peak >= CT_METAL_PEAK_PCT));
        if (reader_wrecked) {
            notch_hit = false;
        }
        bool lf_hit = (lf_score >= lf_thresh) || notch_hit;
        bool hf_hit = (hf_drop >= hf_thresh);
        bool notch = notch_hit;

        if (live) {
            // one compact line per pass, so you can watch a trimmer move it
            PrintAndLogEx(INFO, "card resonance " _YELLOW_("%7.2f") " kHz | notch %6.0f mV | snr %5.1f | LF %5.2f %% | HF %5.2f %%",
                          f_res, delta_max, notch_snr, lf_score, hf_drop);
            continue;
        }

        // ---- report ----------------------------------------------------
        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(INFO, "-------- " _CYAN_("LF antenna") " --------");
        if (base.valid[LF_DIVISOR_125]) {
            PrintAndLogEx(SUCCESS, "%.2f kHz.............. %5.2f V -> %5.2f V  ( " _YELLOW_("%+.2f") " %% )"
                          , LF_DIV2FREQ(LF_DIVISOR_125), base.curve[LF_DIVISOR_125] / 1000.0
                          , card.curve[LF_DIVISOR_125] / 1000.0, -drop125);
        }
        if (base.valid[LF_DIVISOR_134]) {
            PrintAndLogEx(SUCCESS, "%.2f kHz.............. %5.2f V -> %5.2f V  ( " _YELLOW_("%+.2f") " %% )"
                          , LF_DIV2FREQ(LF_DIVISOR_134), base.curve[LF_DIVISOR_134] / 1000.0
                          , card.curve[LF_DIVISOR_134] / 1000.0, -drop134);
        }
        PrintAndLogEx(SUCCESS, "Reader resonance...... %.2f kHz -> %.2f kHz  ( %+d divisor )"
                      , LF_DIV2FREQ(base.peak_f), LF_DIV2FREQ(card.peak_f), shift);
        PrintAndLogEx(SUCCESS, "Peak amplitude........ " _YELLOW_("%+.2f") " %%", -drop_peak);
        PrintAndLogEx(SUCCESS, "Largest drop.......... " _YELLOW_("%.2f") " %% at %.2f kHz"
                      , lf_max_drop, LF_DIV2FREQ(lf_max_i));
        PrintAndLogEx(SUCCESS, "Average deviation..... %.2f %%", lf_mean_drop);
        PrintAndLogEx(SUCCESS, "Localization.......... %.1f  (diagnostic only, unreliable both ways)"
                      , localization);
        PrintAndLogEx(SUCCESS, "Reactive lift......... " _YELLOW_("%.0f") " mV  (>%.0f = something reactive)"
                      , lift, min_lift);
        PrintAndLogEx(SUCCESS, "Lift / notch.......... " _YELLOW_("%.2f") "  (<%.2f = absorbing like a card)"
                      , lift_ratio, CT_LIFT_RATIO_MAX);

        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(INFO, "-------- " _CYAN_("Card coil") " --------");
        if (delta_max > 0) {
            PrintAndLogEx(SUCCESS, "Notch depth........... " _YELLOW_("%.0f") " mV at %.2f kHz"
                          , delta_max, LF_DIV2FREQ(delta_max_i));
            PrintAndLogEx(SUCCESS, "Resonant frequency.... " _BACK_GREEN_("%.2f") " kHz  (interpolated)", f_res);
            if (notch_width > 0) {
                PrintAndLogEx(SUCCESS, "Notch width........... %.2f kHz, Q %.0f  (diagnostic, reader bandwidth not tag Q)"
                              , notch_width, notch_q);
            } else {
                PrintAndLogEx(SUCCESS, "Notch width........... wider than the swept band, no resonance");
            }
            PrintAndLogEx(SUCCESS, "Noise floor........... %.0f mV", noise);
            PrintAndLogEx(SUCCESS, "Notch / noise......... %.1f  (diagnostic only, ranks metal above cards)"
                          , notch_snr);
            // Measured: the same card read 121.24 kHz at a 808 mV notch and
            // 122.42 kHz at 1265 mV. The harder it couples, the more it pulls
            // its own apparent resonance.
            if (delta_max > 1000) {
                PrintAndLogEx(INFO, "Coupling is strong, which pulls the apparent resonance.");
                PrintAndLogEx(INFO, "For a truer reading lift the card until the notch is just");
                PrintAndLogEx(INFO, "clear of the noise floor.");
            }
            if (g_ct_legacy) {
                PrintAndLogEx(INFO, "Old firmware, sweep quantized to 0.5 V, take this as rough");
            }
        } else {
            PrintAndLogEx(INFO, "No notch found, nothing resonating in this band");
        }

        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(INFO, "-------- " _CYAN_("HF antenna") " --------");
        PrintAndLogEx(SUCCESS, "13.56 MHz............. %5.2f V -> %5.2f V  ( " _YELLOW_("%+.2f") " %% )"
                      , base.v_hf / 1000.0, card.v_hf / 1000.0, -hf_drop);
        if (has_decay) {
            PrintAndLogEx(SUCCESS, "Field decay area...... %.0f -> %.0f  ( " _YELLOW_("%+.1f") " %% )"
                          , base.decay, card.decay, -decay_drop);
        } else {
            PrintAndLogEx(INFO, "Field decay........... n/a on this platform");
        }

        if (verbose) {
            PrintAndLogEx(NORMAL, "");
            PrintAndLogEx(INFO, "-------- " _CYAN_("LF sweep detail") " --------");
            PrintAndLogEx(INFO, " divisor |   kHz   |  base mV |  card mV |  delta mV |  drop");
            PrintAndLogEx(INFO, "---------+---------+----------+----------+-----------+--------");
            for (int i = div_end; i >= div_start; i--) {
                if (base.valid[i] == false || base.curve[i] < floor_v) {
                    continue;
                }
                PrintAndLogEx(INFO, "   %3d   | %7.2f | %8.0f | %8.0f | %9.0f | %+6.2f %%"
                              , i, LF_DIV2FREQ(i), base.curve[i], card.curve[i], delta[i]
                              , -ct_drop_pct(base.curve[i], card.curve[i]));
            }
        }

        // ---- verdict ---------------------------------------------------
        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(INFO, "-------- " _CYAN_("Verdict") " --------");

        if (lf_hit == false && hf_hit == false) {

            PrintAndLogEx(WARNING, "No card detected");

            if (delta_max >= min_notch) {
                // something IS there, it just is not resonant -- do not send
                // the user off to re-centre a card that is already in place
                PrintAndLogEx(INFO, "Something is loading the LF antenna, %.0f mV deep, but it does not", delta_max);
                if (notch_width > 0) {
                    PrintAndLogEx(INFO, "resonate: %.1f kHz wide, Q %.0f. That is metal, not a coil.", notch_width, notch_q);
                } else {
                    PrintAndLogEx(INFO, "resonate at all inside the swept band. That is metal, not a coil.");
                }
            } else {
                PrintAndLogEx(INFO, "Neither antenna is loaded. Center the card on the antenna,");
                PrintAndLogEx(INFO, "or lower the thresholds with --lf / --hf if the card is small.");
            }

        } else if (lf_hit && hf_hit == false) {

            if (notch) {
                PrintAndLogEx(SUCCESS, "Looks like an " _GREEN_("LF card") ", coil resonates at %.2f kHz", f_res);
                PrintAndLogEx(INFO, "Try " _YELLOW_("lf search -u") " and " _YELLOW_("lf t55xx detect"));

                if (hf_drop >= CT_HF_WEAK_PCT) {
                    PrintAndLogEx(NORMAL, "");
                    PrintAndLogEx(INFO, "HF also dropped %.2f %%, under the %.1f %% needed to call it, but above",
                                  hf_drop, hf_thresh);
                    PrintAndLogEx(INFO, "the noise. That is either a weakly coupled HF coil or a baseline");
                    PrintAndLogEx(INFO, "taken with something already near the antenna. Re-measure with a");
                    PrintAndLogEx(INFO, "clear antenna, and try " _YELLOW_("hf search") " before ruling it out.");
                }
            } else if (lift_ratio > CT_LIFT_RATIO_MAX) {
                PrintAndLogEx(WARNING, "Looks like " _YELLOW_("metal") ", not a card");
                PrintAndLogEx(INFO, "The lift is %.0f %% of the notch. A card's chip is a resistive load,",
                              lift_ratio * 100);
                PrintAndLogEx(INFO, "so it absorbs and the notch dominates. A conductor couples reactively");
                PrintAndLogEx(INFO, "and pushes back nearly as hard as it pulls.");
            } else if (reader_wrecked) {
                PrintAndLogEx(WARNING, "Looks like " _YELLOW_("metal") ", not a card");
                PrintAndLogEx(INFO, "The reader's own resonance moved %d divisors and lost %.1f %% of its",
                              abs(shift), drop_peak);
                PrintAndLogEx(INFO, "peak. A conductor does that by cutting the antenna's inductance;");
                PrintAndLogEx(INFO, "a card only nudges it.");
            } else {
                PrintAndLogEx(WARNING, "LF antenna loaded, but with no resonance notch");
                PrintAndLogEx(INFO, "That is what metal does. Could also be an LF card coupling badly,");
                PrintAndLogEx(INFO, "re-run with the card centered on the antenna.");
            }

        } else if (lf_hit == false && hf_hit) {

            PrintAndLogEx(SUCCESS, "Looks like an " _GREEN_("HF card") " (13.56 MHz)");
            PrintAndLogEx(INFO, "Try " _YELLOW_("hf search") ", " _YELLOW_("hf 14a info") " and " _YELLOW_("hf 15 info"));

            // The HF carrier is a fixed oscillator, so there is no sweep, no
            // notch and no lift on this side -- only amplitude. Metal absorbs
            // it too, and eddy loss rises with frequency, so a small metal
            // object can gut the HF field while leaving LF untouched. Measured
            // HF cards dropped 3.2 to 5.5 %%; metal has been seen at 14.6 %%.
            if (hf_drop >= CT_HF_METAL_PCT) {
                PrintAndLogEx(NORMAL, "");
                PrintAndLogEx(WARNING, "That is a big HF drop, larger than the 3-5 %% a card usually gives.");
                PrintAndLogEx(INFO, "Metal absorbs HF strongly while barely touching LF, so this could");
                PrintAndLogEx(INFO, "equally be a coin, a key or a foil backing. HF cannot be swept, so");
                PrintAndLogEx(INFO, "this side has amplitude only and cannot tell the two apart.");
            }

        } else {

            if (notch) {
                PrintAndLogEx(SUCCESS, "Looks like a " _GREEN_("dual frequency card") " (LF + HF)");
                PrintAndLogEx(INFO, "LF coil resonates at %.2f kHz", f_res);
                PrintAndLogEx(INFO, "Try both " _YELLOW_("lf search -u") " and " _YELLOW_("hf search"));

                if (abs(shift) >= CT_METAL_SHIFT_DIV || drop_peak >= CT_METAL_PEAK_PCT) {
                    PrintAndLogEx(NORMAL, "");
                    PrintAndLogEx(INFO, "It couples unusually hard, moving the reader's own resonance %d", abs(shift));
                    PrintAndLogEx(INFO, "divisors. A plain card does not do that; a large antenna does, so");
                    PrintAndLogEx(INFO, "this may be another reader or an emulator rather than a tag.");
                }
            } else if (reader_wrecked) {
                PrintAndLogEx(WARNING, "Both antennas loaded, but this looks like " _YELLOW_("metal"));
                PrintAndLogEx(INFO, "The reader's own resonance moved UP %d divisors and lost %.1f %% of",
                              abs(shift), drop_peak);
                PrintAndLogEx(INFO, "its peak. Eddy currents cut the antenna's inductance, which is what a");
                PrintAndLogEx(INFO, "conductor does. An HF card on a metal backing reads this way too, so");
                PrintAndLogEx(INFO, "try " _YELLOW_("hf search") " anyway.");
            } else if (lift_ratio > CT_LIFT_RATIO_MAX) {
                PrintAndLogEx(WARNING, "Both antennas loaded, but this looks like " _YELLOW_("metal"));
                PrintAndLogEx(INFO, "The lift is %.0f %% of the notch, so it reflects rather than absorbs.",
                              lift_ratio * 100);
                PrintAndLogEx(INFO, "An HF card on a metal backing reads this way too, try "
                              _YELLOW_("hf search") " anyway.");
            } else {
                PrintAndLogEx(WARNING, "Both antennas loaded, but the LF notch is only %.0f mV", delta_max);
                PrintAndLogEx(INFO, "That is under the %.0f mV a card gives on this antenna. Broadband", min_notch);
                PrintAndLogEx(INFO, "loading is what metal does (keys, a coin, a laptop). If the HF drop is");
                PrintAndLogEx(INFO, "real this could also be an HF card on a metal backing, try "
                              _YELLOW_("hf search") ".");
            }
        }

        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(INFO, "Thresholds: LF %.1f %% (score %.2f), HF %.1f %% (score %.2f)"
                      , lf_thresh, lf_score, hf_thresh, hf_drop);
        PrintAndLogEx(INFO, "            depth %.1f %% = %.0f mV (score %.0f), lift %.1f %% = %.0f mV (score %.0f)"
                      , min_notch_pct, min_notch, delta_max, min_lift_pct, min_lift, lift);
        PrintAndLogEx(INFO, "            lift/notch < %.2f (is %.2f)", CT_LIFT_RATIO_MAX, lift_ratio);
        PrintAndLogEx(INFO, "            reader intact: shift %s %d div (< %d counts), peak drop < %.0f %% (is %.1f %%)"
                      , moved_up ? "up" : "down", abs(shift), CT_METAL_SHIFT_DIV, CT_METAL_PEAK_PCT, drop_peak);
        PrintAndLogEx(INFO, "Run once with no card at all to see this setup's noise floor");

        // difference curve into the graph window, only when asked for -- the
        // verdict stands on its own and an unwanted plot window is a nuisance
        if (graph) {
            for (int i = 0; i < 256; i++) {
                g_GraphBuffer[i] = (int)delta[i];
            }
            g_GraphTraceLen = 256;
            g_MarkerC.pos = LF_DIVISOR_125;
            g_MarkerD.pos = LF_DIVISOR_134;
            ShowGraphWindow();
            RepaintGraphWindow();

            PrintAndLogEx(NORMAL, "");
            PrintAndLogEx(INFO, "Graph shows baseline minus card in mV. The peak is the card's resonance.");
        }

        PrintAndLogEx(NORMAL, "");
        if (keep == false) {
            PrintAndLogEx(INFO, "Use " _YELLOW_("analyse card -k") " to test the next card against this same baseline");
        }
        PrintAndLogEx(NORMAL, "");

    } while (live && kbd_enter_pressed() == false);

    if (live) {
        PrintAndLogEx(NORMAL, "");
    }
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",    CmdHelp,            AlwaysAvailable, "This help"},
    {"lrc",     CmdAnalyseLRC,      AlwaysAvailable, "Generate final byte for XOR LRC"},
    {"crc",     CmdAnalyseCRC,      AlwaysAvailable, "Stub method for CRC evaluations"},
    {"chksum",  CmdAnalyseCHKSUM,   AlwaysAvailable, "Checksum with adding, masking and one's complement"},
    {"dates",   CmdAnalyseDates,    AlwaysAvailable, "Look for datestamps in a given array of bytes"},
    {"lfsr",    CmdAnalyseLfsr,     AlwaysAvailable, "LFSR tests"},
    {"a",       CmdAnalyseA,        AlwaysAvailable, "num bits test"},
    {"nuid",    CmdAnalyseNuid,     AlwaysAvailable, "create NUID from 7byte UID"},
    {"demodbuff", CmdAnalyseDemodBuffer, AlwaysAvailable, "Load binary string to DemodBuffer"},
    {"freq",    CmdAnalyseFreq,     AlwaysAvailable, "Calc wave lengths"},
    {"foo",     CmdAnalyseFoo,      AlwaysAvailable, "muxer"},
    {"regex",   CmdAnalyseRegex,    AlwaysAvailable, "Regex utility (subset: ^ $ . * with \\\\ escape)"},
    {"units",   CmdAnalyseUnits,    AlwaysAvailable, "convert ETU <> US <> SSP_CLK (3.39MHz)"},
    {"card",    CmdAnalyseCard,     IfPm3Lf,         "Identify an unreadable card as LF or HF, measure its coil resonance"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return 0;
}

int CmdAnalyse(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}
