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

static int CmdHelp(const char *Cmd);

static uint8_t calculateLRC(const uint8_t *d, uint8_t n) {
    uint8_t lcr = 0;
    for (uint8_t i = 0; i < n; i++)
        lcr ^= d[i];
    return lcr;
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

static int CmdAnalyseLCR(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "analyse lcr",
                  "Specifying the bytes of a UID with a known LRC will find the last byte value\n"
                  "needed to generate that LRC with a rolling XOR. All bytes should be specified in HEX.",
                  "analyse lcr -d 04008064BA     ->  Target (BA) requires final LRC XOR byte value: 5A"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1("d", "data", "<hex>", "bytes to calc missing XOR in a LCR"),
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
        arg_lit0("v", "verbose", "verbose"),
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
    PrintAndLogEx(HINT, "Use `" _YELLOW_("data print") "` to view DemodBuffer");
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

    int data3len = 512;
    uint8_t data3[512];
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

static command_t CommandTable[] = {
    {"help",    CmdHelp,            AlwaysAvailable, "This help"},
    {"lcr",     CmdAnalyseLCR,      AlwaysAvailable, "Generate final byte for XOR LRC"},
    {"crc",     CmdAnalyseCRC,      AlwaysAvailable, "Stub method for CRC evaluations"},
    {"chksum",  CmdAnalyseCHKSUM,   AlwaysAvailable, "Checksum with adding, masking and one's complement"},
    {"dates",   CmdAnalyseDates,    AlwaysAvailable, "Look for datestamps in a given array of bytes"},
    {"lfsr",    CmdAnalyseLfsr,     AlwaysAvailable, "LFSR tests"},
    {"a",       CmdAnalyseA,        AlwaysAvailable, "num bits test"},
    {"nuid",    CmdAnalyseNuid,     AlwaysAvailable, "create NUID from 7byte UID"},
    {"demodbuff", CmdAnalyseDemodBuffer, AlwaysAvailable, "Load binary string to DemodBuffer"},
    {"freq",    CmdAnalyseFreq,     AlwaysAvailable, "Calc wave lengths"},
    {"foo",     CmdAnalyseFoo,      AlwaysAvailable, "muxer"},
    {"units",   CmdAnalyseUnits,    AlwaysAvailable, "convert ETU <> US <> SSP_CLK (3.39MHz)"},
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
