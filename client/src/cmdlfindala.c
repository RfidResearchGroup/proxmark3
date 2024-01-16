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
// Low frequency Indala commands
// PSK1, rf/32, 64 or 224 bits (known)
//-----------------------------------------------------------------------------

#include "cmdlfindala.h"
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <inttypes.h>
#include "cmdparser.h"    // command_t
#include "comms.h"
#include "graph.h"
#include "cliparser.h"
#include "commonutil.h"
#include "ui.h"           // PrintAndLog
#include "proxgui.h"
#include "lfdemod.h"      // parityTest, bitbytes_to_byte
#include "cmddata.h"
#include "cmdlf.h"        // lf_read
#include "protocols.h"    // t55 defines
#include "cmdlft55xx.h"   // verifywrite
#include "cliparser.h"
#include "cmdlfem4x05.h"  // EM defines
#include "parity.h"       // parity
#include "util_posix.h"

#define INDALA_ARR_LEN 64

static int CmdHelp(const char *Cmd);

//large 224 bit indala formats (different preamble too...)
static uint8_t preamble224[] = {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

// standard 64 bit indala formats including 26 bit 40134 format
static uint8_t preamble64[] =  {1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};

#define HEDEN2L_OFFSET 31
static void encodeHeden2L(uint8_t *dest, uint32_t cardnumber) {

    uint8_t template[] = {
        1, 0, 1, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        1, 0, 0, 0, 1, 0, 0, 0,
        1, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 1, 0, 0, 1,
        0, 0, 0, 0, 0, 0, 1, 0
    };
    uint8_t cardbits[32];

    num_to_bytebits(cardnumber, sizeof(cardbits), cardbits);

    if (cardbits[31] == 1) template[HEDEN2L_OFFSET + 8] = 0x1;
    if (cardbits[30] == 1) template[HEDEN2L_OFFSET + 10] = 0x1;
    if (cardbits[29] == 1) template[HEDEN2L_OFFSET + 14] = 0x1;
    if (cardbits[28] == 1) template[HEDEN2L_OFFSET + 15] = 0x1;
    if (cardbits[27] == 1) template[HEDEN2L_OFFSET + 12] = 0x1;
    if (cardbits[26] == 1) template[HEDEN2L_OFFSET + 28] = 0x1;
    if (cardbits[25] == 1) template[HEDEN2L_OFFSET + 3] = 0x1;
    if (cardbits[24] == 1) template[HEDEN2L_OFFSET + 11] = 0x1;
    if (cardbits[23] == 1) template[HEDEN2L_OFFSET + 19] = 0x1;
    if (cardbits[22] == 1) template[HEDEN2L_OFFSET + 26] = 0x1;
    if (cardbits[21] == 1) template[HEDEN2L_OFFSET + 17] = 0x1;
    if (cardbits[20] == 1) template[HEDEN2L_OFFSET + 18] = 0x1;
    if (cardbits[19] == 1) template[HEDEN2L_OFFSET + 20] = 0x1;
    if (cardbits[18] == 1) template[HEDEN2L_OFFSET + 13] = 0x1;
    if (cardbits[17] == 1) template[HEDEN2L_OFFSET + 7] = 0x1;
    if (cardbits[16] == 1) template[HEDEN2L_OFFSET + 23] = 0x1;

    // Parity
    uint8_t counter = 0;
    for (int i = 0; i < sizeof(template) - HEDEN2L_OFFSET; i++) {
        if (template[i])
            counter++;
    }
    template[63] = (counter & 0x1);

    for (int i = 0; i < sizeof(template); i += 8) {
        dest[i / 8] = bytebits_to_byte(template + i, 8);
    }

    PrintAndLogEx(INFO, "Heden-2L card number %u", cardnumber);
}

static void decodeHeden2L(uint8_t *bits) {

    uint32_t cardnumber = 0;
    uint8_t offset = HEDEN2L_OFFSET;

    if (bits[offset +  8]) cardnumber += 1;
    if (bits[offset + 10]) cardnumber += 2;
    if (bits[offset + 14]) cardnumber += 4;
    if (bits[offset + 15]) cardnumber += 8;
    if (bits[offset + 12]) cardnumber += 16;
    if (bits[offset + 28]) cardnumber += 32;
    if (bits[offset +  3]) cardnumber += 64;
    if (bits[offset + 11]) cardnumber += 128;
    if (bits[offset + 19]) cardnumber += 256;
    if (bits[offset + 26]) cardnumber += 512;
    if (bits[offset + 17]) cardnumber += 1024;
    if (bits[offset + 18]) cardnumber += 2048;
    if (bits[offset + 20]) cardnumber += 4096;
    if (bits[offset + 13]) cardnumber += 8192;
    if (bits[offset +  7]) cardnumber += 16384;
    if (bits[offset + 23]) cardnumber += 32768;

    PrintAndLogEx(SUCCESS, "  Heden-2L...... %u", cardnumber);
}

// sending three times.  Didn't seem to break the previous sim?
static int sendPing(void) {
    SendCommandNG(CMD_BREAK_LOOP, NULL, 0);
    SendCommandNG(CMD_PING, NULL, 0);
    clearCommandBuffer();
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_PING, &resp, 1000) == false) {
        return PM3_ETIMEOUT;
    }
    return PM3_SUCCESS;
}

static int sendTry(uint8_t fc, uint16_t cn, uint32_t delay, bool fmt4041x, bool verbose) {

    // convert to fc / cn to binarray
    uint8_t bs[64];
    memset(bs, 0x00, sizeof(bs));

    // Bitstream generation, format select
    int res;
    if (fmt4041x) {
        res = getIndalaBits4041x(fc, cn, bs);
    } else {
        res = getIndalaBits(fc, cn, bs);
    }

    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Error with tag bitstream generation.");
        return res;
    }

    if (verbose) {

        uint8_t raw[8];
        raw[0] = bytebits_to_byte(bs, 8);
        raw[1] = bytebits_to_byte(bs + 8, 8);
        raw[2] = bytebits_to_byte(bs + 16, 8);
        raw[3] = bytebits_to_byte(bs + 24, 8);
        raw[4] = bytebits_to_byte(bs + 32, 8);
        raw[5] = bytebits_to_byte(bs + 40, 8);
        raw[6] = bytebits_to_byte(bs + 48, 8);
        raw[7] = bytebits_to_byte(bs + 56, 8);

        PrintAndLogEx(INFO, "Trying FC: " _YELLOW_("%u") " CN: " _YELLOW_("%u") " Raw: " _YELLOW_("%s")
                      , fc
                      , cn
                      , sprint_hex_inrow(raw, sizeof(raw))
                     );
    }

    // indala PSK,  clock 32, carrier 0
    lf_psksim_t *payload = calloc(1, sizeof(lf_psksim_t) + sizeof(bs));
    payload->carrier = 2;
    payload->invert = 0;
    payload->clock = 32;
    memcpy(payload->data, bs, sizeof(bs));

    clearCommandBuffer();
    SendCommandNG(CMD_LF_PSK_SIMULATE, (uint8_t *)payload,  sizeof(lf_psksim_t) + sizeof(bs));
    free(payload);

    msleep(delay);
    return sendPing();
}


// Indala 26 bit decode
// by marshmellow, martinbeier
// optional arguments - same as PSKDemod (clock & invert & maxerr)
int demodIndalaEx(int clk, int invert, int maxErr, bool verbose) {
    (void) verbose; // unused so far
    int ans = PSKDemod(clk, invert, maxErr, true);
    if (ans != PM3_SUCCESS) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - Indala can't demod signal: %d", ans);
        return PM3_ESOFT;
    }

    uint8_t inv = 0;
    size_t size = g_DemodBufferLen;
    int idx = detectIndala(g_DemodBuffer, &size, &inv);
    if (idx < 0) {
        if (idx == -1)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Indala: not enough samples");
        else if (idx == -2)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Indala: only noise found");
        else if (idx == -4)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Indala: preamble not found");
        else if (idx == -5)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Indala: size not correct: %zu", size);
        else
            PrintAndLogEx(DEBUG, "DEBUG: Error - Indala: error demoding psk idx: %d", idx);
        return PM3_ESOFT;
    }
    setDemodBuff(g_DemodBuffer, size, idx);
    setClockGrid(g_DemodClock, g_DemodStartIdx + (idx * g_DemodClock));

    //convert UID to HEX
    uint32_t uid1 = bytebits_to_byte(g_DemodBuffer, 32);
    uint32_t uid2 = bytebits_to_byte(g_DemodBuffer + 32, 32);
    // To be checked, what's this internal ID ?
    // foo is only used for 64b ids and in that case uid1 must be only preamble, plus the following code is wrong as x<<32 & 0x1FFFFFFF is always zero
    //uint64_t foo = (((uint64_t)uid1 << 32) & 0x1FFFFFFF) | (uid2 & 0x7FFFFFFF);
    uint64_t foo = uid2 & 0x7FFFFFFF;

    // to reduce false_positives
    // let's check the ratio of zeros in the demod buffer.
    size_t cnt_zeros = 0;
    for (size_t i = 0; i < g_DemodBufferLen; i++) {
        if (g_DemodBuffer[i] == 0x00)
            ++cnt_zeros;
    }

    // if more than 95% zeros in the demodbuffer then assume its wrong
    int32_t stats = (int32_t)((cnt_zeros * 100 / g_DemodBufferLen));
    if (stats > 95) {
        return PM3_ESOFT;
    }

    if (g_DemodBufferLen == 64) {
        PrintAndLogEx(SUCCESS, "Indala (len %zu)  Raw: " _GREEN_("%x%08x"), g_DemodBufferLen, uid1, uid2);

        uint16_t p1  = 0;
        p1 |= g_DemodBuffer[32 + 3] << 8;
        p1 |= g_DemodBuffer[32 + 6] << 5;
        p1 |= g_DemodBuffer[32 + 8] << 4;
        p1 |= g_DemodBuffer[32 + 9] << 3;
        p1 |= g_DemodBuffer[32 + 11] << 1;
        p1 |= g_DemodBuffer[32 + 16] << 6;
        p1 |= g_DemodBuffer[32 + 19] << 7;
        p1 |= g_DemodBuffer[32 + 20] << 10;
        p1 |= g_DemodBuffer[32 + 21] << 2;
        p1 |= g_DemodBuffer[32 + 22] << 0;
        p1 |= g_DemodBuffer[32 + 24] << 9;

        uint8_t fc = 0;
        fc |= g_DemodBuffer[57] << 7; // b8
        fc |= g_DemodBuffer[49] << 6; // b7
        fc |= g_DemodBuffer[44] << 5; // b6
        fc |= g_DemodBuffer[47] << 4; // b5
        fc |= g_DemodBuffer[48] << 3; // b4
        fc |= g_DemodBuffer[53] << 2; // b3
        fc |= g_DemodBuffer[39] << 1; // b2
        fc |= g_DemodBuffer[58] << 0; // b1

        uint16_t csn = 0;
        csn |= g_DemodBuffer[42] << 15; // b16
        csn |= g_DemodBuffer[45] << 14; // b15
        csn |= g_DemodBuffer[43] << 13; // b14
        csn |= g_DemodBuffer[40] << 12; // b13
        csn |= g_DemodBuffer[52] << 11; // b12
        csn |= g_DemodBuffer[36] << 10; // b11
        csn |= g_DemodBuffer[35] << 9; // b10
        csn |= g_DemodBuffer[51] << 8; // b9
        csn |= g_DemodBuffer[46] << 7; // b8
        csn |= g_DemodBuffer[33] << 6; // b7
        csn |= g_DemodBuffer[37] << 5; // b6
        csn |= g_DemodBuffer[54] << 4; // b5
        csn |= g_DemodBuffer[56] << 3; // b4
        csn |= g_DemodBuffer[59] << 2; // b3
        csn |= g_DemodBuffer[50] << 1; // b2
        csn |= g_DemodBuffer[41] << 0; // b1

        uint8_t parity = 0;
        parity |= g_DemodBuffer[34] << 1; // b2
        parity |= g_DemodBuffer[38] << 0; // b1

        uint8_t checksum = 0;
        checksum |= g_DemodBuffer[62] << 1; // b2
        checksum |= g_DemodBuffer[63] << 0; // b1

        PrintAndLogEx(SUCCESS, "Fmt " _GREEN_("26") " FC: " _GREEN_("%u") " Card: " _GREEN_("%u") " Parity: " _GREEN_("%1d%1d")
                      , fc
                      , csn
                      , parity >> 1 & 0x01
                      , parity & 0x01
                     );
        PrintAndLogEx(DEBUG, "two bit checksum... " _GREEN_("%1d%1d"), checksum >> 1 & 0x01, checksum & 0x01);

        PrintAndLogEx(INFO, "");
        PrintAndLogEx(SUCCESS, "Possible de-scramble patterns");
        // This doesn't seem to line up with the hot-stamp numbers on any HID cards I have seen, but, leaving it alone since I do not know how those work. -MS
        PrintAndLogEx(SUCCESS, "  Printed....... __%04d__  ( 0x%X )", p1, p1);
        PrintAndLogEx(SUCCESS, "  Internal ID... %" PRIu64, foo);
        decodeHeden2L(g_DemodBuffer);

    } else {

        if (g_DemodBufferLen != 224) {
            PrintAndLogEx(INFO, "Odd size,  false positive?");
        }

        uint32_t uid3 = bytebits_to_byte(g_DemodBuffer + 64, 32);
        uint32_t uid4 = bytebits_to_byte(g_DemodBuffer + 96, 32);
        uint32_t uid5 = bytebits_to_byte(g_DemodBuffer + 128, 32);
        uint32_t uid6 = bytebits_to_byte(g_DemodBuffer + 160, 32);
        uint32_t uid7 = bytebits_to_byte(g_DemodBuffer + 192, 32);
        PrintAndLogEx(
            SUCCESS
            , "Indala (len %zu)  Raw: " _GREEN_("%x%08x%08x%08x%08x%08x%08x")
            , g_DemodBufferLen
            , uid1
            , uid2
            , uid3
            , uid4
            , uid5
            , uid6
            , uid7
        );
    }

    if (g_debugMode) {
        PrintAndLogEx(DEBUG, "DEBUG: Indala - printing DemodBuffer");
        printDemodBuff(0, false, false, false);
    }
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}

int demodIndala(bool verbose) {
    return demodIndalaEx(0, 0, 100, verbose);
}

static int CmdIndalaDemod(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf indala demod",
                  "Tries to PSK demodulate the graphbuffer as Indala",
                  "lf indala demod\n"
                  "lf indala demod --clock 32      -> demod a Indala tag from the GraphBuffer using a clock of RF/32\n"
                  "lf indala demod --clock 32 -i    -> demod a Indala tag from the GraphBuffer using a clock of RF/32 and inverting data\n"
                  "lf indala demod --clock 64 -i --maxerror 0  -> demod a Indala tag from the GraphBuffer using a clock of RF/64, inverting data and allowing 0 demod errors"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_int0(NULL, "clock", "<dec>", "optional - set clock (as integer), if not set, autodetect."),
        arg_int0(NULL, "maxerr", "<dec>", "optional - set maximum allowed errors, default = 100"),
        arg_lit0("i", "invert", "optional - invert output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    uint32_t clk = arg_get_u32_def(ctx, 1, 32);
    uint32_t max_err = arg_get_u32_def(ctx, 2, 100);
    bool invert = arg_get_lit(ctx, 3);
    CLIParserFree(ctx);

    return demodIndalaEx(clk, invert, max_err, true);
}

// older alternative indala demodulate (has some positives and negatives)
// returns false positives more often - but runs against more sets of samples
// poor psk signal can be difficult to demod this approach might succeed when the other fails
// but the other appears to currently be more accurate than this approach most of the time.
static int CmdIndalaDemodAlt(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf indala altdemod",
                  "Tries to PSK demodulate the graphbuffer as Indala\n"
                  "This is uses a alternative way to demodulate and was used from the beginning in the Pm3 client.\n"
                  "It's now considered obsolete but remains because it has sometimes its advantages.",
                  "lf indala altdemod\n"
                  "lf indala altdemod --long     -> demod a Indala tag from the GraphBuffer as 224 bit long format"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("l", "long", "optional - demod as 224b long format"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool is_long = arg_get_lit(ctx, 1);
    CLIParserFree(ctx);

    // Usage: recover 64bit UID by default, specify "224" as arg to recover a 224bit UID
    int state = -1;
    int count = 0;
    int i, j;

    // worst case with g_GraphTraceLen=40000 is < 4096
    // under normal conditions it's < 2048
    uint8_t data[MAX_GRAPH_TRACE_LEN] = {0};
    size_t datasize = getFromGraphBuf(data);

    uint8_t rawbits[4096] = {0};
    int rawbit = 0;
    int worst = 0, worstPos = 0;

    //clear clock grid and demod plot
    setClockGrid(0, 0);
    g_DemodBufferLen = 0;

    // PrintAndLogEx(NORMAL, "Expecting a bit less than %d raw bits", g_GraphTraceLen / 32);
    // loop through raw signal - since we know it is psk1 rf/32 fc/2 skip every other value (+=2)
    for (i = 0; i < datasize - 1; i += 2) {
        count += 1;
        if ((data[i] > data[i + 1]) && (state != 1)) {
            // appears redundant - marshmellow
            if (state == 0) {
                for (j = 0; j <  count - 8; j += 16) {
                    rawbits[rawbit++] = 0;
                }
                if ((abs(count - j)) > worst) {
                    worst = abs(count - j);
                    worstPos = i;
                }
            }
            state = 1;
            count = 0;
        } else if ((data[i] < data[i + 1]) && (state != 0)) {
            //appears redundant
            if (state == 1) {
                for (j = 0; j <  count - 8; j += 16) {
                    rawbits[rawbit++] = 1;
                }
                if ((abs(count - j)) > worst) {
                    worst = abs(count - j);
                    worstPos = i;
                }
            }
            state = 0;
            count = 0;
        }
    }

    if (rawbit > 0) {
        PrintAndLogEx(INFO, "Recovered %d raw bits, expected: %zu", rawbit, g_GraphTraceLen / 32);
        PrintAndLogEx(INFO, "Worst metric (0=best..7=worst): %d at pos %d", worst, worstPos);
    } else {
        return PM3_ESOFT;
    }

    // Finding the start of a UID
    int uidlen, long_wait;
    if (is_long) {
        uidlen = 224;
        long_wait = 30;
    } else {
        uidlen = 64;
        long_wait = 29;
    }

    int start;
    int first = 0;
    for (start = 0; start <= rawbit - uidlen; start++) {
        first = rawbits[start];
        for (i = start; i < start + long_wait; i++) {
            if (rawbits[i] != first) {
                break;
            }
        }
        if (i == (start + long_wait)) {
            break;
        }
    }

    if (start == rawbit - uidlen + 1) {
        PrintAndLogEx(FAILED, "Nothing to wait for");
        return PM3_ESOFT;
    }

    // Inverting signal if needed
    if (first == 1) {
        for (i = start; i < rawbit; i++) {
            rawbits[i] = !rawbits[i];
        }
    }

    // Dumping UID
    uint8_t bits[224] = {0x00};
    char showbits[225] = {0x00};
    int bit;
    i = start;
    int times = 0;

    if (uidlen > rawbit) {
        PrintAndLogEx(WARNING, "Warning: not enough raw bits to get a full UID");
        for (bit = 0; bit < rawbit; bit++) {
            bits[bit] = rawbits[i++];
            // As we cannot know the parity, let's use "." and "/"
            showbits[bit] = '.' + bits[bit];
        }
        showbits[bit + 1] = '\0';
        PrintAndLogEx(SUCCESS, "Partial UID... %s", showbits);
        return PM3_SUCCESS;
    } else {
        for (bit = 0; bit < uidlen; bit++) {
            bits[bit] = rawbits[i++];
            showbits[bit] = '0' + bits[bit];
        }
        times = 1;
    }

    //convert UID to HEX
    int idx;
    uint32_t uid1 = 0;
    uint32_t uid2 = 0;

    if (uidlen == 64) {
        for (idx = 0; idx < 64; idx++) {
            if (showbits[idx] == '0') {
                uid1 = (uid1 << 1) | (uid2 >> 31);
                uid2 = (uid2 << 1) | 0;
            } else {
                uid1 = (uid1 << 1) | (uid2 >> 31);
                uid2 = (uid2 << 1) | 1;
            }
        }
        PrintAndLogEx(SUCCESS, "UID... %s ( %x%08x )", showbits, uid1, uid2);
    } else {
        uint32_t uid3 = 0;
        uint32_t uid4 = 0;
        uint32_t uid5 = 0;
        uint32_t uid6 = 0;
        uint32_t uid7 = 0;

        for (idx = 0; idx < 224; idx++) {
            uid1 = (uid1 << 1) | (uid2 >> 31);
            uid2 = (uid2 << 1) | (uid3 >> 31);
            uid3 = (uid3 << 1) | (uid4 >> 31);
            uid4 = (uid4 << 1) | (uid5 >> 31);
            uid5 = (uid5 << 1) | (uid6 >> 31);
            uid6 = (uid6 << 1) | (uid7 >> 31);

            if (showbits[idx] == '0')
                uid7 = (uid7 << 1) | 0;
            else
                uid7 = (uid7 << 1) | 1;
        }
        PrintAndLogEx(SUCCESS, "UID... %s (%x%08x%08x%08x%08x%08x%08x)", showbits, uid1, uid2, uid3, uid4, uid5, uid6, uid7);
    }

    // Checking UID against next occurrences
    for (; i + uidlen <= rawbit;) {
        int failed = 0;
        for (bit = 0; bit < uidlen; bit++) {
            if (bits[bit] != rawbits[i++]) {
                failed = 1;
                break;
            }
        }
        if (failed == 1) {
            break;
        }
        times += 1;
    }

    PrintAndLogEx(DEBUG, "Occurrences: %d (expected %d)", times, (rawbit - start) / uidlen);

    // Remodulating for tag cloning
    // HACK: 2015-01-04 this will have an impact on our new way of seening lf commands (demod)
    // since this changes graphbuffer data.
    g_GraphTraceLen = 32 * uidlen;
    i = 0;
    int phase;
    for (bit = 0; bit < uidlen; bit++) {
        if (bits[bit] == 0) {
            phase = 0;
        } else {
            phase = 1;
        }
        for (j = 0; j < 32; j++) {
            g_GraphBuffer[i++] = phase;
            phase = !phase;
        }
    }

    RepaintGraphWindow();
    return PM3_SUCCESS;
}

// this read is the "normal" read,  which download lf signal and tries to demod here.
static int CmdIndalaReader(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf indala reader",
                  "read a Indala tag",
                  "lf indala reader -@   -> continuous reader mode"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_int0(NULL, "clock", "<dec>", "optional - set clock (as integer), if not set, autodetect."),
        arg_int0(NULL, "maxerr", "<dec>", "optional - set maximum allowed errors, default = 100"),
        arg_lit0("i", "invert", "optional - invert output"),
        arg_lit0("@", NULL, "optional - continuous reader mode"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    uint32_t clk = arg_get_u32_def(ctx, 1, 32);
    uint32_t max_err = arg_get_u32_def(ctx, 2, 100);
    bool invert = arg_get_lit(ctx, 3);
    bool cm = arg_get_lit(ctx, 4);
    CLIParserFree(ctx);

    if (cm) {
        PrintAndLogEx(INFO, "Press " _GREEN_("<Enter>") " to exit");
    }

    do {
        lf_read(false, 30000);
        demodIndalaEx(clk, invert, max_err, !cm);
    } while (cm && !kbd_enter_pressed());
    return PM3_SUCCESS;
}

static int CmdIndalaSim(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf indala sim",
                  "Enables simulation of Indala card with specified facility code and card number.\n"
                  "Simulation runs until the button is pressed or another USB command is issued.",
                  "lf indala sim --heden 888\n"
                  "lf indala sim --fc 123 --cn 1337 \n"
                  "lf indala sim --fc 123 --cn 1337 --4041x\n"
                  "lf indala sim --raw a0000000a0002021\n"
                  "lf indala sim --raw 80000001b23523a6c2e31eba3cbee4afb3c6ad1fcf649393928c14e5"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("r", "raw", "<hex>", "raw bytes"),
        arg_int0(NULL, "heden", "<decimal>", "Cardnumber for Heden 2L format"),
        arg_int0(NULL, "fc", "<decimal>", "Facility code (26 bit H10301 format)"),
        arg_int0(NULL, "cn", "<decimal>", "Card number (26 bit H10301 format)"),
        arg_lit0(NULL, "4041x", "Optional - specify Indala 4041X format, must use with fc and cn"),
        arg_param_end
    };

    CLIExecWithReturn(ctx, Cmd, argtable, false);

    // raw param
    int raw_len = 0;
    uint8_t raw[(7 * 4) + 1];
    memset(raw, 0, sizeof(raw));
    CLIGetHexWithReturn(ctx, 1, raw, &raw_len);

    bool is_long_uid = (raw_len == 28);

    bool fmt4041x = arg_get_lit(ctx, 5);


    int32_t cardnumber = 0;
    uint8_t fc = 0;
    uint16_t cn = 0;
    bool got_cn = false, got_26 = false;

    if (is_long_uid == false) {

        // Heden param
        cardnumber = arg_get_int_def(ctx, 2, -1);
        got_cn = (cardnumber != -1);

        // 26b FC/CN param
        fc = arg_get_int_def(ctx, 3, 0);
        cn = arg_get_int_def(ctx, 4, 0);
        got_26 = (fc != 0 && cn != 0);
    }

    CLIParserFree(ctx);

    if ((got_26 == false) && fmt4041x) {
        PrintAndLogEx(FAILED, "You must specify a facility code and card number when using 4041X format");
        return PM3_EINVARG;
    }

    // if HEDEN fmt?
    if (got_cn) {
        encodeHeden2L(raw, cardnumber);
        raw_len = 8;
    }

    // convert to binarray
    uint8_t bs[224];
    memset(bs, 0x00, sizeof(bs));

    // if RAW,  copy to bitstream
    uint8_t counter = 0;
    for (int32_t i = 0; i < raw_len; i++) {
        uint8_t b = raw[i];
        bs[counter++] = (b >> 7) & 1;
        bs[counter++] = (b >> 6) & 1;
        bs[counter++] = (b >> 5) & 1;
        bs[counter++] = (b >> 4) & 1;
        bs[counter++] = (b >> 3) & 1;
        bs[counter++] = (b >> 2) & 1;
        bs[counter++] = (b >> 1) & 1;
        bs[counter++] = b & 1;
    }

    counter = (raw_len * 8);

    // HEDEN

    // FC / CN  not HEDEN.
    if (raw_len == 0 && got_26) {
        // Bitstream generation, format select
        int res = PM3_ESOFT;
        if (fmt4041x) {
            res = getIndalaBits4041x(fc, cn, bs);
        } else {
            res = getIndalaBits(fc, cn, bs);
        }

        if (res != PM3_SUCCESS) {
            PrintAndLogEx(ERR, "Error with tag bitstream generation.");
            return res;
        }

        counter = INDALA_ARR_LEN;

        PrintAndLogEx(SUCCESS, "Simulating " _YELLOW_("64 bit") " Indala FC " _YELLOW_("%u") " CN " _YELLOW_("%u"), fc, cn);
    } else {
        PrintAndLogEx(SUCCESS, "Simulating " _YELLOW_("%s") " Indala raw " _YELLOW_("%s")
                      , (is_long_uid) ? "224 bit" : "64 bit"
                      , sprint_hex_inrow(raw, counter)
                     );
    }

    // a0 00 00 00 bd 98 9a 11

    // indala PSK
    // It has to send either 64bits (8bytes) or 224bits (28bytes).  Zero padding needed if not.
    // lf simpsk -1 -c 32 --fc 2 -d 0102030405060708


    PrintAndLogEx(SUCCESS, "Press pm3-button to abort simulation or run another command");

    // indala PSK,  clock 32, carrier 0
    lf_psksim_t *payload = calloc(1, sizeof(lf_psksim_t) + sizeof(bs));
    payload->carrier = 2;
    payload->invert = 0;
    payload->clock = 32;
    memcpy(payload->data, bs, counter);

    clearCommandBuffer();
    SendCommandNG(CMD_LF_PSK_SIMULATE, (uint8_t *)payload,  sizeof(lf_psksim_t) + counter);
    free(payload);

    PacketResponseNG resp;
    WaitForResponse(CMD_LF_PSK_SIMULATE, &resp);

    PrintAndLogEx(INFO, "Done");
    if (resp.status != PM3_EOPABORTED) {
        return resp.status;
    }
    return PM3_SUCCESS;
}

static int CmdIndalaClone(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf indala clone",
                  "clone Indala UID to T55x7 or Q5/T5555 tag using different known formats\n"
                  _RED_("\nWarning, encoding with FC/CN doesn't always work"),
                  "lf indala clone --heden 888\n"
                  "lf indala clone --fc 123 --cn 1337\n"
                  "lf indala clone --fc 123 --cn 1337 --4041x\n"
                  "lf indala clone -r a0000000a0002021\n"
                  "lf indala clone -r 80000001b23523a6c2e31eba3cbee4afb3c6ad1fcf649393928c14e5");

    void *argtable[] = {
        arg_param_begin,
        arg_str0("r", "raw", "<hex>", "raw bytes"),
        arg_int0(NULL, "heden", "<decimal>", "Card number for Heden 2L format"),
        arg_int0(NULL, "fc", "<decimal>", "Facility code (26 bit H10301 format)"),
        arg_int0(NULL, "cn", "<decimal>", "Card number (26 bit H10301 format)"),
        arg_lit0(NULL, "q5", "Optional - specify writing to Q5/T5555 tag"),
        arg_lit0(NULL, "em", "Optional - specify writing to EM4305/4469 tag"),
        arg_lit0(NULL, "4041x", "Optional - specify Indala 4041X format, must use with fc and cn"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    // raw param
    int raw_len = 0;
    uint8_t raw[(7 * 4) + 1];
    CLIGetHexWithReturn(ctx, 1, raw, &raw_len);

    bool is_long_uid = (raw_len == 28);

    bool q5 = arg_get_lit(ctx, 5);
    bool em = arg_get_lit(ctx, 6);
    bool fmt4041x = arg_get_lit(ctx, 7);

    int32_t cardnumber;
    uint8_t fc = 0;
    uint16_t cn = 0;
    bool got_cn = false, got_26 = false;

    if (is_long_uid == false) {

        // Heden param
        cardnumber = arg_get_int_def(ctx, 2, -1);
        got_cn = (cardnumber != -1);

        // 26b FC/CN param
        fc = arg_get_int_def(ctx, 3, 0);
        cn = arg_get_int_def(ctx, 4, 0);
        got_26 = (fc != 0 && cn != 0);
    }
    CLIParserFree(ctx);

    if (q5 && em) {
        PrintAndLogEx(FAILED, "Can't specify both Q5 and EM4305 at the same time");
        return PM3_EINVARG;
    }

    if ((got_26 == false) && fmt4041x) {
        PrintAndLogEx(FAILED, "You must specify a facility code and card number when using 4041X format");
        return PM3_EINVARG;
    }

    uint8_t max = 0;
    uint32_t blocks[8] = {0};
    char cardtype[16] = {"T55x7"};

    if (is_long_uid) {

        blocks[0] = T55x7_BITRATE_RF_32 | T55x7_MODULATION_PSK2 | (7 << T55x7_MAXBLOCK_SHIFT);
        if (q5) {
            blocks[0] = T5555_FIXED | T5555_SET_BITRATE(32) | T5555_MODULATION_PSK2 | (7 << T5555_MAXBLOCK_SHIFT);
            snprintf(cardtype, sizeof(cardtype), "Q5/T5555");
        }

        if (em) {
            blocks[0] = EM4305_INDALA_224_CONFIG_BLOCK;
            snprintf(cardtype, sizeof(cardtype), "EM4305/4469");
        }

        blocks[1] = bytes_to_num(raw, 4);
        blocks[2] = bytes_to_num(raw +  4, 4);
        blocks[3] = bytes_to_num(raw +  8, 4);
        blocks[4] = bytes_to_num(raw + 12, 4);
        blocks[5] = bytes_to_num(raw + 16, 4);
        blocks[6] = bytes_to_num(raw + 20, 4);
        blocks[7] = bytes_to_num(raw + 24, 4);
        max = 8;

        // 224 BIT UID
        // config for Indala (RF/32;PSK2 with RF/2;Maxblock=7)
        PrintAndLogEx(INFO, "Preparing to clone Indala 224 bit to " _YELLOW_("%s") " raw " _GREEN_("%s")
                      , cardtype
                      , sprint_hex_inrow(raw, raw_len)
                     );

    } else {
        // 64 BIT UID
        if (got_cn) {
            encodeHeden2L(raw, cardnumber);
            raw_len = 8;
        } else if (got_26) {

            PrintAndLogEx(INFO, "Using Indala 64 bit, FC " _GREEN_("%u") " CN " _GREEN_("%u"), fc, cn);

            // Used with the 26bit FC/CSN
            uint8_t *bits = calloc(INDALA_ARR_LEN, sizeof(uint8_t));
            if (bits == NULL) {
                PrintAndLogEx(WARNING, "Failed to allocate memory");
                return PM3_EMALLOC;
            }

            // Bitstream generation, format select
            int indalaReturn = PM3_ESOFT;
            if (fmt4041x) {
                indalaReturn = getIndalaBits4041x(fc, cn, bits);
            } else {
                indalaReturn = getIndalaBits(fc, cn, bits);
            }

            if (indalaReturn != PM3_SUCCESS) {
                PrintAndLogEx(ERR, "Error with tag bitstream generation.");
                free(bits);
                return indalaReturn;
            }

            raw[0] = bytebits_to_byte(bits, 8);
            raw[1] = bytebits_to_byte(bits + 8, 8);
            raw[2] = bytebits_to_byte(bits + 16, 8);
            raw[3] = bytebits_to_byte(bits + 24, 8);
            raw[4] = bytebits_to_byte(bits + 32, 8);
            raw[5] = bytebits_to_byte(bits + 40, 8);
            raw[6] = bytebits_to_byte(bits + 48, 8);
            raw[7] = bytebits_to_byte(bits + 56, 8);
            raw_len = 8;

            free(bits);
        }

        blocks[0] = T55x7_BITRATE_RF_32 | T55x7_MODULATION_PSK1 | (2 << T55x7_MAXBLOCK_SHIFT);

        if (q5) {
            blocks[0] = T5555_FIXED | T5555_SET_BITRATE(32) | T5555_MODULATION_PSK1 | (2 << T5555_MAXBLOCK_SHIFT);
            snprintf(cardtype, sizeof(cardtype), "Q5/T5555");
        }

        if (em) {
            blocks[0] = EM4305_INDALA_64_CONFIG_BLOCK;
            snprintf(cardtype, sizeof(cardtype), "EM4305/4469");
        }

        blocks[1] = bytes_to_num(raw, 4);
        blocks[2] = bytes_to_num(raw + 4, 4);
        max = 3;

        // config for Indala 64 format (RF/32;PSK1 with RF/2;Maxblock=2)
        PrintAndLogEx(INFO, "Preparing to clone Indala 64 bit to " _YELLOW_("%s") " raw " _GREEN_("%s")
                      , cardtype
                      , sprint_hex_inrow(raw, raw_len)
                     );
    }

    print_blocks(blocks, max);

    int res;
    if (em) {
        res = em4x05_clone_tag(blocks, ARRAYLEN(blocks), 0, false);
    } else {
        res = clone_t55xx_tag(blocks, ARRAYLEN(blocks));
    }
    PrintAndLogEx(SUCCESS, "Done");
    PrintAndLogEx(HINT, "Hint: try " _YELLOW_("`lf indala reader`") " to verify");
    return res;
}

static int CmdIndalaBrute(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf indala brute",
                  "Enables bruteforce of INDALA readers with specified facility code.\n"
                  "This is a attack against reader. if cardnumber is given, it starts with it and goes up / down one step\n"
                  "if cardnumber is not given, it starts with 1 and goes up to 65535",
                  "lf indala brute --fc 224\n"
                  "lf indala brute --fc 21 -d 2000\n"
                  "lf indala brute -v --fc 21 --cn 200 -d 2000\n"
                  "lf indala brute -v --fc 21 --cn 200 -d 2000 --up\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("v", "verbose", "verbose output"),
        arg_u64_0(NULL, "fc", "<dec>", "facility code"),
        arg_u64_0(NULL, "cn", "<dec>", "card number to start with"),
        arg_u64_0("d", "delay", "<dec>", "delay betweens attempts in ms. Default 1000ms"),
        arg_lit0(NULL, "up", "direction to increment card number. (default is both directions)"),
        arg_lit0(NULL, "down", "direction to decrement card number. (default is both directions)"),
        arg_lit0(NULL, "4041x", "specify Indala 4041X format"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool verbose = arg_get_lit(ctx, 1);

    uint32_t fc = arg_get_u32_def(ctx, 2, 0);
    uint32_t cn = arg_get_u32_def(ctx, 3, 0);

    uint32_t delay = arg_get_u32_def(ctx, 4, 1000);

    int direction = 0;
    if (arg_get_lit(ctx, 5) && arg_get_lit(ctx, 6)) {
        direction = 0;
    } else if (arg_get_lit(ctx, 5)) {
        direction = 1;
    } else if (arg_get_lit(ctx, 6)) {
        direction = 2;
    }

    bool fmt4041x = arg_get_lit(ctx, 7);
    CLIParserFree(ctx);

    if (verbose) {
        PrintAndLogEx(INFO, "Wiegand format... " _YELLOW_("%s"), (fmt4041x) ? "4041x" : "Standard");
        PrintAndLogEx(INFO, "Facility code.... " _YELLOW_("%u"), fc);
        PrintAndLogEx(INFO, "Card number...... " _YELLOW_("%u"), cn);
        PrintAndLogEx(INFO, "Delay............ " _YELLOW_("%d"), delay);
        switch (direction) {
            case 0:
                PrintAndLogEx(INFO, "Direction........ " _YELLOW_("BOTH"));
                break;
            case 1:
                PrintAndLogEx(INFO, "Direction........ " _YELLOW_("UP"));
                break;
            case 2:
                PrintAndLogEx(INFO, "Direction........ " _YELLOW_("DOWN"));
                break;
            default:
                break;
        }
    }
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "Started brute-forcing INDALA Prox reader");
    PrintAndLogEx(INFO, "Press " _GREEN_("<Enter>") " or pm3-button to abort simulation");
    PrintAndLogEx(NORMAL, "");

    // main loop
    // iceman:  could add options for bruteforcing FC as well..
    uint8_t fc_hi = fc;
    uint8_t fc_low = fc;
    uint16_t cn_hi = cn;
    uint16_t cn_low = cn;

    bool exitloop = false;
    bool fin_hi, fin_low;
    fin_hi = fin_low = false;
    do {

        if (g_session.pm3_present == false) {
            PrintAndLogEx(WARNING, "Device offline\n");
            return PM3_ENODATA;
        }

        if (kbd_enter_pressed()) {
            PrintAndLogEx(WARNING, "aborted via keyboard!");
            return sendPing();
        }

        // do one up
        if (direction != 2) {
            if (cn_hi < 0xFFFF) {
                if (sendTry(fc_hi, cn_hi, delay, fmt4041x, verbose) != PM3_SUCCESS) {
                    return PM3_ESOFT;
                }
                cn_hi++;
            } else {
                fin_hi = true;
            }
        }

        // do one down
        if (direction != 1) {
            if (cn_low > 0) {
                cn_low--;
                if (sendTry(fc_low, cn_low, delay, fmt4041x, verbose) != PM3_SUCCESS) {
                    return PM3_ESOFT;
                }
            } else {
                fin_low = true;
            }
        }

        switch (direction) {
            case 0:
                if (fin_hi && fin_low) {
                    exitloop = true;
                }
                break;
            case 1:
                exitloop = fin_hi;
                break;
            case 2:
                exitloop = fin_low;
                break;
            default:
                break;
        }

    } while (exitloop == false);

    PrintAndLogEx(INFO, "Brute forcing finished");
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",     CmdHelp,            AlwaysAvailable, "This help"},
    {"brute",    CmdIndalaBrute,     IfPm3Lf,         "Demodulate an Indala tag (PSK1) from the GraphBuffer"},
    {"demod",    CmdIndalaDemod,     AlwaysAvailable, "Demodulate an Indala tag (PSK1) from the GraphBuffer"},
    {"altdemod", CmdIndalaDemodAlt,  AlwaysAvailable, "Alternative method to demodulate samples for Indala 64 bit UID (option '224' for 224 bit)"},
    {"reader",   CmdIndalaReader,    IfPm3Lf,         "Read an Indala tag from the antenna"},
    {"clone",    CmdIndalaClone,     IfPm3Lf,         "Clone Indala tag to T55x7 or Q5/T5555"},
    {"sim",      CmdIndalaSim,       IfPm3Lf,         "Simulate Indala tag"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdLFINDALA(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

int getIndalaBits(uint8_t fc, uint16_t cn, uint8_t *bits) {
    // preamble
    // is there a preamble?
    bits[0] = 1;
    bits[2] = 1;
    bits[32] = 1;

    // add fc
    bits[57] = ((fc >> 7) & 1); // b8
    bits[49] = ((fc >> 6) & 1); // b7
    bits[44] = ((fc >> 5) & 1); // b6
    bits[47] = ((fc >> 4) & 1); // b5
    bits[48] = ((fc >> 3) & 1); // b4
    bits[53] = ((fc >> 2) & 1); // b3
    bits[39] = ((fc >> 1) & 1); // b2
    bits[58] = (fc & 1);        // b1

    // add cn
    bits[42] = ((cn >> 15) & 1); // b16
    bits[45] = ((cn >> 14) & 1); // b15 - c
    bits[43] = ((cn >> 13) & 1); // b14
    bits[40] = ((cn >> 12) & 1); // b13 - c
    bits[52] = ((cn >> 11) & 1); // b12
    bits[36] = ((cn >> 10) & 1); // b11
    bits[35] = ((cn >> 9) & 1);  // b10 - c
    bits[51] = ((cn >> 8) & 1);  // b9  - c
    bits[46] = ((cn >> 7) & 1);  // b8
    bits[33] = ((cn >> 6) & 1);  // b7  - c
    bits[37] = ((cn >> 5) & 1);  // b6  - c
    bits[54] = ((cn >> 4) & 1);  // b5
    bits[56] = ((cn >> 3) & 1);  // b4
    bits[59] = ((cn >> 2) & 1);  // b3  - c
    bits[50] = ((cn >> 1) & 1);  // b2
    bits[41] = (cn & 1);         // b1  - c

    // checksum
    uint8_t chk = 0;
    //sum(y2, y4, y7, y8, y10, y11, y14, y16
    chk += ((cn >> 14) & 1); //y2 == 75 - 30 = 45
    chk += ((cn >> 12) & 1); //y4 == 70 - 30 = 40
    chk += ((cn >> 9) & 1); //y7 == 65 - 30 = 35
    chk += ((cn >> 8) & 1); //y8 == 81 - 30 = 51
    chk += ((cn >> 6) & 1); //y10 == 63 - 30 = 33
    chk += ((cn >> 5) & 1); //y11 == 67 - 30 = 37
    chk += ((cn >> 2) & 1); //y14 == 89 - 30 = 59
    chk += (cn & 1); //y16 == 71 - 30 = 41

    if ((chk & 1) == 0) {
        bits[62] = 0;
        bits[63] = 1;
    } else {
        bits[62] = 1;
        bits[63] = 0;
    }

    // add parity
    bits[34] = 1; // p1  64 - 30 = 34
    bits[38] = 1; // p2  68 - 30 = 38

    // 92 = 62
    // 93 = 63

    return PM3_SUCCESS;
}

/*
    Permutation table for this format, lower 4 bytes of card data.

    0x40 |  1   | CN 6 | P Hi | CN 9 | CN A | CN 5 | P Lo | FC 1 |
    0x50 | CN C | CN 0 | CN 5 | CN D | FC 5 | CN E | CN 7 | FC 4 |
    0x60 | FC 3 | FC 6 | CN 1 | CN 8 | CN B | FC 2 | CN 4 |  1   |
    0x70 | CN 3 | FC 7 | FC 0 | CN 2 |  0   |  0   |  0   |  0   |
*/
int getIndalaBits4041x(uint8_t fc, uint16_t cn, uint8_t *bits) {

    // Preamble and required values
    bits[0] = 0x01;
    bits[2] = 0x01;
    bits[32] = 0x01;
    bits[40] = 0x01;
    bits[55] = 0x01;

    // Facility code
    bits[57] = ((fc >> 7) & 0x01);  // MSB
    bits[49] = ((fc >> 6) & 0x01);
    bits[44] = ((fc >> 5) & 0x01);
    bits[47] = ((fc >> 4) & 0x01);
    bits[48] = ((fc >> 3) & 0x01);
    bits[53] = ((fc >> 2) & 0x01);
    bits[39] = ((fc >> 1) & 0x01);
    bits[58] = (fc & 0x01);         // LSB

    // Serial number
    bits[42] = ((cn >> 15) & 0x01); // MSB H
    bits[45] = ((cn >> 14) & 0x01);
    bits[43] = ((cn >> 13) & 0x01);
    bits[40] = ((cn >> 12) & 0x01);
    bits[52] = ((cn >> 11) & 0x01);
    bits[36] = ((cn >> 10) & 0x01);
    bits[35] = ((cn >> 9) & 0x01);
    bits[51] = ((cn >> 8) & 0x01);  // LSB H
    bits[46] = ((cn >> 7) & 0x01);  // MSB L
    bits[33] = ((cn >> 6) & 0x01);
    bits[37] = ((cn >> 5) & 0x01);
    bits[54] = ((cn >> 4) & 0x01);
    bits[56] = ((cn >> 3) & 0x01);
    bits[59] = ((cn >> 2) & 0x01);
    bits[50] = ((cn >> 1) & 0x01);
    bits[41] = (cn & 0x01);         // LSB L

    // Parity
    bits[34] = evenparity16((fc << 4) | (cn >> 12));
    bits[38] = oddparity16(cn & 0x0fff);

    return PM3_SUCCESS;
}

// redesigned by marshmellow adjusted from existing decode functions
// indala id decoding
int detectIndala(uint8_t *dest, size_t *size, uint8_t *invert) {

    uint8_t preamble64_i[]  = {0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0};
    uint8_t preamble224_i[] = {0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
    size_t idx = 0;
    size_t found_size = *size;

    // PSK1
    bool res = preambleSearch(dest, preamble64, sizeof(preamble64), &found_size, &idx);
    if (res) {
        PrintAndLogEx(DEBUG, "DEBUG: detectindala PSK1 found 64");
        goto out;
    }
    idx = 0;
    found_size = *size;
    res = preambleSearch(dest, preamble64_i, sizeof(preamble64_i), &found_size, &idx);
    if (res) {
        PrintAndLogEx(DEBUG, "DEBUG: detectindala PSK1 found 64 inverted preamble");
        goto inv;
    }

    /*
    idx = 0;
    found_size = *size;
    res = preambleSearch(dest, preamble224, sizeof(preamble224), &found_size, &idx);
    if ( res ) {
        PrintAndLogEx(DEBUG, "DEBUG: detectindala PSK1 found 224");
        goto out;
    }

    idx = 0;
    found_size = *size;
    res = preambleSearch(dest, preamble224_i, sizeof(preamble224_i), &found_size, &idx);
    if ( res ) {
        PrintAndLogEx(DEBUG, "DEBUG: detectindala PSK1 found 224 inverted preamble");
        goto inv;
    }
    */

    // PSK2
    psk1TOpsk2(dest, *size);
    PrintAndLogEx(DEBUG, "DEBUG: detectindala Converting PSK1 -> PSK2");

    idx = 0;
    found_size = *size;
    res = preambleSearch(dest, preamble64, sizeof(preamble64), &found_size, &idx);
    if (res) {
        PrintAndLogEx(DEBUG, "DEBUG: detectindala PSK2 found 64 preamble");
        goto out;
    }

    idx = 0;
    found_size = *size;
    res = preambleSearch(dest, preamble224, sizeof(preamble224), &found_size, &idx);
    if (res) {
        PrintAndLogEx(DEBUG, "DEBUG: detectindala PSK2 found 224 preamble");
        goto out;
    }

    idx = 0;
    found_size = *size;
    res = preambleSearch(dest, preamble64_i, sizeof(preamble64_i), &found_size, &idx);
    if (res) {
        PrintAndLogEx(DEBUG, "DEBUG: detectindala PSK2 found 64 inverted preamble");
        goto inv;
    }

    idx = 0;
    found_size = *size;
    res = preambleSearch(dest, preamble224_i, sizeof(preamble224_i), &found_size, &idx);
    if (res) {
        PrintAndLogEx(DEBUG, "DEBUG: detectindala PSK2 found 224 inverted preamble");
        goto inv;
    }

    return -4;

inv:

    *invert ^= 1;

    if (*invert && idx > 0) {
        for (size_t i = idx - 1; i < found_size + idx + 2; i++) {
            dest[i] ^= 1;
        }
    }

    PrintAndLogEx(DEBUG, "DEBUG: Warning - Indala had to invert bits");

out:

    *size = found_size;

    if (found_size < 64) {
        PrintAndLogEx(INFO, "DEBUG: detectindala | %zu", found_size);
        return -5;
    }

    // 224 formats are typically PSK2 (afaik 2017 Marshmellow)
    // note loses 1 bit at beginning of transformation...
    return (int) idx;

}
