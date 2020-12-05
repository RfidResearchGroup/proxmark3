//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency EM4x commands
//-----------------------------------------------------------------------------

#include "cmdlfem410x.h"
#include "cmdlfem4x50.h"
#include "cmdlfem4x70.h"

#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <ctype.h>
#include <stdlib.h>

#include "fileutils.h"
#include "cmdparser.h"    // command_t
#include "comms.h"
#include "commonutil.h"
#include "common.h"
#include "util_posix.h"
#include "protocols.h"
#include "ui.h"
#include "proxgui.h"
#include "graph.h"
#include "cmddata.h"
#include "cmdlf.h"
#include "lfdemod.h"
#include "generator.h"
#include "cliparser.h"
#include "cmdhw.h"

static uint64_t g_em410xid = 0;

static int CmdHelp(const char *Cmd);

//////////////// 410x commands
static int usage_lf_em410x_demod(void) {
    PrintAndLogEx(NORMAL, "Usage:  lf em 410x_demod [h] [clock] <0|1> [maxError]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "     h                   - this help");
    PrintAndLogEx(NORMAL, "     clock               -  set clock as integer, optional, if not set, autodetect.");
    PrintAndLogEx(NORMAL, "     <0|1>               - 0 normal output, 1 for invert output");
    PrintAndLogEx(NORMAL, "     maxerror            - set maximum allowed errors, default = 100.");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, _YELLOW_("           lf em 410x_demod") "        = demod an EM410x Tag ID from GraphBuffer");
    PrintAndLogEx(NORMAL, _YELLOW_("           lf em 410x_demod 32") "     = demod an EM410x Tag ID from GraphBuffer using a clock of RF/32");
    PrintAndLogEx(NORMAL, _YELLOW_("           lf em 410x_demod 32 1") "   = demod an EM410x Tag ID from GraphBuffer using a clock of RF/32 and inverting data");
    PrintAndLogEx(NORMAL, _YELLOW_("           lf em 410x_demod 1") "      = demod an EM410x Tag ID from GraphBuffer while inverting data");
    PrintAndLogEx(NORMAL, _YELLOW_("           lf em 410x_demod 64 1 0") " = demod an EM410x Tag ID from GraphBuffer using a clock of RF/64 and inverting data and allowing 0 demod errors");
    return PM3_SUCCESS;
}
static int usage_lf_em410x_watch(void) {
    PrintAndLogEx(NORMAL, "Enables IOProx compatible reader mode printing details of scanned tags.");
    PrintAndLogEx(NORMAL, "By default, values are printed and logged until the button is pressed or another USB command is issued.");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  lf em 410x_watch");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, _YELLOW_("        lf em 410x_watch"));
    return PM3_SUCCESS;
}

static int usage_lf_em410x_clone(void) {
    PrintAndLogEx(NORMAL, "Writes EM410x ID to a T55x7 or Q5/T5555 tag");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  lf em 410x_clone [h] <id> <card> [clock]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h         - this help");
    PrintAndLogEx(NORMAL, "       <id>      - ID number");
    PrintAndLogEx(NORMAL, "       <card>    - 0|1  0 = Q5/T5555,  1 = T55x7");
    PrintAndLogEx(NORMAL, "       <clock>   - 16|32|40|64, optional, set R/F clock rate, defaults to 64");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, _YELLOW_("      lf em 410x_clone 0F0368568B 1") "       = write ID to t55x7 card");
    return PM3_SUCCESS;
}
static int usage_lf_em410x_ws(void) {
    PrintAndLogEx(NORMAL, "Watch 'nd Spoof, activates reader, waits until a EM410x tag gets presented then it starts simulating the found UID");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  lf em 410x_spoof [h]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h         - this help");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, _YELLOW_("      lf em 410x_spoof"));
    return PM3_SUCCESS;
}
static int usage_lf_em410x_sim(void) {
    PrintAndLogEx(NORMAL, "Simulating EM410x tag");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  lf em 410x_sim [h] <uid> <clock>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h         - this help");
    PrintAndLogEx(NORMAL, "       uid       - uid (10 HEX symbols)");
    PrintAndLogEx(NORMAL, "       clock     - clock (32|64) (optional)");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, _YELLOW_("      lf em 410x_sim 0F0368568B"));
    PrintAndLogEx(NORMAL, _YELLOW_("      lf em 410x_sim 0F0368568B 32"));
    return PM3_SUCCESS;
}
static int usage_lf_em410x_brute(void) {
    PrintAndLogEx(NORMAL, "Bruteforcing by emulating EM410x tag");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  lf em 410x_brute [h] ids.txt [d 2000] [c clock]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h             - this help");
    PrintAndLogEx(NORMAL, "       ids.txt       - file with UIDs in HEX format, one per line");
    PrintAndLogEx(NORMAL, "       d (2000)      - pause delay in milliseconds between UIDs simulation, default 1000 ms (optional)");
    PrintAndLogEx(NORMAL, "       c (32)        - clock (32|64), default 64 (optional)");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, _YELLOW_("      lf em 410x_brute ids.txt"));
    PrintAndLogEx(NORMAL, _YELLOW_("      lf em 410x_brute ids.txt c 32"));
    PrintAndLogEx(NORMAL, _YELLOW_("      lf em 410x_brute ids.txt d 3000"));
    PrintAndLogEx(NORMAL, _YELLOW_("      lf em 410x_brute ids.txt d 3000 c 32"));
    return PM3_SUCCESS;
}

/* Read the ID of an EM410x tag.
 * Format:
 *   1111 1111 1           <-- standard non-repeatable header
 *   XXXX [row parity bit] <-- 10 rows of 5 bits for our 40 bit tag ID
 *   ....
 *   CCCC                  <-- each bit here is parity for the 10 bits above in corresponding column
 *   0                     <-- stop bit, end of tag
 */

// Construct the graph for emulating an EM410X tag
static void ConstructEM410xEmulGraph(const char *uid, const  uint8_t clock) {

    int i, j, binary[4], parity[4];
    uint32_t n;
    /* clear our graph */
    ClearGraph(true);

    /* write 16 zero bit sledge */
    for (i = 0; i < 20; i++)
        AppendGraph(false, clock, 0);

    /* write 9 start bits */
    for (i = 0; i < 9; i++)
        AppendGraph(false, clock, 1);

    /* for each hex char */
    parity[0] = parity[1] = parity[2] = parity[3] = 0;
    for (i = 0; i < 10; i++) {
        /* read each hex char */
        sscanf(&uid[i], "%1x", &n);
        for (j = 3; j >= 0; j--, n /= 2)
            binary[j] = n % 2;

        /* append each bit */
        AppendGraph(false, clock, binary[0]);
        AppendGraph(false, clock, binary[1]);
        AppendGraph(false, clock, binary[2]);
        AppendGraph(false, clock, binary[3]);

        /* append parity bit */
        AppendGraph(false, clock, binary[0] ^ binary[1] ^ binary[2] ^ binary[3]);

        /* keep track of column parity */
        parity[0] ^= binary[0];
        parity[1] ^= binary[1];
        parity[2] ^= binary[2];
        parity[3] ^= binary[3];
    }

    /* parity columns */
    AppendGraph(false, clock, parity[0]);
    AppendGraph(false, clock, parity[1]);
    AppendGraph(false, clock, parity[2]);
    AppendGraph(false, clock, parity[3]);

    /* stop bit */
    AppendGraph(true, clock, 0);
}

//by marshmellow
//print 64 bit EM410x ID in multiple formats
void printEM410x(uint32_t hi, uint64_t id) {

    if (!id && !hi) return;

    PrintAndLogEx(SUCCESS, "EM410x%s pattern found", (hi) ? " XL" : "");

    uint64_t n = 1;
    uint64_t id2lo = 0;
    uint8_t m, i;
    for (m = 5; m > 0; m--) {
        for (i = 0; i < 8; i++) {
            id2lo = (id2lo << 1LL) | ((id & (n << (i + ((m - 1) * 8)))) >> (i + ((m - 1) * 8)));
        }
    }

    if (hi) {
        //output 88 bit em id
        PrintAndLogEx(NORMAL, "\nEM TAG ID      : "_YELLOW_("%06X%016" PRIX64), hi, id);
        PrintAndLogEx(NORMAL, "Clock rate     : "_YELLOW_("RF/%d"), g_DemodClock);
    } else {
        //output 40 bit em id
        PrintAndLogEx(NORMAL, "\nEM TAG ID      : "_YELLOW_("%010" PRIX64), id);
        PrintAndLogEx(NORMAL, "Clock rate     : "_YELLOW_("RF/%d"), g_DemodClock);
        PrintAndLogEx(NORMAL, "\nPossible de-scramble patterns\n");
        PrintAndLogEx(NORMAL, "Unique TAG ID  : %010" PRIX64, id2lo);
        PrintAndLogEx(NORMAL, "HoneyWell IdentKey {");
        PrintAndLogEx(NORMAL, "DEZ 8          : %08" PRIu64, id & 0xFFFFFF);
        PrintAndLogEx(NORMAL, "DEZ 10         : %010" PRIu64, id & 0xFFFFFFFF);
        PrintAndLogEx(NORMAL, "DEZ 5.5        : %05" PRIu64 ".%05" PRIu64, (id >> 16LL) & 0xFFFF, (id & 0xFFFF));
        PrintAndLogEx(NORMAL, "DEZ 3.5A       : %03" PRIu64 ".%05" PRIu64, (id >> 32ll), (id & 0xFFFF));
        PrintAndLogEx(NORMAL, "DEZ 3.5B       : %03" PRIu64 ".%05" PRIu64, (id & 0xFF000000) >> 24, (id & 0xFFFF));
        PrintAndLogEx(NORMAL, "DEZ 3.5C       : %03" PRIu64 ".%05" PRIu64, (id & 0xFF0000) >> 16, (id & 0xFFFF));
        PrintAndLogEx(NORMAL, "DEZ 14/IK2     : %014" PRIu64, id);
        PrintAndLogEx(NORMAL, "DEZ 15/IK3     : %015" PRIu64, id2lo);
        PrintAndLogEx(NORMAL, "DEZ 20/ZK      : %02" PRIu64 "%02" PRIu64 "%02" PRIu64 "%02" PRIu64 "%02" PRIu64 "%02" PRIu64 "%02" PRIu64 "%02" PRIu64 "%02" PRIu64 "%02" PRIu64,
                      (id2lo & 0xf000000000) >> 36,
                      (id2lo & 0x0f00000000) >> 32,
                      (id2lo & 0x00f0000000) >> 28,
                      (id2lo & 0x000f000000) >> 24,
                      (id2lo & 0x0000f00000) >> 20,
                      (id2lo & 0x00000f0000) >> 16,
                      (id2lo & 0x000000f000) >> 12,
                      (id2lo & 0x0000000f00) >> 8,
                      (id2lo & 0x00000000f0) >> 4,
                      (id2lo & 0x000000000f)
                     );
        uint64_t paxton = (((id >> 32) << 24) | (id & 0xffffff))  + 0x143e00;
        PrintAndLogEx(NORMAL, "}\nOther          : %05" PRIu64 "_%03" PRIu64 "_%08" PRIu64, (id & 0xFFFF), ((id >> 16LL) & 0xFF), (id & 0xFFFFFF));
        PrintAndLogEx(NORMAL, "Pattern Paxton : %" PRIu64 " [0x%" PRIX64 "]", paxton, paxton);

        uint32_t p1id = (id & 0xFFFFFF);
        uint8_t arr[32] = {0x00};
        int j = 23;
        for (int k = 0 ; k < 24; ++k, --j) {
            arr[k] = (p1id >> k) & 1;
        }

        uint32_t p1  = 0;

        p1 |= arr[23] << 21;
        p1 |= arr[22] << 23;
        p1 |= arr[21] << 20;
        p1 |= arr[20] << 22;

        p1 |= arr[19] << 18;
        p1 |= arr[18] << 16;
        p1 |= arr[17] << 19;
        p1 |= arr[16] << 17;

        p1 |= arr[15] << 13;
        p1 |= arr[14] << 15;
        p1 |= arr[13] << 12;
        p1 |= arr[12] << 14;

        p1 |= arr[11] << 6;
        p1 |= arr[10] << 2;
        p1 |= arr[9]  << 7;
        p1 |= arr[8]  << 1;

        p1 |= arr[7]  << 0;
        p1 |= arr[6]  << 8;
        p1 |= arr[5]  << 11;
        p1 |= arr[4]  << 3;

        p1 |= arr[3]  << 10;
        p1 |= arr[2]  << 4;
        p1 |= arr[1]  << 5;
        p1 |= arr[0]  << 9;
        PrintAndLogEx(NORMAL, "Pattern 1      : %d [0x%X]", p1, p1);

        uint16_t sebury1 = id & 0xFFFF;
        uint8_t  sebury2 = (id >> 16) & 0x7F;
        uint32_t sebury3 = id & 0x7FFFFF;
        PrintAndLogEx(NORMAL, "Pattern Sebury : %d %d %d  [0x%X 0x%X 0x%X]", sebury1, sebury2, sebury3, sebury1, sebury2, sebury3);
    }
}
/* Read the ID of an EM410x tag.
 * Format:
 *   1111 1111 1           <-- standard non-repeatable header
 *   XXXX [row parity bit] <-- 10 rows of 5 bits for our 40 bit tag ID
 *   ....
 *   CCCC                  <-- each bit here is parity for the 10 bits above in corresponding column
 *   0                     <-- stop bit, end of tag
 */
int AskEm410xDecode(bool verbose, uint32_t *hi, uint64_t *lo) {
    size_t idx = 0;
    uint8_t bits[512] = {0};
    size_t size = sizeof(bits);
    if (!getDemodBuff(bits, &size)) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - Em410x problem during copy from ASK demod");
        return PM3_ESOFT;
    }

    int ans = Em410xDecode(bits, &size, &idx, hi, lo);
    if (ans < 0) {

        if (ans == -2)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Em410x not enough samples after demod");
        else if (ans == -4)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Em410x preamble not found");
        else if (ans == -5)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Em410x Size not correct: %zu", size);
        else if (ans == -6)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Em410x parity failed");

        return PM3_ESOFT;
    }
    if (!lo && !hi) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - Em410x decoded to all zeros");
        return PM3_ESOFT;
    }

    //set GraphBuffer for clone or sim command
    setDemodBuff(DemodBuffer, (size == 40) ? 64 : 128, idx + 1);
    setClockGrid(g_DemodClock, g_DemodStartIdx + ((idx + 1)*g_DemodClock));

    PrintAndLogEx(DEBUG, "DEBUG: Em410x idx: %zu, Len: %zu, Printing Demod Buffer:", idx, size);
    if (g_debugMode) {
        printDemodBuff(0, false, false, true);
    }

    if (verbose)
        printEM410x(*hi, *lo);

    return PM3_SUCCESS;
}

int AskEm410xDemod(int clk, int invert, int maxErr, size_t maxLen, bool amplify, uint32_t *hi, uint64_t *lo, bool verbose) {
    bool st = true;

    // em410x simulation etc uses 0/1 as signal data. This must be converted in order to demod it back again
    if (isGraphBitstream()) {
        convertGraphFromBitstream();
    }
    if (ASKDemod_ext(clk, invert, maxErr, maxLen, amplify, false, false, 1, &st) != PM3_SUCCESS)
        return PM3_ESOFT;
    return AskEm410xDecode(verbose, hi, lo);
}

// this read loops on device side.
// uses the demod in lfops.c
static int CmdEM410xWatch(const char *Cmd) {
    uint8_t c = tolower(param_getchar(Cmd, 0));
    if (c == 'h') return usage_lf_em410x_watch();

    PrintAndLogEx(SUCCESS, "Watching for EM410x cards - place tag on antenna");
    PrintAndLogEx(INFO, "Press pm3-button to stop reading cards");
    clearCommandBuffer();
    SendCommandNG(CMD_LF_EM410X_WATCH, NULL, 0);
    PacketResponseNG resp;
    WaitForResponse(CMD_LF_EM410X_WATCH, &resp);
    PrintAndLogEx(INFO, "Done");
    return resp.status;
}

//by marshmellow
//takes 3 arguments - clock, invert and maxErr as integers
//attempts to demodulate ask while decoding manchester
//prints binary found and saves in graphbuffer for further commands
int demodEM410x(bool verbose) {
    (void) verbose; // unused so far
    uint32_t hi = 0;
    uint64_t lo = 0;
    return AskEm410xDemod(0, 0, 100, 0, false, &hi, &lo, true);
}

static int CmdEM410xDemod(const char *Cmd) {
    char cmdp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) > 10 || cmdp == 'h') return usage_lf_em410x_demod();

    uint32_t hi = 0;
    uint64_t lo = 0;
    int clk = 0;
    int invert = 0;
    int maxErr = 100;
    size_t maxLen = 0;
    char amp = tolower(param_getchar(Cmd, 0));
    sscanf(Cmd, "%i %i %i %zu %c", &clk, &invert, &maxErr, &maxLen, &amp);
    bool amplify = amp == 'a';
    if (AskEm410xDemod(clk, invert, maxErr, maxLen, amplify, &hi, &lo, true) != PM3_SUCCESS)
        return PM3_ESOFT;

    g_em410xid = lo;
    return PM3_SUCCESS;
}

// this read is the "normal" read,  which download lf signal and tries to demod here.
static int CmdEM410xRead(const char *Cmd) {
    char cmdp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) > 10 || cmdp == 'h') return usage_lf_em410x_demod();

    uint32_t hi = 0;
    uint64_t lo = 0;
    int clk = 0;
    int invert = 0;
    int maxErr = 100;
    size_t maxLen = 0;
    char amp = tolower(param_getchar(Cmd, 0));
    sscanf(Cmd, "%i %i %i %zu %c", &clk, &invert, &maxErr, &maxLen, &amp);
    bool amplify = amp == 'a';
    lf_read(false, 12288);
    return AskEm410xDemod(clk, invert, maxErr, maxLen, amplify, &hi, &lo, true);
}

// emulate an EM410X tag
static int CmdEM410xSim(const char *Cmd) {
    char cmdp = tolower(param_getchar(Cmd, 0));
    if (cmdp == 'h') return usage_lf_em410x_sim();

    uint8_t uid[5] = {0x00};

    /* clock is 64 in EM410x tags */
    uint8_t clk = 64;

    if (param_gethex(Cmd, 0, uid, 10)) {
        PrintAndLogEx(FAILED, "UID must include 10 HEX symbols");
        return PM3_EINVARG;
    }

    param_getdec(Cmd, 1, &clk);

    PrintAndLogEx(SUCCESS, "Starting simulating UID "_YELLOW_("%02X%02X%02X%02X%02X")" clock: "_YELLOW_("%d"), uid[0], uid[1], uid[2], uid[3], uid[4], clk);
    PrintAndLogEx(SUCCESS, "Press pm3-button to abort simulation");

    ConstructEM410xEmulGraph(Cmd, clk);

    CmdLFSim("0"); //240 start_gap.
    return PM3_SUCCESS;
}

static int CmdEM410xBrute(const char *Cmd) {
    char filename[FILE_PATH_SIZE] = {0};
    FILE *f = NULL;
    char buf[11];
    uint32_t uidcnt = 0;
    uint8_t stUidBlock = 20;
    uint8_t *uidBlock = NULL, *p = NULL;
    uint8_t uid[5] = {0x00};
    /* clock is 64 in EM410x tags */
    uint8_t clock1 = 64;
    /* default pause time: 1 second */
    uint32_t delay = 1000;

    char cmdp = tolower(param_getchar(Cmd, 0));
    if (cmdp == 'h') return usage_lf_em410x_brute();

    cmdp = tolower(param_getchar(Cmd, 1));
    if (cmdp == 'd') {
        delay = param_get32ex(Cmd, 2, 1000, 10);
        param_getdec(Cmd, 4, &clock1);
    } else if (cmdp == 'c') {
        param_getdec(Cmd, 2, &clock1);
        delay = param_get32ex(Cmd, 4, 1000, 10);
    }

    int filelen = param_getstr(Cmd, 0, filename, FILE_PATH_SIZE);
    if (filelen == 0) {
        PrintAndLogEx(ERR, "Error: Please specify a filename");
        return PM3_EINVARG;
    }

    if ((f = fopen(filename, "r")) == NULL) {
        PrintAndLogEx(ERR, "Error: Could not open UIDs file ["_YELLOW_("%s")"]", filename);
        return PM3_EFILE;
    }

    uidBlock = calloc(stUidBlock, 5);
    if (uidBlock == NULL) {
        fclose(f);
        return PM3_ESOFT;
    }

    while (fgets(buf, sizeof(buf), f)) {
        if (strlen(buf) < 10 || buf[9] == '\n') continue;
        while (fgetc(f) != '\n' && !feof(f));  //goto next line

        //The line start with # is comment, skip
        if (buf[0] == '#') continue;

        if (param_gethex(buf, 0, uid, 10)) {
            PrintAndLogEx(FAILED, "UIDs must include 10 HEX symbols");
            free(uidBlock);
            fclose(f);
            return PM3_ESOFT;
        }

        buf[10] = 0;

        if (stUidBlock - uidcnt < 2) {
            p = realloc(uidBlock, 5 * (stUidBlock += 10));
            if (!p) {
                PrintAndLogEx(WARNING, "Cannot allocate memory for UIDs");
                free(uidBlock);
                fclose(f);
                return PM3_ESOFT;
            }
            uidBlock = p;
        }
        memset(uidBlock + 5 * uidcnt, 0, 5);
        num_to_bytes(strtoll(buf, NULL, 16), 5, uidBlock + 5 * uidcnt);
        uidcnt++;
        memset(buf, 0, sizeof(buf));
    }

    fclose(f);

    if (uidcnt == 0) {
        PrintAndLogEx(FAILED, "No UIDs found in file");
        free(uidBlock);
        return PM3_ESOFT;
    }

    PrintAndLogEx(SUCCESS, "Loaded "_YELLOW_("%d")" UIDs from "_YELLOW_("%s")", pause delay:"_YELLOW_("%d")" ms", uidcnt, filename, delay);

    // loop
    for (uint32_t c = 0; c < uidcnt; ++c) {
        char testuid[11];
        testuid[10] = 0;

        if (kbd_enter_pressed()) {
            PrintAndLogEx(WARNING, "\nAborted via keyboard!\n");
            free(uidBlock);
            return PM3_EOPABORTED;
        }

        sprintf(testuid, "%010" PRIX64, bytes_to_num(uidBlock + 5 * c, 5));
        PrintAndLogEx(NORMAL, "Bruteforce %d / %d: simulating UID  %s, clock %d", c + 1, uidcnt, testuid, clock1);

        ConstructEM410xEmulGraph(testuid, clock1);

        CmdLFSim("0"); //240 start_gap.

        msleep(delay);
    }

    free(uidBlock);
    return PM3_SUCCESS;
}

//currently only supports manchester modulations
static int CmdEM410xWatchnSpoof(const char *Cmd) {

    char cmdp = tolower(param_getchar(Cmd, 0));
    if (cmdp == 'h') return usage_lf_em410x_ws();

    // loops if the captured ID was in XL-format.
    CmdEM410xWatch(Cmd);
    PrintAndLogEx(SUCCESS, "# Replaying captured ID: "_YELLOW_("%010" PRIx64), g_em410xid);
    CmdLFaskSim("");
    return PM3_SUCCESS;
}

static int CmdEM410xClone(const char *Cmd) {
    char cmdp = tolower(param_getchar(Cmd, 0));
    if (cmdp == 0x00 || cmdp == 'h') return usage_lf_em410x_clone();

    uint64_t id = param_get64ex(Cmd, 0, -1, 16);
    uint8_t card = param_get8ex(Cmd, 1, 0xFF, 10);
    uint8_t clock1 = param_get8ex(Cmd, 2, 0, 10);

    // Check ID
    if (id == 0xFFFFFFFFFFFFFFFF) {
        PrintAndLogEx(ERR, "error, ID is required\n");
        usage_lf_em410x_clone();
        return PM3_EINVARG;
    }
    if (id >= 0x10000000000) {
        PrintAndLogEx(ERR, "error, given EM410x ID is longer than 40 bits\n");
        usage_lf_em410x_clone();
        return PM3_EINVARG;
    }

    // Check Card
    if (card > 1) {
        PrintAndLogEx(FAILED, "error, bad card type selected\n");
        usage_lf_em410x_clone();
        return PM3_EINVARG;
    }

    // Check Clock
    if (clock1 == 0)
        clock1 = 64;

    // Allowed clock rates: 16, 32, 40 and 64
    if ((clock1 != 16) && (clock1 != 32) && (clock1 != 64) && (clock1 != 40)) {
        PrintAndLogEx(FAILED, "error, clock rate" _RED_("%d")" not valid", clock1);
        PrintAndLogEx(INFO, "supported clock rates: " _YELLOW_("16, 32, 40, 60") "\n");
        usage_lf_em410x_clone();
        return PM3_EINVARG;
    }

    PrintAndLogEx(SUCCESS, "Writing " _YELLOW_("%s") " tag with UID 0x%010" PRIx64 " (clock rate: %d)", (card == 1) ? "T55x7" : "Q5/T5555", id, clock1);
    // NOTE: We really should pass the clock in as a separate argument, but to
    //   provide for backwards-compatibility for older firmware, and to avoid
    //   having to add another argument to CMD_LF_EM410X_WRITE, we just store
    //   the clock rate in bits 8-15 of the card value

    struct {
        uint8_t card;
        uint8_t clock;
        uint32_t high;
        uint32_t low;
    } PACKED params;

    params.card = card;
    params.clock = clock1;
    params.high = (uint32_t)(id >> 32);
    params.low = (uint32_t)id;

    clearCommandBuffer();
    SendCommandNG(CMD_LF_EM410X_WRITE, (uint8_t *)&params, sizeof(params));

    PacketResponseNG resp;
    WaitForResponse(CMD_LF_EM410X_WRITE, &resp);
    switch (resp.status) {
        case PM3_SUCCESS: {
            PrintAndLogEx(SUCCESS, "Done");
            PrintAndLogEx(HINT, "Hint: try " _YELLOW_("`lf em 410x_read`") " to verify");
            break;
        }
        default: {
            PrintAndLogEx(WARNING, "Something went wrong");
            break;
        }
    }
    return resp.status;
}

static command_t CommandTable[] = {
    {"help",        CmdHelp,              AlwaysAvailable, "This help"},
    //{"demod",  CmdEMdemodASK,        IfPm3Lf,         "Extract ID from EM410x tag on antenna)"},
    {"demod",  CmdEM410xDemod,       AlwaysAvailable, "demodulate a EM410x tag from the GraphBuffer"},
    {"read",   CmdEM410xRead,        IfPm3Lf,         "attempt to read and extract tag data"},
    {"sim",    CmdEM410xSim,         IfPm3Lf,         "simulate EM410x tag"},
    {"brute",  CmdEM410xBrute,       IfPm3Lf,         "reader bruteforce attack by simulating EM410x tags"},
    {"watch",  CmdEM410xWatch,       IfPm3Lf,         "watches for EM410x 125/134 kHz tags (option 'h' for 134)"},
    {"spoof",  CmdEM410xWatchnSpoof, IfPm3Lf,         "watches for EM410x 125/134 kHz tags, and replays them. (option 'h' for 134)" },
    {"clone",  CmdEM410xClone,       IfPm3Lf,         "write EM410x UID to T55x7 or Q5/T5555 tag"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdLFEM410X(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}
