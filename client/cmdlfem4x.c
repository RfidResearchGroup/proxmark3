//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency EM4x commands
//-----------------------------------------------------------------------------

#include "cmdlfem4x.h"

uint64_t g_em410xid = 0;

static int CmdHelp(const char *Cmd);

//////////////// 410x commands
int usage_lf_em410x_demod(void) {
    PrintAndLogEx(NORMAL, "Usage:  lf em 410x_demod [h] [clock] <0|1> [maxError]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "     h                   - this help");
    PrintAndLogEx(NORMAL, "     clock               -  set clock as integer, optional, if not set, autodetect.");
    PrintAndLogEx(NORMAL, "     <0|1>               - 0 normal output, 1 for invert output");
    PrintAndLogEx(NORMAL, "     maxerror            - set maximum allowed errors, default = 100.");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "           lf em 410x_demod        = demod an EM410x Tag ID from GraphBuffer");
    PrintAndLogEx(NORMAL, "           lf em 410x_demod 32     = demod an EM410x Tag ID from GraphBuffer using a clock of RF/32");
    PrintAndLogEx(NORMAL, "           lf em 410x_demod 32 1   = demod an EM410x Tag ID from GraphBuffer using a clock of RF/32 and inverting data");
    PrintAndLogEx(NORMAL, "           lf em 410x_demod 1      = demod an EM410x Tag ID from GraphBuffer while inverting data");
    PrintAndLogEx(NORMAL, "           lf em 410x_demod 64 1 0 = demod an EM410x Tag ID from GraphBuffer using a clock of RF/64 and inverting data and allowing 0 demod errors");
    return 0;
}
int usage_lf_em410x_write(void) {
    PrintAndLogEx(NORMAL, "Writes EM410x ID to a T55x7 / T5555 (Q5) tag");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  lf em 410x_write [h] <id> <card> [clock]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h         - this help");
    PrintAndLogEx(NORMAL, "       <id>      - ID number");
    PrintAndLogEx(NORMAL, "       <card>    - 0|1 T5555 (Q5) / T55x7");
    PrintAndLogEx(NORMAL, "       <clock>   - 16|32|40|64, optional, set R/F clock rate, defaults to 64");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      lf em 410x_write 0F0368568B 1       = write ID to t55x7 card");
    return 0;
}
int usage_lf_em410x_ws(void) {
    PrintAndLogEx(NORMAL, "Watch 'nd Spoof, activates reader, waits until a EM410x tag gets presented then it starts simulating the found UID");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  lf em 410x_spoof [h]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h         - this help");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      lf em 410x_spoof");
    return 0;
}
int usage_lf_em410x_clone(void) {
    PrintAndLogEx(NORMAL, "Simulating EM410x tag");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  lf em 410x_clone [h] <uid> <clock>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h         - this help");
    PrintAndLogEx(NORMAL, "       uid       - uid (10 HEX symbols)");
    PrintAndLogEx(NORMAL, "       clock     - clock (32|64) (optional)");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      lf em 410x_clone 0F0368568B");
    PrintAndLogEx(NORMAL, "      lf em 410x_clone 0F0368568B 32");
    return 0;
}
int usage_lf_em410x_sim(void) {
    PrintAndLogEx(NORMAL, "Simulating EM410x tag");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  lf em 410x_sim [h] <uid> <clock>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h         - this help");
    PrintAndLogEx(NORMAL, "       uid       - uid (10 HEX symbols)");
    PrintAndLogEx(NORMAL, "       clock     - clock (32|64) (optional)");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      lf em 410x_sim 0F0368568B");
    PrintAndLogEx(NORMAL, "      lf em 410x_sim 0F0368568B 32");
    return 0;
}
int usage_lf_em410x_brute(void) {
    PrintAndLogEx(NORMAL, "Bruteforcing by emulating EM410x tag");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  lf em 410x_brute [h] ids.txt [d 2000] [c clock]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h             - this help");
    PrintAndLogEx(NORMAL, "       ids.txt       - file with UIDs in HEX format, one per line");
    PrintAndLogEx(NORMAL, "       d (2000)      - pause delay in milliseconds between UIDs simulation, default 1000 ms (optional)");
    PrintAndLogEx(NORMAL, "       c (32)        - clock (32|64), default 64 (optional)");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      lf em 410x_brute ids.txt");
    PrintAndLogEx(NORMAL, "      lf em 410x_brute ids.txt c 32");
    PrintAndLogEx(NORMAL, "      lf em 410x_brute ids.txt d 3000");
    PrintAndLogEx(NORMAL, "      lf em 410x_brute ids.txt d 3000 c 32");
    return 0;
}

//////////////// 4050 / 4450 commands
int usage_lf_em4x50_dump(void) {
    PrintAndLogEx(NORMAL, "Dump EM4x50/EM4x69.  Tag must be on antenna. ");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  lf em 4x50_dump [h] <pwd>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h         - this help");
    PrintAndLogEx(NORMAL, "       pwd       - password (hex) (optional)");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      lf em 4x50_dump");
    PrintAndLogEx(NORMAL, "      lf em 4x50_dump 11223344");
    return 0;
}
int usage_lf_em4x50_read(void) {
    PrintAndLogEx(NORMAL, "Read EM 4x50/EM4x69.  Tag must be on antenna. ");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  lf em 4x50_read [h] <address> <pwd>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h         - this help");
    PrintAndLogEx(NORMAL, "       address   - memory address to read. (0-15)");
    PrintAndLogEx(NORMAL, "       pwd       - password (hex) (optional)");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      lf em 4x50_read 1");
    PrintAndLogEx(NORMAL, "      lf em 4x50_read 1 11223344");
    return 0;
}
int usage_lf_em4x50_write(void) {
    PrintAndLogEx(NORMAL, "Write EM 4x50/4x69.  Tag must be on antenna. ");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  lf em 4x50_write [h] <address> <data> <pwd>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h         - this help");
    PrintAndLogEx(NORMAL, "       address   - memory address to write to. (0-15)");
    PrintAndLogEx(NORMAL, "       data      - data to write (hex)");
    PrintAndLogEx(NORMAL, "       pwd       - password (hex) (optional)");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      lf em 4x50_write 1 deadc0de");
    PrintAndLogEx(NORMAL, "      lf em 4x50_write 1 deadc0de 11223344");
    return 0;
}

//////////////// 4205 / 4305 commands
int usage_lf_em4x05_dump(void) {
    PrintAndLogEx(NORMAL, "Dump EM4x05/EM4x69.  Tag must be on antenna. ");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  lf em 4x05_dump [h] <pwd>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h         - this help");
    PrintAndLogEx(NORMAL, "       pwd       - password (hex) (optional)");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      lf em 4x05_dump");
    PrintAndLogEx(NORMAL, "      lf em 4x05_dump 11223344");
    return 0;
}
int usage_lf_em4x05_read(void) {
    PrintAndLogEx(NORMAL, "Read EM4x05/EM4x69.  Tag must be on antenna. ");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  lf em 4x05_read [h] <address> <pwd>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h         - this help");
    PrintAndLogEx(NORMAL, "       address   - memory address to read. (0-15)");
    PrintAndLogEx(NORMAL, "       pwd       - password (hex) (optional)");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      lf em 4x05_read 1");
    PrintAndLogEx(NORMAL, "      lf em 4x05_read 1 11223344");
    return 0;
}
int usage_lf_em4x05_write(void) {
    PrintAndLogEx(NORMAL, "Write EM4x05/4x69.  Tag must be on antenna. ");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  lf em 4x05_write [h] <address> <data> <pwd>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h         - this help");
    PrintAndLogEx(NORMAL, "       address   - memory address to write to. (0-15)");
    PrintAndLogEx(NORMAL, "       data      - data to write (hex)");
    PrintAndLogEx(NORMAL, "       pwd       - password (hex) (optional)");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      lf em 4x05_write 1 deadc0de");
    PrintAndLogEx(NORMAL, "      lf em 4x05_write 1 deadc0de 11223344");
    return 0;
}
int usage_lf_em4x05_info(void) {
    PrintAndLogEx(NORMAL, "Tag information EM4205/4305/4469//4569 tags.  Tag must be on antenna.");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  lf em 4x05_info [h] <pwd>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h         - this help");
    PrintAndLogEx(NORMAL, "       pwd       - password (hex) (optional)");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      lf em 4x05_info");
    PrintAndLogEx(NORMAL, "      lf em 4x05_info deadc0de");
    return 0;
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
void ConstructEM410xEmulGraph(const char *uid, const  uint8_t clock) {

    int i, j, binary[4], parity[4];
    uint32_t n;
    /* clear our graph */
    ClearGraph(false);

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

    PrintAndLogEx(SUCCESS, "EM410x %s pattern found", (hi) ? "XL" : "");

    uint64_t iii = 1;
    uint64_t id2lo = 0;
    uint32_t ii = 0;
    uint32_t i = 0;
    for (ii = 5; ii > 0; ii--) {
        for (i = 0; i < 8; i++) {
            id2lo = (id2lo << 1LL) | ((id & (iii << (i + ((ii - 1) * 8)))) >> (i + ((ii - 1) * 8)));
        }
    }

    if (hi) {
        //output 88 bit em id
        PrintAndLogEx(NORMAL, "\nEM TAG ID      : %06X%016" PRIX64, hi, id);
    } else {
        //output 40 bit em id
        PrintAndLogEx(NORMAL, "\nEM TAG ID      : %010" PRIX64, id);
        PrintAndLogEx(NORMAL, "\nPossible de-scramble patterns");
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
        int i = 0;
        int j = 23;
        for (; i < 24; ++i, --j) {
            arr[i] = (p1id >> i) & 1;
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
    if (!getDemodBuf(bits, &size)) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - Em410x problem during copy from ASK demod");
        return 0;
    }

    int ans = Em410xDecode(bits, &size, &idx, hi, lo);
    if (ans < 0) {

        if (ans == -2)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Em410x not enough samples after demod");
        else if (ans == -4)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Em410x preamble not found");
        else if (ans == -5)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Em410x Size not correct: %d", size);
        else if (ans == -6)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Em410x parity failed");

        return 0;
    }
    if (!lo && !hi) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - Em410x decoded to all zeros");
        return 0;
    }

    //set GraphBuffer for clone or sim command
    setDemodBuf(DemodBuffer, (size == 40) ? 64 : 128, idx + 1);
    setClockGrid(g_DemodClock, g_DemodStartIdx + ((idx + 1)*g_DemodClock));

    PrintAndLogEx(DEBUG, "DEBUG: Em410x idx: %d, Len: %d, Printing Demod Buffer:", idx, size);
    if (g_debugMode)
        printDemodBuff();

    if (verbose)
        printEM410x(*hi, *lo);

    return 1;
}
int AskEm410xDemod(const char *Cmd, uint32_t *hi, uint64_t *lo, bool verbose) {
    bool st = true;
    if (!ASKDemod_ext(Cmd, false, false, 1, &st)) return 0;
    return AskEm410xDecode(verbose, hi, lo);
}

// this read is the "normal" read,  which download lf signal and tries to demod here.
int CmdEM410xRead(const char *Cmd) {
    lf_read(true, 8192);
    return CmdEM410xDemod(Cmd);
}

// this read loops on device side.
// uses the demod in lfops.c
int CmdEM410xRead_device(const char *Cmd) {
    char cmdp = tolower(param_getchar(Cmd, 0));
    uint8_t findone = (cmdp == '1') ? 1 : 0;
    UsbCommand c = {CMD_EM410X_DEMOD, {findone, 0, 0}};
    SendCommand(&c);
    return 0;
}

//by marshmellow
//takes 3 arguments - clock, invert and maxErr as integers
//attempts to demodulate ask while decoding manchester
//prints binary found and saves in graphbuffer for further commands
int CmdEM410xDemod(const char *Cmd) {
    char cmdp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) > 10 || cmdp == 'h') return usage_lf_em410x_demod();

    uint32_t hi = 0;
    uint64_t lo = 0;

    if (AskEm410xDemod(Cmd, &hi, &lo, true) != 1) return 0;

    g_em410xid = lo;
    return 1;
}

// emulate an EM410X tag
int CmdEM410xSim(const char *Cmd) {
    char cmdp = tolower(param_getchar(Cmd, 0));
    if (cmdp == 'h') return usage_lf_em410x_sim();

    uint8_t uid[5] = {0x00};

    /* clock is 64 in EM410x tags */
    uint8_t clock = 64;

    if (param_gethex(Cmd, 0, uid, 10)) {
        PrintAndLogEx(FAILED, "UID must include 10 HEX symbols");
        return 0;
    }

    param_getdec(Cmd, 1, &clock);

    PrintAndLogEx(SUCCESS, "Starting simulating UID %02X%02X%02X%02X%02X  clock: %d", uid[0], uid[1], uid[2], uid[3], uid[4], clock);
    PrintAndLogEx(SUCCESS, "Press pm3-button to abort simulation");

    ConstructEM410xEmulGraph(Cmd, clock);

    CmdLFSim("0"); //240 start_gap.
    return 0;
}

int CmdEM410xBrute(const char *Cmd) {
    char filename[FILE_PATH_SIZE] = {0};
    FILE *f = NULL;
    char buf[11];
    uint32_t uidcnt = 0;
    uint8_t stUidBlock = 20;
    uint8_t *uidBlock = NULL, *p = NULL;
    uint8_t uid[5] = {0x00};
    /* clock is 64 in EM410x tags */
    uint8_t clock = 64;
    /* default pause time: 1 second */
    uint32_t delay = 1000;

    char cmdp = tolower(param_getchar(Cmd, 0));
    if (cmdp == 'h') return usage_lf_em410x_brute();

    cmdp = tolower(param_getchar(Cmd, 1));
    if (cmdp == 'd') {
        delay = param_get32ex(Cmd, 2, 1000, 10);
        param_getdec(Cmd, 4, &clock);
    } else if (cmdp == 'c') {
        param_getdec(Cmd, 2, &clock);
        delay = param_get32ex(Cmd, 4, 1000, 10);
    }

    int filelen = param_getstr(Cmd, 0, filename, FILE_PATH_SIZE);
    if (filelen == 0) {
        PrintAndLogEx(WARNING, "Error: Please specify a filename");
        return 1;
    }

    if ((f = fopen(filename, "r")) == NULL) {
        PrintAndLogEx(WARNING, "Error: Could not open UIDs file [%s]", filename);
        return 1;
    }

    uidBlock = calloc(stUidBlock, 5);
    if (uidBlock == NULL) {
        fclose(f);
        return 1;
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
            return 1;
        }

        buf[10] = 0;

        if (stUidBlock - uidcnt < 2) {
            p = realloc(uidBlock, 5 * (stUidBlock += 10));
            if (!p) {
                PrintAndLogEx(WARNING, "Cannot allocate memory for UIDs");
                free(uidBlock);
                fclose(f);
                return 1;
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
        return 1;
    }

    PrintAndLogEx(SUCCESS, "Loaded %d UIDs from %s, pause delay: %d ms", uidcnt, filename, delay);

    // loop
    for (uint32_t c = 0; c < uidcnt; ++c) {
        char testuid[11];
        testuid[10] = 0;

        if (ukbhit()) {
            int gc = getchar();
            (void)gc;
            PrintAndLogEx(WARNING, "\nAborted via keyboard!\n");
            free(uidBlock);
            return 0;
        }

        sprintf(testuid, "%010" PRIX64, bytes_to_num(uidBlock + 5 * c, 5));
        PrintAndLogEx(NORMAL, "Bruteforce %d / %d: simulating UID  %s, clock %d", c + 1, uidcnt, testuid, clock);

        ConstructEM410xEmulGraph(testuid, clock);

        CmdLFSim("0"); //240 start_gap.

        msleep(delay);
    }

    free(uidBlock);
    return 0;
}

/* Function is equivalent of lf read + data samples + em410xread
 * looped until an EM410x tag is detected
 *
 * Why is CmdSamples("16000")?
 *  TBD: Auto-grow sample size based on detected sample rate.  IE: If the
 *       rate gets lower, then grow the number of samples
 *  Changed by martin, 4000 x 4 = 16000,
 *  see http://www.proxmark.org/forum/viewtopic.php?pid=7235#p7235
 *
 *  EDIT -- capture enough to get 2 complete preambles at the slowest data rate known to be used (rf/64) (64*64*2+9 = 8201) marshmellow
*/
int CmdEM410xWatch(const char *Cmd) {
    do {
        if (ukbhit()) {
            int gc = getchar();
            (void)gc;
            PrintAndLogEx(WARNING, "\naborted via keyboard!\n");
            break;
        }
        lf_read(true, 8201);

    } while (!CmdEM410xRead(""));
    return 0;
}

//currently only supports manchester modulations
int CmdEM410xWatchnSpoof(const char *Cmd) {

    char cmdp = tolower(param_getchar(Cmd, 0));
    if (cmdp == 'h') return usage_lf_em410x_ws();

    // loops if the captured ID was in XL-format.
    CmdEM410xWatch(Cmd);
    PrintAndLogEx(SUCCESS, "# Replaying captured ID: %010" PRIx64, g_em410xid);
    CmdLFaskSim("");
    return 0;
}

int CmdEM410xWrite(const char *Cmd) {
    char cmdp = tolower(param_getchar(Cmd, 0));
    if (cmdp == 0x00 || cmdp == 'h') return usage_lf_em410x_write();

    uint64_t id = 0xFFFFFFFFFFFFFFFF; // invalid id value
    int card = 0xFF; // invalid card value
    uint32_t clock = 0; // invalid clock value

    sscanf(Cmd, "%" SCNx64 " %d %d", &id, &card, &clock);

    // Check ID
    if (id == 0xFFFFFFFFFFFFFFFF) {
        PrintAndLogEx(WARNING, "Error! ID is required.\n");
        return 0;
    }
    if (id >= 0x10000000000) {
        PrintAndLogEx(WARNING, "Error! Given EM410x ID is longer than 40 bits.\n");
        return 0;
    }

    // Check Card
    if (card == 0xFF) {
        PrintAndLogEx(WARNING, "Error! Card type required.\n");
        return 0;
    }
    if (card < 0) {
        PrintAndLogEx(WARNING, "Error! Bad card type selected.\n");
        return 0;
    }

    // Check Clock
    if (clock == 0)
        clock = 64;

    // Allowed clock rates: 16, 32, 40 and 64
    if ((clock != 16) && (clock != 32) && (clock != 64) && (clock != 40)) {
        PrintAndLogEx(WARNING, "Error! Clock rate %d not valid. Supported clock rates are 16, 32, 40 and 64.\n", clock);
        return 0;
    }

    if (card == 1) {
        PrintAndLogEx(SUCCESS, "Writing %s tag with UID 0x%010" PRIx64 " (clock rate: %d)", "T55x7", id, clock);
        // NOTE: We really should pass the clock in as a separate argument, but to
        //   provide for backwards-compatibility for older firmware, and to avoid
        //   having to add another argument to CMD_EM410X_WRITE_TAG, we just store
        //   the clock rate in bits 8-15 of the card value
        card = (card & 0xFF) | ((clock << 8) & 0xFF00);
    } else if (card == 0) {
        PrintAndLogEx(SUCCESS, "Writing %s tag with UID 0x%010" PRIx64, "T5555", id, clock);
        card = (card & 0xFF) | ((clock << 8) & 0xFF00);
    } else {
        PrintAndLogEx(FAILED, "Error! Bad card type selected.\n");
        return 0;
    }

    UsbCommand c = {CMD_EM410X_WRITE_TAG, {card, (uint32_t)(id >> 32), (uint32_t)id}};
    SendCommand(&c);
    return 0;
}

//**************** Start of EM4x50 Code ************************
bool EM_EndParityTest(uint8_t *bs, size_t size, uint8_t rows, uint8_t cols, uint8_t pType) {
    if (rows * cols > size) return false;
    uint8_t colP = 0;
    //assume last col is a parity and do not test
    for (uint8_t colNum = 0; colNum < cols - 1; colNum++) {
        for (uint8_t rowNum = 0; rowNum < rows; rowNum++) {
            colP ^= bs[(rowNum * cols) + colNum];
        }
        if (colP != pType) return false;
    }
    return true;
}

bool EM_ByteParityTest(uint8_t *bs, size_t size, uint8_t rows, uint8_t cols, uint8_t pType) {
    if (rows * cols > size) return false;

    uint8_t rowP = 0;
    //assume last row is a parity row and do not test
    for (uint8_t rowNum = 0; rowNum < rows - 1; rowNum++) {
        for (uint8_t colNum = 0; colNum < cols; colNum++) {
            rowP ^= bs[(rowNum * cols) + colNum];
        }
        if (rowP != pType) return false;
    }
    return true;
}

// EM word parity test.
// 9*5 = 45 bits in total
// 012345678|r1
// 012345678|r2
// 012345678|r3
// 012345678|r4
// ------------
//c012345678| 0
//            |- must be zero

bool EMwordparitytest(uint8_t *bits) {

    // last row/col parity must be 0
    if (bits[44] != 0) return false;

    // col parity check
    uint8_t c1 = bytebits_to_byte(bits, 8) ^ bytebits_to_byte(bits + 9, 8) ^ bytebits_to_byte(bits + 18, 8) ^ bytebits_to_byte(bits + 27, 8);
    uint8_t c2 = bytebits_to_byte(bits + 36, 8);
    if (c1 != c2) return false;

    // row parity check
    uint8_t rowP = 0;
    for (uint8_t i = 0; i < 36; ++i) {

        rowP ^= bits[i];
        if (i > 0 && (i % 9) == 0) {

            if (rowP != EVEN)
                return false;

            rowP = 0;
        }
    }
    // all checks ok.
    return true;
}

//////////////// 4050 / 4450 commands

uint32_t OutputEM4x50_Block(uint8_t *BitStream, size_t size, bool verbose, bool pTest) {
    if (size < 45) return 0;

    uint32_t code = bytebits_to_byte(BitStream, 8);
    code = code << 8 | bytebits_to_byte(BitStream + 9, 8);
    code = code << 8 | bytebits_to_byte(BitStream + 18, 8);
    code = code << 8 | bytebits_to_byte(BitStream + 27, 8);

    if (verbose || g_debugMode) {
        for (uint8_t i = 0; i < 5; i++) {
            if (i == 4) PrintAndLogEx(NORMAL, ""); //parity byte spacer
            PrintAndLogEx(NORMAL, "%d%d%d%d%d%d%d%d %d -> 0x%02x",
                          BitStream[i * 9],
                          BitStream[i * 9 + 1],
                          BitStream[i * 9 + 2],
                          BitStream[i * 9 + 3],
                          BitStream[i * 9 + 4],
                          BitStream[i * 9 + 5],
                          BitStream[i * 9 + 6],
                          BitStream[i * 9 + 7],
                          BitStream[i * 9 + 8],
                          bytebits_to_byte(BitStream + i * 9, 8)
                         );
        }

        PrintAndLogEx(SUCCESS, "Parity checks | %s", (pTest) ? _GREEN_("Passed") : _RED_("Failed"));
    }
    return code;
}

/* Read the transmitted data of an EM4x50 tag from the graphbuffer
 * Format:
 *
 *  XXXXXXXX [row parity bit (even)] <- 8 bits plus parity
 *  XXXXXXXX [row parity bit (even)] <- 8 bits plus parity
 *  XXXXXXXX [row parity bit (even)] <- 8 bits plus parity
 *  XXXXXXXX [row parity bit (even)] <- 8 bits plus parity
 *  CCCCCCCC                         <- column parity bits
 *  0                                <- stop bit
 *  LW                               <- Listen Window
 *
 * This pattern repeats for every block of data being transmitted.
 * Transmission starts with two Listen Windows (LW - a modulated
 * pattern of 320 cycles each (32/32/128/64/64)).
 *
 * Note that this data may or may not be the UID. It is whatever data
 * is stored in the blocks defined in the control word First and Last
 * Word Read values. UID is stored in block 32.
 */
//completed by Marshmellow
int EM4x50Read(const char *Cmd, bool verbose) {
    uint8_t fndClk[] = {8, 16, 32, 40, 50, 64, 128};
    int clk = 0, invert = 0, tol = 0, phaseoff;
    int i = 0, j = 0, startblock, skip, block, start, end, low = 0, high = 0, minClk = 255;
    uint32_t Code[6];
    char tmp[6];
    char tmp2[20];
    bool complete = false;

    int tmpbuff[MAX_GRAPH_TRACE_LEN / 64];
    memset(tmpbuff, 0, sizeof(tmpbuff));

    // get user entry if any
    sscanf(Cmd, "%i %i", &clk, &invert);

    uint8_t bits[MAX_GRAPH_TRACE_LEN] = {0};
    size_t size = getFromGraphBuf(bits);
    computeSignalProperties(bits, size);

    signal_t *sp = getSignalProperties();
    high = sp->high;
    low = sp->low;

    // get to first full low to prime loop and skip incomplete first pulse
    while ((i < size) && (bits[i] < high))
        ++i;
    while ((i < size) && (bits[i] > low))
        ++i;
    skip = i;

    // populate tmpbuff buffer with pulse lengths
    while (i < size) {
        // measure from low to low
        while ((i < size) && (bits[i] > low))
            ++i;
        start = i;
        while ((i < size) && (bits[i] < high))
            ++i;
        while ((i < size) && (bits[i] > low))
            ++i;
        if (j >= (MAX_GRAPH_TRACE_LEN / 64)) {
            break;
        }
        tmpbuff[j++] = i - start;
        if (i - start < minClk && i < size) {
            minClk = i - start;
        }
    }
    // set clock
    if (!clk) {
        for (uint8_t clkCnt = 0; clkCnt < 7; clkCnt++) {
            tol = fndClk[clkCnt] / 8;
            if (minClk >= fndClk[clkCnt] - tol && minClk <= fndClk[clkCnt] + 1) {
                clk = fndClk[clkCnt];
                break;
            }
        }
        if (!clk) {
            if (verbose || g_debugMode) PrintAndLogEx(WARNING, "Error: EM4x50 - didn't find a clock");
            return 0;
        }
    } else tol = clk / 8;

    // look for data start - should be 2 pairs of LW (pulses of clk*3,clk*2)
    start = -1;
    for (i = 0; i < j - 4 ; ++i) {
        skip += tmpbuff[i];
        if (tmpbuff[i] >= clk * 3 - tol && tmpbuff[i] <= clk * 3 + tol)  //3 clocks
            if (tmpbuff[i + 1] >= clk * 2 - tol && tmpbuff[i + 1] <= clk * 2 + tol) //2 clocks
                if (tmpbuff[i + 2] >= clk * 3 - tol && tmpbuff[i + 2] <= clk * 3 + tol) //3 clocks
                    if (tmpbuff[i + 3] >= clk - tol) { //1.5 to 2 clocks - depends on bit following
                        start = i + 4;
                        break;
                    }
    }
    startblock = i + 4;

    // skip over the remainder of LW
    skip += (tmpbuff[i + 1] + tmpbuff[i + 2] + clk);

    if (tmpbuff[i + 3] > clk)
        phaseoff = tmpbuff[i + 3] - clk;
    else
        phaseoff = 0;

    // now do it again to find the end
    end = skip;
    for (i += 3; i < j - 4 ; ++i) {
        end += tmpbuff[i];
        if (tmpbuff[i] >= clk * 3 - tol && tmpbuff[i] <= clk * 3 + tol)  //3 clocks
            if (tmpbuff[i + 1] >= clk * 2 - tol && tmpbuff[i + 1] <= clk * 2 + tol) //2 clocks
                if (tmpbuff[i + 2] >= clk * 3 - tol && tmpbuff[i + 2] <= clk * 3 + tol) //3 clocks
                    if (tmpbuff[i + 3] >= clk - tol) { //1.5 to 2 clocks - depends on bit following
                        complete = true;
                        break;
                    }
    }
    end = i;
    // report back
    if (verbose || g_debugMode) {
        if (start >= 0) {
            PrintAndLogEx(NORMAL, "\nNote: one block = 50 bits (32 data, 12 parity, 6 marker)");
        } else {
            PrintAndLogEx(NORMAL, "No data found!, clock tried:%d", clk);
            PrintAndLogEx(NORMAL, "Try again with more samples.");
            PrintAndLogEx(NORMAL, "  or after a 'data askedge' command to clean up the read");
            return 0;
        }
    } else if (start < 0) return 0;

    start = skip;
    snprintf(tmp2, sizeof(tmp2), "%d %d 1000 %d", clk, invert, clk * 47);
    // save GraphBuffer - to restore it later
    save_restoreGB(GRAPH_SAVE);
    // get rid of leading crap
    snprintf(tmp, sizeof(tmp), "%i", skip);
    CmdLtrim(tmp);
    bool pTest;
    bool AllPTest = true;
    // now work through remaining buffer printing out data blocks
    block = 0;
    i = startblock;
    while (block < 6) {
        if (verbose || g_debugMode) PrintAndLogEx(NORMAL, "\nBlock %i:", block);
        skip = phaseoff;

        // look for LW before start of next block
        for (; i < j - 4 ; ++i) {
            skip += tmpbuff[i];
            if (tmpbuff[i] >= clk * 3 - tol && tmpbuff[i] <= clk * 3 + tol)
                if (tmpbuff[i + 1] >= clk - tol)
                    break;
        }
        if (i >= j - 4) break; //next LW not found
        skip += clk;
        if (tmpbuff[i + 1] > clk)
            phaseoff = tmpbuff[i + 1] - clk;
        else
            phaseoff = 0;

        i += 2;

        if (ASKDemod(tmp2, false, false, 1) < 1) {
            save_restoreGB(GRAPH_RESTORE);
            return 0;
        }
        //set DemodBufferLen to just one block
        DemodBufferLen = skip / clk;
        //test parities
        pTest = EM_ByteParityTest(DemodBuffer, DemodBufferLen, 5, 9, 0);
        pTest &= EM_EndParityTest(DemodBuffer, DemodBufferLen, 5, 9, 0);
        AllPTest &= pTest;
        //get output
        Code[block] = OutputEM4x50_Block(DemodBuffer, DemodBufferLen, verbose, pTest);
        PrintAndLogEx(DEBUG, "\nskipping %d samples, bits:%d", skip, skip / clk);
        //skip to start of next block
        snprintf(tmp, sizeof(tmp), "%i", skip);
        CmdLtrim(tmp);
        block++;
        if (i >= end) break; //in case chip doesn't output 6 blocks
    }
    //print full code:
    if (verbose || g_debugMode || AllPTest) {
        if (!complete) {
            PrintAndLogEx(NORMAL, _RED_("* **Warning!"));
            PrintAndLogEx(NORMAL, "Partial data - no end found!");
            PrintAndLogEx(NORMAL, "Try again with more samples.");
        }
        PrintAndLogEx(NORMAL, "Found data at sample: %i - using clock: %i", start, clk);
        end = block;
        for (block = 0; block < end; block++) {
            PrintAndLogEx(NORMAL, "Block %d: %08x", block, Code[block]);
        }

        PrintAndLogEx(NORMAL, "Parities checks | %s", (AllPTest) ? _GREEN_("Passed") : _RED_("Failed"));

        if (AllPTest == 0) {
            PrintAndLogEx(NORMAL, "Try cleaning the read samples with " _YELLOW_("'data askedge'"));
        }
    }

    //restore GraphBuffer
    save_restoreGB(GRAPH_RESTORE);
    return (int)AllPTest;
}

int CmdEM4x50Read(const char *Cmd) {
    uint8_t ctmp = tolower(param_getchar(Cmd, 0));
    if (ctmp == 'h') return usage_lf_em4x50_read();
    return EM4x50Read(Cmd, true);
}
int CmdEM4x50Write(const char *Cmd) {
    uint8_t ctmp = tolower(param_getchar(Cmd, 0));
    if (ctmp == 'h') return usage_lf_em4x50_write();
    PrintAndLogEx(NORMAL, "no implemented yet");
    return 0;
}
int CmdEM4x50Dump(const char *Cmd) {
    uint8_t ctmp = tolower(param_getchar(Cmd, 0));
    if (ctmp == 'h') return usage_lf_em4x50_dump();
    PrintAndLogEx(NORMAL, "no implemented yet");
    return 0;
}

#define EM_PREAMBLE_LEN 6
// download samples from device and copy to Graphbuffer
bool downloadSamplesEM() {

    // 8 bit preamble + 32 bit word response (max clock (128) * 40bits = 5120 samples)
    uint8_t got[6000];
    if (!GetFromDevice(BIG_BUF, got, sizeof(got), 0, NULL, 2500, false)) {
        PrintAndLogEx(WARNING, "command execution time out");
        return false;
    }

    setGraphBuf(got, sizeof(got));
    // set signal properties low/high/mean/amplitude and is_noise detection
    computeSignalProperties(got, sizeof(got));
    RepaintGraphWindow();
    if (getSignalProperties()->isnoise) {
        PrintAndLogEx(DEBUG, "No tag found - signal looks like noise");
        return false;
    }
    return true;
}

// em_demod
bool doPreambleSearch(size_t *startIdx) {

    // sanity check
    if (DemodBufferLen < EM_PREAMBLE_LEN) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - EM4305 demodbuffer too small");
        return false;
    }

    // set size to 20 to only test first 14 positions for the preamble
    size_t size = (20 > DemodBufferLen) ? DemodBufferLen : 20;
    *startIdx = 0;
    // skip first two 0 bits as they might have been missed in the demod
    uint8_t preamble[EM_PREAMBLE_LEN] = {0, 0, 1, 0, 1, 0};

    if (!preambleSearchEx(DemodBuffer, preamble, EM_PREAMBLE_LEN, &size, startIdx, true)) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - EM4305 preamble not found :: %d", *startIdx);
        return false;
    }
    return true;
}

bool detectFSK() {
    // detect fsk clock
    if (!GetFskClock("", false)) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - EM: FSK clock failed");
        return false;
    }
    // demod
    int ans = FSKrawDemod("0 0", false);
    if (!ans) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - EM: FSK Demod failed");
        return false;
    }
    return true;
}
// PSK clocks should be easy to detect ( but difficult to demod a non-repeating pattern... )
bool detectPSK() {
    int ans = GetPskClock("", false);
    if (ans <= 0) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - EM: PSK clock failed");
        return false;
    }
    //demod
    //try psk1 -- 0 0 6 (six errors?!?)
    ans = PSKDemod("0 0 6", false);
    if (!ans) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - EM: PSK1 Demod failed");

        //try psk1 inverted
        ans = PSKDemod("0 1 6", false);
        if (!ans) {
            PrintAndLogEx(DEBUG, "DEBUG: Error - EM: PSK1 inverted Demod failed");
            return false;
        }
    }
    // either PSK1 or PSK1 inverted is ok from here.
    // lets check PSK2 later.
    return true;
}
// try manchester - NOTE: ST only applies to T55x7 tags.
bool detectASK_MAN() {
    bool stcheck = false;
    if (!ASKDemod_ext("0 0 0", false, false, 1, &stcheck)) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - EM: ASK/Manchester Demod failed");
        return false;
    }
    return true;
}
bool detectASK_BI() {
    int ans = ASKbiphaseDemod("0 0 1", false);
    if (!ans) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - EM: ASK/biphase normal demod failed");

        ans = ASKbiphaseDemod("0 1 1", false);
        if (!ans) {
            PrintAndLogEx(DEBUG, "DEBUG: Error - EM: ASK/biphase inverted demod failed");
            return false;
        }
    }
    return true;
}

// param: idx - start index in demoded data.
bool setDemodBufferEM(uint32_t *word, size_t idx) {

    //test for even parity bits.
    uint8_t parity[45] = {0};
    memcpy(parity, DemodBuffer, 45);
    if (!EMwordparitytest(parity)) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - EM Parity tests failed");
        return false;
    }

    // test for even parity bits and remove them. (leave out the end row of parities so 36 bits)
    if (!removeParity(DemodBuffer, idx + EM_PREAMBLE_LEN, 9, 0, 36)) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - EM, failed removing parity");
        return false;
    }
    setDemodBuf(DemodBuffer, 32, 0);
    *word = bytebits_to_byteLSBF(DemodBuffer, 32);
    return true;
}

// FSK, PSK, ASK/MANCHESTER, ASK/BIPHASE, ASK/DIPHASE
// should cover 90% of known used configs
// the rest will need to be manually demoded for now...
bool demodEM4x05resp(uint32_t *word) {
    size_t idx = 0;
    *word = 0;
    if (detectASK_MAN() && doPreambleSearch(&idx))
        return setDemodBufferEM(word, idx);

    if (detectASK_BI() && doPreambleSearch(&idx))
        return setDemodBufferEM(word, idx);

    if (detectFSK() && doPreambleSearch(&idx))
        return setDemodBufferEM(word, idx);

    if (detectPSK()) {
        if (doPreambleSearch(&idx))
            return setDemodBufferEM(word, idx);

        psk1TOpsk2(DemodBuffer, DemodBufferLen);
        if (doPreambleSearch(&idx))
            return setDemodBufferEM(word, idx);
    }
    return false;
}

//////////////// 4205 / 4305 commands
int EM4x05ReadWord_ext(uint8_t addr, uint32_t pwd, bool usePwd, uint32_t *word) {
    UsbCommand c = {CMD_EM4X_READ_WORD, {addr, pwd, usePwd}};
    clearCommandBuffer();
    SendCommand(&c);
    UsbCommand resp;
    if (!WaitForResponseTimeout(CMD_ACK, &resp, 2500)) {
        PrintAndLogEx(DEBUG, "timeout while waiting for reply.");
        return -1;
    }
    if (!downloadSamplesEM()) {
        return -1;
    }

    return demodEM4x05resp(word);
}

int CmdEM4x05Dump(const char *Cmd) {
    uint8_t addr = 0;
    uint32_t pwd = 0;
    bool usePwd = false;
    uint8_t ctmp = tolower(param_getchar(Cmd, 0));
    if (ctmp == 'h') return usage_lf_em4x05_dump();

    // for now use default input of 1 as invalid (unlikely 1 will be a valid password...)
    pwd = param_get32ex(Cmd, 0, 1, 16);

    if (pwd != 1)
        usePwd = true;

    int success = 1;
    uint32_t word = 0;
    PrintAndLogEx(NORMAL, "Addr | data   | ascii");
    PrintAndLogEx(NORMAL, "-----+--------+------");
    for (; addr < 16; addr++) {

        if (addr == 2) {
            if (usePwd) {
                PrintAndLogEx(NORMAL, " %02u | %08X", addr, pwd, word);
            } else {
                PrintAndLogEx(NORMAL, " 02 | " _RED_("cannot read"));
            }
        } else {
            success &= EM4x05ReadWord_ext(addr, pwd, usePwd, &word);
        }
    }

    return success;
}

int CmdEM4x05Read(const char *Cmd) {
    uint8_t addr;
    uint32_t pwd;
    bool usePwd = false;
    uint8_t ctmp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) == 0 || ctmp == 'h') return usage_lf_em4x05_read();

    addr = param_get8ex(Cmd, 0, 50, 10);
    pwd =  param_get32ex(Cmd, 1, 1, 16);

    if (addr > 15) {
        PrintAndLogEx(NORMAL, "Address must be between 0 and 15");
        return 1;
    }
    if (pwd == 1) {
        PrintAndLogEx(NORMAL, "Reading address %02u", addr);
    } else {
        usePwd = true;
        PrintAndLogEx(NORMAL, "Reading address %02u | password %08X", addr, pwd);
    }

    uint32_t word = 0;
    int isOk = EM4x05ReadWord_ext(addr, pwd, usePwd, &word);
    if (isOk)
        PrintAndLogEx(NORMAL, "Address %02d | %08X - %s", addr, word, (addr > 13) ? "Lock" : "");
    else
        PrintAndLogEx(NORMAL, "Read Address %02d | " _RED_("failed"), addr);
    return isOk;
}

int CmdEM4x05Write(const char *Cmd) {
    uint8_t ctmp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) == 0 || ctmp == 'h') return usage_lf_em4x05_write();

    bool usePwd = false;
    uint8_t addr = 50; // default to invalid address
    uint32_t data = 0; // default to blank data
    uint32_t pwd = 1; // default to blank password

    addr = param_get8ex(Cmd, 0, 50, 10);
    data = param_get32ex(Cmd, 1, 0, 16);
    pwd =  param_get32ex(Cmd, 2, 1, 16);

    if (addr > 15) {
        PrintAndLogEx(NORMAL, "Address must be between 0 and 15");
        return 1;
    }
    if (pwd == 1)
        PrintAndLogEx(NORMAL, "Writing address %d data %08X", addr, data);
    else {
        usePwd = true;
        PrintAndLogEx(NORMAL, "Writing address %d data %08X using password %08X", addr, data, pwd);
    }

    uint16_t flag = (addr << 8) | (usePwd);

    UsbCommand c = {CMD_EM4X_WRITE_WORD, {flag, data, pwd}};
    clearCommandBuffer();
    SendCommand(&c);
    UsbCommand resp;
    if (!WaitForResponseTimeout(CMD_ACK, &resp, 2000)) {
        PrintAndLogEx(WARNING, "Error occurred, device did not respond during write operation.");
        return -1;
    }

    if (!downloadSamplesEM())
        return -1;

    //need 0 bits demoded (after preamble) to verify write cmd
    uint32_t dummy = 0;
    int isOk = demodEM4x05resp(&dummy);
    if (isOk)
        PrintAndLogEx(NORMAL, "Write " _GREEN_("Verified"));
    else
        PrintAndLogEx(NORMAL, "Write could " _RED_("not") "be verified");
    return isOk;
}

void printEM4x05config(uint32_t wordData) {
    uint16_t datarate = (((wordData & 0x3F) + 1) * 2);
    uint8_t encoder = ((wordData >> 6) & 0xF);
    char enc[14];
    memset(enc, 0, sizeof(enc));

    uint8_t PSKcf = (wordData >> 10) & 0x3;
    char cf[10];
    memset(cf, 0, sizeof(cf));
    uint8_t delay = (wordData >> 12) & 0x3;
    char cdelay[33];
    memset(cdelay, 0, sizeof(cdelay));
    uint8_t numblks = EM4x05_GET_NUM_BLOCKS(wordData);
    uint8_t LWR = numblks + 5 - 1; //last word read
    switch (encoder) {
        case 0:
            snprintf(enc, sizeof(enc), "NRZ");
            break;
        case 1:
            snprintf(enc, sizeof(enc), "Manchester");
            break;
        case 2:
            snprintf(enc, sizeof(enc), "Biphase");
            break;
        case 3:
            snprintf(enc, sizeof(enc), "Miller");
            break;
        case 4:
            snprintf(enc, sizeof(enc), "PSK1");
            break;
        case 5:
            snprintf(enc, sizeof(enc), "PSK2");
            break;
        case 6:
            snprintf(enc, sizeof(enc), "PSK3");
            break;
        case 7:
            snprintf(enc, sizeof(enc), "Unknown");
            break;
        case 8:
            snprintf(enc, sizeof(enc), "FSK1");
            break;
        case 9:
            snprintf(enc, sizeof(enc), "FSK2");
            break;
        default:
            snprintf(enc, sizeof(enc), "Unknown");
            break;
    }

    switch (PSKcf) {
        case 0:
            snprintf(cf, sizeof(cf), "RF/2");
            break;
        case 1:
            snprintf(cf, sizeof(cf), "RF/8");
            break;
        case 2:
            snprintf(cf, sizeof(cf), "RF/4");
            break;
        case 3:
            snprintf(cf, sizeof(cf), "unknown");
            break;
    }

    switch (delay) {
        case 0:
            snprintf(cdelay, sizeof(cdelay), "no delay");
            break;
        case 1:
            snprintf(cdelay, sizeof(cdelay), "BP/8 or 1/8th bit period delay");
            break;
        case 2:
            snprintf(cdelay, sizeof(cdelay), "BP/4 or 1/4th bit period delay");
            break;
        case 3:
            snprintf(cdelay, sizeof(cdelay), "no delay");
            break;
    }
    uint8_t readLogin = (wordData & EM4x05_READ_LOGIN_REQ) >> 18;
    uint8_t readHKL = (wordData & EM4x05_READ_HK_LOGIN_REQ) >> 19;
    uint8_t writeLogin = (wordData & EM4x05_WRITE_LOGIN_REQ) >> 20;
    uint8_t writeHKL = (wordData & EM4x05_WRITE_HK_LOGIN_REQ) >> 21;
    uint8_t raw = (wordData & EM4x05_READ_AFTER_WRITE) >> 22;
    uint8_t disable = (wordData & EM4x05_DISABLE_ALLOWED) >> 23;
    uint8_t rtf = (wordData & EM4x05_READER_TALK_FIRST) >> 24;
    uint8_t pigeon = (wordData & (1 << 26)) >> 26;
    PrintAndLogEx(NORMAL, "ConfigWord: %08X (Word 4)\n", wordData);
    PrintAndLogEx(NORMAL, "Config Breakdown:");
    PrintAndLogEx(NORMAL, " Data Rate:  %02u | RF/%u", wordData & 0x3F, datarate);
    PrintAndLogEx(NORMAL, "   Encoder:   %u | %s", encoder, enc);
    PrintAndLogEx(NORMAL, "    PSK CF:   %u | %s", PSKcf, cf);
    PrintAndLogEx(NORMAL, "     Delay:   %u | %s", delay, cdelay);
    PrintAndLogEx(NORMAL, " LastWordR:  %02u | Address of last word for default read - meaning %u blocks are output", LWR, numblks);
    PrintAndLogEx(NORMAL, " ReadLogin:   %u | Read Login is %s", readLogin, readLogin ? "Required" : "Not Required");
    PrintAndLogEx(NORMAL, "   ReadHKL:   %u | Read Housekeeping Words Login is %s", readHKL, readHKL ? "Required" : "Not Required");
    PrintAndLogEx(NORMAL, "WriteLogin:   %u | Write Login is %s", writeLogin, writeLogin ? "Required" : "Not Required");
    PrintAndLogEx(NORMAL, "  WriteHKL:   %u | Write Housekeeping Words Login is %s", writeHKL, writeHKL ? "Required" : "Not Required");
    PrintAndLogEx(NORMAL, "    R.A.W.:   %u | Read After Write is %s", raw, raw ? "On" : "Off");
    PrintAndLogEx(NORMAL, "   Disable:   %u | Disable Command is %s", disable, disable ? "Accepted" : "Not Accepted");
    PrintAndLogEx(NORMAL, "    R.T.F.:   %u | Reader Talk First is %s", rtf, rtf ? "Enabled" : "Disabled");
    PrintAndLogEx(NORMAL, "    Pigeon:   %u | Pigeon Mode is %s\n", pigeon, pigeon ? "Enabled" : "Disabled");
}

void printEM4x05info(uint32_t block0, uint32_t serial) {

    uint8_t chipType = (block0 >> 1) & 0xF;
    uint8_t cap = (block0 >> 5) & 3;
    uint16_t custCode = (block0 >> 9) & 0x3FF;

    switch (chipType) {
        case 9:
            PrintAndLogEx(NORMAL, "\n Chip Type:   %u | EM4305", chipType);
            break;
        case 8:
            PrintAndLogEx(NORMAL, "\n Chip Type:   %u | EM4205", chipType);
            break;
        case 4:
            PrintAndLogEx(NORMAL, " Chip Type:   %u | Unknown", chipType);
            break;
        case 2:
            PrintAndLogEx(NORMAL, " Chip Type:   %u | EM4469", chipType);
            break;
        //add more here when known
        default:
            PrintAndLogEx(NORMAL, " Chip Type:   %u Unknown", chipType);
            break;
    }

    switch (cap) {
        case 3:
            PrintAndLogEx(NORMAL, "  Cap Type:   %u | 330pF", cap);
            break;
        case 2:
            PrintAndLogEx(NORMAL, "  Cap Type:   %u | %spF", cap, (chipType == 2) ? "75" : "210");
            break;
        case 1:
            PrintAndLogEx(NORMAL, "  Cap Type:   %u | 250pF", cap);
            break;
        case 0:
            PrintAndLogEx(NORMAL, "  Cap Type:   %u | no resonant capacitor", cap);
            break;
        default:
            PrintAndLogEx(NORMAL, "  Cap Type:   %u | unknown", cap);
            break;
    }

    PrintAndLogEx(NORMAL, " Cust Code: %03u | %s", custCode, (custCode == 0x200) ? "Default" : "Unknown");
    if (serial != 0)
        PrintAndLogEx(NORMAL, "\n  Serial #: %08X\n", serial);
}

void printEM4x05ProtectionBits(uint32_t word) {
    for (uint8_t i = 0; i < 15; i++) {
        PrintAndLogEx(NORMAL, "      Word:  %02u | %s", i, (((1 << i) & word) || i < 2) ? "Is Write Locked" : "Is Not Write Locked");
        if (i == 14)
            PrintAndLogEx(NORMAL, "      Word:  %02u | %s", i + 1, (((1 << i) & word) || i < 2) ? "Is Write Locked" : "Is Not Write Locked");
    }
}

//quick test for EM4x05/EM4x69 tag
bool EM4x05IsBlock0(uint32_t *word) {
    int res = EM4x05ReadWord_ext(0, 0, false, word);
    return (res > 0) ? true : false;
}

int CmdEM4x05Info(const char *Cmd) {
#define EM_SERIAL_BLOCK 1
#define EM_CONFIG_BLOCK 4
#define EM_PROT1_BLOCK 14
#define EM_PROT2_BLOCK 15
    uint32_t pwd;
    uint32_t word = 0, block0 = 0, serial = 0;
    bool usePwd = false;
    uint8_t ctmp = tolower(param_getchar(Cmd, 0));
    if (ctmp == 'h') return usage_lf_em4x05_info();

    // for now use default input of 1 as invalid (unlikely 1 will be a valid password...)
    pwd = param_get32ex(Cmd, 0, 1, 16);

    if (pwd != 1)
        usePwd = true;

    // read word 0 (chip info)
    // block 0 can be read even without a password.
    if (!EM4x05IsBlock0(&block0))
        return -1;

    // read word 1 (serial #) doesn't need pwd
    // continue if failed, .. non blocking fail.
    EM4x05ReadWord_ext(EM_SERIAL_BLOCK, 0, false, &serial);
    printEM4x05info(block0, serial);

    // read word 4 (config block)
    // needs password if one is set
    if (EM4x05ReadWord_ext(EM_CONFIG_BLOCK, pwd, usePwd, &word) != 1)
        return 0;

    printEM4x05config(word);

    // read word 14 and 15 to see which is being used for the protection bits
    if (EM4x05ReadWord_ext(EM_PROT1_BLOCK, pwd, usePwd, &word) != 1) {
        return 0;
    }
    // if status bit says this is not the used protection word
    if (!(word & 0x8000)) {
        if (EM4x05ReadWord_ext(EM_PROT2_BLOCK, pwd, usePwd, &word) != 1)
            return 0;
    }
    //something went wrong
    if (!(word & 0x8000)) return 0;
    printEM4x05ProtectionBits(word);
    return 1;
}

static command_t CommandTable[] = {
    {"help",        CmdHelp,              1, "This help"},
    //{"410x_demod",  CmdEMdemodASK,        0, "Extract ID from EM410x tag on antenna)"},
    {"410x_demod",  CmdEM410xDemod,       1, "demodulate a EM410x tag from the GraphBuffer"},
    {"410x_read",   CmdEM410xRead,        0, "attempt to read and extract tag data"},
    {"410x_sim",    CmdEM410xSim,         0, "simulate EM410x tag"},
    {"410x_brute",  CmdEM410xBrute,       0, "reader bruteforce attack by simulating EM410x tags"},
    {"410x_watch",  CmdEM410xWatch,       0, "watches for EM410x 125/134 kHz tags (option 'h' for 134)"},
    {"410x_spoof",  CmdEM410xWatchnSpoof, 0, "watches for EM410x 125/134 kHz tags, and replays them. (option 'h' for 134)" },
    {"410x_write",  CmdEM410xWrite,       0, "write EM410x UID to T5555(Q5) or T55x7 tag"},
    {"4x05_dump",   CmdEM4x05Dump,        0, "dump EM4x05/EM4x69 tag"},
    {"4x05_info",   CmdEM4x05Info,        0, "tag information EM4x05/EM4x69"},
    {"4x05_read",   CmdEM4x05Read,        0, "read word data from EM4x05/EM4x69"},
    {"4x05_write",  CmdEM4x05Write,       0, "write word data to EM4x05/EM4x69"},
    {"4x50_dump",   CmdEM4x50Dump,        0, "dump EM4x50 tag"},
    {"4x50_read",   CmdEM4x50Read,        0, "read word data from EM4x50"},
    {"4x50_write",  CmdEM4x50Write,       0, "write word data to EM4x50"},
    {NULL, NULL, 0, NULL}
};

int CmdLFEM4X(const char *Cmd) {
    clearCommandBuffer();
    CmdsParse(CommandTable, Cmd);
    return 0;
}

int CmdHelp(const char *Cmd) {
    CmdsHelp(CommandTable);
    return 0;
}
