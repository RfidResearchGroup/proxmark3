//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
// 2016,2017, marshmellow, iceman
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency HID commands
//-----------------------------------------------------------------------------

#include "cmdlfhid.h"

#ifndef BITS
# define BITS 96
#endif

static int CmdHelp(const char *Cmd);

int usage_lf_hid_read(void) {
    PrintAndLogEx(NORMAL, "Enables HID compatible reader mode printing details.");
    PrintAndLogEx(NORMAL, "By default, values are printed and logged until the button is pressed or another USB command is issued.");
    PrintAndLogEx(NORMAL, "If the [1] option is provided, reader mode is exited after reading a single HID card.");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  lf hid read [h] [1]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "      h :  This help");
    PrintAndLogEx(NORMAL, "      1 : (optional) stop after reading a single card");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "       lf hid read");
    PrintAndLogEx(NORMAL, "       lf hid read 1");
    return 0;
}
int usage_lf_hid_wiegand(void) {
    PrintAndLogEx(NORMAL, "This command converts facility code/card number to Wiegand code");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage: lf hid wiegand [h] [OEM] [FC] [CN]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h             - This help");
    PrintAndLogEx(NORMAL, "       OEM           - OEM number / site code");
    PrintAndLogEx(NORMAL, "       FC            - facility code");
    PrintAndLogEx(NORMAL, "       CN            - card number");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      lf hid wiegand 0 101 2001");
    return 0;
}
int usage_lf_hid_sim(void) {
    PrintAndLogEx(NORMAL, "Enables simulation of HID card with card number.");
    PrintAndLogEx(NORMAL, "Simulation runs until the button is pressed or another USB command is issued.");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  lf hid sim [h] [ID]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h   - This help");
    PrintAndLogEx(NORMAL, "       ID  - HID id");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      lf hid sim 2006ec0c86");
    return 0;
}
int usage_lf_hid_clone(void) {
    PrintAndLogEx(NORMAL, "Clone HID to T55x7.  Tag must be on antenna. ");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  lf hid clone [h] [ID] <L>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h   - This help");
    PrintAndLogEx(NORMAL, "       ID  - HID id");
    PrintAndLogEx(NORMAL, "       L   - 84bit ID");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      lf hid clone 2006ec0c86");
    PrintAndLogEx(NORMAL, "      lf hid clone 2006ec0c86 L");
    return 0;
}
int usage_lf_hid_brute(void) {
    PrintAndLogEx(NORMAL, "Enables bruteforce of HID readers with specified facility code.");
    PrintAndLogEx(NORMAL, "This is a attack against reader. if cardnumber is given, it starts with it and goes up / down one step");
    PrintAndLogEx(NORMAL, "if cardnumber is not given, it starts with 1 and goes up to 65535");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  lf hid brute [h] [v] a <format> f <facility-code> c <cardnumber> d <delay>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "       h                 :  This help");
    PrintAndLogEx(NORMAL, "       a <format>        :  26|33|34|35|37|40|44|84");
    PrintAndLogEx(NORMAL, "       f <facility-code> :  8-bit value HID facility code");
    PrintAndLogEx(NORMAL, "       c <cardnumber>    :  (optional) cardnumber to start with, max 65535");
    PrintAndLogEx(NORMAL, "       d <delay>         :  delay betweens attempts in ms. Default 1000ms");
    PrintAndLogEx(NORMAL, "       v                 :  verbose logging, show all tries");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "       lf hid brute a 26 f 224");
    PrintAndLogEx(NORMAL, "       lf hid brute a 26 f 21 d 2000");
    PrintAndLogEx(NORMAL, "       lf hid brute v a 26 f 21 c 200 d 2000");
    return 0;
}

// sending three times.  Didn't seem to break the previous sim?
static bool sendPing(void) {
    UsbCommand ping = {CMD_PING, {1, 2, 3}};
    SendCommand(&ping);
    SendCommand(&ping);
    SendCommand(&ping);
    clearCommandBuffer();
    UsbCommand resp;
    if (!WaitForResponseTimeout(CMD_ACK, &resp, 1000))
        return false;
    return true;
}
static bool sendTry(uint8_t fmtlen, uint32_t fc, uint32_t cn, uint32_t delay, uint8_t *bits, bool verbose) {

    // this should be optional.
    if (verbose)
        PrintAndLogEx(INFO, "Trying FC: %u; CN: %u", fc, cn);

    calcWiegand(fmtlen, fc, cn, bits);

    uint64_t arg1 = bytebits_to_byte(bits, 32);
    uint64_t arg2 = bytebits_to_byte(bits + 32, 32);
    UsbCommand c = {CMD_HID_SIM_TAG, {arg1, arg2, 0}};
    clearCommandBuffer();
    SendCommand(&c);

    msleep(delay);
    sendPing();
    return true;
}

//by marshmellow (based on existing demod + holiman's refactor)
//HID Prox demod - FSK RF/50 with preamble of 00011101 (then manchester encoded)
//print full HID Prox ID and some bit format details if found
int CmdHIDDemod(const char *Cmd) {
    //raw fsk demod no manchester decoding no start bit finding just get binary from wave
    uint32_t hi2 = 0, hi = 0, lo = 0;

    uint8_t bits[MAX_GRAPH_TRACE_LEN] = {0};
    size_t size = getFromGraphBuf(bits);
    if (size == 0) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - HID not enough samples");
        return 0;
    }
    //get binary from fsk wave
    int waveIdx = 0;
    int idx = HIDdemodFSK(bits, &size, &hi2, &hi, &lo, &waveIdx);
    if (idx < 0) {

        if (idx == -1)
            PrintAndLogEx(DEBUG, "DEBUG: Error - HID not enough samples");
        else if (idx == -2)
            PrintAndLogEx(DEBUG, "DEBUG: Error - HID just noise detected");
        else if (idx == -3)
            PrintAndLogEx(DEBUG, "DEBUG: Error - HID problem during FSK demod");
        else if (idx == -4)
            PrintAndLogEx(DEBUG, "DEBUG: Error - HID preamble not found");
        else if (idx == -5)
            PrintAndLogEx(DEBUG, "DEBUG: Error - HID error in Manchester data, size %d", size);
        else
            PrintAndLogEx(DEBUG, "DEBUG: Error - HID error demoding fsk %d", idx);

        return 0;
    }

    setDemodBuf(bits, size, idx);
    setClockGrid(50, waveIdx + (idx * 50));

    if (hi2 == 0 && hi == 0 && lo == 0) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - HID no values found");
        return 0;
    }

    if (hi2 != 0) { //extra large HID tags
        PrintAndLogEx(SUCCESS, "HID Prox TAG ID: %x%08x%08x (%u)", hi2, hi, lo, (lo >> 1) & 0xFFFF);
    } else {  //standard HID tags <38 bits
        uint8_t fmtLen = 0;
        uint32_t cc = 0;
        uint32_t fc = 0;
        uint32_t cardnum = 0;
        if (((hi >> 5) & 1) == 1) {//if bit 38 is set then < 37 bit format is used
            uint32_t lo2 = 0;
            lo2 = (((hi & 31) << 12) | (lo >> 20)); //get bits 21-37 to check for format len bit
            uint8_t idx3 = 1;
            while (lo2 > 1) { //find last bit set to 1 (format len bit)
                lo2 >>= 1;
                idx3++;
            }
            fmtLen = idx3 + 19;
            fc = 0;
            cardnum = 0;
            if (fmtLen == 26) {
                cardnum = (lo >> 1) & 0xFFFF;
                fc = (lo >> 17) & 0xFF;
            }
            if (fmtLen == 32 && (lo & 0x40000000)) { //if 32 bit and Kastle bit set
                cardnum = (lo >> 1) & 0xFFFF;
                fc = (lo >> 17) & 0xFF;
                cc = (lo >> 25) & 0x1F;
            }
            if (fmtLen == 34) {
                cardnum = (lo >> 1) & 0xFFFF;
                fc = ((hi & 1) << 15) | (lo >> 17);
            }
            if (fmtLen == 35) {
                cardnum = (lo >> 1) & 0xFFFFF;
                fc = ((hi & 1) << 11) | (lo >> 21);
            }
        } else { //if bit 38 is not set then 37 bit format is used
            fmtLen = 37;
            fc = 0;
            cardnum = 0;
            if (fmtLen == 37) {
                cardnum = (lo >> 1) & 0x7FFFF;
                fc = ((hi & 0xF) << 12) | (lo >> 20);
            }
        }
        if (fmtLen == 32 && (lo & 0x40000000)) { //if 32 bit and Kastle bit set
            PrintAndLogEx(SUCCESS, "HID Prox TAG (Kastle format) ID: %08x (%u) - Format Len: 32bit - CC: %u - FC: %u - Card: %u", lo, (lo >> 1) & 0xFFFF, cc, fc, cardnum);
        } else {
            PrintAndLogEx(SUCCESS, "HID Prox TAG ID: %x%08x (%u) - Format Len: %ubit - FC: %u - Card: %u", hi, lo, (lo >> 1) & 0xFFFF, fmtLen, fc, cardnum);
        }
    }

    PrintAndLogEx(DEBUG, "DEBUG: HID idx: %d, Len: %d, Printing Demod Buffer:", idx, size);
    if (g_debugMode)
        printDemodBuff();

    return 1;
}

// this read is the "normal" read,  which download lf signal and tries to demod here.
int CmdHIDRead(const char *Cmd) {
    lf_read(true, 12000);
    return CmdHIDDemod(Cmd);
}

// this read loops on device side.
// uses the demod in lfops.c
int CmdHIDRead_device(const char *Cmd) {

    if (Cmd[0] == 'h' || Cmd[0] == 'H') return usage_lf_hid_read();
    uint8_t findone = (Cmd[0] == '1') ? 1 : 0;
    UsbCommand c = {CMD_HID_DEMOD_FSK, {findone, 0, 0}};
    clearCommandBuffer();
    SendCommand(&c);
    return 0;
}

int CmdHIDSim(const char *Cmd) {
    uint32_t hi = 0, lo = 0;
    uint32_t n = 0, i = 0;

    uint8_t ctmp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) == 0 || ctmp == 'h') return usage_lf_hid_sim();

    while (sscanf(&Cmd[i++], "%1x", &n) == 1) {
        hi = (hi << 4) | (lo >> 28);
        lo = (lo << 4) | (n & 0xf);
    }

    PrintAndLogEx(SUCCESS, "Simulating HID tag with ID %x%08x", hi, lo);
    PrintAndLogEx(SUCCESS, "Press pm3-button to abort simulation");

    UsbCommand c = {CMD_HID_SIM_TAG, {hi, lo, 0}};
    clearCommandBuffer();
    SendCommand(&c);
    return 0;
}

int CmdHIDClone(const char *Cmd) {

    uint32_t hi2 = 0, hi = 0, lo = 0;
    uint32_t n = 0, i = 0;
    UsbCommand c = {CMD_HID_CLONE_TAG};

    uint8_t ctmp = param_getchar(Cmd, 0);
    if (strlen(Cmd) == 0 || ctmp == 'H' || ctmp == 'h') return usage_lf_hid_clone();

    if (strchr(Cmd, 'l') != 0) {
        while (sscanf(&Cmd[i++], "%1x", &n) == 1) {
            hi2 = (hi2 << 4) | (hi >> 28);
            hi = (hi << 4) | (lo >> 28);
            lo = (lo << 4) | (n & 0xf);
        }

        PrintAndLogEx(INFO, "Preparing to clone HID tag with long ID %x%08x%08x", hi2, hi, lo);

        c.d.asBytes[0] = 1;
    } else {
        while (sscanf(&Cmd[i++], "%1x", &n) == 1) {
            hi = (hi << 4) | (lo >> 28);
            lo = (lo << 4) | (n & 0xf);
        }
        PrintAndLogEx(INFO, "Preparing to clone HID tag with ID %x%08x", hi, lo);
        hi2 = 0;
        c.d.asBytes[0] = 0;
    }

    c.arg[0] = hi2;
    c.arg[1] = hi;
    c.arg[2] = lo;

    clearCommandBuffer();
    SendCommand(&c);
    return 0;
}
// struct to handle wiegand
typedef struct {
    uint8_t  FormatLen;
    uint8_t  SiteCode;
    uint8_t  FacilityCode;
    uint8_t  CardNumber;
    uint8_t *Wiegand;
    size_t   Wiegand_n;
} wiegand_t;

static void addHIDMarker(uint8_t fmtlen, uint8_t *out) {
    // temp array
    uint8_t arr[BITS];
    memset(arr, 0, BITS);

    // copy inpu
    uint8_t pos = sizeof(arr) - fmtlen;
    memcpy(arr + pos, out, fmtlen);

    switch (fmtlen) {
        case 26: {
            // start sentinel, BITS-bit 27 = 1
            arr[BITS - 27] = 1;
            // fmt smaller than 37 used,  bit37 = 1
            arr[BITS - 38]  = 1;
            memcpy(out, arr, BITS);
            break;
        }
        case 34:
            // start sentinel, BITS-bit 27 = 1
            arr[BITS - 35] = 1;

            // fmt smaller than 37 used,  bit37 = 1
            arr[BITS - 38]  = 1;
            memcpy(out, arr, BITS);
            break;
        default:
            break;
    }
}

// static void getParity34(uint32_t *hi, uint32_t *lo){
// uint32_t result = 0;
// int i;

// // even parity
// for (i = 7;i >= 0;i--)
// result ^= (*hi >> i) & i;
// for (i = 31;i >= 24;i--)
// result ^= (*lo >> i) & 1;

// *hi |= result << 2;

// // odd parity bit
// result = 0;
// for (i = 23;i >= 1;i--)
// result ^= (*lo >> i) & 1;

// *lo |= !result;
// }
// static void getParity37H(uint32_t *hi, uint32_t *lo){
// uint32_t result = 0;
// int i;

// // even parity
// for (i = 4;i >= 0;i--)
// result ^= (*hi >> i) & 1;
// for (i = 31;i >= 20;i--)
// result ^= (*lo >> i) & 1;
// *hi |= result << 4;

// // odd parity
// result = 0;
// for (i = 19;i >= 1;i--)
// result ^= (*lo >> i) & 1;
// *lo |= result;
// }

//static void calc26(uint16_t fc, uint32_t cardno,  uint8_t *out){
static void calc26(uint16_t fc, uint32_t cardno, uint8_t *out) {
    uint8_t wiegand[24];
    num_to_bytebits(fc, 8, wiegand);
    num_to_bytebits(cardno, 16, wiegand + 8);
    wiegand_add_parity(out,  wiegand, sizeof(wiegand));
}
// static void calc33(uint16_t fc, uint32_t cardno,  uint8_t *out){
// }
static void calc34(uint16_t fc, uint32_t cardno, uint8_t *out) {
    uint8_t wiegand[32];
    num_to_bytebits(fc, 16, wiegand);
    num_to_bytebits(cardno, 16, wiegand + 16);
    wiegand_add_parity(out,  wiegand, sizeof(wiegand));
}
// static void calc35(uint16_t fc, uint32_t cardno,  uint8_t *out){
// *lo = ((cardno & 0xFFFFF) << 1) | fc << 21;
// *hi = (1 << 5) | ((fc >> 11) & 1);
// }
static void calc37S(uint16_t fc, uint32_t cardno, uint8_t *out) {
    // FC 2 - 17   - 16 bit
    // cardno 18 - 36  - 19 bit
    // Even P1   1 - 19
    // Odd  P37  19 - 36
    uint8_t wiegand[35];
    num_to_bytebits(fc, 16, wiegand);
    num_to_bytebits(cardno, 19, wiegand + 16);
    wiegand_add_parity(out,  wiegand, sizeof(wiegand));
}
static void calc37H(uint64_t cardno, uint8_t *out) {
    // SC NONE
    // cardno 1-35 34 bits
    // Even Parity  0th bit  1-18
    // Odd  Parity 36th bit 19-35
    uint8_t wiegand[37];
    num_to_bytebits((uint32_t)(cardno >> 32), 2, wiegand);
    num_to_bytebits((uint32_t)(cardno >> 0), 32, wiegand + 2);
    wiegand_add_parity(out,  wiegand, sizeof(wiegand));

    PrintAndLogEx(NORMAL, "%x %x\n", (uint32_t)(cardno >> 32), (uint32_t)cardno);
}
// static void calc40(uint64_t cardno,  uint8_t *out){
// cardno = (cardno & 0xFFFFFFFFFF);
// *lo = ((cardno & 0xFFFFFFFF) << 1 );
// *hi = (cardno >> 31);
// }

void calcWiegand(uint8_t fmtlen, uint16_t fc, uint64_t cardno, uint8_t *bits) {
    uint32_t cn32 = (cardno & 0xFFFFFFFF);
    switch (fmtlen) {
        case 26:
            calc26(fc, cn32, bits);
            break;
        // case 33 : calc33(fc, cn32, bits); break;
        case 34:
            calc34(fc, cn32, bits);
            break;
        // case 35 : calc35(fc, cn32, bits); break;
        case 37:
            calc37S(fc, cn32, bits);
            break;
        case 38:
            calc37H(cardno, bits);
            break;
        // case 40 : calc40(cardno, bits); break;
        // case 44 : { break; }
        // case 84 : { break; }
        default:
            break;
    }
}

int CmdHIDWiegand(const char *Cmd) {
    uint32_t oem = 0, fc = 0;
    uint64_t cardnum = 0;
    uint64_t blocks = 0, wiegand = 0;

    uint8_t bits[BITS];
    uint8_t *bs = bits;
    memset(bs, 0, sizeof(bits));

    uint8_t ctmp = param_getchar(Cmd, 0);
    if (strlen(Cmd) == 0 || strlen(Cmd) < 3 || ctmp == 'H' || ctmp == 'h') return usage_lf_hid_wiegand();

    oem = param_get8(Cmd, 0);
    fc = param_get32ex(Cmd, 1, 0, 10);
    cardnum = param_get64ex(Cmd, 2, 0, 10);

    uint8_t fmtlen[] = {26, 33, 34, 35, 37, 38, 40};

    PrintAndLogEx(NORMAL, "HID | OEM | FC   | CN      |  Wiegand  |  HID Formatted");
    PrintAndLogEx(NORMAL, "----+-----+------+---------+-----------+--------------------");
    for (uint8_t i = 0; i < sizeof(fmtlen); i++) {
        memset(bits, 0x00, sizeof(bits));
        calcWiegand(fmtlen[i], fc, cardnum, bs);
        PrintAndLogEx(NORMAL, "ice:: %s \n", sprint_bin(bs, fmtlen[i]));
        wiegand = (uint64_t)bytebits_to_byte(bs, 32) << 32 | bytebits_to_byte(bs + 32, 32);

        addHIDMarker(fmtlen[i], bs);
        PrintAndLogEx(NORMAL, "ice:: %s\n", sprint_bin(bs, BITS));
        blocks = (uint64_t)bytebits_to_byte(bs + 32, 32) << 32 | bytebits_to_byte(bs + 64, 32);
        uint8_t shifts = 64 - fmtlen[i];
        wiegand >>= shifts;

        PrintAndLogEx(NORMAL, " %u | %03u | %03u  | %" PRIu64 "  | %" PRIX64 "  |  %" PRIX64,
                      fmtlen[i],
                      oem,
                      fc,
                      cardnum,
                      wiegand,
                      blocks
                     );
    }
    PrintAndLogEx(NORMAL, "----+-----+-----+-------+-----------+--------------------");
    return 0;
}

int CmdHIDBrute(const char *Cmd) {

    bool errors = false, verbose = false;
    uint32_t fc = 0, cn = 0, delay = 1000;
    uint8_t fmtlen = 0;
    uint8_t bits[96];
    memset(bits, 0, sizeof(bits));
    uint8_t cmdp = 0;

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_lf_hid_brute();
            case 'f':
                fc =  param_get32ex(Cmd, cmdp + 1, 0, 10);
                if (!fc)
                    errors = true;
                cmdp += 2;
                break;
            case 'd':
                // delay between attemps,  defaults to 1000ms.
                delay = param_get32ex(Cmd, cmdp + 1, 1000, 10);
                cmdp += 2;
                break;
            case 'c':
                cn = param_get32ex(Cmd, cmdp + 1, 0, 10);
                // truncate cardnumber.
                cn &= 0xFFFF;
                cmdp += 2;
                break;
            case 'a':
                fmtlen = param_get8(Cmd, cmdp + 1);
                cmdp += 2;
                bool is_ftm_ok = false;
                uint8_t ftms[] = {26, 33, 34, 35, 37};
                for (uint8_t i = 0; i < sizeof(ftms); i++) {
                    if (ftms[i] == fmtlen) {
                        is_ftm_ok = true;
                    }
                }
                // negated
                errors = !is_ftm_ok;
                break;
            case 'v':
                verbose = true;
                cmdp++;
                break;
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }
    if (fc == 0) errors = true;
    if (errors) return usage_lf_hid_brute();

    PrintAndLogEx(INFO, "Brute-forcing HID reader");
    PrintAndLogEx(INFO, "Press pm3-button to abort simulation or run another command");

    uint16_t up = cn;
    uint16_t down = cn;

    // main loop
    for (;;) {

        if (IsOffline()) {
            PrintAndLogEx(WARNING, "Device offline\n");
            return  2;
        }

        if (ukbhit()) {
            int gc = getchar();
            (void)gc;
            PrintAndLogEx(INFO, "aborted via keyboard!");
            return sendPing();
        }

        // Do one up
        if (up < 0xFFFF)
            if (!sendTry(fmtlen, fc, up++, delay, bits, verbose)) return 1;

        // Do one down  (if cardnumber is given)
        if (cn > 1)
            if (down > 1)
                if (!sendTry(fmtlen, fc, --down, delay, bits, verbose)) return 1;
    }
    return 0;
}

static command_t CommandTable[] = {
    {"help",    CmdHelp,        1, "this help"},
    {"demod",   CmdHIDDemod,    0, "demodulate HID Prox tag from the GraphBuffer"},
    {"read",    CmdHIDRead,     0, "attempt to read and extract tag data"},
    {"clone",   CmdHIDClone,    0, "clone HID to T55x7"},
    {"sim",     CmdHIDSim,      0, "simulate HID tag"},
    {"wiegand", CmdHIDWiegand,  1, "convert facility code/card number to Wiegand code"},
    {"brute",   CmdHIDBrute,    0, "bruteforce card number against reader"},
    {NULL, NULL, 0, NULL}
};

int CmdLFHID(const char *Cmd) {
    clearCommandBuffer();
    CmdsParse(CommandTable, Cmd);
    return 0;
}

int CmdHelp(const char *Cmd) {
    CmdsHelp(CommandTable);
    return 0;
}
