//-----------------------------------------------------------------------------
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency Farpoint / Pyramid tag commands
// FSK2a, rf/50, 128 bits (complete)
//-----------------------------------------------------------------------------
#include "cmdlfpyramid.h"

static int CmdHelp(const char *Cmd);

int usage_lf_pyramid_clone(void) {
    PrintAndLogEx(NORMAL, "clone a Farpointe/Pyramid tag to a T55x7 tag.");
    PrintAndLogEx(NORMAL, "The facility-code is 8-bit and the card number is 16-bit.  Larger values are truncated. ");
    PrintAndLogEx(NORMAL, "Currently only works on 26bit");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage: lf pyramid clone [h] <Facility-Code> <Card-Number> [Q5]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "  h               : this help");
    PrintAndLogEx(NORMAL, "  <Facility-Code> :  8-bit value facility code");
    PrintAndLogEx(NORMAL, "  <Card Number>   : 16-bit value card number");
    PrintAndLogEx(NORMAL, "  Q5              : optional - clone to Q5 (T5555) instead of T55x7 chip");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "       lf pyramid clone 123 11223");
    return 0;
}

int usage_lf_pyramid_sim(void) {
    PrintAndLogEx(NORMAL, "Enables simulation of Farpointe/Pyramid card with specified card number.");
    PrintAndLogEx(NORMAL, "Simulation runs until the button is pressed or another USB command is issued.");
    PrintAndLogEx(NORMAL, "The facility-code is 8-bit and the card number is 16-bit.  Larger values are truncated.");
    PrintAndLogEx(NORMAL, "Currently work only on 26bit");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  lf pyramid sim [h] <Facility-Code> <Card-Number>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "  h               : this help");
    PrintAndLogEx(NORMAL, "  <Facility-Code> :  8-bit value facility code");
    PrintAndLogEx(NORMAL, "  <Card Number>   : 16-bit value card number");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "       lf pyramid sim 123 11223");
    return 0;
}

// by marshmellow
// FSK Demod then try to locate a Farpointe Data (pyramid) ID
int detectPyramid(uint8_t *dest, size_t *size, int *waveStartIdx) {
    //make sure buffer has data
    if (*size < 128 * 50) return -1;

    //test samples are not just noise
    if (getSignalProperties()->isnoise) return -2;

    // FSK demodulator RF/50 FSK 10,8
    *size = fskdemod(dest, *size, 50, 1, 10, 8, waveStartIdx);  // pyramid fsk2

    //did we get a good demod?
    if (*size < 128) return -3;

    size_t startIdx = 0;
    uint8_t preamble[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1};
    if (!preambleSearch(dest, preamble, sizeof(preamble), size, &startIdx))
        return -4; //preamble not found

    // wrong size?  (between to preambles)
    if (*size != 128) return -5;

    return (int)startIdx;
}

// Works for 26bits.
int GetPyramidBits(uint32_t fc, uint32_t cn, uint8_t *pyramidBits) {

    uint8_t pre[128];
    memset(pre, 0x00, sizeof(pre));

    // format start bit
    pre[79] = 1;

    // Get 26 wiegand from FacilityCode, CardNumber
    uint8_t wiegand[24];
    memset(wiegand, 0x00, sizeof(wiegand));
    num_to_bytebits(fc, 8, wiegand);
    num_to_bytebits(cn, 16, wiegand + 8);

    // add wiegand parity bits (dest, source, len)
    wiegand_add_parity(pre + 80, wiegand, 24);

    // add paritybits (bitsource, dest, sourcelen, paritylen, parityType (odd, even,)
    addParity(pre + 8, pyramidBits + 8, 102, 8, 1);

    // add checksum
    uint8_t csBuff[13];
    for (uint8_t i = 0; i < 13; i++)
        csBuff[i] = bytebits_to_byte(pyramidBits + 16 + (i * 8), 8);

    uint32_t crc = CRC8Maxim(csBuff, 13);
    num_to_bytebits(crc, 8, pyramidBits + 120);
    return 1;
}

//by marshmellow
//Pyramid Prox demod - FSK RF/50 with preamble of 0000000000000001  (always a 128 bit data stream)
//print full Farpointe Data/Pyramid Prox ID and some bit format details if found
int CmdPyramidDemod(const char *Cmd) {
    //raw fsk demod no manchester decoding no start bit finding just get binary from wave
    uint8_t bits[MAX_GRAPH_TRACE_LEN] = {0};
    size_t size = getFromGraphBuf(bits);
    if (size == 0) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - Pyramid not enough samples");
        return 0;
    }
    //get binary from fsk wave
    int waveIdx = 0;
    int idx = detectPyramid(bits, &size, &waveIdx);
    if (idx < 0) {
        if (idx == -1)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Pyramid: not enough samples");
        else if (idx == -2)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Pyramid: only noise found");
        else if (idx == -3)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Pyramid: problem during FSK demod");
        else if (idx == -4)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Pyramid: preamble not found");
        else if (idx == -5)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Pyramid: size not correct: %d", size);
        else
            PrintAndLogEx(DEBUG, "DEBUG: Error - Pyramid: error demoding fsk idx: %d", idx);
        return 0;
    }
    setDemodBuf(bits, size, idx);
    setClockGrid(50, waveIdx + (idx * 50));

    // Index map
    // 0           10          20          30            40          50          60
    // |           |           |           |             |           |           |
    // 0123456 7 8901234 5 6789012 3 4567890 1 2345678 9 0123456 7 8901234 5 6789012 3
    // -----------------------------------------------------------------------------
    // 0000000 0 0000000 1 0000000 1 0000000 1 0000000 1 0000000 1 0000000 1 0000000 1
    // premable  xxxxxxx o xxxxxxx o xxxxxxx o xxxxxxx o xxxxxxx o xxxxxxx o xxxxxxx o

    // 64    70            80          90          100         110           120
    // |     |             |           |           |           |             |
    // 4567890 1 2345678 9 0123456 7 8901234 5 6789012 3 4567890 1 2345678 9 0123456 7
    // -----------------------------------------------------------------------------
    // 0000000 1 0000000 1 0000000 1 0110111 0 0011000 1 0000001 0 0001100 1 1001010 0
    // xxxxxxx o xxxxxxx o xxxxxxx o xswffff o ffffccc o ccccccc o ccccccw o ppppppp o
    //                                  |---115---||---------71---------|
    // s = format start bit, o = odd parity of last 7 bits
    // f = facility code, c = card number
    // w = wiegand parity, x = extra space for other formats
    // p = CRC8maxim checksum
    // (26 bit format shown)

    //get bytes for checksum calc
    uint8_t checksum = bytebits_to_byte(bits + idx + 120, 8);
    uint8_t csBuff[14] = {0x00};
    for (uint8_t i = 0; i < 13; i++) {
        csBuff[i] = bytebits_to_byte(bits + idx + 16 + (i * 8), 8);
    }
    //check checksum calc
    //checksum calc thanks to ICEMAN!!
    uint32_t checkCS =  CRC8Maxim(csBuff, 13);

    //get raw ID before removing parities
    uint32_t rawLo = bytebits_to_byte(bits + idx + 96, 32);
    uint32_t rawHi = bytebits_to_byte(bits + idx + 64, 32);
    uint32_t rawHi2 = bytebits_to_byte(bits + idx + 32, 32);
    uint32_t rawHi3 = bytebits_to_byte(bits + idx, 32);

    size = removeParity(bits, idx + 8, 8, 1, 120);
    if (size != 105) {
        if (size == 0)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Pyramid: parity check failed - IDX: %d, hi3: %08X", idx, rawHi3);
        else
            PrintAndLogEx(DEBUG, "DEBUG: Error - Pyramid: at parity check - tag size does not match Pyramid format, SIZE: %d, IDX: %d, hi3: %08X", size, idx, rawHi3);
        return 0;
    }

    // ok valid card found!

    // Index map
    // 0         10        20        30        40        50        60        70
    // |         |         |         |         |         |         |         |
    // 01234567890123456789012345678901234567890123456789012345678901234567890
    // -----------------------------------------------------------------------
    // 00000000000000000000000000000000000000000000000000000000000000000000000
    // xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

    // 71         80         90          100
    // |          |          |           |
    // 1 2 34567890 1234567890123456 7 8901234
    // ---------------------------------------
    // 1 1 01110011 0000000001000110 0 1001010
    // s w ffffffff cccccccccccccccc w ppppppp
    //     |--115-| |------71------|
    // s = format start bit, o = odd parity of last 7 bits
    // f = facility code, c = card number
    // w = wiegand parity, x = extra space for other formats
    // p = CRC8-Maxim checksum
    // (26 bit format shown)

    //find start bit to get fmtLen
    int j;
    for (j = 0; j < size; ++j) {
        if (bits[j]) break;
    }

    uint8_t fmtLen = size - j - 8;
    uint32_t fc = 0;
    uint32_t cardnum = 0;
    uint32_t code1 = 0;

    if (fmtLen == 26) {
        fc = bytebits_to_byte(bits + 73, 8);
        cardnum = bytebits_to_byte(bits + 81, 16);
        code1 = bytebits_to_byte(bits + 72, fmtLen);
        PrintAndLogEx(SUCCESS, "Pyramid ID Found - BitLength: %d, FC: %d, Card: %d - Wiegand: %x, Raw: %08x%08x%08x%08x", fmtLen, fc, cardnum, code1, rawHi3, rawHi2, rawHi, rawLo);
    } else if (fmtLen == 45) {
        fmtLen = 42; //end = 10 bits not 7 like 26 bit fmt
        fc = bytebits_to_byte(bits + 53, 10);
        cardnum = bytebits_to_byte(bits + 63, 32);
        PrintAndLogEx(SUCCESS, "Pyramid ID Found - BitLength: %d, FC: %d, Card: %d - Raw: %08x%08x%08x%08x", fmtLen, fc, cardnum, rawHi3, rawHi2, rawHi, rawLo);
    } else {
        cardnum = bytebits_to_byte(bits + 81, 16);
        if (fmtLen > 32) {
            //code1 = bytebits_to_byte(bits+(size-fmtLen),fmtLen-32);
            //code2 = bytebits_to_byte(bits+(size-32),32);
            PrintAndLogEx(SUCCESS, "Pyramid ID Found - BitLength: %d -unknown BitLength- (%d), Raw: %08x%08x%08x%08x", fmtLen, cardnum, rawHi3, rawHi2, rawHi, rawLo);
        } else {
            //code1 = bytebits_to_byte(bits+(size-fmtLen),fmtLen);
            PrintAndLogEx(SUCCESS, "Pyramid ID Found - BitLength: %d -unknown BitLength- (%d), Raw: %08x%08x%08x%08x", fmtLen, cardnum, rawHi3, rawHi2, rawHi, rawLo);
        }
    }

    PrintAndLogEx(DEBUG, "DEBUG: Pyramid: checksum : 0x%02X - %02X - %s"
        , checksum
        , checkCS
        , (checksum == checkCS) ? _GREEN_("Passed") : _RED_("Failed")
        );
        
    PrintAndLogEx(DEBUG, "DEBUG: Pyramid: idx: %d, Len: %d, Printing Demod Buffer:", idx, 128);
    if (g_debugMode)
        printDemodBuff();

    return 1;
}

int CmdPyramidRead(const char *Cmd) {
    lf_read(true, 15000);
    return CmdPyramidDemod(Cmd);
}

int CmdPyramidClone(const char *Cmd) {

    char cmdp = param_getchar(Cmd, 0);
    if (strlen(Cmd) == 0 || cmdp == 'h' || cmdp == 'H') return usage_lf_pyramid_clone();

    uint32_t facilitycode = 0, cardnumber = 0, fc = 0, cn = 0;
    uint32_t blocks[5];
    uint8_t bs[128];
    memset(bs, 0x00, sizeof(bs));

    if (sscanf(Cmd, "%u %u", &fc, &cn) != 2) return usage_lf_pyramid_clone();

    facilitycode = (fc & 0x000000FF);
    cardnumber = (cn & 0x0000FFFF);

    if (!GetPyramidBits(facilitycode, cardnumber, bs)) {
        PrintAndLogEx(WARNING, "Error with tag bitstream generation.");
        return 1;
    }

    //Pyramid - compat mode, FSK2a, data rate 50, 4 data blocks
    blocks[0] = T55x7_MODULATION_FSK2a | T55x7_BITRATE_RF_50 | 4 << T55x7_MAXBLOCK_SHIFT;

    // Q5
    if (param_getchar(Cmd, 2) == 'Q' || param_getchar(Cmd, 2) == 'q')
        blocks[0] = T5555_MODULATION_FSK2 | T5555_INVERT_OUTPUT | T5555_SET_BITRATE(50) | 4 << T5555_MAXBLOCK_SHIFT;

    blocks[1] = bytebits_to_byte(bs, 32);
    blocks[2] = bytebits_to_byte(bs + 32, 32);
    blocks[3] = bytebits_to_byte(bs + 64, 32);
    blocks[4] = bytebits_to_byte(bs + 96, 32);

    PrintAndLogEx(INFO, "Preparing to clone Farpointe/Pyramid to T55x7 with Facility Code: %u, Card Number: %u", facilitycode, cardnumber);
    print_blocks(blocks, 5);

    UsbCommand resp;
    UsbCommand c = {CMD_T55XX_WRITE_BLOCK, {0, 0, 0}};

    for (uint8_t i = 0; i < 5; ++i) {
        c.arg[0] = blocks[i];
        c.arg[1] = i;
        clearCommandBuffer();
        SendCommand(&c);
        if (!WaitForResponseTimeout(CMD_ACK, &resp, T55XX_WRITE_TIMEOUT)) {
            PrintAndLogEx(WARNING, "Error occurred, device did not respond during write operation.");
            return -1;
        }
    }
    return 0;
}

int CmdPyramidSim(const char *Cmd) {

    char cmdp = param_getchar(Cmd, 0);
    if (strlen(Cmd) == 0 || cmdp == 'h' || cmdp == 'H') return usage_lf_pyramid_sim();

    uint32_t facilitycode = 0, cardnumber = 0, fc = 0, cn = 0;

    uint8_t bs[128];
    size_t size = sizeof(bs);
    memset(bs, 0x00, size);

    // Pyramid uses:  fcHigh: 10, fcLow: 8, clk: 50, invert: 0
    uint8_t clk = 50, invert = 0, high = 10, low = 8;
    uint16_t arg1, arg2;
    arg1 = high << 8 | low;
    arg2 = invert << 8 | clk;

    if (sscanf(Cmd, "%u %u", &fc, &cn) != 2) return usage_lf_pyramid_sim();

    facilitycode = (fc & 0x000000FF);
    cardnumber = (cn & 0x0000FFFF);

    if (!GetPyramidBits(facilitycode, cardnumber, bs)) {
        PrintAndLogEx(WARNING, "Error with tag bitstream generation.");
        return 1;
    }

    PrintAndLogEx(SUCCESS, "Simulating Farpointe/Pyramid - Facility Code: %u, CardNumber: %u", facilitycode, cardnumber);

    UsbCommand c = {CMD_FSK_SIM_TAG, {arg1, arg2, size}};
    memcpy(c.d.asBytes, bs, size);
    clearCommandBuffer();
    SendCommand(&c);
    return 0;
}

static command_t CommandTable[] = {
    {"help",    CmdHelp,        1, "this help"},
    {"demod",   CmdPyramidDemod, 0, "demodulate a Pyramid FSK tag from the GraphBuffer"},
    {"read",    CmdPyramidRead, 0, "attempt to read and extract tag data"},
    {"clone",   CmdPyramidClone, 0, "clone pyramid tag"},
    {"sim",     CmdPyramidSim,  0, "simulate pyramid tag"},
    {NULL, NULL, 0, NULL}
};

int CmdLFPyramid(const char *Cmd) {
    clearCommandBuffer();
    CmdsParse(CommandTable, Cmd);
    return 0;
}

int CmdHelp(const char *Cmd) {
    CmdsHelp(CommandTable);
    return 0;
}
