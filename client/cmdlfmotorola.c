//-----------------------------------------------------------------------------
// Iceman, 2019
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency Motorola tag commands
// PSK1, RF/32, 64 bits long,  at 74 kHz
//-----------------------------------------------------------------------------
#include "cmdlfmotorola.h"

#include <ctype.h>          //tolower

#include "commonutil.h"     // ARRAYLEN
#include "common.h"
#include "cmdparser.h"    // command_t
#include "comms.h"
#include "ui.h"
#include "cmddata.h"
#include "cmdlf.h"
#include "lfdemod.h"    // preamble test
#include "protocols.h"  // t55xx defines
#include "cmdlft55xx.h" // clone..
#include "cmdlf.h"      // cmdlfconfig
#include "cliparser/cliparser.h" // cli parse input


static int CmdHelp(const char *Cmd);

//see PSKDemod for what args are accepted
static int CmdMotorolaDemod(const char *Cmd) {

    //PSK1
    if (PSKDemod("32 1", true) != PM3_SUCCESS) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - Motorola: PSK Demod failed");
        return PM3_ESOFT;
    }
    size_t size = DemodBufferLen;
    int ans = detectMotorola(DemodBuffer, &size);
    if (ans < 0) {
        if (ans == -1)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Motorola: too few bits found");
        else if (ans == -2)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Motorola: preamble not found");
        else if (ans == -3)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Motorola: Size not correct: %zu", size);
        else
            PrintAndLogEx(DEBUG, "DEBUG: Error - Motorola: ans: %d", ans);

        return PM3_ESOFT;
    }
    setDemodBuff(DemodBuffer, 64, ans);
    setClockGrid(g_DemodClock, g_DemodStartIdx + (ans * g_DemodClock));

    //got a good demod
    uint32_t raw1 = bytebits_to_byte(DemodBuffer, 32);
    uint32_t raw2 = bytebits_to_byte(DemodBuffer + 32, 32);

// A0000000E308C0C1
// 10100000000000000000000000000000 1110 0011 0000 1000 1100 0000 1100 0001


//                1    1    2    2    2    3    3    4    4    4    5    5    6
// 0    4    8    2    6    0    4    8    2    6    0    4    8    2    6    0
// 1010 0000 0000 0000 0000 0000 0000 0000 1110 0011 0000 1000 1100 0000 0101 0010
//                                           9    .0      5  4 26    3 .  71
//                                           .    .0      5  4 26    3 .  71
//                                          6 9 A5   C0FD  E7    18 B 4  3  2

// hex(234)  0xEA    bin(234)    1110 1010
// hex(437)  0x1B5   bin(437)  1 1011 0101
// hex(229)  0xE5    bin(229)    1110 0101

    uint16_t fc = 0;

// FC seems to be guess work.  Need more samples
// guessing  printed FC is 4 digits.  1024? 10bit?
//    fc |= DemodBuffer[38] << 9; // b10
    fc |= DemodBuffer[34] << 8; // b9

    fc |= DemodBuffer[44] << 7; // b8
    fc |= DemodBuffer[47] << 6; // b7
    fc |= DemodBuffer[57] << 5; // b6
    fc |= DemodBuffer[49] << 4; // b5

// seems to match
    fc |= DemodBuffer[53] << 3; // b4
    fc |= DemodBuffer[48] << 2; // b3
    fc |= DemodBuffer[58] << 1; // b2
    fc |= DemodBuffer[39] << 0; // b1

// CSN was same as Indala CSN descramble.
    uint16_t csn = 0;
    csn |= DemodBuffer[42] << 15; // b16
    csn |= DemodBuffer[45] << 14; // b15
    csn |= DemodBuffer[43] << 13; // b14
    csn |= DemodBuffer[40] << 12; // b13
    csn |= DemodBuffer[52] << 11; // b12
    csn |= DemodBuffer[36] << 10; // b11
    csn |= DemodBuffer[35] << 9; // b10
    csn |= DemodBuffer[51] << 8; // b9
    csn |= DemodBuffer[46] << 7; // b8
    csn |= DemodBuffer[33] << 6; // b7
    csn |= DemodBuffer[37] << 5; // b6
    csn |= DemodBuffer[54] << 4; // b5
    csn |= DemodBuffer[56] << 3; // b4
    csn |= DemodBuffer[59] << 2; // b3
    csn |= DemodBuffer[50] << 1; // b2
    csn |= DemodBuffer[41] << 0; // b1

    uint8_t checksum = 0;
    checksum |= DemodBuffer[62] << 1; // b2
    checksum |= DemodBuffer[63] << 0; // b1

    PrintAndLogEx(SUCCESS, "Motorola Tag Found -- Raw: %08X%08X", raw1, raw2);
    PrintAndLogEx(SUCCESS, "Fmt 26 bit  FC %u , CSN %u , checksum %1d%1d", fc, csn, checksum >> 1 & 0x01, checksum & 0x01);
    PrintAndLogEx(NORMAL, "");

    return PM3_SUCCESS;
}

static int CmdMotorolaRead(const char *Cmd) {
    // Motorola Flexpass seem to work at 74 kHz
    // and take about 4400 samples to befor modulating
    sample_config sc = {
        .decimation = 0,
        .bits_per_sample = 0,
        .averaging = false,
        .divisor = LF_FREQ2DIV(74),
        .trigger_threshold = -1,
        .samples_to_skip = 4500,
        .verbose = false
    };
    lf_config(&sc);

    // 64 * 32 * 2 * n-ish
    lf_read(true, 5000);

    // reset back to 125 kHz
    sc.divisor = LF_DIVISOR_125;
    sc.samples_to_skip = 0;
    lf_config(&sc);
    return CmdMotorolaDemod(Cmd);
}

static int CmdMotorolaClone(const char *Cmd) {

    uint32_t blocks[3] = {0};
    uint8_t data[8];
    int datalen = 0;

    CLIParserInit("lf indala clone",
                  "Enables cloning of Motorola card with specified uid onto T55x7\n"
                  "defaults to 64.\n",
                  "\n"
                  "Samples:\n"
                  "\tlf motorola clone a0000000a0002021\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_strx1(NULL, NULL, "<uid (hex)>", NULL),
        arg_param_end
    };
    CLIExecWithReturn(Cmd, argtable, false);
    CLIGetHexWithReturn(1, data, &datalen);
    CLIParserFree();

    //TODO add selection of chip for Q5 or T55x7
    // data[0] = T5555_SET_BITRATE(32 | T5555_MODULATION_PSK1 | 2 << T5555_MAXBLOCK_SHIFT;

    // config for Motorola 64 format (RF/32;PSK1 with RF/2; Maxblock=2)
    PrintAndLogEx(INFO, "Preparing to clone Motorola 64bit tag with RawID %s", sprint_hex(data, datalen));
    blocks[0] =  T55x7_BITRATE_RF_32 | T55x7_MODULATION_PSK1 | (2 << T55x7_MAXBLOCK_SHIFT);
    blocks[1] = bytes_to_num(data, 4);
    blocks[2] = bytes_to_num(data + 4, 4);

    print_blocks(blocks, ARRAYLEN(blocks));
    return clone_t55xx_tag(blocks, ARRAYLEN(blocks));
}

static int CmdMotorolaSim(const char *Cmd) {

    // PSK sim.
    PrintAndLogEx(INFO, " PSK1 at 66 kHz... Interesting.");
    PrintAndLogEx(INFO, " To be implemented, feel free to contribute!");
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",  CmdHelp,           AlwaysAvailable, "This help"},
    {"demod", CmdMotorolaDemod,  AlwaysAvailable, "Demodulate an MOTOROLA tag from the GraphBuffer"},
    {"read",  CmdMotorolaRead,   IfPm3Lf,         "Attempt to read and extract tag data from the antenna"},
    {"clone", CmdMotorolaClone,  IfPm3Lf,         "clone MOTOROLA tag to T55x7"},
    {"sim",   CmdMotorolaSim,    IfPm3Lf,         "simulate MOTOROLA tag"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdLFMotorola(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

// find MOTOROLA preamble in already demoded data
int detectMotorola(uint8_t *dest, size_t *size) {

    //make sure buffer has data
    if (*size < 64)
        return -1;

    bool inverted = false;
    size_t found_size = *size;
    size_t start_idx = 0;

    // Seems Motorola is based on the following indala format.
    // standard 64 bit Motorola formats including 26 bit 40134 format
    uint8_t preamble[] =  {1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    uint8_t preamble_i[]  = {0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0};

    // preamble not found
    if (!preambleSearch(dest, preamble, sizeof(preamble), &found_size, &start_idx)) {
        found_size = *size;
        if (!preambleSearch(dest, preamble_i, sizeof(preamble_i), &found_size, &start_idx)) {
            return -2;
        }
        PrintAndLogEx(DEBUG, "DEBUG: detectMotorola PSK1 found inverted preamble");
        inverted = true;
    }

    *size = found_size;

    // wrong demoded size
    if (*size != 64)
        return -3;

    if (inverted && start_idx > 0) {
        for (size_t i = start_idx - 1 ; i < *size + start_idx + 2; i++) {
            dest[i] ^= 1;
        }
    }

    return (int)start_idx;
}

int demodMotorola(void) {
    return CmdMotorolaDemod("");
}

int readMotorolaUid(void) {
    return (CmdMotorolaRead("") == PM3_SUCCESS);
}
