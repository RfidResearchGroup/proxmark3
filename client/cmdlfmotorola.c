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

    PrintAndLogEx(SUCCESS, "Motorola Tag Found -- Raw: %08X%08X", raw1, raw2);
    PrintAndLogEx(INFO, "How the Raw ID is translated by the reader is unknown. Share your trace file on forum");
    return PM3_SUCCESS;
}

static int CmdMotorolaRead(const char *Cmd) {
    // Motorola Flexpass seem to work at 74 kHz
    // and take about 4400 samples to befor modulating
    sample_config sc = {
          .decimation = 0,
          .bits_per_sample = 0,
          .averaging= false,
          .divisor = LF_DIVISOR(74),
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
    if (*size < 64) return -1; //make sure buffer has data
    size_t startIdx = 0;
    uint8_t preamble[] = {
          0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 1
          };
    if (!preambleSearch(dest, preamble, sizeof(preamble), size, &startIdx))
        return -2; //preamble not found
    if (*size != 64) return -3; //wrong demoded size
    //return start position
    return (int)startIdx;
}

int demodMotorola(void) {
    return CmdMotorolaDemod("");
}

int readMotorolaUid(void) {
    return ( CmdMotorolaRead("") == PM3_SUCCESS);
}
