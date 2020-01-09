//-----------------------------------------------------------------------------
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency Kantech ioProx commands
// FSK2a, rf/64, 64 bits (complete)
//-----------------------------------------------------------------------------

#include "cmdlfio.h"

#include <stdio.h>      // sscanf
#include <stdlib.h>
#include <string.h>

#include <ctype.h>

#include "commonutil.h"     //ARRAYLEN
#include "cmdparser.h"    // command_t
#include "comms.h"
#include "graph.h"
#include "cmdlf.h"
#include "ui.h"         // PrintAndLog
#include "lfdemod.h"    // parityTest, bitbytes_to_byte
#include "protocols.h"  // for T55xx config register definitions
#include "cmddata.h"
#include "cmdlft55xx.h" // verifywrite

static int CmdHelp(const char *Cmd);

static int usage_lf_io_watch(void) {
    PrintAndLogEx(NORMAL, "Enables IOProx compatible reader mode printing details of scanned tags.");
    PrintAndLogEx(NORMAL, "By default, values are printed and logged until the button is pressed or another USB command is issued.");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  lf io watch");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "        lf io watch");
    return PM3_SUCCESS;
}

static int usage_lf_io_sim(void) {
    PrintAndLogEx(NORMAL, "Enables simulation of IOProx card with specified facility-code and card number.");
    PrintAndLogEx(NORMAL, "Simulation runs until the button is pressed or another USB command is issued.");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  lf io sim [h] <version> <facility-code> <card-number>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "                h :  This help");
    PrintAndLogEx(NORMAL, "        <version> :  8bit version (decimal)");
    PrintAndLogEx(NORMAL, "  <facility-code> :  8bit value facility code (hex)");
    PrintAndLogEx(NORMAL, "    <card number> :  16bit value card number (decimal)");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "       lf io sim 26 101 1337");
    return PM3_SUCCESS;
}

static int usage_lf_io_clone(void) {
    PrintAndLogEx(NORMAL, "Enables cloning of IOProx card with specified facility-code and card number onto T55x7.");
    PrintAndLogEx(NORMAL, "The T55x7 must be on the antenna when issuing this command.  T55x7 blocks are calculated and printed in the process.");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  lf io clone [h] <version> <facility-code> <card-number> [Q5]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "                h :  This help");
    PrintAndLogEx(NORMAL, "        <version> :  8bit version (decimal)");
    PrintAndLogEx(NORMAL, "  <facility-code> :  8bit value facility code (hex)");
    PrintAndLogEx(NORMAL, "    <card number> :  16bit value card number (decimal)");
    PrintAndLogEx(NORMAL, "               Q5 :  optional - clone to Q5 (T5555) instead of T55x7 chip");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "       lf io clone 26 101 1337");
    return PM3_SUCCESS;
}

// this read loops on device side.
// uses the demod in lfops.c
static int CmdIOProxWatch(const char *Cmd) {
    uint8_t ctmp = tolower(param_getchar(Cmd, 0));
    if (ctmp == 'h') return usage_lf_io_watch();
    clearCommandBuffer();
    SendCommandNG(CMD_LF_IO_DEMOD, NULL, 0);
    return PM3_SUCCESS;
}

//by marshmellow
//IO-Prox demod - FSK RF/64 with preamble of 000000001
//print ioprox ID and some format details
static int CmdIOProxDemod(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    int idx = 0, retval = PM3_SUCCESS;
    uint8_t bits[MAX_GRAPH_TRACE_LEN] = {0};
    size_t size = getFromGraphBuf(bits);
    if (size < 65) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - IO prox not enough samples in GraphBuffer");
        return PM3_ESOFT;
    }
    //get binary from fsk wave
    int waveIdx = 0;
    idx = detectIOProx(bits, &size, &waveIdx);
    if (idx < 0) {
        if (g_debugMode) {
            if (idx == -1) {
                PrintAndLogEx(DEBUG, "DEBUG: Error - IO prox not enough samples");
            } else if (idx == -2) {
                PrintAndLogEx(DEBUG, "DEBUG: Error - IO prox just noise detected");
            } else if (idx == -3) {
                PrintAndLogEx(DEBUG, "DEBUG: Error - IO prox error during fskdemod");
            } else if (idx == -4) {
                PrintAndLogEx(DEBUG, "DEBUG: Error - IO prox preamble not found");
            } else if (idx == -5) {
                PrintAndLogEx(DEBUG, "DEBUG: Error - IO size not correct, size %zu", size);
            } else if (idx == -6) {
                PrintAndLogEx(DEBUG, "DEBUG: Error - IO prox separator bits not found");
            } else {
                PrintAndLogEx(DEBUG, "DEBUG: Error - IO prox error demoding fsk %d", idx);
            }
        }
        return PM3_ESOFT;
    }
    setDemodBuff(bits, size, idx);
    setClockGrid(64, waveIdx + (idx * 64));

    if (idx == 0) {
        if (g_debugMode) {
            PrintAndLogEx(DEBUG, "DEBUG: Error - IO prox data not found - FSK Bits: %zu", size);
            if (size > 92) PrintAndLogEx(DEBUG, "%s", sprint_bin_break(bits, 92, 16));
        }
        return PM3_ESOFT;
    }

    //Index map
    //0           10          20          30          40          50          60
    //|           |           |           |           |           |           |
    //01234567 8 90123456 7 89012345 6 78901234 5 67890123 4 56789012 3 45678901 23
    //-----------------------------------------------------------------------------
    //00000000 0 11110000 1 facility 1 version* 1 code*one 1 code*two 1 ???????? 11
    //
    //XSF(version)facility:codeone+codetwo (raw)

    PrintAndLogEx(DEBUG, "%d%d%d%d%d%d%d%d %d", bits[idx], bits[idx + 1], bits[idx + 2], bits[idx + 3], bits[idx + 4], bits[idx + 5], bits[idx + 6], bits[idx + 7], bits[idx + 8]);
    PrintAndLogEx(DEBUG, "%d%d%d%d%d%d%d%d %d", bits[idx + 9], bits[idx + 10], bits[idx + 11], bits[idx + 12], bits[idx + 13], bits[idx + 14], bits[idx + 15], bits[idx + 16], bits[idx + 17]);
    PrintAndLogEx(DEBUG, "%d%d%d%d%d%d%d%d %d facility", bits[idx + 18], bits[idx + 19], bits[idx + 20], bits[idx + 21], bits[idx + 22], bits[idx + 23], bits[idx + 24], bits[idx + 25], bits[idx + 26]);
    PrintAndLogEx(DEBUG, "%d%d%d%d%d%d%d%d %d version", bits[idx + 27], bits[idx + 28], bits[idx + 29], bits[idx + 30], bits[idx + 31], bits[idx + 32], bits[idx + 33], bits[idx + 34], bits[idx + 35]);
    PrintAndLogEx(DEBUG, "%d%d%d%d%d%d%d%d %d code1", bits[idx + 36], bits[idx + 37], bits[idx + 38], bits[idx + 39], bits[idx + 40], bits[idx + 41], bits[idx + 42], bits[idx + 43], bits[idx + 44]);
    PrintAndLogEx(DEBUG, "%d%d%d%d%d%d%d%d %d code2", bits[idx + 45], bits[idx + 46], bits[idx + 47], bits[idx + 48], bits[idx + 49], bits[idx + 50], bits[idx + 51], bits[idx + 52], bits[idx + 53]);
    PrintAndLogEx(DEBUG, "%d%d%d%d%d%d%d%d %d%d checksum", bits[idx + 54], bits[idx + 55], bits[idx + 56], bits[idx + 57], bits[idx + 58], bits[idx + 59], bits[idx + 60], bits[idx + 61], bits[idx + 62], bits[idx + 63]);

    uint32_t code = bytebits_to_byte(bits + idx, 32);
    uint32_t code2 = bytebits_to_byte(bits + idx + 32, 32);
    uint8_t version = bytebits_to_byte(bits + idx + 27, 8); //14,4
    uint8_t facilitycode = bytebits_to_byte(bits + idx + 18, 8) ;
    uint16_t number = (bytebits_to_byte(bits + idx + 36, 8) << 8) | (bytebits_to_byte(bits + idx + 45, 8)); //36,9
    uint8_t crc = bytebits_to_byte(bits + idx + 54, 8);
    uint8_t calccrc = 0;

    for (uint8_t i = 1; i < 6; ++i) {
        calccrc += bytebits_to_byte(bits + idx + 9 * i, 8);
    }
    calccrc &= 0xff;
    calccrc = 0xff - calccrc;

    char crcStr[30];
    memset(crcStr, 0x00, sizeof(crcStr));

    if (crc == calccrc) {
        snprintf(crcStr, 3, "ok");

    } else {
        PrintAndLogEx(DEBUG, "DEBUG: Error - IO prox crc failed");

        snprintf(crcStr, sizeof(crcStr), "failed 0x%02X != 0x%02X", crc, calccrc);
        retval = PM3_ESOFT;
    }

    PrintAndLogEx(SUCCESS, "IO Prox XSF(%02d)%02x:%05d (%08x%08x) [crc %s]", version, facilitycode, number, code, code2, crcStr);

    if (g_debugMode) {
        PrintAndLogEx(DEBUG, "DEBUG: IO prox idx: %d, Len: %zu, Printing demod buffer:", idx, size);
        printDemodBuff();
    }
    return retval;
}

// this read is the "normal" read,  which download lf signal and tries to demod here.
static int CmdIOProxRead(const char *Cmd) {
    lf_read(false, 12000);
    return CmdIOProxDemod(Cmd);
}
static int CmdIOProxSim(const char *Cmd) {
    uint16_t cn = 0;
    uint8_t version = 0, fc = 0;
    uint8_t bs[64];
    memset(bs, 0x00, sizeof(bs));

    char cmdp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) == 0 || cmdp == 'h') return usage_lf_io_sim();

    version = param_get8(Cmd, 0);
    fc = param_get8ex(Cmd, 1, 0, 16);
    cn = param_get32ex(Cmd, 2, 0, 10);

    if (!version || !fc || !cn) return usage_lf_io_sim();

    if ((cn & 0xFFFF) != cn) {
        cn &= 0xFFFF;
        PrintAndLogEx(INFO, "Card Number Truncated to 16-bits (IOProx): %u", cn);
    }

    PrintAndLogEx(SUCCESS, "Simulating IOProx version: %u FC: %u; CN: %u\n", version, fc, cn);
    PrintAndLogEx(SUCCESS, "Press pm3-button to abort simulation or run another command");

    if (getIOProxBits(version, fc, cn, bs) != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Error with tag bitstream generation.");
        return PM3_ESOFT;
    }
    // IOProx uses: fcHigh: 10, fcLow: 8, clk: 64, invert: 1
    // arg1 --- fcHigh<<8 + fcLow
    // arg2 --- Invert and clk setting
    // size --- 64 bits == 8 bytes
    lf_fsksim_t *payload = calloc(1, sizeof(lf_fsksim_t) + sizeof(bs));
    payload->fchigh = 10;
    payload->fclow = 8;
    payload->separator = 1;
    payload->clock = 64;
    memcpy(payload->data, bs, sizeof(bs));

    clearCommandBuffer();
    SendCommandNG(CMD_LF_FSK_SIMULATE, (uint8_t *)payload,  sizeof(lf_fsksim_t) + sizeof(bs));
    free(payload);

    PacketResponseNG resp;
    WaitForResponse(CMD_LF_FSK_SIMULATE, &resp);

    PrintAndLogEx(INFO, "Done");
    if (resp.status != PM3_EOPABORTED)
        return resp.status;
    return PM3_SUCCESS;
}

static int CmdIOProxClone(const char *Cmd) {

    uint16_t cn = 0;
    uint8_t version = 0, fc = 0;
    uint8_t bits[64];
    memset(bits, 0, sizeof(bits));

    char cmdp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) == 0 || cmdp == 'h') return usage_lf_io_clone();

    version = param_get8(Cmd, 0);
    fc = param_get8ex(Cmd, 1, 0, 16);
    cn = param_get32ex(Cmd, 2, 0, 10);

    if (!version || !fc || !cn) return usage_lf_io_clone();

    if ((cn & 0xFFFF) != cn) {
        cn &= 0xFFFF;
        PrintAndLogEx(INFO, "Card Number Truncated to 16-bits (IOProx): %u", cn);
    }

    if (getIOProxBits(version, fc, cn, bits) != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Error with tag bitstream generation.");
        return PM3_ESOFT;
    }

    uint32_t blocks[3] = {T55x7_MODULATION_FSK2a | T55x7_BITRATE_RF_64 | 2 << T55x7_MAXBLOCK_SHIFT, 0, 0};

    if (tolower(param_getchar(Cmd, 3) == 'q'))
        blocks[0] = T5555_MODULATION_FSK2 | T5555_INVERT_OUTPUT | T5555_SET_BITRATE(64) | 2 << T5555_MAXBLOCK_SHIFT;

    blocks[1] = bytebits_to_byte(bits, 32);
    blocks[2] = bytebits_to_byte(bits + 32, 32);

    PrintAndLogEx(INFO, "Preparing to clone IOProx to T55x7 with Version: %u FC: %u, CN: %u", version, fc, cn);
    print_blocks(blocks,  ARRAYLEN(blocks));

    return clone_t55xx_tag(blocks, ARRAYLEN(blocks));
}

static command_t CommandTable[] = {
    {"help",    CmdHelp,        AlwaysAvailable, "this help"},
    {"demod",   CmdIOProxDemod, AlwaysAvailable, "demodulate an IOProx tag from the GraphBuffer"},
    {"read",    CmdIOProxRead,  IfPm3Lf,         "attempt to read and extract tag data"},
    {"clone",   CmdIOProxClone, IfPm3Lf,         "clone IOProx tag to T55x7 (or to q5/T5555)"},
    {"sim",     CmdIOProxSim,   IfPm3Lf,         "simulate IOProx tag"},
    {"watch",   CmdIOProxWatch, IfPm3Lf,         "continuously watch for cards. Reader mode"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdLFIO(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

int demodIOProx(void) {
    return CmdIOProxDemod("");
}

//Index map
//0           10          20          30          40          50          60
//|           |           |           |           |           |           |
//01234567 8 90123456 7 89012345 6 78901234 5 67890123 4 56789012 3 45678901 23
//-----------------------------------------------------------------------------
//00000000 0 11110000 1 facility 1 version* 1 code*one 1 code*two 1   crc    11
//XSF(version)facility:codeone+codetwo (raw)
int getIOProxBits(uint8_t version, uint8_t fc, uint16_t cn, uint8_t *bits) {
#define SEPARATOR 1
    uint8_t pos = 0;
    // the return bits, preamble 0000 0000 0
    uint8_t pre[64];
    memset(pre, 0, sizeof(pre));

    // skip 9 zeros as preamble
    pos = 9;

    // another fixed byte 11110000 = 0xF0
    num_to_bytebits(0xF0, 8, pre + pos);
    pos += 8;
    pre[pos] = SEPARATOR;
    pos++;

    // add facilitycode
    num_to_bytebits(fc, 8, pre + pos);
    pos += 8;
    pre[pos] = SEPARATOR;
    pos++;

    // add version
    num_to_bytebits(version, 8, pre + pos);
    pos += 8;
    pre[pos] = SEPARATOR;
    pos++;

    // cardnumber high byte
    num_to_bytebits(((cn & 0xFF00) >> 8), 8, pre + pos);
    pos += 8;
    pre[pos] = SEPARATOR;
    pos++;

    // cardnumber low byte
    num_to_bytebits((cn & 0xFF), 8, pre + pos);
    pos += 8;
    pre[pos] = SEPARATOR;
    pos++;

    // calculate and add CRC
    uint16_t crc = 0;
    for (uint8_t i = 1; i < 6; ++i)
        crc += bytebits_to_byte(pre + 9 * i, 8);

    crc &= 0xFF;
    crc = 0xff - crc;
    num_to_bytebits(crc, 8, pre + pos);
    pos += 8;

    // Final two ONES
    pre[pos] = SEPARATOR;
    pre[++pos] = SEPARATOR;

    memcpy(bits, pre, sizeof(pre));

    PrintAndLogEx(SUCCESS, "IO raw bits:\n %s \n", sprint_bin(bits, 64));
    return PM3_SUCCESS;
}

