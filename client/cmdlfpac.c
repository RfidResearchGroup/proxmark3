//-----------------------------------------------------------------------------
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency PAC/Stanley tag commands
// NRZ, RF/32, 128 bits long
//-----------------------------------------------------------------------------
#include "cmdlfpac.h"

#include <ctype.h>          //tolower
#include <string.h>
#include <stdlib.h>

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
#include "parity.h"

static int CmdHelp(const char *Cmd);

static int usage_lf_pac_clone(void) {
    PrintAndLogEx(NORMAL, "clone a PAC/Stanley tag to a T55x7 tag.");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage: lf pac clone [h] [c <card id>] [b <raw hex>]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "  h               : this help");
    PrintAndLogEx(NORMAL, "  c <card id>     : 8 byte card ID");
    PrintAndLogEx(NORMAL, "  b <raw hex>     : raw hex data. 16 bytes max");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "       lf pac clone c CD4F5552 ");
    PrintAndLogEx(NORMAL, "       lf pac clone b FF2049906D8511C593155B56D5B2649F ");
    return PM3_SUCCESS;
}
static int usage_lf_pac_sim(void) {
    PrintAndLogEx(NORMAL, "Enables simulation of PAC/Stanley card with specified card number.");
    PrintAndLogEx(NORMAL, "Simulation runs until the button is pressed or another USB command is issued.");
    PrintAndLogEx(NORMAL, "The card ID is 8 byte number. Larger values are truncated.");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  lf pac sim <Card-ID>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "  <Card ID>       : 8 byte PAC/Stanley card id");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "       lf pac sim 12345678");
    return PM3_SUCCESS;
}
// by danshuk
// PAC_8byte format: preamble (8 mark/idle bits), ascii STX (02), ascii '2' (32), ascii '0' (30), ascii bytes 0..7 (cardid), then xor checksum of cardid bytes
// all bytes following 8 bit preamble are one start bit (0), 7 data bits (lsb first), odd parity bit, and one stop bit (1)
static int demodbuf_to_pacid(uint8_t *src, const size_t src_size, uint8_t *dst, const size_t dst_size) {
    const size_t byteLength = 10; // start bit, 7 data bits, parity bit, stop bit
    const size_t startIndex = 8 + (3 * byteLength) + 1; // skip 8 bits preamble, STX, '2', '0', and first start bit
    const size_t dataLength = 9;

    if (startIndex + byteLength * (dataLength - 1) > src_size) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - PAC: Source buffer too small");
        return PM3_EOVFLOW;
    }
    if (dataLength > dst_size) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - PAC: Destination buffer too small");
        return PM3_EOVFLOW;
    }

    uint8_t checksum = 0;
    for (size_t idx = 0; idx < dataLength; idx++) {
        uint8_t byte = (uint8_t)bytebits_to_byteLSBF(src + startIndex + (byteLength * idx), 8);
        dst[idx] = byte & 0x7F; // discard the parity bit
        if (oddparity8(dst[idx]) != (byte & 0x80) >> 7) {
            PrintAndLogEx(DEBUG, "DEBUG: Error - PAC: Parity check failed");
            return PM3_ESOFT;
        }
        if (idx < dataLength - 1) checksum ^= byte;
    }
    if (dst[dataLength - 1] != checksum) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - PAC: Bad checksum - expected: %02X, actual: %02X", dst[dataLength - 1], checksum);
        return PM3_ESOFT;
    }
    dst[dataLength - 1] = 0; // overwrite checksum byte with null terminator

    return PM3_SUCCESS;
}

/*
// convert a 16 byte array of raw demod data (FF204990XX...) to 8 bytes of PAC_8byte ID
// performs no parity or checksum validation
static void pacRawToCardId(uint8_t* outCardId, const uint8_t* rawBytes) {
    for (int i = 4; i < 12; i++) {
        uint8_t shift = 7 - (i + 3) % 4 * 2;
        size_t index = i + (i - 1) / 4;

        outCardId[i - 4] = reflect8((((rawBytes[index] << 8) | (rawBytes[index + 1])) >> shift) & 0xFE);
    }
}
*/

// convert 8 bytes of PAC_8byte ID to 16 byte array of raw data (FF204990XX...)
static void pacCardIdToRaw(uint8_t *outRawBytes, const char *cardId) {
    uint8_t idbytes[10];

    // prepend PAC_8byte card type "20"
    idbytes[0] = '2';
    idbytes[1] = '0';
    for (size_t i = 0; i < 8; i++)
        idbytes[i + 2] = toupper(cardId[i]);

    // initialise array with start and stop bits
    for (size_t i = 0; i < 16; i++)
        outRawBytes[i] = 0x40 >> (i + 3) % 5 * 2;

    outRawBytes[0] = 0xFF; // mark + stop
    outRawBytes[1] = 0x20; // start + reflect8(STX)

    uint8_t checksum = 0;
    for (size_t i = 2; i < 13; i++) {
        uint8_t shift = 7 - (i + 3) % 4 * 2;
        uint8_t index = i + (i - 1) / 4;

        uint16_t pattern;
        if (i < 12) {
            pattern = reflect8(idbytes[i - 2]);
            pattern |= oddparity8(pattern);
            if (i > 3) checksum ^= idbytes[i - 2];
        } else
            pattern = (reflect8(checksum) & 0xFE) | oddparity8(checksum);
        pattern <<= shift;

        outRawBytes[index] |= pattern >> 8 & 0xFF;
        outRawBytes[index + 1] |= pattern & 0xFF;
    }
}

//see NRZDemod for what args are accepted
static int CmdPacDemod(const char *Cmd) {

    //NRZ
    if (NRZrawDemod(Cmd, false) != PM3_SUCCESS) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - PAC: NRZ Demod failed");
        return PM3_ESOFT;
    }
    size_t size = DemodBufferLen;
    int ans = detectPac(DemodBuffer, &size);
    if (ans < 0) {
        if (ans == -1)
            PrintAndLogEx(DEBUG, "DEBUG: Error - PAC: too few bits found");
        else if (ans == -2)
            PrintAndLogEx(DEBUG, "DEBUG: Error - PAC: preamble not found");
        else if (ans == -3)
            PrintAndLogEx(DEBUG, "DEBUG: Error - PAC: Size not correct: %zu", size);
        else
            PrintAndLogEx(DEBUG, "DEBUG: Error - PAC: ans: %d", ans);

        return PM3_ESOFT;
    }
    setDemodBuff(DemodBuffer, 128, ans);
    setClockGrid(g_DemodClock, g_DemodStartIdx + (ans * g_DemodClock));

    //got a good demod
    uint32_t raw1 = bytebits_to_byte(DemodBuffer, 32);
    uint32_t raw2 = bytebits_to_byte(DemodBuffer + 32, 32);
    uint32_t raw3 = bytebits_to_byte(DemodBuffer + 64, 32);
    uint32_t raw4 = bytebits_to_byte(DemodBuffer + 96, 32);

    const size_t idLen = 9; // 8 bytes + null terminator
    uint8_t cardid[idLen];
    int retval = demodbuf_to_pacid(DemodBuffer, DemodBufferLen, cardid, sizeof(cardid));

    if (retval == PM3_SUCCESS)
        PrintAndLogEx(SUCCESS, "PAC/Stanley Tag Found -- Card ID: %s, Raw: %08X%08X%08X%08X", cardid, raw1, raw2, raw3, raw4);

    return retval;
}

static int CmdPacRead(const char *Cmd) {
    lf_read(true, 4096 * 2 + 20);
    return CmdPacDemod(Cmd);
}

static int CmdPacClone(const char *Cmd) {

    uint32_t blocks[5];
    bool errors = false;
    uint8_t cmdp = 0;
    int datalen = 0;

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_lf_pac_clone();
            case 'c': {
                // skip first block,  4*4 = 16 bytes left
                uint8_t rawhex[16] = {0};
                char cardid[9];
                int res = param_getstr(Cmd, cmdp + 1, cardid, sizeof(cardid));
                if (res < 8)
                    errors = true;

                pacCardIdToRaw(rawhex, cardid);
                for (uint8_t i = 1; i < ARRAYLEN(blocks); i++) {
                    blocks[i] = bytes_to_num(rawhex + ((i - 1) * 4), sizeof(uint32_t));
                }
                cmdp += 2;
                break;
            }
            case 'b': {
                // skip first block,  4*4 = 16 bytes left
                uint8_t rawhex[16] = {0};
                int res = param_gethex_to_eol(Cmd, cmdp + 1, rawhex, sizeof(rawhex), &datalen);
                if (res != 0)
                    errors = true;

                for (uint8_t i = 1; i < ARRAYLEN(blocks); i++) {
                    blocks[i] = bytes_to_num(rawhex + ((i - 1) * 4), sizeof(uint32_t));
                }
                cmdp += 2;
                break;
            }
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }

    if (errors || cmdp == 0) return usage_lf_pac_clone();

    //Pac - compat mode, NRZ, data rate 32, 3 data blocks
    blocks[0] = T55x7_MODULATION_DIRECT | T55x7_BITRATE_RF_32 | 4 << T55x7_MAXBLOCK_SHIFT;

    PrintAndLogEx(INFO, "Preparing to clone PAC/Stanley tag to T55x7 with raw hex");
    print_blocks(blocks,  ARRAYLEN(blocks));

    return clone_t55xx_tag(blocks, ARRAYLEN(blocks));
}

static int CmdPacSim(const char *Cmd) {

    // NRZ sim.
    char cardid[9] = { 0 };
    uint8_t rawBytes[16] = { 0 };
    uint32_t rawBlocks[4];
    char cmdp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) == 0 || cmdp == 'h') return usage_lf_pac_sim();

    int res = param_getstr(Cmd, 0, cardid, sizeof(cardid));
    if (res < 8) return usage_lf_pac_sim();

    uint8_t bs[128];
    pacCardIdToRaw(rawBytes, cardid);
    for (size_t i = 0; i < ARRAYLEN(rawBlocks); i++) {
        rawBlocks[i] = bytes_to_num(rawBytes + (i * sizeof(uint32_t)), sizeof(uint32_t));
        num_to_bytebits(rawBlocks[i], sizeof(uint32_t) * 8, bs + (i * sizeof(uint32_t) * 8));
    }
    
    PrintAndLogEx(SUCCESS, "Simulating PAC/Stanley - ID " _YELLOW_("%s")" raw "_YELLOW_("%08X%08X%08X%08X"), cardid, rawBlocks[0], rawBlocks[1], rawBlocks[2], rawBlocks[3]);

    lf_nrzsim_t *payload = calloc(1, sizeof(lf_nrzsim_t) + sizeof(bs));
    payload->invert = 0;
    payload->separator = 0;
    payload->clock = 32;
    memcpy(payload->data, bs, sizeof(bs));

    clearCommandBuffer();
    SendCommandNG(CMD_LF_NRZ_SIMULATE, (uint8_t *)payload,  sizeof(lf_nrzsim_t) + sizeof(bs));
    free(payload);

    PacketResponseNG resp;
    WaitForResponse(CMD_LF_NRZ_SIMULATE, &resp);

    PrintAndLogEx(INFO, "Done");
    if (resp.status != PM3_EOPABORTED)
        return resp.status;

    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",  CmdHelp,      AlwaysAvailable, "This help"},
    {"demod", CmdPacDemod,  AlwaysAvailable, "Demodulate a PAC tag from the GraphBuffer"},
    {"read",  CmdPacRead,   IfPm3Lf,         "Attempt to read and extract tag data from the antenna"},
    {"clone", CmdPacClone,  IfPm3Lf,         "clone PAC tag to T55x7"},
    {"sim",   CmdPacSim,    IfPm3Lf,         "simulate PAC tag"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdLFPac(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

// by marshmellow
// find PAC preamble in already demoded data
int detectPac(uint8_t *dest, size_t *size) {
    if (*size < 128) return -1; //make sure buffer has data
    size_t startIdx = 0;
    uint8_t preamble[] = {1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0};
    if (!preambleSearch(dest, preamble, sizeof(preamble), size, &startIdx))
        return -2; //preamble not found
    if (*size != 128) return -3; //wrong demoded size
    //return start position
    return (int)startIdx;
}

int demodPac(void) {
    return CmdPacDemod("");
}

