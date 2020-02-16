//-----------------------------------------------------------------------------
// Iceman, 2019
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency GALLAGHER tag commands
// ASK/MAN, RF/32, 96 bits long (unknown cs) (0x00088060)
// sample Q5 ,  ASK RF/32, STT,  96 bits  (3blocks)   ( 0x9000F006)
//-----------------------------------------------------------------------------
#include "cmdlfgallagher.h"

#include <ctype.h>          //tolower
#include <stdio.h>
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
#include "crc.h" // CRC8/Cardx

static int CmdHelp(const char *Cmd);

static int usage_lf_gallagher_clone(void) {
    PrintAndLogEx(NORMAL, "clone a GALLAGHER tag to a T55x7 tag.");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage: lf gallagher clone [h] [b <raw hex>]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "  h               : this help");
    PrintAndLogEx(NORMAL, "  b <raw hex>     : raw hex data. 12 bytes max");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "       lf gallagher clone b 0FFD5461A9DA1346B2D1AC32 ");
    return PM3_SUCCESS;
}

static void descramble(uint8_t *arr, uint8_t len) {

    uint8_t lut[] = {
        0xa3, 0xb0, 0x80, 0xc6, 0xb2, 0xf4, 0x5c, 0x6c, 0x81, 0xf1, 0xbb, 0xeb, 0x55, 0x67, 0x3c, 0x05,
        0x1a, 0x0e, 0x61, 0xf6, 0x22, 0xce, 0xaa, 0x8f, 0xbd, 0x3b, 0x1f, 0x5e, 0x44, 0x04, 0x51, 0x2e,
        0x4d, 0x9a, 0x84, 0xea, 0xf8, 0x66, 0x74, 0x29, 0x7f, 0x70, 0xd8, 0x31, 0x7a, 0x6d, 0xa4, 0x00,
        0x82, 0xb9, 0x5f, 0xb4, 0x16, 0xab, 0xff, 0xc2, 0x39, 0xdc, 0x19, 0x65, 0x57, 0x7c, 0x20, 0xfa,
        0x5a, 0x49, 0x13, 0xd0, 0xfb, 0xa8, 0x91, 0x73, 0xb1, 0x33, 0x18, 0xbe, 0x21, 0x72, 0x48, 0xb6,
        0xdb, 0xa0, 0x5d, 0xcc, 0xe6, 0x17, 0x27, 0xe5, 0xd4, 0x53, 0x42, 0xf3, 0xdd, 0x7b, 0x24, 0xac,
        0x2b, 0x58, 0x1e, 0xa7, 0xe7, 0x86, 0x40, 0xd3, 0x98, 0x97, 0x71, 0xcb, 0x3a, 0x0f, 0x01, 0x9b,
        0x6e, 0x1b, 0xfc, 0x34, 0xa6, 0xda, 0x07, 0x0c, 0xae, 0x37, 0xca, 0x54, 0xfd, 0x26, 0xfe, 0x0a,
        0x45, 0xa2, 0x2a, 0xc4, 0x12, 0x0d, 0xf5, 0x4f, 0x69, 0xe0, 0x8a, 0x77, 0x60, 0x3f, 0x99, 0x95,
        0xd2, 0x38, 0x36, 0x62, 0xb7, 0x32, 0x7e, 0x79, 0xc0, 0x46, 0x93, 0x2f, 0xa5, 0xba, 0x5b, 0xaf,
        0x52, 0x1d, 0xc3, 0x75, 0xcf, 0xd6, 0x4c, 0x83, 0xe8, 0x3d, 0x30, 0x4e, 0xbc, 0x08, 0x2d, 0x09,
        0x06, 0xd9, 0x25, 0x9e, 0x89, 0xf2, 0x96, 0x88, 0xc1, 0x8c, 0x94, 0x0b, 0x28, 0xf0, 0x47, 0x63,
        0xd5, 0xb3, 0x68, 0x56, 0x9c, 0xf9, 0x6f, 0x41, 0x50, 0x85, 0x8b, 0x9d, 0x59, 0xbf, 0x9f, 0xe2,
        0x8e, 0x6a, 0x11, 0x23, 0xa1, 0xcd, 0xb5, 0x7d, 0xc7, 0xa9, 0xc8, 0xef, 0xdf, 0x02, 0xb8, 0x03,
        0x6b, 0x35, 0x3e, 0x2c, 0x76, 0xc9, 0xde, 0x1c, 0x4b, 0xd1, 0xed, 0x14, 0xc5, 0xad, 0xe9, 0x64,
        0x4a, 0xec, 0x8d, 0xf7, 0x10, 0x43, 0x78, 0x15, 0x87, 0xe4, 0xd7, 0x92, 0xe1, 0xee, 0xe3, 0x90
    };

    for (int i = 0; i < len;  i++) {
        arr[i] = lut[arr[i]];
    }
}

//see ASK/MAN Demod for what args are accepted
static int CmdGallagherDemod(const char *Cmd) {

    (void)Cmd;
    bool st = true;
    if (ASKDemod_ext("32 0 0 0", false, false, 1, &st) != PM3_SUCCESS) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - GALLAGHER: ASKDemod failed");
        return PM3_ESOFT;
    }

    size_t size = DemodBufferLen;
    int ans = detectGallagher(DemodBuffer, &size);
    if (ans < 0) {
        if (ans == -1)
            PrintAndLogEx(DEBUG, "DEBUG: Error - GALLAGHER: too few bits found");
        else if (ans == -2)
            PrintAndLogEx(DEBUG, "DEBUG: Error - GALLAGHER: preamble not found");
        else if (ans == -3)
            PrintAndLogEx(DEBUG, "DEBUG: Error - GALLAGHER: Size not correct: %zu", size);
        else
            PrintAndLogEx(DEBUG, "DEBUG: Error - GALLAGHER: ans: %d", ans);

        return PM3_ESOFT;
    }
    setDemodBuff(DemodBuffer, 96, ans);
    setClockGrid(g_DemodClock, g_DemodStartIdx + (ans * g_DemodClock));

    //got a good demod
    uint32_t raw1 = bytebits_to_byte(DemodBuffer, 32);
    uint32_t raw2 = bytebits_to_byte(DemodBuffer + 32, 32);
    uint32_t raw3 = bytebits_to_byte(DemodBuffer + 64, 32);

    // bytes
    uint8_t arr[8] = {0};
    for (int i = 0, pos = 0; i < ARRAYLEN(arr); i++) {
        pos = (i * 8) + i;
        arr[i] = bytebits_to_byte(DemodBuffer + pos, 8);
        printf("%d -", pos);
    }
    printf("\n");

    // crc
    uint8_t crc = bytebits_to_byte(DemodBuffer + 72, 8);
    uint8_t calc_crc =  CRC8Cardx(arr, ARRAYLEN(arr));

    PrintAndLogEx(INFO, " Before:  %s", sprint_hex(arr, 8));
    descramble(arr, ARRAYLEN(arr));
    PrintAndLogEx(INFO, " After :  %s", sprint_hex(arr, 8));

    // 4bit region code
    uint8_t rc = (arr[3] & 0x0E) >> 1;

    // 16bit FC
    uint16_t fc = (arr[5] & 0x0F) << 12 | arr[1] << 4 | ((arr[7] >> 4) & 0x0F);

    // 24bit CN
    uint32_t cn = arr[0] << 16 | (arr[4] & 0x1F) << 11 | arr[2] << 3 | (arr[3] & 0xE0) >> 4;

    // 4bit issue level
    uint8_t il = arr[7] & 0x0F;

    PrintAndLogEx(SUCCESS, "GALLAGHER Tag Found -- Region: %u  FC: %u  CN: %u  Issue Level: %u", rc, fc, cn, il);
    PrintAndLogEx(SUCCESS, "   Printed: %C%u", rc + 0x40, fc);
    PrintAndLogEx(SUCCESS, "   Raw: %08X%08X%08X", raw1, raw2, raw3);
    PrintAndLogEx(SUCCESS, "   CRC: %02X - %02X (%s)", crc, calc_crc, (crc == calc_crc) ? "OK" : "Failed");
    return PM3_SUCCESS;
}

static int CmdGallagherRead(const char *Cmd) {
    lf_read(false, 4096 * 2 + 20);
    return CmdGallagherDemod(Cmd);
}

static int CmdGallagherClone(const char *Cmd) {

    uint32_t blocks[4];
    bool errors = false;
    uint8_t cmdp = 0;
    int datalen = 0;

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_lf_gallagher_clone();
            case 'b': {
                // skip first block,  3*4 = 12 bytes left
                uint8_t rawhex[12] = {0};
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

    if (errors || cmdp == 0) return usage_lf_gallagher_clone();

    //Pac - compat mode, NRZ, data rate 40, 3 data blocks
    blocks[0] = T55x7_MODULATION_MANCHESTER | T55x7_BITRATE_RF_32 | 3 << T55x7_MAXBLOCK_SHIFT;

    PrintAndLogEx(INFO, "Preparing to clone Gallagher to T55x7 with raw hex");
    print_blocks(blocks,  ARRAYLEN(blocks));

    return clone_t55xx_tag(blocks, ARRAYLEN(blocks));
}

static int CmdGallagherSim(const char *Cmd) {
    // ASK/MAN sim.
    PrintAndLogEx(INFO, " To be implemented, feel free to contribute!");
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",  CmdHelp,            AlwaysAvailable, "This help"},
    {"demod", CmdGallagherDemod,  AlwaysAvailable, "Demodulate an GALLAGHER tag from the GraphBuffer"},
    {"read",  CmdGallagherRead,   IfPm3Lf,         "Attempt to read and extract tag data from the antenna"},
    {"clone", CmdGallagherClone,  IfPm3Lf,         "clone GALLAGHER tag to T55x7"},
    {"sim",   CmdGallagherSim,    IfPm3Lf,         "simulate GALLAGHER tag"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdLFGallagher(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

// find Gallagher preamble in already demoded data
int detectGallagher(uint8_t *dest, size_t *size) {
    if (*size < 96) return -1; //make sure buffer has data
    size_t startIdx = 0;
    uint8_t preamble[] = { 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0 };
    if (!preambleSearch(dest, preamble, sizeof(preamble), size, &startIdx))
        return -2; //preamble not found

    if (*size != 96) return -3; //wrong demoded size
    //return start position
    return (int)startIdx;
}

int demodGallagher(void) {
    return CmdGallagherDemod("");
}

