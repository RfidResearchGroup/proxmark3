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
// Low frequency Farpoint G Prox II / Pyramid tag commands
// Biphase, rf/ , 96 bits  (unknown key calc + some bits)
//-----------------------------------------------------------------------------
#include "cmdlfguard.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include "commonutil.h"   // ARRAYLEN
#include "cmdparser.h"    // command_t
#include "comms.h"
#include "ui.h"
#include "cmddata.h"
#include "cmdlf.h"
#include "protocols.h"    // for T55xx config register definitions
#include "lfdemod.h"      // parityTest
#include "cmdlft55xx.h"   // verifywrite
#include "cliparser.h"
#include "cmdlfem4x05.h"  // EM defines

static int CmdHelp(const char *Cmd);

static int demod_guard_raw(uint8_t *raw, uint8_t rlen) {

    if (rlen != 12) {
        return PM3_EINVARG;
    }

    uint8_t bits[96] = {0x00};
    bytes_to_bytebits(raw, rlen, bits);

    // start after 6 bit preamble
    size_t start_idx = 6;
    uint8_t bits_no_spacer[90];
    memcpy(bits_no_spacer, bits + start_idx, 90);

    // remove the 18 (90/5=18) parity bits (down to 72 bits (96-6-18=72))
    size_t len = removeParity(bits_no_spacer, 0, 5, 3, 90); // source, startloc, paritylen, ptype, length_to_run
    if (len != 72) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - gProxII spacer removal did not produce 72 bits: %zu, start: %zu", len, start_idx);
        return PM3_ESOFT;
    }

    uint8_t plain[8] = {0x00};

    // get key and then get all 8 bytes of payload decoded
    uint8_t xorKey = (uint8_t)bytebits_to_byteLSBF(bits_no_spacer, 8);
    for (size_t idx = 0; idx < 8; idx++) {
        plain[idx] = ((uint8_t)bytebits_to_byteLSBF(bits_no_spacer + 8 + (idx * 8), 8)) ^ xorKey;
        PrintAndLogEx(DEBUG, "DEBUG: gProxII byte %zu after xor: %02x", idx, plain[idx]);
    }

    // plain contains 8 Bytes (64 bits) of decrypted raw tag data
    uint8_t fmtlen = plain[0] >> 2;
    uint32_t FC = 0;
    uint32_t Card = 0;

    bool unknown = false;
    switch (fmtlen) {
        case 36:
            FC = ((plain[3] & 0x7F) << 7) | (plain[4] >> 1);
            Card = ((plain[4] & 1) << 19) | (plain[5] << 11) | (plain[6] << 3) | ((plain[7] & 0xE0) >> 5);
            break;
        case 26:
            FC = ((plain[3] & 0x7F) << 1) | (plain[4] >> 7);
            Card = ((plain[4] & 0x7F) << 9) | (plain[5] << 1) | (plain[6] >> 7);
            break;
        default :
            unknown = true;
            break;
    }

    if (unknown)
        PrintAndLogEx(SUCCESS, "G-Prox-II - Unknown len: " _GREEN_("%u") "xor: " _GREEN_("%u")", Raw: %s", fmtlen, xorKey, sprint_hex_inrow(raw, rlen));
    else
        PrintAndLogEx(SUCCESS, "G-Prox-II - Len: " _GREEN_("%u")" FC: " _GREEN_("%u") " Card: " _GREEN_("%u") "xor: " _GREEN_("%u")", Raw: %s", fmtlen, FC, Card, xorKey, sprint_hex_inrow(raw, rlen));

    return PM3_SUCCESS;
}

// attempts to demodulate and identify a G_Prox_II verex/chubb card
// WARNING: if it fails during some points it will destroy the g_DemodBuffer data
// but will leave the g_GraphBuffer intact.
// if successful it will push askraw data back to g_DemodBuffer ready for emulation
int demodGuard(bool verbose) {
    (void) verbose; // unused so far
    //Differential Biphase
    //get binary from ask wave
    if (ASKbiphaseDemod(0, 64, 0, 0, false) != PM3_SUCCESS) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - gProxII ASKbiphaseDemod failed");
        return PM3_ESOFT;
    }

    size_t size = g_DemodBufferLen;

    int preambleIndex = detectGProxII(g_DemodBuffer, &size);
    if (preambleIndex < 0) {

        if (preambleIndex == -1)
            PrintAndLogEx(DEBUG, "DEBUG: Error - gProxII too few bits found");
        else if (preambleIndex == -2)
            PrintAndLogEx(DEBUG, "DEBUG: Error - gProxII preamble not found");
        else if (preambleIndex == -3)
            PrintAndLogEx(DEBUG, "DEBUG: Error - gProxII size not correct: %zu", size);
        else if (preambleIndex == -5)
            PrintAndLogEx(DEBUG, "DEBUG: Error - gProxII wrong spacerbits");
        else
            PrintAndLogEx(DEBUG, "DEBUG: Error - gProxII ans: %d", preambleIndex);
        return PM3_ESOFT;
    }

    // got a good demod of 96 bits
    uint8_t plain[8] = {0x00};
    uint8_t xorKey = 0;
    size_t startIdx = preambleIndex + 6; //start after 6 bit preamble
    uint8_t bits_no_spacer[90];

    // not mess with raw g_DemodBuffer copy to a new sample array
    memcpy(bits_no_spacer, g_DemodBuffer + startIdx, 90);

    // remove the 18 (90/5=18) parity bits (down to 72 bits (96-6-18=72))
    size_t len = removeParity(bits_no_spacer, 0, 5, 3, 90); //source, startloc, paritylen, ptype, length_to_run
    if (len != 72) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - gProxII spacer removal did not produce 72 bits: %zu, start: %zu", len, startIdx);
        return PM3_ESOFT;
    }

    // get key and then get all 8 bytes of payload decoded
    xorKey = (uint8_t)bytebits_to_byteLSBF(bits_no_spacer, 8);
    PrintAndLogEx(DEBUG, "DEBUG: gProxII xorKey: %u", xorKey);

    for (size_t idx = 0; idx < 8; idx++) {
        plain[idx] = ((uint8_t)bytebits_to_byteLSBF(bits_no_spacer + 8 + (idx * 8), 8)) ^ xorKey;
        PrintAndLogEx(DEBUG, "DEBUG: gProxII byte %zu after xor: %02x (%02x before xor)", idx, plain[idx], bytebits_to_byteLSBF(bits_no_spacer + 8 + (idx * 8), 8));
    }

    setDemodBuff(g_DemodBuffer, 96, preambleIndex);
    setClockGrid(g_DemodClock, g_DemodStartIdx + (preambleIndex * g_DemodClock));

    //plain contains 8 Bytes (64 bits) of decrypted raw tag data
    uint8_t fmtLen = plain[0] >> 2;
    uint32_t FC = 0;
    uint32_t Card = 0;
    //get raw 96 bits to print
    uint32_t raw1 = bytebits_to_byte(g_DemodBuffer, 32);
    uint32_t raw2 = bytebits_to_byte(g_DemodBuffer + 32, 32);
    uint32_t raw3 = bytebits_to_byte(g_DemodBuffer + 64, 32);
    bool unknown = false;
    switch (fmtLen) {
        case 36:
            PrintAndLogEx(DEBUG, "DEBUG: FC 1: %x", (plain[3] & 0x7F) << 7);
            PrintAndLogEx(DEBUG, "DEBUG: FC 2: %x", plain[4] >> 1);
            PrintAndLogEx(DEBUG, "DEBUG: Card 1: %x", (plain[4] & 1) << 19);
            PrintAndLogEx(DEBUG, "DEBUG: Card 2: %x", plain[5] << 11);
            PrintAndLogEx(DEBUG, "DEBUG: Card 3: %x", plain[6] << 3);
            PrintAndLogEx(DEBUG, "DEBUG: Card 4: %x", (plain[7] & 0xE0) >> 5);
            FC = ((plain[3] & 0x7F) << 7) | (plain[4] >> 1);
            Card = ((plain[4] & 1) << 19) | (plain[5] << 11) | (plain[6] << 3) | ((plain[7] & 0xE0) >> 5);
            break;
        case 26:
            FC = ((plain[3] & 0x7F) << 1) | (plain[4] >> 7);
            Card = ((plain[4] & 0x7F) << 9) | (plain[5] << 1) | (plain[6] >> 7);
            break;
        default :
            unknown = true;
            break;
    }
    if (unknown)
        PrintAndLogEx(SUCCESS, "G-Prox-II - Unknown len: " _GREEN_("%u") " xor: " _GREEN_("%u")", Raw: %08x%08x%08x ", fmtLen, xorKey, raw1, raw2, raw3);
    else
        PrintAndLogEx(SUCCESS, "G-Prox-II - Len: " _GREEN_("%u")" FC: " _GREEN_("%u") " Card: " _GREEN_("%u") " xor: " _GREEN_("%u") ", Raw: %08x%08x%08x", fmtLen, FC, Card, xorKey, raw1, raw2, raw3);

    return PM3_SUCCESS;
}

static int CmdGuardDemod(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf gproxii demod",
                  "Try to find Guardall Prox-II preamble, if found decode / descramble data",
                  "lf gproxii demod -> use graphbuffer to decode\n"
                  "lf gproxii demod --raw fb8ee718ee3b8cc785c11b92   ->"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("r", "raw", "<hex>", "raw bytes"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int raw_len = 0;
    uint8_t raw[12] = {0};
    CLIGetHexWithReturn(ctx, 1, raw, &raw_len);

    CLIParserFree(ctx);

    if (raw_len != 12 && raw_len != 0) {
        PrintAndLogEx(FAILED, "Must specify 12 bytes, got " _YELLOW_("%u"), raw_len);
        return PM3_EINVARG;
    }

    if (raw_len == 0)
        return demodGuard(true);
    else
        return demod_guard_raw(raw, raw_len);
}

static int CmdGuardReader(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf gproxii reader",
                  "read a Guardall tag",
                  "lf gproxii reader -@   -> continuous reader mode"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("@", NULL, "optional - continuous reader mode"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool cm = arg_get_lit(ctx, 1);
    CLIParserFree(ctx);

    if (cm) {
        PrintAndLogEx(INFO, "Press " _GREEN_("<Enter>") " to exit");
    }

    do {
        lf_read(false, 10000);
        demodGuard(!cm);
    } while (cm && !kbd_enter_pressed());

    return PM3_SUCCESS;
}

static int CmdGuardClone(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf gproxii clone",
                  "Clone a Guardall tag to a T55x7, Q5/T5555 or EM4305/4469 tag.\n"
                  "The facility-code is 8-bit and the card number is 20-bit.  Larger values are truncated.\n"
                  "Currently work only on 26 | 36 bit format",
                  "lf gproxii clone --xor 141 --fmt 26 --fc 123 --cn 1337       -> encode for T55x7 tag\n"
                  "lf gproxii clone --xor 141 --fmt 26 --fc 123 --cn 1337 --q5  -> encode for Q5/T5555 tag\n"
                  "lf gproxii clone --xor 141 --fmt 26 --fc 123 --cn 1337 --em  -> encode for EM4305/4469"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_u64_1(NULL, "xor", "<dec>", "8-bit xor value (installation dependant)"),
        arg_u64_1(NULL, "fmt", "<dec>", "format length 26|32|36|40"),
        arg_u64_1(NULL, "fc", "<dec>", "8-bit value facility code"),
        arg_u64_1(NULL, "cn", "<dec>", "16-bit value card number"),
        arg_lit0(NULL, "q5", "optional - specify writing to Q5/T5555 tag"),
        arg_lit0(NULL, "em", "optional - specify writing to EM4305/4469 tag"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    uint32_t xorval = arg_get_u32_def(ctx, 1, 0);
    uint32_t fmtlen = arg_get_u32_def(ctx, 2, 0);
    uint32_t fc = arg_get_u32_def(ctx, 3, 0);
    uint32_t cn = arg_get_u32_def(ctx, 4, 0);

    bool q5 = arg_get_lit(ctx, 5);
    bool em = arg_get_lit(ctx, 6);
    CLIParserFree(ctx);

    if (q5 && em) {
        PrintAndLogEx(FAILED, "Can't specify both Q5 and EM4305 at the same time");
        return PM3_EINVARG;
    }

    fmtlen &= 0x7f;
    uint32_t facilitycode = (fc & 0x000000FF);
    uint32_t cardnumber = (cn & 0x00FFFFFF);

    //GuardProxII - compat mode, ASK/Biphase,  data rate 64, 3 data blocks
    uint8_t *bs = calloc(96, sizeof(uint8_t));
    if (getGuardBits(xorval, fmtlen, facilitycode, cardnumber, bs) != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Error with tag bitstream generation.");
        free(bs);
        return PM3_ESOFT;
    }

    uint32_t blocks[4] = {T55x7_MODULATION_BIPHASE | T55x7_BITRATE_RF_64 | 3 << T55x7_MAXBLOCK_SHIFT, 0, 0, 0};
    char cardtype[16] = {"T55x7"};
    // Q5
    if (q5) {
        blocks[0] = T5555_FIXED | T5555_MODULATION_BIPHASE  | T5555_SET_BITRATE(64) | 3 << T5555_MAXBLOCK_SHIFT;
        snprintf(cardtype, sizeof(cardtype), "Q5/T5555");
    }

    // EM4305
    if (em) {
        blocks[0] = EM4305_GUARDPROXII_CONFIG_BLOCK;
        snprintf(cardtype, sizeof(cardtype), "EM4305/4469");
    }

    blocks[1] = bytebits_to_byte(bs, 32);
    blocks[2] = bytebits_to_byte(bs + 32, 32);
    blocks[3] = bytebits_to_byte(bs + 64, 32);

    free(bs);

    PrintAndLogEx(INFO, "Preparing to clone Guardall to " _YELLOW_("%s") " with Facility Code: " _GREEN_("%u") " Card Number: " _GREEN_("%u") " xorKey: " _GREEN_("%u")
                  , cardtype
                  , facilitycode
                  , cardnumber
                  , xorval
                 );
    print_blocks(blocks,  ARRAYLEN(blocks));

    int res;
    if (em) {
        res = em4x05_clone_tag(blocks, ARRAYLEN(blocks), 0, false);
    } else {
        res = clone_t55xx_tag(blocks, ARRAYLEN(blocks));
    }
    PrintAndLogEx(SUCCESS, "Done");
    PrintAndLogEx(HINT, "Hint: try " _YELLOW_("`lf gproxii reader`") " to verify");
    return res;
}

static int CmdGuardSim(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf gproxii sim",
                  "Enables simulation of Guardall card with specified card number.\n"
                  "Simulation runs until the button is pressed or another USB command is issued.\n"
                  "The facility-code is 8-bit and the card number is 16-bit.  Larger values are truncated.\n"
                  "Currently work only on 26 | 36 bit format",
                  "lf gproxii sim --xor 141 --fmt 26 --fc 123 --cn 1337\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_u64_1(NULL, "xor", "<dec>", "8-bit xor value (installation dependant)"),
        arg_u64_1(NULL, "fmt", "<dec>", "format length 26|32|36|40"),
        arg_u64_1(NULL, "fc", "<dec>", "8-bit value facility code"),
        arg_u64_1(NULL, "cn", "<dec>", "16-bit value card number"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    uint32_t xorval = arg_get_u32_def(ctx, 1, 0);
    uint32_t fmtlen = arg_get_u32_def(ctx, 2, 0);
    uint32_t fc = arg_get_u32_def(ctx, 3, 0);
    uint32_t cn = arg_get_u32_def(ctx, 4, 0);
    CLIParserFree(ctx);

    fmtlen &= 0x7F;
    uint32_t facilitycode = (fc & 0x000000FF);
    uint32_t cardnumber = (cn & 0x000FFFFF);

    uint8_t bs[96];
    memset(bs, 0x00, sizeof(bs));

    if (getGuardBits(xorval, fmtlen, facilitycode, cardnumber, bs) != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Error with tag bitstream generation.");
        return PM3_ESOFT;
    }

    PrintAndLogEx(SUCCESS, "Simulating Guardall Prox - xorKey: " _YELLOW_("%u") " Facility Code: " _YELLOW_("%u") " CardNumber: " _YELLOW_("%u")
                  , xorval
                  , facilitycode
                  , cardnumber
                 );

    // Guard uses:  clk: 64, invert: 0, encoding: 2 (ASK Biphase)
    lf_asksim_t *payload = calloc(1, sizeof(lf_asksim_t) + sizeof(bs));
    payload->encoding =  2;
    payload->invert = 0;
    payload->separator = 0;
    payload->clock = 64;
    memcpy(payload->data, bs, sizeof(bs));

    clearCommandBuffer();
    SendCommandNG(CMD_LF_ASK_SIMULATE, (uint8_t *)payload,  sizeof(lf_asksim_t) + sizeof(bs));
    free(payload);

    PacketResponseNG resp;
    WaitForResponse(CMD_LF_ASK_SIMULATE, &resp);

    PrintAndLogEx(INFO, "Done");
    if (resp.status != PM3_EOPABORTED)
        return resp.status;
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",    CmdHelp,        AlwaysAvailable, "this help"},
    {"demod",   CmdGuardDemod,  AlwaysAvailable, "demodulate a G Prox II tag from the GraphBuffer"},
    {"reader",  CmdGuardReader, IfPm3Lf,         "attempt to read and extract tag data"},
    {"clone",   CmdGuardClone,  IfPm3Lf,         "clone Guardall tag to T55x7 or Q5/T5555"},
    {"sim",     CmdGuardSim,    IfPm3Lf,         "simulate Guardall tag"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdLFGuard(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

// demod gProxIIDemod
// error returns as -x
// success returns start position in bitstream
// Bitstream must contain previously askrawdemod and biphasedemoded data
int detectGProxII(uint8_t *bits, size_t *size) {

    size_t startIdx = 0;
    uint8_t preamble[] = {1, 1, 1, 1, 1, 0};

    // sanity check
    if (*size < sizeof(preamble)) return -1;

    if (!preambleSearch(bits, preamble, sizeof(preamble), size, &startIdx))
        return -2; //preamble not found

    //gProxII should be 96 bits
    if (*size != 96) return -3;

    //check first 6 spacer bits to verify format
    if (!bits[startIdx + 5] && !bits[startIdx + 10] && !bits[startIdx + 15] && !bits[startIdx + 20] && !bits[startIdx + 25] && !bits[startIdx + 30]) {
        //confirmed proper separator bits found
        //return start position
        return (int) startIdx;
    }
    return -5; //spacer bits not found - not a valid gproxII
}

// Works for 26bits.
int getGuardBits(uint8_t xorKey, uint8_t fmtlen, uint32_t fc, uint32_t cn, uint8_t *guardBits) {

    uint8_t i;
    uint8_t pre[96];
    uint8_t rawbytes[12];
    memset(pre, 0x00, sizeof(pre));
    memset(rawbytes, 0x00, sizeof(rawbytes));

    // add format length (decimal)
    switch (fmtlen) {
        case 32: {
            rawbytes[1] = (32 << 2);
            break;
        }
        case 36: {
            rawbytes[1] = (36 << 2);
            // Get wiegand from FacilityCode 14bits, CardNumber 20bits
            uint8_t wiegand[36];
            memset(wiegand, 0x00, sizeof(wiegand));

            num_to_bytebits(fc, 14, wiegand);
            num_to_bytebits(cn, 20, wiegand + 14);

            // add wiegand parity bits (dest, source, len)
            wiegand_add_parity(pre, wiegand, 34);
            break;
        }
        case 40: {
            rawbytes[1] = (40 << 2);
            break;
        }
        case 26:
        default: {
            rawbytes[1] = (26 << 2);
            // Get 26 wiegand from FacilityCode, CardNumber
            uint8_t wiegand[24];
            memset(wiegand, 0x00, sizeof(wiegand));
            num_to_bytebits(fc, 8, wiegand);
            num_to_bytebits(cn, 16, wiegand + 8);

            // add wiegand parity bits (dest, source, len)
            wiegand_add_parity(pre, wiegand, 24);
            break;
        }
    }
    // 2bit checksum, unknown today,
    // these two bits are the last ones of rawbyte[1], hence the LSHIFT above.


    // xor key
    rawbytes[0] = xorKey;

    rawbytes[2] = 1;
    rawbytes[3] = 0;

    // add wiegand to rawbytes
    for (i = 0; i < 5; ++i)
        rawbytes[i + 4] = bytebits_to_byte(pre + (i * 8), 8);

    PrintAndLogEx(DEBUG, " WIE | %s", sprint_hex(rawbytes, sizeof(rawbytes)));

    // XOR (only works on wiegand stuff)
    for (i = 1; i < sizeof(rawbytes); ++i)
        rawbytes[i] ^= xorKey ;

    PrintAndLogEx(DEBUG, " XOR | %s", sprint_hex(rawbytes, sizeof(rawbytes)));

    // convert rawbytes to bits in pre
    for (i = 0; i < sizeof(rawbytes); ++i)
        num_to_bytebitsLSBF(rawbytes[i], 8, pre + (i * 8));

    PrintAndLogEx(DEBUG, " Raw | %s", sprint_hex(rawbytes, sizeof(rawbytes)));
    PrintAndLogEx(DEBUG, " Raw | %s", sprint_bytebits_bin(pre, 96));

    // add spacer bit 0 every 4 bits, starting with index 0,
    // 12 bytes, 24 nibbles.  24+1 extra bites. 3bytes.  ie 9bytes | 1byte xorkey, 8bytes rawdata (72bits, should be enough for a 40bit wiegand)
    addParity(pre, guardBits + 6, 72, 5, 3);

    // preamble
    guardBits[0] = 1;
    guardBits[1] = 1;
    guardBits[2] = 1;
    guardBits[3] = 1;
    guardBits[4] = 1;
    guardBits[5] = 0;

    PrintAndLogEx(DEBUG, " FIN | %s\n", sprint_bytebits_bin(guardBits, 96));
    return PM3_SUCCESS;
}

