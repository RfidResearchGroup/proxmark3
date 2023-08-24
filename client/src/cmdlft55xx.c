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
// Low frequency T55xx commands
//-----------------------------------------------------------------------------

// ensure localtime_r is available even with -std=c99; must be included before
#if !defined(_WIN32)
#define _POSIX_C_SOURCE 200112L
#endif

#include "cmdlft55xx.h"
#include <ctype.h>
#include <time.h>         // MingW
#include "cmdparser.h"    // command_t
#include "comms.h"
#include "commonutil.h"
#include "protocols.h"
#include "proxgui.h"
#include "graph.h"
#include "cmddata.h"
#include "lfdemod.h"
#include "cmdhf14a.h"     // for getTagInfo
#include "fileutils.h"    // loadDictionary
#include "util_posix.h"
#include "cmdlf.h"        // for lf sniff
#include "generator.h"
#include "cliparser.h"    // cliparsing

// Some defines for readability
#define T55XX_DLMODE_FIXED         0 // Default Mode
#define T55XX_DLMODE_LLR           1 // Long Leading Reference
#define T55XX_DLMODE_LEADING_ZERO  2 // Leading Zero
#define T55XX_DLMODE_1OF4          3 // 1 of 4
// #define T55XX_LONGLEADINGREFERENCE 4 // Value to tell Write Bit to send long reference
#define T55XX_DLMODE_ALL           4 // Tell help to show 'r 4' for all dl modes
#define T55XX_DLMODE_SINGLE        5 // Tell help file NOT to show 'r 4' (not available)

#define T55XX_PrintConfig           true
#define T55XX_DontPrintConfig       false

//static uint8_t bit_rates[9] = {8, 16, 32, 40, 50, 64, 100, 128, 0};

// Default configuration
static t55xx_conf_block_t config = {
    .modulation = DEMOD_ASK,
    .inverted = false,
    .offset = 0x00,
    .block0 = 0x00,
    .block0Status = NOTSET,
    .Q5 = false,
    .usepwd = false,
    .downlink_mode = refFixedBit
};

static t55xx_memory_item_t cardmem[T55x7_BLOCK_COUNT] = {{0}};

t55xx_conf_block_t Get_t55xx_Config(void) {
    return config;
}

void Set_t55xx_Config(t55xx_conf_block_t conf) {
    config = conf;
}

static int CmdHelp(const char *Cmd);

static void arg_add_t55xx_downloadlink(void *at[], uint8_t *idx, uint8_t show, uint8_t dl_mode_def) {
    const size_t r_count = 56;
    const size_t r_len = r_count * sizeof(uint8_t);

    char *r0 = (char *)calloc(r_count, sizeof(uint8_t));
    char *r1 = (char *)calloc(r_count, sizeof(uint8_t));
    char *r2 = (char *)calloc(r_count, sizeof(uint8_t));
    char *r3 = (char *)calloc(r_count, sizeof(uint8_t));

    snprintf(r0, r_len, "downlink - fixed bit length %s", (dl_mode_def == 0) ? "(detected def)" : "");
    snprintf(r1, r_len, "downlink - long leading reference %s", (dl_mode_def == 1) ? "(detected def)" : "");
    snprintf(r2, r_len, "downlink - leading zero %s", (dl_mode_def == 2) ? "(detected def)" : "");
    snprintf(r3, r_len, "downlink - 1 of 4 coding reference %s", (dl_mode_def == 3) ? "(detected def)" : "");

    uint8_t n = *idx;
    at[n++] = arg_lit0(NULL, "r0", r0);
    at[n++] = arg_lit0(NULL, "r1", r1);
    at[n++] = arg_lit0(NULL, "r2", r2);
    at[n++] = arg_lit0(NULL, "r3", r3);

    if (show == T55XX_DLMODE_ALL) {
        char *r4 = (char *)calloc(r_count, sizeof(uint8_t));
        snprintf(r4, r_len, "try all downlink modes %s", (dl_mode_def == 4) ? "(def)" : "");
        at[n++] = arg_lit0(NULL, "all", r4);
    }
    at[n++] = arg_param_end;
    *idx = n;
}

static int CmdT55xxCloneHelp(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf t55xx clonehelp",
                  "Display a list of available commands for cloning specific techs on T5xx tags",
                  "lf t55xx clonehelp"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    PrintAndLogEx(NORMAL, "For cloning specific techs on T55xx tags, see commands available in corresponding LF sub-menus, e.g.:");
    PrintAndLogEx(NORMAL, _GREEN_("lf awid clone"));
    PrintAndLogEx(NORMAL, _GREEN_("lf destron clone"));
    PrintAndLogEx(NORMAL, _GREEN_("lf em 410x clone"));
// todo:  implement restore
//    PrintAndLogEx(NORMAL, _GREEN_("lf em 4x05 write"));
//    PrintAndLogEx(NORMAL, _GREEN_("lf em 4x50 restore"));
    PrintAndLogEx(NORMAL, _GREEN_("lf fdxb clone"));
    PrintAndLogEx(NORMAL, _GREEN_("lf gallagher clone"));
    PrintAndLogEx(NORMAL, _GREEN_("lf gproxii clone"));
    PrintAndLogEx(NORMAL, _GREEN_("lf hid clone"));
// todo:  implement restore
//    PrintAndLogEx(NORMAL, _GREEN_("lf hitag clone"));
    PrintAndLogEx(NORMAL, _GREEN_("lf idteck clone"));
    PrintAndLogEx(NORMAL, _GREEN_("lf indala clone"));
    PrintAndLogEx(NORMAL, _GREEN_("lf io clone"));
    PrintAndLogEx(NORMAL, _GREEN_("lf jablotron clone"));
    PrintAndLogEx(NORMAL, _GREEN_("lf keri clone"));
    PrintAndLogEx(NORMAL, _GREEN_("lf motorola clone"));
    PrintAndLogEx(NORMAL, _GREEN_("lf nedap clone"));
    PrintAndLogEx(NORMAL, _GREEN_("lf nexwatch clone"));
    PrintAndLogEx(NORMAL, _GREEN_("lf noralsy clone"));
    PrintAndLogEx(NORMAL, _GREEN_("lf pac clone"));
    PrintAndLogEx(NORMAL, _GREEN_("lf paradox clone"));
    PrintAndLogEx(NORMAL, _GREEN_("lf presco clone"));
    PrintAndLogEx(NORMAL, _GREEN_("lf pyramid clone"));
    PrintAndLogEx(NORMAL, _GREEN_("lf securakey clone"));
    PrintAndLogEx(NORMAL, _GREEN_("lf viking clone"));
    PrintAndLogEx(NORMAL, _GREEN_("lf visa2000 clone"));
    return PM3_SUCCESS;
}

static void T55x7_SaveBlockData(uint8_t idx, uint32_t data) {
    if (idx < T55x7_BLOCK_COUNT) {
        cardmem[idx].valid      = true;
        cardmem[idx].blockdata  = data;
    }
}
static void T55x7_ClearAllBlockData(void) {
    for (uint8_t idx = 0; idx < T55x7_BLOCK_COUNT; idx++) {
        cardmem[idx].valid      = false;
        cardmem[idx].blockdata  = 0x00;
    }
}

int clone_t55xx_tag(uint32_t *blockdata, uint8_t numblocks) {

    if (blockdata == NULL)
        return PM3_EINVARG;
    if (numblocks < 1 || numblocks > 8)
        return PM3_EINVARG;

    PacketResponseNG resp;

    // fast push mode
    g_conn.block_after_ACK = true;

    for (int8_t i = 0; i < numblocks; i++) {

        // Disable fast mode on last packet
        if (i == numblocks - 1) {
            g_conn.block_after_ACK = false;
        }

        clearCommandBuffer();

        t55xx_write_block_t ng;
        ng.data = blockdata[i];
        ng.pwd = 0;
        ng.blockno = i;
        ng.flags = 0;

        SendCommandNG(CMD_LF_T55XX_WRITEBL, (uint8_t *)&ng, sizeof(ng));
        if (!WaitForResponseTimeout(CMD_LF_T55XX_WRITEBL, &resp, T55XX_WRITE_TIMEOUT)) {
            PrintAndLogEx(ERR, "Error occurred, device did not respond during write operation.");
            return PM3_ETIMEOUT;
        }
    }

    uint8_t res = 0;
    for (int8_t i = 0; i < numblocks; i++) {

        if (i == 0) {
            SetConfigWithBlock0(blockdata[0]);
            if (t55xxAcquireAndCompareBlock0(false, 0, blockdata[0], false))
                continue;
        }

        if (t55xxVerifyWrite(i, 0, false, false, 0, 0xFF, blockdata[i]) == false)
            res++;
    }

    if (res == 0)
        PrintAndLogEx(SUCCESS, "Data written and verified");

    return PM3_SUCCESS;
}

static bool t55xxProtect(bool lock, bool usepwd, uint8_t override, uint32_t password, uint8_t downlink_mode, uint32_t new_password) {

    PrintAndLogEx(INFO, "Checking current configuration");

    bool testmode = false;
    uint32_t block0 = 0;

    int res = T55xxReadBlockEx(T55x7_CONFIGURATION_BLOCK, T55x7_PAGE0, usepwd, override, password, downlink_mode, false);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, "Failed to read block0, use " _YELLOW_("`p`") " password parameter?");
        return false;
    }

    if (GetT55xxBlockData(&block0) == false) {
        PrintAndLogEx(DEBUG, "ERROR decoded block0 == %08x", block0);
        return false;
    }
    PrintAndLogEx(DEBUG, "OK read block0 == %08x", block0);


    bool isPwdBitAlreadySet = (block0 >> (32 - 28) & 1);
    if (isPwdBitAlreadySet) {
        PrintAndLogEx(INFO, "PWD bit is already set");
        usepwd = true;
    }

    // set / clear pwd bit
    if (lock) {
        block0 |= 1 << 4;
    } else {
        block0 &= ~(1 << 4);
    }

    // write new password
    if (t55xxWrite(T55x7_PWD_BLOCK, T55x7_PAGE0, usepwd, testmode, password, downlink_mode, new_password) != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Failed to write new password");
        return false;
    } else {
        PrintAndLogEx(SUCCESS, "Wrote new password");
    }

    // validate new password
    uint32_t curr_password = (isPwdBitAlreadySet) ? new_password : password;

    if (t55xxVerifyWrite(T55x7_PWD_BLOCK, T55x7_PAGE0, usepwd, override, curr_password, downlink_mode, new_password) == false) {
        PrintAndLogEx(WARNING, "Failed to validate the password write. aborting.");
        return false;
    } else {
        PrintAndLogEx(SUCCESS, "Validated new password");
    }

    // write config
    if (t55xxWrite(T55x7_CONFIGURATION_BLOCK, T55x7_PAGE0, usepwd, testmode, curr_password, downlink_mode, block0) != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Failed to write modified configuration block %08X", block0);
        return false;
    } else {
        PrintAndLogEx(SUCCESS, "Wrote modified configuration block");
    }

    // validate new config.  If all went well,  card should now demand pwd, hence override = 0.
    override = 0;
    if (t55xxVerifyWrite(T55x7_CONFIGURATION_BLOCK, T55x7_PAGE0, true, override, new_password, downlink_mode, block0) == false) {
        PrintAndLogEx(WARNING, "Failed to validate pwd bit set on configuration block. aborting.");
        return false;
    } else {
        PrintAndLogEx(SUCCESS, "New configuration block " _YELLOW_("%08X")" password " _YELLOW_("%08X"), block0, new_password);
        PrintAndLogEx(SUCCESS, "Success, tag is locked");
        return true;
    }
}

bool t55xxAcquireAndCompareBlock0(bool usepwd, uint32_t password, uint32_t known_block0, bool verbose) {

    if (verbose)
        PrintAndLogEx(INFO, "Block0 write detected, running `detect` to see if validation is possible");

    for (uint8_t m = 0; m < 4; m++) {
        if (AcquireData(T55x7_PAGE0, T55x7_CONFIGURATION_BLOCK, usepwd, password, m) == false) {
            continue;
        }

        if (DecodeT55xxBlock() == false) {
            continue;
        }

        for (size_t i = 0; i < g_DemodBufferLen - 32; i++) {
            uint32_t tmp = PackBits(i, 32, g_DemodBuffer);
            if (tmp == known_block0) {
                config.offset = i;
                config.downlink_mode = m;
                return true;
            }
        }
    }
    return false;
}

bool t55xxAcquireAndDetect(bool usepwd, uint32_t password, uint32_t known_block0, bool verbose) {

    if (verbose)
        PrintAndLogEx(INFO, "Block0 write detected, running `detect` to see if validation is possible");

    for (uint8_t m = 0; m < 4; m++) {
        if (AcquireData(T55x7_PAGE0, T55x7_CONFIGURATION_BLOCK, usepwd, password, m) == false)
            continue;

        if (t55xxTryDetectModulationEx(m, verbose, known_block0, (usepwd) ? password : -1) == false)
            continue;

        config.downlink_mode = m;
        return true;
    }
    config.usepwd = false; // unknown so assume no password
    config.pwd = 0x00;
    return false;
}

bool t55xxVerifyWrite(uint8_t block, bool page1, bool usepwd, uint8_t override, uint32_t password, uint8_t downlink_mode, uint32_t data) {

    uint32_t read_data = 0;

    if (downlink_mode == 0xFF)
        downlink_mode = config.downlink_mode;

    int res = T55xxReadBlockEx(block, page1, usepwd, override, password, downlink_mode, false);
    if (res == PM3_SUCCESS) {

        if (GetT55xxBlockData(&read_data) == false)
            return false;

    } else if (res == PM3_EWRONGANSWER) {

        // couldn't decode.  Lets see if this was a block 0 write and try read/detect it auto.
        // this messes up with ppl config..
        if (block == 0 && page1 == false) {

            if (t55xxAcquireAndDetect(usepwd, password, data, true) == false)
                return false;

            return t55xxVerifyWrite(block, page1, usepwd, 2, password, config.downlink_mode, data);
        }
    }

    return (read_data == data);
}

int t55xxWrite(uint8_t block, bool page1, bool usepwd, bool testMode, uint32_t password, uint8_t downlink_mode, uint32_t data) {

    uint8_t flags;
    flags  = (usepwd)   ? 0x1 : 0;
    flags |= (page1)    ? 0x2 : 0;
    flags |= (testMode) ? 0x4 : 0;
    flags |= (downlink_mode << 3);

    /*
        OLD style
       arg0 = data, (4 bytes)
       arg1 = block (1 byte)
       arg2 = password (4 bytes)
       flags = data[0] (1 byte)

       new style
       uses struct in pm3_cmd.h
    */
    t55xx_write_block_t ng;
    ng.data    = data;
    ng.pwd     = password;
    ng.blockno = block;
    ng.flags   = flags;

    PacketResponseNG resp;
    clearCommandBuffer();
    SendCommandNG(CMD_LF_T55XX_WRITEBL, (uint8_t *)&ng, sizeof(ng));
    if (!WaitForResponseTimeout(CMD_LF_T55XX_WRITEBL, &resp, 2000)) {
        PrintAndLogEx(ERR, "Error occurred, device did not ACK write operation.");
        return PM3_ETIMEOUT;
    }
    return resp.status;
}

void printT5xxHeader(uint8_t page) {
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(SUCCESS, "Page " _YELLOW_("%d"), page);
    PrintAndLogEx(SUCCESS, "blk | hex data | binary                           | ascii");
    PrintAndLogEx(SUCCESS, "----+----------+----------------------------------+-------");
}

void SetConfigWithBlock0(uint32_t block0) {
    SetConfigWithBlock0Ex(block0, 0, false);
}
void SetConfigWithBlock0Ex(uint32_t block0, uint8_t offset, bool Q5) {
    // T55x7
    uint32_t extend = (block0 >> (32 - 15)) & 0x01;
    uint32_t dbr;
    if (extend)
        dbr = (block0 >> (32 - 14)) & 0x3F;
    else
        dbr = (block0 >> (32 - 14)) & 0x07;

    uint32_t datamod  = (block0 >> (32 - 20)) & 0x1F;
    bool pwd = (bool)((block0 >> (32 - 28)) & 0x01);
    bool sst = (bool)((block0 >> (32 - 29)) & 0x01);
    bool inv = (bool)((block0 >> (32 - 31)) & 0x01);

    config.modulation = datamod;
    config.bitrate = dbr;

    // FSK1a, FSK2a
    if (datamod == DEMOD_FSK1a || datamod == DEMOD_FSK2a || datamod ==  DEMOD_BIa)
        config.inverted = 1;
    else
        config.inverted = inv;

    config.Q5 = Q5;
    config.ST = sst;
    config.usepwd = pwd;
    config.offset = offset;
    config.block0 = block0;
}

static int CmdT55xxSetConfig(const char *Cmd) {
    // No args
    if (strlen(Cmd) == 0) {
        PrintAndLogEx(INFO, "--- " _CYAN_("current t55xx config") " --------------------------");
        return printConfiguration(config);
    }

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf t55xx config",
                  "Set/Get T55XX configuration of the pm3 client. Like modulation, inverted, offset, rate etc.\n"
                  "Offset is start position to decode data.",
                  "lf t55xx config --FSK         --> FSK demodulation\n"
                  "lf t55xx config --FSK -i      --> FSK demodulation, inverse data\n"
                  "lf t55xx config --FSK -i -o 3 --> FSK demodulation, inverse data, offset 3\n"
                 );

    // 1 (help) + 19 (user specified params) + (5 T55XX_DLMODE_SINGLE)
    void *argtable[1 + 12 + 6 + 5] = {
        arg_param_begin,
        arg_lit0(NULL, "FSK",   "set demodulation FSK"),
        arg_lit0(NULL, "FSK1",  "set demodulation FSK 1"),
        arg_lit0(NULL, "FSK1A", "set demodulation FSK 1a (inv)"),
        arg_lit0(NULL, "FSK2",  "set demodulation FSK 2"),
        arg_lit0(NULL, "FSK2A", "set demodulation FSK 2a (inv)"),
        arg_lit0(NULL, "ASK",   "set demodulation ASK"),
        arg_lit0(NULL, "PSK1",  "set demodulation PSK 1"),
        arg_lit0(NULL, "PSK2",  "set demodulation PSK 2"),
        arg_lit0(NULL, "PSK3",  "set demodulation PSK 3"),
        arg_lit0(NULL, "NRZ",   "set demodulation NRZ"),
        arg_lit0(NULL, "BI",    "set demodulation Biphase"),
        arg_lit0(NULL, "BIA",   "set demodulation Diphase (inverted biphase)"),
        arg_lit0("i", "inv", "set/reset data signal inversion"),
        arg_lit0(NULL, "q5", "set/reset as Q5/T5555 chip instead of T55x7"),
        arg_lit0(NULL, "st", "set/reset Sequence Terminator on"),
        arg_int0(NULL, "rate", "<dec>", "set bitrate <8|16|32|40|50|64|100|128>"),
        arg_str0("c", "blk0", "<hex>", "set configuration from a block0 (4 hex bytes)"),
        arg_int0("o", "offset", "<0-255>", "set offset, where data should start decode in bitstream "),
    };

    uint8_t idx = 19;
    arg_add_t55xx_downloadlink(argtable, &idx, T55XX_DLMODE_SINGLE, config.downlink_mode);
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    idx = 1;
    bool mods[12];
    int verify_mods = 0;
    while (idx - 1 < sizeof(mods)) {
        mods[idx - 1] = arg_get_lit(ctx, idx);
        verify_mods += mods[idx - 1];
        idx++;
    }

    // Not these flags are used to Toggle the values.
    // If not flag then don't set or reset, leave as is since the call may just be be setting a different value.
    bool invert = arg_get_lit(ctx, idx++);
    bool use_q5 = arg_get_lit(ctx, idx++);
    bool use_st = arg_get_lit(ctx, idx++);

    int bitrate = arg_get_int_def(ctx, idx, -1);
    idx++;

    bool gotconf = false;
    uint32_t block0 = 0;
    int res = arg_get_u32_hexstr_def_nlen(ctx, idx++, 0, &block0, 4, true);
    if (res == 0 || res == 2) {
        PrintAndLogEx(ERR, "block0 data must be 4 hex bytes");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }
    if (res == 1) {
        gotconf = true;
    }

    int offset = arg_get_int_def(ctx, idx, -1);
    idx++;

    bool r0 = arg_get_lit(ctx, idx++);
    bool r1 = arg_get_lit(ctx, idx++);
    bool r2 = arg_get_lit(ctx, idx++);
    bool r3 = arg_get_lit(ctx, idx++);
    CLIParserFree(ctx);

    // validate user specified downlink mode
    if ((r0 + r1 + r2 + r3) > 1) {
        PrintAndLogEx(FAILED, "Error multiple downlink encoding");
        return PM3_EINVARG;
    }

    // validate user specified modulation FSK,FSK1,...BIA
    if (verify_mods > 1) {
        PrintAndLogEx(FAILED, "Error multiple demodulations, select one");
        return PM3_EINVARG;
    }

    // validate user specified bitrate

    if (bitrate != -1) {
        uint8_t rates[9] = {8, 16, 32, 40, 50, 64, 100, 128, 0};
        uint8_t i = 0;
        for (; i < ARRAYLEN(rates); i++) {
            if (rates[i] == bitrate) {
                config.bitrate = i;
                config.block0 = ((config.block0 & ~(0x1c0000)) | (i << 18));
                break;
            }
        }
        if (i == 9) {
            PrintAndLogEx(FAILED, "Error select a valid bitrate");
            return PM3_EINVARG;
        }
    }

    // validate user specified offset
    if (offset > -1 && offset < 0x100) {
        config.offset = offset;
    }

    // validate user specific T5555 / Q5 - use the flag to toggle between T5577 and Q5
    config.Q5 ^= use_q5;

    // validate user specific sequence terminator
    // if use_st flag was supplied, then toggle and update the config block0; if not supplied skip the config block0 update.
    if (use_st) {
        config.ST ^= use_st;
        config.block0 = ((config.block0 & ~(0x8)) | (config.ST << 3));
    }

    // validate user specific invert
    // In theory this should also be set in the config block 0; butit requries the extend mode config, which will change other things.
    // as such, leave in user config for decoding the data until a full fix can be added.
    // use the flag to toggle if invert is on or off.
    config.inverted ^= invert;

    // validate user specific downlink mode
    uint8_t downlink_mode = config.downlink_mode;
    if (r0)
        downlink_mode = refFixedBit;
    else if (r1)
        downlink_mode = refLongLeading;
    else if (r2)
        downlink_mode = refLeading0;
    else if (r3)
        downlink_mode = ref1of4;

    config.downlink_mode = downlink_mode;

    // validate user specific modulation
    if (mods[0]) {
        config.modulation = DEMOD_FSK;
    } else if (mods[1]) {
        config.modulation = DEMOD_FSK1;
        config.inverted = 0;
    } else if (mods[2]) {
        config.modulation = DEMOD_FSK1a;
        config.inverted = 1;
    } else if (mods[3]) {
        config.modulation = DEMOD_FSK2;
        config.inverted = 0;
    } else if (mods[4]) {
        config.modulation = DEMOD_FSK2a;
        config.inverted = 1;
    } else if (mods[5]) {
        config.modulation = DEMOD_ASK;
    } else if (mods[6]) {
        config.modulation = DEMOD_PSK1;
    } else if (mods[7]) {
        config.modulation = DEMOD_PSK2;
    } else if (mods[8]) {
        config.modulation = DEMOD_PSK3;
    } else if (mods[9]) {
        config.modulation = DEMOD_NRZ;
    } else if (mods[10]) {
        config.modulation = DEMOD_BI;
        config.inverted = 0;
    } else if (mods[11]) {
        config.modulation = DEMOD_BIa;
        config.inverted = 1;
    }

    config.block0 = ((config.block0 & ~(0x1f000)) | (config.modulation << 12));

    config.block0Status = USERSET;
    if (gotconf) {
        SetConfigWithBlock0Ex(block0, config.offset, config.Q5);
    }

    PrintAndLogEx(INFO, "--- " _CYAN_("current t55xx config") " --------------------------");
    return printConfiguration(config);
}
int T55xxReadBlock(uint8_t block, bool page1, bool usepwd, uint8_t override, uint32_t password, uint8_t downlink_mode) {
    return T55xxReadBlockEx(block, page1, usepwd, override, password, downlink_mode, true);
}

int T55xxReadBlockEx(uint8_t block, bool page1, bool usepwd, uint8_t override, uint32_t password, uint8_t downlink_mode, bool verbose) {
    //Password mode
    if (usepwd) {
        // try reading the config block and verify that PWD bit is set before doing this!
        // override = 1 (override and display)
        // override = 2 (override and no display)
        if (override == 0) {
            if (AcquireData(T55x7_PAGE0, T55x7_CONFIGURATION_BLOCK, false, 0, downlink_mode) == false)
                return PM3_ERFTRANS;

            if (t55xxTryDetectModulationEx(downlink_mode, false, 0, password) == false) {
                PrintAndLogEx(WARNING, "Safety check: Could not detect if PWD bit is set in config block. Exits.");
                PrintAndLogEx(HINT, "Consider using the override parameter to force read.");
                return PM3_EWRONGANSWER;
            } else {
                PrintAndLogEx(WARNING, "Safety check: PWD bit is NOT set in config block. Reading without password...");
                usepwd = false;
                page1 = false; // ??
            }
        } else if (override == 1) {
            PrintAndLogEx(INFO, "Safety check overridden - proceeding despite risk");
        }
    }

    if (AcquireData(page1, block, usepwd, password, downlink_mode) == false)
        return PM3_ERFTRANS;

    if (DecodeT55xxBlock() == false)
        return PM3_EWRONGANSWER;

    if (verbose)
        printT55xxBlock(block, page1);

    return PM3_SUCCESS;
}

static int CmdT55xxReadBlock(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf t55xx read",
                  "Read T55xx block data.  This commands defaults to page 0.\n\n"
                  _RED_("           * * * WARNING * * *") "\n"
                  _CYAN_("Use of read with password on a tag not configured") "\n"
                  _CYAN_("for a password can damage the tag") "\n"
                  _RED_("           * * * * * * * * * *"),
                  "lf t55xx read -b 0                   --> read data from block 0\n"
                  "lf t55xx read -b 0 --pwd 01020304    --> read data from block 0, pwd 01020304\n"
                  "lf t55xx read -b 0 --pwd 01020304 -o --> read data from block 0, pwd 01020304, override\n"
                 );

    // 1 (help) + 4(four user specified params) + (5 T55XX_DLMODE_SINGLE)
    void *argtable[5 + 5] = {
        arg_param_begin,
        arg_int1("b", "blk", "<0-7>", "block number to read"),
        arg_str0("p", "pwd", "<hex>", "password (4 hex bytes)"),
        arg_lit0("o", "override", "override safety check"),
        arg_lit0(NULL, "pg1", "read page 1"),
    };
    uint8_t idx = 5;
    arg_add_t55xx_downloadlink(argtable, &idx, T55XX_DLMODE_SINGLE, config.downlink_mode);
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int block = arg_get_int_def(ctx, 1, REGULAR_READ_MODE_BLOCK);

    bool usepwd = false;
    uint32_t password = 0;
    int res = arg_get_u32_hexstr_def_nlen(ctx, 2, 0, &password, 4, true);
    if (res == 0 || res == 2) {
        PrintAndLogEx(ERR, "Password should be 4 hex bytes");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }
    if (res == 1) {
        usepwd = true;
    }

    uint8_t override = arg_get_lit(ctx, 3);
    bool page1 = arg_get_lit(ctx, 4);

    bool r0 = arg_get_lit(ctx, 5);
    bool r1 = arg_get_lit(ctx, 6);
    bool r2 = arg_get_lit(ctx, 7);
    bool r3 = arg_get_lit(ctx, 8);
    CLIParserFree(ctx);

    if ((r0 + r1 + r2 + r3) > 1) {
        PrintAndLogEx(FAILED, "Error multiple downlink encoding");
        return PM3_EINVARG;
    }

    uint8_t downlink_mode = config.downlink_mode;
    if (r0)
        downlink_mode = refFixedBit;
    else if (r1)
        downlink_mode = refLongLeading;
    else if (r2)
        downlink_mode = refLeading0;
    else if (r3)
        downlink_mode = ref1of4;

    if (block > 7 && block != REGULAR_READ_MODE_BLOCK) {
        PrintAndLogEx(NORMAL, "Block must be between 0 and 7");
        return PM3_ESOFT;
    }

    printT5xxHeader(page1);
    return T55xxReadBlock(block, page1, usepwd, override, password, downlink_mode);
}

bool DecodeT55xxBlock(void) {

    int ans = 0;
    bool ST = config.ST;
    uint8_t bitRate[8] = {8, 16, 32, 40, 50, 64, 100, 128};
    g_DemodBufferLen = 0x00;

    switch (config.modulation) {
        case DEMOD_FSK:
            ans = FSKrawDemod(bitRate[config.bitrate], config.inverted, 0, 0, false);
            break;
        case DEMOD_FSK1:
        case DEMOD_FSK1a:
            ans = FSKrawDemod(bitRate[config.bitrate], config.inverted, 8, 5, false);
            break;
        case DEMOD_FSK2:
        case DEMOD_FSK2a:
            ans = FSKrawDemod(bitRate[config.bitrate], config.inverted, 10, 8, false);
            break;
        case DEMOD_ASK:
            ans = ASKDemod_ext(bitRate[config.bitrate], config.inverted, 1, 0, false, false, false, 1, &ST);
            break;
        case DEMOD_PSK1:
            ans = PSKDemod(bitRate[config.bitrate], config.inverted, 6, false);
            break;
        case DEMOD_PSK2: //inverted won't affect this
        case DEMOD_PSK3: //not fully implemented
            ans = PSKDemod(bitRate[config.bitrate], 0, 6, false);
            psk1TOpsk2(g_DemodBuffer, g_DemodBufferLen);
            break;
        case DEMOD_NRZ:
            ans = NRZrawDemod(bitRate[config.bitrate], config.inverted, 1, false);
            break;
        case DEMOD_BI:
        case DEMOD_BIa:
            ans = ASKbiphaseDemod(0, bitRate[config.bitrate], config.inverted, 1, false);
            break;
        default:
            return false;
    }
    return (ans == PM3_SUCCESS);
}

static bool DecodeT5555TraceBlock(void) {
    g_DemodBufferLen = 0x00;

    // According to datasheet. Always: RF/64, not inverted, Manchester
    bool st = false;
    return (ASKDemod_ext(64, 0, 1, 0, false, false, false, 1, &st) == PM3_SUCCESS);
}

// sanity check. Don't use proxmark if it is offline and you didn't specify useGraphbuf
static int SanityOfflineCheck(bool useGraphBuffer) {
    if (!useGraphBuffer && !g_session.pm3_present) {
        PrintAndLogEx(WARNING, "Your proxmark3 device is offline. Specify [1] to use graphbuffer data instead");
        return PM3_ENODATA;
    }
    return PM3_SUCCESS;
}

static void T55xx_Print_DownlinkMode(uint8_t downlink_mode) {
    char msg[80];
    snprintf(msg, sizeof(msg), "Downlink Mode used : ");

    switch (downlink_mode) {
        case  1 :
            strcat(msg, _YELLOW_("long leading reference"));
            break;
        case  2 :
            strcat(msg, _YELLOW_("leading zero reference"));
            break;
        case  3 :
            strcat(msg, _YELLOW_("1 of 4 coding reference"));
            break;
        default :
            strcat(msg, _YELLOW_("default/fixed bit length"));
            break;
    }

    PrintAndLogEx(SUCCESS, msg);
}

static int CmdT55xxWakeUp(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf t55xx wakeup",
                  "This commands sends the Answer-On-Request command and leaves the readerfield ON afterwards",
                  "lf t55xx wakeup -p 11223344   --> send wakeup with password\n"
                 );

    // 1 (help) + 2 (two user specified params) + (5 T55XX_DLMODE_SINGLE)
    void *argtable[3 + 5] = {
        arg_param_begin,
        arg_str0("p", "pwd", "<hex>", "password (4 hex bytes)"),
        arg_lit0("v", "verbose", "verbose output"),
    };
    uint8_t idx = 3;
    arg_add_t55xx_downloadlink(argtable, &idx, T55XX_DLMODE_SINGLE, config.downlink_mode);
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    uint32_t password = 0;
    int res = arg_get_u32_hexstr_def_nlen(ctx, 2, 0, &password, 4, true);
    if (res == 0 || res == 2) {
        PrintAndLogEx(ERR, "Password should be 4 hex bytes");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    bool verbose = arg_get_lit(ctx, 2);
    bool r0 = arg_get_lit(ctx, 3);
    bool r1 = arg_get_lit(ctx, 4);
    bool r2 = arg_get_lit(ctx, 5);
    bool r3 = arg_get_lit(ctx, 6);
    CLIParserFree(ctx);

    if ((r0 + r1 + r2 + r3) > 1) {
        PrintAndLogEx(FAILED, "Error multiple downlink encoding");
        return PM3_EINVARG;
    }

    uint8_t downlink_mode = config.downlink_mode;
    if (r0)
        downlink_mode = refFixedBit;
    else if (r1)
        downlink_mode = refLongLeading;
    else if (r2)
        downlink_mode = refLeading0;
    else if (r3)
        downlink_mode = ref1of4;

    struct p {
        uint32_t password;
        uint8_t flags;
    } PACKED payload;

    payload.password = password;
    payload.flags = (downlink_mode << 3);

    clearCommandBuffer();
    SendCommandNG(CMD_LF_T55XX_WAKEUP, (uint8_t *)&payload, sizeof(payload));
    if (WaitForResponseTimeout(CMD_LF_T55XX_WAKEUP, NULL, 1000) == false) {
        PrintAndLogEx(WARNING, "command execution time out");
        return PM3_ETIMEOUT;
    }

    if (verbose)
        PrintAndLogEx(SUCCESS, "Wake up command sent. Try read now");

    return PM3_SUCCESS;
}

static int CmdT55xxDetect(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf t55xx detect",
                  "Try detecting the tag modulation from reading the configuration block",
                  "lf t55xx detect\n"
                  "lf t55xx detect -1\n"
                  "lf t55xx detect -p 11223344\n"
                 );

    // 1 (help) + 2 (two user specified params) + (6 T55XX_DLMODE_ALL)
    void *argtable[3 + 6] = {
        arg_param_begin,
        arg_lit0("1", NULL, "extract using data from graphbuffer"),
        arg_str0("p", "pwd", "<hex>", "password (4 hex bytes)"),
    };
    uint8_t idx = 3;
    arg_add_t55xx_downloadlink(argtable, &idx, T55XX_DLMODE_ALL, config.downlink_mode);
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool use_gb = arg_get_lit(ctx, 1);

    bool usepwd = false;
    uint64_t password = -1;
    uint32_t tmp_pwd = 0;
    int res = arg_get_u32_hexstr_def_nlen(ctx, 2, 0, &tmp_pwd, 4, true);
    if (res == 0 || res == 2) {
        PrintAndLogEx(ERR, "Password should be 4 hex bytes");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }
    if (res == 1) {
        usepwd = true;
        password = tmp_pwd;
    }

    bool r0 = arg_get_lit(ctx, 3);
    bool r1 = arg_get_lit(ctx, 4);
    bool r2 = arg_get_lit(ctx, 5);
    bool r3 = arg_get_lit(ctx, 6);
    bool ra = arg_get_lit(ctx, 7);
    CLIParserFree(ctx);

    if ((r0 + r1 + r2 + r3 + ra) > 1) {
        PrintAndLogEx(FAILED, "Error multiple downlink encoding");
        return PM3_EINVARG;
    }

    bool try_all_dl_modes = false;
    uint8_t downlink_mode = config.downlink_mode;
    if (r0)
        downlink_mode = refFixedBit;
    else if (r1)
        downlink_mode = refLongLeading;
    else if (r2)
        downlink_mode = refLeading0;
    else if (r3)
        downlink_mode = ref1of4;
    else // This will set the default to user all d/l modes which will cover the ra flag as well.
        try_all_dl_modes = true;

    bool found = false;

    // Setup the 90ms time value to sleep for after the wake, to allow delay init to complete (~70ms)
    struct timespec sleepperiod;
    sleepperiod.tv_sec = 0;
    sleepperiod.tv_nsec = 90000000;

    // detect called so clear data blocks
    T55x7_ClearAllBlockData();

    // sanity check.
    if (SanityOfflineCheck(use_gb) != PM3_SUCCESS)
        return PM3_ESOFT;

    if (use_gb == false) {

        char wakecmd[20] = { 0x00 };
        snprintf(wakecmd, sizeof(wakecmd), "-p %08" PRIx64, password);

        bool usewake = false;
        bool try_with_pwd = false;
        // do ... while not found and not yet tried with wake (for AOR or Init Delay)
        do {
            // do ... while to check without password then loop back if password supplied
            do {
                if (try_all_dl_modes) {
                    // Loop from 1st d/l mode refFixedBit to the last d/l mode ref1of4
                    for (uint8_t m = refFixedBit; m <= ref1of4; m++) {
                        if (usewake) {
                            // call wake
                            if (try_with_pwd)
                                CmdT55xxWakeUp(wakecmd);
                            else
                                CmdT55xxWakeUp("");
                            // sleep 90 ms
                            nanosleep(&sleepperiod, &sleepperiod);
                        }

                        if (AcquireData(T55x7_PAGE0, T55x7_CONFIGURATION_BLOCK, (try_with_pwd && usepwd), password, m) == false)
                            continue;

                        if (t55xxTryDetectModulationEx(m, T55XX_PrintConfig, 0, (try_with_pwd && usepwd) ? password : -1) == false)
                            continue;

                        found = true;
                        break;
                    }
                } else {
                    if (usewake) {
                        // call wake
                        if (try_with_pwd)
                            CmdT55xxWakeUp(wakecmd);
                        else
                            CmdT55xxWakeUp("");
                        // sleep 90 ms
                        nanosleep(&sleepperiod, &sleepperiod);
                    }

                    if (AcquireData(T55x7_PAGE0, T55x7_CONFIGURATION_BLOCK, usepwd, password, downlink_mode)) {
                        found = t55xxTryDetectModulationEx(downlink_mode, T55XX_PrintConfig, 0, (usepwd) ? password : -1);
                    }
                }

                // toggle so we loop back if not found and try with pwd
                if (found == false && usepwd)
                    try_with_pwd = !try_with_pwd;

                // force exit as detect block has been found
                if (found)
                    try_with_pwd = false;

            } while (try_with_pwd);
            // Toggle so we loop back and try with wakeup.
            usewake = !usewake;
        } while (found == false && usewake);
    } else {
        found = t55xxTryDetectModulation(downlink_mode, T55XX_PrintConfig);
    }

    if (found == false) {
        config.usepwd = false;
        config.pwd = 0x00;
        PrintAndLogEx(WARNING, "Could not detect modulation automatically. Try setting it manually with " _YELLOW_("\'lf t55xx config\'"));
    }

    return PM3_SUCCESS;
}

// detect configuration?
bool t55xxTryDetectModulation(uint8_t downlink_mode, bool print_config) {
    return t55xxTryDetectModulationEx(downlink_mode, print_config, 0, -1);
}

bool t55xxTryDetectModulationEx(uint8_t downlink_mode, bool print_config, uint32_t wanted_conf, uint64_t pwd) {

    t55xx_conf_block_t tests[15];
    int bitRate = 0, clk = 0, firstClockEdge = 0;
    uint8_t hits = 0, fc1 = 0, fc2 = 0, ans = 0;

    ans = fskClocks(&fc1, &fc2, (uint8_t *)&clk, &firstClockEdge);

    if (ans && ((fc1 == 10 && fc2 == 8) || (fc1 == 8 && fc2 == 5))) {
        if ((FSKrawDemod(0, 0, 0, 0, false) == PM3_SUCCESS) && test(DEMOD_FSK, &tests[hits].offset, &bitRate, clk, &tests[hits].Q5)) {
            tests[hits].modulation = DEMOD_FSK;
            if (fc1 == 8 && fc2 == 5)
                tests[hits].modulation = DEMOD_FSK1a;
            else if (fc1 == 10 && fc2 == 8)
                tests[hits].modulation = DEMOD_FSK2;
            tests[hits].bitrate = bitRate;
            tests[hits].inverted = false;
            tests[hits].block0 = PackBits(tests[hits].offset, 32, g_DemodBuffer);
            tests[hits].ST = false;
            tests[hits].downlink_mode = downlink_mode;
            ++hits;
        }
        if ((FSKrawDemod(0, 1, 0, 0, false) == PM3_SUCCESS) && test(DEMOD_FSK, &tests[hits].offset, &bitRate, clk, &tests[hits].Q5)) {
            tests[hits].modulation = DEMOD_FSK;
            if (fc1 == 8 && fc2 == 5)
                tests[hits].modulation = DEMOD_FSK1;
            else if (fc1 == 10 && fc2 == 8)
                tests[hits].modulation = DEMOD_FSK2a;
            tests[hits].bitrate = bitRate;
            tests[hits].inverted = true;
            tests[hits].block0 = PackBits(tests[hits].offset, 32, g_DemodBuffer);
            tests[hits].ST = false;
            tests[hits].downlink_mode = downlink_mode;
            ++hits;
        }
    } else {
        clk = GetAskClock("", false);
        if (clk > 0) {
            tests[hits].ST = true;
            // "0 0 1 " == clock auto, invert false, maxError 1.
            // false = no verbose
            // false = no emSearch
            // 1 = Ask/Man
            // st = true
            if ((ASKDemod_ext(0, 0, 1, 0, false, false, false, 1, &tests[hits].ST) == PM3_SUCCESS) && test(DEMOD_ASK, &tests[hits].offset, &bitRate, clk, &tests[hits].Q5)) {
                tests[hits].modulation = DEMOD_ASK;
                tests[hits].bitrate = bitRate;
                tests[hits].inverted = false;
                tests[hits].block0 = PackBits(tests[hits].offset, 32, g_DemodBuffer);
                tests[hits].downlink_mode = downlink_mode;
                ++hits;
            }
            tests[hits].ST = true;
            // "0 0 1 " == clock auto, invert true, maxError 1.
            // false = no verbose
            // false = no emSearch
            // 1 = Ask/Man
            // st = true
            if ((ASKDemod_ext(0, 1, 1, 0, false, false, false, 1, &tests[hits].ST) == PM3_SUCCESS) && test(DEMOD_ASK, &tests[hits].offset, &bitRate, clk, &tests[hits].Q5)) {
                tests[hits].modulation = DEMOD_ASK;
                tests[hits].bitrate = bitRate;
                tests[hits].inverted = true;
                tests[hits].block0 = PackBits(tests[hits].offset, 32, g_DemodBuffer);
                tests[hits].downlink_mode = downlink_mode;
                ++hits;
            }
            if ((ASKbiphaseDemod(0, 0, 0, 2, false) == PM3_SUCCESS) && test(DEMOD_BI, &tests[hits].offset, &bitRate, clk, &tests[hits].Q5)) {
                tests[hits].modulation = DEMOD_BI;
                tests[hits].bitrate = bitRate;
                tests[hits].inverted = false;
                tests[hits].block0 = PackBits(tests[hits].offset, 32, g_DemodBuffer);
                tests[hits].ST = false;
                tests[hits].downlink_mode = downlink_mode;
                ++hits;
            }
            if ((ASKbiphaseDemod(0, 0, 1, 2, false) == PM3_SUCCESS) && test(DEMOD_BIa, &tests[hits].offset, &bitRate, clk, &tests[hits].Q5)) {
                tests[hits].modulation = DEMOD_BIa;
                tests[hits].bitrate = bitRate;
                tests[hits].inverted = true;
                tests[hits].block0 = PackBits(tests[hits].offset, 32, g_DemodBuffer);
                tests[hits].ST = false;
                tests[hits].downlink_mode = downlink_mode;
                ++hits;
            }
        }
        clk = GetNrzClock("", false);
        if (clk > 8) { //clock of rf/8 is likely a false positive, so don't use it.
            if ((NRZrawDemod(0, 0, 1, false) == PM3_SUCCESS) && test(DEMOD_NRZ, &tests[hits].offset, &bitRate, clk, &tests[hits].Q5)) {
                tests[hits].modulation = DEMOD_NRZ;
                tests[hits].bitrate = bitRate;
                tests[hits].inverted = false;
                tests[hits].block0 = PackBits(tests[hits].offset, 32, g_DemodBuffer);
                tests[hits].ST = false;
                tests[hits].downlink_mode = downlink_mode;
                ++hits;
            }

            if ((NRZrawDemod(0, 1, 1, false) == PM3_SUCCESS) && test(DEMOD_NRZ, &tests[hits].offset, &bitRate, clk, &tests[hits].Q5)) {
                tests[hits].modulation = DEMOD_NRZ;
                tests[hits].bitrate = bitRate;
                tests[hits].inverted = true;
                tests[hits].block0 = PackBits(tests[hits].offset, 32, g_DemodBuffer);
                tests[hits].ST = false;
                tests[hits].downlink_mode = downlink_mode;
                ++hits;
            }
        }

        clk = GetPskClock("", false);
        if (clk > 0) {
            // allow undo
            save_restoreGB(GRAPH_SAVE);
            // skip first 160 samples to allow antenna to settle in (psk gets inverted occasionally otherwise)
            CmdLtrim("-i 160");
            if ((PSKDemod(0, 0, 6, false) == PM3_SUCCESS) && test(DEMOD_PSK1, &tests[hits].offset, &bitRate, clk, &tests[hits].Q5)) {
                tests[hits].modulation = DEMOD_PSK1;
                tests[hits].bitrate = bitRate;
                tests[hits].inverted = false;
                tests[hits].block0 = PackBits(tests[hits].offset, 32, g_DemodBuffer);
                tests[hits].ST = false;
                tests[hits].downlink_mode = downlink_mode;
                ++hits;
            }
            if ((PSKDemod(0, 1, 6, false) == PM3_SUCCESS) && test(DEMOD_PSK1, &tests[hits].offset, &bitRate, clk, &tests[hits].Q5)) {
                tests[hits].modulation = DEMOD_PSK1;
                tests[hits].bitrate = bitRate;
                tests[hits].inverted = true;
                tests[hits].block0 = PackBits(tests[hits].offset, 32, g_DemodBuffer);
                tests[hits].ST = false;
                tests[hits].downlink_mode = downlink_mode;
                ++hits;
            }
            //ICEMAN: are these PSKDemod calls needed?
            // PSK2 - needs a call to psk1TOpsk2.
            if (PSKDemod(0, 0, 6, false) == PM3_SUCCESS) {
                psk1TOpsk2(g_DemodBuffer, g_DemodBufferLen);
                if (test(DEMOD_PSK2, &tests[hits].offset, &bitRate, clk, &tests[hits].Q5)) {
                    tests[hits].modulation = DEMOD_PSK2;
                    tests[hits].bitrate = bitRate;
                    tests[hits].inverted = false;
                    tests[hits].block0 = PackBits(tests[hits].offset, 32, g_DemodBuffer);
                    tests[hits].ST = false;
                    tests[hits].downlink_mode = downlink_mode;
                    ++hits;
                }
            } // inverse waves does not affect this demod
            // PSK3 - needs a call to psk1TOpsk2.
            if (PSKDemod(0, 0, 6, false) == PM3_SUCCESS) {
                psk1TOpsk2(g_DemodBuffer, g_DemodBufferLen);
                if (test(DEMOD_PSK3, &tests[hits].offset, &bitRate, clk, &tests[hits].Q5)) {
                    tests[hits].modulation = DEMOD_PSK3;
                    tests[hits].bitrate = bitRate;
                    tests[hits].inverted = false;
                    tests[hits].block0 = PackBits(tests[hits].offset, 32, g_DemodBuffer);
                    tests[hits].ST = false;
                    tests[hits].downlink_mode = downlink_mode;
                    ++hits;
                }
            } // inverse waves does not affect this demod
            //undo trim samples
            save_restoreGB(GRAPH_RESTORE);
        }
    }
    if (hits == 1) {
        config.modulation = tests[0].modulation;
        config.bitrate = tests[0].bitrate;
        config.inverted = tests[0].inverted;
        config.offset = tests[0].offset;
        config.block0 = tests[0].block0;
        config.Q5 = tests[0].Q5;
        config.ST = tests[0].ST;
        config.downlink_mode = downlink_mode;
        if (pwd != -1) {
            config.usepwd = true;
            config.pwd = pwd & 0xffffffff;
        }

        config.block0Status = AUTODETECT;
        if (print_config)
            printConfiguration(config);

        return true;
    }

    bool retval = false;
    if (hits > 1) {
        PrintAndLogEx(SUCCESS, "Found [%d] possible matches for modulation.", hits);
        for (int i = 0; i < hits; ++i) {

            bool wanted = false;
            if (wanted_conf > 0)
                wanted = (wanted_conf == tests[i].block0);

            retval = testKnownConfigBlock(tests[i].block0);
            if (retval || wanted) {
                PrintAndLogEx(NORMAL, "--[%d]--------------- << selected this", i + 1);
                config.modulation = tests[i].modulation;
                config.bitrate = tests[i].bitrate;
                config.inverted = tests[i].inverted;
                config.offset = tests[i].offset;
                config.block0 = tests[i].block0;
                config.Q5 = tests[i].Q5;
                config.ST = tests[i].ST;
                config.downlink_mode = tests[i].downlink_mode;

                if (pwd != -1) {
                    config.usepwd = true;
                    config.pwd = pwd & 0xffffffff;
                }
            } else {
                PrintAndLogEx(NORMAL, "--[%d]---------------", i + 1);
            }

            config.block0Status = AUTODETECT;
            if (print_config)
                printConfiguration(tests[i]);
        }
    }
    return retval;
}

bool testKnownConfigBlock(uint32_t block0) {
    switch (block0) {
        case T55X7_DEFAULT_CONFIG_BLOCK:
        case T55X7_RAW_CONFIG_BLOCK:
        case T55X7_EM_UNIQUE_CONFIG_BLOCK:
        case T55X7_FDXB_CONFIG_BLOCK:
        case T55X7_FDXB_2_CONFIG_BLOCK:
        case T55X7_HID_26_CONFIG_BLOCK:
        case T55X7_PYRAMID_CONFIG_BLOCK:
        case T55X7_INDALA_64_CONFIG_BLOCK:
        case T55X7_INDALA_224_CONFIG_BLOCK:
        case T55X7_GUARDPROXII_CONFIG_BLOCK:
        case T55X7_VIKING_CONFIG_BLOCK:
        case T55X7_NORALSY_CONFIG_BLOCK:
        case T55X7_IOPROX_CONFIG_BLOCK:
        case T55X7_PRESCO_CONFIG_BLOCK:
        case T55X7_NEDAP_64_CONFIG_BLOCK:
        case T55X7_NEDAP_128_CONFIG_BLOCK:
        case T55X7_VISA2000_CONFIG_BLOCK:
        case T55X7_SECURAKEY_CONFIG_BLOCK:
        case T55X7_PAC_CONFIG_BLOCK:
        case T55X7_VERICHIP_CONFIG_BLOCK:
        case T55X7_KERI_CONFIG_BLOCK:
        case T55X7_NEXWATCH_CONFIG_BLOCK:
        case T55X7_JABLOTRON_CONFIG_BLOCK:
            return true;
    }
    return false;
}

bool GetT55xxBlockData(uint32_t *blockdata) {

    if (g_DemodBufferLen == 0)
        return false;

    uint8_t idx = config.offset;

    if (idx + 32 > g_DemodBufferLen) {
        PrintAndLogEx(WARNING, "The configured offset %d is too big. Possible offset: %zu)", idx, g_DemodBufferLen - 32);
        return false;
    }

    *blockdata = PackBits(0, 32, g_DemodBuffer + idx);
    return true;
}

void printT55xxBlock(uint8_t blockNum, bool page1) {

    uint32_t val = 0;
    if (GetT55xxBlockData(&val) == false)
        return;

    uint8_t bytes[4] = {0};
    num_to_bytes(val, 4, bytes);

    T55x7_SaveBlockData((page1) ? blockNum + 8 : blockNum, val);

    PrintAndLogEx(SUCCESS, " %02d | %08X | %s | %s", blockNum, val, sprint_bytebits_bin(g_DemodBuffer + config.offset, 32), sprint_ascii(bytes, 4));
}

static bool testModulation(uint8_t mode, uint8_t modread) {
    switch (mode) {
        case DEMOD_FSK:
            if (modread >= DEMOD_FSK1 && modread <= DEMOD_FSK2a) return true;
            break;
        case DEMOD_ASK:
            if (modread == DEMOD_ASK) return true;
            break;
        case DEMOD_PSK1:
            if (modread == DEMOD_PSK1) return true;
            break;
        case DEMOD_PSK2:
            if (modread == DEMOD_PSK2) return true;
            break;
        case DEMOD_PSK3:
            if (modread == DEMOD_PSK3) return true;
            break;
        case DEMOD_NRZ:
            if (modread == DEMOD_NRZ) return true;
            break;
        case DEMOD_BI:
            if (modread == DEMOD_BI) return true;
            break;
        case DEMOD_BIa:
            if (modread == DEMOD_BIa) return true;
            break;
        default:
            return false;
    }
    return false;
}

static bool testQ5Modulation(uint8_t mode, uint8_t modread) {
    switch (mode) {
        case DEMOD_FSK:
            if (modread >= 4 && modread <= 5) return true;
            break;
        case DEMOD_ASK:
            if (modread == 0) return true;
            break;
        case DEMOD_PSK1:
            if (modread == 1) return true;
            break;
        case DEMOD_PSK2:
            if (modread == 2) return true;
            break;
        case DEMOD_PSK3:
            if (modread == 3) return true;
            break;
        case DEMOD_NRZ:
            if (modread == 7) return true;
            break;
        case DEMOD_BI:
            if (modread == 6) return true;
            break;
        default:
            return false;
    }
    return false;
}

static int convertQ5bitRate(uint8_t bitRateRead) {
    const uint8_t expected[] = {8, 16, 32, 40, 50, 64, 100, 128};
    for (int i = 0; i < 8; i++)
        if (expected[i] == bitRateRead)
            return i;

    return -1;
}

static bool testQ5(uint8_t mode, uint8_t *offset, int *fndBitRate, uint8_t clk) {

    if (g_DemodBufferLen < 64) return false;

    for (uint8_t idx = 28; idx < 64; idx++) {
        uint8_t si = idx;
        if (PackBits(si, 28, g_DemodBuffer) == 0x00) continue;

        uint8_t safer     = PackBits(si, 4, g_DemodBuffer);
        si += 4;     //master key
        uint8_t resv      = PackBits(si, 8, g_DemodBuffer);
        si += 8;
        // 2nibble must be zeroed.
        if (safer != 0x6 && safer != 0x9) continue;
        if (resv > 0x00) continue;
        //uint8_t pageSel   = PackBits(si, 1, g_DemodBuffer); si += 1;
        //uint8_t fastWrite = PackBits(si, 1, g_DemodBuffer); si += 1;
        si += 1 + 1;
        int bitRate       = PackBits(si, 6, g_DemodBuffer) * 2 + 2;
        si += 6;     //bit rate
        if (bitRate > 128 || bitRate < 8) continue;

        //uint8_t AOR       = PackBits(si, 1, g_DemodBuffer); si += 1;
        //uint8_t PWD       = PackBits(si, 1, g_DemodBuffer); si += 1;
        //uint8_t pskcr     = PackBits(si, 2, g_DemodBuffer); si += 2;  //could check psk cr
        //uint8_t inverse   = PackBits(si, 1, g_DemodBuffer); si += 1;
        si += 1 + 1 + 2 + 1;
        uint8_t modread   = PackBits(si, 3, g_DemodBuffer);
        si += 3;
        uint8_t maxBlk    = PackBits(si, 3, g_DemodBuffer);
        si += 3;
        //uint8_t ST        = PackBits(si, 1, g_DemodBuffer); si += 1;
        if (maxBlk == 0) continue;

        //test modulation
        if (!testQ5Modulation(mode, modread)) continue;
        if (bitRate != clk) continue;

        *fndBitRate = convertQ5bitRate(bitRate);
        if (*fndBitRate < 0) continue;

        *offset = idx;

        return true;
    }
    return false;
}

static bool testBitRate(uint8_t readRate, uint8_t clk) {
    const uint8_t expected[] = {8, 16, 32, 40, 50, 64, 100, 128};
    if (expected[readRate] == clk)
        return true;

    return false;
}

bool test(uint8_t mode, uint8_t *offset, int *fndBitRate, uint8_t clk, bool *Q5) {

    if (g_DemodBufferLen < 64) return false;
    for (uint8_t idx = 28; idx < 64; idx++) {
        uint8_t si = idx;
        if (PackBits(si, 28, g_DemodBuffer) == 0x00) continue;

        uint8_t safer    = PackBits(si, 4, g_DemodBuffer);
        si += 4;     //master key
        uint8_t resv     = PackBits(si, 4, g_DemodBuffer);
        si += 4;     //was 7 & +=7+3 //should be only 4 bits if extended mode
        // 2nibble must be zeroed.
        // moved test to here, since this gets most faults first.
        if (resv > 0x00) continue;

        int bitRate      = PackBits(si, 6, g_DemodBuffer);
        si += 6;     //bit rate (includes extended mode part of rate)
        uint8_t extend   = PackBits(si, 1, g_DemodBuffer);
        si += 1;     //bit 15 extended mode
        uint8_t modread  = PackBits(si, 5, g_DemodBuffer);
        si += 5 + 2 + 1;
        //uint8_t pskcr   = PackBits(si, 2, g_DemodBuffer); si += 2+1;  //could check psk cr
        //uint8_t nml01    = PackBits(si, 1, g_DemodBuffer); si += 1+5;   //bit 24, 30, 31 could be tested for 0 if not extended mode
        //uint8_t nml02    = PackBits(si, 2, g_DemodBuffer); si += 2;

        //if extended mode
        bool extMode = ((safer == 0x6 || safer == 0x9) && extend) ? true : false;

        if (!extMode) {
            if (bitRate > 7) continue;
            if (!testBitRate(bitRate, clk)) continue;
        } else { //extended mode bitrate = same function to calc bitrate as em4x05
            if (EM4x05_GET_BITRATE(bitRate) != clk) continue;

        }
        //test modulation
        if (!testModulation(mode, modread)) continue;
        *fndBitRate = bitRate;
        *offset = idx;
        *Q5 = false;
        return true;
    }
    if (testQ5(mode, offset, fndBitRate, clk)) {
        *Q5 = true;
        return true;
    }
    return false;
}

int CmdT55xxSpecial(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf t55xx special",
                  "Show block changes with 64 different offsets,  data taken from DemodBuffer.",
                  "lf t55xx special\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);

    uint8_t bits[32] = {0x00};

    PrintAndLogEx(NORMAL, "OFFSET | DATA  | BINARY                              | ASCII");
    PrintAndLogEx(NORMAL, "-------+-------+-------------------------------------+------");
    int i, j = 0;
    for (; j < 64; ++j) {

        for (i = 0; i < 32; ++i)
            bits[i] = g_DemodBuffer[j + i];

        uint32_t blockData = PackBits(0, 32, bits);

        PrintAndLogEx(NORMAL, "%02d | 0x%08X | %s", j, blockData, sprint_bytebits_bin(bits, 32));
    }
    return PM3_SUCCESS;
}

int printConfiguration(t55xx_conf_block_t b) {
    PrintAndLogEx(INFO, " Chip type......... " _GREEN_("%s"), (b.Q5) ? "Q5/T5555" : "T55x7");
    PrintAndLogEx(INFO, " Modulation........ " _GREEN_("%s"), GetSelectedModulationStr(b.modulation));
    PrintAndLogEx(INFO, " Bit rate.......... %s", GetBitRateStr(b.bitrate, (b.block0 & T55x7_X_MODE && (b.block0 >> 28 == 6 || b.block0 >> 28 == 9))));
    PrintAndLogEx(INFO, " Inverted.......... %s", (b.inverted) ? _GREEN_("Yes") : "No");
    PrintAndLogEx(INFO, " Offset............ %d", b.offset);
    PrintAndLogEx(INFO, " Seq. terminator... %s", (b.ST) ? _GREEN_("Yes") : "No");
    PrintAndLogEx(INFO, " Block0............ %08X %s", b.block0, GetConfigBlock0Source(b.block0Status));
    PrintAndLogEx(INFO, " Downlink mode..... %s", GetDownlinkModeStr(b.downlink_mode));
    PrintAndLogEx(INFO, " Password set...... %s", (b.usepwd) ? _RED_("Yes") : _GREEN_("No"));
    if (b.usepwd) {
        PrintAndLogEx(INFO, " Password.......... %08X", b.pwd);
    }
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}

static int CmdT55xxWriteBlock(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf t55xx write",
                  "Write T55xx block data",
                  "lf t55xx write -b 3 -d 11223344                         --> write 11223344 to block 3\n"
                  "lf t55xx write -b 3 -d 11223344 --pwd 01020304          --> write 11223344 to block 3, pwd 01020304\n"
                  "lf t55xx write -b 3 -d 11223344 --pwd 01020304 --verify --> write 11223344 to block 3 and try validating write"
                 );

    // 1 (help) + 6 (six user specified params) + (5 T55XX_DLMODE_SINGLE)
    void *argtable[7 + 5] = {
        arg_param_begin,
        arg_int1("b", "blk", "<0-7>", "block number to write"),
        arg_str0("d", "data", "<hex>", "data to write (4 hex bytes)"),
        arg_str0("p", "pwd", "<hex>", "password (4 hex bytes)"),
        arg_lit0("t", "tm", "test mode write ( " _RED_("danger") " )"),
        arg_lit0(NULL, "pg1", "write page 1"),
        arg_lit0(NULL, "verify", "try validate data afterward"),
    };
    uint8_t idx = 7;
    arg_add_t55xx_downloadlink(argtable, &idx, T55XX_DLMODE_SINGLE, config.downlink_mode);
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int block = arg_get_int_def(ctx, 1, REGULAR_READ_MODE_BLOCK);

    uint32_t data = 0; // default to blank Block
    int res = arg_get_u32_hexstr_def_nlen(ctx, 2, 0, &data, 4, true);
    if (res == 0 || res == 2) {
        PrintAndLogEx(ERR, "data must be 4 hex bytes");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    bool usepwd = false;
    uint32_t password = 0; // default to blank Block 7
    res = arg_get_u32_hexstr_def_nlen(ctx, 3, 0, &password, 4, true);
    if (res == 0 || res == 2) {
        PrintAndLogEx(ERR, "Password should be 4 hex bytes");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }
    if (res == 1) {
        usepwd = true;
    }

    bool testmode = arg_get_lit(ctx, 4);
    bool page1 = arg_get_lit(ctx, 5);
    bool validate = arg_get_lit(ctx, 6);

    bool r0 = arg_get_lit(ctx, 7);
    bool r1 = arg_get_lit(ctx, 8);
    bool r2 = arg_get_lit(ctx, 9);
    bool r3 = arg_get_lit(ctx, 10);
    CLIParserFree(ctx);

    if ((r0 + r1 + r2 + r3) > 1) {
        PrintAndLogEx(FAILED, "Error multiple downlink encoding");
        return PM3_EINVARG;
    }

    uint8_t downlink_mode = config.downlink_mode;
    if (r0)
        downlink_mode = refFixedBit;
    else if (r1)
        downlink_mode = refLongLeading;
    else if (r2)
        downlink_mode = refLeading0;
    else if (r3)
        downlink_mode = ref1of4;

    if (block > 7 && block != REGULAR_READ_MODE_BLOCK) {
        PrintAndLogEx(NORMAL, "Block must be between 0 and 7");
        return PM3_ESOFT;
    }

    char pwdstr[16] = {0};
    snprintf(pwdstr, sizeof(pwdstr), "pwd: 0x%08X", password);

    PrintAndLogEx(INFO, "Writing page %d  block: %02d  data: 0x%08X %s", page1, block, data, (usepwd) ? pwdstr : "");

    if (t55xxWrite(block, page1, usepwd, testmode, password, downlink_mode, data) != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Write failed");
        return PM3_ESOFT;
    }

    if (validate) {
        bool isOK = t55xxVerifyWrite(block, page1, usepwd, 1, password, downlink_mode, data);
        if (isOK)
            PrintAndLogEx(SUCCESS, "Write OK, validation successful");
        else
            PrintAndLogEx(WARNING, "Write could not validate the written data");
    }

    return PM3_SUCCESS;
}

static int CmdT55xxDangerousRaw(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf t55xx dangerraw",
                  "This command allows to emit arbitrary raw commands on T5577 and cut the field after arbitrary duration.\n"
                  "Uncontrolled usage can easily write an invalid configuration, activate lock bits,\n"
                  "OTP bit, password protection bit, deactivate test-mode, lock your card forever.\n"
                  _RED_("WARNING:") _CYAN_(" this may lock definitively the tag in an unusable state!"),
                  "lf t55xx dangerraw -d 01000000000000010000100000000100000000 -t 3200\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1("d", "data", NULL, "raw bit string"),
        arg_int1("t", "time", "<us>", "<0 - 200000> time in microseconds before dropping the field"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    // supports only default downlink mode
    t55xx_test_block_t ng;
    ng.time = 0;
    ng.bitlen = 0;
    memset(ng.data, 0x00, sizeof(ng.data));

    int bin_len = 127;
    uint8_t bin[128] = {0};
    CLIGetStrWithReturn(ctx, 1, bin, &bin_len);

    ng.time = arg_get_int_def(ctx, 2, 0);
    CLIParserFree(ctx);

    if (ng.time == 0 || ng.time > 200000) {
        PrintAndLogEx(ERR, "Timing off 1..200000 limits, got %i", ng.time);
        return PM3_EINVARG;
    }

    int bs_len = binstring2binarray(ng.data, (char *)bin, bin_len);
    if (bs_len == 0) {
        return PM3_EINVARG;
    }

    ng.bitlen = bs_len;

    PacketResponseNG resp;
    clearCommandBuffer();
    SendCommandNG(CMD_LF_T55XX_DANGERRAW, (uint8_t *)&ng, sizeof(ng));
    if (!WaitForResponseTimeout(CMD_LF_T55XX_DANGERRAW, &resp, 2000)) {
        PrintAndLogEx(ERR, "Error occurred, device did not ACK write operation.");
        return PM3_ETIMEOUT;
    }
    return resp.status;
}

static int CmdT55xxReadTrace(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf t55xx trace",
                  "Show T55x7 configuration data (page 0/ blk 0) from reading the configuration block",
                  "lf t55xx trace\n"
                  "lf t55xx trace -1"
                 );

    // 1 (help) + 1 (one user specified params) + (5 T55XX_DLMODE_SINGLE)
    void *argtable[2 + 5] = {
        arg_param_begin,
        arg_lit0("1", NULL, "extract using data from graphbuffer"),
    };
    uint8_t idx = 2;
    arg_add_t55xx_downloadlink(argtable, &idx, T55XX_DLMODE_SINGLE, config.downlink_mode);
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool use_gb = arg_get_lit(ctx, 1);

    bool r0 = arg_get_lit(ctx, 2);
    bool r1 = arg_get_lit(ctx, 3);
    bool r2 = arg_get_lit(ctx, 4);
    bool r3 = arg_get_lit(ctx, 5);
    CLIParserFree(ctx);

    if ((r0 + r1 + r2 + r3) > 1) {
        PrintAndLogEx(FAILED, "Error multiple downlink encoding");
        return PM3_EINVARG;
    }

    uint8_t downlink_mode = config.downlink_mode;
    if (r0)
        downlink_mode = refFixedBit;
    else if (r1)
        downlink_mode = refLongLeading;
    else if (r2)
        downlink_mode = refLeading0;
    else if (r3)
        downlink_mode = ref1of4;

    if (use_gb == false) {
        // sanity check.
        if (SanityOfflineCheck(false) != PM3_SUCCESS) return PM3_ENODATA;

        bool pwdmode = false;
        uint32_t password = 0;

        // REGULAR_READ_MODE_BLOCK - yields correct Page 1 Block 2 data i.e. + 32 bit offset.
        if (!AcquireData(T55x7_PAGE1, REGULAR_READ_MODE_BLOCK, pwdmode, password, downlink_mode))
            return PM3_ENODATA;
    }

    if (config.Q5) {
        if (DecodeT5555TraceBlock() == false) {
            return PM3_ESOFT;
        }
    } else {
        if (DecodeT55xxBlock() == false) {
            return PM3_ESOFT;
        }
    }

    if (g_DemodBufferLen == 0) {
        return PM3_ESOFT;
    }

    RepaintGraphWindow();
    uint8_t repeat = (config.offset > 5) ? 32 : 0;

    uint8_t si = config.offset + repeat;
    uint32_t bl1 = PackBits(si, 32, g_DemodBuffer);
    uint32_t bl2 = PackBits(si + 32, 32, g_DemodBuffer);

    if (config.Q5) {
        uint32_t hdr = PackBits(si, 9,  g_DemodBuffer);
        si += 9;

        if (hdr != 0x1FF) {
            PrintAndLogEx(FAILED, "Invalid Q5/T5555 Trace data header (expected 0x1FF, found %X)", hdr);
            return PM3_ESOFT;
        }

        t5555_tracedata_t data = {.bl1 = bl1, .bl2 = bl2, .icr = 0, .lotidc = '?', .lotid = 0, .wafer = 0, .dw = 0};

        data.icr     = PackBits(si, 2,  g_DemodBuffer);
        si += 2;
        data.lotidc  = 'Z' - PackBits(si, 2,  g_DemodBuffer);
        si += 3;

        data.lotid   = PackBits(si, 4,  g_DemodBuffer);
        si += 5;
        data.lotid <<= 4;
        data.lotid  |= PackBits(si, 4,  g_DemodBuffer);
        si += 5;
        data.lotid <<= 4;
        data.lotid  |= PackBits(si, 4,  g_DemodBuffer);
        si += 5;
        data.lotid <<= 4;
        data.lotid  |= PackBits(si, 4,  g_DemodBuffer);
        si += 5;
        data.lotid <<= 1;
        data.lotid  |= PackBits(si, 1,  g_DemodBuffer);
        si += 1;

        data.wafer   = PackBits(si, 3,  g_DemodBuffer);
        si += 4;
        data.wafer <<= 2;
        data.wafer  |= PackBits(si, 2,  g_DemodBuffer);
        si += 2;

        data.dw      = PackBits(si, 2,  g_DemodBuffer);
        si += 3;
        data.dw    <<= 4;
        data.dw     |= PackBits(si, 4,  g_DemodBuffer);
        si += 5;
        data.dw    <<= 4;
        data.dw     |= PackBits(si, 4,  g_DemodBuffer);
        si += 5;
        data.dw    <<= 4;
        data.dw     |= PackBits(si, 4,  g_DemodBuffer);

        printT5555Trace(data, repeat);

    } else {

        t55x7_tracedata_t data = {.bl1 = bl1, .bl2 = bl2, .acl = 0, .mfc = 0, .cid = 0, .year = 0, .quarter = 0, .icr = 0,  .lotid = 0, .wafer = 0, .dw = 0};

        data.acl = PackBits(si, 8,  g_DemodBuffer);
        si += 8;
        if (data.acl != 0xE0) {
            PrintAndLogEx(FAILED, "The modulation is most likely wrong since the ACL is not 0xE0. ");
            return PM3_ESOFT;
        }

        data.mfc     = PackBits(si, 8,  g_DemodBuffer);
        si += 8;
        data.cid     = PackBits(si, 5,  g_DemodBuffer);
        si += 5;
        data.icr     = PackBits(si, 3,  g_DemodBuffer);
        si += 3;
        data.year    = PackBits(si, 4,  g_DemodBuffer);
        si += 4;
        data.quarter = PackBits(si, 2,  g_DemodBuffer);
        si += 2;
        data.lotid   = PackBits(si, 14, g_DemodBuffer);
        si += 14;
        data.wafer   = PackBits(si, 5,  g_DemodBuffer);
        si += 5;
        data.dw      = PackBits(si, 15, g_DemodBuffer);

        struct tm *ct, tm_buf;
        time_t now = time(NULL);
#if defined(_WIN32)
        ct = localtime_s(&tm_buf, &now) == 0 ? &tm_buf : NULL;
#else
        ct = localtime_r(&now, &tm_buf);
#endif

        if (data.year > ct->tm_year - 110)
            data.year += 2000;
        else
            data.year += 2010;

        printT55x7Trace(data, repeat);
    }
    return PM3_SUCCESS;
}

void printT55x7Trace(t55x7_tracedata_t data, uint8_t repeat) {
    PrintAndLogEx(INFO, "--- " _CYAN_("T55x7 Trace Information") " ----------------------------------");
    PrintAndLogEx(INFO, " ACL Allocation class (ISO/IEC 15963-1)  : 0x%02X ( %d )", data.acl, data.acl);
    PrintAndLogEx(INFO, " MFC Manufacturer ID (ISO/IEC 7816-6)    : 0x%02X ( %d ) - %s", data.mfc, data.mfc, getTagInfo(data.mfc));
    PrintAndLogEx(INFO, " CID                                     : 0x%02X ( %d ) - %s", data.cid, data.cid, GetModelStrFromCID(data.cid));
    PrintAndLogEx(INFO, " ICR IC Revision                         : %d", data.icr);
    PrintAndLogEx(INFO, " Manufactured");
    PrintAndLogEx(INFO, "     Year/Quarter... %d/%d", data.year, data.quarter);
    PrintAndLogEx(INFO, "     Lot ID......... %d", data.lotid);
    PrintAndLogEx(INFO, "     Wafer number... %d", data.wafer);
    PrintAndLogEx(INFO, "     Die Number..... %d", data.dw);
    PrintAndLogEx(INFO, "-------------------------------------------------------------");
    PrintAndLogEx(INFO, " Raw Data - Page 1");
    PrintAndLogEx(INFO, "     Block 1... %08X - %s", data.bl1, sprint_bytebits_bin(g_DemodBuffer + config.offset + repeat, 32));
    PrintAndLogEx(INFO, "     Block 2... %08X - %s", data.bl2, sprint_bytebits_bin(g_DemodBuffer + config.offset + repeat + 32, 32));
    PrintAndLogEx(NORMAL, "");

    /*
    Trace info.
      M1, M2  has the about ATMEL definition of trace data.
      M3 has unique format following industry defacto standard with row/col parity

    TRACE - BLOCK O
        Bits    Definition                             HEX
        1-8     ACL Allocation class (ISO/IEC 15963-1) 0xE0
        9-16    MFC Manufacturer ID (ISO/IEC 7816-6)   0x15 Atmel Corporation
        17-21   CID                                    0x1 = Atmel ATA5577M1
                                                       0x2 = Atmel ATA5577M2
                                                       0x3 = Atmel ATA5577M3
        22-24   ICR IC revision
        25-28   YEAR (BCD encoded)                     9 (= 2009)
        29-30   QUARTER                                1,2,3,4
        31-32   LOT ID

    TRACE - BLOCK 1
        1-12    LOT ID
        13-17   Wafer number
        18-32   DW,  die number sequential


    Startup times (FC)
      M1, M2 = 192
      M3     = 128
    */
}

void printT5555Trace(t5555_tracedata_t data, uint8_t repeat) {
    PrintAndLogEx(INFO, "--- " _CYAN_("Q5/T5555 Trace Information") " ---------------------------");
    PrintAndLogEx(INFO, " ICR IC Revision.... %d", data.icr);
    PrintAndLogEx(INFO, "     Lot ID......... %c%d", data.lotidc, data.lotid);
    PrintAndLogEx(INFO, "     Wafer number... %d", data.wafer);
    PrintAndLogEx(INFO, "     Die Number..... %d", data.dw);
    PrintAndLogEx(INFO, "-------------------------------------------------------------");
    PrintAndLogEx(INFO, " Raw Data - Page 1");
    PrintAndLogEx(INFO, "     Block 1... %08X - %s", data.bl1, sprint_bytebits_bin(g_DemodBuffer + config.offset + repeat, 32));
    PrintAndLogEx(INFO, "     Block 2... %08X - %s", data.bl2, sprint_bytebits_bin(g_DemodBuffer + config.offset + repeat + 32, 32));

    /*
        ** Q5 **
        TRACE - BLOCK O and BLOCK1
        Bits  Definition                HEX
        1-9   Header                  0x1FF
        10-11 IC Revision
        12-13 Lot ID char
        15-35 Lot ID (NB parity)
        36-41 Wafer number (NB parity)
        42-58 DW, die number sequential (NB parity)
        60-63 Parity bits
        64    Always zero
    */
}

static void printT5x7KnownBlock0(uint32_t b0) {

    char s[40];
    memset(s, 0, sizeof(s));

    switch (b0) {
        case T55X7_DEFAULT_CONFIG_BLOCK:
            snprintf(s, sizeof(s) - strlen(s), "T55x7 Default ");
            break;
        case T55X7_RAW_CONFIG_BLOCK:
            snprintf(s + strlen(s), sizeof(s) - strlen(s), "T55x7 Raw ");
            break;
        case T55X7_EM_UNIQUE_CONFIG_BLOCK:
            snprintf(s + strlen(s), sizeof(s) - strlen(s), "EM unique, Paxton ");
            break;
        case T55X7_FDXB_2_CONFIG_BLOCK:
        case T55X7_FDXB_CONFIG_BLOCK:
            snprintf(s + strlen(s), sizeof(s) - strlen(s), "FDXB ");
            break;
        case T55X7_HID_26_CONFIG_BLOCK:
            snprintf(s + strlen(s), sizeof(s) - strlen(s), "HID 26b (ProxCard), Paradox, AWID ");
            break;
        case T55X7_PYRAMID_CONFIG_BLOCK:
            snprintf(s + strlen(s), sizeof(s) - strlen(s), "Pyramid ");
            break;
        case T55X7_INDALA_64_CONFIG_BLOCK:
            snprintf(s + strlen(s), sizeof(s) - strlen(s), "Indala 64, Motorola, Idteck");
            break;
        case T55X7_INDALA_224_CONFIG_BLOCK:
            snprintf(s + strlen(s), sizeof(s) - strlen(s), "Indala 224 ");
            break;
        case T55X7_GUARDPROXII_CONFIG_BLOCK:
            snprintf(s + strlen(s), sizeof(s) - strlen(s), "Guard Prox II ");
            break;
        case T55X7_VIKING_CONFIG_BLOCK:
            snprintf(s + strlen(s), sizeof(s) - strlen(s), "Viking ");
            break;
        case T55X7_NORALSY_CONFIG_BLOCK:
            snprintf(s + strlen(s), sizeof(s) - strlen(s), "Noralys ");
            break;
        case T55X7_IOPROX_CONFIG_BLOCK:
            snprintf(s + strlen(s), sizeof(s) - strlen(s), "IO Prox ");
            break;
        case T55X7_PRESCO_CONFIG_BLOCK:
            snprintf(s + strlen(s), sizeof(s) - strlen(s), "Presco ");
            break;
        case T55X7_NEDAP_64_CONFIG_BLOCK:
            snprintf(s + strlen(s), sizeof(s) - strlen(s), "Nedap 64 ");
            break;
        case T55X7_NEDAP_128_CONFIG_BLOCK:
            snprintf(s + strlen(s), sizeof(s) - strlen(s), "Nedap 128 ");
            break;
        case T55X7_PAC_CONFIG_BLOCK:
            snprintf(s + strlen(s), sizeof(s) - strlen(s), "PAC/Stanley ");
            break;
        case T55X7_VERICHIP_CONFIG_BLOCK:
            snprintf(s + strlen(s), sizeof(s) - strlen(s), "Verichip ");
            break;
        case T55X7_VISA2000_CONFIG_BLOCK:
            snprintf(s + strlen(s), sizeof(s) - strlen(s), "VISA2000 ");
            break;
        case T55X7_JABLOTRON_CONFIG_BLOCK:
            snprintf(s + strlen(s), sizeof(s) - strlen(s), "Jablotron ");
            break;
        case T55X7_KERI_CONFIG_BLOCK:
            snprintf(s + strlen(s), sizeof(s) - strlen(s), "KERI ");
            break;
        case T55X7_SECURAKEY_CONFIG_BLOCK:
            snprintf(s + strlen(s), sizeof(s) - strlen(s), "SecuraKey ");
            break;
        case T55X7_NEXWATCH_CONFIG_BLOCK:
            snprintf(s + strlen(s), sizeof(s) - strlen(s), "NexWatch, Quadrakey ");
            break;
        default:
            break;
    }

    if (strlen(s) > 0) {
        PrintAndLogEx(SUCCESS, "Config block match        : " _YELLOW_("%s"), s);
    }
}

static int CmdT55xxInfo(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf t55xx info",
                  "Show T55x7 configuration data (page 0/ blk 0) from reading the configuration block\n"
                  "from tag. Use `-c` to specify a config block data to be used instead of reading tag.",
                  "lf t55xx info\n"
                  "lf t55xx info -1\n"
                  "lf t55xx info -p 11223344\n"
                  "lf t55xx info -c 00083040\n"
                  "lf t55xx info -c 6001805A --q5"
                 );

    // 1 (help) + 4 (four user specified params) + (5 T55XX_DLMODE_SINGLE)
    void *argtable[5 + 5] = {
        arg_param_begin,
        arg_lit0("1", NULL, "extract using data from graphbuffer"),
        arg_str0("p", "pwd", "<hex>", "password (4 hex bytes)"),
        arg_str0("c", "blk0", "<hex>", "use these data instead (4 hex bytes)"),
        arg_lit0(NULL, "q5", "interprete provided data as T5555/Q5 config"),
    };
    uint8_t idx = 5;
    arg_add_t55xx_downloadlink(argtable, &idx, T55XX_DLMODE_SINGLE, config.downlink_mode);
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool use_gb = arg_get_lit(ctx, 1);

    bool usepwd = false;
    uint32_t password = 0;
    int res = arg_get_u32_hexstr_def_nlen(ctx, 2, 0, &password, 4, true);
    if (res == 0 || res == 2) {
        PrintAndLogEx(ERR, "Password must be 4 hex bytes");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }
    if (res == 1) {
        usepwd = true;
    }

    bool gotdata = false;
    uint32_t block0 = 0;
    res = arg_get_u32_hexstr_def_nlen(ctx, 3, 0, &block0, 4, true);
    if (res == 0 || res == 2) {
        PrintAndLogEx(ERR, "block0 data must be 4 hex bytes");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }
    if (res == 1) {
        gotdata = true;
    }

    bool dataasq5 = arg_get_lit(ctx, 4);

    bool r0 = arg_get_lit(ctx, 5);
    bool r1 = arg_get_lit(ctx, 6);
    bool r2 = arg_get_lit(ctx, 7);
    bool r3 = arg_get_lit(ctx, 8);
    CLIParserFree(ctx);

    if (gotdata && use_gb) {
        PrintAndLogEx(FAILED, "Must select one of user supplied data and use graphbuffer");
        return PM3_EINVARG;
    }

    if (dataasq5 && gotdata == false) {
        PrintAndLogEx(FAILED, "Must specify user supplied Q5 data");
        return PM3_EINVARG;
    }

    if ((r0 + r1 + r2 + r3) > 1) {
        PrintAndLogEx(FAILED, "Error multiple downlink encoding");
        return PM3_EINVARG;
    }

    uint8_t downlink_mode = config.downlink_mode;
    if (r0)
        downlink_mode = refFixedBit;
    else if (r1)
        downlink_mode = refLongLeading;
    else if (r2)
        downlink_mode = refLeading0;
    else if (r3)
        downlink_mode = ref1of4;


    /*
        Page 0 Block 0 Configuration data.
        Normal mode
        Extended mode
    */

    if (use_gb == false && gotdata == false) {
        // sanity check.
        if (SanityOfflineCheck(false) != PM3_SUCCESS)  {
            return PM3_ENODATA;
        }

        if (!AcquireData(T55x7_PAGE0, T55x7_CONFIGURATION_BLOCK, usepwd, password, downlink_mode)) {
            return PM3_ENODATA;
        }
    }

    if (gotdata == false) {
        if (DecodeT55xxBlock() == false) {
            return PM3_ESOFT;
        }

        // too little space to start with
        if (g_DemodBufferLen < 32 + config.offset) {
            return PM3_ESOFT;
        }

        //PrintAndLogEx(NORMAL, "Offset+32 ==%d\n DemodLen == %d", config.offset + 32, g_DemodBufferLen);
        block0 = PackBits(config.offset, 32, g_DemodBuffer);
    }

    PrintAndLogEx(NORMAL, "");
    if (((!gotdata) && config.Q5) || (gotdata && dataasq5)) {
        uint32_t header   = (block0 >> (32 - 12)) & 0xFFF;
        uint32_t ps       = (block0 >> (32 - 13)) & 0x01;
        uint32_t fw       = (block0 >> (32 - 14)) & 0x01;
        uint32_t dbr      = (block0 >> (32 - 20)) & 0x3F;
        uint32_t aor      = (block0 >> (32 - 21)) & 0x01;
        uint32_t pwd      = (block0 >> (32 - 22)) & 0x01;
        uint32_t pskcf    = (block0 >> (32 - 24)) & 0x03;
        uint32_t inv      = (block0 >> (32 - 25)) & 0x01;
        uint32_t datamod  = (block0 >> (32 - 28)) & 0x07;
        uint32_t maxblk   = (block0 >> (32 - 31)) & 0x07;
        uint32_t st       = block0 & 0x01;
        PrintAndLogEx(INFO, "--- " _CYAN_("Q5 Configuration & Information") " ------------");
        PrintAndLogEx(INFO, " Header                    : 0x%03X%s", header, (header != 0x600) ? _RED_(" - Warning") : "");
        PrintAndLogEx(INFO, " Page select               : %d", ps);
        PrintAndLogEx(INFO, " Fast Write                : %s", (fw)  ? _GREEN_("Yes") : "No");
        PrintAndLogEx(INFO, " Data bit rate             : %s", GetBitRateStr(dbr, 1));
        PrintAndLogEx(INFO, " AOR - Answer on Request   : %s", (aor) ? _GREEN_("Yes") : "No");
        PrintAndLogEx(INFO, " Password mode             : %s", (pwd) ? _GREEN_("Yes") : "No");
        PrintAndLogEx(INFO, " PSK clock frequency       : %s", GetPskCfStr(pskcf, 1));
        PrintAndLogEx(INFO, " Inverse data              : %s", (inv) ? _GREEN_("Yes") : "No");
        PrintAndLogEx(INFO, " Modulation                : %s", GetQ5ModulationStr(datamod));
        PrintAndLogEx(INFO, " Max block                 : %d", maxblk);
        PrintAndLogEx(INFO, " Sequence Terminator       : %s", (st) ? _GREEN_("Yes") : "No");
    } else {
        uint32_t safer    = (block0 >> (32 -  4)) & 0x0F;
        uint32_t extend   = (block0 >> (32 - 15)) & 0x01;
        uint32_t resv, dbr;
        if (extend) {
            resv     = (block0 >> (32 -  8)) & 0x0F;
            dbr      = (block0 >> (32 - 14)) & 0x3F;
        } else {
            resv     = (block0 >> (32 - 11)) & 0x7F;
            dbr      = (block0 >> (32 - 14)) & 0x07;
        }
        uint32_t datamod  = (block0 >> (32 - 20)) & 0x1F;
        uint32_t pskcf    = (block0 >> (32 - 22)) & 0x03;
        uint32_t aor      = (block0 >> (32 - 23)) & 0x01;
        uint32_t otp      = (block0 >> (32 - 24)) & 0x01;
        uint32_t maxblk   = (block0 >> (32 - 27)) & 0x07;
        uint32_t pwd      = (block0 >> (32 - 28)) & 0x01;
        uint32_t sst      = (block0 >> (32 - 29)) & 0x01;
        uint32_t fw       = (block0 >> (32 - 30)) & 0x01;
        uint32_t inv      = (block0 >> (32 - 31)) & 0x01;
        uint32_t por      = (block0 >> (32 - 32)) & 0x01;

        PrintAndLogEx(INFO, "--- " _CYAN_("T55x7 Configuration & Information") " ---------");
        PrintAndLogEx(INFO, " Safer key                 : %s", GetSaferStr(safer));
        PrintAndLogEx(INFO, " reserved                  : %d", resv);
        PrintAndLogEx(INFO, " Data bit rate             : %s", GetBitRateStr(dbr, extend));
        PrintAndLogEx(INFO, " eXtended mode             : %s", (extend) ? _YELLOW_("Yes - Warning") : "No");
        PrintAndLogEx(INFO, " Modulation                : %s", GetModulationStr(datamod, extend));
        PrintAndLogEx(INFO, " PSK clock frequency       : %s", GetPskCfStr(pskcf, 0));
        PrintAndLogEx(INFO, " AOR - Answer on Request   : %s", (aor) ? _GREEN_("Yes") : "No");
        PrintAndLogEx(INFO, " OTP - One Time Pad        : %s", (otp) ? ((extend) ? _YELLOW_("Yes - Warning") : _RED_("Yes - Warning")) : "No");
        PrintAndLogEx(INFO, " Max block                 : %d", maxblk);
        PrintAndLogEx(INFO, " Password mode             : %s", (pwd) ? _GREEN_("Yes") : "No");
        PrintAndLogEx(INFO, " Sequence %-12s     : %s", (extend) ? "Start Marker" : "Terminator", (sst) ? _GREEN_("Yes") : "No");
        PrintAndLogEx(INFO, " Fast Write                : %s", (fw)  ? ((extend) ? _GREEN_("Yes") : _RED_("Yes - Warning")) : "No");
        PrintAndLogEx(INFO, " Inverse data              : %s", (inv) ? ((extend) ? _GREEN_("Yes") : _RED_("Yes - Warning")) : "No");
        PrintAndLogEx(INFO, " POR-Delay                 : %s", (por) ? _GREEN_("Yes") : "No");
    }
    PrintAndLogEx(INFO, "-------------------------------------------------------------");
    PrintAndLogEx(INFO, " Raw Data - Page 0, block 0");
    if (gotdata)
        PrintAndLogEx(INFO, " " _GREEN_("%08X"), block0);
    else
        PrintAndLogEx(INFO, " " _GREEN_("%08X") " - %s", block0, sprint_bytebits_bin(g_DemodBuffer + config.offset, 32));

    if (((!gotdata) && (!config.Q5)) || (gotdata && (!dataasq5))) {
        PrintAndLogEx(INFO, "--- " _CYAN_("Fingerprint") " ------------");
        printT5x7KnownBlock0(block0);
    }

    PrintAndLogEx(NORMAL, "");
    //PrintAndLogEx(INFO, "-------------------------------------------------------------");
    return PM3_SUCCESS;
}

static int CmdT55xxDump(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf t55xx dump",
                  "This command dumps a T55xx card Page 0 block 0-7.\n"
                  "It will create three files (bin/eml/json)",
                  "lf t55xx dump\n"
                  "lf t55xx dump -p aabbccdd --override\n"
                  "lf t55xx dump -f my_lf_dump"
                 );

    // 1 (help) + 4 (two user specified params) + (5 T55XX_DLMODE_SINGLE)
    void *argtable[5 + 5] = {
        arg_param_begin,
        arg_str0("f", "file", "<fn>", "filename (default is generated on blk 0)"),
        arg_lit0("o", "override", "override, force pwd read despite danger to card"),
        arg_str0("p", "pwd", "<hex>", "password (4 hex bytes)"),
        arg_lit0(NULL, "ns", "no save"),
    };
    uint8_t idx = 5;
    arg_add_t55xx_downloadlink(argtable, &idx, T55XX_DLMODE_SINGLE, T55XX_DLMODE_SINGLE);
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);

    uint8_t override = arg_get_lit(ctx, 2) ? 1 : 0;

    bool usepwd = false;
    uint32_t password = 0;
    int res = arg_get_u32_hexstr_def_nlen(ctx, 3, 0, &password, 4, true);
    if (res == 0 || res == 2) {
        PrintAndLogEx(ERR, "Password should be 4 hex bytes");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }
    if (res == 1) {
        usepwd = true;
    }

    bool nosave = arg_get_lit(ctx, 4);

    bool r0 = arg_get_lit(ctx, 5);
    bool r1 = arg_get_lit(ctx, 6);
    bool r2 = arg_get_lit(ctx, 7);
    bool r3 = arg_get_lit(ctx, 8);
    CLIParserFree(ctx);

    if ((r0 + r1 + r2 + r3) > 1) {
        PrintAndLogEx(FAILED, "Error multiple downlink encoding");
        return PM3_EINVARG;
    }

    uint8_t downlink_mode = config.downlink_mode;
    if (r0)
        downlink_mode = refFixedBit;
    else if (r1)
        downlink_mode = refLongLeading;
    else if (r2)
        downlink_mode = refLeading0;
    else if (r3)
        downlink_mode = ref1of4;

    bool success = true;

    // Due to the few different T55xx cards and number of blocks supported
    // will save the dump file if ALL page 0 is OK
    printT5xxHeader(0);
    for (uint8_t i = 0; i < 8; ++i) {
        if (T55xxReadBlock(i, 0, usepwd, override, password, downlink_mode) != PM3_SUCCESS) {
            success = false;
        }

        // only show override warning on the first block read
        if (override == 1) {
            override++;
        }
    }
    printT5xxHeader(1);
    for (uint8_t i = 0; i < 4; i++) {
        if (T55xxReadBlock(i, 1, usepwd, override, password, downlink_mode) != PM3_SUCCESS) {
            T55x7_SaveBlockData(8 + i, 0x00);
        }
    }

    // all ok, save dump to file
    if (success && nosave == false) {

        // set default filename, if not set by user
        if (strlen(filename) == 0) {
            strcpy(filename, "lf-t55xx");
            for (uint8_t i = 1; i <= 7; i++) {
                if ((cardmem[i].blockdata != 0x00) && (cardmem[i].blockdata != 0xFFFFFFFF)) {
                    snprintf(filename + strlen(filename), sizeof(filename) - strlen(filename), "-%08X", cardmem[i].blockdata);
                } else {
                    break;
                }
            }
            strcat(filename, "-dump");
        }

        // Swap endian so the files match the txt display
        uint32_t data[T55x7_BLOCK_COUNT];

        for (int i = 0; i < T55x7_BLOCK_COUNT; i++) {
            data[i] = BSWAP_32(cardmem[i].blockdata);
        }

        // saveFileEML will add .eml extension to filename
        // saveFile (binary) passes in the .bin extension.
        saveFileJSON(filename, jsfT55x7, (uint8_t *)data, T55x7_BLOCK_COUNT * sizeof(uint32_t), NULL);
        saveFileEML(filename, (uint8_t *)data, T55x7_BLOCK_COUNT * sizeof(uint32_t), sizeof(uint32_t));
        saveFile(filename, ".bin", data, sizeof(data));
    }

    return PM3_SUCCESS;
}

static int CmdT55xxRestore(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf t55xx restore",
                  "Restore T55xx card page 0/1 n blocks from (bin/eml/json) dump file",
                  "lf t55xx restore -f lf-t55xx-00148040-dump.bin"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("f", "file", "<fn>", "filename of dump file"),
        arg_str0("p", "pwd", "<hex>", "password if target card has password set (4 hex bytes)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);

    bool usepwd = false;
    uint32_t password = 0;
    int res = arg_get_u32_hexstr_def_nlen(ctx, 2, 0, &password, 4, true);
    if (res == 0 || res == 2) {
        PrintAndLogEx(ERR, "Password should be 4 hex bytes");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }
    if (res == 1) {
        usepwd = true;
    }
    CLIParserFree(ctx);

    if (fnlen == 0) {
        PrintAndLogEx(ERR, "Must specify a filename");
        return PM3_EINVARG;
    }

    // read dump file
    uint32_t *dump = NULL;
    size_t bytes_read = 0;
    res = pm3_load_dump(filename, (void **)&dump, &bytes_read, (T55x7_BLOCK_COUNT * 4));
    if (res != PM3_SUCCESS) {
        return res;
    }

    if (bytes_read != (T55x7_BLOCK_COUNT * 4)) {
        free(dump);
        PrintAndLogEx(FAILED, "wrong length of dump file. Expected 48 bytes, got %zu", bytes_read);
        return PM3_EFILE;
    }

    // 12 blocks * 4 bytes per block
    // this part creates strings to call "lf t55 write" command.
    PrintAndLogEx(INFO, "Starting to write...");

    uint8_t downlink_mode;
    char wcmd[100];
    char pwdopt [14] = {0}; // p XXXXXXXX

    if (usepwd) {
        snprintf(pwdopt, sizeof(pwdopt), "-p %08X", password);
    }

    uint8_t idx;
    // Restore endien for writing to card
    for (idx = 0; idx < 12; idx++) {
        dump[idx] = BSWAP_32(dump[idx]);
    }

    // Have data ready, lets write
    // Order
    //    write blocks 1..7 page 0
    //    write blocks 1..3 page 1
    //    update downlink mode (if needed) and write b 0
    downlink_mode = 0;
    if ((((dump[11] >> 28) & 0xF) == 6) || (((dump[11] >> 28) & 0xF) == 9))
        downlink_mode = (dump[11] >> 10) & 3;

    // write out blocks 1-7 page 0
    for (idx = 1; idx <= 7; idx++) {
        snprintf(wcmd, sizeof(wcmd), "-b %d -d %08X %s", idx, dump[idx], pwdopt);

        if (CmdT55xxWriteBlock(wcmd) != PM3_SUCCESS) {
            PrintAndLogEx(WARNING, "Warning: error writing blk %d", idx);
        }
    }

    // if password was set on the "blank" update as we may have just changed it
    if (usepwd) {
        snprintf(pwdopt, sizeof(pwdopt), "-p %08X", dump[7]);
    }

    // write out blocks 1-3 page 1
    for (idx = 9; idx <= 11; idx++) {
        snprintf(wcmd, sizeof(wcmd), "-b %d --pg1 -d %08X %s", idx - 8, dump[idx], pwdopt);

        if (CmdT55xxWriteBlock(wcmd) != PM3_SUCCESS) {
            PrintAndLogEx(WARNING, "Warning: error writing blk %d", idx);
        }
    }

    // Update downlink mode for the page 0 config write.
    config.downlink_mode = downlink_mode;

    // Write the page 0 config
    snprintf(wcmd, sizeof(wcmd), "-b 0 -d %08X %s", dump[0], pwdopt);
    if (CmdT55xxWriteBlock(wcmd) != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, "Warning: error writing blk 0");
    }
    free(dump);
    PrintAndLogEx(INFO, "Done!");
    return PM3_SUCCESS;
}
/*
static int CmdT55xxRestore(const char *Cmd) {

    uint32_t password = 0;
    uint8_t override = 0;
    uint8_t downlink_mode = config.downlink_mode;
    bool usepwd = false;
    bool errors = false;
    uint8_t cmdp = 0;

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_t55xx_restore();
            case 'r':
                downlink_mode = param_get8ex(Cmd, cmdp + 1, 0, 10);
                if (downlink_mode > 3)
                    downlink_mode = 0;

                cmdp += 2;
                break;
            case 'p':
                password = param_get32ex(Cmd, cmdp + 1, 0, 16);
                usepwd = true;
                cmdp += 2;
                break;
            case 'o':
                override = 1;
                cmdp++;
                break;
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }
    if (errors) return usage_t55xx_restore();

    PrintAndLogEx(INFO,  "Work in progress.  To be implemented");
    if (usepwd || password || override ) {

    }
    // load file name  (json/eml/bin)

    // Print dump data?

    uint32_t res = PM3_SUCCESS;

// page0.
//    res = clone_t55xx_tag(blockdata, numblocks);

    return res;
}
*/
bool AcquireData(uint8_t page, uint8_t block, bool pwdmode, uint32_t password, uint8_t downlink_mode) {
    // arg0 bitmodes:
    //  b0 = pwdmode
    //  b1 = page to read from
    //  b2 = brute_mem (armside function)
    // arg1: which block to read
    // arg2: password
    struct p {
        uint32_t password;
        uint8_t  blockno;
        uint8_t  page;
        bool     pwdmode;
        uint8_t  downlink_mode;
    } PACKED;
    struct p payload;
    payload.password      = password;
    payload.blockno       = block;
    payload.page          = page & 0x1;
    payload.pwdmode       = pwdmode;
    payload.downlink_mode = downlink_mode;

    clearCommandBuffer();
    SendCommandNG(CMD_LF_T55XX_READBL, (uint8_t *)&payload, sizeof(payload));
    if (!WaitForResponseTimeout(CMD_LF_T55XX_READBL, NULL, 2500)) {
        PrintAndLogEx(WARNING, "command execution time out");
        return false;
    }

    getSamples(12000, false);
    bool ok = !getSignalProperties()->isnoise;

    config.usepwd = pwdmode;
    return ok;
}

char *GetPskCfStr(uint32_t id, bool q5) {
    static char buf[40];
    char *retStr = buf;
    switch (id) {
        case 0:
            snprintf(retStr, sizeof(buf), "%u - RF/2", id);
            break;
        case 1:
            snprintf(retStr, sizeof(buf), "%u - RF/4", id);
            break;
        case 2:
            snprintf(retStr, sizeof(buf), "%u - RF/8", id);
            break;
        case 3:
            if (q5)
                snprintf(retStr, sizeof(buf), "%u - RF/8", id);
            else
                snprintf(retStr, sizeof(buf), "%u - " _RED_("(Unknown)"), id);
            break;
        default:
            snprintf(retStr, sizeof(buf), "%u - " _RED_("(Unknown)"), id);
            break;
    }
    return buf;
}

char *GetBitRateStr(uint32_t id, bool xmode) {
    static char buf[35];

    char *retStr = buf;
    if (xmode) { //xmode bitrate calc is same as em4x05 calc
        snprintf(retStr, sizeof(buf), "%u - RF/%u", id, EM4x05_GET_BITRATE(id));
    } else {
        switch (id) {
            case 0:
                snprintf(retStr, sizeof(buf), "%u - "_GREEN_("RF/8"), id);
                break;
            case 1:
                snprintf(retStr, sizeof(buf), "%u - "_GREEN_("RF/16"), id);
                break;
            case 2:
                snprintf(retStr, sizeof(buf), "%u - "_GREEN_("RF/32"), id);
                break;
            case 3:
                snprintf(retStr, sizeof(buf), "%u - "_GREEN_("RF/40"), id);
                break;
            case 4:
                snprintf(retStr, sizeof(buf), "%u - "_GREEN_("RF/50"), id);
                break;
            case 5:
                snprintf(retStr, sizeof(buf), "%u - "_GREEN_("RF/64"), id);
                break;
            case 6:
                snprintf(retStr, sizeof(buf), "%u - "_GREEN_("RF/100"), id);
                break;
            case 7:
                snprintf(retStr, sizeof(buf), "%u - "_GREEN_("RF/128"), id);
                break;
            default:
                snprintf(retStr, sizeof(buf), "%u - " _RED_("(Unknown)"), id);
                break;
        }
    }
    return buf;
}

char *GetSaferStr(uint32_t id) {
    static char buf[40];
    char *retStr = buf;

    snprintf(retStr, sizeof(buf), "%u", id);
    if (id == 6) {
        snprintf(retStr, sizeof(buf), "%u - " _YELLOW_("passwd"), id);
    }
    if (id == 9) {
        snprintf(retStr, sizeof(buf), "%u - " _YELLOW_("testmode"), id);
    }

    return buf;
}

char *GetModulationStr(uint32_t id, bool xmode) {
    static char buf[60];
    char *retStr = buf;

    switch (id) {
        case 0:
            snprintf(retStr, sizeof(buf), "%u - DIRECT (ASK/NRZ)", id);
            break;
        case 1:
            snprintf(retStr, sizeof(buf), "%u - PSK 1 phase change when input changes", id);
            break;
        case 2:
            snprintf(retStr, sizeof(buf), "%u - PSK 2 phase change on bitclk if input high", id);
            break;
        case 3:
            snprintf(retStr, sizeof(buf), "%u - PSK 3 phase change on rising edge of input", id);
            break;
        case 4:
            snprintf(retStr, sizeof(buf), "%u - FSK 1 RF/8  RF/5", id);
            break;
        case 5:
            snprintf(retStr, sizeof(buf), "%u - FSK 2 RF/8  RF/10", id);
            break;
        case 6:
            snprintf(retStr, sizeof(buf), "%u - %s RF/5  RF/8", id, (xmode) ? "FSK 1a" : _YELLOW_("FSK 1a"));
            break;
        case 7:
            snprintf(retStr, sizeof(buf), "%u - %s RF/10  RF/8", id, (xmode) ? "FSK 2a" : _YELLOW_("FSK 2a"));
            break;
        case 8:
            snprintf(retStr, sizeof(buf), "%u - Manchester", id);
            break;
        case 16:
            snprintf(retStr, sizeof(buf), "%u - Biphase", id);
            break;
        case 24:
            snprintf(retStr, sizeof(buf), "%u - %s", id, (xmode) ? "Biphase a - AKA Conditional Dephase Encoding(CDP)" : _YELLOW_("Reserved"));
            break;
        default:
            snprintf(retStr, sizeof(buf), "0x%02X " _RED_("(Unknown)"), id);
            break;
    }
    return buf;
}

char *GetDownlinkModeStr(uint8_t downlink_mode) {
    static char buf[30];
    char *retStr = buf;

    switch (downlink_mode) {
        case T55XX_DLMODE_FIXED :
            snprintf(retStr, sizeof(buf), "default/fixed bit length");
            break;
        case T55XX_DLMODE_LLR :
            snprintf(retStr, sizeof(buf), "long leading reference");
            break;
        case T55XX_DLMODE_LEADING_ZERO :
            snprintf(retStr, sizeof(buf), "leading zero reference");
            break;
        case T55XX_DLMODE_1OF4 :
            snprintf(retStr, sizeof(buf), "1 of 4 coding reference");
            break;
        default:
            snprintf(retStr, sizeof(buf), _RED_("(Unknown)"));
            break;
    }
    return buf;
}

char *GetQ5ModulationStr(uint32_t id) {
    static char buf[60];
    char *retStr = buf;

    switch (id) {
        case 0:
            snprintf(retStr, sizeof(buf), "%u - Manchester", id);
            break;
        case 1:
            snprintf(retStr, sizeof(buf), "%u - PSK 1 phase change when input changes", id);
            break;
        case 2:
            snprintf(retStr, sizeof(buf), "%u - PSK 2 phase change on bitclk if input high", id);
            break;
        case 3:
            snprintf(retStr, sizeof(buf), "%u - PSK 3 phase change on rising edge of input", id);
            break;
        case 4:
            snprintf(retStr, sizeof(buf), "%u - FSK 1a RF/5  RF/8", id);
            break;
        case 5:
            snprintf(retStr, sizeof(buf), "%u - FSK 2a RF/10  RF/8", id);
            break;
        case 6:
            snprintf(retStr, sizeof(buf), "%u - Biphase", id);
            break;
        case 7:
            snprintf(retStr, sizeof(buf), "%u - NRZ / Direct", id);
            break;
    }
    return buf;
}

char *GetModelStrFromCID(uint32_t cid) {

    static char buf[10];
    char *retStr = buf;

    if (cid == 1) snprintf(retStr, sizeof(buf), "ATA5577M1");
    if (cid == 2) snprintf(retStr, sizeof(buf), "ATA5577M2");
    if (cid == 3) snprintf(retStr, sizeof(buf), "ATA5577M3");
    return buf;
}

char *GetConfigBlock0Source(uint8_t id) {

    static char buf[40];
    char *retStr = buf;

    switch (id) {
        case AUTODETECT:
            snprintf(retStr, sizeof(buf), _YELLOW_("(auto detect)"));
            break;
        case USERSET:
            snprintf(retStr, sizeof(buf), _YELLOW_("(user set)"));
            break;
        case TAGREAD:
            snprintf(retStr, sizeof(buf), _GREEN_("(tag read)"));
            break;
        default:
            snprintf(retStr, sizeof(buf), _RED_("(n/a)"));
            break;
    }
    return buf;
}

char *GetSelectedModulationStr(uint8_t id) {

    static char buf[20];
    char *retStr = buf;

    switch (id) {
        case DEMOD_FSK:
            snprintf(retStr, sizeof(buf), "FSK");
            break;
        case DEMOD_FSK1:
            snprintf(retStr, sizeof(buf), "FSK1");
            break;
        case DEMOD_FSK1a:
            snprintf(retStr, sizeof(buf), "FSK1a");
            break;
        case DEMOD_FSK2:
            snprintf(retStr, sizeof(buf), "FSK2");
            break;
        case DEMOD_FSK2a:
            snprintf(retStr, sizeof(buf), "FSK2a");
            break;
        case DEMOD_ASK:
            snprintf(retStr, sizeof(buf), "ASK");
            break;
        case DEMOD_NRZ:
            snprintf(retStr, sizeof(buf), "DIRECT/NRZ");
            break;
        case DEMOD_PSK1:
            snprintf(retStr, sizeof(buf), "PSK1");
            break;
        case DEMOD_PSK2:
            snprintf(retStr, sizeof(buf), "PSK2");
            break;
        case DEMOD_PSK3:
            snprintf(retStr, sizeof(buf), "PSK3");
            break;
        case DEMOD_BI:
            snprintf(retStr, sizeof(buf), "BIPHASE");
            break;
        case DEMOD_BIa:
            snprintf(retStr, sizeof(buf), "BIPHASEa - (CDP)");
            break;
        default:
            snprintf(retStr, sizeof(buf), _RED_("(Unknown)"));
            break;
    }
    return buf;
}

/*
static void t55x7_create_config_block(int tagtype) {

    // T55X7_DEFAULT_CONFIG_BLOCK, T55X7_RAW_CONFIG_BLOCK
    // T55X7_EM_UNIQUE_CONFIG_BLOCK, T55X7_FDXB_CONFIG_BLOCK,
    // T55X7_FDXB_CONFIG_BLOCK, T55X7_HID_26_CONFIG_BLOCK, T55X7_INDALA_64_CONFIG_BLOCK, T55X7_INDALA_224_CONFIG_BLOCK
    // T55X7_GUARDPROXII_CONFIG_BLOCK, T55X7_VIKING_CONFIG_BLOCK, T55X7_NORALYS_CONFIG_BLOCK, T55X7_IOPROX_CONFIG_BLOCK
    static char buf[60];
    char *retStr = buf;

    switch (tagtype) {
        case 0:
            snprintf(retStr, sizeof(buf), "%08X - T55X7 Default", T55X7_DEFAULT_CONFIG_BLOCK);
            break;
        case 1:
            snprintf(retStr, sizeof(buf), "%08X - T55X7 Raw", T55X7_RAW_CONFIG_BLOCK);
            break;
        case 2:
            snprintf(retStr, sizeof(buf), "%08X - Q5/T5555 Default", T5555_DEFAULT_CONFIG_BLOCK);
            break;
        default:
            break;
    }
    PrintAndLogEx(NORMAL, buf);
}
*/

static int CmdResetRead(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf t55xx resetread",
                  "Send Reset Cmd then `lf read` the stream to attempt\n"
                  "to identify the start of it (needs a demod and/or plot after)",
                  "lf t55xx resetread"
                 );

    // 1 (help) + 0(one user specified params) + (5 T55XX_DLMODE_SINGLE)
    void *argtable[2 + 5] = {
        arg_param_begin,
        arg_lit0("1", NULL, "extract using data from graphbuffer"),
    };
    uint8_t idx = 2;
    arg_add_t55xx_downloadlink(argtable, &idx, T55XX_DLMODE_SINGLE, config.downlink_mode);
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool r0 = arg_get_lit(ctx, 1);
    bool r1 = arg_get_lit(ctx, 2);
    bool r2 = arg_get_lit(ctx, 3);
    bool r3 = arg_get_lit(ctx, 4);
    CLIParserFree(ctx);

    if ((r0 + r1 + r2 + r3) > 1) {
        PrintAndLogEx(FAILED, "Error multiple downlink encoding");
        return PM3_EINVARG;
    }

    uint8_t downlink_mode = config.downlink_mode;
    if (r0)
        downlink_mode = refFixedBit;
    else if (r1)
        downlink_mode = refLongLeading;
    else if (r2)
        downlink_mode = refLeading0;
    else if (r3)
        downlink_mode = ref1of4;

    uint8_t flags = downlink_mode << 3;

    PrintAndLogEx(INFO, "Sending reset command...");

    PacketResponseNG resp;
    clearCommandBuffer();
    SendCommandNG(CMD_LF_T55XX_RESET_READ, &flags, sizeof(flags));
    if (WaitForResponseTimeout(CMD_LF_T55XX_RESET_READ, &resp, 2500) == false) {
        PrintAndLogEx(WARNING, "command execution time out");
        return PM3_ETIMEOUT;
    }

    if (resp.status == PM3_SUCCESS) {

        uint16_t gotsize = g_pm3_capabilities.bigbuf_size - 1;
        uint8_t *got = calloc(gotsize, sizeof(uint8_t));
        if (got == NULL) {
            PrintAndLogEx(WARNING, "failed to allocate memory");
            return PM3_EMALLOC;
        }

        PrintAndLogEx(INFO, "Downloading samples...");
        if (!GetFromDevice(BIG_BUF, got, gotsize, 0, NULL, 0, NULL, 2500, false)) {
            PrintAndLogEx(WARNING, "command execution time out");
            free(got);
            return PM3_ETIMEOUT;
        }
        setGraphBuf(got, gotsize);
        free(got);
    }

    PrintAndLogEx(INFO, "Done");
    return PM3_SUCCESS;
}

static int CmdT55xxWipe(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf t55xx wipe",
                  "This commands wipes a tag, fills blocks 1-7 with zeros and a default configuration block",
                  "lf t55xx wipe               -> wipes a T55x7 tag, config block 0x000880E0\n"
                  "lf t55xx wipe --q5          -> wipes a Q5/T5555 tag, config block 0x6001F004\n"
                  "lf t55xx wipe -p 11223344   -> wipes a T55x7 tag, config block 0x000880E0, using pwd"
                 );

    // 1 (help) + 3 (three user specified params) + (5 T55XX_DLMODE_SINGLE)
    void *argtable[4 + 5] = {
        arg_param_begin,
        arg_str0("c", "cfg", "<hex>", "configuration block0 (4 hex bytes)"),
        arg_str0("p", "pwd", "<hex>", "password (4 hex bytes)"),
        arg_lit0(NULL, "q5", "specify writing to Q5/T5555 tag using dedicated config block"),
    };
    uint8_t idx = 4;
    arg_add_t55xx_downloadlink(argtable, &idx, T55XX_DLMODE_SINGLE, config.downlink_mode);
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool usepwd = false, gotconf = false;
    uint32_t block0 = 0;
    int res = arg_get_u32_hexstr_def(ctx, 1, 0, &block0);
    if (res == 1) {
        gotconf = true;
    }
    if (res == 2) {
        CLIParserFree(ctx);
        PrintAndLogEx(WARNING, "config block needs to be 4 hex bytes");
        return PM3_EINVARG;
    }

    uint32_t password = 0;
    res = arg_get_u32_hexstr_def(ctx, 2, 0x51243648, &password);
    if (res) {
        usepwd = true;
    }

    if (res == 2) {
        PrintAndLogEx(WARNING, "Password should be 4 bytes, using default pwd");
    }

    bool Q5 = arg_get_lit(ctx, 3);
    CLIParserFree(ctx);

    PrintAndLogEx(INFO, "Target " _YELLOW_("%s")" tag", (Q5) ? "Q5/T5555" : "T55x7");

    // default config blocks.
    if (gotconf == false) {
        block0 = (Q5) ? 0x6001F004 : 0x000880E0;
    }

    if (usepwd)
        PrintAndLogEx(INFO, "Using password " _GREEN_("%08X"), password);

    char msg[80] = {0};
    if (gotconf)
        snprintf(msg, sizeof(msg), "User provided configuration block " _GREEN_("%08X"), block0);
    else
        snprintf(msg, sizeof(msg), "Default configuration block " _GREEN_("%08X"), block0);

    PrintAndLogEx(INFO, "%s\n", msg);

    PrintAndLogEx(INFO, "Begin wiping...");

    // Creating cmd string for write block :)
    char wcmd[36] = {0};
    char *pwcmd = wcmd;

    snprintf(pwcmd, sizeof(wcmd), "-b 0 ");

    if (usepwd) {
        snprintf(pwcmd + strlen(wcmd), sizeof(wcmd) - strlen(wcmd), "-p %08x ", password);
    }
    snprintf(pwcmd + strlen(wcmd), sizeof(wcmd) - strlen(wcmd), "-d %08X", block0);

    if (CmdT55xxWriteBlock(pwcmd) != PM3_SUCCESS)
        PrintAndLogEx(WARNING, "Warning: error writing blk 0");

    for (uint8_t blk = 1; blk < 8; blk++) {

        snprintf(pwcmd, sizeof(wcmd), "-b %d -d 00000000", blk);

        if (CmdT55xxWriteBlock(pwcmd) != PM3_SUCCESS)
            PrintAndLogEx(WARNING, "Warning: error writing blk %d", blk);

        memset(wcmd, 0x00, sizeof(wcmd));
    }

    // Check and rest t55xx downlink mode.
    if (config.downlink_mode != T55XX_DLMODE_FIXED) { // Detect found a different mode so card must support
        snprintf(pwcmd, sizeof(wcmd), "-b 3 --pg1 -d 00000000");
        if (CmdT55xxWriteBlock(pwcmd) != PM3_SUCCESS) {
            PrintAndLogEx(WARNING, "Warning: failed writing block 3 page 1 (config)");
        }
        memset(wcmd, 0x00, sizeof(wcmd));
    }
    return PM3_SUCCESS;
}

static bool IsCancelled(void) {
    if (kbd_enter_pressed()) {
        PrintAndLogEx(WARNING, "\naborted via keyboard!\n");
        return true;
    }
    return false;
}

// load a default pwd file.
static int CmdT55xxChkPwds(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf t55xx chk",
                  "This command uses a dictionary attack.\n"
                  "For some cloners, try '--em' for known pwdgen algo.\n"
                  "Try to reading Page 0 block 7 before.\n"
                  _RED_("WARNING:") _CYAN_(" this may brick non-password protected chips!"),
                  "lf t55xx chk -m                     -> use dictionary from flash memory (RDV4)\n"
                  "lf t55xx chk -f my_dictionary_pwds  -> loads a default keys dictionary file\n"
                  "lf t55xx chk --em aa11223344        -> try known pwdgen algo from some cloners based on EM4100 ID"
                 );

    /*
      Calculate size of argtable accordingly:
      1 (help) + 3 (three user specified params) + ( 5 or 6  T55XX_DLMODE)
      start index to call arg_add_t55xx_downloadlink() is 4 (1 + 3) given the above sample
    */

    // 1 (help) + 3 (three user specified params) + (6 T55XX_DLMODE_ALL)
    void *argtable[4 + 6] = {
        arg_param_begin,
        arg_lit0("m", "fm", "use dictionary from flash memory (RDV4)"),
        arg_str0("f", "file", "<fn>", "file name"),
        arg_str0(NULL, "em", "<hex>", "EM4100 ID (5 hex bytes)"),
    };
    uint8_t idx = 4;
    arg_add_t55xx_downloadlink(argtable, &idx, T55XX_DLMODE_ALL, T55XX_DLMODE_ALL);
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool from_flash = arg_get_lit(ctx, 1);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 2), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);

    // White cloner password based on EM4100 ID
    bool use_calc_password = false;
    uint32_t card_password = 0x00;
    uint64_t cardid = 0;
    int res = arg_get_u64_hexstr_def_nlen(ctx, 3, 0x00, &cardid, 5, true);
    if (res == 1) {
        use_calc_password = true;
        uint32_t calc = cardid & 0xFFFFFFFF;
        card_password = lf_t55xx_white_pwdgen(calc);
    }
    if (res == 2) {
        CLIParserFree(ctx);
        PrintAndLogEx(WARNING, "EM4100 ID must be 5 hex bytes");
        return PM3_EINVARG;
    }
    if (res == 0) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    bool r0 = arg_get_lit(ctx, 4);
    bool r1 = arg_get_lit(ctx, 5);
    bool r2 = arg_get_lit(ctx, 6);
    bool r3 = arg_get_lit(ctx, 7);
    bool ra = arg_get_lit(ctx, 8);
    CLIParserFree(ctx);

    if ((r0 + r1 + r2 + r3 + ra) > 1) {
        PrintAndLogEx(FAILED, "Error multiple downlink encoding");
        return PM3_EINVARG;
    }

    uint8_t downlink_mode = refFixedBit; // Password checks should always start with default/fixed bit unluess requested by user for specific mode
    //  if (r0 || ra) // ra should start downlink mode ad fixed bit to loop through all modes correctly
    //      downlink_mode = refFixedBit;
    //  else
    if (r1)
        downlink_mode = refLongLeading;
    else if (r2)
        downlink_mode = refLeading0;
    else if (r3)
        downlink_mode = ref1of4;

    bool use_pwd_file = true; // Assume we are going to use a file, unless turned off later.

    if (strlen(filename) == 0) {
        snprintf(filename, sizeof(filename), "t55xx_default_pwds");
    }

    PrintAndLogEx(INFO, "press " _GREEN_("<Enter>") " to exit");
    PrintAndLogEx(NORMAL, "");
    /*
    // block 7,  page1 = false, usepwd = false, override = false, pwd = 00000000
    if ( T55xxReadBlock(7, false, false, false, 0x00000000) == PM3_SUCCESS) {

        // now try to validate it..
        PrintAndLogEx(WARNING, "\n Block 7 was readable");
        return PM3_SUCCESS;
    }
    */

    bool found = false;

    uint64_t t1 = msclock();
    uint8_t flags = downlink_mode << 3;

    if (from_flash) {
        use_pwd_file = false; // turn of local password file since we are checking from flash.
        clearCommandBuffer();
        SendCommandNG(CMD_LF_T55XX_CHK_PWDS, &flags, sizeof(flags));
        PacketResponseNG resp;

        uint8_t timeout = 0;
        while (!WaitForResponseTimeout(CMD_LF_T55XX_CHK_PWDS, &resp, 2000)) {
            timeout++;
            PrintAndLogEx(NORMAL, "." NOLF);
            if (timeout > 180) {
                PrintAndLogEx(WARNING, "\nno response from Proxmark3. Aborting...");
                return PM3_ENODATA;
            }
        }
        PrintAndLogEx(NORMAL, "");
        struct p {
            bool found;
            uint32_t candidate;
        } PACKED;
        struct p *packet = (struct p *)resp.data.asBytes;

        if (packet->found) {
            PrintAndLogEx(SUCCESS, "\nfound a candidate [ " _YELLOW_("%08"PRIX32) " ]", packet->candidate);

            if (AcquireData(T55x7_PAGE0, T55x7_CONFIGURATION_BLOCK, true, packet->candidate, downlink_mode)) {
                found = t55xxTryDetectModulationEx(downlink_mode, T55XX_PrintConfig, 0, packet->candidate);
                if (found) {
                    PrintAndLogEx(SUCCESS, "found valid password [ " _GREEN_("%08"PRIX32) " ]", packet->candidate);

                } else {
                    PrintAndLogEx(WARNING, "check pwd failed");
                }
            } else {
                PrintAndLogEx(WARNING, "check pwd failed");
            }
        } else {
            PrintAndLogEx(WARNING, "check pwd failed");
        }
        goto out;
    }

    // to try each downlink mode for each password
    int dl_mode;

    // try calculated password
    if (use_calc_password) {

        PrintAndLogEx(INFO, "testing %08"PRIX32" generated ", card_password);
        for (dl_mode = downlink_mode; dl_mode <= 3; dl_mode++) {

            if (!AcquireData(T55x7_PAGE0, T55x7_CONFIGURATION_BLOCK, true, card_password, dl_mode)) {
                continue;
            }

            found = t55xxTryDetectModulationEx(dl_mode, T55XX_PrintConfig, 0, card_password);
            if (found) {
                PrintAndLogEx(SUCCESS, "found valid password : [ " _GREEN_("%08"PRIX32) " ]", card_password);
                break;
            }

            if (ra == false)
                break;
        }
    }

    if ((found == false) && use_pwd_file) {
        uint32_t keycount = 0;
        uint8_t *keyblock = NULL;

        res = loadFileDICTIONARY_safe(filename, (void **) &keyblock, 4, &keycount);
        if (res != PM3_SUCCESS || keycount == 0 || keyblock == NULL) {
            PrintAndLogEx(WARNING, "no keys found in file");
            if (keyblock != NULL)
                free(keyblock);

            return PM3_ESOFT;
        }

        PrintAndLogEx(INFO, "press " _GREEN_("<Enter>") " to exit");

        for (uint32_t c = 0; c < keycount && found == false; ++c) {

            if (!g_session.pm3_present) {
                PrintAndLogEx(WARNING, "device offline\n");
                free(keyblock);
                return PM3_ENODATA;
            }

            if (IsCancelled()) {
                free(keyblock);
                return PM3_EOPABORTED;
            }

            uint32_t curr_password = bytes_to_num(keyblock + 4 * c, 4);

            PrintAndLogEx(INFO, "testing %08"PRIX32, curr_password);
            for (dl_mode = downlink_mode; dl_mode <= 3; dl_mode++) {
                // If acquire fails, then we still need to check if we are only trying a single downlink mode.
                // If we continue on fail, it will skip that test and try the next downlink mode; thus slowing down the check
                // when on a single downlink mode is wanted.
                if (AcquireData(T55x7_PAGE0, T55x7_CONFIGURATION_BLOCK, true, curr_password, dl_mode)) {
                    found = t55xxTryDetectModulationEx(dl_mode, T55XX_PrintConfig, 0, curr_password);
                    if (found) {
                        PrintAndLogEx(SUCCESS, "found valid password: [ " _GREEN_("%08"PRIX32) " ]", curr_password);
                        break;
                    }
                }
                if (ra == false) // Exit loop if not trying all downlink modes
                    break;
            }
        }

        free(keyblock);
    }

    if (found == false)
        PrintAndLogEx(WARNING, "failed to find password");

out:
    t1 = msclock() - t1;
    PrintAndLogEx(SUCCESS, "\ntime in check pwd " _YELLOW_("%.0f") " seconds\n", (float)t1 / 1000.0);
    return PM3_SUCCESS;
}

// Bruteforce - incremental password range search
static int CmdT55xxBruteForce(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf t55xx bruteforce",
                  "This command uses bruteforce to scan a number range.\n"
                  "Try reading Page 0, block 7 before.\n\n"
                  _RED_("WARNING") _CYAN_(" this may brick non-password protected chips!"),
                  "lf t55xx bruteforce --r2 -s aaaaaa77 -e aaaaaa99\n"
                 );

    // 1 (help) + 2 (two user specified params) + (6 T55XX_DLMODE_ALL)
    void *argtable[3 + 6] = {
        arg_param_begin,
        arg_str1("s", "start", "<hex>", "search start password (4 hex bytes)"),
        arg_str1("e", "end", "<hex>", "search end password (4 hex bytes)"),
    };
    uint8_t idx = 3;
    arg_add_t55xx_downloadlink(argtable, &idx, T55XX_DLMODE_ALL, T55XX_DLMODE_ALL);
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    uint32_t start_password = 0;
    int res = arg_get_u32_hexstr_def(ctx, 1, 0, &start_password);
    if (res == 2) {
        CLIParserFree(ctx);
        PrintAndLogEx(FAILED, "start password should be 4 bytes");
        return PM3_EINVARG;
    }

    uint32_t end_password = 0xFFFFFFFF;
    res = arg_get_u32_hexstr_def(ctx, 2, 0xFFFFFFFF, &end_password);
    if (res == 2) {
        CLIParserFree(ctx);
        PrintAndLogEx(FAILED, "end password should be 4 bytes");
        return PM3_EINVARG;
    }

    bool r0 = arg_get_lit(ctx, 3);
    bool r1 = arg_get_lit(ctx, 4);
    bool r2 = arg_get_lit(ctx, 5);
    bool r3 = arg_get_lit(ctx, 6);
    bool ra = arg_get_lit(ctx, 7);
    CLIParserFree(ctx);

    if ((r0 + r1 + r2 + r3 + ra) > 1) {
        PrintAndLogEx(FAILED, "Error multiple downlink encoding");
        return PM3_EINVARG;
    }

    uint8_t downlink_mode = refFixedBit; // if no downlink mode suppliled use fixed bit/default as the is the most common
    // Since we don't know the password the config.downlink mode is of little value.
//   if (r0 || ra) // if try all (ra) then start at fixed bit for correct try all
//       downlink_mode = refFixedBit;
//    else
    if (r1)
        downlink_mode = refLongLeading;
    else if (r2)
        downlink_mode = refLeading0;
    else if (r3)
        downlink_mode = ref1of4;

    uint32_t curr = 0;
    uint8_t found = 0; // > 0 if found xx1 xx downlink needed, 1 found

    if (start_password > end_password) {
        PrintAndLogEx(FAILED, "Error, start larger then end password");
        return PM3_EINVARG;
    }

    PrintAndLogEx(INFO, "press " _GREEN_("<Enter>") " to exit");
    PrintAndLogEx(INFO, "Search password range [%08X -> %08X]", start_password, end_password);

    uint64_t t1 = msclock();
    curr = start_password;

    while (found == 0) {

        PrintAndLogEx(NORMAL, "." NOLF);

        if (IsCancelled()) {
            return PM3_EOPABORTED;
        }

        found = t55xx_try_one_password(curr, downlink_mode, ra);

        if (curr == end_password)
            break;

        curr++;
    }

    PrintAndLogEx(NORMAL, "");

    if (found) {
        if (curr != end_password) {
            PrintAndLogEx(SUCCESS, "Found valid password: [ " _GREEN_("%08X") " ]", curr - 1);
        } else
            PrintAndLogEx(SUCCESS, "Found valid password: [ " _GREEN_("%08X") " ]", curr);
        T55xx_Print_DownlinkMode((found >> 1) & 3);
    } else
        PrintAndLogEx(WARNING, "Bruteforce failed, last tried: [ " _YELLOW_("%08X") " ]", curr);

    t1 = msclock() - t1;
    PrintAndLogEx(SUCCESS, "\ntime in bruteforce " _YELLOW_("%.0f") " seconds\n", (float)t1 / 1000.0);
    return PM3_SUCCESS;
}

uint8_t t55xx_try_one_password(uint32_t password, uint8_t downlink_mode,  bool try_all_dl_modes) {

    PrintAndLogEx(INFO, "Trying password %08X", password);

    // ensure 0-3
    downlink_mode = (downlink_mode & 3);

    // check if dl mode 4 and loop if needed
    for (uint8_t dl_mode = downlink_mode; dl_mode < 4; dl_mode++) {

        if (AcquireData(T55x7_PAGE0, T55x7_CONFIGURATION_BLOCK, true, password, dl_mode)) {
            //  if (getSignalProperties()->isnoise == false) {
            //  } else {
            if (t55xxTryDetectModulationEx(dl_mode, T55XX_PrintConfig, 0, password)) {
                return 1 + (dl_mode << 1);
            }
            //  }
        }
        if (try_all_dl_modes == false) {
            break;
        }
    }
    return 0;
}

static int CmdT55xxRecoverPW(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf t55xx recoverpw",
                  "This command uses a few tricks to try to recover mangled password.\n"
                  "Try reading Page 0, block 7 before.\n\n"
                  _RED_("WARNING") _CYAN_(" this may brick non-password protected chips!"),
                  "lf t55xx recoverpw\n"
                  "lf t55xx recoverpw -p 11223344\n"
                  "lf t55xx recoverpw -p 11223344 --r3\n"
                 );

    // 1 (help) + 1 (one user specified params) + (6 T55XX_DLMODE_ALL)
    void *argtable[2 + 6] = {
        arg_param_begin,
        arg_str0("p", "pwd", "<hex>", "password (4 hex bytes)"),
    };
    uint8_t idx = 2;
    arg_add_t55xx_downloadlink(argtable, &idx, T55XX_DLMODE_ALL, T55XX_DLMODE_ALL);
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    uint32_t orig_password = 0;
    int res = arg_get_u32_hexstr_def(ctx, 1, 0x51243648, &orig_password);
    if (res == 2) {
        PrintAndLogEx(INFO, "Password should be 4 bytes, using default pwd instead");
    }

    bool r0 = arg_get_lit(ctx, 2);
    bool r1 = arg_get_lit(ctx, 3);
    bool r2 = arg_get_lit(ctx, 4);
    bool r3 = arg_get_lit(ctx, 5);
    bool ra = arg_get_lit(ctx, 6);
    CLIParserFree(ctx);

    if ((r0 + r1 + r2 + r3 + ra) > 1) {
        PrintAndLogEx(FAILED, "Error multiple downlink encoding");
        return PM3_EINVARG;
    }

    uint8_t downlink_mode = config.downlink_mode;
    if (r0)
        downlink_mode = refFixedBit;
    else if (r1)
        downlink_mode = refLongLeading;
    else if (r2)
        downlink_mode = refLeading0;
    else if (r3)
        downlink_mode = ref1of4;

    PrintAndLogEx(INFO, "press " _GREEN_("<Enter>") " to exit");

    int bit = 0;
    uint32_t curr_password = 0x0;
    uint32_t prev_password = 0xffffffff;
    uint32_t mask = 0x0;
    uint8_t found = 0;

    // first try fliping each bit in the expected password
    while (bit < 32) {
        curr_password = orig_password ^ (1u << bit);
        found = t55xx_try_one_password(curr_password, downlink_mode, ra);
        if (found > 0) // xx1 for found xx = dl mode used
            goto out;

        bit++;

        if (IsCancelled())
            return PM3_EOPABORTED;
    }

    // now try to use partial original password, since block 7 should have been completely
    // erased during the write sequence and it is possible that only partial password has been
    // written
    // not sure from which end the bit bits are written, so try from both ends
    // from low bit to high bit
    bit = 0;
    while (bit < 32) {
        mask += (1u << bit);
        curr_password = orig_password & mask;
        // if updated mask didn't change the password, don't try it again
        if (prev_password == curr_password) {
            bit++;
            continue;
        }

        found = t55xx_try_one_password(curr_password, downlink_mode, ra);
        if (found > 0)
            goto out;

        bit++;
        prev_password = curr_password;

        if (IsCancelled())
            return PM3_EOPABORTED;
    }

    // from high bit to low
    bit = 0;
    mask = 0xffffffff;
    while (bit < 32) {
        mask -= (1u << bit);
        curr_password = orig_password & mask;
        // if updated mask didn't change the password, don't try it again
        if (prev_password == curr_password) {
            bit++;
            continue;
        }
        found = t55xx_try_one_password(curr_password, downlink_mode, ra);
        if (found > 0)
            goto out;

        bit++;
        prev_password = curr_password;

        if (IsCancelled())
            return PM3_EOPABORTED;
    }

out:
    PrintAndLogEx(NORMAL, "");

    if (found > 0) {
        PrintAndLogEx(SUCCESS, "Found valid password: [ " _GREEN_("%08X") " ]", curr_password);
        T55xx_Print_DownlinkMode((found >> 1) & 3);
    } else {
        PrintAndLogEx(FAILED, "Recover password failed");
    }
    return PM3_SUCCESS;
}

// note length of data returned is different for different chips.
// some return all page 1 (64 bits) and others return just that block (32 bits)
// unfortunately the 64 bits makes this more likely to get a false positive...
bool tryDetectP1(bool getData) {
    uint8_t  preamble[] = {1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1};
    size_t   startIdx   = 0;
    uint8_t  fc1        = 0, fc2 = 0, ans = 0;
    int      clk        = 0, firstClockEdge = 0;
    bool     st         = true;

    if (getData) {
        if (!AcquireData(T55x7_PAGE1, T55x7_TRACE_BLOCK1, false, 0, 0))
            return false;
    }

    // try fsk clock detect. if successful it cannot be any other type of modulation...  (in theory...)
    ans = fskClocks(&fc1, &fc2, (uint8_t *)&clk, &firstClockEdge);
    if (ans && ((fc1 == 10 && fc2 == 8) || (fc1 == 8 && fc2 == 5))) {
        if ((FSKrawDemod(0, 0, 0, 0, false) == PM3_SUCCESS) &&
                preambleSearchEx(g_DemodBuffer, preamble, sizeof(preamble), &g_DemodBufferLen, &startIdx, false) &&
                (g_DemodBufferLen == 32 || g_DemodBufferLen == 64)) {
            return true;
        }
        if ((FSKrawDemod(0, 1, 0, 0, false) == PM3_SUCCESS) &&
                preambleSearchEx(g_DemodBuffer, preamble, sizeof(preamble), &g_DemodBufferLen, &startIdx, false) &&
                (g_DemodBufferLen == 32 || g_DemodBufferLen == 64)) {
            return true;
        }
        return false;
    }

    // try ask clock detect.  it could be another type even if successful.
    clk = GetAskClock("", false);
    if (clk > 0) {
        if ((ASKDemod_ext(0, 0, 1, 0, false, false, false, 1, &st) == PM3_SUCCESS) &&
                preambleSearchEx(g_DemodBuffer, preamble, sizeof(preamble), &g_DemodBufferLen, &startIdx, false) &&
                (g_DemodBufferLen == 32 || g_DemodBufferLen == 64)) {
            return true;
        }

        st = true;
        if ((ASKDemod_ext(0, 1, 1, 0, false, false, false, 1, &st) == PM3_SUCCESS) &&
                preambleSearchEx(g_DemodBuffer, preamble, sizeof(preamble), &g_DemodBufferLen, &startIdx, false) &&
                (g_DemodBufferLen == 32 || g_DemodBufferLen == 64)) {
            return true;
        }

        if ((ASKbiphaseDemod(0, 0, 0, 2, false) == PM3_SUCCESS) &&
                preambleSearchEx(g_DemodBuffer, preamble, sizeof(preamble), &g_DemodBufferLen, &startIdx, false) &&
                (g_DemodBufferLen == 32 || g_DemodBufferLen == 64)) {
            return true;
        }

        if ((ASKbiphaseDemod(0, 0, 1, 2, false) == PM3_SUCCESS) &&
                preambleSearchEx(g_DemodBuffer, preamble, sizeof(preamble), &g_DemodBufferLen, &startIdx, false) &&
                (g_DemodBufferLen == 32 || g_DemodBufferLen == 64)) {
            return true;
        }
    }

    // try NRZ clock detect.  it could be another type even if successful.
    clk = GetNrzClock("", false); //has the most false positives :(
    if (clk > 0) {
        if ((NRZrawDemod(0, 0, 1, false) == PM3_SUCCESS) &&
                preambleSearchEx(g_DemodBuffer, preamble, sizeof(preamble), &g_DemodBufferLen, &startIdx, false) &&
                (g_DemodBufferLen == 32 || g_DemodBufferLen == 64)) {
            return true;
        }
        if ((NRZrawDemod(0, 1, 1, false) == PM3_SUCCESS)  &&
                preambleSearchEx(g_DemodBuffer, preamble, sizeof(preamble), &g_DemodBufferLen, &startIdx, false) &&
                (g_DemodBufferLen == 32 || g_DemodBufferLen == 64)) {
            return true;
        }
    }

    // Fewer card uses PSK
    // try psk clock detect. if successful it cannot be any other type of modulation... (in theory...)
    clk = GetPskClock("", false);
    if (clk > 0) {
        // allow undo
        // save_restoreGB(GRAPH_SAVE);
        // skip first 160 samples to allow antenna to settle in (psk gets inverted occasionally otherwise)
        //CmdLtrim("-i 160");
        if ((PSKDemod(0, 0, 6, false) == PM3_SUCCESS) &&
                preambleSearchEx(g_DemodBuffer, preamble, sizeof(preamble), &g_DemodBufferLen, &startIdx, false) &&
                (g_DemodBufferLen == 32 || g_DemodBufferLen == 64)) {
            //save_restoreGB(GRAPH_RESTORE);
            return true;
        }
        if ((PSKDemod(0, 1, 6, false) == PM3_SUCCESS) &&
                preambleSearchEx(g_DemodBuffer, preamble, sizeof(preamble), &g_DemodBufferLen, &startIdx, false) &&
                (g_DemodBufferLen == 32 || g_DemodBufferLen == 64)) {
            //save_restoreGB(GRAPH_RESTORE);
            return true;
        }
        // PSK2 - needs a call to psk1TOpsk2.
        if (PSKDemod(0, 0, 6, false) == PM3_SUCCESS) {
            psk1TOpsk2(g_DemodBuffer, g_DemodBufferLen);
            if (preambleSearchEx(g_DemodBuffer, preamble, sizeof(preamble), &g_DemodBufferLen, &startIdx, false) &&
                    (g_DemodBufferLen == 32 || g_DemodBufferLen == 64)) {
                //save_restoreGB(GRAPH_RESTORE);
                return true;
            }
        } // inverse waves does not affect PSK2 demod
        //undo trim samples
        //save_restoreGB(GRAPH_RESTORE);
        // no other modulation clocks = 2 or 4 so quit searching
        if (fc1 != 8) return false;
    }

    return false;
}
//  does this need to be a callable command?
static int CmdT55xxDetectPage1(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf t55xx p1detect",
                  "Detect Page 1 of a T55xx chip",
                  "lf t55xx p1detect\n"
                  "lf t55xx p1detect -1\n"
                  "lf t55xx p1detect -p 11223344 --r3\n"
                 );

    // 1 (help) + 2 (two user specified params) + (5 T55XX_DLMODE_SINGLE)
    void *argtable[3 + 5] = {
        arg_param_begin,
        arg_lit0("1", NULL, "extract using data from graphbuffer"),
        arg_str0("p", "pwd", "<hex>", "password (4 hex bytes)"),
    };
    uint8_t idx = 3;
    arg_add_t55xx_downloadlink(argtable, &idx, T55XX_DLMODE_SINGLE, config.downlink_mode);
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool use_graphbuf = arg_get_lit(ctx, 1);

    bool usepwd = false;
    uint32_t password = 0;
    int res = arg_get_u32_hexstr_def(ctx, 2, 0, &password);
    if (res == 2) {
        PrintAndLogEx(INFO, "Password should be 4 hex bytes");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    } else if (res == 1) {
        usepwd = true;
    }

    bool r0 = arg_get_lit(ctx, 3);
    bool r1 = arg_get_lit(ctx, 4);
    bool r2 = arg_get_lit(ctx, 5);
    bool r3 = arg_get_lit(ctx, 6);
    CLIParserFree(ctx);

    if ((r0 + r1 + r2 + r3) > 1) {
        PrintAndLogEx(FAILED, "Error multiple downlink encoding");
        return PM3_EINVARG;
    }

    uint8_t downlink_mode = config.downlink_mode;
    if (r0)
        downlink_mode = refFixedBit;
    else if (r1)
        downlink_mode = refLongLeading;
    else if (r2)
        downlink_mode = refLeading0;
    else if (r3)
        downlink_mode = ref1of4;

    bool try_all_dl_modes = true;

    //ICEMAN STRANGE
    if (downlink_mode == 4)
        try_all_dl_modes = true;
    if (downlink_mode < 4)
        try_all_dl_modes = false;

    if (downlink_mode > 3)
        downlink_mode = 0;

    bool found = false;
    uint8_t found_mode = 0;

    if (use_graphbuf == false) {
        for (uint8_t dl_mode = downlink_mode; dl_mode < 4; dl_mode++) {

            if (AcquireData(T55x7_PAGE1, T55x7_TRACE_BLOCK1, usepwd, password, dl_mode) == false)
                continue;

            if (tryDetectP1(false)) {
                found = true;
                found_mode = dl_mode;
                break;
            } else {
                found = false;
            }

            if (try_all_dl_modes == false) {
                break;
            }
        }
    } else {
        found = tryDetectP1(false);
    }

    if (found) {
        PrintAndLogEx(SUCCESS, "T55xx chip found!");
        T55xx_Print_DownlinkMode(found_mode);
    } else
        PrintAndLogEx(WARNING, "Could not detect modulation automatically. Try setting it manually with " _YELLOW_("\'lf t55xx config\'"));

    return PM3_SUCCESS;
}

static int CmdT55xxSetDeviceConfig(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf t55xx deviceconfig",
                  "Sets t55x7 timings for direct commands.\n"
                  "The timings are set here in Field Clocks (FC) which is converted to (US) on device.",
                  "lf t55xx deviceconfig -a 29 -b 17 -c 15 -d 47 -e 15    -> default T55XX\n"
                  "lf t55xx deviceconfig -a 55 -b 14 -c 21 -d 30          -> default EM4305"
                 );

    // 1 (help) + 9 (nine user specified params) + (5 T55XX_DLMODE_SINGLE)
    void *argtable[10 + 5] = {
        arg_param_begin,
        arg_int0("a", NULL, "<8..255>", "Set start gap"),
        arg_int0("b", NULL, "<8..255>", "Set write gap"),
        arg_int0("c", NULL, "<8..255>", "Set write ZERO gap"),
        arg_int0("d", NULL, "<8..255>", "Set write ONE gap"),
        arg_int0("e", NULL, "<8..255>", "Set read gap"),
        arg_int0("f", NULL, "<8..255>", "Set write TWO gap (1 of 4 only)"),
        arg_int0("g", NULL, "<8..255>", "Set write THREE gap (1 of 4 only)"),
        arg_lit0("p", "persist", "persist to flash memory (RDV4)"),
        arg_lit0("z", NULL, "Set default t55x7 timings (use `-p` to save if required)"),
    };
    uint8_t idx = 10;
    arg_add_t55xx_downloadlink(argtable, &idx, T55XX_DLMODE_SINGLE, config.downlink_mode);
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    uint8_t startgap = arg_get_int(ctx, 1);
    uint8_t writegap = arg_get_int(ctx, 2);
    uint8_t write0 = arg_get_int(ctx, 3);
    uint8_t write1 = arg_get_int(ctx, 4);
    uint8_t readgap = arg_get_int(ctx, 5);
    uint8_t write2 = arg_get_int(ctx, 6);
    uint8_t write3 = arg_get_int(ctx, 7);
    bool shall_persist = arg_get_lit(ctx, 8);
    bool set_defaults = arg_get_lit(ctx, 9);
    bool r0 = arg_get_lit(ctx, 10);
    bool r1 = arg_get_lit(ctx, 11);
    bool r2 = arg_get_lit(ctx, 12);
    bool r3 = arg_get_lit(ctx, 13);
    CLIParserFree(ctx);

    if ((r0 + r1 + r2 + r3) > 1) {
        PrintAndLogEx(FAILED, "Error multiple downlink encoding");
        return PM3_EINVARG;
    }

    uint8_t downlink_mode = 0;
    if (r0)
        downlink_mode = refFixedBit;
    else if (r1)
        downlink_mode = refLongLeading;
    else if (r2)
        downlink_mode = refLeading0;
    else if (r3)
        downlink_mode = ref1of4;

    t55xx_configurations_t configurations = {{{0}, {0}, {0}, {0}}};

    if (set_defaults) {
        // fixed bit length
        configurations.m[T55XX_DLMODE_FIXED].start_gap  = 29 * 8;
        configurations.m[T55XX_DLMODE_FIXED].write_gap  = 17 * 8;
        configurations.m[T55XX_DLMODE_FIXED].write_0    = 15 * 8;
        configurations.m[T55XX_DLMODE_FIXED].write_1    = 47 * 8;
        configurations.m[T55XX_DLMODE_FIXED].read_gap   = 15 * 8;
        configurations.m[T55XX_DLMODE_FIXED].write_2    = 0;
        configurations.m[T55XX_DLMODE_FIXED].write_3    = 0;

        // long leading reference
        configurations.m[T55XX_DLMODE_LLR].start_gap  = 29 * 8;
        configurations.m[T55XX_DLMODE_LLR].write_gap  = 17 * 8;
        configurations.m[T55XX_DLMODE_LLR].write_0    = 15 * 8;
        configurations.m[T55XX_DLMODE_LLR].write_1    = 47 * 8;
        configurations.m[T55XX_DLMODE_LLR].read_gap   = 15 * 8;
        configurations.m[T55XX_DLMODE_LLR].write_2    = 0;
        configurations.m[T55XX_DLMODE_LLR].write_3    = 0;

        // leading zero
        configurations.m[T55XX_DLMODE_LEADING_ZERO].start_gap  = 29 * 8;
        configurations.m[T55XX_DLMODE_LEADING_ZERO].write_gap  = 17 * 8;
        configurations.m[T55XX_DLMODE_LEADING_ZERO].write_0    = 15 * 8;
        configurations.m[T55XX_DLMODE_LEADING_ZERO].write_1    = 40 * 8;
        configurations.m[T55XX_DLMODE_LEADING_ZERO].read_gap   = 15 * 8;
        configurations.m[T55XX_DLMODE_LEADING_ZERO].write_2    = 0;
        configurations.m[T55XX_DLMODE_LEADING_ZERO].write_3    = 0;

        // 1 of 4 coding reference
        configurations.m[T55XX_DLMODE_1OF4].start_gap  = 29 * 8;
        configurations.m[T55XX_DLMODE_1OF4].write_gap  = 17 * 8;
        configurations.m[T55XX_DLMODE_1OF4].write_0    = 15 * 8;
        configurations.m[T55XX_DLMODE_1OF4].write_1    = 31 * 8;
        configurations.m[T55XX_DLMODE_1OF4].read_gap   = 15 * 8;
        configurations.m[T55XX_DLMODE_1OF4].write_2    = 47 * 8;
        configurations.m[T55XX_DLMODE_1OF4].write_3    = 63 * 8;

    } else {
        configurations.m[downlink_mode].start_gap  = startgap * 8;
        configurations.m[downlink_mode].write_gap  = writegap * 8;
        configurations.m[downlink_mode].write_0    = write0   * 8;
        configurations.m[downlink_mode].write_1    = write1   * 8;
        configurations.m[downlink_mode].read_gap   = readgap  * 8;
        configurations.m[downlink_mode].write_2    = write2   * 8;
        configurations.m[downlink_mode].write_3    = write3   * 8;
    }

    clearCommandBuffer();
    SendCommandMIX(CMD_LF_T55XX_SET_CONFIG, shall_persist, 0, 0, &configurations, sizeof(t55xx_configurations_t));
    return PM3_SUCCESS;
}

static int CmdT55xxProtect(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf t55xx protect",
                  "This command sets the pwd bit on T5577.\n"
                  _RED_("WARNING") _CYAN_(" this locks the tag!"),
                  "lf t55xx protect -n 01020304              -> sets new pwd 01020304\n"
                  "lf t55xx protect -p 11223344 -n 00000000  -> use pwd 11223344, sets new pwd 00000000"
                 );

    // 1 (help) + 3 (three user specified params) + (5 T55XX_DLMODE_SINGLE)
    void *argtable[4 + 5] = {
        arg_param_begin,
        arg_lit0("o", "override", "override safety check"),
        arg_str0("p", "pwd", "<hex>", "password (4 hex bytes)"),
        arg_str1("n", "new", "<hex>", "new password (4 hex bytes)"),
    };
    uint8_t idx = 4;
    arg_add_t55xx_downloadlink(argtable, &idx, T55XX_DLMODE_SINGLE, config.downlink_mode);
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    uint8_t override = 0;
    if (arg_get_lit(ctx, 1))
        override = 2;

    uint32_t password = 0;
    bool usepwd = false;
    int res = arg_get_u32_hexstr_def(ctx, 2, 0, &password);
    if (res == 2) {
        CLIParserFree(ctx);
        PrintAndLogEx(FAILED, "Error parsing password bytes");
        return PM3_EINVARG;
    } else if (res == 1) {
        usepwd = true;
        override = 1;
    }

    uint32_t new_password = 0;
    res = arg_get_u32_hexstr_def(ctx, 3, 0, &new_password);
    if (res == 2) {
        CLIParserFree(ctx);
        PrintAndLogEx(FAILED, "Error parsing new password bytes");
        return PM3_EINVARG;
    } else if (res == 0) {
        PrintAndLogEx(FAILED, "Must specify new password param");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    bool r0 = arg_get_lit(ctx, 4);
    bool r1 = arg_get_lit(ctx, 5);
    bool r2 = arg_get_lit(ctx, 6);
    bool r3 = arg_get_lit(ctx, 7);
    CLIParserFree(ctx);

    if ((r0 + r1 + r2 + r3) > 1) {
        PrintAndLogEx(FAILED, "Error multiple downlink encoding");
        return PM3_EINVARG;
    }

    uint8_t downlink_mode = config.downlink_mode;
    if (r0)
        downlink_mode = refFixedBit;
    else if (r1)
        downlink_mode = refLongLeading;
    else if (r2)
        downlink_mode = refLeading0;
    else if (r3)
        downlink_mode = ref1of4;

    // sanity check.
    if (SanityOfflineCheck(false) != PM3_SUCCESS)
        return PM3_ESOFT;

    // lock
    if (t55xxProtect(true, usepwd, override, password, downlink_mode, new_password) == false) {
        PrintAndLogEx(WARNING, "Command failed. Did you run " _YELLOW_("`lf t55xx detect`") " before?");
        return PM3_ESOFT;
    }
    return PM3_SUCCESS;
}

// if the difference between a and b is less then or eq to d  i.e. does a = b +/- d
#define APPROX_EQ(a, b, d) ((abs(a - b) <= d) ? true : false)

static uint8_t t55sniff_get_packet(const int *pulseBuffer, char *data, uint8_t width0, uint8_t width1, uint8_t tolerance) {
    int i = 0;
    bool ok = true;
    uint8_t len = 0;

    while (ok && (i < 73)) { // 70 bits max Fixed bit packet
        if (APPROX_EQ(width0, pulseBuffer[i], tolerance))  {
            data[len++] = '0';
            i++;
            continue;
        }
        if (APPROX_EQ(width1, pulseBuffer[i], tolerance)) {
            data[len++] = '1';
            i++;
            continue;
        }

        ok = false;
    }
    data[len] = 0x00;
    return len;
}

static uint8_t t55sniff_trim_samples(int *pulseBuffer, int *pulseIdx, uint8_t len) {
    for (uint8_t i = 0; i < (80 - len); i++) {
        pulseBuffer[i] = pulseBuffer[i + len];
    }

    *pulseIdx -= len;
    return PM3_SUCCESS;
}

static int CmdT55xxSniff(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf t55xx sniff",
                  "Sniff LF t55xx based trafic and decode possible cmd / blocks.\n"
                  "Lower tolerance means tighter pulses. ",
                  "lf t55xx sniff\n"
                  "lf t55xx sniff -1 -t 2               -> use buffer with tolerance of 2\n"
                  "lf t55xx sniff -1 --zero 7 --one 14  -> use buffer, zero pulse width 7, one pulse width 15"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("1", NULL, "extract using data from graphbuffer"),
        arg_int0("t", "tol", "<dec>", "set tolerance level (default 5)"),
//        arg_int0(NULL, "signal", "<dec>", "set minimum signal level (default 20)"),
        arg_int0("o", "one", "<dec>", "set samples width for ONE pulse (default auto)"),
        arg_int0("z", "zero", "<dec>", "set samples width for ZERO pulse (default auto)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool use_graphbuf = arg_get_lit(ctx, 1);
    uint8_t tolerance = arg_get_int_def(ctx, 2, 5);
    int opt_width1 = arg_get_int_def(ctx, 3, -1);
    int opt_width0 = arg_get_int_def(ctx, 4, -1);
    CLIParserFree(ctx);

    if (opt_width0 == 0) {
        PrintAndLogEx(ERR, "Must call with --zero larger than 0");
        return PM3_EINVARG;
    }
    if (opt_width1 == 0) {
        PrintAndLogEx(ERR, "Must call with --one larger than 0");
        return PM3_EINVARG;
    }

    if (opt_width0 > 0  && opt_width1 == -1) {
        PrintAndLogEx(ERR, _RED_("Missing sample width for ONE"));
        return PM3_EINVARG;
    }

    if (opt_width1 > 0 && opt_width0 == -1) {
        PrintAndLogEx(ERR, _RED_("Missing sample width for ZERO"));
        return PM3_EINVARG;
    }

    uint8_t width1 = 0;
    uint8_t width0 = 0;

    if (opt_width0 > -1)
        width0 = (uint8_t)opt_width0 & 0xFF;

    if (opt_width1 > -1)
        width1 = (uint8_t)opt_width1 & 0xFF;



    /*
        Notes:
                T55xx packet lengths  (1 of 4 needs to be checked)
                                     -----------------------------------------------
                                    |  Default  |    LL 0   | Leading 0 |   1 of 4  |
                    ----------------------------------------------------------------|
                   | Standard Write |     38    |     39    |    39     |    40     |
                   | Protect Write  |     70    |     71    |    73     |    74     |
                   | AOR            |     34    |     35    |    37     |    38     |
                   | Standard Read  |      5    |      6    |     7     |     8     |
                   | Protect Read   |     38    |     39    |    41     |    42     |
                   | Regular Read   |      2    |      3    |     3     |     4     |
                   | Reset          |      2    |      3    |     3     |     4     |
                    ----------------------------------------------------------------

                T55xx bit widths (decimation 1) - Expected, but may vary a little
                Reference 0 for LL0 and Leading 0 can be longer
                         -----------------------------------------------
                        |  Default  |    LL 0   | Leading 0 |   1 of 4  |
                    ----------------------------------------------------|
                   | 0  |  16 - 32  |   9 - 33  |   5 - 80  |   tbc     |
                   | 1  |  48 - 64  |  41 - 72  |  21 - 96  |   tbc     |
                    ----------------------------------------------------
                                                             00 01 10 11
    */

    uint8_t page, blockAddr;
    size_t idx = 0;
    uint32_t usedPassword, blockData;
    int pulseSamples = 0, pulseIdx = 0;
    char pwdText[100];
    char dataText[100];
    int pulseBuffer[80] = { 0 }; // max should be 73 +/- - Holds Pulse widths
    char data[80]; //  linked to pulseBuffer. - Holds 0/1 from pulse widths

    // setup and sample data from Proxmark
    // if not directed to existing sample/graphbuffer
    if (use_graphbuf == false) {

        // make loop to call sniff with skip samples..
        // then build it up by adding
        CmdLFSniff("");

    }

    // Headings
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, _CYAN_("T55xx command detection"));
    PrintAndLogEx(SUCCESS, "Downlink mode           |  password  |   Data   | blk | page |  0  |  1  | raw");
    PrintAndLogEx(SUCCESS, "------------------------+------------+----------+-----+------+-----+-----+-------------------------------------------------------------------------------");

    idx = 0;
    // loop though sample buffer
    while (idx < g_GraphTraceLen) {

        int minWidth = 1000;
        int maxWidth = 0;
        data[0] = 0;
        bool have_data = false;
        const char *modeText = "Default";
        strncpy(pwdText, " ", sizeof(pwdText));
        strncpy(dataText, " ", sizeof(dataText));

        if (pulseSamples == 0) {
            idx++;
        }

        // find high
        while ((idx < g_GraphTraceLen) && (g_GraphBuffer[idx] < 0)) {
            idx++;
        }

        // count high samples
        pulseSamples = 0;
        while ((idx < g_GraphTraceLen) && (g_GraphBuffer[idx] > 0)) { // last bit seems to be high to zero, but can vary in width..
            pulseSamples++;
            idx++;
        }

        if (pulseSamples > 0) {
            pulseBuffer[pulseIdx++] = pulseSamples;
            if (pulseIdx > 79) { // make room for next sample - if not used by now, it won't be.
                t55sniff_trim_samples(pulseBuffer, &pulseIdx, 1);
            }

            // Check Samples for valid packets;
            // We should find (outside of leading bits) we have a packet of "1" and "0" at same widths.
            if (pulseIdx >= 6) {// min size for a read - ignoring 1of4 10 0 <adr>

                // We auto find widths
                if ((width0 == 0) && (width1 == 0)) {
                    // We ignore bit 0 for the moment as it may be a ref. pulse, so check last
                    uint32_t ii = 2;
                    minWidth = pulseBuffer[1];
                    maxWidth = pulseBuffer[1];
                    bool done = false;

                    while ((!done) && (ii < pulseIdx) && ((maxWidth <= minWidth) || (APPROX_EQ(minWidth, maxWidth, tolerance)))) { // min should be 8, 16-32 more normal
                        if (pulseBuffer[ii] + 3 < minWidth) {
                            minWidth = pulseBuffer[ii];
                            done = true;
                        }
                        if (pulseBuffer[ii] - 1 > maxWidth) {
                            maxWidth = pulseBuffer[ii];
                            done = true;
                        }
                        ii++;
                    }
                } else {
                    minWidth = width0;
                    maxWidth = width1;
                }
            }

            //  out of bounds... min max far enough appart and minWidth is large enough
            if (((maxWidth - minWidth) < 6) || (minWidth < 6)) // min 8 +/-
                continue;

            // At this point we should have
            // - a min of 6 samples
            // - the 0 and 1 sample widths
            // - min 0 and min separations (worst case)
            // No max checks done (yet) as have seen samples > then specs in use.

            // Check first bit.

            // Long leading 0
            if (have_data == false && (APPROX_EQ(pulseBuffer[0], 136 + minWidth, tolerance) && APPROX_EQ(pulseBuffer[1], maxWidth, tolerance))) {
                // printf ("Long Leading 0 - not yet handled | have 1 First bit | Min : %-3d - Max : %-3d : diff : %d\n",minWidth,maxWidth, maxWidth-minWidth);
                continue;
            }

            // Fixed bit - Default
            if (have_data == false && (APPROX_EQ(pulseBuffer[0], maxWidth, tolerance))) {
                uint16_t dataLen = t55sniff_get_packet(pulseBuffer, data, minWidth, maxWidth, tolerance);

                //   if ((dataLen == 39) )
                //           printf ("Fixed | Data end of 80 samples | offset : %llu - datalen %-2d - data : %s  --- - Bit 0 width : %d\n",idx,dataLen,data,pulseBuffer[0]);

                if (data[0] == '0') { // should never get here..
                    data[0] = 0;
                } else {

                    // Default Read
                    if (dataLen == 6) {
                        t55sniff_trim_samples(pulseBuffer, &pulseIdx, 4); // left 1 or 2 samples seemed to help

                        page = data[1] - '0';
                        blockAddr = 0;
                        for (uint8_t i = 3; i < 6; i++) {
                            blockAddr <<= 1;
                            if (data[i] == '1') {
                                blockAddr |= 1;
                            }
                        }
                        blockData = 0;
                        have_data = true;
                        modeText = "Default Read";
                    }

                    // Password Write
                    if (dataLen == 70) {
                        t55sniff_trim_samples(pulseBuffer, &pulseIdx, 70);

                        page = data[1] - '0';
                        usedPassword = 0;
                        for (uint8_t i = 2; i <= 33; i++) {
                            usedPassword <<= 1;
                            if (data[i] == '1') {
                                usedPassword |= 1;
                        }
                        }

                        // Lock bit 34
                        blockData = 0;
                        for (uint8_t i = 35; i <= 66; i++) {
                            blockData <<= 1;
                            if (data[i] == '1') {
                                blockData |= 1;
                        }
                        }

                        blockAddr = 0;
                        for (uint8_t i = 67; i <= 69; i++) {
                            blockAddr <<= 1;
                            if (data[i] == '1') {
                                blockAddr |= 1;
                            }
                        }
                        have_data = true;
                        modeText = "Default pwd write";
                        snprintf(pwdText, sizeof(pwdText), " %08X", usedPassword);
                        snprintf(dataText, sizeof(dataText), "%08X", blockData);
                    }

                    // Default Write or password read ???
                    // the most confusing command.
                    // if the token is with a password - all is OK,
                    // if not - read command with a password will lead to write the shifted password to the memory and:
                    //    IF the most bit of the data is `1` ----> IT LEADS TO LOCK this block of the memory
                    if (dataLen == 38) {
                        t55sniff_trim_samples(pulseBuffer, &pulseIdx, 38);

                        page = data[1] - '0';
                        usedPassword = 0;
                        blockData = 0;
                        for (uint8_t i = 3; i <= 34; i++) {
                            blockData <<= 1;
                            if (data[i] == '1') {
                                blockData |= 1;
                        }
                        }

                        for (uint8_t i = 2; i <= 33; i++) {
                            usedPassword <<= 1;
                            if (data[i] == '1') {
                                usedPassword |= 1;
                            }
                        }

                        blockAddr = 0;
                        for (uint8_t i = 35; i <= 37; i++) {
                            blockAddr <<= 1;
                            if (data[i] == '1') {
                                blockAddr |= 1;
                            }
                        }
                        have_data = true;
                        modeText = "Default write/pwd read";
                        snprintf(pwdText, sizeof(pwdText), "[%08X]", usedPassword);
                        snprintf(dataText, sizeof(dataText), "%08X", blockData);
                    }
                }
            }

            // Leading 0
            if (have_data == false && (APPROX_EQ(pulseBuffer[0], minWidth, tolerance))) {
                // leading 0 (should = 0 width)
                // 1 of 4 (leads with 00)
                uint16_t dataLen = t55sniff_get_packet(pulseBuffer, data, minWidth, maxWidth, tolerance);
                // **** Should check to 0 to be actual 0 as well i.e. 01 .... data ....
                if ((data[0] == '0') && (data[1] == '1')) {
                    if (dataLen == 73) {
                        t55sniff_trim_samples(pulseBuffer, &pulseIdx, 73);

                        page = data[2] - '0';
                        usedPassword = 0;
                        for (uint8_t i = 5; i <= 36; i++) {
                            usedPassword <<= 1;
                            if (data[i] == '1') {
                                usedPassword |= 1;
                        }
                        }

                        blockData = 0;
                        for (uint8_t i = 38; i <= 69; i++) {
                            blockData <<= 1;
                            if (data[i] == '1') {
                                blockData |= 1;
                        }
                        }

                        blockAddr = 0;
                        for (uint8_t i = 70; i <= 72; i++) {
                            blockAddr <<= 1;
                            if (data[i] == '1') {
                                blockAddr |= 1;
                        }
                        }

                        have_data = true;
                        modeText = "Leading 0 pwd write";
                        snprintf(pwdText, sizeof(pwdText), " %08X", usedPassword);
                        snprintf(dataText, sizeof(dataText), "%08X", blockData);
                    }
                }
            }
        }

        // Print results
        if (have_data) {
            if (blockAddr == 7) {
                PrintAndLogEx(SUCCESS, "%-22s  | "_GREEN_("%10s")" | "_YELLOW_("%8s")" |  "_YELLOW_("%d")"  |   "_GREEN_("%d")"  | %3d | %3d | %s"
                    , modeText
                    , pwdText
                    , dataText
                    , blockAddr
                    , page
                    , minWidth
                    , maxWidth
                    , data
                );
            } else {
                PrintAndLogEx(SUCCESS, "%-22s  | "_GREEN_("%10s")" | "_GREEN_("%8s")" |  "_GREEN_("%d")"  |   "_GREEN_("%d")"  | %3d | %3d | %s"
                    , modeText
                    , pwdText
                    , dataText
                    , blockAddr
                    , page
                    , minWidth
                    , maxWidth
                    , data
                );
            }
        }
    }

    // footer
    PrintAndLogEx(SUCCESS, "-----------------------------------------------------------------------------------------------------------------------------------------------------");
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"-----------",  CmdHelp,                 AlwaysAvailable, "---------------------------- " _CYAN_("notice") " -----------------------------"},
    {"",             CmdHelp,                 AlwaysAvailable, "Remember to run `" _YELLOW_("lf t55xx detect") "` first whenever a new card"},
    {"",             CmdHelp,                 AlwaysAvailable, "is placed on the Proxmark3 or the config block changed."},
    {"",             CmdHelp,                 AlwaysAvailable, ""},
    {"help",         CmdHelp,                 AlwaysAvailable, "This help"},
    {"-----------",  CmdHelp,                 AlwaysAvailable, "--------------------- " _CYAN_("operations") " ---------------------"},
    {"clonehelp",    CmdT55xxCloneHelp,       IfPm3Lf,         "Shows the available clone commands"},
    {"config",       CmdT55xxSetConfig,       AlwaysAvailable, "Set/Get T55XX configuration (modulation, inverted, offset, rate)"},
    {"dangerraw",    CmdT55xxDangerousRaw,    IfPm3Lf,         "Sends raw bitstream. Dangerous, do not use!!"},
    {"detect",       CmdT55xxDetect,          AlwaysAvailable, "Try detecting the tag modulation from reading the configuration block"},
    {"deviceconfig", CmdT55xxSetDeviceConfig, IfPm3Lf,         "Set/Get T55XX device configuration"},
    {"dump",         CmdT55xxDump,            IfPm3Lf,         "Dump T55xx card Page 0 block 0-7"},
    {"info",         CmdT55xxInfo,            AlwaysAvailable, "Show T55x7 configuration data (page 0/ blk 0)"},
    {"p1detect",     CmdT55xxDetectPage1,     IfPm3Lf,         "Try detecting if this is a t55xx tag by reading page 1"},
    {"read",         CmdT55xxReadBlock,       IfPm3Lf,         "Read T55xx block data"},
    {"resetread",    CmdResetRead,            IfPm3Lf,         "Send Reset Cmd then lf read the stream to attempt to identify the start of it"},
    {"restore",      CmdT55xxRestore,         IfPm3Lf,         "Restore T55xx card Page 0 / Page 1 blocks"},
    {"trace",        CmdT55xxReadTrace,       AlwaysAvailable, "Show T55x7 traceability data (page 1/ blk 0-1)"},
    {"wakeup",       CmdT55xxWakeUp,          IfPm3Lf,         "Send AOR wakeup command"},
    {"write",        CmdT55xxWriteBlock,      IfPm3Lf,         "Write T55xx block data"},
    {"-----------",  CmdHelp,                 AlwaysAvailable, "--------------------- " _CYAN_("recovery") " ---------------------"},
    {"bruteforce",   CmdT55xxBruteForce,      IfPm3Lf,         "Simple bruteforce attack to find password"},
    {"chk",          CmdT55xxChkPwds,         IfPm3Lf,         "Check passwords from dictionary/flash"},
    {"protect",      CmdT55xxProtect,         IfPm3Lf,         "Password protect tag"},
    {"recoverpw",    CmdT55xxRecoverPW,       IfPm3Lf,         "Try to recover from bad password write from a cloner"},
    {"sniff",        CmdT55xxSniff,           AlwaysAvailable, "Attempt to recover T55xx commands from sample buffer"},
    {"special",      CmdT55xxSpecial,         IfPm3Lf,         "Show block changes with 64 different offsets"},
    {"wipe",         CmdT55xxWipe,            IfPm3Lf,         "Wipe a T55xx tag and set defaults (will destroy any data on tag)"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdLFT55XX(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

