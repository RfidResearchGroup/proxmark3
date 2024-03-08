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
// Low frequency EM4x70 commands
//-----------------------------------------------------------------------------

#include "cmdlfem4x70.h"
#include <ctype.h>
#include "cmdparser.h"    // command_t
#include "cliparser.h"
#include "fileutils.h"
#include "commonutil.h"
#include "em4x70.h"
#include "id48.h"
#include "time.h"

#define LOCKBIT_0 BITMASK(6)
#define LOCKBIT_1 BITMASK(7)

#define BYTE_ARRAY_INDEX_TO_BLOCK(x) ((31-(x))/2)

// result from CMD_LF_EM4X70_INFO
typedef struct _em4x70_tag_info {
    /// <summary>
    /// The full data on an em4x70 the tag.
    /// [31] == Block 15 MSB == UM2₆₃..UM2₅₆
    /// [30] == Block 15 LSB == UM2₅₅..UM2₄₈
    /// [29] == Block 14 MSB == UM2₄₇..UM2₄₀
    /// [28] == Block 14 LSB == UM2₃₉..UM2₃₂
    /// [27] == Block 13 MSB == UM2₃₁..UM2₂₄
    /// [26] == Block 13 LSB == UM2₂₃..UM2₁₆
    /// [25] == Block 12 MSB == UM2₁₅..UM2₀₈
    /// [24] == Block 12 LSB == UM2₀₇..UM2₀₀
    /// [23] == Block 11 MSB == Pin₃₁..Pin₂₄
    /// [22] == Block 11 LSB == Pin₂₃..Pin₁₆
    /// [21] == Block 10 MSB == Pin₁₅..Pin₀₈
    /// [20] == Block 10 LSB == Pin₀₇..Pin₀₀
    /// [19] == Block  9 MSB == Key₉₅..Key₈₈
    /// [18] == Block  9 LSB == Key₈₇..Key₈₀
    /// [17] == Block  8 MSB == Key₇₉..Key₇₂
    /// [16] == Block  8 LSB == Key₇₁..Key₆₄
    /// [15] == Block  7 MSB == Key₆₃..Key₅₆
    /// [14] == Block  7 LSB == Key₅₅..Key₄₈
    /// [13] == Block  6 MSB == Key₄₇..Key₄₀
    /// [12] == Block  6 LSB == Key₃₉..Key₃₂
    /// [11] == Block  5 MSB == Key₃₁..Key₂₄
    /// [10] == Block  5 LSB == Key₂₃..Key₁₆
    /// [ 9] == Block  4 MSB == Key₁₅..Key₀₈
    /// [ 8] == Block  4 LSB == Key₀₇..Key₀₀
    /// [ 7] == Block  3 MSB == ID₃₁..ID₂₄
    /// [ 6] == Block  3 LSB == ID₂₃..ID₁₆
    /// [ 5] == Block  2 MSB == ID₁₅..ID₀₈
    /// [ 4] == Block  2 LSB == ID₀₇..ID₀₀
    /// [ 3] == Block  1 MSB == L₁ L₀ UM1₂₉..UM1₂₄
    /// [ 2] == Block  1 LSB == UM1₂₃..UM1₁₆
    /// [ 1] == Block  0 MSB == UM1₁₅..UM1₀₈
    /// [ 0] == Block  0 LSB == UM1₀₇..UM1₀₀
    /// </summary>
    /// <remarks>
    /// When moving to C++, strongly consider adding
    /// const helper functions to extract a given
    /// block of data into native uint16_t.
    /// See also the print_info_result() function
    /// for visual presentation of the data.
    /// </remarks>
    uint8_t Raw[32];
} em4x70_tag_info;

// result from CMD_LF_EM4X70_AUTH is defined in ID48LIB (id48.h) as ID48LIB_GRN 

typedef struct _em4x70_cmd_helper_options {
    // variables named based on default value (zero-init) being false
    uint32_t use_parity : 1;             // default is false ... no parity
    uint32_t disable_error_output : 1;   // default is false ... errors/warnings are output using PrintAndLogEx()
    uint32_t disable_all_output   : 1;   // default is false ... success often his output using PrintAndLogEx()
    uint32_t : 29; // padding
} em4x70_cmd_helper_options;


static int CmdHelp(const char *Cmd);

static void fill_buffer_prng_bytes(void* buffer, size_t byte_count) {
    if (byte_count <= 0) return;
    srand((unsigned) time(NULL));
    for (size_t i = 0; i < byte_count; i++) {
        ((uint8_t*)buffer)[i] = (uint8_t)rand();
    }
}
static void print_info_result(const em4x70_tag_info *data) {
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Tag Information") " ---------------------------");
    PrintAndLogEx(INFO, "Block |   data   | info");
    PrintAndLogEx(INFO, "------+----------+-----------------------------");
    PrintAndLogEx(INFO, " %2d   |   %02X %02X  |  %s", 15, data->Raw[31], data->Raw[30], "UM2");
    PrintAndLogEx(INFO, " %2d   |   %02X %02X  |  %s", 14, data->Raw[29], data->Raw[28], "UM2");
    PrintAndLogEx(INFO, " %2d   |   %02X %02X  |  %s", 13, data->Raw[27], data->Raw[26], "UM2");
    PrintAndLogEx(INFO, " %2d   |   %02X %02X  |  %s", 12, data->Raw[25], data->Raw[24], "UM2");
    PrintAndLogEx(INFO, "------+----------+-----------------------------");
    PrintAndLogEx(INFO, " %2d   |   -- --  |  %s",     11,                               "PIN write only");
    PrintAndLogEx(INFO, " %2d   |   -- --  |  %s",     10,                               "PIN write only");
    PrintAndLogEx(INFO, "------+----------+-----------------------------");
    PrintAndLogEx(INFO, " %2d   |   -- --  |  %s",      9,                               "KEY write only");
    PrintAndLogEx(INFO, " %2d   |   -- --  |  %s",      8,                               "KEY write only");
    PrintAndLogEx(INFO, " %2d   |   -- --  |  %s",      7,                               "KEY write only");
    PrintAndLogEx(INFO, " %2d   |   -- --  |  %s",      6,                               "KEY write only");
    PrintAndLogEx(INFO, " %2d   |   -- --  |  %s",      5,                               "KEY write only");
    PrintAndLogEx(INFO, " %2d   |   -- --  |  %s",      4,                               "KEY write only");
    PrintAndLogEx(INFO, "------+----------+-----------------------------");
    PrintAndLogEx(INFO, " %2d   |   %02X %02X  |  %s",  3, data->Raw[ 7], data->Raw[ 6], "ID");
    PrintAndLogEx(INFO, " %2d   |   %02X %02X  |  %s",  2, data->Raw[ 5], data->Raw[ 4], "ID");
    PrintAndLogEx(INFO, "------+----------+-----------------------------");
    PrintAndLogEx(INFO, " %2d   |   %02X %02X  |  %s",  1, data->Raw[ 3], data->Raw[ 2], "UM1");
    PrintAndLogEx(INFO, " %2d   |   %02X %02X  |  %s",  0, data->Raw[ 1], data->Raw[ 0], "UM1");
    PrintAndLogEx(INFO, "------+----------+-----------------------------");
    PrintAndLogEx(INFO, "");

    PrintAndLogEx(INFO, "Tag ID:    %02X %02X %02X %02X", data->Raw[7], data->Raw[6], data->Raw[5], data->Raw[4]);
    PrintAndLogEx(INFO, "Lockbit 0: %d", (data->Raw[3] & LOCKBIT_0) ? 1 : 0);
    PrintAndLogEx(INFO, "Lockbit 1: %d", (data->Raw[3] & LOCKBIT_1) ? 1 : 0);
    PrintAndLogEx(INFO, "Tag is %s.", (data->Raw[3] & LOCKBIT_0) ? _RED_("LOCKED") : _GREEN_("UNLOCKED"));
    PrintAndLogEx(INFO, "");

    PrintAndLogEx(NORMAL, "");
}

// Helper functions to simplify building more complex interactions.
// (without creating fake `const char * Cmd` arrays.)
// These functions use 100% explicit arguments.
// If a parameter is an output parameter, the name ends with `_out`.

static int get_em4x70_info(em4x70_cmd_helper_options opts, em4x70_tag_info * data_out) {

    memset(data_out, 0, sizeof(em4x70_tag_info));

    em4x70_data_t edata = { .parity = opts.use_parity };
    clearCommandBuffer();
    SendCommandNG(CMD_LF_EM4X70_INFO, (uint8_t *)&edata, sizeof(em4x70_data_t));

    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_LF_EM4X70_INFO, &resp, TIMEOUT)) {
        if (!opts.disable_error_output) {
            PrintAndLogEx(WARNING, "(em4x70) Timeout while waiting for reply.");
        }
        return PM3_ETIMEOUT;
    }
    if (resp.status) {
        memcpy(data_out, resp.data.asBytes, sizeof(em4x70_tag_info));
        return PM3_SUCCESS;
    }
    return PM3_ESOFT;
}
static int write_em4x70_block(em4x70_cmd_helper_options opts, em4x70_tag_info* data_out, int block, uint16_t value) {

    memset(data_out, 0, sizeof(em4x70_tag_info));

    em4x70_data_t etd = {0};
    etd.address = (uint8_t) block;
    etd.word = value; // ISSUE: Presumes client and target are both little-endian
    etd.parity = opts.use_parity;

    clearCommandBuffer();
    SendCommandNG(CMD_LF_EM4X70_WRITE, (uint8_t *)&etd, sizeof(etd));

    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_LF_EM4X70_WRITE, &resp, TIMEOUT)) {
        if (!opts.disable_error_output) {
            PrintAndLogEx(WARNING, "Timeout while waiting for reply.");
        }
        return PM3_ETIMEOUT;
    }

    if (resp.status) {
        memcpy(data_out, resp.data.asBytes, sizeof(em4x70_tag_info));
        return PM3_SUCCESS;
    }
    if (!opts.disable_error_output) {
        PrintAndLogEx(FAILED, "Writing " _RED_("Failed"));
    }
    return PM3_ESOFT;
}
static int auth_em4x70(em4x70_cmd_helper_options opts, ID48LIB_GRN* data_out, const ID48LIB_NONCE* rn, const ID48LIB_FRN* frn) {
    memset(data_out, 0, sizeof(ID48LIB_GRN));

    em4x70_data_t etd = {0};
    etd.parity = opts.use_parity;
    memcpy(&etd.rnd[0],  &rn->rn[0],   7);
    memcpy(&etd.frnd[0], &frn->frn[0], 4);
    
    clearCommandBuffer();
    SendCommandNG(CMD_LF_EM4X70_AUTH, (uint8_t *)&etd, sizeof(etd));

    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_LF_EM4X70_AUTH, &resp, TIMEOUT)) {
        if (!opts.disable_error_output) {
            PrintAndLogEx(WARNING, "Timeout while waiting for reply.");
        }
        return PM3_ETIMEOUT;
    }
    if (resp.status) {
        // Response is 20-bit from tag

        // HACKHACK -- It appears the byte order differs from what is expected?
        data_out->grn[0] = resp.data.asBytes[2];
        data_out->grn[1] = resp.data.asBytes[1];
        data_out->grn[2] = resp.data.asBytes[0];
        //memcpy(data_out, &resp.data.asBytes[0], sizeof(ID48LIB_GRN));
        return PM3_SUCCESS;
    }
    if (!opts.disable_error_output) {
        PrintAndLogEx(FAILED, "TAG Authentication " _RED_("Failed"));
    }
    return PM3_ESOFT;
}
static int writekey_em4x70(em4x70_cmd_helper_options opts, ID48LIB_KEY* key) {

    em4x70_data_t etd = {0};
    etd.parity = opts.use_parity;
    memcpy(&etd.crypt_key[0], &key->k[0], 12);

    clearCommandBuffer();
    SendCommandNG(CMD_LF_EM4X70_WRITEKEY, (uint8_t *)&etd, sizeof(etd));

    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_LF_EM4X70_WRITEKEY, &resp, TIMEOUT)) {
        if (!opts.disable_error_output) {
            PrintAndLogEx(WARNING, "Timeout while waiting for reply.");
        }
        return PM3_ETIMEOUT;
    }

    if (resp.status) {
        return PM3_SUCCESS;
    }
    if (!opts.disable_error_output) {
        PrintAndLogEx(FAILED, "Writing new key: " _RED_("failed"));
    }
    return PM3_ESOFT;

}

// Note: arm source has a function with same name ... different signature.
static int em4x70_info(em4x70_cmd_helper_options opts) {
    em4x70_tag_info info;
    int result = get_em4x70_info(opts, &info);
    if (result == PM3_SUCCESS) {
        print_info_result(&info);
    }
    return result;
}

//quick test for EM4x70 tag
bool detect_4x70_block(void) {
    em4x70_tag_info info;
    em4x70_cmd_helper_options opts = {
        .use_parity = false,
        .disable_error_output = true,
        // .disable_all_output = false, // legacy version did not do this, so information on the tag gets dumped
    };
    return get_em4x70_info(opts, &info) == PM3_SUCCESS;
}

// TODO: Create unique set of structures to replace em4x70_data_t, one structure defined per command.
//       This will make it much clearer what fields are used for each command.
// TODO: Optional: use those unique structures in a union, call it em4x70_data_t, but add a first
//       common header field that includes the command itself (to improve debugging / validation).
// TODO: split the below functions between parameter validation vs. actual client/firmware comms,
//       so can use the client/firmware comms helper functions as building blocks for more complex
//       interactions without generating fake `const char *Cmd` strings.
//       Helper functions should take all relevant parameters explicitly as inputs.
//       Don't hide what's happening behind global state changes ... be explicit.
//       SPECIFICALLY: Modify writekey to ***VERIFY*** the key was written to the tag.

int CmdEM4x70Info(const char *Cmd) {

    // envoke reading of a EM4x70 tag which has to be on the antenna because
    // decoding is done by the device (not on client side)
    CLIParserContext *ctx;

    CLIParserInit(&ctx, "lf em 4x70 info",
                  "Tag Information EM4x70\n"
                  "  Tag variants include ID48 automotive transponder.\n"
                  "  ID48 does not use command parity (default).\n"
                  "  V4070 and EM4170 do require parity bit.",
                  "lf em 4x70 info\n"
                  "lf em 4x70 info --par -> adds parity bit to command\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0(NULL, "par", "Add parity bit when sending commands"),
        arg_param_end
    };

    CLIExecWithReturn(ctx, Cmd, argtable, true);
    em4x70_cmd_helper_options opts = {
        .use_parity = arg_get_lit(ctx, 0),
    };
    CLIParserFree(ctx);

    // Client command line parsing and validation complete ... now use the helper function
    return em4x70_info(opts);
}

int CmdEM4x70Write(const char *Cmd) {

    // write one block/word (16 bits) to the tag at given block address (0-15)
    CLIParserContext *ctx;

    CLIParserInit(&ctx, "lf em 4x70 write",
                  "Write EM4x70\n",
                  "lf em 4x70 write -b 15 -d c0de       -> write 'c0de' to block 15\n"
                  "lf em 4x70 write -b 15 -d c0de --par -> adds parity bit to commands\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0(NULL, "par",    "Add parity bit when sending commands"),
        arg_int1("b",  "block",  "<dec>", "block/word address, dec"),
        arg_str1("d",  "data",   "<hex>", "data, 2 bytes"),
        arg_param_end
    };

    CLIExecWithReturn(ctx, Cmd, argtable, true);


    em4x70_tag_info info;
    em4x70_cmd_helper_options opts = {
        .use_parity = arg_get_lit(ctx, 1),
    };

    int addr = arg_get_int_def(ctx, 2, 1);
    uint8_t data[2] = {0x0};
    int data_len = 0;
    CLIGetHexWithReturn(ctx, 3, data, &data_len);
    CLIParserFree(ctx);


    if (addr < 0 || addr >= EM4X70_NUM_BLOCKS) {
        PrintAndLogEx(FAILED, "block has to be within range [0, 15] got: %d", addr);
        return PM3_EINVARG;
    }
    if (data_len != 2) {
        PrintAndLogEx(FAILED, "word/data length must be 2 bytes. got: %d", data_len);
        return PM3_EINVARG;
    }


    // Client command line parsing and validation complete ... now use the helper function
    uint16_t value = BYTES2UINT16(data);
    int result = write_em4x70_block(opts, &info, addr, value);
    if (result == PM3_SUCCESS) {
        print_info_result(&info);
    }
    return result;
}
 
// not yet updated to use helper functions
int CmdEM4x70Brute(const char *Cmd) {

    // From paper "Dismantling Megamos Crypto", Roel Verdult, Flavio D. Garcia and Barıs¸ Ege.
    // Partial Key-Update Attack (optimized version)
    em4x70_data_t etd = {0};

    CLIParserContext *ctx;

    CLIParserInit(&ctx, "lf em 4x70 brute",
                  "Optimized partial key-update attack of 16-bit key block 7, 8 or 9 of an EM4x70\n"
                  "This attack does NOT write anything to the tag.\n"
                  "Before starting this attack, 0000 must be written to the 16-bit key block: 'lf em 4x70 write -b 9 -d 0000'.\n"
                  "After success, the 16-bit key block have to be restored with the key found: 'lf em 4x70 write -b 9 -d c0de'\n",
                  "lf em 4x70 brute -b 9 --rnd 45F54ADA252AAC --frn 4866BB70    --> bruteforcing key bits k95...k80\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0(NULL, "par", "Add parity bit when sending commands"),
        arg_int1("b",  "block",  "<dec>", "block/word address, dec"),
        arg_str1(NULL, "rnd", "<hex>", "Random 56-bit"),
        arg_str1(NULL, "frn", "<hex>", "F(RN) 28-bit as 4 hex bytes"),
        arg_str0("s", "start", "<hex>", "Start bruteforce enumeration from this key value"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    etd.parity = arg_get_lit(ctx, 1);

    int addr = arg_get_int_def(ctx, 2, 0);
    if (addr < 7 || addr > 9) {
        PrintAndLogEx(FAILED, "block has to be within range [7, 9] got: %d", addr);
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }
    etd.address = (uint8_t) addr;

    int rnd_len = 7;
    CLIGetHexWithReturn(ctx, 3, etd.rnd, &rnd_len);

    int frnd_len = 4;
    CLIGetHexWithReturn(ctx, 4, etd.frnd, &frnd_len);

    uint32_t start_key = 0;
    int res = arg_get_u32_hexstr_def_nlen(ctx, 5, 0, &start_key, 2, true);
    if (res == 2) {
        PrintAndLogEx(WARNING, "start key parameter must be in range [0, FFFF]");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }
    etd.start_key = start_key;

    CLIParserFree(ctx);

    if (rnd_len != 7) {
        PrintAndLogEx(FAILED, "Random number length must be 7 bytes instead of %d", rnd_len);
        return PM3_EINVARG;
    }

    if (frnd_len != 4) {
        PrintAndLogEx(FAILED, "F(RN) length must be 4 bytes instead of %d", frnd_len);
        return PM3_EINVARG;
    }

    PrintAndLogEx(INFO, "Press " _GREEN_("pm3 button") " or " _GREEN_("<Enter>") " to exit");
    clearCommandBuffer();
    PacketResponseNG resp;
    SendCommandNG(CMD_LF_EM4X70_BRUTE, (uint8_t *)&etd, sizeof(etd));

    uint32_t timeout = 0;
    for (;;) {

        if (kbd_enter_pressed()) {
            SendCommandNG(CMD_BREAK_LOOP, NULL, 0);
            PrintAndLogEx(DEBUG, "User aborted");
            break;
        }

        if (WaitForResponseTimeout(CMD_LF_EM4X70_BRUTE, &resp, TIMEOUT)) {
            if (resp.status) {
                // Response is 16-bit partial key
                PrintAndLogEx(INFO, "Partial Key Response: %02X %02X", resp.data.asBytes[0], resp.data.asBytes[1]);
                return PM3_SUCCESS;
            }
            break;
        }

        // should be done in about 60 minutes.
        if (timeout > ((60 * 60000) / TIMEOUT)) {
            PrintAndLogEx(WARNING, "\nNo response from Proxmark3. Aborting...");
            break;
        }
        timeout++;
    }

    PrintAndLogEx(FAILED, "Bruteforce of partial key " _RED_("failed"));
    return PM3_ESOFT;
}

// not yet updated to use helper functions
int CmdEM4x70Unlock(const char *Cmd) {

    // send pin code to device, unlocking it for writing
    em4x70_data_t etd = {0};

    CLIParserContext *ctx;

    CLIParserInit(&ctx, "lf em 4x70 unlock",
                  "Unlock EM4x70 by sending PIN\n"
                  "Default pin may be:\n"
                  " AAAAAAAA\n"
                  " 00000000\n",
                  "lf em 4x70 unlock -p 11223344 -> Unlock with PIN\n"
                  "lf em 4x70 unlock -p 11223344 --par -> Unlock with PIN using parity commands\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0(NULL, "par", "Add parity bit when sending commands"),
        arg_str1("p",  "pin", "<hex>", "pin, 4 bytes"),
        arg_param_end
    };

    CLIExecWithReturn(ctx, Cmd, argtable, true);

    etd.parity = arg_get_lit(ctx, 1);

    int pin_len = 0;
    uint8_t pin[4] = {0x0};

    CLIGetHexWithReturn(ctx, 2, pin, &pin_len);

    CLIParserFree(ctx);

    if (pin_len != 4) {
        PrintAndLogEx(FAILED, "PIN length must be 4 bytes instead of %d", pin_len);
        return PM3_EINVARG;
    }

    etd.pin = BYTES2UINT32(pin);

    clearCommandBuffer();
    SendCommandNG(CMD_LF_EM4X70_UNLOCK, (uint8_t *)&etd, sizeof(etd));

    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_LF_EM4X70_UNLOCK, &resp, TIMEOUT)) {
        PrintAndLogEx(WARNING, "Timeout while waiting for reply.");
        return PM3_ETIMEOUT;
    }

    if (resp.status) {
        em4x70_tag_info* q = (em4x70_tag_info*)resp.data.asBytes;
        print_info_result(q);
        return PM3_SUCCESS;
    }

    PrintAndLogEx(FAILED, "Unlocking tag " _RED_("failed"));
    return PM3_ESOFT;
}

int CmdEM4x70Auth(const char *Cmd) {

    // Authenticate transponder
    // Send 56-bit random number + pre-computed f(rnd, k) to transponder.
    // Transponder will respond with a response
    CLIParserContext *ctx;

    CLIParserInit(&ctx, "lf em 4x70 auth",
                  "Authenticate against an EM4x70 by sending random number (RN) and F(RN)\n"
                  "  If F(RN) is incorrect based on the tag key, the tag will not respond\n"
                  "  If F(RN) is correct based on the tag key, the tag will give a 20-bit response\n",
                  "lf em 4x70 auth --rnd 45F54ADA252AAC --frn 4866BB70     --> (using pm3 test key)\n"
                  "lf em 4x70 auth --rnd 3FFE1FB6CC513F --frn F355F1A0     --> (using research paper key)\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0(NULL, "par", "Add parity bit when sending commands"),
        arg_str1(NULL, "rnd", "<hex>", "Random 56-bit"),
        arg_str1(NULL, "frn", "<hex>", "F(RN) 28-bit as 4 hex bytes"),
        arg_param_end
    };

    CLIExecWithReturn(ctx, Cmd, argtable, true);

    em4x70_cmd_helper_options opts = {
        .use_parity = arg_get_lit(ctx, 1),
    };
    ID48LIB_NONCE rn;
    ID48LIB_FRN frn;

    int rn_len = 7;
    CLIGetHexWithReturn(ctx, 2, &rn.rn[0], &rn_len);

    int frn_len = 4;
    CLIGetHexWithReturn(ctx, 3, &frn.frn[0], &frn_len);
    CLIParserFree(ctx);
    if (rn_len != 7) {
        PrintAndLogEx(FAILED, "Random number length must be 7 bytes instead of %d", rn_len);
        return PM3_EINVARG;
    }
    if (frn_len != 4) {
        PrintAndLogEx(FAILED, "F(RN) length must be 4 bytes instead of %d", frn_len);
        return PM3_EINVARG;
    }

    // Client command line parsing and validation complete ... now use the helper function
    ID48LIB_GRN grn;
    int result = auth_em4x70(opts, &grn, &rn, &frn);
    if (PM3_SUCCESS == result) {
        PrintAndLogEx(INFO, "Tag Auth Response: %02X %02X %02X", grn.grn[0], grn.grn[1], grn.grn[2]);
    }
    return result;

}

// not yet updated to use helper functions
int CmdEM4x70WritePIN(const char *Cmd) {

    em4x70_data_t etd = {0};

    CLIParserContext *ctx;

    CLIParserInit(&ctx, "lf em 4x70 writepin",
                  "Write PIN\n",
                  "lf em 4x70 writepin -p 11223344 -> Write PIN\n"
                  "lf em 4x70 writepin -p 11223344 --par -> Write PIN using parity commands\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0(NULL, "par", "Add parity bit when sending commands"),
        arg_str1("p",  "pin", "<hex>", "pin, 4 bytes"),
        arg_param_end
    };

    CLIExecWithReturn(ctx, Cmd, argtable, true);

    etd.parity = arg_get_lit(ctx, 1);

    int pin_len = 0;
    uint8_t pin[4] = {0x0};

    CLIGetHexWithReturn(ctx, 2, pin, &pin_len);

    CLIParserFree(ctx);

    if (pin_len != 4) {
        PrintAndLogEx(FAILED, "PIN length must be 4 bytes instead of %d", pin_len);
        return PM3_EINVARG;
    }

    etd.pin = BYTES2UINT32(pin);

    clearCommandBuffer();
    SendCommandNG(CMD_LF_EM4X70_WRITEPIN, (uint8_t *)&etd, sizeof(etd));

    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_LF_EM4X70_WRITEPIN, &resp, TIMEOUT)) {
        PrintAndLogEx(WARNING, "Timeout while waiting for reply.");
        return PM3_ETIMEOUT;
    }

    if (resp.status) {
        em4x70_tag_info* q = (em4x70_tag_info*)resp.data.asBytes;
        print_info_result(q);
        PrintAndLogEx(INFO, "Writing new PIN: " _GREEN_("ok"));
        return PM3_SUCCESS;
    }

    PrintAndLogEx(FAILED, "Writing new PIN: " _RED_("failed"));
    return PM3_ESOFT;
}

int CmdEM4x70WriteKey(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf em 4x70 writekey",
                  "Write new 96-bit key to tag\n",
                  "lf em 4x70 writekey -k F32AA98CF5BE4ADFA6D3480B   (pm3 test key)\n"
                  "lf em 4x70 writekey -k A090A0A02080000000000000   (research paper key)\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0(NULL, "par", "Add parity bit when sending commands"),
        arg_str1("k",  "key", "<hex>", "Key as 12 hex bytes"),
        arg_param_end
    };

    CLIExecWithReturn(ctx, Cmd, argtable, true);

    em4x70_cmd_helper_options opts = {
        .use_parity = arg_get_lit(ctx, 1),
    };
    ID48LIB_KEY key;
    int key_len = 12;
    if (CLIParamHexToBuf(arg_get_str(ctx, 2), &key.k[0], sizeof(ID48LIB_KEY), &key_len)) {
        CLIParserFree((ctx));
        return PM3_ESOFT;
    }
    CLIParserFree(ctx);
    if (key_len != 12) {
        PrintAndLogEx(FAILED, "Key length must be 12 bytes instead of %d", key_len);
        return PM3_EINVARG;
    }

    // Client command line parsing and validation complete ... now use the helper function
    int result = writekey_em4x70(opts, &key);
    if (PM3_SUCCESS == result) {
        PrintAndLogEx(INFO, "Writing new key: " _GREEN_("ok"));

        // TODO: authenticate using this new key to ensure it was correctly written
        ID48LIB_NONCE rn;
        fill_buffer_prng_bytes(&rn.rn[0], 7);
        ID48LIB_FRN frn;
        ID48LIB_GRN grn;
        ID48LIB_GRN tag_grn;
        id48lib_generator(&key, &rn, &frn, &grn);

        // dump the auth command to the screen, to enable the user to manually check validity
        PrintAndLogEx(INFO,
            "Verifying auth for new key: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x"
            " -->  " _YELLOW_("lf em 4x70 auth --rnd %02X%02X%02X%02X%02X%02X%02X --frn %02X%02X%02X%02X")
            " --> %02X%02X%02X",
            key.k[ 0], key.k[ 1], key.k[ 2], key.k[ 3], key.k[ 4], key.k[ 5],
            key.k[ 6], key.k[ 7], key.k[ 8], key.k[ 9], key.k[10], key.k[11],
            rn.rn[0],
            rn.rn[1],
            rn.rn[2],
            rn.rn[3],
            rn.rn[4],
            rn.rn[5],
            rn.rn[6],
            frn.frn[0],
            frn.frn[1],
            frn.frn[2],
            frn.frn[3],
            grn.grn[0],
            grn.grn[1],
            grn.grn[2]
            );
        result = auth_em4x70(opts, &tag_grn, &rn, &frn);
        if (PM3_SUCCESS != result) {
            PrintAndLogEx(FAILED, "Authenticating with new key: " _RED_("failed"));
        } else if (memcmp(&grn, &tag_grn, sizeof(ID48LIB_GRN)) != 0) {
            PrintAndLogEx(FAILED, "Authenticating with new key returned %02x %02x %02x, expected %02x %02x %02x (torn write): " _RED_("failed"),
                tag_grn.grn[0], tag_grn.grn[1], tag_grn.grn[2],
                grn.grn[0], grn.grn[1], grn.grn[2]
                );
        } else {
            PrintAndLogEx(INFO, "Authenticating with new key: " _GREEN_("ok"));
        }
    }
    return result;
}

// largest seen "in the wild" was 6
#define MAXIMUM_ID48_RECOVERED_KEY_COUNT 10
typedef struct _em4x70_recovery_data_t {
    ID48LIB_KEY   key;
    ID48LIB_NONCE nonce;
    ID48LIB_FRN   frn;
    ID48LIB_GRN   grn;
    bool verify; // if true, tag must be present
    bool parity; // if true, add parity bit to commands sent to tag

    uint8_t       keys_found_count;
    uint8_t       keys_validated_count;
    ID48LIB_KEY   potential_keys[MAXIMUM_ID48_RECOVERED_KEY_COUNT];
    ID48LIB_NONCE alt_nonce;
    ID48LIB_FRN   alt_frn[MAXIMUM_ID48_RECOVERED_KEY_COUNT];
    ID48LIB_GRN   alt_grn[MAXIMUM_ID48_RECOVERED_KEY_COUNT];
    bool          potential_keys_validated[MAXIMUM_ID48_RECOVERED_KEY_COUNT];
} em4x70_recovery_data_t;

static int CmdEM4x70Recover_ParseArgs(const char *Cmd, em4x70_recovery_data_t* out_results) {
    memset(out_results, 0, sizeof(em4x70_recovery_data_t));

    int result = PM3_SUCCESS;
    
    CLIParserContext *ctx;
    CLIParserInit(
        &ctx,
        "lf em 4x70 recover",
        "After obtaining key bits 95..48 (such as via 'lf em 4x70 brute'), this command will recover\n"
        "key bits 47..00.  By default, this process does NOT require a tag to be present.\n"
        "\n"
        "By default, the potential keys are shown (typically 1-6) along with a corresponding\n"
        "'lf em 4x70 auth' command that will authenticate, if that potential key is correct.\n"
        "The user can copy/paste these commands when the tag is present to manually check\n"
        "which of the potential keys is correct.\n"
        //   "\n"
        //   "If the `--verify` option is provided, the tag must be present.  The rnd/frn parameters will\n"
        //   "be used to authenticate against the tag, and then any potential keys will be automatically\n"
        //   "be checked for correctness against the tag, reducing manual steps.\n"
        ,
        "lf em 4x70 recover --key F32AA98CF5BE --rnd 45F54ADA252AAC --frn 4866BB70 --grn 9BD180   (pm3 test key)\n"
        "lf em 4x70 recover --key A090A0A02080 --rnd 3FFE1FB6CC513F --frn F355F1A0 --grn 609D60   (research paper key)\n"
        );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0(NULL, "par",    "Add parity bit when sending commands"),
        arg_str1("k",  "key",    "<hex>", "Key as 6 hex bytes"),
        arg_str1(NULL, "rnd",    "<hex>", "Random 56-bit"),
        arg_str1(NULL, "frn",    "<hex>", "F(RN) 28-bit as 4 hex bytes"),
        arg_str1(NULL, "grn",    "<hex>", "G(RN) 20-bit as 3 hex bytes"),
        //arg_lit0(NULL, "verify", "automatically use tag for validation"),
        arg_param_end
    };

    // do the command line arguments even parse?
    if (CLIParserParseString(ctx, Cmd, argtable, arg_getsize(argtable), true)) {
        result = PM3_ESOFT;
    }
    int key_len  = 0; // must be 6 bytes hex data
    int rnd_len  = 0; // must be 7 bytes hex data
    int frn_len = 0; // must be 4 bytes hex data
    int grn_len = 0; // must be 3 bytes hex data

    // if all OK so far, convert to internal data structure
    if (PM3_SUCCESS == result) {
        // magic number == index in argtable above.  Fragile technique!
        out_results->parity = arg_get_lit(ctx, 1);
        if (CLIParamHexToBuf(arg_get_str(ctx, 2), &(out_results->key.k[0]), 12, &key_len)) {
            result = PM3_ESOFT;
        }
        if (CLIParamHexToBuf(arg_get_str(ctx, 3), &(out_results->nonce.rn[0]), 7, &rnd_len)) {
            result = PM3_ESOFT;
        }
        if (CLIParamHexToBuf(arg_get_str(ctx, 4), &(out_results->frn.frn[0]), 4, &frn_len)) {
            result = PM3_ESOFT;
        }
        if (CLIParamHexToBuf(arg_get_str(ctx, 5), &(out_results->grn.grn[0]), 3, &grn_len)) {
            result = PM3_ESOFT;
        }
        //out_results->verify = arg_get_lit(ctx, 6); 
    }
    // if all OK so far, do additional parameter validation
    if (PM3_SUCCESS == result) {
        // Validate number of bytes read for hex data
        if (key_len != 6) {
            PrintAndLogEx(FAILED, "Key length must be 6 bytes instead of %d", key_len);
            result = PM3_EINVARG;
        }
        if (rnd_len != 7) {
            PrintAndLogEx(FAILED, "Random number length must be 7 bytes instead of %d", rnd_len);
            result = PM3_EINVARG;
        }
        if (frn_len != 4) {
            PrintAndLogEx(FAILED, "F(RN) length must be 4 bytes instead of %d", frn_len);
            result = PM3_EINVARG;
        }
        if (grn_len != 3) {
            PrintAndLogEx(FAILED, "G(RN) length must be 3 bytes instead of %d", grn_len);
            result = PM3_EINVARG;
        }
    }

    if (PM3_SUCCESS == result) {
        fill_buffer_prng_bytes(&out_results->alt_nonce, sizeof(ID48LIB_NONCE));
    }

    // single exit point
    CLIParserFree(ctx);
    return result;
}
int CmdEM4x70Recover(const char *Cmd) {
    // From paper "Dismantling Megamos Crypto", Roel Verdult, Flavio D. Garcia and Barıs¸ Ege.
    // Partial Key-Update Attack -- final 48 bits (after optimized version gets k95..k48)
    em4x70_recovery_data_t recover_ctx = {0};
    int result = PM3_SUCCESS;
    
    result = CmdEM4x70Recover_ParseArgs(Cmd, &recover_ctx);
    // recover the potential keys -- no more than a few seconds
    if (PM3_SUCCESS == result) {
        // The library is stateful.  First must initialize its internal context.
        id48lib_key_recovery_init(&recover_ctx.key, &recover_ctx.nonce, &recover_ctx.frn, &recover_ctx.grn);

        // repeatedly call id48lib_key_recovery_next() to get the next potential key
        ID48LIB_KEY q;
        while ((PM3_SUCCESS == result) && id48lib_key_recovery_next(&q)) {
            if (recover_ctx.keys_found_count >= MAXIMUM_ID48_RECOVERED_KEY_COUNT) {
                PrintAndLogEx(ERR, "Found more than %d potential keys. This is unexpected and likely a code failure.", MAXIMUM_ID48_RECOVERED_KEY_COUNT);
                result = PM3_EFAILED;
            } else {
                recover_ctx.potential_keys[recover_ctx.keys_found_count] = q;
                ++recover_ctx.keys_found_count;
            }
        }
        if (recover_ctx.keys_found_count == 0) {
            PrintAndLogEx(ERR, "No potential keys recovered.  This is unexpected and likely a code failure.");
            result = PM3_EFAILED;
        }
    }
    // generate alternate authentication for each potential key -- sub-second execution, no error paths
    if (PM3_SUCCESS == result) {
        for (uint8_t i = 0; i < recover_ctx.keys_found_count; ++i) {
            // generate the alternate frn/grn for the alternate nonce
            id48lib_generator(&recover_ctx.potential_keys[i], &recover_ctx.alt_nonce, &recover_ctx.alt_frn[i], &recover_ctx.alt_grn[i]);
        }
    }
    // display alternate authentication for each potential key -- no error paths
    if (PM3_SUCCESS == result) {
        PrintAndLogEx(INFO, "Recovered %d potential keys:", recover_ctx.keys_found_count);
        for (uint8_t i = 0; i < recover_ctx.keys_found_count; ++i) {
            // generate an alternative authentication based on the potential key
            // and the alternate nonce.
            ID48LIB_KEY q = recover_ctx.potential_keys[i];
            ID48LIB_FRN alt_frn = recover_ctx.alt_frn[i];
            ID48LIB_GRN alt_grn = recover_ctx.alt_grn[i];

            // dump the results to screen, to enable the user to manually check validity
            PrintAndLogEx(INFO,
                "Potential Key #%d: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x"
                " -->  " _YELLOW_("lf em 4x70 auth --rnd %02X%02X%02X%02X%02X%02X%02X --frn %02X%02X%02X%02X")
                " --> %02X%02X%02X",
                i,
                q.k[ 0], q.k[ 1], q.k[ 2], q.k[ 3], q.k[ 4], q.k[ 5],
                q.k[ 6], q.k[ 7], q.k[ 8], q.k[ 9], q.k[10], q.k[11],
                recover_ctx.alt_nonce.rn[0],
                recover_ctx.alt_nonce.rn[1],
                recover_ctx.alt_nonce.rn[2],
                recover_ctx.alt_nonce.rn[3],
                recover_ctx.alt_nonce.rn[4],
                recover_ctx.alt_nonce.rn[5],
                recover_ctx.alt_nonce.rn[6],
                alt_frn.frn[0],
                alt_frn.frn[1],
                alt_frn.frn[2],
                alt_frn.frn[3],
                alt_grn.grn[0],
                alt_grn.grn[1],
                alt_grn.grn[2]
                );
        }
        printf("\n");
    }
    if (PM3_SUCCESS == result && recover_ctx.verify) {
        // TODO: automatic verification against a present tag.
        // Updates ctx.potential_keys_validated[10] and ctx.keys_validated_count
        PrintAndLogEx(WARNING, "Automatic verification against tag is not yet implemented.");
        // 0. verify a tag is present
        // 1. verify the parameters provided authenticate against the tag
        //    if not, print "Authentication failed.  Verify the current tag matches parameters provided."
        //    print the authentication command used (allows user to easily copy/paste)
        //    SET ERROR
        // 2. for each potential key:
        //    a. Attempt to authentic against the tag using alt_nonce and alt_frn[i]
        //    b. verify tag's response is alt_grn[i]
        //    c. if successful, set ctx.potential_keys_validated[i] = true and increment ctx.keys_validated_count
        //
        // All validation done... now just interpret the results....
        //
        // 3. if ctx.keys_validated_count == 0, print "No keys recovered.  Check tag for good coupling (position, etc)?"
        // 4. if ctx.keys_validated_count >= 2, print "Multiple keys recovered.  Run command again (will use different alt nonce)?"
        // 5. if ctx.keys_validated_count == 1, print "Found key: " ...
    }


    return result;
}

static command_t CommandTable[] = {
    {"help",     CmdHelp,           AlwaysAvailable, "This help"},
    {"brute",    CmdEM4x70Brute,    IfPm3EM4x70,     "Bruteforce EM4X70 to find partial key"},
    {"info",     CmdEM4x70Info,     IfPm3EM4x70,     "Tag information EM4x70"},
    {"write",    CmdEM4x70Write,    IfPm3EM4x70,     "Write EM4x70"},
    {"unlock",   CmdEM4x70Unlock,   IfPm3EM4x70,     "Unlock EM4x70 for writing"},
    {"auth",     CmdEM4x70Auth,     IfPm3EM4x70,     "Authenticate EM4x70"},
    {"writepin", CmdEM4x70WritePIN, IfPm3EM4x70,     "Write PIN"},
    {"writekey", CmdEM4x70WriteKey, IfPm3EM4x70,     "Write key"},
    {"recover",  CmdEM4x70Recover,  IfPm3EM4x70,     "Recover remaining key from partial key"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdLFEM4X70(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}
