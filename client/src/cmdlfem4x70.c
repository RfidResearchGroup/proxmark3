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
#include "util_posix.h" // msleep()

#define LOCKBIT_0 BITMASK(6)
#define LOCKBIT_1 BITMASK(7)

#define BYTE_ARRAY_INDEX_TO_BLOCK(x) ((31-(x))/2)

// TODO: Optional: use those unique structures in a union, call it em4x70_data_t, but add a first
//       common header field that includes the command itself (to improve debugging / validation).
typedef struct _em4x70_tag_info_t {
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
} em4x70_tag_info_t;

typedef struct _em4x70_cmd_input_info_t {
    uint8_t use_parity;
} em4x70_cmd_input_info_t;
typedef struct _em4x70_cmd_input_writeblock_t {
    uint8_t use_parity;
    uint8_t block;
    uint8_t value[2];
} em4x70_cmd_input_writeblock_t;

typedef struct _em4x70_cmd_input_brute_t {
    uint8_t use_parity;
    ID48LIB_NONCE rn;
    ID48LIB_FRN frn;
    uint8_t block;
    uint8_t partial_key_start[2];
} em4x70_cmd_input_brute_t;
typedef struct _em4x70_cmd_output_brute_t {
    /// <summary>
    /// The returned data is big endian (MSB first).
    /// For block 9:
    ///     partial_key[0] == Key₉₅..Key₈₈ == Block  9 MSB
    ///     partial_key[1] == Key₈₇..Key₈₀ == Block  9 LSB
    /// For block 8:
    ///     partial_key[0] == Key₇₉..Key₇₂ == Block  8 MSB
    ///     partial_key[1] == Key₇₁..Key₆₄ == Block  8 LSB
    /// For block 7:
    ///     partial_key[15] == Key₆₃..Key₅₆ == Block  7 MSB
    ///     partial_key[14] == Key₅₅..Key₄₈ == Block  7 LSB
    /// </summary>
    uint8_t partial_key[2];
} em4x70_cmd_output_brute_t;

typedef struct _em4x70_cmd_input_unlock_t {
    uint8_t use_parity;
    uint8_t pin[4];
} em4x70_cmd_input_unlock_t;

typedef struct _em4x70_cmd_input_auth_t {
    uint8_t use_parity;
    ID48LIB_NONCE rn;
    ID48LIB_FRN frn;
} em4x70_cmd_input_auth_t;
typedef struct _em4x70_cmd_output_auth_t {
    ID48LIB_GRN grn;
} em4x70_cmd_output_auth_t;

typedef struct _em4x70_cmd_input_writepin_t {
    uint8_t use_parity;
    uint8_t pin[4];
} em4x70_cmd_input_writepin_t;

typedef struct _em4x70_cmd_input_writekey_t {
    uint8_t use_parity;
    ID48LIB_KEY key;
} em4x70_cmd_input_writekey_t;
// There is no output data when writing a new key
typedef struct _em4x70_cmd_input_recover_t {
    ID48LIB_KEY   key;  // only the first 6 bytes (48 bits) are considered valid
    ID48LIB_NONCE nonce;
    ID48LIB_FRN   frn;
    ID48LIB_GRN   grn;
    bool parity; // if true, add parity bit to commands sent to tag
    bool verify; // if true, tag must be present
} em4x70_cmd_input_recover_t;
// largest seen "in the wild" was 6
#define MAXIMUM_ID48_RECOVERED_KEY_COUNT 10
typedef struct _em4x70_cmd_output_recover_t {
    uint8_t potential_key_count;
    ID48LIB_KEY potential_keys[MAXIMUM_ID48_RECOVERED_KEY_COUNT];
} em4x70_cmd_output_recover_t;
typedef struct _em4x70_cmd_input_verify_auth_t {
    uint8_t use_parity;
    ID48LIB_NONCE rn;
    ID48LIB_FRN frn;
    ID48LIB_GRN grn;
} em4x70_cmd_input_verify_auth_t;



static int CmdHelp(const char *Cmd);

static void fill_buffer_prng_bytes(void *buffer, size_t byte_count) {
    if (byte_count <= 0) return;
    srand((unsigned) time(NULL));
    for (size_t i = 0; i < byte_count; i++) {
        ((uint8_t *)buffer)[i] = (uint8_t)rand();
    }
}
static void print_info_result(const em4x70_tag_info_t *data) {
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

static int get_em4x70_info(const em4x70_cmd_input_info_t *opts, em4x70_tag_info_t *data_out) {

    memset(data_out, 0, sizeof(em4x70_tag_info_t));

    // TODO: change firmware to use per-cmd structures
    em4x70_data_t edata = { .parity = opts->use_parity };
    clearCommandBuffer();
    SendCommandNG(CMD_LF_EM4X70_INFO, (uint8_t *)&edata, sizeof(em4x70_data_t));

    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_LF_EM4X70_INFO, &resp, TIMEOUT)) {
        return PM3_ETIMEOUT;
    }
    if (resp.status) {
        memcpy(data_out, resp.data.asBytes, sizeof(em4x70_tag_info_t));
        return PM3_SUCCESS;
    }
    return PM3_ESOFT;
}
static int writeblock_em4x70(const em4x70_cmd_input_writeblock_t *opts, em4x70_tag_info_t *data_out) {

    memset(data_out, 0, sizeof(em4x70_tag_info_t));

    // TODO: change firmware to use per-cmd structures
    em4x70_data_t etd = {0};
    etd.address = opts->block;
    etd.word = BYTES2UINT16(opts->value);
    etd.parity = opts->use_parity;

    clearCommandBuffer();
    SendCommandNG(CMD_LF_EM4X70_WRITE, (uint8_t *)&etd, sizeof(etd));

    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_LF_EM4X70_WRITE, &resp, TIMEOUT)) {
        return PM3_ETIMEOUT;
    }

    if (resp.status) {
        memcpy(data_out, resp.data.asBytes, sizeof(em4x70_tag_info_t));
        return PM3_SUCCESS;
    }
    return PM3_ESOFT;
}
static int auth_em4x70(const em4x70_cmd_input_auth_t *opts, em4x70_cmd_output_auth_t *data_out) {
    memset(data_out, 0, sizeof(ID48LIB_GRN));

    // TODO: change firmware to use per-cmd structures
    em4x70_data_t etd = {0};
    etd.parity = opts->use_parity;
    memcpy(&etd.rnd[0],  &opts->rn.rn[0],   7);
    memcpy(&etd.frnd[0], &opts->frn.frn[0], 4);

    clearCommandBuffer();
    SendCommandNG(CMD_LF_EM4X70_AUTH, (uint8_t *)&etd, sizeof(etd));

    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_LF_EM4X70_AUTH, &resp, TIMEOUT)) {
        return PM3_ETIMEOUT;
    }
    if (resp.status) {
        // Response is 20-bit from tag

        // HACKHACK -- It appears the byte order differs from what is expected?
        data_out->grn.grn[0] = resp.data.asBytes[2];
        data_out->grn.grn[1] = resp.data.asBytes[1];
        data_out->grn.grn[2] = resp.data.asBytes[0];
        //memcpy(data_out, &resp.data.asBytes[0], sizeof(ID48LIB_GRN));
        return PM3_SUCCESS;
    }
    return PM3_ESOFT;
}
static int writekey_em4x70(const em4x70_cmd_input_writekey_t *opts) {

    // TODO: change firmware to use per-cmd structures
    em4x70_data_t etd = {0};
    etd.parity = opts->use_parity;
    memcpy(&etd.crypt_key[0], &opts->key.k[0], 12);

    clearCommandBuffer();
    SendCommandNG(CMD_LF_EM4X70_WRITEKEY, (uint8_t *)&etd, sizeof(etd));

    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_LF_EM4X70_WRITEKEY, &resp, TIMEOUT)) {
        return PM3_ETIMEOUT;
    }
    if (resp.status) {
        return PM3_SUCCESS;
    }
    return PM3_ESOFT;
}
static int brute_em4x70(const em4x70_cmd_input_brute_t *opts, em4x70_cmd_output_brute_t *data_out) {
    memset(data_out, 0, sizeof(em4x70_cmd_output_brute_t));

    // TODO: change firmware to use per-cmd structures
    em4x70_data_t etd = {0};
    etd.parity = opts->use_parity;
    etd.address = opts->block;
    memcpy(&etd.rnd[0],  &opts->rn.rn[0],   7);
    memcpy(&etd.frnd[0], &opts->frn.frn[0], 4);

    // TODO: FIX THIS MESS WITH BYTE ORDER CHANGING BACK AND FORTH!
    //       Just use byte arrays when sending to the firmware.
    //       Lowers the cognitive load AND makes it easier to understand.
    // opts structure stored value in BIG ENDIAN
    // Note that the FIRMWARE side will swap the byte order back to BIG ENDIAN.
    // (yes, this is a bit of a mess, but it is what it is for now...)
    uint16_t start_key_be = (opts->partial_key_start[0] << 8) | opts->partial_key_start[1];
    etd.start_key = start_key_be;

    clearCommandBuffer();
    PacketResponseNG resp;
    SendCommandNG(CMD_LF_EM4X70_BRUTE, (uint8_t *)&etd, sizeof(etd));

    uint32_t timeout = 0;
    for (;;) {

        if (kbd_enter_pressed()) {
            SendCommandNG(CMD_BREAK_LOOP, NULL, 0);
            return PM3_EOPABORTED;
        }

        if (WaitForResponseTimeout(CMD_LF_EM4X70_BRUTE, &resp, TIMEOUT)) {
            if (resp.status) {
                memcpy(data_out, resp.data.asBytes, sizeof(em4x70_cmd_output_brute_t));
                return PM3_SUCCESS;
            }
            return PM3_ESOFT;
        }

        // NOTE: It takes about 11 seconds per 0x0100 authentication attempts.
        //       Thus, each block takes a maximum of 256 * 11 seconds == 46m56s.
        //       A timeout of 60 minutes corresponds to ~14 seconds per 0x0100 auths,
        //       which is ~25% margin.  Plus, on average, it takes half that
        //       amount of time (for a random value in the key block).
        if (timeout > ((60u * 60000u) / TIMEOUT)) {
            PrintAndLogEx(WARNING, "\nNo response from Proxmark3. Aborting...");
            return PM3_ETIMEOUT;
        }
        timeout++;
    }
}
static int unlock_em4x70(const em4x70_cmd_input_unlock_t *opts, em4x70_tag_info_t *data_out) {
    memset(data_out, 0, sizeof(em4x70_tag_info_t));

    // TODO: change firmware to use per-cmd structures
    em4x70_data_t etd = {0};
    etd.parity = opts->use_parity;
    etd.pin = BYTES2UINT32(opts->pin);

    clearCommandBuffer();
    SendCommandNG(CMD_LF_EM4X70_UNLOCK, (uint8_t *)&etd, sizeof(etd));

    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_LF_EM4X70_UNLOCK, &resp, TIMEOUT)) {
        return PM3_ETIMEOUT;
    }

    if (resp.status) {
        memcpy(data_out, resp.data.asBytes, sizeof(em4x70_tag_info_t));
        return PM3_SUCCESS;
    }
    return PM3_ESOFT;

}
static int writepin_em4x70(const em4x70_cmd_input_writepin_t *opts, em4x70_tag_info_t *data_out) {
    memset(data_out, 0, sizeof(em4x70_tag_info_t));

    // TODO: change firmware to use per-cmd structures
    em4x70_data_t etd = {0};
    etd.parity = opts->use_parity;
    etd.pin = BYTES2UINT32(opts->pin);

    clearCommandBuffer();
    SendCommandNG(CMD_LF_EM4X70_WRITEPIN, (uint8_t *)&etd, sizeof(etd));

    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_LF_EM4X70_WRITEPIN, &resp, TIMEOUT)) {
        return PM3_ETIMEOUT;
    }
    if (resp.status) {
        memcpy(data_out, resp.data.asBytes, sizeof(em4x70_tag_info_t));
        return PM3_SUCCESS;
    }
    return PM3_ESOFT;
}
static int recover_em4x70(const em4x70_cmd_input_recover_t *opts, em4x70_cmd_output_recover_t *data_out) {
    memset(data_out, 0, sizeof(em4x70_cmd_output_recover_t));

    // The library is stateful.  First must initialize its internal context.
    id48lib_key_recovery_init(&opts->key, &opts->nonce, &opts->frn, &opts->grn);

    // repeatedly call id48lib_key_recovery_next() to get the next potential key
    ID48LIB_KEY q;
    int result = PM3_SUCCESS;
    while ((PM3_SUCCESS == result) && id48lib_key_recovery_next(&q)) {
        if (data_out->potential_key_count >= MAXIMUM_ID48_RECOVERED_KEY_COUNT) {
            result = PM3_EOVFLOW;
        } else {
            data_out->potential_keys[data_out->potential_key_count] = q;
            ++data_out->potential_key_count;
        }
    }
    if ((PM3_SUCCESS == result) && (data_out->potential_key_count == 0)) {
        result = PM3_EFAILED;
    }
    return result;
}
static int verify_auth_em4x70(const em4x70_cmd_input_verify_auth_t *opts) {
    em4x70_cmd_input_auth_t opts_auth = {
        .use_parity = opts->use_parity,
        .rn = opts->rn,
        .frn = opts->frn,
    };
    em4x70_cmd_output_auth_t tag_grn;
    int result = auth_em4x70(&opts_auth, &tag_grn);
    if (PM3_SUCCESS == result) {
        if (memcmp(&opts->grn, &tag_grn, sizeof(ID48LIB_GRN)) != 0) {
            result = PM3_EWRONGANSWER;
        }
    }
    return result;
}

// used by `lf search` and `search`, this is a quick test for EM4x70 tag
// In alignment with other tags implementations, this also dumps basic information
// about the tag, if one is found.
// Use helper function `get_em4x70_info()` if wanting to limit / avoid output.
bool detect_4x70_block(void) {
    em4x70_tag_info_t info;
    em4x70_cmd_input_info_t opts = { 0 };
    int result = get_em4x70_info(&opts, &info);
    if (result == PM3_ETIMEOUT) { // consider removing this output?
        PrintAndLogEx(WARNING, "(em4x70) Timeout while waiting for reply.");
    }
    return result == PM3_SUCCESS;
}

int CmdEM4x70Info(const char *Cmd) {

    // invoke reading of a EM4x70 tag which has to be on the antenna because
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
    em4x70_cmd_input_info_t opts = {
        .use_parity = arg_get_lit(ctx, 0),
    };
    CLIParserFree(ctx);

    // Client command line parsing and validation complete ... now use the helper function
    em4x70_tag_info_t info;
    int result = get_em4x70_info(&opts, &info);
    if (result == PM3_ETIMEOUT) {
        PrintAndLogEx(WARNING, "(em4x70) Timeout while waiting for reply.");
    } else if (result == PM3_SUCCESS) {
        print_info_result(&info);
    } else {
        PrintAndLogEx(FAILED, "Reading " _RED_("Failed"));
    }
    return result;
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


    em4x70_cmd_input_writeblock_t opts = {
        .use_parity = arg_get_lit(ctx, 1),
        .block = arg_get_int_def(ctx, 2, 1),
        .value = {0}, // hex value macro exits function, so cannot be initialized here
    };
    int value_len = 0;
    CLIGetHexWithReturn(ctx, 3, opts.value, &value_len);
    CLIParserFree(ctx);

    if (opts.block >= EM4X70_NUM_BLOCKS) {
        PrintAndLogEx(FAILED, "block has to be within range [0, 15] got: %d", opts.block);
        return PM3_EINVARG;
    }
    if (value_len != 2) {
        PrintAndLogEx(FAILED, "word/data length must be 2 bytes. got: %d", value_len);
        return PM3_EINVARG;
    }

    // Client command line parsing and validation complete ... now use the helper function
    em4x70_tag_info_t info;
    int result = writeblock_em4x70(&opts, &info);
    if (result == PM3_ETIMEOUT) {
        PrintAndLogEx(WARNING, "(em4x70) Timeout while waiting for reply.");
    } else if (result == PM3_SUCCESS) {
        print_info_result(&info);
    } else {
        PrintAndLogEx(FAILED, "Writing " _RED_("Failed"));
    }
    return result;
}

int CmdEM4x70Brute(const char *Cmd) {

    // From paper "Dismantling Megamos Crypto", Roel Verdult, Flavio D. Garcia and Barıs¸ Ege.
    // Partial Key-Update Attack (optimized version)
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

    em4x70_cmd_input_brute_t opts = {
        .use_parity = arg_get_lit(ctx, 1),
        .block = arg_get_int_def(ctx, 2, 0),
        .rn = {{0}},                // hex value macro exits function, so cannot be initialized here
        .frn = {{0}},               // hex value macro exits function, so cannot be initialized here
        .partial_key_start = {0},   // hex value macro exits function, so cannot be initialized here
    };

    if (opts.block < 7 || opts.block > 9) {
        PrintAndLogEx(FAILED, "block has to be within range [7, 9] got: %d", opts.block);
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    int rnd_len = 7;
    CLIGetHexWithReturn(ctx, 3, opts.rn.rn, &rnd_len);

    int frnd_len = 4;
    CLIGetHexWithReturn(ctx, 4, opts.frn.frn, &frnd_len);

    // would prefer to use above CLIGetHexWithReturn(), but it does not
    // appear to support optional arguments.
    uint32_t start_key = 0;
    int res = arg_get_u32_hexstr_def_nlen(ctx, 5, 0, &start_key, 2, true); // this stores in NATIVE ENDIAN
    if (res == 2) {
        PrintAndLogEx(WARNING, "start key parameter must be in range [0, FFFF]");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }
    CLIParserFree(ctx);

    // opts structure takes value in BIG ENDIAN form
    opts.partial_key_start[0] = (uint8_t)((start_key >>  8) & 0xFF);
    opts.partial_key_start[1] = (uint8_t)((start_key >>  0) & 0xFF);

    if (rnd_len != 7) {
        PrintAndLogEx(FAILED, "Random number length must be 7 bytes instead of %d", rnd_len);
        return PM3_EINVARG;
    }

    if (frnd_len != 4) {
        PrintAndLogEx(FAILED, "F(RN) length must be 4 bytes instead of %d", frnd_len);
        return PM3_EINVARG;
    }

    // Client command line parsing and validation complete ... now use the helper function
    PrintAndLogEx(INFO, "Press " _GREEN_("pm3 button") " or " _GREEN_("<Enter>") " to exit");
    em4x70_cmd_output_brute_t data;
    int result = brute_em4x70(&opts, &data);
    if (result == PM3_EOPABORTED) {
        PrintAndLogEx(DEBUG, "User aborted");
    } else if (result == PM3_ETIMEOUT) {
        PrintAndLogEx(WARNING, "\nNo response from Proxmark3. Aborting...");
    } else if (result == PM3_SUCCESS) {
        PrintAndLogEx(INFO, "Partial Key Response: %02X %02X", data.partial_key[0], data.partial_key[1]);
    } else {
        PrintAndLogEx(FAILED, "Bruteforce of partial key " _RED_("failed"));
    }
    return result;
}

int CmdEM4x70Unlock(const char *Cmd) {

    // send pin code to device, unlocking it for writing
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

    em4x70_cmd_input_unlock_t opts = {
        .use_parity = arg_get_lit(ctx, 1),
        .pin = {0}, // hex value macro exits function, so cannot be initialized here
    };
    int pin_len = 0;
    CLIGetHexWithReturn(ctx, 2, opts.pin, &pin_len);
    CLIParserFree(ctx);

    if (pin_len != 4) {
        PrintAndLogEx(FAILED, "PIN length must be 4 bytes instead of %d", pin_len);
        return PM3_EINVARG;
    }

    // Client command line parsing and validation complete ... now use the helper function
    em4x70_tag_info_t info;
    int result = unlock_em4x70(&opts, &info);
    if (result == PM3_ETIMEOUT) {
        PrintAndLogEx(WARNING, "Timeout while waiting for reply.");
    } else if (result == PM3_SUCCESS) {
        print_info_result(&info);
    } else {
        PrintAndLogEx(FAILED, "Unlocking tag " _RED_("Failed"));
    }
    return result;
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

    em4x70_cmd_input_auth_t opts = {
        .use_parity = arg_get_lit(ctx, 1),
        .rn = {{0}},                // hex value macro exits function, so cannot be initialized here
        .frn = {{0}},               // hex value macro exits function, so cannot be initialized here
    };
    int rn_len = 7;
    CLIGetHexWithReturn(ctx, 2, opts.rn.rn,   &rn_len);

    int frn_len = 4;
    CLIGetHexWithReturn(ctx, 3, opts.frn.frn, &frn_len);
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
    em4x70_cmd_output_auth_t data;
    int result = auth_em4x70(&opts, &data);
    if (PM3_SUCCESS == result) {
        PrintAndLogEx(INFO, "Tag Auth Response: %02X %02X %02X", data.grn.grn[0], data.grn.grn[1], data.grn.grn[2]);
    } else if (PM3_ETIMEOUT == result) {
        PrintAndLogEx(WARNING, "Timeout while waiting for reply.");
    } else {
        PrintAndLogEx(FAILED, "TAG Authentication " _RED_("Failed"));
    }
    return result;
}

int CmdEM4x70WritePIN(const char *Cmd) {
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

    em4x70_cmd_input_writepin_t opts = {
        .use_parity = arg_get_lit(ctx, 1),
        .pin = {0}, // hex value macro exits function, so cannot be initialized here
    };

    int pin_len = 0;
    CLIGetHexWithReturn(ctx, 2, opts.pin, &pin_len);
    CLIParserFree(ctx);

    if (pin_len != 4) {
        PrintAndLogEx(FAILED, "PIN length must be 4 bytes instead of %d", pin_len);
        return PM3_EINVARG;
    }

    // Client command line parsing and validation complete ... now use the helper function
    em4x70_tag_info_t info;
    int result = writepin_em4x70(&opts, &info);
    if (result == PM3_ETIMEOUT) {
        PrintAndLogEx(WARNING, "Timeout while waiting for reply.");
    } else if (result == PM3_SUCCESS) {
        print_info_result(&info);
        PrintAndLogEx(INFO, "Writing new PIN: " _GREEN_("ok"));
    } else {
        PrintAndLogEx(FAILED, "Writing new PIN: " _RED_("failed"));
    }
    return result;
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

    em4x70_cmd_input_writekey_t opts = {
        .use_parity = arg_get_lit(ctx, 1),
        .key = {{0}}, // hex value macro exits function, so cannot be initialized here
    };
    int key_len = 12;
    CLIGetHexWithReturn(ctx, 2, opts.key.k, &key_len);
    CLIParserFree(ctx);
    if (key_len != 12) {
        PrintAndLogEx(FAILED, "Key length must be 12 bytes instead of %d", key_len);
        return PM3_EINVARG;
    }

    // Client command line parsing and validation complete ... now use the helper function
    int result = writekey_em4x70(&opts);
    if (PM3_ETIMEOUT == result) {
        PrintAndLogEx(WARNING, "Timeout while waiting for reply.");
        return PM3_ETIMEOUT;
    } else if (PM3_SUCCESS != result) {
        PrintAndLogEx(FAILED, "Writing new key: " _RED_("failed"));
        return result;
    }

    PrintAndLogEx(INFO, "Writing new key: " _GREEN_("ok"));

    // Now verify authentication using the new key, to ensure it was correctly written
    em4x70_cmd_input_verify_auth_t opts_v = {
        .use_parity = opts.use_parity,
        //.rn = opts_auth.rn,
        //.frn = opts_auth.frn,
        //.grn = {{0}},
    };
    fill_buffer_prng_bytes(&opts_v.rn, sizeof(ID48LIB_NONCE));
    id48lib_generator(&opts.key, &opts_v.rn, &opts_v.frn, &opts_v.grn);

    // dump the auth command to the screen, to enable the user to manually check validity
    PrintAndLogEx(INFO,
                  "Verifying auth for new key: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x"
                  " -->  " _YELLOW_("lf em 4x70 auth --rnd %02X%02X%02X%02X%02X%02X%02X --frn %02X%02X%02X%02X")
                  " --> %02X%02X%02X",
                  opts.key.k[ 0], opts.key.k[ 1], opts.key.k[ 2], opts.key.k[ 3], opts.key.k[ 4], opts.key.k[ 5],
                  opts.key.k[ 6], opts.key.k[ 7], opts.key.k[ 8], opts.key.k[ 9], opts.key.k[10], opts.key.k[11],
                  opts_v.rn.rn[0],
                  opts_v.rn.rn[1],
                  opts_v.rn.rn[2],
                  opts_v.rn.rn[3],
                  opts_v.rn.rn[4],
                  opts_v.rn.rn[5],
                  opts_v.rn.rn[6],
                  opts_v.frn.frn[0],
                  opts_v.frn.frn[1],
                  opts_v.frn.frn[2],
                  opts_v.frn.frn[3],
                  opts_v.grn.grn[0],
                  opts_v.grn.grn[1],
                  opts_v.grn.grn[2]
                 );
    result = verify_auth_em4x70(&opts_v);
    if (PM3_ETIMEOUT == result) {
        PrintAndLogEx(WARNING, "Timeout while waiting for reply.");
        return result;
    } else if (PM3_SUCCESS != result) {
        PrintAndLogEx(FAILED, "Authenticating with new key: " _RED_("failed"));
        return result;
    } else {
        PrintAndLogEx(INFO, "Authenticating with new key: " _GREEN_("ok"));
    }
    return result;
}

typedef struct _em4x70_recovery_data_t {

    em4x70_cmd_input_recover_t opts;
    em4x70_cmd_output_recover_t data;

    uint8_t       keys_validated_count;
    ID48LIB_NONCE alt_nonce;
    ID48LIB_FRN   alt_frn[MAXIMUM_ID48_RECOVERED_KEY_COUNT];
    ID48LIB_GRN   alt_grn[MAXIMUM_ID48_RECOVERED_KEY_COUNT];
    bool          potential_keys_validated[MAXIMUM_ID48_RECOVERED_KEY_COUNT];
} em4x70_recovery_data_t;

static int CmdEM4x70Recover_ParseArgs(const char *Cmd, em4x70_cmd_input_recover_t *out_results) {
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

    result = CmdEM4x70Recover_ParseArgs(Cmd, &recover_ctx.opts);
    // recover the potential keys -- no more than a few seconds
    if (PM3_SUCCESS == result) {
        result = recover_em4x70(&recover_ctx.opts, &recover_ctx.data);
        if (PM3_EOVFLOW == result) {
            PrintAndLogEx(ERR, "Found more than %d potential keys. This is unexpected and likely a code failure.", MAXIMUM_ID48_RECOVERED_KEY_COUNT);
        } else if (PM3_SUCCESS != result) {
            PrintAndLogEx(ERR, "No potential keys recovered.  This is unexpected and likely a code failure.");
        }
    }
    // generate alternate authentication for each potential key -- no error paths, sub-second execution
    if (PM3_SUCCESS == result) {
        fill_buffer_prng_bytes(&recover_ctx.alt_nonce, sizeof(ID48LIB_NONCE));
        for (uint8_t i = 0; i < recover_ctx.data.potential_key_count; ++i) {
            // generate the alternate frn/grn for the alternate nonce
            id48lib_generator(&recover_ctx.data.potential_keys[i], &recover_ctx.alt_nonce, &recover_ctx.alt_frn[i], &recover_ctx.alt_grn[i]);
        }
    }
    // display alternate authentication for each potential key -- no error paths
    if (PM3_SUCCESS == result) {
        PrintAndLogEx(INFO, "Recovered %d potential keys:", recover_ctx.data.potential_key_count);
        for (uint8_t i = 0; i < recover_ctx.data.potential_key_count; ++i) {
            // generate an alternative authentication based on the potential key
            // and the alternate nonce.
            ID48LIB_KEY q = recover_ctx.data.potential_keys[i];
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
    // which of those keys actually validates?
    if (PM3_SUCCESS == result && recover_ctx.opts.verify) {
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

static int CmdEM4x70AutoRecover_ParseArgs(const char *Cmd, em4x70_cmd_input_recover_t *out_results) {
    memset(out_results, 0, sizeof(em4x70_cmd_input_recover_t));

    int result = PM3_SUCCESS;
    //  The following key is found quickly, and has multiple potential keys.
    //  Useful for quicker testing, as this function could take over 2 hours.
    //      lf em 4x70 writekey -k 001200340055BAADCAFEF00D
    //      lf em 4x70 autorecover --rnd 1782779E7E3BC8 --frn 00357080 --grn F3C480
    CLIParserContext *ctx;
    CLIParserInit(
        &ctx,
        "lf em 4x70 autorecover",
        "This command will perform automatic recovery of the key from a writable tag.\n"
        "All steps are possible to do manually.  The corresponding sequence, if done\n"
        "manually, is as follows:\n"
        "1. Verify passed parameters authenticate with the tag (safety check)\n"
        "   " _YELLOW_("lf em 4x70 auth --rnd <rnd_1> --frn <frn_1>") "\n"
        "2. Brute force the key bits in block 9\n"
        "   " _YELLOW_("lf em 4x70 write -b 9 -d 0000") "\n"
        "   " _YELLOW_("lf em 4x70 recover -b 9 --rnd <rnd_1> --frn <frn_1>") "\n"
        "   " _YELLOW_("lf em 4x70 write -b 9 -d <key_block_9>") "\n"
        "3. Brute force the key bits in block 8\n"
        "   " _YELLOW_("lf em 4x70 write -b 8 -d 0000") "\n"
        "   " _YELLOW_("lf em 4x70 recover -b 8 --rnd <rnd_1> --frn <frn_1>") "\n"
        "   " _YELLOW_("lf em 4x70 write -b 8 -d <key_block_8>") "\n"
        "4. Brute force the key bits in block 7\n"
        "   " _YELLOW_("lf em 4x70 write -b 7 -d 0000)") "\n"
        "   " _YELLOW_("lf em 4x70 recover -b 7 --rnd <rnd_1> --frn <frn_1>") "\n"
        "   " _YELLOW_("lf em 4x70 write -b 7 -d <key_block_7>") "\n"
        "5. Recover potential values of the lower 48 bits of the key\n"
        "   " _YELLOW_("lf em 4x70 recover --key <key_block_9><key_block_8><key_block_7> --rnd <rnd_1> --frn <frn_1>") "\n"
        "6. Verify which potential key is actually on the tag (using a different rnd/frn combination)\n"
        "   " _YELLOW_("lf em 4x70 auth --rnd <rnd_2> --frn <frn_N>") "\n"
        "7. Print the validated key\n"
        "\n"
        "This command simply requires the rnd/frn/grn from a single known-good authentication.\n"
        "\n"
        ""
        //   "\n"
        //   "If the `--verify` option is provided, the tag must be present.  The rnd/frn parameters will\n"
        //   "be used to authenticate against the tag, and then any potential keys will be automatically\n"
        //   "be checked for correctness against the tag, reducing manual steps.\n"
        ,
        "lf em 4x70 autorecover --rnd 45F54ADA252AAC --frn 4866BB70 --grn 9BD180   (pm3 test key)\n"
        "lf em 4x70 autorecover --rnd 3FFE1FB6CC513F --frn F355F1A0 --grn 609D60   (research paper key)\n"
    );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0(NULL, "par",    "Add parity bit when sending commands"),
        arg_str1(NULL, "rnd",    "<hex>", "Random 56-bit from known-good authentication"),
        arg_str1(NULL, "frn",    "<hex>", "F(RN) 28-bit as 4 hex bytes from known-good authentication"),
        arg_str1(NULL, "grn",    "<hex>", "G(RN) 20-bit as 3 hex bytes from known-good authentication"),
        //arg_lit0(NULL, "verify", "automatically use tag for validation"),
        arg_param_end
    };

    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int rnd_len = 0; // must be 7 bytes hex data
    int frn_len = 0; // must be 4 bytes hex data
    int grn_len = 0; // must be 3 bytes hex data
    out_results->parity = arg_get_lit(ctx, 1);
    CLIGetHexWithReturn(ctx, 2, out_results->nonce.rn, &rnd_len);
    CLIGetHexWithReturn(ctx, 3, out_results->frn.frn, &frn_len);
    CLIGetHexWithReturn(ctx, 4, out_results->grn.grn, &grn_len);
    CLIParserFree(ctx);

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

    return result;
}
static int CmdEM4x70AutoRecover(const char *Cmd) {
    em4x70_cmd_input_recover_t opts = {0};
    em4x70_cmd_output_recover_t data = {0};
    em4x70_tag_info_t tag_info = {0};
    int result = CmdEM4x70AutoRecover_ParseArgs(Cmd, &opts);
    // 0. Parse the command line
    if (PM3_SUCCESS != result) {
        return result;
    }

    // The parameters are valid.  Per Iceman's direct request, the code has been updated
    // to immediately exit on errors.  Unfortunately, this requirement limits the clarity
    // of summarizing the failure (and providing options for recovery in case of failures)
    // at a single point at the end of the function.  It will also undoubtedly reduce
    // code coverage numbers, when those are tracked.
    //
    // As to clarity, if failures occurred in steps 2-4, it was expected that the cleanup
    // code would, in a single location, verify if the original authentication worked.
    // If so, then the tag was left in a good state (even if an error occurred).
    // If not, then at least it would be possible for the user to restart manually, and
    // to be given clear instructions on how to do that to return the tag to its original
    // state.
    //
    // TODO: Wrap this entire function in another function, whose sole purpose is to
    //       perform that additional cleanup?   Not a great solution.  Pity, as the
    //       cleanup code was much more helpful than the below print statements.
    int last_successful_step = 0;
    char rnd_string[14 + 1] = {0};
    char frn_string[ 8 + 1] = {0};
    char grn_string[ 6 + 1] = {0};
    // These strings will be re-used often, are safe to pre-allocate, and make later PrintAndLogEx() calls cleaner.
    snprintf(rnd_string, 15, "%02X%02X%02X%02X%02X%02X%02X", opts.nonce.rn[0], opts.nonce.rn[1], opts.nonce.rn[2], opts.nonce.rn[3], opts.nonce.rn[4], opts.nonce.rn[5], opts.nonce.rn[6]);
    snprintf(frn_string, 9, "%02X%02X%02X%02X", opts.frn.frn[0], opts.frn.frn[1], opts.frn.frn[2], opts.frn.frn[3]);
    snprintf(grn_string, 7, "%02X%02X%02X", opts.grn.grn[0], opts.grn.grn[1], opts.grn.grn[2]);

    // 1. Verify passed parameters authenticate with the tag (safety check)
    //    lf em 4x70 auth --rnd <rnd_1> --frn <frn_1>
    if (PM3_SUCCESS == result) {
        PrintAndLogEx(INFO, "Step 1. Verifying passed parameters authenticate with the tag (safety check)");
        PrintAndLogEx(HINT, "        " _YELLOW_("lf em 4x70 auth --rnd %s --frn %s"), rnd_string, frn_string);
        em4x70_cmd_input_auth_t opts_auth = {
            .use_parity = opts.parity,
            .rn  = opts.nonce,
            .frn = opts.frn,
        };
        em4x70_cmd_output_auth_t tag_grn;
        result = auth_em4x70(&opts_auth, &tag_grn);
        if (PM3_ETIMEOUT == result) {
            PrintAndLogEx(WARNING, "Timeout while waiting for reply.");
            return result;
        } else if (PM3_SUCCESS != result) {
            PrintAndLogEx(FAILED, "Authenticating with provided values: " _RED_("failed"));
            return result;
        } else if (memcmp(&opts.grn, &tag_grn, sizeof(ID48LIB_GRN)) != 0) {
            PrintAndLogEx(FAILED, "Authenticating with new key returned %02x %02x %02x, expected %s (maybe 5 lsb of key wrong?): " _RED_("failed"),
                          tag_grn.grn.grn[0], tag_grn.grn.grn[1], tag_grn.grn.grn[2],
                          grn_string
                         );
            result = PM3_EWRONGANSWER;
            return result;
        }
        last_successful_step = 1;
    }

    // 2/3/4. Brute force the key bits in block 7,8,9
    //        lf em 4x70 write -b N -d 0000
    //        lf em 4x70 brute -b N --rnd <rnd_1> --frn <frn_1>
    //        lf em 4x70 write -b N -d <key_block_N>
    for (uint8_t block = 9; (PM3_SUCCESS == result) && (block > 6); --block) {
        uint8_t step =
            block == 9 ? 2 :
            block == 8 ? 3 :
            block == 7 ? 4 :
            197;
        em4x70_cmd_output_brute_t brute = {0};

        //    lf em 4x70 write   -b N -d 0000
        if (PM3_SUCCESS == result) {
            PrintAndLogEx(INFO, "Step %d. Brute force the key bits in block %d", step, block);
            PrintAndLogEx(HINT, "        " _YELLOW_("lf em 4x70 write -b %d -d 0000"), block);
            em4x70_cmd_input_writeblock_t opt_write_zeros = {
                .use_parity = opts.parity,
                .block = block,
                .value = {0x00, 0x00},
            };
            result = writeblock_em4x70(&opt_write_zeros, &tag_info);
            if (PM3_ETIMEOUT == result) {
                PrintAndLogEx(FAILED, "Timeout while waiting for reply.");
                PrintAndLogEx(HINT, "Block %d data may have been overwritten.  Manually restart at step %d.", block, step);
                return result;
            } else if (PM3_SUCCESS != result) {
                PrintAndLogEx(FAILED, "Writing block %d: " _RED_("failed") ".", block);
                PrintAndLogEx(HINT, "Block %d data was overwritten.  Manually restart at step %d.", block, step);
                return result;
            }
        }
        //    lf em 4x70 brute -b N --rnd <rnd_1> --frn <frn_1>
        if (PM3_SUCCESS == result) {
            PrintAndLogEx(HINT, "        " _YELLOW_("lf em 4x70 brute -b %d --rnd %s --frn %s"), block, rnd_string, frn_string);
            em4x70_cmd_input_brute_t opts_brute = {
                .use_parity = opts.parity,
                .block = block,
                .rn = opts.nonce,
                .frn = opts.frn,
                .partial_key_start = {0},
            };

            result = brute_em4x70(&opts_brute, &brute);
            if (PM3_ETIMEOUT == result) {
                PrintAndLogEx(FAILED, "Timeout while waiting for reply.");
                PrintAndLogEx(HINT, "Block %d data was overwritten.  Manually restart at step %d.", block, step);
                return result;
            } else if (PM3_SUCCESS != result) {
                PrintAndLogEx(FAILED, "Writing block %d: " _RED_("failed") ".");
                PrintAndLogEx(HINT, "Block %d data was overwritten.  Manually restart at step %d.", block, step);
                return result;
            } else {
                PrintAndLogEx(INFO, "        Found: Partial key in block %d is " _GREEN_("%02X%02X"), block, brute.partial_key[0], brute.partial_key[1]);
                // Save the partial key...
                if (block == 9) {
                    opts.key.k[0] = brute.partial_key[0];
                    opts.key.k[1] = brute.partial_key[1];
                } else if (block == 8) {
                    opts.key.k[2] = brute.partial_key[0];
                    opts.key.k[3] = brute.partial_key[1];
                } else if (block == 7) {
                    opts.key.k[4] = brute.partial_key[0];
                    opts.key.k[5] = brute.partial_key[1];
                }
            }
        }
        //    lf em 4x70 write   -b N -d <key_block_N>
        if (PM3_SUCCESS == result) {
            PrintAndLogEx(HINT, "        " _YELLOW_("lf em 4x70 write -b %d -d %02X%02X"), block, brute.partial_key[0], brute.partial_key[1]);
            em4x70_cmd_input_writeblock_t opt_write_zeros = {
                .use_parity = opts.parity,
                .block = block,
                .value = {brute.partial_key[0], brute.partial_key[1]},
            };
            result = writeblock_em4x70(&opt_write_zeros, &tag_info);
            if (PM3_ETIMEOUT == result) {
                PrintAndLogEx(FAILED, "Timeout while waiting for reply.");
                PrintAndLogEx(HINT, "Block %d data (" _GREEN_("%02X%02X") ") may need to be rewritten.", block, brute.partial_key[0], brute.partial_key[1]);
                return result;
            } else if (PM3_SUCCESS != result) {
                PrintAndLogEx(FAILED, "Writing block %d: " _RED_("failed") ".", block);
                PrintAndLogEx(HINT, "Block %d data (" _GREEN_("%02X%02X") ") may need to be rewritten.", block, brute.partial_key[0], brute.partial_key[1]);
                return result;
            }
        }
        if (PM3_SUCCESS == result) {
            last_successful_step = step;
        }
    }
    // The good news is that, if the above succeeded, then from this point forward, the tag remains in a known-good state.

    char key_string[24 + 1] = {0}; // holds partial key initially, full key later
    snprintf(key_string, 25, "%02X%02X%02X%02X%02X%02X", opts.key.k[0], opts.key.k[1], opts.key.k[2], opts.key.k[3], opts.key.k[4], opts.key.k[5]);

    // 5. Recover potential values of the lower 48 bits of the key
    //    lf em 4x70 recover --key <key_block_9><key_block_8><key_block_7> --rnd <rnd_1> --frn <frn_1>
    if (PM3_SUCCESS == result) {
        PrintAndLogEx(INFO, "Step 5. Recover potential values of the lower 48 bits of the key");
        PrintAndLogEx(HINT, "        " _YELLOW_("lf em 4x70 recover --key %s --rnd %s --frn %s --grn %s"), key_string, rnd_string, frn_string, grn_string);
        result = recover_em4x70(&opts, &data);
        if (PM3_EOVFLOW == result) {
            PrintAndLogEx(ERR, "Found more than %d potential keys. This is unexpected and likely a code failure.", MAXIMUM_ID48_RECOVERED_KEY_COUNT);
            return result;
        } else if (PM3_SUCCESS != result) {
            PrintAndLogEx(ERR, "No potential keys recovered.  This is unexpected and likely a code failure.");
            return result;
        } else {
            PrintAndLogEx(INFO, "        Found " _GREEN_("%d") " potential keys.", data.potential_key_count);
            for (uint8_t idx = 0; idx < data.potential_key_count; ++idx) {
                ID48LIB_KEY q = data.potential_keys[idx];
                PrintAndLogEx(DEBUG, "        Potential Key %d: %s %02X%02X%02X%02X%02X%02X",
                              idx,
                              key_string,
                              q.k[ 6], q.k[ 7], q.k[ 8], q.k[ 9], q.k[10], q.k[11]
                             );
            }
            last_successful_step = 5;
        }
    }

    // 6. Verify which potential key is actually on the tag (using a different rnd/frn combination)
    //    lf em 4x70 auth --rnd <rnd_2> --frn <frn_N>
    if (PM3_SUCCESS == result) {
        PrintAndLogEx(INFO, "Step 6. Verify which potential key is actually on the tag");
        em4x70_cmd_input_verify_auth_t opts_v = {
            .use_parity = opts.parity,
            //.rn  = {{0}},
            //.frn = {{0}},
            //.grn = {{0}},
        };

        // TODO: retry a few time, if >1 key validated with the new nonce
        bool continue_loop = true;
        bool found_one_key = false;
        bool found_more_than_one_key = false;
        uint8_t first_validated_key_idx = 0xFF;

        for (uint8_t attempt = 0; continue_loop && (attempt  < 10); ++attempt) {
            continue_loop = false;
            found_one_key = false;
            found_more_than_one_key = false;
            first_validated_key_idx = 0xFF;
            fill_buffer_prng_bytes(&opts_v.rn, sizeof(ID48LIB_NONCE));
            for (uint8_t i = 0; i < data.potential_key_count; ++i) {
                // generate the alternate frn/grn for this key + nonce combo
                id48lib_generator(&data.potential_keys[i], &opts_v.rn, &opts_v.frn, &opts_v.grn);

                int tmpResult = verify_auth_em4x70(&opts_v);
                if (PM3_SUCCESS == tmpResult) {
                    if (!found_one_key) {
                        first_validated_key_idx = i;
                        found_one_key = true;
                    } else {
                        found_more_than_one_key = true;
                    }
                }
            }
            if (!found_one_key) {
                PrintAndLogEx(WARNING, "No potential keys validated.  Will try again with different nonce.");
                continue_loop = true;
                msleep(2000); // delay 2 seconds ... in case tag was bumped, etc.
            } else if (found_more_than_one_key) {
                PrintAndLogEx(WARNING, "Multiple potential keys validated.  Will try different nonce.");
                continue_loop = true;
                msleep(2000); // delay 2 seconds ... in case tag was bumped, etc.
            } else {
                last_successful_step = 6;
            }
        }
        if ((!found_one_key) || found_more_than_one_key) {
            PrintAndLogEx(FAILED, "Unable to recover any of the multiple potential keys.  Check tag for good coupling (position, etc)?");
            return PM3_EFAILED;
        } else {
            // print the validated key to the string buffer (for step 7)
            ID48LIB_KEY q = data.potential_keys[first_validated_key_idx];
            snprintf(key_string, 25, "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",
                     q.k[ 0], q.k[ 1], q.k[ 2], q.k[ 3], q.k[ 4], q.k[ 5],
                     q.k[ 6], q.k[ 7], q.k[ 8], q.k[ 9], q.k[10], q.k[11]
                    );
        }
    }
    // 7. Print the validated key
    if (PM3_SUCCESS == result) {
        PrintAndLogEx(SUCCESS, "Recovered key: " _GREEN_("%s"), key_string);
        last_successful_step = 7;
    }

    // For posterity, step 7 used to do the following:
    // 7. Print the validated key --OR-- Print that the tag is still OK --OR-- Print instructions on what to retry to recover tag to a good state
    // If success ... print the final key
    // Else if authentication works with original rnd/frn ... print
    // Else warn user that the tag is no longer in original state, and print steps to return it to a good state.
    (void)last_successful_step;
    return result;
}


static command_t CommandTable[] = {
    {"help",        CmdHelp,               AlwaysAvailable, "This help"},
    {"brute",       CmdEM4x70Brute,        IfPm3EM4x70,     "Bruteforce EM4X70 to find partial key"},
    {"info",        CmdEM4x70Info,         IfPm3EM4x70,     "Tag information EM4x70"},
    {"write",       CmdEM4x70Write,        IfPm3EM4x70,     "Write EM4x70"},
    {"unlock",      CmdEM4x70Unlock,       IfPm3EM4x70,     "Unlock EM4x70 for writing"},
    {"auth",        CmdEM4x70Auth,         IfPm3EM4x70,     "Authenticate EM4x70"},
    {"writepin",    CmdEM4x70WritePIN,     IfPm3EM4x70,     "Write PIN"},
    {"writekey",    CmdEM4x70WriteKey,     IfPm3EM4x70,     "Write key"},
    {"recover",     CmdEM4x70Recover,      IfPm3EM4x70,     "Recover remaining key from partial key"},
    {"autorecover", CmdEM4x70AutoRecover,  IfPm3EM4x70,     "Recover entire key from writable tag"},
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
