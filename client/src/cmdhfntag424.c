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
// High frequency ISO14443A / NTAG424 DNA Commands
//-----------------------------------------------------------------------------

#include "cmdhfntag424.h"
#include <ctype.h>
#include "cmdparser.h"
#include "commonutil.h"
#include "comms.h"
#include "protocols.h"
#include "cliparser.h"
#include "cmdmain.h"
#include "fileutils.h"          // saveFile
#include "crypto/libpcrypto.h"  // aes_decode
#include "cmac.h"
#include "cmdhf14a.h"
#include "ui.h"
#include "util.h"
#include "crc32.h"

#define NTAG424_MAX_BYTES  412

static int CmdHelp(const char *Cmd);

static int CmdHF_ntag424_view(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf ntag424 view",
                  "Print a NTAG 424 DNA dump file (bin/eml/json)",
                  "hf ntag424 view -f hf-ntag424-01020304-dump.bin"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_str1("f", "file", "<fn>", "Specify a filename for dump file"),
        arg_lit0("v", "verbose", "Verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    int fnlen = 0;
    char filename[FILE_PATH_SIZE];
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);
    bool verbose = arg_get_lit(ctx, 2);
    CLIParserFree(ctx);

    // read dump file
    uint8_t *dump = NULL;
    size_t bytes_read = NTAG424_MAX_BYTES;
    int res = pm3_load_dump(filename, (void **)&dump, &bytes_read, NTAG424_MAX_BYTES);
    if (res != PM3_SUCCESS) {
        return res;
    }

    if (verbose) {
        PrintAndLogEx(INFO, "File: " _YELLOW_("%s"), filename);
        PrintAndLogEx(INFO, "File size %zu bytes", bytes_read);
    }

    free(dump);
    return PM3_SUCCESS;
}

//
// Original from  https://github.com/rfidhacking/node-sdm/
//
typedef struct sdm_picc_s {
    uint8_t tag;
    uint8_t uid[7];
    uint8_t cnt[3];
    uint32_t cnt_int;
} sdm_picc_t;

// -------------- Encryption structs ---------------------------
typedef struct {
    uint8_t ti[4];
    uint8_t rnd_a[16];
    uint8_t pd_cap2[6];
    uint8_t pcd_cap2[6];
} ntag424_ev2_response_t;

typedef struct {
    uint16_t command_counter;
    uint8_t ti[4];
    uint8_t encryption[16];
    uint8_t mac[16];
} ntag424_session_keys_t;

// -------------- File settings structs -------------------------
// Enabling this bit in the settings will also reset the read counter to 0
#define FILE_SETTINGS_OPTIONS_SDM_AND_MIRRORING (1 << 6) 

#define FILE_SETTINGS_SDM_OPTIONS_UID (1 << 7)
#define FILE_SETTINGS_SDM_OPTIONS_SDM_READ_COUNTER (1 << 6)
#define FILE_SETTINGS_SDM_OPTIONS_SDM_READ_COUNTER_LIMIT (1 << 5)
#define FILE_SETTINGS_SDM_OPTIONS_SDM_ENC_FILE_DATA (1 << 4)
#define FILE_SETTINGS_SDM_OPTIONS_ENCODING_MODE_ASCII (1 << 0)

typedef struct {
    uint8_t sdm_options;
    uint8_t sdm_access[2];
    uint8_t sdm_data[8][3];
} ntag424_file_sdm_settings_t;

typedef struct {
    uint8_t type;
    uint8_t options;
    uint8_t access[2];
    uint8_t size[3];
    ntag424_file_sdm_settings_t optional_sdm_settings;
} ntag424_file_settings_t;

#define SETTINGS_WITHOUT_SDM_DATA_SIZE (1+1+2+3+1+2)

// A different struct is used when actually writing the settings back,
// since we obviously can't change the size or type of a static file.
typedef struct {
    uint8_t options;
    uint8_t access[2];
    ntag424_file_sdm_settings_t optional_sdm_settings;
} file_settings_write_t;

// Currently unused functions, commented out due to -Wunused-function
/*static void ntag424_file_settings_set_access_rights(ntag424_file_settings_t *settings,
                                                    uint8_t read_write_key, uint8_t change_key,
                                                    uint8_t read_key, uint8_t write_key)

{
    settings->access[0] = read_write_key << 4 | change_key;
    settings->access[1] = read_key << 4 | write_key;
}*/

// Currently unused functions, commented out due to -Wunused-function
/*static void ntag424_file_settings_set_sdm_access_rights(ntag424_file_settings_t *settings,
                                                        uint8_t sdm_meta_read, uint8_t sdm_file_read, uint8_t sdm_ctr_ret)
{
    settings->optional_sdm_settings.sdm_access[1] = sdm_meta_read << 4 | sdm_file_read;
    settings->optional_sdm_settings.sdm_access[0] = 0xf << 4 | sdm_ctr_ret; // (0xf is due to reserved for future use)
}*/


static uint8_t ntag424_file_settings_get_sdm_meta_read(const ntag424_file_settings_t *settings) {
    return settings->optional_sdm_settings.sdm_access[1] >> 4;
}

static uint8_t ntag424_file_settings_get_sdm_file_read(const ntag424_file_settings_t *settings) {
    return settings->optional_sdm_settings.sdm_access[1] & 0xf;
}

// Currently unused functions, commented out due to -Wunused-function
/*static uint8_t ntag424_file_settings_get_sdm_ctr_ret(const ntag424_file_settings_t *settings) {
    return settings->optional_sdm_settings.sdm_access[0] & 4;
}*/

// Calculate the actual size of a file settings struct. A variable number of data is attached
// at the end depending on settings.
static int ntag424_calc_file_settings_size(const ntag424_file_settings_t *settings) {
    int size = 7;
    
    if(settings->options & FILE_SETTINGS_OPTIONS_SDM_AND_MIRRORING) {
        size += 3; // sdm_options and sdm_access must be present

        if(settings->optional_sdm_settings.sdm_options & FILE_SETTINGS_SDM_OPTIONS_UID &&
           ntag424_file_settings_get_sdm_meta_read(settings) == 0xe)
        {
            size += 3; // UIDOffset
        }

        if(settings->optional_sdm_settings.sdm_options & FILE_SETTINGS_SDM_OPTIONS_SDM_READ_COUNTER &&
           ntag424_file_settings_get_sdm_meta_read(settings) == 0xe)
        {
            size += 3; // SDMReadCtrOffset
        }

        if(ntag424_file_settings_get_sdm_meta_read(settings) <= 0x04) {
            size += 3; // PICCDataOffset
        }

        if(ntag424_file_settings_get_sdm_file_read(settings) != 0x0f) {
            size += 3; // SDMMacInputOffset
        }

        if(ntag424_file_settings_get_sdm_file_read(settings) != 0x0f &&
           settings->optional_sdm_settings.sdm_options & FILE_SETTINGS_SDM_OPTIONS_SDM_ENC_FILE_DATA)
        {
            size += 3; // SDMEncOffset
            size += 3; // SDMEncLength
        }

        if(ntag424_file_settings_get_sdm_file_read(settings) != 0x0f) {
            // Warning, this value has different offsets depending on
            // FILE_SETTINGS_SDM_OPTIONS_SDM_ENC_FILE_DATA
            size += 3; // SDMMacOffset
        }

        if(settings->optional_sdm_settings.sdm_options & FILE_SETTINGS_SDM_OPTIONS_SDM_READ_COUNTER_LIMIT)
        {
            size += 3; // SDMReadCtrLimit
        }  
    }

    return size;
}

static int ntag424_calc_file_write_settings_size(const ntag424_file_settings_t *settings) {
    return ntag424_calc_file_settings_size(settings) - 4;
}
    
static int ntag424_read_file_settings(uint8_t fileno, ntag424_file_settings_t *settings_out) {
    const size_t RESPONSE_LENGTH = sizeof(ntag424_file_settings_t) + 2;
    uint8_t cmd[] = { 0x90, 0xF5, 0x00, 0x00, 0x01, fileno, 0x00};
    uint8_t resp[RESPONSE_LENGTH];
    int outlen = 0;
    int res;

    res = ExchangeAPDU14a(cmd, sizeof(cmd), false, true, resp, RESPONSE_LENGTH, &outlen);
    if(res != PM3_SUCCESS)
    {
        PrintAndLogEx(ERR, "Failed to send apdu");
        return res;
    }

    if(outlen < 9) {
        PrintAndLogEx(ERR, "Incorrect response length: %d", outlen);
        return PM3_ESOFT;
    }

    if(resp[outlen-2] != 0x91 || resp[outlen-1] != 0x00)
    {
        PrintAndLogEx(ERR, "Failed to get file settings");
        return PM3_ESOFT;
    }

    if(settings_out)
    {
        memcpy(settings_out, resp, outlen-2);
    }

    return PM3_SUCCESS;
}

static void ntag424_calc_iv(ntag424_session_keys_t *session_keys, uint8_t *out_ivc) {
    uint8_t iv_clear[] = { 0xa5, 0x5a,
        session_keys->ti[0], session_keys->ti[1], session_keys->ti[2], session_keys->ti[3],
        (uint8_t)(session_keys->command_counter), (uint8_t)(session_keys->command_counter >> 8),
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    uint8_t zero_iv[16] = {0};
    aes_encode(zero_iv, session_keys->encryption, iv_clear, out_ivc, 16);
}

static void ntag424_calc_mac(ntag424_session_keys_t *session_keys, uint8_t command, uint8_t command_header, uint8_t *data, uint8_t datalen, uint8_t *out_mac) {
    uint8_t mac_input_header[] = { command,
        (uint8_t)session_keys->command_counter, (uint8_t)(session_keys->command_counter >> 8),
        session_keys->ti[0], session_keys->ti[1], session_keys->ti[2], session_keys->ti[3],
        command_header,
    };

    int mac_input_len = sizeof(mac_input_header) + datalen;

    uint8_t *mac_input = (uint8_t*)malloc(mac_input_len);
    memcpy(mac_input, mac_input_header, sizeof(mac_input_header));
    memcpy(&mac_input[sizeof(mac_input_header)], data, datalen);
    uint8_t mac[16] = {0};
    mbedtls_aes_cmac_prf_128(session_keys->mac, 16, mac_input, sizeof(mac_input_header) + datalen, mac);
    
    for(int i = 0; i < 8; i++)
    {
        out_mac[i] = mac[i*2+1];
    }

    free(mac_input);
}

static int ntag424_comm_full_encrypt_apdu(const uint8_t *apdu_in, uint8_t *apdu_out, int *apdu_out_size, ntag424_session_keys_t *session_keys)
{
#define MAC_SIZE 8
#define APDU_HEADER_SIZE 5
#define APDU_OVERHEAD (APDU_HEADER_SIZE + 1)
    
    // ------- Calculate IV
    uint8_t ivc[16];
    ntag424_calc_iv(session_keys, ivc);


    // ------- Copy apdu header
    size_t size = apdu_in[4];
    memcpy(apdu_out, apdu_in, 6);

    size_t encrypt_data_size = size - 1;
    size_t padded_data_size = encrypt_data_size + 16 - (encrypt_data_size % 16); // pad up to 16 byte blocks
    uint8_t temp_buffer[256] = {0};

    int apdu_final_size = APDU_OVERHEAD + padded_data_size + 8 + 1; // + MAC and CmdHdr
    if(*apdu_out_size < apdu_final_size)
    {
        PrintAndLogEx(ERR, "APDU out buffer not large enough");
        return PM3_EINVARG;
    }

    *apdu_out_size = apdu_final_size;

    // ------ Pad data
    memcpy(temp_buffer, &apdu_in[APDU_HEADER_SIZE + 1], encrypt_data_size); // We encrypt everything except the CmdHdr
    temp_buffer[encrypt_data_size] = 0x80;

    // ------ Encrypt it
    memcpy(apdu_out, apdu_in, 4);
    aes_encode(ivc, session_keys->encryption, temp_buffer, &apdu_out[6], padded_data_size);

    // ------ Add MAC
    ntag424_calc_mac(session_keys, apdu_in[1], apdu_in[5], &apdu_out[6], padded_data_size, &apdu_out[APDU_HEADER_SIZE + padded_data_size + 1]);

    apdu_out[4] = (uint8_t)(padded_data_size+8+1); // Set size to CmdHdr + padded data + MAC
    apdu_out[APDU_HEADER_SIZE + padded_data_size + 8 + 1] = 0; // Le
        

    return PM3_SUCCESS;
}

static int ntag424_write_file_settings(uint8_t fileno, ntag424_file_settings_t *settings, ntag424_session_keys_t *session_keys) {
    
    // ------- Convert file settings to the format for writing
    file_settings_write_t write_settings = {
        .options = settings->options,
        .access[0] = settings->access[0],
        .access[1] = settings->access[1],
        .optional_sdm_settings = settings->optional_sdm_settings,
    };

    // ------- Assemble the actual command
    size_t settings_size = ntag424_calc_file_write_settings_size(settings);
    uint8_t lc = 1 + settings_size; // CmdHeader + size */

    uint8_t cmd_header[] = {
        0x90, 0x5f, 0x00, 0x00,
        lc,
        fileno
    };
    uint8_t cmd[256] = {0};
    memcpy(cmd, cmd_header, sizeof(cmd_header));
    memcpy(&cmd[sizeof(cmd_header)], (void*)&write_settings, settings_size);
    cmd[sizeof(cmd_header) + settings_size] = 0x00;

    uint8_t apdu_out[256] = {0};
    int apdu_out_size = 256;
    ntag424_comm_full_encrypt_apdu(cmd, apdu_out, &apdu_out_size, session_keys);

    // ------- Actually send the APDU
    const size_t RESPONSE_LENGTH = 8 + 2;
    int outlen;
    uint8_t resp[RESPONSE_LENGTH];
    int res = ExchangeAPDU14a(apdu_out, apdu_out_size, false, true, resp, RESPONSE_LENGTH, &outlen);
    if(res != PM3_SUCCESS)
    {
        PrintAndLogEx(ERR, "Failed to send apdu");
        return res;
    }

    if(outlen != RESPONSE_LENGTH) {
        PrintAndLogEx(ERR, "Incorrect response length: %d, %02X%02X", outlen, resp[outlen-2], resp[outlen-1]);
        return PM3_ESOFT;
    }

    if(resp[outlen-2] != 0x91 || resp[outlen-1] != 0x00)
    {
        PrintAndLogEx(ERR, "Failed to get file settings");
        return PM3_ESOFT;
    }

    session_keys->command_counter++; // Should this be incremented only on success?
    return PM3_SUCCESS;
}

static void ntag424_print_file_settings(uint8_t fileno, const ntag424_file_settings_t *settings) {

    int num_sdm_data = (ntag424_calc_file_settings_size(settings) - SETTINGS_WITHOUT_SDM_DATA_SIZE) / 3;
    
    PrintAndLogEx(SUCCESS, "--- " _CYAN_("File %d settings:") , fileno);

    PrintAndLogEx(SUCCESS, "       type: " _GREEN_("%02X"), settings->type);
    PrintAndLogEx(SUCCESS, "    options: " _GREEN_("%02X"), settings->options);
    PrintAndLogEx(SUCCESS, "     access: " _GREEN_("%02X%02X (RW, C, R, W)"), settings->access[0], settings->access[1]);
    PrintAndLogEx(SUCCESS, "       size: " _GREEN_("%02X%02X%02X"), settings->size[2], settings->size[1], settings->size[0]);

    if(settings->options & FILE_SETTINGS_OPTIONS_SDM_AND_MIRRORING)
    {
        PrintAndLogEx(SUCCESS, "--- " _CYAN_("SDM settings: "));
        PrintAndLogEx(SUCCESS, "    options: " _GREEN_("%02X"), settings->optional_sdm_settings.sdm_options);
        PrintAndLogEx(SUCCESS, " sdm access: " _GREEN_("%02X%02X"), settings->optional_sdm_settings.sdm_access[0], settings->optional_sdm_settings.sdm_access[1]);

        if(num_sdm_data > 0)
        {
            PrintAndLogEx(SUCCESS, "--- " _CYAN_("SDM data: "));
            for(int i = 0; i < num_sdm_data; i++)
            {
                PrintAndLogEx(SUCCESS, "          %d: %02X%02X%02X", i,
                              settings->optional_sdm_settings.sdm_data[i][2],
                              settings->optional_sdm_settings.sdm_data[i][1],
                              settings->optional_sdm_settings.sdm_data[i][0]);
            }
        }
    }
}

// NTAG424 only have one static application, so we select it here
static int ntag424_select_application(void) {
    const size_t RESPONSE_LENGTH = 2;
    uint8_t cmd[] = {0x00, 0xA4, 0x04, 0x0C, 0x07, 0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01, 0x00 };
    uint8_t resp[RESPONSE_LENGTH];
    int outlen = 0;
    int res;

    res = ExchangeAPDU14a(cmd, sizeof(cmd), false, true, resp, RESPONSE_LENGTH, &outlen);
    if(res != PM3_SUCCESS)
    {
        PrintAndLogEx(ERR, "Failed to send apdu");
        return res;
    }

    if(outlen != RESPONSE_LENGTH || resp[RESPONSE_LENGTH-2] != 0x90 || resp[RESPONSE_LENGTH-1] != 0x00)
    {
        PrintAndLogEx(ERR, "Failed to select application");
        return PM3_ESOFT;
    }

    return PM3_SUCCESS;
}

static int ntag424_auth_first_step(uint8_t keyno, uint8_t *key, uint8_t *out)
{
    const size_t RESPONSE_LENGTH = 16 + 2;
    uint8_t cmd[] = {0x90, 0x71, 0x00, 0x00, 0x02, keyno, 0x00, 0x00};
    uint8_t resp[RESPONSE_LENGTH];
    int outlen = 0;
    int res;

    res = ExchangeAPDU14a(cmd, sizeof(cmd), false, true, resp, RESPONSE_LENGTH, &outlen);
    if(res != PM3_SUCCESS)
    {
        PrintAndLogEx(ERR, "Failed to send apdu");
        return res;
    }

    if(outlen != RESPONSE_LENGTH || resp[RESPONSE_LENGTH-2] != 0x91 || resp[RESPONSE_LENGTH-1] != 0xAF)
    {
        PrintAndLogEx(ERR, "Failed to get RndB (invalid key number?)");
        return PM3_ESOFT;
    }

    uint8_t iv[16] = {0};
    aes_decode(iv, key, resp, out, 16);

    return PM3_SUCCESS;
}

static int ntag424_auth_second_step(uint8_t *challenge, uint8_t *response)
{
    uint8_t cmd_header[] = { 0x90, 0xAF, 0x00, 0x00, 0x20 };

    uint8_t cmd[sizeof(cmd_header) + 32 + 1] = {0};

    memcpy(cmd, cmd_header, sizeof(cmd_header));
    memcpy(&cmd[sizeof(cmd_header)], challenge, 32);

    const size_t RESPONSE_LENGTH = 256;
    uint8_t resp[RESPONSE_LENGTH];
    int outlen = 0;
    int res;

    res = ExchangeAPDU14a(cmd, sizeof(cmd), false, true, resp, RESPONSE_LENGTH, &outlen);
    if(res != PM3_SUCCESS)
    {
        return res;
    }

    if(resp[outlen-2] != 0x91 || resp[outlen-1] != 0x00)
    {
        PrintAndLogEx(ERR, "Challenge failed: wrong key?");
        return PM3_ESOFT;
    }

    memcpy(response, resp, outlen-2);

    return PM3_SUCCESS;
}

// Authenticate against a key number and optionally get session keys out
static int ntag424_authenticate_ev2_first(uint8_t keyno, uint8_t *key, ntag424_session_keys_t *session_keys_out)
{
    // -------- Get first challenge from card    
    uint8_t rnd_b_clear[16] = {0};

    int res = ntag424_auth_first_step(keyno, key, rnd_b_clear);
    if(res != PM3_SUCCESS)
    {
        return res;
    }

    // -------- Concatenate RndA and RndB and encrypt it with the key
    uint8_t concat_clear[32] = {0};
    uint8_t concat_enc[32] = {0};
    // This should of course be completely random, if we cared
    // about security
    uint8_t rnd_a_clear[16] = {
        0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
        0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf
    };

    uint8_t iv[16] = {0};
    memcpy(&concat_clear[16], &rnd_b_clear[1], 15);
    concat_clear[31] = rnd_b_clear[0];
    memcpy(concat_clear, rnd_a_clear, 16);

    aes_encode(iv, key, concat_clear, concat_enc, 32);

    // -------- Do second step with our concatenated encrypted RndA || RndB
    uint8_t resp[4+16+6+6];
    res = ntag424_auth_second_step(concat_enc, resp);
    if(res != PM3_SUCCESS)
    {
        return res;
    }

    ntag424_ev2_response_t response;
    aes_decode(iv, key, resp, (uint8_t*)&response, sizeof(ntag424_ev2_response_t));

    // -------- Verify that the response we got contains the RndA that we supplied (rotated one byte)
    if(memcmp(response.rnd_a, &rnd_a_clear[1], 15) != 0 ||
       response.rnd_a[15] != rnd_a_clear[0])
    {
        PrintAndLogEx(ERR, "Incorrect response from card\n"
                      "expected: %s\n"
                      "got: %s"
                      , sprint_hex(rnd_a_clear, 16),
                      sprint_hex(response.rnd_a, 16));
        return PM3_ESOFT;
    }

    // -------- Optionally calculate session keys
    if(session_keys_out)
    {
        memset(session_keys_out, 0, sizeof(ntag424_session_keys_t));
        memcpy(session_keys_out->ti, response.ti, sizeof(response.ti));

        // SV 1 = [0xA5][0x5A][0x00][0x01]
        // [0x00][0x80][RndA[15:14] ||
        // [ (RndA[13:8] ⊕ RndB[15:10]) ] ||
        // [RndB[9:0] || RndA[7:0]

        uint8_t sv1[] = { 0xa5, 0x5a, 0x00, 0x01, 0x00, 0x80, rnd_a_clear[0], rnd_a_clear[1],
            rnd_a_clear[2] ^ rnd_b_clear[0],
            rnd_a_clear[3] ^ rnd_b_clear[1],
            rnd_a_clear[4] ^ rnd_b_clear[2],
            rnd_a_clear[5] ^ rnd_b_clear[3],
            rnd_a_clear[6] ^ rnd_b_clear[4],
            rnd_a_clear[7] ^ rnd_b_clear[5],
            rnd_b_clear[6], rnd_b_clear[7], rnd_b_clear[8], rnd_b_clear[9], rnd_b_clear[10],
            rnd_b_clear[11], rnd_b_clear[12], rnd_b_clear[13], rnd_b_clear[14], rnd_b_clear[15],
            rnd_a_clear[8], rnd_a_clear[9], rnd_a_clear[10],
            rnd_a_clear[11], rnd_a_clear[12], rnd_a_clear[13], rnd_a_clear[14], rnd_a_clear[15]
        };

        // SV 2 = [0x5A][0xA5][0x00][0x01]
        // [0x00][0x80][RndA[15:14] ||
        // [ (RndA[13:8] ⊕ RndB[15:10]) ] ||
        // [RndB[9:0] || RndA[7:0]

        uint8_t sv2[] = { 0x5a, 0xa5, 0x00, 0x01, 0x00, 0x80, rnd_a_clear[0], rnd_a_clear[1],
            rnd_a_clear[2] ^ rnd_b_clear[0],
            rnd_a_clear[3] ^ rnd_b_clear[1],
            rnd_a_clear[4] ^ rnd_b_clear[2],
            rnd_a_clear[5] ^ rnd_b_clear[3],
            rnd_a_clear[6] ^ rnd_b_clear[4],
            rnd_a_clear[7] ^ rnd_b_clear[5],
            rnd_b_clear[6], rnd_b_clear[7], rnd_b_clear[8], rnd_b_clear[9], rnd_b_clear[10],
            rnd_b_clear[11], rnd_b_clear[12], rnd_b_clear[13], rnd_b_clear[14], rnd_b_clear[15],
            rnd_a_clear[8], rnd_a_clear[9], rnd_a_clear[10],
            rnd_a_clear[11], rnd_a_clear[12], rnd_a_clear[13], rnd_a_clear[14], rnd_a_clear[15]
        };
        
        mbedtls_aes_cmac_prf_128(key, 16, sv1, sizeof(sv1), session_keys_out->encryption);
        mbedtls_aes_cmac_prf_128(key, 16, sv2, sizeof(sv2), session_keys_out->mac);
    }

    return PM3_SUCCESS;
}

#define MAX_WRITE_APDU 248

// Write file to card. Only supports plain communications mode. Authentication must be done
// first unless file has free write access.
static int ntag424_write_file(uint8_t fileno, uint16_t offset, uint16_t num_bytes, uint8_t *in) {
    const size_t RESPONSE_LENGTH = 2;
    size_t remainder = 0;

    if(num_bytes > MAX_WRITE_APDU)
    {
        remainder = num_bytes - MAX_WRITE_APDU;
        num_bytes = MAX_WRITE_APDU;
    }

    // 248 + 
    uint8_t cmd_header[] = { 0x90, 0x8d, 0x00, 0x00, 0x07 + num_bytes, fileno,
        (uint8_t)offset, (uint8_t)(offset << 8), (uint8_t)(offset << 16), // offset
        (uint8_t)num_bytes, (uint8_t)(num_bytes >> 8), (uint8_t)(num_bytes >> 16) //size
    };

    uint8_t cmd[512] = {0};

    memcpy(cmd, cmd_header, sizeof(cmd_header));
    memcpy(&cmd[sizeof(cmd_header)], in, num_bytes);

    size_t total_size = sizeof(cmd_header) + num_bytes + 1; //(Le)
    
    uint8_t resp[RESPONSE_LENGTH];
    int outlen = 0;
    int res;

    res = ExchangeAPDU14a(cmd, total_size, false, true, resp, RESPONSE_LENGTH, &outlen);
    if(res != PM3_SUCCESS)
    {
        PrintAndLogEx(ERR, "Failed to send apdu");
        return res;
    }

    if(outlen != RESPONSE_LENGTH) {
        PrintAndLogEx(ERR, "Incorrect response length: %d, %s", outlen, sprint_hex(resp, 2));
        return PM3_ESOFT;
    }

    if(resp[outlen-2] != 0x91 || resp[outlen-1] != 0x00)
    {
        PrintAndLogEx(ERR, "Failed to write file");
        return PM3_ESOFT;
    }

    if(remainder > 0)
    {
        return ntag424_write_file(fileno, offset + num_bytes, remainder, &in[num_bytes]);
    }
    
    return PM3_SUCCESS;
}

// Read file from card. Only supports plain communications mode. Authentication must be done
// first unless file has free read access.
static int ntag424_read_file(uint8_t fileno, uint16_t offset, uint16_t num_bytes, uint8_t *out) {
    const size_t RESPONSE_LENGTH = num_bytes + 2;
    
    uint8_t cmd[] = { 0x90, 0xad, 0x00, 0x00, 0x07, fileno,
        (uint8_t)offset, (uint8_t)(offset << 8), (uint8_t)(offset << 16), // offset
        (uint8_t)num_bytes, (uint8_t)(num_bytes >> 8), 0x00, //size
        0x00 };
    uint8_t resp[RESPONSE_LENGTH];
    int outlen = 0;
    int res;

    res = ExchangeAPDU14a(cmd, sizeof(cmd), false, true, resp, RESPONSE_LENGTH, &outlen);
    if(res != PM3_SUCCESS)
    {
        PrintAndLogEx(ERR, "Failed to send apdu");
        return res;
    }

    if(outlen != RESPONSE_LENGTH) {
        PrintAndLogEx(ERR, "Incorrect response length: %d, %s", outlen, sprint_hex(resp, 2));
        return PM3_ESOFT;
    }

    if(resp[outlen-2] != 0x91 || resp[outlen-1] != 0x00)
    {
        PrintAndLogEx(ERR, "Failed to read file");
        return PM3_ESOFT;
    }

    memcpy(out, resp, num_bytes);
    return PM3_SUCCESS;
}

static int ntag424_change_key(uint8_t keyno, uint8_t *new_key, uint8_t *old_key, uint8_t version, ntag424_session_keys_t *session_keys) {
    // -------- Calculate xor and crc
    uint8_t key[16] = {0};
    uint8_t crc[4] = {0};
    if(keyno != 0)
    {
        for(int i = 0; i < 16; i++)
        {
            key[i] = old_key[i] ^ new_key[i];
        }
        crc32_ex(new_key, 16, crc);
    }
    else
    {
        memcpy(key, new_key, 16);
    }
    
    // ------- Calculate KeyData
    uint8_t keydata[32] = {0};
    memcpy(keydata, key, 16);
    keydata[16] = version;
    int key_data_len;
    if(keyno != 0)
    {
        memcpy(&keydata[17], crc, 4);
        keydata[21] = 0x80;
        key_data_len = 16 + 4 + 1;
    }
    else
    {
        keydata[17] = 0x80;
        key_data_len = 16 + 1;
    }

    // ------- Assemble APDU
    uint8_t cmd_header[] = {
        0x90, 0xC4, 0x00, 0x00, key_data_len+1, keyno
    };

    uint8_t cmd[512] = {0};
    memcpy(cmd, cmd_header, sizeof(cmd_header));
    memcpy(&cmd[sizeof(cmd_header)], keydata, key_data_len);

    uint8_t apdu_out[256];
    int apdu_out_size = 256;
    ntag424_comm_full_encrypt_apdu(cmd, apdu_out, &apdu_out_size, session_keys);
        

    // ------- Actually send the APDU
    const size_t RESPONSE_LENGTH = 8 + 2;
    int outlen;
    uint8_t resp[RESPONSE_LENGTH];
    int res = ExchangeAPDU14a(apdu_out, apdu_out_size, false, true, resp, RESPONSE_LENGTH, &outlen);
    if(res != PM3_SUCCESS)
    {
        PrintAndLogEx(ERR, "Failed to send apdu");
        return res;
    }

    if(outlen < 2) {
        PrintAndLogEx(ERR, "Incorrect response length: %d", outlen);
        return PM3_ESOFT;
    }

    if(resp[outlen-2] != 0x91 || resp[outlen-1] != 0x00)
    {
        PrintAndLogEx(ERR, "Error when changing key. Wrong old key?");
        return PM3_ESOFT;
    }

    session_keys->command_counter++; // Should this be incremented only on success?
        
    return PM3_SUCCESS;

}

static int CmdHF_ntag424_info(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf ntag424 info",
                  "Get info about NXP NTAG424 DNA Family styled tag.",
                  "hf ntag424 info"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    PrintAndLogEx(INFO, "not implemented yet");
    PrintAndLogEx(INFO, "Feel free to contribute!");
    return PM3_SUCCESS;
}

static int ntag424_cli_get_auth_information(CLIParserContext *ctx, int key_no_index, int key_index, int *keyno, uint8_t *key_out)
{
    uint8_t key[16];
    int keylen = 16;
    if(keyno)
    {
        *keyno = arg_get_int(ctx, key_no_index);
    }
    CLIGetHexWithReturn(ctx, key_index, key, &keylen);

    if(keylen != 16)
    {
        PrintAndLogEx(ERR, "Key must be 16 bytes");
        return PM3_ESOFT;
    }

    memcpy(key_out, key, 16);
    
    return PM3_SUCCESS;
}

static int CmdHF_ntag424_auth(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf ntag424 auth",
                  "Authenticate with selected key against NTAG424.",
                  "hf ntag424 auth -n 0 -k 00000000000000000000000000000000");

    void *argtable[] = {
        arg_param_begin,
        arg_int1("n",  "keyno", "<dec>", "Key number"),
        arg_str1("k",  "key", "<hex>", "Key for authenticate (HEX 16 bytes)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    int keyno;
    uint8_t key[16] = {0};

    if(ntag424_cli_get_auth_information(ctx, 1, 2, &keyno, key) != PM3_SUCCESS)
    {
        CLIParserFree(ctx);
        return PM3_ESOFT;
    }

    CLIParserFree(ctx);

    int res = SelectCard14443A_4(false, true, NULL);
    if (res != PM3_SUCCESS)
    {
        PrintAndLogEx(ERR, "Failed to select card");
        DropField();
        return res;
    }

    res = ntag424_select_application();
    if(res != PM3_SUCCESS)
    {
        DropField();
        return res;
    }    

    res = ntag424_authenticate_ev2_first(keyno, key, NULL);
    if(res != PM3_SUCCESS)
    {
        PrintAndLogEx(ERR, "Failed to authenticate with key %d", keyno);
    }
    else
    {
        PrintAndLogEx(SUCCESS, "Successfully authenticated with key %d", keyno);
    }

    DropField();

    return res;
}

// Read can only read files with plain communication mode!
static int CmdHF_ntag424_read(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf ntag424 read",
                  "Read and print data from file on NTAG424 tag. Will authenticate if key information is provided.",
                  "hf ntag424 read -f 2 -n 0 -k 00000000000000000000000000000000 -o 0 -l 256");

    void *argtable[] = {
        arg_param_begin,
        arg_int1("f",  "fileno", "<dec>", "File number (1-3), (default 2)"),
        arg_int0("n",  "keyno", "<dec>", "Key number"),
        arg_str0("k",  "key", "<hex>", "Key for authentication (HEX 16 bytes)"),
        arg_int0("o",  "offset", "<dec>", "Offset to read in file (default 0)"),
        arg_int1("l",  "length", "<dec>", "Number of bytes to read"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int keyno;
    uint8_t key[16] = {0};
    int auth = 1;

    int fileno = arg_get_int(ctx, 1);

    if(ntag424_cli_get_auth_information(ctx, 2, 3, &keyno, key) != PM3_SUCCESS)
    {
        PrintAndLogEx(INFO, "Reading unauthenticated");
        auth = 0;
    }
    else
    {
        PrintAndLogEx(INFO, "Reading authenticated");
    }

    int offset = arg_get_int_def(ctx, 4, 0);
    int read_length = arg_get_int(ctx, 5);
    
    CLIParserFree(ctx);

    int res = SelectCard14443A_4(false, true, NULL);
    if (res != PM3_SUCCESS)
    {
        DropField();
        PrintAndLogEx(ERR, "Failed to select card");
        return res;
    }

    res = ntag424_select_application();
    if(res != PM3_SUCCESS)
    {
        DropField();
        return res;
    }    

    if(auth)
    {
        res = ntag424_authenticate_ev2_first(keyno, key, NULL);
        if(res != PM3_SUCCESS)
        {
            PrintAndLogEx(ERR, "Failed to authenticate with key %d", keyno);
            DropField();
            return res;
        }
        else
        {
            PrintAndLogEx(SUCCESS, "Successfully authenticated with key %d", keyno);
        }
    }

    uint8_t data[512];

    res = ntag424_read_file(fileno, offset, read_length, data);
    if(res != PM3_SUCCESS)
    {
        DropField();
        return res;
    }

    PrintAndLogEx(SUCCESS, " -------- Read file %d contents ------------ ", fileno);
    print_hex_break(data, read_length, 16);

    DropField();

    return res;
}

static int CmdHF_ntag424_write(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf ntag424 write",
                  "Write data to file on NTAG424 tag. Will authenticate if key information is provided.",
                  "hf ntag424 write -f 2 -n 0 -k 00000000000000000000000000000000 -o 0 -d 1122334455667788");

    void *argtable[] = {
        arg_param_begin,
        arg_int1("f",  "fileno", "<dec>", "File number (1-3), (default 2)"),
        arg_int0("n",  "keyno", "<dec>", "Key number"),
        arg_str0("k",  "key", "<hex>", "Key for authentication (HEX 16 bytes)"),
        arg_int0("o",  "offset", "<dec>", "Offset to write in file (default 0)"),
        arg_str1("d",  "data", "<hex>", "Data to write"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int keyno;
    uint8_t key[16] = {0};
    int auth = 1;

    int fileno = arg_get_int(ctx, 1);

    if(ntag424_cli_get_auth_information(ctx, 2, 3, &keyno, key) != PM3_SUCCESS)
    {
        PrintAndLogEx(INFO, "Will write unauthenticated");
        auth = 0;
    }
    else
    {
        PrintAndLogEx(INFO, "Will write authenticated");
    }

    int offset = arg_get_int_def(ctx, 4, 0);

    uint8_t data[512] = {0};
    int datalen = 512;
    CLIGetHexWithReturn(ctx, 5, data, &datalen);
    
    CLIParserFree(ctx);

    int res = SelectCard14443A_4(false, true, NULL);
    if (res != PM3_SUCCESS)
    {
        DropField();
        PrintAndLogEx(ERR, "Failed to select card");
        return res;
    }

    res = ntag424_select_application();
    if(res != PM3_SUCCESS)
    {
        DropField();
        return res;
    }    

    if(auth)
    {
        res = ntag424_authenticate_ev2_first(keyno, key, NULL);
        if(res != PM3_SUCCESS)
        {
            PrintAndLogEx(ERR, "Failed to authenticate with key %d", keyno);
            DropField();
            return res;
        }
        else
        {
            PrintAndLogEx(SUCCESS, "Successfully authenticated with key %d", keyno);
        }
    }

    res = ntag424_write_file(fileno, offset, datalen, data);
    if(res != PM3_SUCCESS)
    {
        DropField();
        return res;
    }

    PrintAndLogEx(SUCCESS, "Wrote %d bytes", datalen);

    DropField();

    return res;
}

static int CmdHF_ntag424_getfilesettings(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf ntag424 getfilesettings",
                  "Read and print file settings for file",
                  "hf ntag424 getfilesettings -f 2");

    void *argtable[] = {
        arg_param_begin,
        arg_int1("f",  "file", "<dec>", "File number"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    int fileno = arg_get_int(ctx, 1);

    CLIParserFree(ctx);

    int res = SelectCard14443A_4(false, true, NULL);
    if (res != PM3_SUCCESS)
    {
        DropField();
        PrintAndLogEx(ERR, "Failed to select card");
        return res;
    }

    res = ntag424_select_application();
    if(res != PM3_SUCCESS)
    {
        DropField();
        return res;
    }    

    ntag424_file_settings_t settings;
    res = ntag424_read_file_settings(fileno, &settings);
    DropField();
    if(res != PM3_SUCCESS)
    {
        return res;
    }

    ntag424_print_file_settings(fileno, &settings);


    return res;
}

static int CmdHF_ntag424_changefilesettings(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf ntag424 changefilesettings",
                  "Updates file settings for file, must be authenticated.\n"
                  "This is a short explanation of the settings. See AN12196 for more information:\n"
                  "options: byte with bit flags\n"
                  "  Bit:   Setting:\n"
                  "   6     Enable SDM and mirroring\n\n"
                  
                  "access: two byte access rights.\n"
                  "Each nibble is a key number, or E for free access.\n"
                  "Order is key for readwrite, change, read and write\n\n"
                  
                  "sdmoptions: byte with bit flags\n"
                  "  Bit:   Setting:\n"
                  "   0     ASCII encoding\n"
                  "   4     SDMEncFileData\n"
                  "   5     SDMReadCtrLimit\n"
                  "   6     SDMReadCtr\n"
                  "   7     SDMOptionsUID\n\n"
                  
                  "sdmaccess: two byte access rights.\n"
                  "Each nibble is a key, or E for plain mirror and F for no mirroring\n"
                  "Order is SDMMetaRead, SDMFileRead, Reserved and SDMCtrRet\n\n"

                  "sdm_data: Three bytes of data used to control SDM settings. Can be specified multiple times.\n"
                  "Data means different things depending on settings.\n\n"

                  "Note: Not all of these settings will be written. It depends on the option byte, and the keys set. See AN12196 for more information.\n"
                  "You must also start with sdmdata1, then sdmdata2, up to the number of sdm_data you want to write",
                  
                  
                  "hf ntag424 changefilesettings -f 2 -n 0 -k 00000000000000000000000000000000 -o 40 -a 00E0 -s C1 -c F000 --sdmdata1 000020 --sdmdata2 000043 --sdmdata3 000043");

    void *argtable[] = {
        arg_param_begin,
        arg_int1("f",  "file", "<dec>", "File number"),
        arg_int1("n",  "keyno", "<dec>", "Key number"),
        arg_str1("k",  "key", "<hex>", "Key for authentication (HEX 16 bytes)"),
        arg_str0("o",  "options", "<hex>", "File options byte (HEX 1 byte)"),
        arg_str0("a",  "access", "<hex>", "File access settings (HEX 2 bytes)"),
        arg_str0("s",  "sdmoptions", "<hex>", "SDM options (HEX 1 byte)"),
        arg_str0("c",  "sdmaccess", "<hex>", "SDM access settings (HEX 2 bytes)"),
        arg_str0(NULL, "sdmdata1", "<hex>", "SDM data (HEX 3 bytes)"),
        arg_str0(NULL, "sdmdata2", "<hex>", "SDM data (HEX 3 bytes)"),
        arg_str0(NULL, "sdmdata3", "<hex>", "SDM data (HEX 3 bytes)"),
        arg_str0(NULL, "sdmdata4", "<hex>", "SDM data (HEX 3 bytes)"),
        arg_str0(NULL, "sdmdata5", "<hex>", "SDM data (HEX 3 bytes)"),
        arg_str0(NULL, "sdmdata6", "<hex>", "SDM data (HEX 3 bytes)"),
        arg_str0(NULL, "sdmdata7", "<hex>", "SDM data (HEX 3 bytes)"),
        arg_str0(NULL, "sdmdata8", "<hex>", "SDM data (HEX 3 bytes)"),
        // Sorry, couldn't figure out how to work with arg_strn...
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    int fileno = arg_get_int(ctx, 1);

    int keyno;
    uint8_t key[16] = {0};

    uint8_t has_options = 0;
    uint8_t options[1];
    uint8_t has_access = 0;
    uint8_t access[2];
    uint8_t has_sdmoptions = 0;
    uint8_t sdmoptions[1];
    uint8_t has_sdmaccess = 0;
    uint8_t sdmaccess[2];
    uint8_t num_sdm_data = 0;
    uint8_t sdm_data[8][3];

    if(ntag424_cli_get_auth_information(ctx, 2, 3, &keyno, key) != PM3_SUCCESS)
    {
        PrintAndLogEx(ERR, "Could not get key settings");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }
    int len = 1;
    if(arg_get_str(ctx,4)->count == 1)
    {
        has_options = 1;
        CLIGetHexWithReturn(ctx, 4, options, &len);
        if(len != 1)
        {
            PrintAndLogEx(ERR, "Options must be 1 byte");
            CLIParserFree(ctx);
            return PM3_EINVARG;
        }
    }
    len = 2;
    if(arg_get_str(ctx,5)->count == 1)
    {
        has_access = 1;
        CLIGetHexWithReturn(ctx, 5, access, &len);
        if(len != 2)
        {
            PrintAndLogEx(ERR, "Access must be 2 bytes");
            CLIParserFree(ctx);
            return PM3_EINVARG;
        }
    }
    len = 1;
    if(arg_get_str(ctx,6)->count == 1)
    {
        has_sdmoptions = 1;
        CLIGetHexWithReturn(ctx, 6, sdmoptions, &len);
        if(len != 1)
        {
            PrintAndLogEx(ERR, "SDM Options must be 1 byte");
            CLIParserFree(ctx);
            return PM3_EINVARG;
        }
    }
    len = 2;
    if(arg_get_str(ctx,7)->count == 1)
    {
        has_sdmaccess = 1;
        CLIGetHexWithReturn(ctx, 7, sdmaccess, &len);
        if(len != 2)
        {
            PrintAndLogEx(ERR, "SDM Access must be 2 bytes");
            CLIParserFree(ctx);
            return PM3_EINVARG;
        }
    }

    for(int i = 0; i < 8; i++)
    {
        if(arg_get_str(ctx,8+i)->count == 1)
        {
            len = 3;
            num_sdm_data++;
            CLIGetHexWithReturn(ctx, 8+i, sdm_data[i], &len);
            if(len != 3)
            {
                PrintAndLogEx(ERR, "sdmdata must be 3 bytes");
                CLIParserFree(ctx);
                return PM3_EINVARG;
            }
        }
        else
        {
            break;
        }
    }
        

    CLIParserFree(ctx);

    int res = SelectCard14443A_4(false, true, NULL);
    if (res != PM3_SUCCESS)
    {
        DropField();
        PrintAndLogEx(ERR, "Failed to select card");
        return res;
    }

    res = ntag424_select_application();
    if(res != PM3_SUCCESS)
    {
        DropField();
        return res;
    }    

    ntag424_file_settings_t settings;
    res = ntag424_read_file_settings(fileno, &settings);
    if(res != PM3_SUCCESS)
    {
        DropField();
        return res;
    }

    ntag424_session_keys_t session = {0};
    res = ntag424_authenticate_ev2_first(keyno, key, &session);
    if(res != PM3_SUCCESS)
    {
        PrintAndLogEx(ERR, "Failed to authenticate with key %d", keyno);
        DropField();
        return res;
    }

    if(has_options)
    {
        settings.options = options[0];
    }
    if(has_access)
    {
        memcpy(settings.access, access, 2);
    }
    if(has_sdmoptions)
    {
        settings.optional_sdm_settings.sdm_options = sdmoptions[0];
    }
    if(has_sdmaccess)
    {
        memcpy(settings.optional_sdm_settings.sdm_access, sdmaccess, 2);
    }

    for(int i = 0; i < num_sdm_data; i++)
    {
        settings.optional_sdm_settings.sdm_data[i][2] = sdm_data[i][0];
        settings.optional_sdm_settings.sdm_data[i][1] = sdm_data[i][1];
        settings.optional_sdm_settings.sdm_data[i][0] = sdm_data[i][2];
    }

    if(ntag424_write_file_settings(fileno, &settings, &session) != PM3_SUCCESS)
    {
        PrintAndLogEx(ERR, "Failed to write settings");
        DropField();
        return PM3_ESOFT;
    }
    PrintAndLogEx(SUCCESS, "Wrote settings successfully");
    ntag424_print_file_settings(fileno, &settings);
   
    DropField();
    return res;
}

static int CmdHF_ntag424_changekey(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf ntag424 changekey",
                  "Change a key.\n"
                  "Authentication key must currently be different to the one we want to change.\n",
                  "hf ntag424 changekey -n 1 --oldkey 00000000000000000000000000000000 --newkey 11111111111111111111111111111111 --key0 00000000000000000000000000000000 -v 1\n"
                  "hf ntag424 changekey -n 0 --newkey 11111111111111111111111111111111 --key0 00000000000000000000000000000000 -v 1\n"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_int1("n",  "keyno", "<dec>", "Key number to change"),
        arg_str0(NULL, "oldkey", "<hex>", "Old key (only needed when changing key 1-4, HEX 16 bytes)"),
        arg_str1(NULL, "newkey", "<hex>", "New key (HEX 16 bytes)"),
        arg_str1(NULL, "key0", "<hex>", "Authentication key (must be key 0, HEX 16 bytes)"),
        arg_int1("v",  "version", "<dec>", "Version of the new key"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    uint8_t version = arg_get_int(ctx, 6);
    int keyno = arg_get_int(ctx, 1);
    uint8_t oldkey[16];
    uint8_t newkey[16];
    uint8_t authkey[16];

    if(keyno != 0)
    {
        if(ntag424_cli_get_auth_information(ctx, 0, 2, NULL, oldkey) != PM3_SUCCESS)
        {
            
            PrintAndLogEx(ERR, "Could not get keyno or old key");
            CLIParserFree(ctx);
            return PM3_EINVARG;
        }
    }
    if(ntag424_cli_get_auth_information(ctx, 0, 3, NULL, newkey) != PM3_SUCCESS)
    {
        PrintAndLogEx(ERR, "Could not get new key");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }
    if(ntag424_cli_get_auth_information(ctx, 0, 4, NULL, authkey) != PM3_SUCCESS)
    {
        PrintAndLogEx(ERR, "Could not get authentication key");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }
    CLIParserFree(ctx);

    int res = SelectCard14443A_4(false, true, NULL);
    if (res != PM3_SUCCESS)
    {
        DropField();
        PrintAndLogEx(ERR, "Failed to select card");
        return res;
    }

    res = ntag424_select_application();
    if(res != PM3_SUCCESS)
    {
        DropField();
        return res;
    }    

    ntag424_session_keys_t session = {0};
    res = ntag424_authenticate_ev2_first(0, authkey, &session);
    if(res != PM3_SUCCESS)
    {
        DropField();
        PrintAndLogEx(ERR, "Failed to authenticate");
        return PM3_ESOFT;
    }
    else
    {
        PrintAndLogEx(SUCCESS, "Successfully authenticated");
    }
    
    res = ntag424_change_key(keyno, newkey, oldkey, version, &session);
    if(res != PM3_SUCCESS)
    {
        DropField();
        PrintAndLogEx(ERR, "Failed to change key");
        DropField();
        return PM3_ESOFT;
    }
    else
    {
        PrintAndLogEx(SUCCESS, "Successfully changed key %d", keyno);
    }

    DropField();
    return PM3_SUCCESS;
}

//------------------------------------
// Menu Stuff
//------------------------------------
static command_t CommandTable[] = {
    {"help",            CmdHelp,                             AlwaysAvailable,  "This help"},
    {"-----------",     CmdHelp,                             IfPm3Iso14443a,   "----------------------- " _CYAN_("operations") " -----------------------"},
    {"info",               CmdHF_ntag424_info,               IfPm3Iso14443a,   "Tag information (not implemented yet)"},
    {"view",               CmdHF_ntag424_view,               AlwaysAvailable,  "Display content from tag dump file"},
    {"auth",               CmdHF_ntag424_auth,               IfPm3Iso14443a,   "Test authentication with key"},
    {"read",               CmdHF_ntag424_read,               IfPm3Iso14443a,   "Read file"},
    {"write",              CmdHF_ntag424_write,              IfPm3Iso14443a,   "Write file"},
    {"getfilesettings",    CmdHF_ntag424_getfilesettings,    IfPm3Iso14443a,   "Get file settings"},
    {"changefilesettings", CmdHF_ntag424_changefilesettings, IfPm3Iso14443a,   "Change file settings"},
    {"changekey",          CmdHF_ntag424_changekey,          IfPm3Iso14443a,   "Change key"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdHF_ntag424(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}
