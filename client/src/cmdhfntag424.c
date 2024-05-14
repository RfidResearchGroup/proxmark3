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
#include "iso7816/apduinfo.h"
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
#include "cmdhfmfdes.h"

#define NTAG424_MAX_BYTES 412


// NTAG424 commands currently implemented
#define NTAG424_CMD_GET_FILE_SETTINGS      0xF5
#define NTAG424_CMD_CHANGE_FILE_SETTINGS   0x5F
#define NTAG424_CMD_CHANGE_KEY             0xC4
#define NTAG424_CMD_READ_DATA              0xAD
#define NTAG424_CMD_WRITE_DATA             0x8D
#define NTAG424_CMD_AUTHENTICATE_EV2_FIRST 0x71
#define NTAG424_CMD_MORE_DATA              0xAF
#define NTAG424_CMD_GET_VERSION            0x60
#define NTAG424_CMD_GET_SIGNATURE          0x3C

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

typedef enum {
    COMM_PLAIN,
    COMM_MAC,
    COMM_FULL
} ntag424_communication_mode_t;

const CLIParserOption ntag424_communication_mode_options[] = {
    {COMM_PLAIN,     "plain"},
    {COMM_MAC,     "mac"},
    {COMM_FULL, "encrypt"},
    {0,    NULL},
};

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

// -------------- Version information structs -------------------------
typedef struct {
    uint8_t vendor_id;
    uint8_t type;
    uint8_t sub_type;
    uint8_t major_version;
    uint8_t minor_version;
    uint8_t storage_size;
    uint8_t protocol;
} PACKED ntag424_version_information_t;

typedef struct {
    uint8_t uid[7];
    uint8_t batch[4];
    uint8_t fab_key_high : 4;
    uint8_t batchno : 4;
    uint8_t week_prod : 7;
    uint8_t fab_key_low : 1;
    uint8_t year_prod;
} PACKED ntag424_production_information_t;

typedef struct {
    ntag424_version_information_t hardware;
    ntag424_version_information_t software;
    ntag424_production_information_t production;
} ntag424_full_version_information_t;


static void ntag424_print_version_information(ntag424_version_information_t *version) {
    PrintAndLogEx(INFO, "   vendor id: " _GREEN_("%02X"), version->vendor_id);
    PrintAndLogEx(INFO, "        type: " _GREEN_("%02X"), version->type);
    PrintAndLogEx(INFO, "    sub type: " _GREEN_("%02X"), version->sub_type);
    PrintAndLogEx(INFO, "     version: " _GREEN_("%d.%d"), version->major_version, version->minor_version);
    PrintAndLogEx(INFO, "storage size: " _GREEN_("%02X"), version->storage_size);
    PrintAndLogEx(INFO, "    protocol: " _GREEN_("%02X"), version->protocol);
}

static void ntag424_print_production_information(ntag424_production_information_t *version) {
    PrintAndLogEx(INFO, "         uid: " _GREEN_("%s"), sprint_hex(version->uid, sizeof(version->uid)));
    PrintAndLogEx(INFO, "       batch: " _GREEN_("%s"), sprint_hex(version->batch, sizeof(version->batch)));
    PrintAndLogEx(INFO, "     batchno: " _GREEN_("%02X"), version->batchno);
    PrintAndLogEx(INFO, "     fab key: " _GREEN_("%02X"), (version->fab_key_high << 1) | version->fab_key_low);
    PrintAndLogEx(INFO, "        date: week " _GREEN_("%02X") " / " _GREEN_("20%02X"), version->week_prod, version->year_prod);
}

static void ntag424_print_full_version_information(ntag424_full_version_information_t *version) {
    PrintAndLogEx(INFO, "--- " _CYAN_("Hardware version information:"));
    ntag424_print_version_information(&version->hardware);

    PrintAndLogEx(INFO, "--- " _CYAN_("Software version information:"));
    ntag424_print_version_information(&version->software);

    PrintAndLogEx(INFO, "--- " _CYAN_("Production information:"));
    ntag424_print_production_information(&version->production);
}

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

    if (settings->options & FILE_SETTINGS_OPTIONS_SDM_AND_MIRRORING) {
        size += 3; // sdm_options and sdm_access must be present

        if (settings->optional_sdm_settings.sdm_options & FILE_SETTINGS_SDM_OPTIONS_UID &&
                ntag424_file_settings_get_sdm_meta_read(settings) == 0xe) {
            size += 3; // UIDOffset
        }

        if (settings->optional_sdm_settings.sdm_options & FILE_SETTINGS_SDM_OPTIONS_SDM_READ_COUNTER &&
                ntag424_file_settings_get_sdm_meta_read(settings) == 0xe) {
            size += 3; // SDMReadCtrOffset
        }

        if (ntag424_file_settings_get_sdm_meta_read(settings) <= 0x04) {
            size += 3; // PICCDataOffset
        }

        if (ntag424_file_settings_get_sdm_file_read(settings) != 0x0f) {
            size += 3; // SDMMacInputOffset
        }

        if (ntag424_file_settings_get_sdm_file_read(settings) != 0x0f &&
                settings->optional_sdm_settings.sdm_options & FILE_SETTINGS_SDM_OPTIONS_SDM_ENC_FILE_DATA) {
            size += 3; // SDMEncOffset
            size += 3; // SDMEncLength
        }

        if (ntag424_file_settings_get_sdm_file_read(settings) != 0x0f) {
            // Warning, this value has different offsets depending on
            // FILE_SETTINGS_SDM_OPTIONS_SDM_ENC_FILE_DATA
            size += 3; // SDMMacOffset
        }

        if (settings->optional_sdm_settings.sdm_options & FILE_SETTINGS_SDM_OPTIONS_SDM_READ_COUNTER_LIMIT) {
            size += 3; // SDMReadCtrLimit
        }
    }

    return size;
}

static int ntag424_calc_file_write_settings_size(const ntag424_file_settings_t *settings) {
    return ntag424_calc_file_settings_size(settings) - 4;
}

static void ntag424_calc_send_iv(ntag424_session_keys_t *session_keys, uint8_t *out_ivc) {
    uint8_t iv_clear[] = { 0xa5, 0x5a,
                           session_keys->ti[0], session_keys->ti[1], session_keys->ti[2], session_keys->ti[3],
                           (uint8_t)(session_keys->command_counter), (uint8_t)(session_keys->command_counter >> 8),
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
                         };

    uint8_t zero_iv[16] = {0};
    aes_encode(zero_iv, session_keys->encryption, iv_clear, out_ivc, 16);
}

static void ntag424_calc_receive_iv(ntag424_session_keys_t *session_keys, uint8_t *out_ivc) {
    uint8_t iv_clear[] = { 0x5a, 0xa5,
                           session_keys->ti[0], session_keys->ti[1], session_keys->ti[2], session_keys->ti[3],
                           (uint8_t)(session_keys->command_counter), (uint8_t)(session_keys->command_counter >> 8),
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
                         };

    uint8_t zero_iv[16] = {0};
    aes_encode(zero_iv, session_keys->encryption, iv_clear, out_ivc, 16);
}

static void ntag424_calc_mac(const ntag424_session_keys_t *session_keys, uint8_t command, const uint8_t *data, uint8_t datalen, uint8_t *out_mac) {
    uint8_t mac_input_header[] = { command,
                                   (uint8_t)session_keys->command_counter, (uint8_t)(session_keys->command_counter >> 8),
                                   session_keys->ti[0], session_keys->ti[1], session_keys->ti[2], session_keys->ti[3]
                                 };

    int mac_input_len = sizeof(mac_input_header) + datalen;

    uint8_t *mac_input = (uint8_t *)calloc(mac_input_len, sizeof(uint8_t));
    memcpy(mac_input, mac_input_header, sizeof(mac_input_header));
    memcpy(&mac_input[sizeof(mac_input_header)], data, datalen);
    uint8_t mac[16] = {0};
    mbedtls_aes_cmac_prf_128(session_keys->mac, 16, mac_input, sizeof(mac_input_header) + datalen, mac);

    for (int i = 0; i < 8; i++) {
        out_mac[i] = mac[i * 2 + 1];
    }

    free(mac_input);
}

static int ntag424_comm_mac_apdu(APDU_t *apdu, int command_header_length, int apdu_max_data_size, ntag424_session_keys_t *session_keys) {

    int size = apdu->lc;

    if (size + 8 > apdu_max_data_size) {
        return PM3_EOVFLOW;
    }

    ntag424_calc_mac(session_keys, apdu->ins, apdu->data, size, &apdu->data[size]);
    session_keys->command_counter++; // CmdCtr should be incremented each time a MAC is calculated
    apdu->lc = size + 8;

    return PM3_SUCCESS;
}

static int ntag424_comm_encrypt_apdu(APDU_t *apdu, int command_header_length, int apdu_max_data_size, ntag424_session_keys_t *session_keys) {
    // ------- Calculate IV
    uint8_t ivc[16];
    ntag424_calc_send_iv(session_keys, ivc);

    int size = apdu->lc;

    size_t encrypt_data_size = size - command_header_length;
    size_t padded_data_size = encrypt_data_size + 16 - (encrypt_data_size % 16); // pad up to 16 byte blocks
    uint8_t temp_buffer[256] = {0};

    if (!encrypt_data_size) {
        return PM3_SUCCESS;
    }

    if (padded_data_size + command_header_length > apdu_max_data_size) {
        return PM3_EOVFLOW;
    }

    // ------ Pad data
    memcpy(temp_buffer, &apdu->data[command_header_length], encrypt_data_size); // We encrypt everything except the CmdHdr (first byte in data)
    temp_buffer[encrypt_data_size] = 0x80;

    // ------ Encrypt it
    aes_encode(ivc, session_keys->encryption, temp_buffer, &apdu->data[command_header_length], padded_data_size);

    apdu->lc = (uint8_t)(command_header_length + padded_data_size); // Set size to CmdHdr + padded data

    return PM3_SUCCESS;
}

static int ntag424_exchange_apdu(APDU_t apdu, int command_header_length, uint8_t *response, int *response_length, ntag424_communication_mode_t comm_mode, ntag424_session_keys_t *session_keys, uint8_t sw1_expected, uint8_t sw2_expected) {

    int res;

    // New buffer since we might need to expand the data in the apdu
    int buffer_length = 256;
    uint8_t tmp_apdu_buffer[256] = {0};

    if (comm_mode != COMM_PLAIN) {
        if (session_keys == NULL) {
            PrintAndLogEx(ERR, "Non-plain communications mode requested but no session keys supplied");
            return PM3_EINVARG;
        }
        memcpy(tmp_apdu_buffer, apdu.data, apdu.lc);
        apdu.data = tmp_apdu_buffer;
    }

    if (comm_mode == COMM_FULL) {
        res = ntag424_comm_encrypt_apdu(&apdu, command_header_length, buffer_length, session_keys);
        if (res != PM3_SUCCESS) {
            return res;
        }
    }

    if (comm_mode == COMM_MAC || comm_mode == COMM_FULL) {
        res = ntag424_comm_mac_apdu(&apdu, command_header_length, buffer_length, session_keys);
        if (res != PM3_SUCCESS) {
            return res;
        }
    }

    uint8_t cmd[256] = {0};
    int apdu_length = 256;

    if (APDUEncode(&apdu, cmd, &apdu_length) != 0) {
        return PM3_EINVARG;
    }

    res = ExchangeAPDU14a(cmd, apdu_length + 1, false, true, response, *response_length, response_length);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Failed to exchange APDU: %d", res);
        return res;
    }

    if (*response_length < 2) {
        PrintAndLogEx(ERR, "No response");
        return PM3_ESOFT;
    }

    uint8_t sw1 = response[*response_length - 2];
    uint8_t sw2 = response[*response_length - 1];

    if (sw1 != sw1_expected || sw2 != sw2_expected) {
        PrintAndLogEx(ERR, "Error from card: %02X %02X (%s)", sw1, sw2, GetAPDUCodeDescription(sw1, sw2));
        return PM3_ESOFT;
    }

    // Decrypt data if we are in full communications mode. If we want to verify MAC, this
    // should also be done here
    if (comm_mode == COMM_FULL) {
        uint8_t iv[16] = {0};
        ntag424_calc_receive_iv(session_keys, iv);

        uint8_t tmp[256];
        memcpy(tmp, response, *response_length);
        aes_decode(iv, session_keys->encryption, response, tmp, *response_length - 10);

        memcpy(response, tmp, *response_length);
    }

    return PM3_SUCCESS;
}


static int ntag424_get_file_settings(uint8_t fileno, ntag424_file_settings_t *settings_out) {
    int response_length = sizeof(ntag424_file_settings_t) + 2;
    uint8_t response[response_length];

    APDU_t apdu = {
        .cla = 0x90,
        .ins = NTAG424_CMD_GET_FILE_SETTINGS,
        .lc = 1,
        .data = &fileno,
        .extended_apdu = false
    };

    int res = ntag424_exchange_apdu(apdu, 1, response, &response_length, COMM_PLAIN, NULL, 0x91, 0x00);
    if (res != PM3_SUCCESS) {
        return res;
    }

    if (settings_out) {
        memcpy(settings_out, response, response_length);
    }

    return PM3_SUCCESS;
}

static int ntag424_write_file_settings(uint8_t fileno, const ntag424_file_settings_t *settings, ntag424_session_keys_t *session_keys) {

    // ------- Convert file settings to the format for writing
    file_settings_write_t write_settings = {
        .options = settings->options,
        .access[0] = settings->access[0],
        .access[1] = settings->access[1],
        .optional_sdm_settings = settings->optional_sdm_settings,
    };

    size_t settings_size = ntag424_calc_file_write_settings_size(settings);

    uint8_t cmd_buffer[256];
    cmd_buffer[0] = fileno;
    memcpy(&cmd_buffer[1], &write_settings, settings_size);

    APDU_t apdu = {
        .cla = 0x90,
        .ins = NTAG424_CMD_CHANGE_FILE_SETTINGS,
        .lc = 1 + settings_size,
        .data = cmd_buffer
    };


    // ------- Actually send the APDU
    int response_length = 8 + 2;
    uint8_t response[response_length];

    int res = ntag424_exchange_apdu(apdu, 1, response, &response_length, COMM_FULL, session_keys, 0x91, 0x00);
    return res;
}

static void ntag424_print_file_settings(uint8_t fileno, const ntag424_file_settings_t *settings) {

    int num_sdm_data = (ntag424_calc_file_settings_size(settings) - SETTINGS_WITHOUT_SDM_DATA_SIZE) / 3;

    PrintAndLogEx(SUCCESS, "--- " _CYAN_("File %d settings:"), fileno);

    PrintAndLogEx(SUCCESS, "       type: " _GREEN_("%02X"), settings->type);
    PrintAndLogEx(SUCCESS, "    options: " _GREEN_("%02X"), settings->options);
    PrintAndLogEx(SUCCESS, "     access: " _GREEN_("%02X%02X (RW, C, R, W)"), settings->access[0], settings->access[1]);
    PrintAndLogEx(SUCCESS, "       size: " _GREEN_("%02X%02X%02X"), settings->size[2], settings->size[1], settings->size[0]);

    if (settings->options & FILE_SETTINGS_OPTIONS_SDM_AND_MIRRORING) {
        PrintAndLogEx(SUCCESS, "--- " _CYAN_("SDM settings: "));
        PrintAndLogEx(SUCCESS, "    options: " _GREEN_("%02X"), settings->optional_sdm_settings.sdm_options);
        PrintAndLogEx(SUCCESS, " sdm access: " _GREEN_("%02X%02X"), settings->optional_sdm_settings.sdm_access[0], settings->optional_sdm_settings.sdm_access[1]);

        if (num_sdm_data > 0) {
            PrintAndLogEx(SUCCESS, "--- " _CYAN_("SDM data: "));
            for (int i = 0; i < num_sdm_data; i++) {
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
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Failed to send apdu");
        return res;
    }

    if (outlen != RESPONSE_LENGTH || resp[RESPONSE_LENGTH - 2] != 0x90 || resp[RESPONSE_LENGTH - 1] != 0x00) {
        PrintAndLogEx(ERR, "Failed to select application");
        return PM3_ESOFT;
    }

    return PM3_SUCCESS;
}

static int ntag424_auth_first_step(uint8_t keyno, uint8_t *key, uint8_t *out) {
    uint8_t key_number[2] = { keyno, 0x00 };

    APDU_t apdu = {
        .cla = 0x90,
        .ins = NTAG424_CMD_AUTHENTICATE_EV2_FIRST,
        .lc = 0x02,
        .data = key_number
    };

    int response_length = 16 + 2;
    uint8_t response[response_length];

    int res = ntag424_exchange_apdu(apdu, 2, response, &response_length, COMM_PLAIN, NULL, 0x91, 0xAF);
    if (res != PM3_SUCCESS) {
        return res;
    }

    if (response_length != 16 + 2) {
        PrintAndLogEx(ERR, "Failed to get RndB (invalid key number?)");
        return PM3_ESOFT;
    }

    uint8_t iv[16] = {0};
    aes_decode(iv, key, response, out, 16);

    return PM3_SUCCESS;
}

static int ntag424_auth_second_step(uint8_t *challenge, uint8_t *response_out) {
    APDU_t apdu = {
        .cla = 0x90,
        .ins = NTAG424_CMD_MORE_DATA,
        .lc = 0x20,
        .data = challenge,
    };
    int response_length = 256;
    uint8_t response[response_length];

    int res = ntag424_exchange_apdu(apdu, 0x20, response, &response_length, COMM_PLAIN, NULL, 0x91, 0x00);
    if (res != PM3_SUCCESS) {
        return res;
    }

    memcpy(response_out, response, response_length - 2);

    return PM3_SUCCESS;
}

// Authenticate against a key number and optionally get session keys out
static int ntag424_authenticate_ev2_first(uint8_t keyno, uint8_t *key, ntag424_session_keys_t *session_keys_out) {
    // -------- Get first challenge from card
    uint8_t rnd_b_clear[16] = {0};

    int res = ntag424_auth_first_step(keyno, key, rnd_b_clear);
    if (res != PM3_SUCCESS) {
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
    uint8_t resp[4 + 16 + 6 + 6];
    res = ntag424_auth_second_step(concat_enc, resp);
    if (res != PM3_SUCCESS) {
        return res;
    }

    ntag424_ev2_response_t response;
    aes_decode(iv, key, resp, (uint8_t *)&response, sizeof(ntag424_ev2_response_t));

    // -------- Verify that the response we got contains the RndA that we supplied (rotated one byte)
    if (memcmp(response.rnd_a, &rnd_a_clear[1], 15) != 0 ||
            response.rnd_a[15] != rnd_a_clear[0]) {
        PrintAndLogEx(ERR, "Incorrect response from card\n"
                      "expected: %s\n"
                      "got: %s"
                      , sprint_hex(rnd_a_clear, 16),
                      sprint_hex(response.rnd_a, 16));
        return PM3_ESOFT;
    }

    // -------- Optionally calculate session keys
    if (session_keys_out) {
        memset(session_keys_out, 0, sizeof(ntag424_session_keys_t));
        memcpy(session_keys_out->ti, response.ti, sizeof(response.ti));

        // SV 1 = [0xA5][0x5A][0x00][0x01]
        // [0x00][0x80][RndA[15:14] ||
        // [ (RndA[13:8] ⊕ RndB[15:10]) ] ||
        // [RndB[9:0] || RndA[7:0]

        uint8_t sv1[] = { 0xa5, 0x5a, 0x00, 0x01, 0x00, 0x80, rnd_a_clear[0], rnd_a_clear[1],
                          rnd_a_clear[2] ^rnd_b_clear[0],
                          rnd_a_clear[3] ^rnd_b_clear[1],
                          rnd_a_clear[4] ^rnd_b_clear[2],
                          rnd_a_clear[5] ^rnd_b_clear[3],
                          rnd_a_clear[6] ^rnd_b_clear[4],
                          rnd_a_clear[7] ^rnd_b_clear[5],
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
                          rnd_a_clear[2] ^rnd_b_clear[0],
                          rnd_a_clear[3] ^rnd_b_clear[1],
                          rnd_a_clear[4] ^rnd_b_clear[2],
                          rnd_a_clear[5] ^rnd_b_clear[3],
                          rnd_a_clear[6] ^rnd_b_clear[4],
                          rnd_a_clear[7] ^rnd_b_clear[5],
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

#define MAX_WRITE_APDU (200)

// Write file to card. Only supports plain communications mode. Authentication must be done
// first unless file has free write access.
static int ntag424_write_data(uint8_t fileno, uint32_t offset, uint32_t num_bytes, uint8_t *in, ntag424_communication_mode_t comm_mode, ntag424_session_keys_t *session_keys) {
    size_t remainder = 0;

    // Split writes that are too large for one APDU
    if (num_bytes > MAX_WRITE_APDU) {
        remainder = num_bytes - MAX_WRITE_APDU;
        num_bytes = MAX_WRITE_APDU;
    }

    uint8_t cmd_header[] = {
        fileno,
        (uint8_t)offset,
        (uint8_t)(offset << 8),
        (uint8_t)(offset << 16), // offset
        (uint8_t)num_bytes,
        (uint8_t)(num_bytes >> 8),
        (uint8_t)(num_bytes >> 16) // size
    };

    uint8_t cmd[256] = {0};

    memcpy(cmd, cmd_header, sizeof(cmd_header));
    memcpy(&cmd[sizeof(cmd_header)], in, num_bytes);

    APDU_t apdu = {
        .cla = 0x90,
        .ins = NTAG424_CMD_WRITE_DATA,
        .lc = sizeof(cmd_header) + num_bytes,
        .data = cmd,
    };

    int response_length = 8 + 2; // potential MAC and result
    uint8_t response[response_length];

    int res = ntag424_exchange_apdu(apdu, sizeof(cmd_header), response, &response_length, comm_mode, session_keys, 0x91, 0x00);
    if (res != PM3_SUCCESS) {
        return res;
    }

    if (remainder > 0) {
        return ntag424_write_data(fileno, offset + num_bytes, remainder, &in[num_bytes], comm_mode, session_keys);
    }

    return PM3_SUCCESS;
}

// Read file from card. Only supports plain communications mode. Authentication must be done
// first unless file has free read access.
static int ntag424_read_data(uint8_t fileno, uint16_t offset, uint16_t num_bytes, uint8_t *out, ntag424_communication_mode_t comm_mode, ntag424_session_keys_t *session_keys) {
    uint8_t cmd_header[] = {
        fileno,
        (uint8_t)offset, (uint8_t)(offset << 8), (uint8_t)(offset << 16), // offset
        (uint8_t)num_bytes, (uint8_t)(num_bytes >> 8), 0x00
    };

    APDU_t apdu = {
        .cla = 0x90,
        .ins = NTAG424_CMD_READ_DATA,
        .lc = sizeof(cmd_header),
        .data = cmd_header,
    };

    int response_length = num_bytes + 4 + 2 + 20; // number of bytes to read + mac + result + potential padding
    uint8_t response[response_length];

    int res = ntag424_exchange_apdu(apdu, sizeof(cmd_header), response, &response_length, comm_mode, session_keys, 0x91, 0x00);
    if (res != PM3_SUCCESS) {
        return res;
    }

    memcpy(out, response, num_bytes);
    return PM3_SUCCESS;
}

static int ntag424_get_version(ntag424_full_version_information_t *version) {
    APDU_t apdu = {
        .cla = 0x90,
        .ins = NTAG424_CMD_GET_VERSION,
    };


    uint8_t response[256];

    int response_length = sizeof(ntag424_version_information_t) + 2;
    if (ntag424_exchange_apdu(apdu, 0, response, &response_length, COMM_PLAIN, NULL, 0x91, 0xAF) != PM3_SUCCESS) {
        return PM3_ESOFT;
    }
    memcpy(&version->hardware, response, sizeof(ntag424_version_information_t));

    APDU_t continue_apdu = {
        .cla = 0x90,
        .ins = NTAG424_CMD_MORE_DATA,
    };

    response_length = sizeof(ntag424_version_information_t) + 2;
    if (ntag424_exchange_apdu(continue_apdu, 0, response, &response_length, COMM_PLAIN, NULL, 0x91, 0xAF) != PM3_SUCCESS) {
        return PM3_ESOFT;
    }
    memcpy(&version->software, response, sizeof(ntag424_version_information_t));

    response_length = sizeof(ntag424_production_information_t) + 2;
    if (ntag424_exchange_apdu(continue_apdu, 0, response, &response_length, COMM_PLAIN, NULL, 0x91, 0x00) != PM3_SUCCESS) {
        return PM3_ESOFT;
    }
    memcpy(&version->production, response, sizeof(ntag424_production_information_t));

    return PM3_SUCCESS;
}

#define NXP_SIGNATURE_LENGTH 56
#define NXP_SIGNATURE_ID 0x00

static int ntag424_get_signature(uint8_t *signature_out) {
    uint8_t signature_id = NXP_SIGNATURE_ID;
    APDU_t apdu = {
        .cla = 0x90,
        .ins = NTAG424_CMD_GET_SIGNATURE,
        .lc = 1,
        .data = &signature_id,
    };

    int response_length = NXP_SIGNATURE_LENGTH + 2;
    // This is a weird one. Datasheet claims this command should result in 91 00, but cards, and the AN12196
    // document shows 91 90 on success.
    if (ntag424_exchange_apdu(apdu, 1, signature_out, &response_length, COMM_PLAIN, NULL, 0x91, 0x90) != PM3_SUCCESS) {
        return PM3_ESOFT;
    }

    return PM3_SUCCESS;
}

static int ntag424_change_key(uint8_t keyno, const uint8_t *new_key, const uint8_t *old_key, uint8_t version, ntag424_session_keys_t *session_keys) {
    // -------- Calculate xor and crc
    uint8_t key[16] = {0};
    uint8_t crc[4] = {0};
    if (keyno != 0) {
        for (int i = 0; i < 16; i++) {
            key[i] = old_key[i] ^ new_key[i];
        }
        crc32_ex(new_key, 16, crc);
    } else {
        memcpy(key, new_key, 16);
    }

    // ------- Assemble KeyData command
    uint8_t key_cmd_data[32] = {0};
    key_cmd_data[0] = keyno;
    memcpy(&key_cmd_data[1], key, 16);
    key_cmd_data[17] = version;
    int key_data_len;
    if (keyno != 0) {
        memcpy(&key_cmd_data[18], crc, sizeof(crc));
        key_data_len = sizeof(keyno) + sizeof(key) + sizeof(version) + sizeof(crc);
    } else {
        key_data_len = sizeof(keyno) + sizeof(key) + sizeof(version);
    }

    APDU_t apdu = {
        .cla = 0x90,
        .ins = NTAG424_CMD_CHANGE_KEY,
        .lc = key_data_len,
        .data = key_cmd_data
    };

    int response_length = 8 + 2;
    uint8_t response[response_length];

    int res = ntag424_exchange_apdu(apdu, 1, response, &response_length, COMM_FULL, session_keys, 0x91, 0x00);
    return res;
}

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
    char fn[FILE_PATH_SIZE];
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)fn, FILE_PATH_SIZE, &fnlen);
    bool verbose = arg_get_lit(ctx, 2);
    CLIParserFree(ctx);

    // read dump file
    uint8_t *dump = NULL;
    size_t bytes_read = NTAG424_MAX_BYTES;
    int res = pm3_load_dump(fn, (void **)&dump, &bytes_read, NTAG424_MAX_BYTES);
    if (res != PM3_SUCCESS) {
        return res;
    }

    if (verbose) {
        PrintAndLogEx(INFO, "File: " _YELLOW_("%s"), fn);
        PrintAndLogEx(INFO, "File size %zu bytes", bytes_read);
    }

    // to be implemented...
    PrintAndLogEx(INFO, "not implemented yet");
    PrintAndLogEx(INFO, "Feel free to contribute!");

    free(dump);
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

    if (SelectCard14443A_4(false, true, NULL) != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Failed to select card");
        DropField();
        return PM3_ERFTRANS;
    }

    if (ntag424_select_application() != PM3_SUCCESS) {
        DropField();
        return PM3_ESOFT;
    }

    ntag424_full_version_information_t version = {0};
    if (ntag424_get_version(&version) != PM3_SUCCESS) {
        DropField();
        return PM3_ESOFT;
    }
    ntag424_print_full_version_information(&version);

    uint8_t signature[NXP_SIGNATURE_LENGTH];
    int res = ntag424_get_signature(signature);
    DropField();

    if (res == PM3_SUCCESS) {
        PrintAndLogEx(INFO, "--- " _CYAN_("NXP originality signature:"));
        desfire_print_signature(version.production.uid, 7, signature, NXP_SIGNATURE_LENGTH);
    }

    return res;
}

static int ntag424_cli_get_auth_information(CLIParserContext *ctx, int keyno_index, int key_index, int *keyno, uint8_t *key_out) {

    if (keyno) {
        *keyno = arg_get_int(ctx, keyno_index);
    }

    int keylen = 16;
    uint8_t key[16] = {0};

    if (CLIParamHexToBuf(arg_get_str(ctx, key_index), key, sizeof(key), &keylen) || (keylen != 16)) {
        return PM3_ESOFT;
    }

    memcpy(key_out, key, 16);
    return PM3_SUCCESS;
}

static int CmdHF_ntag424_auth(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf ntag424 auth",
                  "Authenticate with selected key against NTAG424.",
                  "hf ntag424 auth --keyno 0 -k 00000000000000000000000000000000");

    void *argtable[] = {
        arg_param_begin,
        arg_int1(NULL, "keyno", "<dec>", "Key number"),
        arg_str1("k",  "key", "<hex>", "Key for authenticate (HEX 16 bytes)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int keyno = 0;
    uint8_t key[16] = {0};
    if (ntag424_cli_get_auth_information(ctx, 1, 2, &keyno, key) != PM3_SUCCESS) {
        CLIParserFree(ctx);
        return PM3_ESOFT;
    }

    CLIParserFree(ctx);

    if (SelectCard14443A_4(false, true, NULL) != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Failed to select card");
        DropField();
        return PM3_ERFTRANS;
    }

    if (ntag424_select_application() != PM3_SUCCESS) {
        DropField();
        return PM3_ESOFT;
    }

    int res = ntag424_authenticate_ev2_first(keyno, key, NULL);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Auth key %d ( " _RED_("fail") " )", keyno);
    } else {
        PrintAndLogEx(SUCCESS, "Auth key %d ( " _GREEN_("ok") " )", keyno);
    }

    DropField();
    return PM3_SUCCESS;
}

// Read can only read files with plain communication mode!
static int CmdHF_ntag424_read(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf ntag424 read",
                  "Read and print data from file on NTAG424 tag. Will authenticate if key information is provided.",
                  "hf ntag424 read --fileno 1 --keyno 0 -k 00000000000000000000000000000000 -o 0 -l 32\n"
                  "hf ntag424 read --fileno 2 --keyno 0 -k 00000000000000000000000000000000 -o 0 -l 256\n"
                  "hf ntag424 read --fileno 3 --keyno 3 -k 00000000000000000000000000000000 -o 0 -l 128 -m encrypt");

    void *argtable[] = {
        arg_param_begin,
        arg_int1(NULL, "fileno", "<1|2|3>", "File number"),
        arg_int0(NULL, "keyno",  "<dec>",   "Key number"),
        arg_str0("k",  "key",    "<hex>",   "Key for authentication (HEX 16 bytes)"),
        arg_int0("o",  "offset", "<dec>",   "Offset to read in file (def 0)"),
        arg_int1("l",  "length", "<dec>",   "Number of bytes to read"),
        arg_str0("m",  "cmode",  "<plain|mac|encrypt>", "Communication mode"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int fileno = arg_get_int(ctx, 1);

    int keyno = 0;
    uint8_t key[16] = {0};
    bool auth = (ntag424_cli_get_auth_information(ctx, 2, 3, &keyno, key) == PM3_SUCCESS);

    int offset = arg_get_int_def(ctx, 4, 0);
    int read_length = arg_get_int(ctx, 5);

    ntag424_communication_mode_t comm_mode;
    int comm_out = 0;
    if (CLIGetOptionList(arg_get_str(ctx, 6), ntag424_communication_mode_options, &comm_out)) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }
    CLIParserFree(ctx);

    comm_mode = comm_out;

    if (comm_mode != COMM_PLAIN && auth == false) {
        PrintAndLogEx(ERR, "Only plain communication mode can be used without a key specified");
        return PM3_EINVARG;
    }

    if (SelectCard14443A_4(false, true, NULL) != PM3_SUCCESS) {
        DropField();
        PrintAndLogEx(ERR, "Failed to select card");
        return PM3_ERFTRANS;
    }

    if (ntag424_select_application() != PM3_SUCCESS) {
        DropField();
        return PM3_ESOFT;
    }

    int res = PM3_SUCCESS;
    ntag424_session_keys_t session_keys;
    if (auth) {
        res = ntag424_authenticate_ev2_first(keyno, key, &session_keys);
        if (res != PM3_SUCCESS) {
            PrintAndLogEx(ERR, "Auth key %d ( " _RED_("fail") " )", keyno);
            DropField();
            return res;
        } else {
            PrintAndLogEx(SUCCESS, "Auth key %d ( " _GREEN_("ok") " )", keyno);
        }
    }

    uint8_t data[512] = {0};
    res = ntag424_read_data(fileno, offset, read_length, data, comm_mode, &session_keys);
    DropField();
    if (res == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, " -------- Read file " _YELLOW_("%d") " contents ------------ ", fileno);
        print_hex_break(data, read_length, 16);
    }
    return res;
}

static int CmdHF_ntag424_write(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf ntag424 write",
                  "Write data to file on NTAG424 tag. Will authenticate if key information is provided.",
                  "hf ntag424 write --fileno 2 --keyno 0 -k 00000000000000000000000000000000 -o 0 -d 1122334455667788\n"
                  "hf ntag424 write --fileno 3 --keyno 3 -k 00000000000000000000000000000000 -o 0 -d 1122334455667788 -m encrypt");

    void *argtable[] = {
        arg_param_begin,
        arg_u64_1(NULL, "fileno",  "<1|2|3>", "File number (def 2)"),
        arg_int0(NULL, "keyno",   "<dec>", "Key number"),
        arg_str0("k",  "key",     "<hex>", "Key for authentication (HEX 16 bytes)"),
        arg_int0("o",  "offset",  "<dec>", "Offset to write in file (def 0)"),
        arg_str1("d",  "data",    "<hex>", "Data to write"),
        arg_str0("m",  "cmode",   "<plain|mac|encrypt>", "Communication mode"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int fileno = arg_get_int(ctx, 1);

    int keyno = 0;
    uint8_t key[16] = {0};
    bool auth = (ntag424_cli_get_auth_information(ctx, 2, 3, &keyno, key) == PM3_SUCCESS);

    uint32_t offset = arg_get_u32_def(ctx, 4, 0);

    uint8_t data[512] = {0};
    int datalen = 512;
    CLIGetHexWithReturn(ctx, 5, data, &datalen);

    ntag424_communication_mode_t comm_mode;
    int comm_out = 0;
    if (CLIGetOptionList(arg_get_str(ctx, 6), ntag424_communication_mode_options, &comm_out)) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }
    CLIParserFree(ctx);

    comm_mode = comm_out;

    if (comm_mode != COMM_PLAIN && auth == false) {
        PrintAndLogEx(ERR, "Only plain communication mode can be used without a key specified");
        return PM3_EINVARG;
    }

    if (SelectCard14443A_4(false, true, NULL) != PM3_SUCCESS) {
        DropField();
        PrintAndLogEx(ERR, "Failed to select card");
        return PM3_ERFTRANS;
    }

    if (ntag424_select_application() != PM3_SUCCESS) {
        DropField();
        return PM3_ESOFT;
    }

    int res = PM3_SUCCESS;
    ntag424_session_keys_t session_keys = {0};
    if (auth) {
        res = ntag424_authenticate_ev2_first(keyno, key, &session_keys);
        if (res != PM3_SUCCESS) {
            PrintAndLogEx(ERR, "Auth key %d ( " _RED_("fail") " )", keyno);
            DropField();
            return res;
        } else {
            PrintAndLogEx(SUCCESS, "Auth key %d ( " _GREEN_("ok") " )", keyno);
        }
    }

    res = ntag424_write_data(fileno, offset, (uint32_t)datalen, data, comm_mode, &session_keys);
    DropField();
    if (res == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "Wrote " _YELLOW_("%d") " bytes ( " _GREEN_("ok") " )", datalen);
    } else {
        PrintAndLogEx(ERR, "Wrote " _YELLOW_("%d") " bytes ( " _RED_("fail") " )", datalen);
    }
    return res;
}

static int CmdHF_ntag424_getfilesettings(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf ntag424 getfs",
                  "Read and print file settings for file",
                  "hf ntag424 getfs --fileno 2");

    void *argtable[] = {
        arg_param_begin,
        arg_int1(NULL,  "fileno", "<dec>", "File number"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    int fileno = arg_get_int(ctx, 1);

    CLIParserFree(ctx);

    if (SelectCard14443A_4(false, true, NULL) != PM3_SUCCESS) {
        DropField();
        PrintAndLogEx(ERR, "Failed to select card");
        return PM3_ERFTRANS;
    }

    if (ntag424_select_application() != PM3_SUCCESS) {
        DropField();
        return PM3_ESOFT;
    }

    ntag424_file_settings_t settings = {0};
    int res = ntag424_get_file_settings(fileno, &settings);
    DropField();
    if (res == PM3_SUCCESS) {
        ntag424_print_file_settings(fileno, &settings);
    }
    return res;
}

static int CmdHF_ntag424_changefilesettings(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf ntag424 changefs",
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
                  "Order is Reserved, SDMCtrRet, SDMMetaRead and SDMFileRead\n\n"

                  "sdm_data: Three bytes of data used to control SDM settings. Can be specified multiple times.\n"
                  "Data means different things depending on settings.\n\n"

                  "Note: Not all of these settings will be written. It depends on the option byte, and the keys set. See AN12196 for more information.\n"
                  "You must also start with sdmdata1, then sdmdata2, up to the number of sdm_data you want to write",

                  "hf ntag424 changefs --fileno 2 --keyno 0 -k 00000000000000000000000000000000 -o 40 -a 00E0 -s C1 -c F000 --data1 000020 --data2 000043 --data3 000043"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_int1(NULL, "fileno", "<dec>", "File number"),
        arg_int1(NULL, "keyno", "<dec>", "Key number"),
        arg_str1("k",  "key", "<hex>", "Key for authentication (HEX 16 bytes)"),
        arg_str0("o",  "options", "<hex>", "File options byte (HEX 1 byte)"),
        arg_str0("a",  "access", "<hex>", "File access settings (HEX 2 bytes)"),
        arg_str0("s",  "sdmoptions", "<hex>", "SDM options (HEX 1 byte)"),
        arg_str0("c",  "sdmaccess", "<hex>", "SDM access settings (HEX 2 bytes)"),
        arg_str0(NULL, "data1", "<hex>", "SDM data (HEX 3 bytes)"),
        arg_str0(NULL, "data2", "<hex>", "SDM data (HEX 3 bytes)"),
        arg_str0(NULL, "data3", "<hex>", "SDM data (HEX 3 bytes)"),
        arg_str0(NULL, "data4", "<hex>", "SDM data (HEX 3 bytes)"),
        arg_str0(NULL, "data5", "<hex>", "SDM data (HEX 3 bytes)"),
        arg_str0(NULL, "data6", "<hex>", "SDM data (HEX 3 bytes)"),
        arg_str0(NULL, "data7", "<hex>", "SDM data (HEX 3 bytes)"),
        arg_str0(NULL, "data8", "<hex>", "SDM data (HEX 3 bytes)"),
        // Sorry, couldn't figure out how to work with arg_strn...
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    int fileno = arg_get_int(ctx, 1);

    int keyno = 0;
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

    if (ntag424_cli_get_auth_information(ctx, 2, 3, &keyno, key) != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Could not get key settings");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    int len = 1;
    if (arg_get_str(ctx, 4)->count == 1) {
        has_options = 1;
        CLIGetHexWithReturn(ctx, 4, options, &len);
        if (len != 1) {
            PrintAndLogEx(ERR, "Options must be 1 byte, got ( %d )", len);
            CLIParserFree(ctx);
            return PM3_EINVARG;
        }
    }
    len = 2;
    if (arg_get_str(ctx, 5)->count == 1) {
        has_access = 1;
        CLIGetHexWithReturn(ctx, 5, access, &len);
        if (len != 2) {
            PrintAndLogEx(ERR, "Access must be 2 bytes, got ( %d )", len);
            CLIParserFree(ctx);
            return PM3_EINVARG;
        }
    }
    len = 1;
    if (arg_get_str(ctx, 6)->count == 1) {
        has_sdmoptions = 1;
        CLIGetHexWithReturn(ctx, 6, sdmoptions, &len);
        if (len != 1) {
            PrintAndLogEx(ERR, "SDM Options must be 1 byte, got ( %d )", len);
            CLIParserFree(ctx);
            return PM3_EINVARG;
        }
    }
    len = 2;
    if (arg_get_str(ctx, 7)->count == 1) {
        has_sdmaccess = 1;
        CLIGetHexWithReturn(ctx, 7, sdmaccess, &len);
        if (len != 2) {
            PrintAndLogEx(ERR, "SDM Access must be 2 bytes, got ( %d )", len);
            CLIParserFree(ctx);
            return PM3_EINVARG;
        }
    }

    for (int i = 0; i < 8; i++) {
        if (arg_get_str(ctx, 8 + i)->count == 1) {
            len = 3;
            num_sdm_data++;
            CLIGetHexWithReturn(ctx, 8 + i, sdm_data[i], &len);
            if (len != 3) {
                PrintAndLogEx(ERR, "sdmdata must be 3 bytes, got ( %d )", len);
                CLIParserFree(ctx);
                return PM3_EINVARG;
            }
        } else {
            break;
        }
    }

    CLIParserFree(ctx);

    if (SelectCard14443A_4(false, true, NULL) != PM3_SUCCESS) {
        DropField();
        PrintAndLogEx(ERR, "Failed to select card");
        return PM3_ERFTRANS;
    }

    if (ntag424_select_application() != PM3_SUCCESS) {
        DropField();
        return PM3_ESOFT;
    }

    ntag424_file_settings_t settings = {0};
    if (ntag424_get_file_settings(fileno, &settings) != PM3_SUCCESS) {
        DropField();
        return PM3_ESOFT;
    }

    int res = PM3_SUCCESS;
    ntag424_session_keys_t session = {0};
    res = ntag424_authenticate_ev2_first(keyno, key, &session);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Auth key %d ( " _RED_("fail") " )", keyno);
        DropField();
        return res;
    } else {
        PrintAndLogEx(SUCCESS, "Auth key %d ( " _GREEN_("ok") " )", keyno);
    }

    if (has_options) {
        settings.options = options[0];
    }

    if (has_access) {
        memcpy(settings.access, access, 2);
    }

    if (has_sdmoptions) {
        settings.optional_sdm_settings.sdm_options = sdmoptions[0];
    }

    if (has_sdmaccess) {
        memcpy(settings.optional_sdm_settings.sdm_access, sdmaccess, 2);
    }

    for (int i = 0; i < num_sdm_data; i++) {
        settings.optional_sdm_settings.sdm_data[i][2] = sdm_data[i][0];
        settings.optional_sdm_settings.sdm_data[i][1] = sdm_data[i][1];
        settings.optional_sdm_settings.sdm_data[i][0] = sdm_data[i][2];
    }

    res = ntag424_write_file_settings(fileno, &settings, &session);
    DropField();
    if (res == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "Write settings ( " _GREEN_("ok") " )");
        ntag424_print_file_settings(fileno, &settings);
    } else {
        PrintAndLogEx(ERR, "Write settings (" _RED_("fail") " )");
    }
    return res;
}

static int CmdHF_ntag424_changekey(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf ntag424 changekey",
                  "Change a key.\n"
                  "Authentication key must currently be different to the one we want to change.\n",
                  "hf ntag424 changekey --keyno 1 --oldkey 00000000000000000000000000000000 --newkey 11111111111111111111111111111111 --key0 00000000000000000000000000000000 --kv 1\n"
                  "hf ntag424 changekey --keyno 0 --newkey 11111111111111111111111111111111 --key0 00000000000000000000000000000000 --kv 1\n"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_int1(NULL, "keyno",  "<dec>", "Key number to change"),
        arg_str0(NULL, "oldkey", "<hex>", "Old key (only needed when changing key 1-4, HEX 16 bytes)"),
        arg_str1(NULL, "newkey", "<hex>", "New key (HEX 16 bytes)"),
        arg_str1(NULL, "key0",   "<hex>", "Authentication key (must be key 0, HEX 16 bytes)"),
        arg_int1(NULL, "kv",     "<dec>", "New key version number"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    uint8_t version = arg_get_int(ctx, 6);
    int keyno = arg_get_int(ctx, 1);

    uint8_t oldkey[16] = {0};
    if (keyno != 0) {
        if (ntag424_cli_get_auth_information(ctx, 0, 2, NULL, oldkey) != PM3_SUCCESS) {
            PrintAndLogEx(ERR, "Could not get keyno or old key");
            CLIParserFree(ctx);
            return PM3_EINVARG;
        }
    }

    uint8_t newkey[16] = {0};
    if (ntag424_cli_get_auth_information(ctx, 0, 3, NULL, newkey) != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Could not get new key");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint8_t authkey[16] = {0};
    if (ntag424_cli_get_auth_information(ctx, 0, 4, NULL, authkey) != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Could not get authentication key");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }
    CLIParserFree(ctx);

    if (SelectCard14443A_4(false, true, NULL) != PM3_SUCCESS) {
        DropField();
        PrintAndLogEx(ERR, "Failed to select card");
        return PM3_ERFTRANS;
    }

    if (ntag424_select_application() != PM3_SUCCESS) {
        DropField();
        return PM3_ESOFT;
    }

    int res = PM3_SUCCESS;
    ntag424_session_keys_t session = {0};
    res = ntag424_authenticate_ev2_first(0, authkey, &session);
    if (res != PM3_SUCCESS) {
        DropField();
        PrintAndLogEx(ERR, "Auth ( " _RED_("fail") " )");
        return PM3_ESOFT;
    } else {
        PrintAndLogEx(SUCCESS, "Auth ( " _GREEN_("ok") " )");
    }

    res = ntag424_change_key(keyno, newkey, oldkey, version, &session);
    DropField();
    if (res == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "Change key %d ( " _GREEN_("ok") " )", keyno);
    } else {
        PrintAndLogEx(ERR, "Change key %d ( "_RED_("fail") " )", keyno);
    }

    return res;
}

static command_t CommandTable[] = {
    {"help",         CmdHelp,                          AlwaysAvailable,  "This help"},
    {"-----------",  CmdHelp,                          IfPm3Iso14443a,   "----------------------- " _CYAN_("operations") " -----------------------"},
    {"info",         CmdHF_ntag424_info,               IfPm3Iso14443a,   "Tag information"},
    {"view",         CmdHF_ntag424_view,               AlwaysAvailable,  "Display content from tag dump file"},
    {"auth",         CmdHF_ntag424_auth,               IfPm3Iso14443a,   "Test authentication with key"},
    {"read",         CmdHF_ntag424_read,               IfPm3Iso14443a,   "Read file"},
    {"write",        CmdHF_ntag424_write,              IfPm3Iso14443a,   "Write file"},
    {"getfs",        CmdHF_ntag424_getfilesettings,    IfPm3Iso14443a,   "Get file settings"},
    {"changefs",     CmdHF_ntag424_changefilesettings, IfPm3Iso14443a,   "Change file settings"},
    {"changekey",    CmdHF_ntag424_changekey,          IfPm3Iso14443a,   "Change key"},
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
