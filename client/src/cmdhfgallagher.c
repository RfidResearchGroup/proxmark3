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
// High frequency GALLAGHER tag commands.
// MIFARE DESFire, AIDs 2081F4-2F81F4
//-----------------------------------------------------------------------------

#include "cmdhfgallagher.h"
#include "generator.h"
#include "mifare.h"
#include "mifare/desfirecore.h"
#include "mifare/gallaghercore.h"
#include <stdio.h>
#include <string.h>
#include "common.h"
#include "commonutil.h"
#include "cmdparser.h"
#include "cliparser.h"
#include "ui.h"

static int CmdHelp(const char *cmd);

// Application ID for the Gallagher Card Application Directory
static const uint32_t CAD_AID = 0x2F81F4;

// Default MIFARE site key (16 bytes)
static const uint8_t DEFAULT_SITE_KEY[] = {
    0x31, 0x12, 0xB7, 0x38, 0xD8, 0x86, 0x2C, 0xCD,
    0x34, 0x30, 0x2E, 0xB2, 0x99, 0xAA, 0xB4, 0x56,
};

/**
 * @brief Create Gallagher Application Master Key by diversifying
 * the MIFARE Site Key with card UID, key number, and application ID.
 *
 * @param site_key MIFARE Site Key (16 bytes).
 * @param uid Card unique ID (4 or 7 bytes).
 * @param uid_len Length of UID.
 * @param key_num Key number (0 <= key_num <= 2).
 * @param aid Application ID (3 bytes, e.g. 0x2081F4).
 * @param key_output Buffer to copy the diversified key into (must be 16 bytes).
 * @return PM3_SUCCESS if successful, PM3_EINVARG if an argument is invalid.
 */
int hfgal_diversify_key(uint8_t *site_key, uint8_t *uid, uint8_t uid_len,
                        uint8_t key_num, uint32_t aid, uint8_t *key_output) {
    // Generate diversification input
    uint8_t kdf_input_len = 11;
    int res = mfdes_kdf_input_gallagher(uid, uid_len, key_num, aid, key_output, &kdf_input_len);
    PM3_RET_IF_ERR_WITH_MSG(res, "Failed generating Gallagher key diversification input");

    uint8_t key[sizeof(DEFAULT_SITE_KEY)];
    if (site_key == NULL) {
        PrintAndLogEx(INFO, "hfgal_diversify_key is using default site key");
        memcpy(key, DEFAULT_SITE_KEY, sizeof(key));
    } else {
        memcpy(key, site_key, sizeof(key));
    }

    // Make temporary DesfireContext
    DesfireContext_t dctx = {0};
    DesfireSetKey(&dctx, 0, T_AES, key);

    // Diversify input & copy to output buffer
    MifareKdfAn10922(&dctx, DCOMasterKey, key_output, kdf_input_len);
    memcpy(key_output, dctx.key, CRYPTO_AES128_KEY_SIZE);

    return PM3_SUCCESS;
}

/**
 * @brief Reverses the bytes in AID. Used when parsing CLI args
 * (because Proxmark displays AIDs in reverse byte order).
 */
// iceman todo:  use commonutil.c fct
static void reverse_aid(uint8_t *aid) {
    uint8_t tmp = aid[0];
    aid[0] = aid[2];
    aid[2] = tmp;
}

/**
 * @brief Converts a Card Application Directory format application ID to an integer.
 * Note: the CAD stores AIDs in reverse order, so this is different to DesfireAIDByteToUint().
 */

// iceman todo:  use commonutil.c fct
static uint32_t cad_aid_byte_to_uint(const uint8_t *data) {
    return data[2] + (data[1] << 8) + (data[0] << 16);
}

/**
 * @brief Converts an integer application ID to Card Application Directory format.
 * Note: the CAD stores AIDs in reverse order, so this is different to DesfireAIDUintToByte().
 */
// iceman todo:  use commonutil.c fct
static void cad_aid_uint_to_byte(uint32_t aid, uint8_t *data) {
    data[2] = aid & 0xff;
    data[1] = (aid >> 8) & 0xff;
    data[0] = (aid >> 16) & 0xff;
}

/**
 * @brief Returns true if the Card Application Directory entry
 * is for the specified region & facility, false otherwise.
 */
static bool cad_facility_match(const uint8_t *entry, uint8_t region_code, uint16_t facility_code) {
    return (entry[0] == region_code) &&
           ((entry[1] << 8) + entry[2] == facility_code);
}

/**
 * @brief Select application ID.
 */
static int select_aid(DesfireContext_t *ctx, uint32_t aid, bool verbose) {
    // TODO: do these both need to be set?
    DesfireSetCommMode(ctx, DCMPlain);
    DesfireSetCommandSet(ctx, DCCNativeISO);

    int res = DesfireSelectEx(ctx, true, ISW6bAID, aid, NULL);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Desfire AID %06X select " _RED_("error"), aid);
        return 202;
    }

    if (verbose) {
        PrintAndLogEx(INFO, "Selected AID %06X", aid);
    }

    return PM3_SUCCESS;
}

/**
 * @brief Authenticate to application. Uses existing authentication keys in context.
 */
static int authenticate(DesfireContext_t *ctx, bool verbose) {
    // TODO: do these both need to be set?
    DesfireSetCommMode(ctx, DCMPlain);
    DesfireSetCommandSet(ctx, DCCNativeISO);
    DesfireClearSession(ctx);

    int res = DesfireAuthenticate(ctx, DACEV1, false);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Desfire authenticate " _RED_("error") ". Result: [%d] %s",
                      res,
                      DesfireAuthErrorToStr(res)
                     );
        return res;
    }

    if (DesfireIsAuthenticated(ctx)) {
        if (verbose) {
            PrintAndLogEx(INFO, "Authenticated to AID " _YELLOW_("%06X"), ctx->selectedAID);
        }
    } else {
        return 201;
    }

    return PM3_SUCCESS;
}

/**
 * @brief Select application ID & authenticate.
 * Uses existing authentication keys in context.
 */
static int select_aid_and_auth(DesfireContext_t *ctx, uint32_t aid, bool verbose) {
    int res = select_aid(ctx, aid, verbose);
    PM3_RET_IF_ERR(res);

    res = authenticate(ctx, verbose);
    PM3_RET_IF_ERR(res);

    return PM3_SUCCESS;
}

/**
 * @brief Select application ID & authenticate with specified AES key.
 */
static int select_aid_and_auth_with_key(DesfireContext_t *ctx, uint32_t aid, uint8_t *key,
                                        uint8_t key_num, bool should_diversify, bool verbose) {
    int res = select_aid(ctx, aid, verbose);
    PM3_RET_IF_ERR(res);

    // Set key & diversification algorithm.
    uint8_t kdf_algo = should_diversify ? MFDES_KDF_ALGO_GALLAGHER : MFDES_KDF_ALGO_NONE;
    DesfireSetKeyNoClear(ctx, key_num, T_AES, key);
    DesfireSetKdf(ctx, kdf_algo, NULL, 0);

    res = authenticate(ctx, verbose);
    PM3_RET_IF_ERR(res);

    return PM3_SUCCESS;
}

/**
 * @brief Returns true if the specified application exists, false otherwise.
 */
static bool aid_exists(DesfireContext_t *ctx, uint32_t aid, bool verbose) {
    // TODO: do these both need to be set?
    DesfireSetCommMode(ctx, DCMPlain);
    DesfireSetCommandSet(ctx, DCCNativeISO);

    int res = DesfireSelectAIDHex(ctx, aid, false, 0);
    if (res != PM3_SUCCESS && res != PM3_EAPDU_FAIL) {
        PM3_RET_ERR(false, "Select failed with error %d, assuming AID %06X does not exist", res, aid);
    }

    if (verbose) {
        PrintAndLogEx(INFO, "AID %06X %s",
                      aid,
                      res == PM3_SUCCESS ? "exists" : "does not exist"
                     );
    }

    return (res == PM3_SUCCESS);
}

/**
 * @brief Returns the lowest available Gallagher application ID.
 * @return The lowest available AID in the range 0x??81F4, where ?? >= 0x20.
 */
static uint32_t find_available_gallagher_aid(DesfireContext_t *ctx, bool verbose) {
    // Select PICC
    int res = select_aid(ctx, 0x000000, verbose);
    PM3_RET_IF_ERR(res);

    // Retrieve the AID list
    uint8_t aid_buf[DESFIRE_BUFFER_SIZE] = {0};
    size_t aid_buf_len = 0;

    res = DesfireGetAIDList(ctx, aid_buf, &aid_buf_len);
    if (res != PM3_SUCCESS) {
        PM3_RET_ERR(0, "Failed retrieving AID list");
    }

    if (verbose) {
        // Print what we got
        PrintAndLogEx(INFO, "Retrieved AID list:" NOLF);

        for (int i = 0; i < aid_buf_len; i += 3) {
            PrintAndLogEx(NORMAL, "%s %06X" NOLF,
                          (i == 0) ? "" : ",",
                          DesfireAIDByteToUint(&aid_buf[i])
                         );
        }
        PrintAndLogEx(NORMAL, "");
    }

    // Find lowest available in range F48120 -> F481FE, excluding the CAD
    for (uint8_t aid_increment = 0x20; aid_increment < 0xFF; aid_increment++) {

        uint32_t aid = 0x0081F4 | (aid_increment << 16);
        if (aid == CAD_AID) {
            continue;
        }

        // Check if AID exists in aid_buf
        bool found = false;
        for (size_t idx = 0; idx < aid_buf_len; idx += 3) {

            if (DesfireAIDByteToUint(&aid_buf[idx]) == aid) {
                found = true;
                break;
            }
        }

        if (found == false) {
            return aid;
        }
    }

    // Failed to find an available AID. This is very unlikely to occur as
    // DESFire cards rarely have more than 1 application on them
    PM3_RET_ERR(0, "Checked 200+ AIDs and all exist, abandoning search");
}

/**
 * @brief Delete the CAD or an application that contains cardholder credentials.
 *
 * @param site_key MIFARE site key.
 * @param aid Application ID to remove.
 */
static int hfgal_delete_app(DesfireContext_t *ctx, uint8_t *site_key,
                            uint32_t aid, bool verbose) {
    // Select application & authenticate
    int res = select_aid_and_auth_with_key(ctx, aid, site_key, 0, true, verbose);
    PM3_RET_IF_ERR(res);

    // Delete application
    DesfireSetCommMode(ctx, DCMMACed);
    res = DesfireDeleteApplication(ctx, aid);
    PM3_RET_IF_ERR_WITH_MSG(res, "Failed deleting AID %06X", aid);

    PrintAndLogEx(INFO, "Successfully deleted AID " _YELLOW_("%06X"), aid);
    return PM3_SUCCESS;
}

/**
 * @brief Read credentials from a single AID.
 *
 * @param aid Application ID to read.
 * @param site_key MIFARE site key.
 * @param creds Decoded credentials will be stored in this structure.
 */
static int hfgal_read_creds_app(DesfireContext_t *ctx, uint32_t aid, uint8_t *site_key,
                                GallagherCredentials_t *creds, bool verbose) {
    // Check that card UID has been set
    if (ctx->uidlen == 0) {
        PM3_RET_ERR(PM3_EINVARG, "Card UID must be set in DesfireContext (required for key div)");
    }

    // Select application & authenticate
    int res = select_aid_and_auth_with_key(ctx, aid, site_key, 0, true, verbose);
    PM3_RET_IF_ERR_WITH_MSG(res, "Failed selecting/authenticating to AID %06X", aid);

    // Read file 0 (contains credentials)
    uint8_t buf[16] = {0};
    size_t read_len = 0;
    DesfireSetCommMode(ctx, DCMEncrypted);
    res = DesfireReadFile(ctx, 0, 0, 16, buf, &read_len);
    PM3_RET_IF_ERR_WITH_MSG(res, "Failed reading file 0 in AID %06X", aid);

    // Check file contained 16 bytes of data
    if (read_len != 16) {
        PM3_RET_ERR(PM3_EFAILED, "Failed reading file 0 in AID %06X, expected 16 bytes, got %zu bytes",
                    aid,
                    read_len
                   );
    }

    // Check second half of file is the bitwise inverse of the first half
    for (uint8_t i = 8; i < 16; i++) {
        buf[i] ^= 0xFF;
    }

    if (memcmp(buf, &buf[8], 8) != 0) {
        PM3_RET_ERR(PM3_EFAILED, "Invalid cardholder data in file 0 in AID %06X. Received %s",
                    aid,
                    sprint_hex_inrow(buf, 16)
                   );
    }

    gallagher_decode_creds(buf, creds);

    // TODO: read MIFARE Enhanced Security file
    // https://github.com/megabug/gallagher-research/blob/master/formats/mes.md

    return PM3_SUCCESS;
}

/**
 * @brief Create a new application to store Gallagher cardholder credentials.
 *
 * @param site_key MIFARE site key.
 * @param aid New application ID. 3 bytes, e.g. 0x2081F4.
 */
static int hfgal_create_creds_app(DesfireContext_t *ctx, uint8_t *site_key, uint32_t aid, bool verbose) {
    // Select application & authenticate
    int res = select_aid_and_auth(ctx, 0x000000, verbose);
    PM3_RET_IF_ERR(res);

    // UID is required for key diversification
    if (ctx->uidlen == 0) {
        PM3_RET_ERR(PM3_EINVARG, "UID is required for key diversification. "
                    "Please fetch it before calling `hfgal_create_creds_app`");
    }

    // Create application
    DesfireCryptoAlgorithm app_algo = T_AES;
    uint8_t num_keys = 3;
    uint8_t ks1 = 0x0B;
    uint8_t ks2 = (DesfireKeyAlgoToType(app_algo) << 6) | num_keys;

    uint8_t data[5] = {0};
    DesfireAIDUintToByte(aid, &data[0]);
    data[3] = ks1;
    data[4] = ks2;

    DesfireSetCommMode(ctx, DCMMACed);
    res = DesfireCreateApplication(ctx, data, ARRAYLEN(data));
    PM3_RET_IF_ERR_WITH_MSG(res, "Failed creating application %06X. Does it already exist?", aid);

    if (verbose) {
        PrintAndLogEx(INFO, "Created application " _YELLOW_("%06X") " (empty contents & blank keys)", aid);
    }

    // Select the new application
    res = select_aid(ctx, aid, verbose);
    PM3_RET_IF_ERR_WITH_MSG(res, "Failed selecting application %06X", aid);

    // Add key 2, then key 0 (we must authenticate with key 0 in order to make changes)
    for (int i = 2; i >= 0; i -= 2) {
        // Diversify key
        uint8_t buf[CRYPTO_AES128_KEY_SIZE] = {0};
        res = hfgal_diversify_key(site_key, ctx->uid, ctx->uidlen, i, aid, buf);
        PM3_RET_IF_ERR_WITH_MSG(res, "Failed diversifying key %d for AID %06X", i, aid);

        PrintAndLogEx(INFO, "Diversified key %d for AID %06X: " _GREEN_("%s"),
                      i,
                      aid,
                      sprint_hex_inrow(buf, ARRAYLEN(buf))
                     );

        // Authenticate
        uint8_t blank_key[CRYPTO_AES128_KEY_SIZE] = {0};
        DesfireSetKeyNoClear(ctx, 0, T_AES, blank_key);
        DesfireSetKdf(ctx, MFDES_KDF_ALGO_NONE, NULL, 0);
        res = authenticate(ctx, verbose);
        PM3_RET_IF_ERR_WITH_MSG(res, "Desfire authenticate error. Result: [%d] %s", res, DesfireAuthErrorToStr(res));

        // Change key
        DesfireSetCommMode(ctx, DCMEncryptedPlain);
        res = DesfireChangeKey(ctx, false, i, app_algo, 1, buf, app_algo, blank_key, verbose);
        PM3_RET_IF_ERR_WITH_MSG(res, "Failed setting key %d for AID %06X", i, aid);

        if (verbose) {
            PrintAndLogEx(INFO, "Successfully set key " _YELLOW_("%d") " for AID " _YELLOW_("%06X"), i, aid);
        }
    }

    PrintAndLogEx(INFO, "Successfully created credentials application " _YELLOW_("%06X"), aid);
    return PM3_SUCCESS;
}

/**
 * @brief Create a new file containing Gallagher cardholder credentials.
 *
 * @param site_key MIFARE site key.
 * @param aid Application ID to put the new file in.
 * @param creds Gallagher cardholder credentials.
 */
static int hfgal_create_creds_file(DesfireContext_t *ctx, uint8_t *site_key, uint32_t aid,
                                   GallagherCredentials_t *creds, bool verbose) {
    // Select application & authenticate
    int res = select_aid_and_auth_with_key(ctx, aid, site_key, 0, true, verbose);
    PM3_RET_IF_ERR(res);

    // Prepare create file command
    uint8_t file_type = 0; // standard data file
    uint8_t file_id = 0x00;
    uint8_t file_size = 16;
    uint8_t file_access_mode = 0x03; // encrypted
    uint32_t file_rights = 0x2000; // key 0 has God mode, key 2 can read

    uint8_t data[7] = {0};
    data[0] = file_id;
    data[1] = file_access_mode;
    data[2] = file_rights & 0xff;
    data[3] = (file_rights >> 8) & 0xff;
    Uint3byteToMemLe(&data[4], file_size);

    // Create file
    res = DesfireCreateFile(ctx, file_type, data, ARRAYLEN(data), false);
    PM3_RET_IF_ERR_WITH_MSG(res, "Failed creating file 0 in AID %06X", aid);

    if (verbose) {
        PrintAndLogEx(INFO, "Created file 0 in AID " _YELLOW_("%06X") " (empty contents)", aid);
    }

    // Create file contents (2nd half is the bitwise inverse of the encoded creds)
    uint8_t contents[16] = {0};
    gallagher_encode_creds(contents, creds);
    for (int i = 0; i < 8; i++) {
        contents[i + 8] = contents[i] ^ 0xFF;
    }

    // Write file
    DesfireSetCommMode(ctx, DCMEncrypted);
    res = DesfireWriteFile(ctx, file_id, 0, ARRAYLEN(contents), contents);
    PM3_RET_IF_ERR_WITH_MSG(res, "Failed writing data to file 0 in AID %06X", aid);

    PrintAndLogEx(INFO, "Successfully wrote cardholder credentials to file " _YELLOW_("0") " in AID " _YELLOW_("%06X"), aid);
    return PM3_SUCCESS;
}

/**
 * @brief Read Gallagher Card Application Directory (CAD) from card.
 *
 * @param dest_buf Buffer to copy Card Application Directory into.
 * @param dest_buf_len Size of dest_buf. Must be at least 108 bytes.
 * @param num_entries Will be set to the number of entries in the CAD.
 */
static int hfgal_read_cad(DesfireContext_t *ctx, uint8_t *dest_buf,
                          uint8_t dest_buf_len, uint8_t *num_entries_out, bool verbose) {
    if (dest_buf_len < 3 * 36) {
        PrintAndLogEx(ERR, "hfgal_read_cad destination buffer is incorrectly sized. Received len %d, must be at least %d",
                      dest_buf_len,
                      3 * 36
                     );
        return PM3_EINVARG;
    }

    // Get card AIDs from Card Application Directory (which contains 1 to 3 files)
    int res = select_aid(ctx, CAD_AID, verbose);
    PM3_RET_IF_ERR_WITH_MSG(res, "Failed selecting Card Application Directory, does AID %06X exist?", CAD_AID);

    // Read up to 3 files with 6x 6-byte entries each
    for (uint8_t i = 0; i < 3; i++) {
        size_t read_len;
        res = DesfireReadFile(ctx, i, 0, 36, &dest_buf[i * 36], &read_len);
        if (res != PM3_SUCCESS && res != PM3_EAPDU_FAIL) {
            PM3_RET_ERR(res, "Failed reading file %d in Card Application Directory (AID %06X)", i, CAD_AID);
        }

        // end if the last entry is NULL
        if (memcmp(&dest_buf[36 * i + 30], "\0\0\0\0\0\0", 6) == 0) {
            break;
        }
    }

    // Count number of entries (i.e. count until we hit a NULL entry)
    uint8_t num_entries = 0;
    for (uint8_t i = 0; i < dest_buf_len; i += 6) {
        if (memcmp(&dest_buf[i], "\0\0\0\0\0\0", 6) == 0) {
            break;
        }
        num_entries++;
    }
    *num_entries_out = num_entries;

    if (num_entries == 0) {
        PrintAndLogEx(WARNING, "Card Application Directory is empty");
    } else if (verbose) {
        // Print what we found
        // iceman maybe on seperate lines for easier reading.
        PrintAndLogEx(SUCCESS, "Card Application Directory contains:" NOLF);
        for (int i = 0; i < num_entries; i++) {
            PrintAndLogEx(NORMAL, "%s %06X" NOLF,
                          (i == 0) ? "" : ",",
                          cad_aid_byte_to_uint(&dest_buf[i * 6 + 3])
                         );
        }
        PrintAndLogEx(NORMAL, "");
    }

    return PM3_SUCCESS;
}

/**
 * @brief Create the Gallagher Card Application Directory.
 *
 * @param key MIFARE site key, or custom CAD key.
 * @param should_diversify True if using a site_key, false if using a custom CAD key.
 */
static int hfgal_create_cad(DesfireContext_t *ctx, uint8_t *key,
                            bool should_diversify, bool verbose) {
    // Check that card UID has been set
    if (ctx->uidlen == 0) {
        PM3_RET_ERR(PM3_EINVARG, "Card UID must be set in DesfireContext (required for key div)");
    }

    // Select application & authenticate
    int res = select_aid_and_auth(ctx, 0x000000, verbose);
    PM3_RET_IF_ERR(res);

    // Create application
    DesfireCryptoAlgorithm app_algo = T_AES;
    uint8_t num_keys = 1;
    uint8_t ks1 = 0x0B;
    uint8_t ks2 = (DesfireKeyAlgoToType(app_algo) << 6) | num_keys;;

    uint8_t data[5] = {0};
    DesfireAIDUintToByte(CAD_AID, &data[0]);
    data[3] = ks1;
    data[4] = ks2;

    DesfireSetCommMode(ctx, DCMMACed);
    res = DesfireCreateApplication(ctx, data, ARRAYLEN(data));
    PM3_RET_IF_ERR_WITH_MSG(res, "Failed creating Card Application Directory (AID " _YELLOW_("%06X")"). Does it already exist?", CAD_AID);

    if (verbose) {
        PrintAndLogEx(INFO, "Created Card Application Directory (AID " _YELLOW_("%06X") ", empty contents & blank keys)",
                      CAD_AID
                     );
    }

    // Select application & authenticate
    uint8_t blank_key[DESFIRE_MAX_KEY_SIZE] = {0};
    res = select_aid_and_auth_with_key(ctx, CAD_AID, blank_key, 0, false, verbose);
    PM3_RET_IF_ERR(res);

    uint8_t buf[CRYPTO_AES128_KEY_SIZE] = {0};
    if (should_diversify) {
        // Diversify key
        res = hfgal_diversify_key(key, ctx->uid, ctx->uidlen, 0, CAD_AID, buf);
        PM3_RET_IF_ERR_WITH_MSG(res, "Failed diversifying key 0 for AID %06X", CAD_AID);

        PrintAndLogEx(INFO, "Diversified key " _YELLOW_("0") " for CAD (AID " _YELLOW_("%06X") "): " _GREEN_("%s"),
                      CAD_AID,
                      sprint_hex_inrow(buf, ARRAYLEN(buf))
                     );
        key = buf;
    } else if (verbose) {
        PrintAndLogEx(INFO, "Using provided key " _YELLOW_("0") " for CAD (AID " _YELLOW_("%06X") "): " _GREEN_("%s"),
                      CAD_AID,
                      sprint_hex_inrow(key, CRYPTO_AES128_KEY_SIZE)
                     );
    }

    // Change key
    DesfireSetCommMode(ctx, DCMEncryptedPlain);
    res = DesfireChangeKey(ctx, false, 0, app_algo, 1, buf, app_algo, blank_key, verbose);
    PM3_RET_IF_ERR_WITH_MSG(res, "Failed setting key 0 for CAD");

    if (verbose) {
        PrintAndLogEx(INFO, "Successfully set key " _YELLOW_("0") " for CAD");
    }

    PrintAndLogEx(INFO, "Successfully created Card Application Directory (AID " _YELLOW_("%06X") ")", CAD_AID);
    return PM3_SUCCESS;
}

/**
 * @brief Update the Gallagher Card Application Directory with a new entry.
 *
 * @param key MIFARE site key, or custom CAD key.
 * @param should_diversify True if using a site_key, false if using a custom CAD key.
 * @param aid Application ID to add to the CAD.
 * @param creds Gallagher cardholder credentials (region_code & facility_code are required).
 */
static int hfgal_add_aid_to_cad(DesfireContext_t *ctx, uint8_t *key, bool should_diversify,
                                uint32_t aid, GallagherCredentials_t *creds, bool verbose) {
    // Check if CAD exists
    uint8_t cad[36 * 3] = {0};
    uint8_t num_entries = 0;
    if (aid_exists(ctx, CAD_AID, false)) {
        if (verbose) {
            PrintAndLogEx(INFO, "Card Application Directory exists, reading entries...");
        }

        int res = hfgal_read_cad(ctx, cad, ARRAYLEN(cad), &num_entries, verbose);
        PM3_RET_IF_ERR(res);

        // Check that there is space for the new entry
        if (num_entries >= 18) {
            PM3_RET_ERR(PM3_EFATAL, "Card application directory is full");
        }

    } else {
        // CAD doesn't exist, we need to create it
        if (verbose) {
            PrintAndLogEx(INFO, "Card Application Directory does not exist, creating it now...");
        }

        int res = hfgal_create_cad(ctx, key, should_diversify, verbose);
        PM3_RET_IF_ERR(res);
    }

    // 6 entries per file
    uint8_t file_id = num_entries / 6;
    uint8_t entry_num = num_entries % 6;

    // Check if facility already exists in CAD.
    for (uint8_t i = 0; i < ARRAYLEN(cad); i += 6) {
        if (cad_facility_match(&cad[i], creds->region_code, creds->facility_code)) {
            PM3_RET_ERR(PM3_EFATAL, "Facility already exists in CAD, delete or update AID %06X",
                        cad_aid_byte_to_uint(&cad[i + 3])
                       );
        }
    }

    // Create entry
    uint8_t *entry = &cad[num_entries * 6];
    entry[0] = creds->region_code;
    entry[1] = (creds->facility_code >> 8) & 0xFF;
    entry[2] = creds->facility_code & 0xFF;
    cad_aid_uint_to_byte(aid, &entry[3]);

    if (verbose) {
        PrintAndLogEx(INFO, "Adding entry to CAD (position " _YELLOW_("%d") " in file " _YELLOW_("%d") "): %s",
                      entry_num,
                      file_id,
                      sprint_hex_inrow(entry, 6)
                     );
    }

    // Select application & authenticate
    int res = select_aid_and_auth_with_key(ctx, CAD_AID, key, 0, should_diversify, verbose);
    PM3_RET_IF_ERR(res);

    // Create file if necessary
    if (entry_num == 0) {
        if (verbose) {
            PrintAndLogEx(INFO, "Creating new file in CAD");
        }

        // Prepare create file command
        uint8_t file_type = 0; // standard data file
        uint8_t file_size = 36;
        uint8_t file_access_mode = 0x00; // plain
        uint32_t file_rights = 0xE000; // key 0 has God mode, everyone can read

        uint8_t data[7] = {0};
        data[0] = file_id;
        data[1] = file_access_mode;
        data[2] = file_rights & 0xff;
        data[3] = (file_rights >> 8) & 0xff;
        Uint3byteToMemLe(&data[4], file_size);

        // Create file
        res = DesfireCreateFile(ctx, file_type, data, ARRAYLEN(data), false);
        PM3_RET_IF_ERR_WITH_MSG(res, "Failed creating file %d in CAD (AID %06X)", file_id, CAD_AID);

        if (verbose) {
            PrintAndLogEx(INFO, "Created file " _YELLOW_("%d") " in CAD (empty contents)", file_id);
        }

        // Write file
        res = DesfireWriteFile(ctx, file_id, 0, 36, &cad[file_id * 36]);
    } else {
        // Write file
        res = DesfireWriteFile(ctx, file_id, entry_num * 6, 6, entry);
    }
    PM3_RET_IF_ERR_WITH_MSG(res, "Failed writing data to file %d in CAD AID %06X)", file_id, CAD_AID);

    PrintAndLogEx(INFO, "Successfully added new entry for " _YELLOW_("%06X") " to the Card Application Directory", aid);
    return PM3_SUCCESS;
}

/**
 * @brief Remove an entry from the Gallagher Card Application Directory.
 *
 * @param key MIFARE site key, or custom CAD key.
 * @param should_diversify True if using a site_key, false if using a custom CAD key.
 * @param aid Application ID to remove from the CAD.
 */
static int hfgal_remove_aid_from_cad(DesfireContext_t *ctx, uint8_t *key,
                                     bool should_diversify, uint32_t aid, bool verbose) {
    // Read CAD
    uint8_t cad[36 * 3] = {0};
    uint8_t num_entries = 0;
    int res = hfgal_read_cad(ctx, cad, ARRAYLEN(cad), &num_entries, verbose);
    PM3_RET_IF_ERR(res);

    // Check if facility already exists in CAD
    uint8_t entry_idx;
    for (entry_idx = 0; entry_idx < num_entries; entry_idx++) {
        if (aid > 0 && aid == cad_aid_byte_to_uint(&cad[entry_idx * 6 + 3])) {
            break;
        }
    }
    if (entry_idx >= num_entries) {
        PM3_RET_ERR(PM3_EINVARG, "Specified facility or AID does not exist in the Card Application Directory");
    }

    // Remove entry (shift all entries left, then clear the last entry)
    memmove(
        &cad[entry_idx * 6],
        &cad[(entry_idx + 1) * 6],
        ARRAYLEN(cad) - (entry_idx + 1) * 6
    );
    memset(&cad[ARRAYLEN(cad) - 6], 0, 6);

    // Select application & authenticate
    res = select_aid_and_auth_with_key(ctx, CAD_AID, key, 0, should_diversify, verbose);
    PM3_RET_IF_ERR(res);

    // Determine what files we need to update
    uint8_t file_id_start = entry_idx / 6;
    uint8_t file_id_stop = (num_entries - 1) / 6;
    bool delete_last_file = (num_entries - 1) % 6 == 0;

    for (uint8_t file_id = file_id_start; file_id <= file_id_stop - delete_last_file; file_id++) {
        // Write file
        res = DesfireWriteFile(ctx, file_id, 0, 36, &cad[file_id * 36]);
        PM3_RET_IF_ERR_WITH_MSG(res, "Failed writing data to file %d in CAD (AID %06X)", file_id, CAD_AID);

        if (verbose) {
            PrintAndLogEx(INFO, "Updated file " _YELLOW_("%d") " in CAD", file_id);
        }
    }

    // Delete empty file if necessary
    if (delete_last_file) {
        uint8_t file_id = file_id_stop;

        DesfireSetCommMode(ctx, DCMMACed);
        res = DesfireDeleteFile(ctx, file_id);
        PM3_RET_IF_ERR_WITH_MSG(res, "Failed deleting file %d from CAD (AID %06X)", file_id, CAD_AID);

        if (verbose) {
            PrintAndLogEx(INFO, "Deleted unnecessary file " _YELLOW_("%d") " from CAD (AID " _YELLOW_("%06X")")",
                          file_id,
                          CAD_AID
                         );
        }
    }

    PrintAndLogEx(INFO, "Successfully removed " _YELLOW_("%06X") " from the Card Application Directory", aid);
    return PM3_SUCCESS;
}

/**
 * @brief Read credentials from a Gallagher card.
 *
 * @param aid Application ID to read. If 0, then the Card Application Directory
 * will be queried and all entries will be read.
 * @param site_key MIFARE site key.
 * @param quiet Suppress error messages. Used when in continuous reader mode.
 */
// iceman,  verbose and quiet... one should be enough.
static int hfgal_read_card(uint32_t aid, uint8_t *site_key, bool verbose, bool quiet) {
    DropField();
    clearCommandBuffer();

    // Set up context
    DesfireContext_t dctx = {0};
    DesfireClearContext(&dctx);

    // Get card UID (for key diversification)
    int res = DesfireGetCardUID(&dctx);
    PM3_RET_IF_ERR_MAYBE_MSG(res, !quiet, "Failed retrieving card UID");

    // Find AIDs to process (from CLI args or the Card Application Directory)
    uint8_t cad[36 * 3] = {0};
    uint8_t num_entries = 0;
    if (aid != 0) {
        cad_aid_uint_to_byte(aid, &cad[3]);
        num_entries = 1;
    } else {
        res = hfgal_read_cad(&dctx, cad, ARRAYLEN(cad), &num_entries, verbose);
        PM3_RET_IF_ERR_MAYBE_MSG(res, !quiet, "Failed reading Card Application Directory");
    }

    // Loop through each application in the CAD
    for (uint16_t i = 0; i < num_entries * 6; i += 6) {
        uint16_t region_code = cad[i + 0];
        uint16_t facility_code = (cad[i + 1] << 8) + cad[i + 2];
        uint32_t current_aid = cad_aid_byte_to_uint(&cad[i + 3]);

        if (verbose) {
            if (region_code > 0 || facility_code > 0 || current_aid > 0) {
                PrintAndLogEx(INFO, "Reading AID: " _YELLOW_("%06X") ", region: " _YELLOW_("%c") " ( " _YELLOW_("%u") " ), facility: " _YELLOW_("%u"),
                              current_aid,
                              'A' + region_code,
                              region_code,
                              facility_code
                             );
            } else {
                PrintAndLogEx(INFO, "Reading AID: " _YELLOW_("%06X"), current_aid);
            }
        }

        // Read & decode credentials
        GallagherCredentials_t creds = {0};
        res = hfgal_read_creds_app(&dctx, current_aid, site_key, &creds, verbose);
        if (res == HFGAL_AUTH_FAIL) {
            PrintAndLogEx(WARNING, "Invalid site key for AID %06X", current_aid);
            continue;
        }
        PM3_RET_IF_ERR_MAYBE_MSG(res, !quiet, "Failed reading card application credentials");

        PrintAndLogEx(SUCCESS, "Gallagher (AID %06X) - region: " _GREEN_("%c") " ( " _GREEN_("%u") " )"
                      ", facility: " _GREEN_("%u")
                      ", card number: " _GREEN_("%u")
                      ", issue level: " _GREEN_("%u"),
                      current_aid,
                      'A' + creds.region_code,
                      creds.region_code,
                      creds.facility_code,
                      creds.card_number,
                      creds.issue_level
                     );
    }
    return PM3_SUCCESS;
}

static int CmdGallagherReader(const char *cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf gallagher reader",
                  "Read a Gallagher DESFire tag from the Card Application Directory, CAD\n"
                  "Specify site key is required if using non-default key\n",
                  "hf gallagher reader -@ -> continuous reader mode\n"
                  "hf gallagher reader --aid 2081f4 --sitekey 00112233445566778899aabbccddeeff -> skip CAD\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0(NULL, "aid",        "<hex>", "Application ID to read (3 bytes). If specified, the CAD is not used"),
        arg_str0(NULL, "sitekey",    "<hex>", "Site key to compute diversified keys (16 bytes)"),
        arg_lit0("@",  "continuous",          "Continuous reader mode"),
        arg_lit0(NULL, "apdu",                "Show APDU requests and responses"),
        arg_lit0("v",  "verbose",             "Verbose mode"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, cmd, argtable, true);

    int aid_len = 0;
    uint8_t aid_buf[3] = {0};
    CLIGetHexWithReturn(ctx, 1, aid_buf, &aid_len);
    if (aid_len > 0 && aid_len != 3) {
        PM3_RET_ERR_FREE(PM3_EINVARG, "--aid must be 3 bytes");
    }

    reverse_aid(aid_buf); // PM3 displays AIDs backwards
    uint32_t aid = DesfireAIDByteToUint(aid_buf);

    int site_key_len = 0;
    uint8_t site_key[16] = {0};
    memcpy(site_key, DEFAULT_SITE_KEY, ARRAYLEN(site_key));
    CLIGetHexWithReturn(ctx, 2, site_key, &site_key_len);
    if (site_key_len > 0 && site_key_len != 16) {
        PM3_RET_ERR_FREE(PM3_EINVARG, "--sitekey must be 16 bytes");
    }

    bool continuous_mode = arg_get_lit(ctx, 3);
    SetAPDULogging(arg_get_lit(ctx, 4));
    bool verbose = arg_get_lit(ctx, 5);
    CLIParserFree(ctx);

    if (continuous_mode == false) {
        // Read single card
        return hfgal_read_card(aid, site_key, verbose, false);
    }

    // Loop until <Enter> is pressed
    PrintAndLogEx(INFO, "Press " _GREEN_("<Enter>") " to exit");
    while (kbd_enter_pressed() == false) {
        hfgal_read_card(aid, site_key, verbose, !verbose);
    }
    return PM3_SUCCESS;
}

static int CmdGallagherClone(const char *cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf gallagher clone",
                  "Clone Gallagher credentials to a writable DESFire card\n"
                  "Specify site key is required if using non-default key\n"
                  "Key, lengths for the different crypto: \n"
                  "   DES 8 bytes\n"
                  "   2TDEA or AES 16 bytes\n"
                  "   3TDEA 24 bytes\n"
                  "AID, default finds lowest available in range 0x??81F4, where ?? >= 0x20.",
                  "hf gallagher clone --rc 1 --fc 22 --cn 3333 --il 4 --sitekey 00112233445566778899aabbccddeeff"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_int0("n",   "keynum",  "<dec>", "PICC key number [default = 0]"),
        arg_str0("t",   "algo",    "<DES|2TDEA|3TDEA|AES>", "PICC crypt algo: DES, 2TDEA, 3TDEA, AES"),
        arg_str0("k",   "key",     "<hex>", "Key for authentication to the PICC to create applications"),
        arg_u64_1(NULL, "rc",      "<dec>", "Region code. 4 bits max"),
        arg_u64_1(NULL, "fc",      "<dec>", "Facility code. 2 bytes max"),
        arg_u64_1(NULL, "cn",      "<dec>", "Card number. 3 bytes max"),
        arg_u64_1(NULL, "il",      "<dec>", "Issue level. 4 bits max"),
        arg_str0(NULL,  "aid",     "<hex>", "Application ID to write (3 bytes) [default automatically chooses]"),
        arg_str0(NULL,  "sitekey", "<hex>", "Site key to compute diversified keys (16 bytes)"),
        arg_str0(NULL,  "cadkey",  "<hex>", "Custom AES key 0 to modify the Card Application Directory (16 bytes)"),
        arg_lit0(NULL,  "nocadupdate",      "Don't modify the Card Application Directory (only creates the app)"),
        arg_lit0(NULL,  "noappcreate",      "Don't create the application (only modifies the CAD)"),
        arg_lit0(NULL,  "apdu",             "Show APDU requests and responses"),
        arg_lit0("v",   "verbose",          "Verbose mode"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, cmd, argtable, false);
    uint8_t arg = 1;

    int picc_key_num = arg_get_int_def(ctx, arg++, 0);

    int picc_key_algo = T_DES;
    if (CLIGetOptionList(arg_get_str(ctx, arg++), DesfireAlgoOpts, &picc_key_algo)) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    int picc_key_len = 0;
    uint8_t picc_key[DESFIRE_MAX_KEY_SIZE] = {0};
    CLIGetHexWithReturn(ctx, arg++, picc_key, &picc_key_len);
    if (picc_key_len && picc_key_len != desfire_get_key_length(picc_key_algo)) {
        PM3_RET_ERR_FREE(PM3_EINVARG, "%s key must have %d bytes length instead of %d",
                         CLIGetOptionListStr(DesfireAlgoOpts, picc_key_algo),
                         desfire_get_key_length(picc_key_algo),
                         picc_key_len
                        );
    }
    if (picc_key_len == 0) {
        // Default to a key of all zeros
        picc_key_len = desfire_get_key_length(picc_key_algo);
    }

    uint64_t region_code = arg_get_u64(ctx, arg++); // uint4, input will be validated later
    uint64_t facility_code = arg_get_u64(ctx, arg++); // uint16
    uint64_t card_number = arg_get_u64(ctx, arg++); // uint24
    uint64_t issue_level = arg_get_u64(ctx, arg++); // uint4

    int aid_len = 0;
    uint8_t aid_buf[3] = {0};
    CLIGetHexWithReturn(ctx, arg++, aid_buf, &aid_len);
    if (aid_len > 0 && aid_len != 3) {
        PM3_RET_ERR_FREE(PM3_EINVARG, "--aid must be 3 bytes");
    }
    reverse_aid(aid_buf); // PM3 displays AIDs backwards
    uint32_t aid = DesfireAIDByteToUint(aid_buf);

    int site_key_len = 0;
    uint8_t site_key[16] = {0};
    memcpy(site_key, DEFAULT_SITE_KEY, ARRAYLEN(site_key));
    CLIGetHexWithReturn(ctx, arg++, site_key, &site_key_len);
    if (site_key_len > 0 && site_key_len != 16) {
        PM3_RET_ERR_FREE(PM3_EINVARG, "--sitekey must be 16 bytes");
    }

    int cad_key_len = 0;
    uint8_t cad_key[16] = {0};
    CLIGetHexWithReturn(ctx, arg++, cad_key, &cad_key_len);
    if (cad_key_len > 0 && cad_key_len != 16) {
        PM3_RET_ERR_FREE(PM3_EINVARG, "--cadkey must be 16 bytes");
    }

    bool no_cad_update = arg_get_lit(ctx, arg++);
    bool no_app_create = arg_get_lit(ctx, arg++);

    SetAPDULogging(arg_get_lit(ctx, arg++));
    bool verbose = arg_get_lit(ctx, arg++);
    CLIParserFree(ctx);

    if (gallagher_is_valid_creds(region_code, facility_code, card_number, issue_level) == false) {
        return PM3_EINVARG;
    }

    GallagherCredentials_t creds = {
        .region_code = region_code,
        .facility_code = facility_code,
        .card_number = card_number,
        .issue_level = issue_level,
    };

    // Set up context
    DropField();
    DesfireContext_t dctx = {0};
    DesfireClearContext(&dctx);

    // Get card UID (for key diversification)
    int res = DesfireGetCardUID(&dctx);
    PM3_RET_IF_ERR_WITH_MSG(res, "Failed retrieving card UID");

    if (aid_len == 0) {
        // Find available Gallagher AID if the user did not specify one
        aid = find_available_gallagher_aid(&dctx, verbose);
        if (aid == 0) {
            PM3_RET_ERR(PM3_EFATAL, "Could not find an available AID, please specify with --aid");
        }
        if (verbose) {
            PrintAndLogEx(INFO, "Using available AID: %06X", aid);
        }
    } else if (no_app_create == false && aid_exists(&dctx, aid, verbose)) {
        // AID was specified but is not available
        PM3_RET_ERR(PM3_EINVARG, "AID already exists: %06X", aid);
    }

    // Update Card Application Directory
    if (no_cad_update == false) {
        // Set keys so that hfgal_add_aid_to_cad can auth to 0x000000
        // if it needs to create the CAD application.
        DesfireSetKeyNoClear(&dctx, picc_key_num, picc_key_algo, picc_key);
        DesfireSetKdf(&dctx, MFDES_KDF_ALGO_NONE, NULL, 0);

        bool should_diversify = cad_key_len == 0;
        uint8_t *key = should_diversify ? site_key : cad_key;
        res = hfgal_add_aid_to_cad(&dctx, key, should_diversify, aid, &creds, verbose);
        PM3_RET_IF_ERR_WITH_MSG(res, "Failed updating Gallagher Card Application Directory");
    }

    // Create application
    if (no_app_create == false) {
        // Set keys so that hfgal_create_creds_app can auth to 0x000000
        // when it creates the application.
        DesfireSetKeyNoClear(&dctx, picc_key_num, picc_key_algo, picc_key);
        DesfireSetKdf(&dctx, MFDES_KDF_ALGO_NONE, NULL, 0);

        res = hfgal_create_creds_app(&dctx, site_key, aid, verbose);
        PM3_RET_IF_ERR_WITH_MSG(res, "Failed creating Gallagher application");

        // Create credential files
        // Don't need to set keys here, they're generated automatically
        res = hfgal_create_creds_file(&dctx, site_key, aid, &creds, verbose);
        PM3_RET_IF_ERR_WITH_MSG(res, "Failed creating Gallagher credential file");
    }

    PrintAndLogEx(SUCCESS, "Done");
    PrintAndLogEx(HINT, "Hint: try " _YELLOW_("`hf gallagher reader`") " to verify");
    return PM3_SUCCESS;
}

static int CmdGallagherDelete(const char *cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf gallagher delete",
                  "Delete Gallagher application from a DESFire card\n"
                  "Specify site key is required if using non-default key",
                  "hf gallagher delete --aid 2081f4 --sitekey 00112233445566778899aabbccddeeff"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1(NULL, "aid",     "<hex>", "Application ID to delete (3 bytes)"),
        arg_str0(NULL, "sitekey", "<hex>", "Site key to compute diversified keys (16 bytes)"),
        arg_str0(NULL, "cadkey",  "<hex>", "Custom AES key 0 to modify the Card Application Directory (16 bytes)"),
        arg_lit0(NULL, "nocadupdate",      "Don't modify the Card Application Directory (only deletes the app)"),
        arg_lit0(NULL, "noappdelete",      "Don't delete the application (only modifies the CAD)"),
        arg_lit0(NULL, "apdu",             "Show APDU requests and responses"),
        arg_lit0("v",  "verbose",          "Verbose mode"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, cmd, argtable, false);
    uint8_t arg = 1;

    int aid_len = 0;
    uint8_t aid_buf[3] = {0};
    CLIGetHexWithReturn(ctx, arg++, aid_buf, &aid_len);
    if (aid_len != 3) {
        PM3_RET_ERR_FREE(PM3_EINVARG, "--aid must be 3 bytes");
    }
    reverse_aid(aid_buf); // PM3 displays AIDs backwards
    uint32_t aid = DesfireAIDByteToUint(aid_buf);

    int site_key_len = 0;
    uint8_t site_key[16] = {0};
    memcpy(site_key, DEFAULT_SITE_KEY, ARRAYLEN(site_key));
    CLIGetHexWithReturn(ctx, arg++, site_key, &site_key_len);
    if (site_key_len > 0 && site_key_len != 16) {
        PM3_RET_ERR_FREE(PM3_EINVARG, "--sitekey must be 16 bytes");
    }

    int cad_key_len = 0;
    uint8_t cad_key[16] = {0};
    CLIGetHexWithReturn(ctx, arg++, cad_key, &cad_key_len);
    if (cad_key_len > 0 && cad_key_len != 16) {
        PM3_RET_ERR_FREE(PM3_EINVARG, "--cadkey must be 16 bytes");
    }

    bool no_cad_update = arg_get_lit(ctx, arg++);
    bool no_app_delete = arg_get_lit(ctx, arg++);

    SetAPDULogging(arg_get_lit(ctx, arg++));
    bool verbose = arg_get_lit(ctx, arg++);
    CLIParserFree(ctx);

    // Set up context
    DropField();
    DesfireContext_t dctx = {0};
    DesfireClearContext(&dctx);

    // Get card UID (for key diversification)
    int res = DesfireGetCardUID(&dctx);
    PM3_RET_IF_ERR_WITH_MSG(res, "Failed retrieving card UID");

    // Update Card Application Directory
    if (no_cad_update == false) {
        bool should_diversify = cad_key_len == 0;
        uint8_t *key = should_diversify ? site_key : cad_key;
        res = hfgal_remove_aid_from_cad(&dctx, key, should_diversify, aid, verbose);
        PM3_RET_IF_ERR_WITH_MSG(res, "Failed removing %06X from the Card Application Directory", aid);
    }

    // Delete application
    if (no_app_delete == false) {
        res = hfgal_delete_app(&dctx, site_key, aid, verbose);
        PM3_RET_IF_ERR_WITH_MSG(res, "Failed deleting Gallagher application");
    }

    PrintAndLogEx(SUCCESS, "Done");
    PrintAndLogEx(HINT, "Hint: try " _YELLOW_("`hf gallagher reader`") " to verify");
    return PM3_SUCCESS;
}

static int CmdGallagherDiversify(const char *cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf gallagher diversify",
                  "Diversify Gallagher key\n"
                  "Specify site key is required if using non-default key",
                  "hf gallagher diversify --uid 11223344556677 --aid 2081f4"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1(NULL, "aid",     "<hex>", "Application ID for diversification (3 bytes)"),
        arg_int0(NULL, "keynum",  "<dec>", "Key number [default = 0]"),
        arg_str0(NULL, "uid",     "<hex>", "Card UID to delete (4 or 7 bytes)"),
        arg_str0(NULL, "sitekey", "<hex>", "Site key to compute diversified keys (16 bytes)"),
        arg_lit0(NULL, "apdu",             "Show APDU requests and responses"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, cmd, argtable, false);

    int aid_len = 0;
    uint8_t aid_buf[3] = {0};
    CLIGetHexWithReturn(ctx, 1, aid_buf, &aid_len);
    if (aid_len != 3) {
        PM3_RET_ERR_FREE(PM3_EINVARG, "--aid must be 3 bytes");
    }
    reverse_aid(aid_buf); // PM3 displays AIDs backwards
    uint32_t aid = DesfireAIDByteToUint(aid_buf);

    int key_num = arg_get_int_def(ctx, 2, 0);

    int uid_len = 0;
    uint8_t uid[7] = {0};
    CLIGetHexWithReturn(ctx, 3, uid, &uid_len);
    if (uid_len > 0 && uid_len != 4 && uid_len != 7) {
        PM3_RET_ERR_FREE(PM3_EINVARG, "--uid must be 4 or 7 bytes");
    }

    int site_key_len = 0;
    uint8_t site_key[16] = {0};
    memcpy(site_key, DEFAULT_SITE_KEY, ARRAYLEN(site_key));
    CLIGetHexWithReturn(ctx, 4, site_key, &site_key_len);
    if (site_key_len > 0 && site_key_len != 16) {
        PM3_RET_ERR_FREE(PM3_EINVARG, "--sitekey must be 16 bytes");
    }

    SetAPDULogging(arg_get_lit(ctx, 5));
    CLIParserFree(ctx);

    if (uid_len == 0) {
        // Set up context
        DropField();
        DesfireContext_t dctx = {0};
        DesfireClearContext(&dctx);

        // Get card UID (for key diversification)
        int res = DesfireGetCardUID(&dctx);
        PM3_RET_IF_ERR_WITH_MSG(res, "Failed retrieving card UID");

        uid_len = dctx.uidlen;
        memcpy(uid, dctx.uid, uid_len);
    }

    // Diversify key
    uint8_t key[CRYPTO_AES128_KEY_SIZE] = {0};
    int res = hfgal_diversify_key(site_key, uid, uid_len, key_num, aid, key);
    PM3_RET_IF_ERR_WITH_MSG(res, "Failed diversifying key");

    char *key_str = sprint_hex_inrow(key, ARRAYLEN(key));
    PrintAndLogEx(SUCCESS, "Successfully diversified key: " _GREEN_("%s"), key_str);

    if (IfPm3Iso14443()) {
        PrintAndLogEx(HINT, "Hint: try " _YELLOW_("`hf mfdes auth --aid %06X --keyno %d --algo AES --key %s`") " to verify",
                      aid,
                      key_num,
                      key_str
                     );
    }
    return PM3_SUCCESS;
}

static int CmdGallagherDecode(const char *cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf gallagher decode",
                  "Decode Gallagher credential block\n"
                  "Credential block can be specified with or without the bitwise inverse.",
                  "hf gallagher decode --data A3B4B0C151B0A31B"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1(NULL, "data", "<hex>", "Credential block (8 or 16 bytes)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, cmd, argtable, false);

    int data_len = 0;
    uint8_t data_buf[16] = {0};
    CLIGetHexWithReturn(ctx, 1, data_buf, &data_len);
    if (data_len != 8 && data_len != 16) {
        PM3_RET_ERR_FREE(PM3_EINVARG, "--data must be 8 or 16 bytes");
    }
    CLIParserFree(ctx);

    if (data_len == 16) {
        // Check second half of file is the bitwise inverse of the first half
        for (uint8_t i = 8; i < 16; i++) {
            data_buf[i] ^= 0xFF;
        }

        if (memcmp(data_buf, &data_buf[8], 8) != 0) {
            PM3_RET_ERR(PM3_EFAILED, "Invalid cardholder data, last 8 bytes should be bitwise inverse of first 16 bytes. Received %s",
                        sprint_hex_inrow(data_buf, 16)
                       );
        }
    } else {
        for (uint8_t i = 0; i < 8; i++) {
            data_buf[i + 8] = data_buf[i] ^ 0xFF;
        }
        PrintAndLogEx(INFO, "Full credential block with bitwise inverse: " _YELLOW_("%s"), sprint_hex_inrow(data_buf, 16));
    }

    GallagherCredentials_t creds = {0};
    gallagher_decode_creds(data_buf, &creds);

    PrintAndLogEx(SUCCESS, "Gallagher - region: " _GREEN_("%c") " ( " _GREEN_("%u") " )"
                  ", facility: " _GREEN_("%u")
                  ", card number: " _GREEN_("%u")
                  ", issue level: " _GREEN_("%u"),
                  'A' + creds.region_code,
                  creds.region_code,
                  creds.facility_code,
                  creds.card_number,
                  creds.issue_level
                 );

    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",         CmdHelp,               AlwaysAvailable, "This help"},
    {"reader",       CmdGallagherReader,    IfPm3Iso14443,   "Read & decode all Gallagher credentials on a DESFire card"},
    {"clone",        CmdGallagherClone,     IfPm3Iso14443,   "Add Gallagher credentials to a DESFire card"},
    {"delete",       CmdGallagherDelete,    IfPm3Iso14443,   "Delete Gallagher credentials from a DESFire card"},
    {"diversifykey", CmdGallagherDiversify, AlwaysAvailable, "Diversify Gallagher key"},
    {"decode",       CmdGallagherDecode,    AlwaysAvailable, "Decode Gallagher credential block"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *cmd) {
    (void) cmd; // cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdHFGallagher(const char *cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, cmd);
}
