/**
 * Matt Moran (@DarkMatterMatt), 2021
 * -----------------------------------------------------------------------------
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 * -----------------------------------------------------------------------------
 * High frequency GALLAGHER tag commands.
 * MIFARE DESFire, AIDs 2081F4-2F81F4
 */

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

/** Application ID for the Gallagher Card Application Directory */
static const uint32_t CAD_AID = 0x2F81F4;

/** Default MIFARE Site Key */
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
 * @param aid Application ID (0x2?81F4 where 0 <= ? <= 0xB).
 * @param key_output Buffer to copy the diversified key into (must be 16 bytes).
 * @return PM3_SUCCESS if successful, PM3_EINVARG if an argument is invalid.
 */
int hfgal_diversify_key(uint8_t *site_key, uint8_t *uid, uint8_t uid_len,
                        uint8_t key_num, uint32_t aid, uint8_t *key_output) {
    // Generate diversification input
    uint8_t kdf_input_len = 11;
    int res = mfdes_kdf_input_gallagher(uid, uid_len, key_num, aid, key_output, &kdf_input_len);
    HFGAL_RET_IF_ERR_WITH_MSG(res, "Failed generating Gallagher key diversification input");

    if (site_key == NULL) {
        PrintAndLogEx(INFO, "hfgal_diversify_key is using default site key: %s",
                      sprint_hex_inrow(DEFAULT_SITE_KEY, ARRAYLEN(DEFAULT_SITE_KEY)));
        site_key = (uint8_t *) &DEFAULT_SITE_KEY;
    }

    // Make temporary DesfireContext
    DesfireContext_t dctx = {0};
    DesfireSetKey(&dctx, 0, T_AES, site_key);

    // Diversify input & copy to output buffer
    MifareKdfAn10922(&dctx, DCOMasterKey, key_output, kdf_input_len);
    memcpy(key_output, dctx.key, CRYPTO_AES128_KEY_SIZE);

    return PM3_SUCCESS;
}

/**
 * @brief Reverses the bytes in AID. Used when parsing CLI args
 * (because Proxmark displays AIDs in reverse byte order).
 */
static void reverse_aid(uint8_t *aid) {
    uint8_t tmp = aid[0];
    aid[0] = aid[2];
    aid[2] = tmp;
}

/**
 * @brief Converts a Card Application Directory format application ID to an integer.
 * Note that the CAD stores AIDs in reverse order, so this function is different to DesfireAIDByteToUint().
 */
static uint32_t cad_aid_byte_to_uint(uint8_t *data) {
    return data[2] + (data[1] << 8) + (data[0] << 16);
}

/**
 * @brief Converts an integer application ID to Card Application Directory format.
 * Note that the CAD stores AIDs in reverse order, so this function is different to DesfireAIDUintToByte().
 */
static void cad_aid_uint_to_byte(uint32_t aid, uint8_t *data) {
    data[2] = aid & 0xff;
    data[1] = (aid >> 8) & 0xff;
    data[0] = (aid >> 16) & 0xff;
}

/**
 * @brief Returns true if the Card Application Directory entry
 * is for the specified region & facility, false otherwise.
 */
static bool cad_facility_match(uint8_t *entry, uint8_t region_code, uint16_t facility_code) {
    return entry[0] == region_code && (entry[1] << 8) + entry[2] == facility_code;
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

    if (verbose)
        PrintAndLogEx(INFO, "Selected AID %06X", aid);

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
        PrintAndLogEx(ERR, "Desfire authenticate " _RED_("error")
                      ". Result: [%d] %s", res, DesfireAuthErrorToStr(res));
        return res;
    }

    if (DesfireIsAuthenticated(ctx)) {
        if (verbose)
            PrintAndLogEx(INFO, "Authenticated to AID %06X", ctx->selectedAID);
    } else
        return 201;

    return PM3_SUCCESS;
}

/**
 * @brief Select application ID & authenticate.
 * Uses existing authentication keys in context.
 */
static int select_aid_and_authenticate(DesfireContext_t *ctx, uint32_t aid, bool verbose) {
    int res = select_aid(ctx, aid, verbose);
    HFGAL_RET_IF_ERR(res);

    res = authenticate(ctx, verbose);
    HFGAL_RET_IF_ERR(res);

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
    if (res != PM3_SUCCESS && res != PM3_EAPDU_FAIL)
        HFGAL_RET_ERR(false, "Select failed with error %d, assuming AID %06X does not exist", res, aid);

    if (verbose)
        PrintAndLogEx(INFO, "AID %06X %s", aid, res == PM3_SUCCESS ? "exists" : "does not exist");

    return res == PM3_SUCCESS;
}

/**
 * @brief Returns the lowest available Gallagher application ID.
 * @return 0 if no AID is available, or an AID in the range 0x2?81F4, where 0 <= ? <= 0xB.
 */
static uint32_t find_available_gallagher_aid(DesfireContext_t *ctx, bool verbose) {
    for (uint8_t i = 0x0; i <= 0xB; i++) {
        uint32_t aid = 0x2081F4 | (i << 16);
        if (!aid_exists(ctx, aid, verbose))
            return aid;
    }
    return 0;
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
    DesfireSetKeyNoClear(ctx, 0, T_AES, site_key);
    DesfireSetKdf(ctx, MFDES_KDF_ALGO_GALLAGHER, NULL, 0);
    int res = select_aid_and_authenticate(ctx, aid, verbose);
    HFGAL_RET_IF_ERR(res);

    // Delete application
    DesfireSetCommMode(ctx, DCMMACed);
    res = DesfireDeleteApplication(ctx, aid);
    HFGAL_RET_IF_ERR_WITH_MSG(res, "Failed deleting AID %06X", aid);

    PrintAndLogEx(INFO, "Successfully deleted AID %06X", aid);
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
    if (ctx->uidlen == 0)
        HFGAL_RET_ERR(PM3_EINVARG, "Card UID must be set in DesfireContext (required for key diversification)");

    // Select application & authenticate
    DesfireSetKeyNoClear(ctx, 2, T_AES, site_key);
    DesfireSetKdf(ctx, MFDES_KDF_ALGO_GALLAGHER, NULL, 0);
    int res = select_aid_and_authenticate(ctx, aid, verbose);
    HFGAL_RET_IF_ERR_WITH_MSG(res, "Failed selecting/authenticating to AID %06X", aid);

    // Read file 0 (contains credentials)
    uint8_t buf[16] = {0};
    size_t read_len = 0;
    DesfireSetCommMode(ctx, DCMEncrypted);
    res = DesfireReadFile(ctx, 0, 0, 16, buf, &read_len);
    HFGAL_RET_IF_ERR_WITH_MSG(res, "Failed reading file 0 in AID %06X", aid);

    // Check file contained 16 bytes of data
    if (read_len != 16)
        HFGAL_RET_ERR(PM3_EFAILED, "Failed reading file 0 in AID %06X, expected 16 bytes but received %d bytes", aid, read_len);

    // Check second half of file is the bitwise inverse of the first half
    for (uint8_t i = 8; i < 16; i++)
        buf[i] ^= 0xFF;
    if (memcmp(buf, &buf[8], 8) != 0)
        HFGAL_RET_ERR(PM3_EFAILED, "Invalid cardholder data in file 0 in AID %06X. Received %s", sprint_hex_inrow(buf, 16));

    gallagher_decode_creds(buf, creds);

    // TODO: read MIFARE Enhanced Security file
    // https://github.com/megabug/gallagher-research/blob/master/formats/mes.md

    return PM3_SUCCESS;
}

/**
 * @brief Create a new application to store Gallagher cardholder credentials.
 *
 * @param site_key MIFARE site key.
 * @param aid New application ID. Should be 0x2?81F4, where 0 <= ? <= 0xB.
 */
static int hfgal_create_creds_app(DesfireContext_t *ctx, uint8_t *site_key, uint32_t aid, bool verbose) {
    // Select application & authenticate
    int res = select_aid_and_authenticate(ctx, 0x000000, verbose);
    HFGAL_RET_IF_ERR(res);

    // UID is required for key diversification
    if (ctx->uidlen == 0)
        HFGAL_RET_ERR(PM3_EINVARG, "UID is required for key diversification. Please fetch it before calling `hfgal_create_creds_app`");

    // Create application
    DesfireCryptoAlgorithm app_algo = T_AES;
    uint8_t num_keys = 3;
    uint8_t ks1 = 0x0B;
    uint8_t ks2 = (DesfireKeyAlgoToType(app_algo) << 6) | num_keys;;

    uint8_t data[5] = {0};
    DesfireAIDUintToByte(aid, &data[0]);
    data[3] = ks1;
    data[4] = ks2;

    DesfireSetCommMode(ctx, DCMMACed);
    res = DesfireCreateApplication(ctx, data, ARRAYLEN(data));
    HFGAL_RET_IF_ERR_WITH_MSG(res, "Failed creating application %06X. Does it already exist?", aid);

    if (verbose)
        PrintAndLogEx(INFO, "Created application %06X (currently has empty contents & blank keys)", aid);

    // Select the new application
    res = select_aid(ctx, aid, verbose);
    HFGAL_RET_IF_ERR_WITH_MSG(res, "Failed selecting application %06X", aid);

    // Add key 2, then key 0 (we must authenticate with key 0 in order to make changes)
    for (int i = 2; i >= 0; i -= 2) {
        // Diversify key
        uint8_t buf[CRYPTO_AES128_KEY_SIZE] = {0};
        res = hfgal_diversify_key(site_key, ctx->uid, ctx->uidlen, i, aid, buf);
        HFGAL_RET_IF_ERR_WITH_MSG(res, "Failed diversifying key %d for AID %06X", i, aid);

        PrintAndLogEx(INFO, "Diversified key %d for AID %06X: " _GREEN_("%s"), i, aid, sprint_hex_inrow(buf, ARRAYLEN(buf)));

        // Authenticate
        uint8_t blank_key[CRYPTO_AES128_KEY_SIZE] = {0};
        DesfireSetKeyNoClear(ctx, 0, T_AES, blank_key);
        DesfireSetKdf(ctx, MFDES_KDF_ALGO_NONE, NULL, 0);
        res = authenticate(ctx, verbose);
        HFGAL_RET_IF_ERR_WITH_MSG(res, "Desfire authenticate error. Result: [%d] %s", res, DesfireAuthErrorToStr(res));

        // Change key
        DesfireSetCommMode(ctx, DCMEncryptedPlain);
        res = DesfireChangeKey(ctx, false, i, app_algo, 1, buf, app_algo, blank_key, verbose);
        HFGAL_RET_IF_ERR_WITH_MSG(res, "Failed setting key %d for AID %06X", i, aid);

        if (verbose)
            PrintAndLogEx(INFO, "Successfully set key %d for AID %06X", i, aid);
    }

    PrintAndLogEx(INFO, "Successfully created credentials application %06X", aid);
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
    DesfireSetKeyNoClear(ctx, 0, T_AES, site_key);
    DesfireSetKdf(ctx, MFDES_KDF_ALGO_GALLAGHER, NULL, 0);
    int res = select_aid_and_authenticate(ctx, aid, verbose);
    HFGAL_RET_IF_ERR(res);

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
    HFGAL_RET_IF_ERR_WITH_MSG(res, "Failed creating file 0 in AID %06X", aid);

    if (verbose)
        PrintAndLogEx(INFO, "Created file 0 in AID %06X (currently has empty contents)", aid);

    // Create file contents (2nd half is the bitwise inverse of the encoded creds)
    uint8_t contents[16] = {0};
    gallagher_encode_creds(contents, creds);
    for (int i = 0; i < 8; i++)
        contents[i + 8] = contents[i] ^ 0xFF;

    // Write file
    DesfireSetCommMode(ctx, DCMEncrypted);
    res = DesfireWriteFile(ctx, file_id, 0, ARRAYLEN(contents), contents);
    HFGAL_RET_IF_ERR_WITH_MSG(res, "Failed writing data to file 0 in AID %06X");

    PrintAndLogEx(INFO, "Successfully wrote cardholder credentials to file 0 in AID %06X", aid);
    return PM3_SUCCESS;
}

/**
 * @brief Read Gallagher Card Application Directory from card.
 *
 * @param dest_buf Buffer to copy Card Application Directory into.
 * @param dest_buf_len Size of dest_buf. Must be at least 108 bytes.
 * @param num_entries Will be set to the number of entries in the Card Application Directory.
 */
static int hfgal_read_cad(DesfireContext_t *ctx, uint8_t *dest_buf,
                          uint8_t dest_buf_len, uint8_t *num_entries, bool verbose) {
    if (dest_buf_len < 3 * 36) {
        PrintAndLogEx(ERR, "hfgal_read_cad destination buffer is incorrectly sized. "
                      "Received length %d, must be at least %d", dest_buf_len, 3 * 36);
        return PM3_EINVARG;
    }

    // Get card AIDs from Card Application Directory (which contains 1 to 3 files)
    int res = select_aid(ctx, CAD_AID, verbose);
    HFGAL_RET_IF_ERR_WITH_MSG(res, "Failed selecting Card Application Directory, does AID %06X exist?", CAD_AID);

    // Read up to 3 files with 6x 6-byte entries each
    for (uint8_t i = 0; i < 3; i++) {
        size_t read_len;
        res = DesfireReadFile(ctx, i, 0, 36, &dest_buf[i * 36], &read_len);
        if (res != PM3_SUCCESS && res != PM3_EAPDU_FAIL)
            HFGAL_RET_ERR(res, "Failed reading file %d in Card Application Directory (AID %06X)", i, CAD_AID);

        // end if the last entry is NULL
        if (memcmp(&dest_buf[36 * i + 30], "\0\0\0\0\0\0", 6) == 0) break;
    }

    // Count number of entries (i.e. count until we hit a NULL entry)
    *num_entries = 0;
    for (uint8_t i = 0; i < dest_buf_len; i += 6) {
        if (memcmp(&dest_buf[i], "\0\0\0\0\0\0", 6) == 0) break;
        *num_entries += 1;
    }

    if (verbose) {
        // Print what we found
        PrintAndLogEx(SUCCESS, "Card Application Directory contains:" NOLF);
        for (int i = 0; i < *num_entries; i++)
            PrintAndLogEx(NORMAL, "%s %06X" NOLF, (i == 0) ? "" : ",",
                          cad_aid_byte_to_uint(&dest_buf[i * 6 + 3]));
        PrintAndLogEx(NORMAL, "");
    }

    return PM3_SUCCESS;
}

/**
 * @brief Create the Gallagher Card Application Directory.
 *
 * @param site_key MIFARE site key.
 */
static int hfgal_create_cad(DesfireContext_t *ctx, uint8_t *site_key, bool verbose) {
    // Check that card UID has been set
    if (ctx->uidlen == 0)
        HFGAL_RET_ERR(PM3_EINVARG, "Card UID must be set in DesfireContext (required for key diversification)");

    // Select application & authenticate
    int res = select_aid_and_authenticate(ctx, 0x000000, verbose);
    HFGAL_RET_IF_ERR(res);

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
    HFGAL_RET_IF_ERR_WITH_MSG(res, "Failed creating Card Application Directory. Does it already exist?", CAD_AID);

    if (verbose)
        PrintAndLogEx(INFO, "Created Card Application Directory (AID %06X, currently has empty contents & blank keys)", CAD_AID);

    // Select application & authenticate
    uint8_t blank_key[DESFIRE_MAX_KEY_SIZE] = {0};
    DesfireSetKeyNoClear(ctx, 0, T_AES, blank_key);
    DesfireSetKdf(ctx, MFDES_KDF_ALGO_NONE, NULL, 0);
    res = select_aid_and_authenticate(ctx, CAD_AID, verbose);
    HFGAL_RET_IF_ERR(res);

    // Diversify key
    uint8_t buf[CRYPTO_AES128_KEY_SIZE] = {0};
    res = hfgal_diversify_key(site_key, ctx->uid, ctx->uidlen, 0, CAD_AID, buf);
    HFGAL_RET_IF_ERR_WITH_MSG(res, "Failed diversifying key 0 for AID %06X", CAD_AID);

    PrintAndLogEx(INFO, "Diversified key 0 for CAD (AID %06X): " _GREEN_("%s"), CAD_AID, sprint_hex_inrow(buf, ARRAYLEN(buf)));

    // Change key
    DesfireSetCommMode(ctx, DCMEncryptedPlain);
    res = DesfireChangeKey(ctx, false, 0, app_algo, 1, buf, app_algo, blank_key, verbose);
    HFGAL_RET_IF_ERR_WITH_MSG(res, "Failed setting key 0 for CAD");

    if (verbose)
        PrintAndLogEx(INFO, "Successfully set key 0 for CAD");

    PrintAndLogEx(INFO, "Successfully created Card Application Directory (AID %06X)", CAD_AID);
    return PM3_SUCCESS;
}

/**
 * @brief Update the Gallagher Card Application Directory with a new entry.
 *
 * @param site_key MIFARE site key.
 * @param aid Application ID to add to the CAD.
 * @param creds Gallagher cardholder credentials (region_code & facility_code are required).
 */
static int hfgal_add_aid_to_cad(DesfireContext_t *ctx, uint8_t *site_key, uint32_t aid,
                                GallagherCredentials_t *creds, bool verbose) {
    // Check if CAD exists
    uint8_t cad[36 * 3] = {0};
    uint8_t num_entries = 0;
    if (aid_exists(ctx, CAD_AID, false)) {
        if (verbose)
            PrintAndLogEx(INFO, "Card Application Directory exists, reading entries...");

        int res = hfgal_read_cad(ctx, cad, ARRAYLEN(cad), &num_entries, verbose);
        HFGAL_RET_IF_ERR(res);

        // Check that there is space for the new entry
        if (num_entries >= 18)
            HFGAL_RET_ERR(PM3_EFATAL, "Card application directory is full");
    } else {
        // CAD doesn't exist, we need to create it
        if (verbose)
            PrintAndLogEx(INFO, "Card Application Directory does not exist, creating it now...");

        int res = hfgal_create_cad(ctx, site_key, verbose);
        HFGAL_RET_IF_ERR(res);
    }

    uint8_t file_id = num_entries / 6; // 6 entries per file
    uint8_t entry_num = num_entries % 6;

    // Check if facility already exists in CAD.
    for (uint8_t i = 0; i < ARRAYLEN(cad); i += 6) {
        if (cad_facility_match(&cad[i], creds->region_code, creds->facility_code))
            HFGAL_RET_ERR(PM3_EFATAL, "Facility already exists in CAD, delete or "
                          "update AID %06X instead", cad_aid_byte_to_uint(&cad[i + 3]));
    }

    // Create entry
    uint8_t *entry = &cad[num_entries * 6];
    entry[0] = creds->region_code;
    entry[1] = (creds->facility_code >> 8) & 0xFF;
    entry[2] = creds->facility_code & 0xFF;
    cad_aid_uint_to_byte(aid, &entry[3]);

    if (verbose)
        PrintAndLogEx(INFO, "Adding entry to CAD (position %d in file %d): %s", entry_num, file_id, sprint_hex_inrow(entry, 6));

    // Select application & authenticate
    DesfireSetKeyNoClear(ctx, 0, T_AES, site_key);
    DesfireSetKdf(ctx, MFDES_KDF_ALGO_GALLAGHER, NULL, 0);
    int res = select_aid_and_authenticate(ctx, CAD_AID, verbose);
    HFGAL_RET_IF_ERR(res);

    // Create file if necessary
    if (entry_num == 0) {
        if (verbose)
            PrintAndLogEx(INFO, "Creating new file in CAD");

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
        HFGAL_RET_IF_ERR_WITH_MSG(res, "Failed creating file %d in CAD (AID %06X)", file_id, CAD_AID);

        if (verbose)
            PrintAndLogEx(INFO, "Created file %d in CAD (currently has empty contents)", file_id);

        // Write file
        res = DesfireWriteFile(ctx, file_id, 0, 36, &cad[file_id * 36]);
    } else
        // Write file
        res = DesfireWriteFile(ctx, file_id, entry_num * 6, 6, entry);
    HFGAL_RET_IF_ERR_WITH_MSG(res, "Failed writing data to file %d in CAD (AID %06X)", file_id, CAD_AID);

    PrintAndLogEx(INFO, "Successfully added new entry for %06X to the Card Application Directory", aid);
    return PM3_SUCCESS;
}

/**
 * @brief Remove an entry from the Gallagher Card Application Directory.
 *
 * @param site_key MIFARE site key.
 * @param aid Application ID to add to the CAD.
 */
static int hfgal_remove_aid_from_cad(DesfireContext_t *ctx, uint8_t *site_key,
                                     uint32_t aid, bool verbose) {
    // Check if CAD exists
    uint8_t cad[36 * 3] = {0};
    uint8_t num_entries = 0;

    int res = hfgal_read_cad(ctx, cad, ARRAYLEN(cad), &num_entries, verbose);
    HFGAL_RET_IF_ERR(res);

    // Check if facility already exists in CAD
    uint8_t entry_num = 0;
    for (; entry_num < num_entries; entry_num++) {
        if (aid > 0 && aid == cad_aid_byte_to_uint(&cad[entry_num * 6 + 3]))
            break;
    }
    if (entry_num >= num_entries)
        HFGAL_RET_ERR(PM3_EINVARG, "Specified facility or AID does not exist in the Card Application Directory");

    // Remove entry (shift all entries left, then clear the last entry)
    memmove(
        &cad[entry_num * 6],
        &cad[(entry_num + 1) * 6],
        ARRAYLEN(cad) - (entry_num + 1) * 6
    );
    memset(&cad[ARRAYLEN(cad) - 6], 0, 6);

    // Select application & authenticate
    DesfireSetKeyNoClear(ctx, 0, T_AES, site_key);
    DesfireSetKdf(ctx, MFDES_KDF_ALGO_GALLAGHER, NULL, 0);
    res = select_aid_and_authenticate(ctx, CAD_AID, verbose);
    HFGAL_RET_IF_ERR(res);

    // Determine what files we need to update
    uint8_t file_id_start = (entry_num - 1) / 6;
    uint8_t file_id_stop = (num_entries - 1) / 6;

    for (uint8_t file_id = file_id_start; file_id <= file_id_stop; file_id++) {
        // Write file
        res = DesfireWriteFile(ctx, file_id, 0, 36, &cad[file_id * 36]);
        HFGAL_RET_IF_ERR_WITH_MSG(res, "Failed writing data to file %d in CAD (AID %06X)", file_id, CAD_AID);

        if (verbose)
            PrintAndLogEx(INFO, "Updated file %d in CAD", file_id);
    }

    // Delete empty files if necessary
    if (file_id_start != file_id_stop) {
        uint8_t file_id = file_id_stop;

        DesfireSetCommMode(ctx, DCMMACed);
        res = DesfireDeleteFile(ctx, file_id);
        HFGAL_RET_IF_ERR_WITH_MSG(res, "Failed deleting file %d from CAD (AID %06X)", file_id, CAD_AID);

        if (verbose)
            PrintAndLogEx(INFO, "Deleted unnecessary file %d from CAD (AID %06X)", file_id, CAD_AID);

        // Delete the Card Application Directory if necessary
        // (if we just deleted the last file in it)
        if (file_id == 0) {
            res = hfgal_delete_app(ctx, site_key, CAD_AID, verbose);
            HFGAL_RET_IF_ERR_WITH_MSG(res, "Failed deleting file %d from CAD (AID %06X)", file_id, CAD_AID);

            if (verbose)
                PrintAndLogEx(INFO, "Removed CAD because it was empty");
        }
    }

    PrintAndLogEx(INFO, "Successfully removed %06X from the Card Application Directory", aid);
    return PM3_SUCCESS;
}

/**
 * @brief Read credentials from a Gallagher card.
 *
 * @param aid Application ID to read. If 0, then the Card Application Directory will be queried and all entries will be read.
 * @param site_key MIFARE site key.
 * @param quiet Suppress error messages. Used when in continuous reader mode.
 */
static int hfgal_read_card(uint32_t aid, uint8_t *site_key, bool verbose, bool quiet) {
    DropField();
    clearCommandBuffer();

    // Set up context
    DesfireContext_t dctx = {0};
    DesfireClearContext(&dctx);

    // Get card UID (for key diversification)
    int res = DesfireGetCardUID(&dctx);
    HFGAL_RET_IF_ERR_MAYBE_MSG(res, !quiet, "Failed retrieving card UID");

    // Find AIDs to process (from CLI args or the Card Application Directory)
    uint8_t cad[36 * 3] = {0};
    uint8_t num_entries = 0;
    if (aid != 0) {
        cad_aid_uint_to_byte(aid, &cad[3]);
        num_entries = 1;
    } else {
        res = hfgal_read_cad(&dctx, cad, ARRAYLEN(cad), &num_entries, verbose);
        HFGAL_RET_IF_ERR_MAYBE_MSG(res, !quiet, "Failed reading Card Application Directory");
    }

    // Loop through each application in the CAD
    for (uint8_t i = 0; i < num_entries * 6; i += 6) {
        uint16_t region_code = cad[i + 0];
        uint16_t facility_code = (cad[i + 1] << 8) + cad[i + 2];
        uint32_t current_aid = cad_aid_byte_to_uint(&cad[i + 3]);

        if (verbose) {
            if (region_code > 0 || facility_code > 0)
                PrintAndLogEx(INFO, "Reading AID: %06X, region: %u, facility: %u", current_aid, region_code, facility_code);
            else
                PrintAndLogEx(INFO, "Reading AID: %06X", current_aid);
        }

        // Read & decode credentials
        GallagherCredentials_t creds = {0};
        res = hfgal_read_creds_app(&dctx, current_aid, site_key, &creds, verbose);
        HFGAL_RET_IF_ERR_MAYBE_MSG(res, !quiet, "Failed reading card application credentials");

        PrintAndLogEx(SUCCESS, "GALLAGHER (AID %06X) - Region: " _GREEN_("%u") ", Facility: " _GREEN_("%u")
                      ", Card No.: " _GREEN_("%u") ", Issue Level: " _GREEN_("%u"), current_aid,
                      creds.region_code, creds.facility_code, creds.card_number, creds.issue_level);
    }

    return PM3_SUCCESS;
}

static int CmdGallagherReader(const char *cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf gallagher reader",
                  "Read a GALLAGHER tag",
                  "hf gallagher reader --aid 2081f4 --sitekey 00112233445566778899aabbccddeeff"
                  " -> act as a reader that skips reading the Card Application Directory and uses a non-default site key\n"
                  "hf gallagher reader -@ -> continuous reader mode"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0(NULL, "aid",     "<hex>",   "Application ID to read (3 bytes)"),
        arg_str0("k",  "sitekey", "<hex>",   "Master site key to compute diversified keys (16 bytes) [default=3112B738D8862CCD34302EB299AAB456]"),
        arg_lit0(NULL, "apdu",               "Show APDU requests and responses"),
        arg_lit0("v",  "verbose",            "Verbose mode"),
        arg_lit0("@",  "continuous",         "Continuous reader mode"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, cmd, argtable, true);

    int aid_len = 0;
    uint8_t aid_buf[3] = {0};
    CLIGetHexWithReturn(ctx, 1, aid_buf, &aid_len);
    if (aid_len > 0 && aid_len != 3)
        HFGAL_RET_ERR(PM3_EINVARG, "--aid must be 3 bytes");

    reverse_aid(aid_buf); // PM3 displays AIDs backwards
    uint32_t aid = DesfireAIDByteToUint(aid_buf);

    int site_key_len = 0;
    uint8_t site_key[16] = {0};
    memcpy(site_key, DEFAULT_SITE_KEY, ARRAYLEN(site_key));
    CLIGetHexWithReturn(ctx, 2, site_key, &site_key_len);
    if (site_key_len > 0 && site_key_len != 16)
        HFGAL_RET_ERR(PM3_EINVARG, "--sitekey must be 16 bytes");

    SetAPDULogging(arg_get_lit(ctx, 3));
    bool verbose = arg_get_lit(ctx, 4);
    bool continuous_mode = arg_get_lit(ctx, 5);
    CLIParserFree(ctx);

    if (!continuous_mode)
        // Read single card
        return hfgal_read_card(aid, site_key, verbose, false);

    // Loop until <Enter> is pressed
    PrintAndLogEx(INFO, "Press " _GREEN_("<Enter>") " to exit");
    while (!kbd_enter_pressed())
        hfgal_read_card(aid, site_key, verbose, !verbose);
    return PM3_SUCCESS;
}

static int CmdGallagherClone(const char *cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf gallagher clone",
                  "Clone a GALLAGHER card to a blank DESFire card",
                  "hf gallagher clone --rc 1 --fc 22 --cn 3333 --il 4 --sitekey 00112233445566778899aabbccddeeff"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0(NULL, "apdu",                  "show APDU requests and responses"),
        arg_lit0("v",  "verbose",               "Verbose mode"),
        arg_int0("n",  "keyno",   "<decimal>",  "Key number [default=0]"),
        arg_str0("t",  "algo",    "<DES/2TDEA/3TDEA/AES>", "Crypt algo: DES, 2TDEA, 3TDEA, AES"),
        arg_str0("k",  "key",     "<hex>",      "Key for authenticate (HEX 8(DES), 16(2TDEA or AES) or 24(3TDEA) bytes)"),

        arg_u64_1(NULL, "rc",      "<decimal>", "Region code. 4 bits max"),
        arg_u64_1(NULL, "fc",      "<decimal>", "Facility code. 2 bytes max"),
        arg_u64_1(NULL, "cn",      "<decimal>", "Card number. 3 bytes max"),
        arg_u64_1(NULL, "il",      "<decimal>", "Issue level. 4 bits max"),
        arg_str0(NULL,  "aid",     "<hex>",     "Application ID to write (3 bytes) [default finds lowest available in range 0x2?81F4, where 0 <= ? <= 0xB]"),
        arg_str0(NULL,  "sitekey", "<hex>",     "Master site key to compute diversified keys (16 bytes) [default=3112B738D8862CCD34302EB299AAB456]"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, cmd, argtable, false);

    SetAPDULogging(arg_get_lit(ctx, 1));
    bool verbose = arg_get_lit(ctx, 2);
    int key_num = arg_get_int_def(ctx, 3, 0);

    int key_algo = T_DES;
    if (CLIGetOptionList(arg_get_str(ctx, 4), DesfireAlgoOpts, &key_algo)) return PM3_ESOFT;

    int key_len = 0;
    uint8_t key[DESFIRE_MAX_KEY_SIZE] = {0};
    CLIGetHexWithReturn(ctx, 5, key, &key_len);
    if (key_len && key_len != desfire_get_key_length(key_algo))
        HFGAL_RET_ERR(PM3_EINVARG, "%s key must have %d bytes length instead of %d", CLIGetOptionListStr(DesfireAlgoOpts, key_algo), desfire_get_key_length(key_algo), key_len);
    if (key_len == 0)
        // Default to a key of all zeros
        key_len = desfire_get_key_length(key_algo);

    uint64_t region_code = arg_get_u64(ctx, 6); // uint4, input will be validated later
    uint64_t facility_code = arg_get_u64(ctx, 7); // uint16
    uint64_t card_number = arg_get_u64(ctx, 8); // uint24
    uint64_t issue_level = arg_get_u64(ctx, 9); // uint4

    int aid_len = 0;
    uint8_t aid_buf[3] = {0};
    uint32_t aid = 0;
    CLIGetHexWithReturn(ctx, 10, aid_buf, &aid_len);
    if (aid_len > 0) {
        if (aid_len != 3)
            HFGAL_RET_ERR(PM3_EINVARG, "--aid must be 3 bytes");
        reverse_aid(aid_buf); // PM3 displays AIDs backwards
        aid = DesfireAIDByteToUint(aid_buf);

        // Check that the AID is in the expected range
        if (memcmp(aid_buf, "\xF4\x81", 2) != 0 || aid_buf[2] < 0x20 || aid_buf[2] > 0x2B)
            // TODO: this should probably be a warning, but key diversification will throw an error later even if we don't
            HFGAL_RET_ERR(PM3_EINVARG, "Invalid Gallagher AID %06X, expected 2?81F4, where 0 <= ? <= 0xB", aid);
    }

    int site_key_len = 0;
    uint8_t site_key[16] = {0};
    memcpy(site_key, DEFAULT_SITE_KEY, ARRAYLEN(site_key));
    CLIGetHexWithReturn(ctx, 11, site_key, &site_key_len);
    if (site_key_len > 0 && site_key_len != 16)
        HFGAL_RET_ERR(PM3_EINVARG, "--sitekey must be 16 bytes");
    CLIParserFree(ctx);

    if (!gallagher_is_valid_creds(region_code, facility_code, card_number, issue_level))
        return PM3_EINVARG;

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
    HFGAL_RET_IF_ERR_WITH_MSG(res, "Failed retrieving card UID");

    // Find available Gallagher AID if the user did not specify one
    if (aid_len == 0) {
        aid = find_available_gallagher_aid(&dctx, verbose);
        if (aid == 0)
            HFGAL_RET_ERR(PM3_EFATAL, "Could not find an available AID, card is full");
    }

    // Update Card Application Directory
    DesfireSetKeyNoClear(&dctx, key_num, key_algo, key);
    DesfireSetKdf(&dctx, MFDES_KDF_ALGO_NONE, NULL, 0);
    res = hfgal_add_aid_to_cad(&dctx, site_key, aid, &creds, verbose);
    HFGAL_RET_IF_ERR_WITH_MSG(res, "Failed updating Gallagher Card Application Directory");

    // Create application
    DesfireSetKeyNoClear(&dctx, key_num, key_algo, key);
    DesfireSetKdf(&dctx, MFDES_KDF_ALGO_NONE, NULL, 0);
    res = hfgal_create_creds_app(&dctx, site_key, aid, verbose);
    HFGAL_RET_IF_ERR_WITH_MSG(res, "Failed creating Gallagher application");

    // Create credential files
    // Don't need to set keys here, they're generated automatically
    res = hfgal_create_creds_file(&dctx, site_key, aid, &creds, verbose);
    HFGAL_RET_IF_ERR_WITH_MSG(res, "Failed creating Gallagher credential file");

    PrintAndLogEx(SUCCESS, "Done");
    PrintAndLogEx(HINT, "Hint: try " _YELLOW_("`hf gallagher reader`") " to verify");
    return PM3_SUCCESS;
}

static int CmdGallagherDelete(const char *cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf gallagher delete",
                  "Delete Gallagher application from a DESFire card",
                  "hf gallagher delete --aid 2081f4 --sitekey 00112233445566778899aabbccddeeff"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0(NULL, "apdu",                  "Show APDU requests and responses"),
        arg_lit0("v",  "verbose",               "Verbose mode"),

        arg_str1(NULL,  "aid",     "<hex>",     "Application ID to delete (3 bytes)"),
        arg_str0(NULL,  "sitekey", "<hex>",     "MIFARE site key to compute diversified keys (16 bytes) [default=3112B738D8862CCD34302EB299AAB456]"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, cmd, argtable, false);

    SetAPDULogging(arg_get_lit(ctx, 1));
    bool verbose = arg_get_lit(ctx, 2);

    int aid_len = 0;
    uint8_t aid_buf[3] = {0};
    uint32_t aid = 0;
    CLIGetHexWithReturn(ctx, 3, aid_buf, &aid_len);

    if (aid_len != 3)
        HFGAL_RET_ERR(PM3_EINVARG, "--aid must be 3 bytes");
    reverse_aid(aid_buf); // PM3 displays AIDs backwards
    aid = DesfireAIDByteToUint(aid_buf);

    // Check that the AID is in the expected range
    if (memcmp(aid_buf, "\xF4\x81", 2) != 0 || aid_buf[2] < 0x20 || aid_buf[2] > 0x2B)
        // TODO: this should probably be a warning, but key diversification will throw an error later even if we don't
        HFGAL_RET_ERR(PM3_EINVARG, "Invalid Gallagher AID %06X, expected 2?81F4, where 0 <= ? <= 0xB", aid);

    int site_key_len = 0;
    uint8_t site_key[16] = {0};
    memcpy(site_key, DEFAULT_SITE_KEY, ARRAYLEN(site_key));
    CLIGetHexWithReturn(ctx, 4, site_key, &site_key_len);
    if (site_key_len > 0 && site_key_len != 16)
        HFGAL_RET_ERR(PM3_EINVARG, "--sitekey must be 16 bytes");
    CLIParserFree(ctx);

    // Set up context
    DropField();
    DesfireContext_t dctx = {0};
    DesfireClearContext(&dctx);

    // Get card UID (for key diversification)
    int res = DesfireGetCardUID(&dctx);
    HFGAL_RET_IF_ERR_WITH_MSG(res, "Failed retrieving card UID");

    // Update Card Application Directory
    res = hfgal_remove_aid_from_cad(&dctx, site_key, aid, verbose);
    HFGAL_RET_IF_ERR_WITH_MSG(res, "Failed removing %06X from the Card Application Directory");

    // Delete application
    res = hfgal_delete_app(&dctx, site_key, aid, verbose);
    HFGAL_RET_IF_ERR_WITH_MSG(res, "Failed deleting Gallagher application");

    PrintAndLogEx(SUCCESS, "Done");
    PrintAndLogEx(HINT, "Hint: try " _YELLOW_("`hf gallagher reader`") " to verify");
    return PM3_SUCCESS;
}

static int CmdGallagherDiversify(const char *cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf gallagher diversify",
                  "Diversify Gallagher key",
                  "hf gallagher diversify --uid 11223344556677 --aid 2081f4"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0(NULL, "apdu",                  "Show APDU requests and responses"),

        arg_str1(NULL,  "aid",     "<hex>",     "Application ID for diversification (3 bytes)"),
        arg_int0(NULL,  "keynum",  "<decimal>", "Key number [default=0]"),
        arg_str0(NULL,  "uid",     "<hex>",     "Card UID to delete (4 or 7 bytes)"),
        arg_str0(NULL,  "sitekey", "<hex>",     "MIFARE site key to compute diversified keys (16 bytes, required if using non-default key)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, cmd, argtable, false);

    SetAPDULogging(arg_get_lit(ctx, 1));

    int aid_len = 0;
    uint8_t aid_buf[3] = {0};
    uint32_t aid = 0;
    CLIGetHexWithReturn(ctx, 2, aid_buf, &aid_len);

    if (aid_len != 3)
        HFGAL_RET_ERR(PM3_EINVARG, "--aid must be 3 bytes");
    reverse_aid(aid_buf); // PM3 displays AIDs backwards
    aid = DesfireAIDByteToUint(aid_buf);

    // Check that the AID is in the expected range
    if (memcmp(aid_buf, "\xF4\x81", 2) != 0 || aid_buf[2] < 0x20 || aid_buf[2] > 0x2B)
        // TODO: this should probably be a warning, but key diversification will throw an error later even if we don't
        HFGAL_RET_ERR(PM3_EINVARG, "Invalid Gallagher AID %06X, expected 2?81F4, where 0 <= ? <= 0xB", aid);

    int key_num = arg_get_int_def(ctx, 3, 0);

    int uid_len = 0;
    uint8_t uid[7] = {0};
    CLIGetHexWithReturn(ctx, 4, uid, &uid_len);
    if (uid_len > 0 && uid_len != 4 && uid_len != 7)
        HFGAL_RET_ERR(PM3_EINVARG, "--uid must be 4 or 7 bytes");

    int site_key_len = 0;
    uint8_t site_key[16] = {0};
    memcpy(site_key, DEFAULT_SITE_KEY, ARRAYLEN(site_key));
    CLIGetHexWithReturn(ctx, 5, site_key, &site_key_len);
    if (site_key_len > 0 && site_key_len != 16)
        HFGAL_RET_ERR(PM3_EINVARG, "--sitekey must be 16 bytes");
    CLIParserFree(ctx);

    if (uid_len == 0) {
        // Set up context
        DropField();
        DesfireContext_t dctx = {0};
        DesfireClearContext(&dctx);

        // Get card UID (for key diversification)
        int res = DesfireGetCardUID(&dctx);
        HFGAL_RET_IF_ERR_WITH_MSG(res, "Failed retrieving card UID");

        uid_len = dctx.uidlen;
        memcpy(uid, dctx.uid, uid_len);
    }

    // Diversify key
    uint8_t key[CRYPTO_AES128_KEY_SIZE] = {0};
    int res = hfgal_diversify_key(site_key, uid, uid_len, key_num, aid, key);
    HFGAL_RET_IF_ERR_WITH_MSG(res, "Failed diversifying key");

    char *key_str = sprint_hex_inrow(key, ARRAYLEN(key));
    PrintAndLogEx(SUCCESS, "Successfully diversified key: " _GREEN_("%s"), key_str);

    if (IfPm3Iso14443())
        PrintAndLogEx(HINT, "Hint: try " _YELLOW_("`hf mfdes auth --aid %06X --keyno %d "
                                                  "--algo AES --key %s`") " to verify", aid, key_num, key_str);
    return PM3_SUCCESS;
}

static int CmdHelp(const char *cmd);

static command_t CommandTable[] = {
    {"help",         CmdHelp,               AlwaysAvailable, "This help"},
    {"reader",       CmdGallagherReader,    IfPm3Iso14443,   "Read & decode all Gallagher credentials on the DESFire card"},
    {"clone",        CmdGallagherClone,     IfPm3Iso14443,   "Add Gallagher credentials to a DESFire card"},
    {"delete",       CmdGallagherDelete,    IfPm3Iso14443,   "Delete Gallagher credentials from a DESFire card"},
    {"diversifykey", CmdGallagherDiversify, AlwaysAvailable, "Diversify Gallagher key"},
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
