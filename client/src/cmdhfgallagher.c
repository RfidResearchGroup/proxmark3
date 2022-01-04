/**
 * Matt Moran (@DarkMatterMatt), 2021
 * -----------------------------------------------------------------------------
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
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
static const uint8_t DEFAULT_SITE_KEY[] = { 0x31, 0x12, 0xB7, 0x38, 0xD8, 0x86, 0x2C, 0xCD, 0x34, 0x30, 0x2E, 0xB2, 0x99, 0xAA, 0xB4, 0x56 };

/**
 * @brief Reverses the bytes in AID. Used when parsing CLI args (because Proxmark displays AIDs in reverse byte order).
 */
static void reverseAid(uint8_t *aid) {
    uint8_t tmp = aid[0];
    aid[0] = aid[2];
    aid[2] = tmp;
}

/**
 * @brief Converts a Card Application Directory format application ID to an integer.
 * Note that the CAD stores AIDs in reverse order, so this function is different to DesfireAIDByteToUint().
 */
static uint32_t cadAidByteToUint(uint8_t *data) {
    return data[2] + (data[1] << 8) + (data[0] << 16);
}

/**
 * @brief Converts an integer application ID to Card Application Directory format.
 * Note that the CAD stores AIDs in reverse order, so this function is different to DesfireAIDUintToByte().
 */
static void cadAidUintToByte(uint32_t aid, uint8_t *data) {
    data[2] = aid & 0xff;
    data[1] = (aid >> 8) & 0xff;
    data[0] = (aid >> 16) & 0xff;
}

/*
 * See header file for description :)
 */
int GallagherDiversifyKey(uint8_t *sitekey, uint8_t *uid, uint8_t uidLen, uint8_t keyNo, uint32_t aid, uint8_t *keyOut) {
    // Generate diversification input
    uint8_t kdfInputLen = 11;
    int res = mfdes_kdf_input_gallagher(uid, uidLen, keyNo, aid, keyOut, &kdfInputLen);
    HFGAL_RET_IF_ERR_WITH_MSG(res, "Failed generating Gallagher key diversification input.");

    if (sitekey == NULL) {
        PrintAndLogEx(INFO, "GallagherDiversifyKey is using default site key: %s",
            sprint_hex_inrow(DEFAULT_SITE_KEY, ARRAYLEN(DEFAULT_SITE_KEY)));
        sitekey = (uint8_t *) &DEFAULT_SITE_KEY;
    }

    // Make temporary DesfireContext
    DesfireContext_t dctx = {0};
    DesfireSetKey(&dctx, 0, T_AES, sitekey);
    
    // Diversify input & copy to output buffer
    MifareKdfAn10922(&dctx, DCOMasterKey, keyOut, kdfInputLen);
    memcpy(keyOut, dctx.key, CRYPTO_AES128_KEY_SIZE);

    return PM3_SUCCESS;
}

/**
 * @brief Select application ID.
 */
static int selectAid(DesfireContext_t *ctx, uint32_t aid, bool verbose) {
    // TODO: do these both need to be set?
    DesfireSetCommMode(ctx, DCMPlain);
    DesfireSetCommandSet(ctx, DCCNativeISO);

    int res = DesfireSelectEx(ctx, true, ISW6bAID, aid, NULL);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Desfire AID %06X select " _RED_("error") ".", aid);
        return 202;
    }

    if (verbose)
        PrintAndLogEx(INFO, "Selected AID %06X", aid);

    return PM3_SUCCESS;
}

/**
 * @brief Authenticate to application.
 */
static int authenticate(DesfireContext_t *ctx, bool verbose) {
    // TODO: do these both need to be set?
    DesfireSetCommMode(ctx, DCMPlain);
    DesfireSetCommandSet(ctx, DCCNativeISO);

    int res = DesfireAuthenticate(ctx, DACEV1, false);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Desfire authenticate " _RED_("error") ". Result: [%d] %s", res, DesfireAuthErrorToStr(res));
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
 * @brief Select application ID & authenticate. Uses existing authentication keys in context.
 */
static int selectAidAndAuthenticate(DesfireContext_t *ctx, uint32_t aid, bool verbose) {
    int res = selectAid(ctx, aid, verbose);
    HFGAL_RET_IF_ERR(res);

    res = authenticate(ctx, verbose);
    HFGAL_RET_IF_ERR(res);

    return PM3_SUCCESS;
}

/**
 * @brief Read Gallagher Card Application Directory from card.
 * 
 * @param destBuf Buffer to copy Card Application Directory into.
 * @param destBufLen Size of destBuf. Must be at least 108 bytes.
 * @param numEntries Will be set to the number of entries in the Card Application Directory.
 */
static int readCardApplicationDirectory(DesfireContext_t *ctx, uint8_t *destBuf, uint8_t destBufLen, uint8_t *numEntries, bool verbose) {
    if (destBufLen < 3 * 36) {
        PrintAndLogEx(ERR, "readCardApplicationDirectory destination buffer is incorrectly sized. "
            "Received length %d, must be at least %d", destBufLen, 3 * 36);
        return PM3_EINVARG;
    }

    // Get card AIDs from Card Application Directory (which contains 1 to 3 files)
    int res = selectAid(ctx, CAD_AID, verbose);
    HFGAL_RET_IF_ERR_WITH_MSG(res, "Failed selecting Card Application Directory, does AID %06X exist?", CAD_AID);

    // Read up to 3 files with 6x 6-byte entries each
    for (uint8_t i = 0; i < 3; i++) {
        size_t readLen;
        res = DesfireReadFile(ctx, i, 0, 36, &destBuf[i * 36], &readLen);
        if (res != PM3_SUCCESS)
            PrintAndLogEx(WARNING, "Failed reading file %d in Card Application Directory (AID %06X)", i, CAD_AID);

        // end if the last entry is NULL
        if (memcmp(&destBuf[36 * i + 30], "\0\0\0\0\0\0", 6) == 0) break;
    }

    // Count number of entries (i.e. count until we hit a NULL entry)
    *numEntries = 0;
    for (uint8_t i = 0; i < destBufLen; i += 6) {
        if (memcmp(&destBuf[i], "\0\0\0\0\0\0", 6) == 0) break;
        *numEntries += 1;
    }

    if (verbose) {
        // Print what we found
        PrintAndLogEx(SUCCESS, "Card Application Directory contains:" NOLF);
        for (int i = 0; i < *numEntries; i++)
            PrintAndLogEx(NORMAL, "%s %06X" NOLF, (i == 0) ? "" : ",", cadAidByteToUint(&destBuf[i*6 + 3]));
        PrintAndLogEx(NORMAL, "");
    }

    return PM3_SUCCESS;
}

/**
 * @brief Read credentials from a single AID.
 * 
 * @param aid Application ID to read.
 * @param sitekey MIFARE site key.
 * @param creds Decoded credentials will be stored in this structure.
 */
static int readCardApplicationCredentials(DesfireContext_t *ctx, uint32_t aid, uint8_t *sitekey, GallagherCredentials_t *creds, bool verbose) {
    // Check that card UID has been set
    if (ctx->uidlen == 0)
        HFGAL_RET_ERR(PM3_EINVARG, "Card UID must be set in DesfireContext (required for key diversification)");

    // Select application & authenticate
    DesfireSetKeyNoClear(ctx, 2, T_AES, sitekey);
    DesfireSetKdf(ctx, MFDES_KDF_ALGO_GALLAGHER, NULL, 0);
    int res = selectAidAndAuthenticate(ctx, aid, verbose);
    HFGAL_RET_IF_ERR_WITH_MSG(res, "Failed selecting/authenticating to AID %06X", aid);

    // Read file 0 (contains credentials)
    uint8_t buf[16] = {0};
    size_t readLen = 0;
    DesfireSetCommMode(ctx, DCMEncrypted);
    res = DesfireReadFile(ctx, 0, 0, 16, buf, &readLen);
    HFGAL_RET_IF_ERR_WITH_MSG(res, "Failed reading file 0 in AID %06X", aid);

    // Check file contained 16 bytes of data
    if (readLen != 16) {
        HFGAL_RET_ERR(PM3_EFAILED, "Failed reading file 0 in AID %06X, expected 16 bytes but received %d bytes", aid, readLen);
    }

    // Check second half of file is the bitwise inverse of the first half
    for (uint8_t i = 8; i < 16; i++)
        buf[i] ^= 0xFF;
    if (memcmp(buf, &buf[8], 8) != 0) {
        HFGAL_RET_ERR(PM3_EFAILED, "Invalid cardholder data in file 0 in AID %06X. Received %s", sprint_hex_inrow(buf, 16));
    }
    
    decodeCardholderCredentials(buf, creds);

    // TODO: read MIFARE Enhanced Security file
    // https://github.com/megabug/gallagher-research/blob/master/formats/mes.md

    return PM3_SUCCESS;
}

/**
 * @brief Read credentials from a Gallagher card.
 * 
 * @param aid Application ID to read. If 0, then the Card Application Directory will be queried and all entries will be read.
 * @param sitekey MIFARE site key.
 * @param quiet Suppress error messages. Used when in continuous reader mode.
 */
static int readCard(uint32_t aid, uint8_t *sitekey, bool verbose, bool quiet) {
    DropField();
    clearCommandBuffer();

    // Set up context
    DesfireContext_t dctx = {0};
    DesfireClearContext(&dctx);

    // Get card UID (for key diversification)
    int res = DesfireGetCardUID(&dctx);
    HFGAL_RET_IF_ERR_MAYBE_MSG(res, !quiet, "Failed retrieving card UID.");

    // Find AIDs to process (from CLI args or the Card Application Directory)
    uint8_t cad[36 * 3] = {0};
    uint8_t numEntries = 0;
    if (aid != 0) {
        cadAidUintToByte(aid, &cad[3]);
        numEntries = 1;
    } else {
        res = readCardApplicationDirectory(&dctx, cad, ARRAYLEN(cad), &numEntries, verbose);
        HFGAL_RET_IF_ERR_MAYBE_MSG(res, !quiet, "Failed reading card application directory.");
    }

    // Loop through each application in the CAD
    for (uint8_t i = 0; i < numEntries * 6; i += 6) {
        uint16_t regionCode = cad[i + 0];
        uint16_t facilityCode = (cad[i + 1] << 8) + cad[i + 2];
        uint32_t currentAid = cadAidByteToUint(&cad[i + 3]);

        if (verbose) {
            if (regionCode > 0 || facilityCode > 0)
                PrintAndLogEx(INFO, "Reading AID: %06X, region: %u, facility: %u", currentAid, regionCode, facilityCode);
            else
                PrintAndLogEx(INFO, "Reading AID: %06X", currentAid);
        }

        // Read & decode credentials
        GallagherCredentials_t creds = {0};
        res = readCardApplicationCredentials(&dctx, currentAid, sitekey, &creds, verbose);
        HFGAL_RET_IF_ERR_MAYBE_MSG(res, !quiet, "Failed reading card application credentials.");

        PrintAndLogEx(SUCCESS, "GALLAGHER - Region: " _GREEN_("%u") ", Facility: " _GREEN_("%u") ", Card No.: " _GREEN_("%u") ", Issue Level: " _GREEN_("%u"),
            creds.region_code, creds.facility_code, creds.card_number, creds.issue_level);
    }

    return PM3_SUCCESS;
}

static int CmdGallagherReader(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf gallagher reader",
                    "read a GALLAGHER tag",
                    "hf gallagher reader --aid 2081f4 --sitekey 00112233445566778899aabbccddeeff"
                    " -> act as a reader that doesn't skips the Card Application Directory and uses a non-default site key\n"
                    "hf gallagher reader -@ -> continuous reader mode"
                );

    void *argtable[] = {
        arg_param_begin,
        arg_str0(NULL, "aid",     "<hex>",   "Application ID to read (3 bytes)"),
        arg_str0("k",  "sitekey", "<hex>",   "Master site key to compute diversified keys (16 bytes) [default=3112B738D8862CCD34302EB299AAB456]"),
        arg_lit0(NULL, "apdu",               "show APDU requests and responses"),
        arg_lit0("v",  "verbose",            "Verbose mode"),
        arg_lit0("@",  "continuous",         "Continuous reader mode"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int aidLen = 0;
    uint8_t aidBuf[3] = {0};
    CLIGetHexWithReturn(ctx, 1, aidBuf, &aidLen);
    if (aidLen > 0 && aidLen != 3)
        HFGAL_RET_ERR(PM3_EINVARG, "--aid must be 3 bytes");

    reverseAid(aidBuf); // PM3 displays AIDs backwards
    uint32_t aid = DesfireAIDByteToUint(aidBuf);
    
    int sitekeyLen = 0;
    uint8_t sitekey[16] = {0};
    memcpy(sitekey, DEFAULT_SITE_KEY, ARRAYLEN(sitekey));
    CLIGetHexWithReturn(ctx, 2, sitekey, &sitekeyLen);
    if (sitekeyLen > 0 && sitekeyLen != 16)
        HFGAL_RET_ERR(PM3_EINVARG, "--sitekey must be 16 bytes");

    SetAPDULogging(arg_get_lit(ctx, 3));
    bool verbose = arg_get_lit(ctx, 4);
    bool continuousMode = arg_get_lit(ctx, 5);
    CLIParserFree(ctx);

    if (!continuousMode) {
        // Read single card
        return readCard(aid, sitekey, verbose, false);
    }

    // Loop until <Enter> is pressed
    PrintAndLogEx(INFO, "Press " _GREEN_("<Enter>") " to exit");
    while (!kbd_enter_pressed()) {
        readCard(aid, sitekey, verbose, !verbose);
    }
    return PM3_SUCCESS;
}

/**
 * @brief Create a new application to store Gallagher cardholder credentials.
 * 
 * @param sitekey MIFARE site key.
 * @param aid New application ID. Should be 0x2?81F4, where 0 <= ? <= 0xB.
 */
static int createGallagherCredentialsApplication(DesfireContext_t *ctx, uint8_t *sitekey, uint32_t aid, bool verbose) {
    // Select application & authenticate
    int res = selectAidAndAuthenticate(ctx, 0x000000, verbose);
    HFGAL_RET_IF_ERR(res);

    // UID is required for key diversification
    if (ctx->uidlen == 0)
        HFGAL_RET_ERR(PM3_EINVARG, "UID is required for key diversification. Please fetch it before calling `createGallagherCredentialsApplication`.");

    // Create application
    DesfireCryptoAlgorithm dstalgo = T_AES;
    uint8_t keycount = 3;
    uint8_t ks1 = 0x0B;
    uint8_t ks2 = (DesfireKeyAlgoToType(dstalgo) << 6) | keycount;;

    uint8_t data[5] = {0};
    DesfireAIDUintToByte(aid, &data[0]);
    data[3] = ks1;
    data[4] = ks2;

    DesfireSetCommMode(ctx, DCMMACed);
    res = DesfireCreateApplication(ctx, data, ARRAYLEN(data));
    HFGAL_RET_IF_ERR_WITH_MSG(res, "Failed creating application %06X. Does it already exist?", aid);

    if (verbose)
        PrintAndLogEx(INFO, "Created application %06X (current has empty contents & blank keys)", aid);

    // Select the new application
    res = selectAid(ctx, aid, verbose);
    HFGAL_RET_IF_ERR_WITH_MSG(res, "Failed selecting application %06X", aid);

    // Add key 2, then key 0 (we must authenticate with key 0 in order to make changes)
    for (int i = 2; i >= 0; i -= 2) {
        // Diversify key
        uint8_t buf[CRYPTO_AES128_KEY_SIZE] = {0};
        res = GallagherDiversifyKey(sitekey, ctx->uid, ctx->uidlen, i, aid, buf);
        HFGAL_RET_IF_ERR_WITH_MSG(res, "Failed diversifying key %d for AID %06X", i, aid);

        PrintAndLogEx(INFO, "Diversified key %d for AID %06X: " _GREEN_("%s"), i, aid, sprint_hex_inrow(buf, ARRAYLEN(buf)));

        // Authenticate
        uint8_t blankKey[CRYPTO_AES128_KEY_SIZE] = {0};
        DesfireSetKeyNoClear(ctx, 0, T_AES, blankKey);
        DesfireSetKdf(ctx, MFDES_KDF_ALGO_NONE, NULL, 0);
        res = authenticate(ctx, verbose);
        HFGAL_RET_IF_ERR_WITH_MSG(res, "Desfire authenticate error. Result: [%d] %s", res, DesfireAuthErrorToStr(res));

        // Change key
        DesfireSetCommMode(ctx, DCMEncryptedPlain);
        res = DesfireChangeKey(ctx, false, i, dstalgo, 1, buf, dstalgo, blankKey, verbose);
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
 * @param sitekey MIFARE site key.
 * @param aid Application ID to put the new file in.
 * @param creds Gallagher cardholder credentials.
 */
static int createGallagherCredentialsFile(DesfireContext_t *ctx, uint8_t *sitekey, uint32_t aid, GallagherCredentials_t *creds, bool verbose) {
    // Select application & authenticate
    DesfireSetKeyNoClear(ctx, 0, T_AES, sitekey);
    DesfireSetKdf(ctx, MFDES_KDF_ALGO_GALLAGHER, NULL, 0);
    int res = selectAidAndAuthenticate(ctx, aid, verbose);
    HFGAL_RET_IF_ERR(res);

    // Prepare create file command
    uint8_t fileType = 0; // standard data file
    uint8_t fileId = 0x00;
    uint8_t fileSize = 16;
    uint8_t fileAccessMode = 0x03; // encrypted
    uint32_t fileRights = 0x2000; // key 0 has God mode, key 2 can read

    uint8_t data[7] = {0};
    data[0] = fileId;
    data[1] = fileAccessMode;
    data[2] = fileRights & 0xff;
    data[3] = (fileRights >> 8) & 0xff;
    Uint3byteToMemLe(&data[4], fileSize);

    // Create file
    res = DesfireCreateFile(ctx, fileType, data, ARRAYLEN(data), false);
    HFGAL_RET_IF_ERR_WITH_MSG(res, "Failed creating file 0 in AID %06X", aid);

    if (verbose)
        PrintAndLogEx(INFO, "Created file 0 in AID %06X (current has empty contents)", aid);

    // Create file contents (2nd half is the bitwise inverse of the encoded creds)
    uint8_t contents[16] = {0};
    encodeCardholderCredentials(contents, creds);
    for (int i = 0; i < 8; i++)
        contents[i + 8] = contents[i] ^ 0xFF;

    // Write file
    DesfireSetCommMode(ctx, DCMEncrypted);
    res = DesfireWriteFile(ctx, fileId, 0, ARRAYLEN(contents), contents);
    HFGAL_RET_IF_ERR_WITH_MSG(res, "Failed writing data to file 0 in AID %06X");
    
    PrintAndLogEx(INFO, "Successfully wrote cardholder credentials to file 0 in AID %06X", aid);
    return PM3_SUCCESS;
}

/**
 * @brief Create the Gallagher Card Application Directory.
 * 
 * @param sitekey MIFARE site key.
 */
static int createGallagherCAD(DesfireContext_t *ctx, uint8_t *sitekey, bool verbose) {
    // Check that card UID has been set
    if (ctx->uidlen == 0)
        HFGAL_RET_ERR(PM3_EINVARG, "Card UID must be set in DesfireContext (required for key diversification)");

    // Select application & authenticate
    int res = selectAidAndAuthenticate(ctx, 0x000000, verbose);
    HFGAL_RET_IF_ERR(res);

    // Create application
    DesfireCryptoAlgorithm dstalgo = T_AES;
    uint8_t keycount = 1;
    uint8_t ks1 = 0x0B;
    uint8_t ks2 = (DesfireKeyAlgoToType(dstalgo) << 6) | keycount;;

    uint8_t data[5] = {0};
    DesfireAIDUintToByte(CAD_AID, &data[0]);
    data[3] = ks1;
    data[4] = ks2;

    DesfireSetCommMode(ctx, DCMMACed);
    res = DesfireCreateApplication(ctx, data, ARRAYLEN(data));
    HFGAL_RET_IF_ERR_WITH_MSG(res, "Failed creating Card Application Directory. Does it already exist?", CAD_AID);

    if (verbose)
        PrintAndLogEx(INFO, "Created Card Application Directory (AID %06X, current has empty contents & blank keys)", CAD_AID);

    // Select application & authenticate
    uint8_t blankKey[DESFIRE_MAX_KEY_SIZE] = {0};
    DesfireSetKeyNoClear(ctx, 0, T_AES, blankKey);
    DesfireSetKdf(ctx, MFDES_KDF_ALGO_NONE, NULL, 0);
    res = selectAidAndAuthenticate(ctx, CAD_AID, verbose);
    HFGAL_RET_IF_ERR(res);

    // Diversify key
    uint8_t buf[CRYPTO_AES128_KEY_SIZE] = {0};
    res = GallagherDiversifyKey(sitekey, ctx->uid, ctx->uidlen, 0, CAD_AID, buf);
    HFGAL_RET_IF_ERR_WITH_MSG(res, "Failed diversifying key 0 for AID %06X", CAD_AID);
    
    PrintAndLogEx(INFO, "Diversified key 0 for CAD (AID %06X): " _GREEN_("%s"), CAD_AID, sprint_hex_inrow(buf, ARRAYLEN(buf)));

    // Change key
    DesfireSetCommMode(ctx, DCMEncryptedPlain);
    res = DesfireChangeKey(ctx, false, 0, dstalgo, 1, buf, dstalgo, blankKey, verbose);
    HFGAL_RET_IF_ERR_WITH_MSG(res, "Failed setting key 0 for CAD");

    if (verbose)
        PrintAndLogEx(INFO, "Successfully set key 0 for CAD");

    PrintAndLogEx(INFO, "Successfully created Card Application Directory (AID %06X)", CAD_AID);
    return PM3_SUCCESS;
}

/**
 * @brief Update the Gallagher Card Application Directory with a new entry.
 * 
 * @param sitekey MIFARE site key.
 * @param aid Application ID to add to the CAD.
 * @param creds Gallagher cardholder credentials (region_code & facility_code are required).
 */
static int updateGallagherCAD(DesfireContext_t *ctx, uint8_t *sitekey, uint32_t aid, GallagherCredentials_t *creds, bool verbose) {
    // Check if CAD exists
    uint8_t cad[36 * 3] = {0};
    uint8_t numEntries = 0;
    int res = selectAid(ctx, CAD_AID, verbose);
    if (res == PM3_SUCCESS) {
        if (verbose)
            PrintAndLogEx(INFO, "Card Application Directory exists, reading entries...");

        res = readCardApplicationDirectory(ctx, cad, ARRAYLEN(cad), &numEntries, verbose);
        HFGAL_RET_IF_ERR(res);

        // Check that there is space for the new entry
        if (numEntries >= 18)
            HFGAL_RET_ERR(PM3_EFATAL, "Card application directory is full.");
    } else {
        if (verbose)
            PrintAndLogEx(INFO, "Card Application Directory does not exist, creating it now...");

        res = createGallagherCAD(ctx, sitekey, verbose);
        HFGAL_RET_IF_ERR(res);
    }

    uint8_t fileId = numEntries / 6; // 6 entries per file
    uint8_t entryNum = numEntries % 6;

    // Create entry
    uint8_t *entry = &cad[numEntries * 6];
    entry[0] = creds->region_code;
    entry[1] = (creds->facility_code >> 8) & 0xFF;
    entry[2] = creds->facility_code & 0xFF;
    cadAidUintToByte(aid, &entry[3]);

    if (verbose)
        PrintAndLogEx(INFO, "Adding entry to CAD (position %d in file %d): %s", entryNum, fileId, sprint_hex_inrow(entry, 6));

    // Select application & authenticate
    DesfireSetKeyNoClear(ctx, 0, T_AES, sitekey);
    DesfireSetKdf(ctx, MFDES_KDF_ALGO_GALLAGHER, NULL, 0);
    res = selectAidAndAuthenticate(ctx, CAD_AID, verbose);
    HFGAL_RET_IF_ERR(res);

    // Create file if necessary
    if (entryNum == 0) {
        if (verbose)
            PrintAndLogEx(INFO, "Creating new file in CAD");

        // Prepare create file command
        uint8_t fileType = 0; // standard data file
        uint8_t fileSize = 36;
        uint8_t fileAccessMode = 0x00; // plain
        uint32_t fileRights = 0xE000; // key 0 has God mode, everyone can read

        uint8_t data[7] = {0};
        data[0] = fileId;
        data[1] = fileAccessMode;
        data[2] = fileRights & 0xff;
        data[3] = (fileRights >> 8) & 0xff;
        Uint3byteToMemLe(&data[4], fileSize);

        // Create file
        res = DesfireCreateFile(ctx, fileType, data, ARRAYLEN(data), false);
        HFGAL_RET_IF_ERR_WITH_MSG(res, "Failed creating file %d in CAD (AID %06X)", fileId, CAD_AID);

        if (verbose)
            PrintAndLogEx(INFO, "Created file %d in CAD (current has empty contents)", fileId);

        // Write file
        res = DesfireWriteFile(ctx, fileId, fileId * 36, 36, entry);
    } else {
        // Write file
        res = DesfireWriteFile(ctx, fileId, entryNum * 6, 6, entry);
    }
    HFGAL_RET_IF_ERR_WITH_MSG(res, "Failed writing data to file %d in CAD (AID %06X)", fileId, CAD_AID);
    
    PrintAndLogEx(INFO, "Successfully added new entry for %06X to the Card Application Directory", aid);
    return PM3_SUCCESS;
}

static int CmdGallagherClone(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf gallagher clone",
                    "clone a GALLAGHER card to a blank DESFire card.",
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
        arg_str0(NULL,  "aid",     "<hex>",     "Application ID to write (3 bytes) [default=2081F4]"),
        arg_str0(NULL,  "sitekey", "<hex>",     "Master site key to compute diversified keys (16 bytes) [default=3112B738D8862CCD34302EB299AAB456]"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    SetAPDULogging(arg_get_lit(ctx, 1));
    bool verbose = arg_get_lit(ctx, 2) || true;
    int keyNum = arg_get_int_def(ctx, 3, 0);
    
    int algo = T_DES;
    if (CLIGetOptionList(arg_get_str(ctx, 4), DesfireAlgoOpts, &algo)) return PM3_ESOFT;

    int keyLen = 0;
    uint8_t key[DESFIRE_MAX_KEY_SIZE] = {0};
    CLIGetHexWithReturn(ctx, 5, key, &keyLen);
    if (keyLen && keyLen != desfire_get_key_length(algo)) {
        HFGAL_RET_ERR(PM3_EINVARG, "%s key must have %d bytes length instead of %d", CLIGetOptionListStr(DesfireAlgoOpts, algo), desfire_get_key_length(algo), keyLen);
    }
    if (keyLen == 0) {
        // Default to a key of all zeros
        keyLen = desfire_get_key_length(algo);
    }

    uint64_t region_code = arg_get_u64(ctx, 6); // uint16, will be validated later
    uint64_t facility_code = arg_get_u64(ctx, 7); // uint32, will be validated later
    uint64_t card_number = arg_get_u64(ctx, 8); // uint64
    uint64_t issue_level = arg_get_u64(ctx, 9); // uint32, will be validated later

    int aidLen = 0;
    uint8_t aidBuf[3] = "\x20\x81\xF4";
    CLIGetHexWithReturn(ctx, 10, aidBuf, &aidLen);
    if (aidLen > 0 && aidLen != 3) {
        HFGAL_RET_ERR(PM3_EINVARG, "--aid must be 3 bytes");
    }
    reverseAid(aidBuf); // PM3 displays AIDs backwards
    uint32_t aid = DesfireAIDByteToUint(aidBuf);

    // Check that the AID is in the expected range
    if (memcmp(aidBuf, "\xF4\x81", 2) != 0 || aidBuf[2] < 0x20 || aidBuf[2] > 0x2B)
        // TODO: this should probably be a warning, but key diversification will throw an error later even if we don't
        HFGAL_RET_ERR(PM3_EINVARG, "Invalid Gallagher AID %06X, expected 2?81F4, where 0 <= ? <= 0xB", aid);
    
    int sitekeyLen = 0;
    uint8_t sitekey[16] = {0};
    memcpy(sitekey, DEFAULT_SITE_KEY, ARRAYLEN(sitekey));
    CLIGetHexWithReturn(ctx, 11, sitekey, &sitekeyLen);
    if (sitekeyLen > 0 && sitekeyLen != 16)
        HFGAL_RET_ERR(PM3_EINVARG, "--sitekey must be 16 bytes");
    CLIParserFree(ctx);

    if (!isValidGallagherCredentials(region_code, facility_code, card_number, issue_level))
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

    // Create application
    DesfireSetKeyNoClear(&dctx, keyNum, algo, key);
    DesfireSetKdf(&dctx, MFDES_KDF_ALGO_NONE, NULL, 0);
    res = createGallagherCredentialsApplication(&dctx, sitekey, aid, verbose);
    HFGAL_RET_IF_ERR_WITH_MSG(res, "Failed creating Gallagher application");

    // Create credential files
    // Don't need to set keys here, they're generated automatically
    res = createGallagherCredentialsFile(&dctx, sitekey, aid, &creds, verbose);
    HFGAL_RET_IF_ERR_WITH_MSG(res, "Failed creating Gallagher credential file.");

    // Update card application directory
    DesfireSetKeyNoClear(&dctx, keyNum, algo, key);
    DesfireSetKdf(&dctx, MFDES_KDF_ALGO_NONE, NULL, 0);
    res = updateGallagherCAD(&dctx, sitekey, aid, &creds, verbose);
    HFGAL_RET_IF_ERR_WITH_MSG(res, "Failed updating Gallagher card application directory.");

    PrintAndLogEx(SUCCESS, "Done");
    PrintAndLogEx(HINT, "Hint: try " _YELLOW_("`hf gallagher reader`") " to verify");
    return PM3_SUCCESS;
}

static int CmdGallagherSim(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf gallagher sim",
                  "Enables simulation of GALLAGHER card with specified card number.\n"
                  "Simulation runs until the button is pressed or another USB command is issued.\n",
                  "hf gallagher sim --rc 1 --fc 22 --cn 3333 --il 4"
                );

    void *argtable[] = {
        arg_param_begin,
        arg_u64_1(NULL, "rc", "<decimal>", "Region code. 4 bits max"),
        arg_u64_1(NULL, "fc", "<decimal>", "Facility code. 2 bytes max"),
        arg_u64_1(NULL, "cn", "<decimal>", "Card number. 3 bytes max"),
        arg_u64_1(NULL, "il", "<decimal>", "Issue level. 4 bits max"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    uint64_t region_code = arg_get_u64(ctx, 1); // uint16, will be validated later
    uint64_t facility_code = arg_get_u64(ctx, 2); // uint32, will be validated later
    uint64_t card_number = arg_get_u64(ctx, 3); // uint64
    uint64_t issue_level = arg_get_u64(ctx, 4); // uint32, will be validated later
    CLIParserFree(ctx);

    if (!isValidGallagherCredentials(region_code, facility_code, card_number, issue_level))
        return PM3_EINVARG;

    // TODO: create data

    // TODO: simulate

    return PM3_ENOTIMPL;
}

static int CmdHelp(const char *Cmd);

static command_t CommandTable[] = {
    {"help",   CmdHelp,            AlwaysAvailable, "This help"},
    {"reader", CmdGallagherReader, IfPm3Iso14443,   "attempt to read and extract tag data"},
    {"clone",  CmdGallagherClone,  IfPm3Iso14443,   "clone GALLAGHER tag to a blank DESFire card"},
    {"sim",    CmdGallagherSim,    IfPm3Iso14443,   "simulate GALLAGHER tag"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void) Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdHFGallagher(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}
