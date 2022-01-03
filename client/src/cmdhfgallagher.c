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

static void reverseAid(uint8_t *aid) {
    uint8_t tmp = aid[0];
    aid[0] = aid[2];
    aid[2] = tmp;
};

static int CmdHelp(const char *Cmd);

static int readCardApplicationDirectory(DesfireContext_t *ctx, uint8_t *destBuf, uint8_t destBufLen, uint8_t *numEntries, bool verbose) {
    if (destBufLen != 3 * 36) {
        PrintAndLogEx(ERR, "readCardApplicationDirectory destination buffer is incorrectly sized. "
            "Received length %d, expected %d", destBufLen, 3 * 36);
        return PM3_EINVARG;
    }

    DesfireSetCommMode(ctx, DCMPlain);

    // Get card AIDs from Card Application Directory (which contains 1 to 3 files)
    uint8_t cadAid[] = { 0xF4, 0x81, 0x2F };
    int res = DesfireSelectAID(ctx, cadAid, NULL);
    HF_GALLAGHER_RETURN_IF_ERROR(res);

    // Read up to 3 files with 6x 6-byte entries each
    for (uint8_t i = 0; i < 3; i++) {
        size_t readLen;
        DesfireReadFile(ctx, i, 0, 36, &destBuf[i * 36], &readLen);
        // end if the last entry is NULL
        if (memcmp(&destBuf[36 * i + 30], "\0\0\0\0\0\0", 6) == 0) break;
    }

    // Keep only valid entries
    *numEntries = 0;
    for (uint8_t i = 0; i < destBufLen; i += 6) {
        if (memcmp(&destBuf[i], "\0\0\0\0\0\0", 6) == 0) break;
        *numEntries += 1;
    }

    if (verbose) {
        // Print what we found
        PrintAndLogEx(SUCCESS, "Card Application Directory contains:" NOLF);
        for (int i = 0; i < *numEntries; i++)
            PrintAndLogEx(NORMAL, "%s %06x" NOLF, (i == 0) ? "" : ",", DesfireAIDByteToUint(&destBuf[i*6 + 3]));
        PrintAndLogEx(NORMAL, "");
    }

    return PM3_SUCCESS;
}

static int readCardApplicationCredentials(DesfireContext_t *ctx, uint8_t *aid, uint8_t *sitekey, GallagherCredentials_t *creds, bool verbose) {
    // Check that card UID has been set
    if (ctx->uidlen == 0) {
        PrintAndLogEx(ERR, "Card UID must be set in DesfireContext (required for key diversification)");
        return PM3_EINVARG;
    }

    // Set up context
    DesfireSetKeyNoClear(ctx, 2, T_AES, sitekey);
    DesfireSetKdf(ctx, MFDES_KDF_ALGO_GALLAGHER, NULL, 0);
    DesfireSetCommMode(ctx, DCMPlain);
    DesfireSetCommandSet(ctx, DCCNativeISO);

    // Select and authenticate to AID
    int res = DesfireSelectAndAuthenticateAppW(ctx, DACEV1, ISW6bAID, DesfireAIDByteToUint(aid), false, verbose);
    HF_GALLAGHER_RETURN_IF_ERROR(res);

    // Read file 0 (contains credentials)
    uint8_t buf[16] = {0};
    size_t readLen = 0;
    DesfireSetCommMode(ctx, DCMEncrypted);
    res = DesfireReadFile(ctx, 0, 0, 16, buf, &readLen);
    HF_GALLAGHER_RETURN_IF_ERROR(res);

    // Check file contained 16 bytes of data
    if (readLen != 16) {
        PrintAndLogEx(ERR, "Failed reading file 0 in %06x", DesfireAIDByteToUint(aid));
        return PM3_EFAILED;
    }

    // Check second half of file is the bitwise inverse of the first half
    for (uint8_t i = 8; i < 16; i++)
        buf[i] ^= 0xFF;
    if (memcmp(buf, &buf[8], 8) != 0) {
        PrintAndLogEx(ERR, "Invalid cardholder data in file 0. Received %s", sprint_hex_inrow(buf, 16));
        return PM3_EFAILED;
    }
    
    decodeCardholderCredentials(buf, creds);

    // TODO: read MIFARE Enhanced Security file
    // https://github.com/megabug/gallagher-research/blob/master/formats/mes.md

    return PM3_SUCCESS;
}

static int readCard(uint8_t *aid, uint8_t *sitekey, bool verbose, bool continuousMode) {
    DropField();
    clearCommandBuffer();

    // Set up context
    DesfireContext_t dctx = {0};
    DesfireClearContext(&dctx);

    // Get card UID (for key diversification)
    int res = DesfireGetCardUID(&dctx);
    HF_GALLAGHER_FAIL_IF_ERROR(res, verbose || !continuousMode, "Failed retrieving card UID.");

    // Find AIDs to process (from CLI args or the Card Application Directory)
    uint8_t cad[36 * 3] = {0};
    uint8_t numEntries = 0;
    if (aid != NULL) {
        memcpy(&cad[3], aid, 3);
        reverseAid(&cad[3]); // CAD stores AIDs backwards
        numEntries = 1;
    } else {
        res = readCardApplicationDirectory(&dctx, cad, ARRAYLEN(cad), &numEntries, verbose);
        HF_GALLAGHER_FAIL_IF_ERROR(res, verbose || !continuousMode, "Failed reading card application directory.");
    }

    // Loop through each application in the CAD
    for (uint8_t i = 0; i < numEntries * 6; i += 6) {
        uint16_t region_code = cad[i + 0];
        uint16_t facility_code = (cad[i + 1] << 8) + cad[i + 2];

        // Copy AID out of CAD record
        uint8_t currentAid[3];
        memcpy(currentAid, &cad[3], 3);
        reverseAid(currentAid); // CAD stores AIDs backwards

        if (verbose) {
            if (region_code > 0 || facility_code > 0)
                PrintAndLogEx(INFO, "Reading AID: %06x, region: %u, facility: %u", DesfireAIDByteToUint(currentAid), region_code, facility_code);
            else
                PrintAndLogEx(INFO, "Reading AID: %06x", DesfireAIDByteToUint(currentAid));
        }

        // Read & decode credentials
        GallagherCredentials_t creds = {0};
        res = readCardApplicationCredentials(&dctx, currentAid, sitekey, &creds, verbose);
        HF_GALLAGHER_FAIL_IF_ERROR(res, verbose || !continuousMode, "Failed reading card application credentials.");

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
        arg_str1("k",  "sitekey", "<hex>",   "Master site key to compute diversified keys (16 bytes)"),
        arg_lit0(NULL, "apdu",               "show APDU requests and responses"),
        arg_lit0("v",  "verbose",            "Verbose mode"),
        arg_lit0("@",  "continuous",         "Continuous reader mode"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int aidLen = 0;
    uint8_t aid[3] = {0};
    CLIGetHexWithReturn(ctx, 1, aid, &aidLen);
    if (aidLen > 0 && aidLen != 3) {
        PrintAndLogEx(ERR, "--aid must be 3 bytes");
        return PM3_EINVARG;
    }
    reverseAid(aid); // PM3 displays AIDs backwards
    
    int sitekeyLen = 0;
    uint8_t sitekey[16] = {0};
    CLIGetHexWithReturn(ctx, 2, sitekey, &sitekeyLen);
    if (sitekeyLen > 0 && sitekeyLen != 16) {
        PrintAndLogEx(ERR, "--sitekey must be 16 bytes");
        return PM3_EINVARG;
    }

    SetAPDULogging(arg_get_lit(ctx, 3));
    bool verbose = arg_get_lit(ctx, 4);
    bool continuousMode = arg_get_lit(ctx, 5);
    CLIParserFree(ctx);

    if (continuousMode)
        PrintAndLogEx(INFO, "Press " _GREEN_("<Enter>") " to exit");

    int res;
    do {
        res = readCard(aidLen > 0 ? aid : NULL, sitekey, verbose, continuousMode);
    } while (continuousMode && !kbd_enter_pressed());

    return continuousMode ? PM3_SUCCESS : res;
}

int GallagherDiversifyKey(uint8_t *sitekey, uint8_t *uid, uint8_t uidLen, uint8_t keyNo, uint32_t aid, uint8_t *keyOut) {
    // Generate diversification input
    uint8_t kdfInputLen = 11;
    int res = mfdes_kdf_input_gallagher(uid, uidLen, keyNo, aid, keyOut, &kdfInputLen);
    HF_GALLAGHER_RETURN_IF_ERROR(res);

    // Make temporary DesfireContext
    DesfireContext_t dctx = {0};
    DesfireSetKey(&dctx, 0, T_AES, sitekey);
    
    // Diversify input & copy to output buffer
    MifareKdfAn10922(&dctx, DCOMasterKey, keyOut, kdfInputLen);
    memcpy(keyOut, dctx.key, CRYPTO_AES128_KEY_SIZE);

    return PM3_SUCCESS;
}

static int createGallagherCredentialsApplication(DesfireContext_t *ctx, uint8_t *sitekey, uint8_t *aid, bool verbose) {
    DesfireSetCommMode(ctx, DCMPlain);
    DesfireSetCommandSet(ctx, DCCNativeISO);
    int res = DesfireSelectAndAuthenticateAppW(ctx, DACEV1, ISW6bAID, 0x000000, false, verbose);
    HF_GALLAGHER_RETURN_IF_ERROR(res);

    // Create application
    DesfireCryptoAlgorithm dstalgo = T_AES;
    uint8_t keycount = 3;
    uint8_t ks1 = 0x0B;
    uint8_t ks2 = (DesfireKeyAlgoToType(dstalgo) << 6) | keycount;;

    uint8_t data[5] = {0};
    memcpy(&data[0], aid, 3);
    data[3] = ks1;
    data[4] = ks2;

    DesfireSetCommMode(ctx, DCMMACed);
    res = DesfireCreateApplication(ctx, data, ARRAYLEN(data));
    HF_GALLAGHER_RETURN_IF_ERROR(res);

    // Select the new application
    DesfireSetCommMode(ctx, DCMPlain);
    res = DesfireSelectEx(ctx, true, ISW6bAID, DesfireAIDByteToUint(aid), NULL);
    HF_GALLAGHER_RETURN_IF_ERROR(res);
    if (verbose)
        PrintAndLogEx(INFO, "AID: %06x is " _GREEN_("selected"), DesfireAIDByteToUint(aid));

    // Add key 2, then key 0 (we must authenticate with key 0 in order to make changes)
    for (int i = 2; i >= 0; i -= 2) {
        // Diversify key
        uint8_t buf[CRYPTO_AES128_KEY_SIZE] = {0};
        res = GallagherDiversifyKey(sitekey, ctx->uid, ctx->uidlen, i, DesfireAIDByteToUint(aid), buf);
        HF_GALLAGHER_RETURN_IF_ERROR(res);

        if (verbose)
            PrintAndLogEx(INFO, " Diversified key %d: " _GREEN_("%s"), i, sprint_hex_inrow(buf, ARRAYLEN(buf)));

        // Authenticate
        uint8_t blankKey[DESFIRE_MAX_KEY_SIZE] = {0};
        DesfireSetKeyNoClear(ctx, 0, T_AES, blankKey);
        DesfireSetCommMode(ctx, DCMPlain);
        res = DesfireAuthenticate(ctx, DACEV1, verbose);
        HF_GALLAGHER_RETURN_IF_ERROR(res);

        // Change key
        DesfireSetCommMode(ctx, DCMEncryptedPlain);
        res = DesfireChangeKey(ctx, false, i, dstalgo, 1, buf, dstalgo, blankKey, true);
        HF_GALLAGHER_RETURN_IF_ERROR(res);
        if (verbose)
            PrintAndLogEx(INFO, " Successfully set key %d", i);
    }

    return PM3_SUCCESS;
}

static int createGallagherCredentialsFile(DesfireContext_t *ctx, uint8_t *sitekey, uint8_t *aid, GallagherCredentials_t *creds, bool verbose) {
    // Set up context
    DesfireSetKeyNoClear(ctx, 0, T_AES, sitekey);
    DesfireSetKdf(ctx, MFDES_KDF_ALGO_GALLAGHER, NULL, 0);
    DesfireSetCommMode(ctx, DCMPlain);

    // Select application
    int res = DesfireSelectAndAuthenticateAppW(ctx, DACEV1, ISW6bAID, DesfireAIDByteToUint(aid), false, verbose);
    HF_GALLAGHER_RETURN_IF_ERROR(res);

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
    HF_GALLAGHER_RETURN_IF_ERROR(res);

    // Create file contents (2nd half is the bitwise inverse of the encoded creds)
    uint8_t contents[16] = {0};
    encodeCardholderCredentials(contents, creds);
    for (int i = 0; i < 8; i++)
        contents[i + 8] = contents[i] ^ 0xFF;

    // Write file
    DesfireSetCommMode(ctx, DCMEncrypted);
    res = DesfireWriteFile(ctx, fileId, 0, ARRAYLEN(contents), contents);
    HF_GALLAGHER_RETURN_IF_ERROR(res);

    return PM3_SUCCESS;
}

static int createGallagherCAD(DesfireContext_t *ctx, uint8_t *sitekey, bool verbose) {
    DesfireClearSession(ctx);
    DesfireSetCommMode(ctx, DCMPlain);
    DesfireSetCommandSet(ctx, DCCNativeISO);
    int res = DesfireSelectAndAuthenticateAppW(ctx, DACEV1, ISW6bAID, 0x000000, false, verbose);
    HF_GALLAGHER_RETURN_IF_ERROR(res);

    // Create application
    uint32_t aid = 0x2F81F4;
    DesfireCryptoAlgorithm dstalgo = T_AES;
    uint8_t keycount = 1;
    uint8_t ks1 = 0x0B;
    uint8_t ks2 = (DesfireKeyAlgoToType(dstalgo) << 6) | keycount;;

    uint8_t data[5] = {0};
    DesfireAIDUintToByte(aid, &data[0]);
    data[3] = ks1;
    data[4] = ks2;

    DesfireSetCommMode(ctx, DCMMACed);
    res = DesfireCreateApplication(ctx, data, ARRAYLEN(data));
    HF_GALLAGHER_RETURN_IF_ERROR(res);

    // Select the new application
    DesfireSetCommMode(ctx, DCMPlain);
    res = DesfireSelectEx(ctx, true, ISW6bAID, aid, NULL);
    HF_GALLAGHER_RETURN_IF_ERROR(res);
    if (verbose)
        PrintAndLogEx(INFO, "AID: %06x is " _GREEN_("selected"), aid);

    // Diversify key
    uint8_t buf[CRYPTO_AES128_KEY_SIZE] = {0};
    res = GallagherDiversifyKey(sitekey, ctx->uid, ctx->uidlen, 0, aid, buf);
    HF_GALLAGHER_RETURN_IF_ERROR(res);

    if (verbose)
        PrintAndLogEx(INFO, " Diversified key 0: " _GREEN_("%s"), sprint_hex_inrow(buf, ARRAYLEN(buf)));

    // Authenticate
    uint8_t blankKey[DESFIRE_MAX_KEY_SIZE] = {0};
    DesfireSetKeyNoClear(ctx, 0, T_AES, blankKey);
    DesfireSetCommMode(ctx, DCMPlain);
    res = DesfireAuthenticate(ctx, DACEV1, verbose);
    HF_GALLAGHER_RETURN_IF_ERROR(res);

    // Change key
    DesfireSetCommMode(ctx, DCMEncryptedPlain);
    res = DesfireChangeKey(ctx, false, 0, dstalgo, 1, buf, dstalgo, blankKey, true);
    HF_GALLAGHER_RETURN_IF_ERROR(res);
    if (verbose)
        PrintAndLogEx(INFO, " Successfully set key 0");

    return PM3_SUCCESS;
}

static int updateGallagherCAD(DesfireContext_t *ctx, uint8_t *sitekey, uint8_t *aid, GallagherCredentials_t *creds, bool verbose) {
    uint32_t cadAid = 0x2F81F4;


    // Check if CAD exists
    uint8_t cad[36 * 3] = {0};
    uint8_t numEntries = 0;
    int res = DesfireSelectEx(ctx, true, ISW6bAID, cadAid, NULL);
    if (res == PM3_SUCCESS) {
        res = readCardApplicationDirectory(ctx, cad, ARRAYLEN(cad), &numEntries, verbose);
        HF_GALLAGHER_RETURN_IF_ERROR(res);
    } else {
        DesfireSetCommandSet(ctx, DCCNativeISO);
        res = createGallagherCAD(ctx, sitekey, verbose);
        HF_GALLAGHER_RETURN_IF_ERROR(res);

        // Check that there is space for the new entry
        if (numEntries == 18) {
            PrintAndLogEx(ERR, "Card application directory is full.");
            return PM3_EFATAL;
        }
    }

    uint8_t fileId = numEntries / 6; // 6 entries per file
    uint8_t entryNum = numEntries % 6;

    // Create entry
    uint8_t *entry = &cad[numEntries * 6];
    entry[0] = creds->region_code;
    entry[1] = (creds->facility_code >> 8) & 0xFF;
    entry[2] = creds->facility_code & 0xFF;
    memcpy(&entry[3], aid, 3);
    reverseAid(&entry[3]); // CAD stores AIDs backwards

    // Set up context
    DesfireSetKeyNoClear(ctx, 0, T_AES, sitekey);
    DesfireSetKdf(ctx, MFDES_KDF_ALGO_GALLAGHER, NULL, 0);
    DesfireSetCommMode(ctx, DCMPlain);

    // Select application
    res = DesfireSelectAndAuthenticateAppW(ctx, DACEV1, ISW6bAID, cadAid, false, verbose);
    HF_GALLAGHER_RETURN_IF_ERROR(res);

    // Create file if necessary
    if (entryNum == 0) {
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
        HF_GALLAGHER_RETURN_IF_ERROR(res);

        // Write file
        res = DesfireWriteFile(ctx, fileId, fileId * 36, 36, entry);
        HF_GALLAGHER_RETURN_IF_ERROR(res);
    } else {
        // Write file
        res = DesfireWriteFile(ctx, fileId, entryNum * 6, 6, entry);
        HF_GALLAGHER_RETURN_IF_ERROR(res);
    }

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
        arg_str1(NULL,  "sitekey", "<hex>",     "Master site key to compute diversified keys (16 bytes)"),
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
        PrintAndLogEx(ERR, "%s key must have %d bytes length instead of %d.", CLIGetOptionListStr(DesfireAlgoOpts, algo), desfire_get_key_length(algo), keyLen);
        return PM3_EINVARG;
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
    uint8_t aid[3] = "\x20\x81\xF4";
    CLIGetHexWithReturn(ctx, 10, aid, &aidLen);
    if (aidLen > 0 && aidLen != 3) {
        PrintAndLogEx(ERR, "--aid must be 3 bytes");
        return PM3_EINVARG;
    }
    reverseAid(aid); // PM3 displays AIDs backwards

    // Check that the AID is in the expected range
    if (memcmp(aid, "\xF4\x81", 2) != 0 || aid[2] < 0x20 || aid[2] > 0x2B) {
        PrintAndLogEx(WARNING, "Invalid Gallagher AID %06X, expected 2?81F4.", DesfireAIDByteToUint(aid));
    }
    
    int sitekeyLen = 0;
    uint8_t sitekey[16] = {0};
    CLIGetHexWithReturn(ctx, 11, sitekey, &sitekeyLen);
    if (sitekeyLen > 0 && sitekeyLen != 16) {
        PrintAndLogEx(ERR, "--sitekey must be 16 bytes");
        return PM3_EINVARG;
    }
    CLIParserFree(ctx);

    if (!isValidGallagherCredentials(region_code, facility_code, card_number, issue_level)) {
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
    HF_GALLAGHER_FAIL_IF_ERROR(res, true, "Failed retrieving card UID.");

    // Create application
        DesfireSetKeyNoClear(&dctx, keyNum, algo, key);
        DesfireSetKdf(&dctx, MFDES_KDF_ALGO_NONE, NULL, 0);
        res = createGallagherCredentialsApplication(&dctx, sitekey, aid, verbose);
        HF_GALLAGHER_FAIL_IF_ERROR(res, true, "Failed creating Gallagher application.");
        DropField();

    // Create credential files
        // Don't need to set keys here, they're generated automatically
        res = createGallagherCredentialsFile(&dctx, sitekey, aid, &creds, verbose);
        HF_GALLAGHER_FAIL_IF_ERROR(res, true, "Failed creating Gallagher credential file.");
        DropField();

    // Update card application directory
        DesfireSetKeyNoClear(&dctx, keyNum, algo, key);
        DesfireSetKdf(&dctx, MFDES_KDF_ALGO_NONE, NULL, 0);
        res = updateGallagherCAD(&dctx, sitekey, aid, &creds, verbose);
        HF_GALLAGHER_FAIL_IF_ERROR(res, true, "Failed updating Gallagher card application directory.");
        DropField();

    DropField();
    PrintAndLogEx(SUCCESS, "Done");
    PrintAndLogEx(HINT, "Hint: try " _YELLOW_("`hf gallagher reader`") " to verify");
    return PM3_ENOTIMPL;
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

    if (!isValidGallagherCredentials(region_code, facility_code, card_number, issue_level)) {
        return PM3_EINVARG;
    }

    // TODO: create data

    // TODO: simulate

    return PM3_ENOTIMPL;
}

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
