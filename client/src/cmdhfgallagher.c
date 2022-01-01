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
    int res = DesfireSelectAndAuthenticateAppW(ctx, DACEV1, ISW6bAID, le24toh(aid), false, verbose);
    HF_GALLAGHER_RETURN_IF_ERROR(res);

    // Read file 0 (contains credentials)
    uint8_t buf[16] = { 0x00 };
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

static int CmdGallagherClone(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf gallagher clone",
                    "clone a GALLAGHER card to a blank DESFire card.",
                    "hf gallagher clone --rc 1 --fc 22 --cn 3333 --il 4"
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

    PrintAndLogEx(INFO, "Preparing to clone Gallagher from specified data.");

    // TODO: write data

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
