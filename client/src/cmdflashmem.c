//-----------------------------------------------------------------------------
// Copyright (C) 2018 iceman
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Proxmark3 RDV40 Flash memory commands
//-----------------------------------------------------------------------------
#include "cmdflashmem.h"
#include <ctype.h>
#include "cmdparser.h"         // command_t
#include "cliparser.h"
#include "pmflash.h"
#include "fileutils.h"         // saveFile
#include "comms.h"             // getfromdevice
#include "cmdflashmemspiffs.h" // spiffs commands
#include "rsa.h"
#include "sha1.h"

#define MCK 48000000
#define FLASH_MINFAST 24000000 //33000000
#define FLASH_BAUD MCK/2
#define FLASH_FASTBAUD MCK
#define FLASH_MINBAUD FLASH_FASTBAUD

static int CmdHelp(const char *Cmd);

static int CmdFlashmemSpiBaudrate(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "mem baudrate",
                  "Set the baudrate for the SPI flash memory communications.\n"
                  "Reading Flash ID will virtually always fail under 48MHz setting.\n"
                  "Unless you know what you are doing, please stay at 24MHz.\n"
                  "If >= 24MHz, FASTREADS instead of READS instruction will be used.",
                  "mem baudrate --mhz 48"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_int1(NULL, "mhz", "<24|48>", "SPI baudrate in MHz"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    int br = arg_get_int_def(ctx, 1, -1);
    CLIParserFree(ctx);

    if (br == -1) {
        PrintAndLogEx(ERR, "failed to get baudrate");
        return PM3_EINVARG;
    }

    uint32_t baudrate = br * 1000000;
    if (baudrate != FLASH_BAUD && baudrate != FLASH_MINBAUD) {
        PrintAndLogEx(ERR, "wrong baudrate. Only 24 or 48 is allowed");
        return PM3_EINVARG;
    }
    SendCommandNG(CMD_FLASHMEM_SET_SPIBAUDRATE, (uint8_t *)&baudrate, sizeof(uint32_t));
    return PM3_SUCCESS;
}

static int CmdFlashMemLoad(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "mem load",
                  "Loads binary file into flash memory on device\n"
                  "Warning: mem area to be written must have been wiped first\n"
                  "( this is already taken care when loading dictionaries )",
                  "mem load -f myfile                 -> upload file myfile values at default offset 0\n"
                  "mem load -f myfile -o 1024         -> upload file myfile values at offset 1024\n"
                  "mem load -f mfc_default_keys -m    -> upload MFC keys\n"
                  "mem load -f t55xx_default_pwds -t  -> upload T55XX passwords\n"
                  "mem load -f iclass_default_keys -i -> upload iCLASS keys\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_int0("o", "offset", "<dec>", "offset in memory"),
        arg_lit0("m", "mifare,mfc", "upload 6 bytes keys (mifare key dictionary)"),
        arg_lit0("i", "iclass", "upload 8 bytes keys (iClass key dictionary)"),
        arg_lit0("t", "t55xx", "upload 4 bytes keys (password dictionary)"),
        arg_strx0("f", "file", "<filename>", "file name"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int offset = arg_get_int_def(ctx, 1, 0);
    bool is_mfc = arg_get_lit(ctx, 2);
    bool is_iclass = arg_get_lit(ctx, 3);
    bool is_t55xx = arg_get_lit(ctx, 4);
    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 5), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);
    CLIParserFree(ctx);

    Dictionary_t d = DICTIONARY_NONE;
    if (is_mfc) {
        d = DICTIONARY_MIFARE;
        PrintAndLogEx(INFO, "treating file as MIFARE Classic keys");
    } else if (is_iclass) {
        d = DICTIONARY_ICLASS;
        PrintAndLogEx(INFO, "treating file as iCLASS keys");
    } else if (is_t55xx) {
        d = DICTIONARY_T55XX;
        PrintAndLogEx(INFO, "treating file as T55xx passwords");
    }

    size_t datalen = 0;
    uint32_t keycount = 0;
    int res = 0;
    uint8_t *data = calloc(FLASH_MEM_MAX_SIZE, sizeof(uint8_t));

    switch (d) {
        case DICTIONARY_MIFARE:
            offset = DEFAULT_MF_KEYS_OFFSET;
            res = loadFileDICTIONARY(filename, data + 2, &datalen, 6, &keycount);
            if (res || !keycount) {
                free(data);
                return PM3_EFILE;
            }
            // limited space on flash mem
            if (keycount > 0xFFFF)
                keycount &= 0xFFFF;

            data[0] = (keycount >> 0) & 0xFF;
            data[1] = (keycount >> 8) & 0xFF;
            datalen += 2;
            break;
        case DICTIONARY_T55XX:
            offset = DEFAULT_T55XX_KEYS_OFFSET;
            res = loadFileDICTIONARY(filename, data + 2, &datalen, 4, &keycount);
            if (res || !keycount) {
                free(data);
                return PM3_EFILE;
            }
            // limited space on flash mem
            if (keycount > 0xFFFF)
                keycount &= 0xFFFF;

            data[0] = (keycount >> 0) & 0xFF;
            data[1] = (keycount >> 8) & 0xFF;
            datalen += 2;
            break;
        case DICTIONARY_ICLASS:
            offset = DEFAULT_ICLASS_KEYS_OFFSET;
            res = loadFileDICTIONARY(filename, data + 2, &datalen, 8, &keycount);
            if (res || !keycount) {
                free(data);
                return PM3_EFILE;
            }
            // limited space on flash mem
            if (keycount > 0xFFFF)
                keycount &= 0xFFFF;

            data[0] = (keycount >> 0) & 0xFF;
            data[1] = (keycount >> 8) & 0xFF;
            datalen += 2;
            break;
        case DICTIONARY_NONE:
            res = loadFile_safe(filename, ".bin", (void **)&data, &datalen);
            if (res != PM3_SUCCESS) {
                free(data);
                return PM3_EFILE;
            }

            if (datalen > FLASH_MEM_MAX_SIZE) {
                PrintAndLogEx(ERR, "error, filesize is larger than available memory");
                free(data);
                return PM3_EOVFLOW;
            }
            break;
    }
// not needed when we transite to loadxxxx_safe methods.(iceman)
    uint8_t *newdata = realloc(data, datalen);
    if (newdata == NULL) {
        free(data);
        return PM3_EMALLOC;
    } else {
        data = newdata;
    }

    //Send to device
    uint32_t bytes_sent = 0;
    uint32_t bytes_remaining = datalen;

    // fast push mode
    conn.block_after_ACK = true;

    while (bytes_remaining > 0) {
        uint32_t bytes_in_packet = MIN(FLASH_MEM_BLOCK_SIZE, bytes_remaining);

        clearCommandBuffer();

        SendCommandOLD(CMD_FLASHMEM_WRITE, offset + bytes_sent, bytes_in_packet, 0, data + bytes_sent, bytes_in_packet);

        bytes_remaining -= bytes_in_packet;
        bytes_sent += bytes_in_packet;

        PacketResponseNG resp;
        if (WaitForResponseTimeout(CMD_ACK, &resp, 2000) == false) {
            PrintAndLogEx(WARNING, "timeout while waiting for reply.");
            conn.block_after_ACK = false;
            free(data);
            return PM3_ETIMEOUT;
        }

        uint8_t isok  = resp.oldarg[0] & 0xFF;
        if (!isok) {
            conn.block_after_ACK = false;
            PrintAndLogEx(FAILED, "Flash write fail [offset %u]", bytes_sent);
            return PM3_EFLASH;
        }
    }

    conn.block_after_ACK = false;
    free(data);
    PrintAndLogEx(SUCCESS, "Wrote "_GREEN_("%zu")" bytes to offset "_GREEN_("%u"), datalen, offset);
    return PM3_SUCCESS;
}

static int CmdFlashMemDump(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "mem dump",
                  "Dumps flash memory on device into a file or view in console",
                  "mem dump -f myfile                           -> download all flashmem to file\n"
                  "mem dump --view -o 262015 --len 128          -> display 128 bytes from offset 262015 (RSA sig)\n"
                  "mem dump --view -f myfile -o 241664 --len 58 -> display 58 bytes from offset 241664 and save to file"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_int0("o", "offset", "<dec>", "offset in memory"),
        arg_int0("l", "len", "<dec>", "length"),
        arg_lit0("v", "view", "view dump"),
        arg_strx0("f", "file", "<filename>", "file name"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int offset = arg_get_int_def(ctx, 1, 0);
    int len = arg_get_int_def(ctx, 2, FLASH_MEM_MAX_SIZE);
    bool view = arg_get_lit(ctx, 3);
    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 4), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);
    CLIParserFree(ctx);

    uint8_t *dump = calloc(len, sizeof(uint8_t));
    if (!dump) {
        PrintAndLogEx(ERR, "error, cannot allocate memory ");
        return PM3_EMALLOC;
    }

    PrintAndLogEx(INFO, "downloading "_YELLOW_("%u")" bytes from flash memory", len);
    if (!GetFromDevice(FLASH_MEM, dump, len, offset, NULL, 0, NULL, -1, true)) {
        PrintAndLogEx(FAILED, "ERROR; downloading from flash memory");
        free(dump);
        return PM3_EFLASH;
    }

    if (view) {
        PrintAndLogEx(INFO, "---- " _CYAN_("data") " ---------------");
        print_hex_break(dump, len, 32);
    }

    if (filename[0] != '\0') {
        saveFile(filename, ".bin", dump, len);
        saveFileEML(filename, dump, len, 16);
    }

    free(dump);
    return PM3_SUCCESS;
}

static int CmdFlashMemWipe(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "mem wipe",
                  "Wipe flash memory on device, which fills it with 0xFF\n"
                  _WHITE_("[ ") _RED_("!!! OBS") " ] use with caution",
                  "mem wipe -p 0 -> wipes first page"
//                  "mem wipe -i -> inital total wipe"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_int0("p", NULL, "<dec>", "0,1,2 page memory"),
//        arg_lit0("i", NULL, "inital total wipe"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool initalwipe = false;
    int page = arg_get_int_def(ctx, 1, -1);
//    initalwipe = arg_get_lit(ctx, 2);
    CLIParserFree(ctx);

    if (page < 0 || page > 2) {
        PrintAndLogEx(WARNING, "page must be 0, 1 or 2");
        return PM3_EINVARG;
    }

    clearCommandBuffer();
    SendCommandMIX(CMD_FLASHMEM_WIPE, page, initalwipe, 0, NULL, 0);
    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_ACK, &resp, 8000)) {
        PrintAndLogEx(WARNING, "timeout while waiting for reply.");
        return PM3_ETIMEOUT;
    }

    const char *msg = "Flash WIPE ";
    uint8_t isok  = resp.oldarg[0] & 0xFF;
    if (isok)
        PrintAndLogEx(SUCCESS, "%s ( " _GREEN_("ok")" )", msg);
    else {
        PrintAndLogEx(FAILED, "%s ( " _RED_("failed") " )", msg);
        return PM3_EFLASH;
    }

    return PM3_SUCCESS;
}

static int CmdFlashMemInfo(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "mem info",
                  "Collect signature and verify it from flash memory",
                  "mem info"
//                  "mem info -s"
                 );

    void *argtable[] = {
        arg_param_begin,
//        arg_lit0("s", NULL, "create a signature"),
//        arg_lit0("w", NULL, "write signature to flash memory"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool shall_sign = false, shall_write = false;
//    shall_sign = arg_get_lit(ctx, 1);
//    shall_write = arg_get_lit(ctx, 2);
    CLIParserFree(ctx);

    clearCommandBuffer();
    SendCommandNG(CMD_FLASHMEM_INFO, NULL, 0);
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_ACK, &resp, 2500) == false) {
        PrintAndLogEx(WARNING, "timeout while waiting for reply");
        return PM3_ETIMEOUT;
    }

    uint8_t isok = resp.oldarg[0] & 0xFF;
    if (isok == false) {
        PrintAndLogEx(FAILED, "failed");
        return PM3_EFLASH;
    }

    // validate signature here
    rdv40_validation_t mem;
    memcpy(&mem, (rdv40_validation_t *)resp.data.asBytes, sizeof(rdv40_validation_t));

    // Flash ID hash (sha1)
    uint8_t sha_hash[20] = {0};
    mbedtls_sha1(mem.flashid, sizeof(mem.flashid), sha_hash);

    // print header
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Flash memory Information") " ---------");
//    PrintAndLogEx(INFO, "-----------------------------------------------------------------");
    PrintAndLogEx(INFO, "ID................... %s", sprint_hex_inrow(mem.flashid, sizeof(mem.flashid)));
    PrintAndLogEx(INFO, "SHA1................. %s", sprint_hex_inrow(sha_hash, sizeof(sha_hash)));
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("RDV4 RSA signature") " ---------------");
    for (int i = 0; i < (sizeof(mem.signature) / 32); i++) {
        PrintAndLogEx(INFO, " %s", sprint_hex_inrow(mem.signature + (i * 32), 32));
    }

//-------------------------------------------------------------------------------
// RRG Public RSA Key
//

// public key Exponent E
#define RSA_E "010001"

// public key modulus N
#define RSA_N "E28D809BF323171D11D1ACA4C32A5B7E0A8974FD171E75AD120D60E9B76968FF" \
              "4B0A6364AE50583F9555B8EE1A725F279E949246DF0EFCE4C02B9F3ACDCC623F" \
              "9337F21C0C066FFB703D8BFCB5067F309E056772096642C2B1A8F50305D5EC33" \
              "DB7FB5A3C8AC42EB635AE3C148C910750ABAA280CE82DC2F180F49F30A1393B5"

//-------------------------------------------------------------------------------
// Example RSA-1024 keypair, for test purposes  (from common/polarssl/rsa.c)
//

// private key  Exponent D
#define RSA_D   "24BF6185468786FDD303083D25E64EFC" \
    "66CA472BC44D253102F8B4A9D3BFA750" \
    "91386C0077937FE33FA3252D28855837" \
    "AE1B484A8A9A45F7EE8C0C634F99E8CD" \
    "DF79C5CE07EE72C7F123142198164234" \
    "CABB724CF78B8173B9F880FC86322407" \
    "AF1FEDFDDE2BEB674CA15F3E81A1521E" \
    "071513A1E85B5DFA031F21ECAE91A34D"

// prime P
#define RSA_P   "C36D0EB7FCD285223CFB5AABA5BDA3D8" \
    "2C01CAD19EA484A87EA4377637E75500" \
    "FCB2005C5C7DD6EC4AC023CDA285D796" \
    "C3D9E75E1EFC42488BB4F1D13AC30A57"

// prime Q
#define RSA_Q   "C000DF51A7C77AE8D7C7370C1FF55B69" \
    "E211C2B9E5DB1ED0BF61D0D9899620F4" \
    "910E4168387E3C30AA1E00C339A79508" \
    "8452DD96A9A5EA5D9DCA68DA636032AF"

#define RSA_DP  "C1ACF567564274FB07A0BBAD5D26E298" \
    "3C94D22288ACD763FD8E5600ED4A702D" \
    "F84198A5F06C2E72236AE490C93F07F8" \
    "3CC559CD27BC2D1CA488811730BB5725"

#define RSA_DQ  "4959CBF6F8FEF750AEE6977C155579C7" \
    "D8AAEA56749EA28623272E4F7D0592AF" \
    "7C1F1313CAC9471B5C523BFE592F517B" \
    "407A1BD76C164B93DA2D32A383E58357"

#define RSA_QP  "9AE7FBC99546432DF71896FC239EADAE" \
    "F38D18D2B2F0E2DD275AA977E2BF4411" \
    "F5A3B2A5D33605AEBBCCBA7FEB9F2D2F" \
    "A74206CEC169D74BF5A8C50D6F48EA08"

#define KEY_LEN 128

    mbedtls_rsa_context rsa;
    mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V15, 0);

    rsa.len = KEY_LEN;

    mbedtls_mpi_read_string(&rsa.N, 16, RSA_N);
    mbedtls_mpi_read_string(&rsa.E, 16, RSA_E);
    mbedtls_mpi_read_string(&rsa.D, 16, RSA_D);
    mbedtls_mpi_read_string(&rsa.P, 16, RSA_P);
    mbedtls_mpi_read_string(&rsa.Q, 16, RSA_Q);
    mbedtls_mpi_read_string(&rsa.DP, 16, RSA_DP);
    mbedtls_mpi_read_string(&rsa.DQ, 16, RSA_DQ);
    mbedtls_mpi_read_string(&rsa.QP, 16, RSA_QP);

    bool is_keyok = (mbedtls_rsa_check_pubkey(&rsa) == 0 || mbedtls_rsa_check_privkey(&rsa) == 0);

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("RDV4 RSA Public key") " --------------");

    char str_exp[10];
    char str_pk[261];
    size_t exlen = 0, pklen = 0;
    mbedtls_mpi_write_string(&rsa.E, 16, str_exp, sizeof(str_exp), &exlen);
    mbedtls_mpi_write_string(&rsa.N, 16, str_pk, sizeof(str_pk), &pklen);

    PrintAndLogEx(INFO, "Len.................. %"PRIu64, rsa.len);
    PrintAndLogEx(INFO, "Exponent............. %s", str_exp);
    PrintAndLogEx(INFO, "Public key modulus N");
    PrintAndLogEx(INFO, " %.64s", str_pk);
    PrintAndLogEx(INFO, " %.64s", str_pk + 64);
    PrintAndLogEx(INFO, " %.64s", str_pk + 128);
    PrintAndLogEx(INFO, " %.64s", str_pk + 192);

    PrintAndLogEx(NORMAL, "");
    const char *msgkey = "RSA key validation... ";
    if (is_keyok)
        PrintAndLogEx(SUCCESS, "%s( " _GREEN_("ok") " )", msgkey);
    else
        PrintAndLogEx(FAILED, "%s( " _RED_("failed") " )", msgkey);

    //
    uint8_t from_device[KEY_LEN];
    uint8_t sign[KEY_LEN];

    // to be verified
    memcpy(from_device, mem.signature, KEY_LEN);

    // to be signed (all zeros
    memset(sign, 0, KEY_LEN);

    // Signing (private key)
    if (shall_sign) {

        int is_signed = mbedtls_rsa_pkcs1_sign(&rsa, NULL, NULL, MBEDTLS_RSA_PRIVATE, MBEDTLS_MD_SHA1, 20, sha_hash, sign);
        const char *msgsign = "RSA signing.......... ";
        if (is_signed == 0)
            PrintAndLogEx(SUCCESS, "%s( " _GREEN_("ok") " )", msgsign);
        else
            PrintAndLogEx(FAILED, "%s( " _RED_("failed") " )", msgsign);

        if (shall_write) {
            // save to mem
            clearCommandBuffer();
            SendCommandOLD(CMD_FLASHMEM_WRITE, FLASH_MEM_SIGNATURE_OFFSET, FLASH_MEM_SIGNATURE_LEN, 0, sign, sizeof(sign));
            if (!WaitForResponseTimeout(CMD_ACK, &resp, 2000)) {
                PrintAndLogEx(WARNING, "timeout while waiting for reply.");
            } else {

                if (!resp.oldarg[0])
                    PrintAndLogEx(FAILED, "Writing signature failed");
                else
                    PrintAndLogEx(SUCCESS, "Writing signature ok [offset: %u]", FLASH_MEM_SIGNATURE_OFFSET);

            }
        }
        PrintAndLogEx(INFO, "Signed");
        for (int i = 0; i < (sizeof(sign) / 32); i++) {
            PrintAndLogEx(INFO, " %s", sprint_hex_inrow(sign + (i * 32), 32));
        }
    }

    // Verify (public key)
    int is_verified = mbedtls_rsa_pkcs1_verify(&rsa, NULL, NULL, MBEDTLS_RSA_PUBLIC, MBEDTLS_MD_SHA1, 20, sha_hash, from_device);
    const char *msgverify = "RSA verification..... ";
    if (is_verified == 0)
        PrintAndLogEx(SUCCESS, "%s( " _GREEN_("ok") " )", msgverify);
    else
        PrintAndLogEx(FAILED, "%s( " _RED_("failed") " )", msgverify);

    PrintAndLogEx(NORMAL, "");
    mbedtls_rsa_free(&rsa);
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",    CmdHelp,            AlwaysAvailable, "This help"},
    {"baudrate", CmdFlashmemSpiBaudrate, IfPm3Flash,  "Set Flash memory Spi baudrate"},
    {"spiffs",  CmdFlashMemSpiFFS,  IfPm3Flash,      "High level SPI FileSystem Flash manipulation"},
    {"info",    CmdFlashMemInfo,    IfPm3Flash,      "Flash memory information"},
    {"load",    CmdFlashMemLoad,    IfPm3Flash,      "Load data into flash memory"},
    {"dump",    CmdFlashMemDump,    IfPm3Flash,      "Dump data from flash memory"},
    {"wipe",    CmdFlashMemWipe,    IfPm3Flash,      "Wipe data from flash memory"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdFlashMem(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}
