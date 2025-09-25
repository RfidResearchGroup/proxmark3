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
// Proxmark3 RDV40 Flash memory commands
//-----------------------------------------------------------------------------
#include "cmdflashmem.h"
#include <ctype.h>
#include <string.h>
#include "cmdparser.h"         // command_t
#include "cliparser.h"
#include "pmflash.h"           // rdv40validation_t
#include "fileutils.h"         // saveFile
#include "comms.h"             // getfromdevice
#include "cmdflashmemspiffs.h" // spiffs commands
#include "rsa.h"
#include "sha1.h"
#include "pk.h"                // PEM key load functions
#include "commonutil.h"

#define MCK 48000000
#define FLASH_MINFAST 24000000 //33000000
#define FLASH_BAUD MCK/2
#define FLASH_FASTBAUD MCK
#define FLASH_MINBAUD FLASH_FASTBAUD

static int CmdHelp(const char *Cmd);

//-------------------------------------------------------------------------------------
#define PM3_RSA_KEY_LEN     ( 128 )
#define PM3_RSA_SHA1_LEN    ( 20 )

typedef struct {
    const char *desc;
    const char *E;  // public key Exponent E
    const char *N;  // public key modulus N
} rsa_keypairs_t;

static const rsa_keypairs_t rsa_keypairs[] = {
// RRG Public RSA Key
    {
        "RDV4", "010001", "E28D809BF323171D11D1ACA4C32A5B7E0A8974FD171E75AD120D60E9B76968FF" \
        "4B0A6364AE50583F9555B8EE1A725F279E949246DF0EFCE4C02B9F3ACDCC623F" \
        "9337F21C0C066FFB703D8BFCB5067F309E056772096642C2B1A8F50305D5EC33" \
        "DB7FB5A3C8AC42EB635AE3C148C910750ABAA280CE82DC2F180F49F30A1393B5"
    },

    // GENERIC Public RSA Key for modded devices. They can now be self signed
    {
        "GENERIC", "010001", "FAECE60ADC10934D8284E52A06121DF018786A94572CBB0F318DCE942BC8B04D" \
        "DDE5488F6FB6A1007F05F5B8C06A5F837E6CFD1D2884264E8C9F35A0B2B5805C" \
        "7E9AF14C9B350FF4CCCD0F132CFF74EE9A2490A844123D0622F014162D76DDEF" \
        "7A5F24FEA9E34FA608AEB58B7C10B4BFC7F39C4BFC6E463503A0DDBB9B773E01"
    },
};

//-------------------------------------------------------------------------------------

int pm3_get_flash_pages64k(uint8_t *pages64k) {
    if (pages64k == NULL) {
        return PM3_EINVARG;
    }

    clearCommandBuffer();
    SendCommandNG(CMD_FLASHMEM_PAGES64K, NULL, 0);
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_FLASHMEM_PAGES64K, &resp, 2500) == false) {
        PrintAndLogEx(WARNING, "pm3_get_flash_pages64k() timeout while waiting for reply");
        return PM3_ETIMEOUT;
    }

    if (resp.status != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "fail reading from flash (pages 64k)");
        return PM3_EFLASH;
    }

    *pages64k = resp.data.asBytes[0];
    return PM3_SUCCESS;
}

int pm3_get_signature(rdv40_validation_t *out) {
    if (out == NULL) {
        return PM3_EINVARG;
    }

    clearCommandBuffer();
    SendCommandNG(CMD_FLASHMEM_GET_SIGNATURE, NULL, 0);
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_FLASHMEM_GET_SIGNATURE, &resp, 2500) == false) {
        PrintAndLogEx(WARNING, "timeout while waiting for reply");
        return PM3_ETIMEOUT;
    }

    if (resp.status != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "fail reading from flashmemory");
        return PM3_EFLASH;
    }

    memcpy(out, (rdv40_validation_t *)resp.data.asBytes, sizeof(rdv40_validation_t));
    return PM3_SUCCESS;
}

// validate signature
int pm3_validate(rdv40_validation_t *mem, signature_e *type) {

    // Flash ID hash (sha1)
    uint8_t sha_hash[PM3_RSA_SHA1_LEN] = {0};
    mbedtls_sha1(mem->flashid, sizeof(mem->flashid), sha_hash);

    *type = SIGN_UNK;
    int is_valid = 0;

    for (uint8_t i = 0; i < ARRAYLEN(rsa_keypairs); i++) {

        // set up RSA
        mbedtls_rsa_context rsa;
        mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V15, 0);
        rsa.len = PM3_RSA_KEY_LEN;
        mbedtls_mpi_read_string(&rsa.N, 16, rsa_keypairs[i].N);
        mbedtls_mpi_read_string(&rsa.E, 16, rsa_keypairs[i].E);

        // Verify (public key)
        is_valid = mbedtls_rsa_pkcs1_verify(&rsa, NULL, NULL, MBEDTLS_RSA_PUBLIC, MBEDTLS_MD_SHA1, PM3_RSA_SHA1_LEN, sha_hash, mem->signature);
        mbedtls_rsa_free(&rsa);

        if (is_valid == 0) {
            *type = i;
            return PM3_SUCCESS;
        }
    }

    return PM3_EFAILED;
}

static int pm3_get_flash_info(spi_flash_t *info) {
    if (info == NULL) {
        return PM3_EINVARG;
    }

    clearCommandBuffer();
    SendCommandNG(CMD_FLASHMEM_GET_INFO, NULL, 0);
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_FLASHMEM_GET_INFO, &resp, 2500) == false) {
        PrintAndLogEx(WARNING, "pm3_get_flash_info() timeout while waiting for reply");
        return PM3_ETIMEOUT;
    }

    if (resp.status != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "fail reading flash info");
        return PM3_EFLASH;
    }

    memcpy(info, resp.data.asBytes, sizeof(spi_flash_t));
    return PM3_SUCCESS;
}

static int pm3_sign_write(uint8_t *signature, uint8_t slen) {

    uint8_t spi_flash_pages = 0;
    int res = pm3_get_flash_pages64k(&spi_flash_pages);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "failed to get flash pages (%x)", res);
        return res;
    }

    flashmem_old_write_t payload = {
        .startidx = FLASH_MEM_SIGNATURE_OFFSET_P(spi_flash_pages),
        .len = FLASH_MEM_SIGNATURE_LEN,
    };
    memcpy(payload.data, signature, slen);

    clearCommandBuffer();
    PacketResponseNG resp;
    SendCommandNG(CMD_FLASHMEM_WRITE, (uint8_t *)&payload, sizeof(payload));

    if (WaitForResponseTimeout(CMD_FLASHMEM_WRITE, &resp, 2000) == false) {
        PrintAndLogEx(WARNING, "timeout while waiting for reply");
        return PM3_EFAILED;
    } else {
        if (resp.status != PM3_SUCCESS) {
            PrintAndLogEx(FAILED, "Writing signature ( "_RED_("fail") ")");
            return PM3_EFAILED;
        }
    }
    PrintAndLogEx(SUCCESS, "Wrote signature at offset " _YELLOW_("%u") " ( "_GREEN_("ok") " )", FLASH_MEM_SIGNATURE_OFFSET_P(spi_flash_pages));
    return PM3_SUCCESS;
}

static void pm3_print_flash_memory_info(spi_flash_t *spi, rdv40_validation_t *mem, uint8_t *sha_hash, signature_e *type) {

    // print header
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Flash memory Information"));
    PrintAndLogEx(INFO, "ID...................... %s", sprint_hex_inrow(mem->flashid, sizeof(mem->flashid)));
    PrintAndLogEx(INFO, "SHA1.................... %s", sprint_hex_inrow(sha_hash, PM3_RSA_SHA1_LEN));

    if (spi->device_id) {
        PrintAndLogEx(INFO, "Mfr ID / Dev ID......... " _YELLOW_("%02X") " / " _YELLOW_("%02X"), spi->manufacturer_id, spi->device_id);
    }

    if (spi->jedec_id) {
        PrintAndLogEx(INFO, "JEDEC Mfr ID / Dev ID... " _YELLOW_("%02X") " / "_YELLOW_("%04X"), spi->manufacturer_id, spi->jedec_id);
    }

    PrintAndLogEx(INFO, "Memory size............. " _YELLOW_("%d Kb") " ( %d * 64 Kb )", spi->pages64k * 64, spi->pages64k);
    PrintAndLogEx(NORMAL, "");

    // Print Signature Header
    switch (*type) {
        case SIGN_RDV4:
        case SIGN_GENERIC:
            PrintAndLogEx(INFO, "--- " _CYAN_("PM3 %s RSA signature"), rsa_keypairs[*type].desc);
            break;
        case SIGN_UNK:
        default:
            PrintAndLogEx(INFO, "--- " _CYAN_("Unknown RSA signature"));
            break;
    }

    // Print the Signature Data
    for (int i = 0; i < (sizeof(mem->signature) / 32); i++) {
        PrintAndLogEx(INFO, " %s", sprint_hex_inrow(mem->signature + (i * 32), 32));
    }
}

static void pm3_print_public_keys(void) {

    mbedtls_rsa_context rsa;
    mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V15, 0);
    rsa.len = PM3_RSA_KEY_LEN;

    for (uint8_t i = 0; i < ARRAYLEN(rsa_keypairs); i++) {

        mbedtls_mpi_read_string(&rsa.N, 16, rsa_keypairs[i].N);
        mbedtls_mpi_read_string(&rsa.E, 16, rsa_keypairs[i].E);

        PrintAndLogEx(INFO, "--- " _CYAN_("%s RSA Public key"), rsa_keypairs[i].desc);
        char str_exp[10];
        char str_pk[261];
        size_t exlen = 0, pklen = 0;
        mbedtls_mpi_write_string(&rsa.E, 16, str_exp, sizeof(str_exp), &exlen);
        mbedtls_mpi_write_string(&rsa.N, 16, str_pk, sizeof(str_pk), &pklen);

        PrintAndLogEx(INFO, "Len........ %"PRIu64, rsa.len);
        PrintAndLogEx(INFO, "Exponent... %s", str_exp);
        PrintAndLogEx(INFO, "Public key modulus N");
        PrintAndLogEx(INFO, " %.64s", str_pk);
        PrintAndLogEx(INFO, " %.64s", str_pk + 64);
        PrintAndLogEx(INFO, " %.64s", str_pk + 128);
        PrintAndLogEx(INFO, " %.64s", str_pk + 192);

        bool is_keyok = (mbedtls_rsa_check_pubkey(&rsa) == 0);
        PrintAndLogEx(
            (is_keyok) ? SUCCESS : FAILED,
            "RSA public key check.... ( %s )",
            (is_keyok) ?  _GREEN_("ok") : _RED_("fail")
        );
        PrintAndLogEx(NORMAL, "");
    }
}


static int CmdFlashmemSpiBaud(const char *Cmd) {

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
                  "Warning! - mem area to be written must have been wiped first\n\n"
                  "OBS! - dictionaries are serviced as files in spiffs so no wipe is needed",
                  "mem load -f myfile                    -> upload file myfile values at default offset 0\n"
                  "mem load -f myfile -o 1024            -> upload file myfile values at offset 1024\n"
                  "mem load -f mfc_default_keys -m       -> upload MIFARE Classic keys\n"
                  "mem load -f t55xx_default_pwds -t     -> upload T55XX passwords\n"
                  "mem load -f iclass_default_keys -i    -> upload iCLASS keys\n"
                  "mem load -f mfulc_default_keys --ulc  -> upload MIFARE UL-C keys\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_int0("o", "offset", "<dec>", "offset in memory"),
        arg_lit0("m", "mfc", "upload 6 bytes keys (MIFARE Classic dictionary)"),
        arg_lit0("i", "iclass", "upload 8 bytes keys (iClass dictionary)"),
        arg_lit0("t", "t55xx", "upload 4 bytes keys (T55xx dictionary)"),
        arg_lit0(NULL, "ulc", "upload 16 bytes keys (MIFARE UL-C dictionary)"),
        arg_lit0(NULL, "aes", "upload 16 bytes keys (MIFARE UL-AES dictionary)"),
        arg_str1("f", "file", "<fn>", "file name"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int offset = arg_get_int_def(ctx, 1, 0);
    bool is_mfc = arg_get_lit(ctx, 2);
    bool is_iclass = arg_get_lit(ctx, 3);
    bool is_t55xx = arg_get_lit(ctx, 4);
    bool is_ulc = arg_get_lit(ctx, 5);
    bool is_ulaes = arg_get_lit(ctx, 6);
    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 7), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);
    CLIParserFree(ctx);

    Dictionary_t d = DICTIONARY_NONE;
    if (is_mfc) {
        d = DICTIONARY_MIFARE;
        PrintAndLogEx(INFO, "Treating file as MIFARE Classic keys");
    } else if (is_iclass) {
        d = DICTIONARY_ICLASS;
        PrintAndLogEx(INFO, "Treating file as iCLASS keys");
    } else if (is_t55xx) {
        d = DICTIONARY_T55XX;
        PrintAndLogEx(INFO, "Treating file as T55xx passwords");
    } else if (is_ulc) {
        d = DICTIONARY_MIFARE_ULC;
        PrintAndLogEx(INFO, "Treating file as MIFARE Ultralight-C keys");
    } else if (is_ulaes) {
        d = DICTIONARY_MIFARE_ULAES;
        PrintAndLogEx(INFO, "Treating file as MIFARE Ultralight AES keys");
    }

    uint8_t spi_flash_pages = 0;
    int res = pm3_get_flash_pages64k(&spi_flash_pages);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Failed to get flash pages count (%x)", res);
        return res;
    }

    size_t datalen = 0;
    uint32_t keycount = 0;
    uint8_t keylen = 0;
    uint8_t *data = calloc(FLASH_MEM_MAX_SIZE_P(spi_flash_pages), sizeof(uint8_t));

    char spiffsDest[32] = {0};

    switch (d) {
        case DICTIONARY_MIFARE: {
            keylen = MF_KEY_LENGTH;
            res = loadFileDICTIONARY(filename, data, &datalen, keylen, &keycount);
            if (res || !keycount) {
                free(data);
                return PM3_EFILE;
            }
            if (datalen > FLASH_MEM_MAX_SIZE_P(spi_flash_pages)) {
                PrintAndLogEx(ERR, "error, filesize is larger than available memory");
                free(data);
                return PM3_EOVFLOW;
            }
            strcpy(spiffsDest, MF_KEYS_FILE);
            break;
        }
        case DICTIONARY_T55XX: {
            keylen = T55XX_KEY_LENGTH;
            res = loadFileDICTIONARY(filename, data, &datalen, keylen, &keycount);
            if (res || !keycount) {
                free(data);
                return PM3_EFILE;
            }
            if (datalen > FLASH_MEM_MAX_SIZE_P(spi_flash_pages)) {
                PrintAndLogEx(ERR, "error, filesize is larger than available memory");
                free(data);
                return PM3_EOVFLOW;
            }
            strcpy(spiffsDest, T55XX_KEYS_FILE);
            break;
        }
        case DICTIONARY_ICLASS: {
            keylen = ICLASS_KEY_LENGTH;
            res = loadFileDICTIONARY(filename, data, &datalen, keylen, &keycount);
            if (res || !keycount) {
                free(data);
                return PM3_EFILE;
            }
            if (datalen > FLASH_MEM_MAX_SIZE_P(spi_flash_pages)) {
                PrintAndLogEx(ERR, "error, filesize is larger than available memory");
                free(data);
                return PM3_EOVFLOW;
            }
            strcpy(spiffsDest, ICLASS_KEYS_FILE);
            break;
        }
        case DICTIONARY_MIFARE_ULC: {
            keylen = MFULC_KEY_LENGTH;
            res = loadFileDICTIONARY(filename, data, &datalen, keylen, &keycount);
            if (res || !keycount) {
                free(data);
                return PM3_EFILE;
            }
            if (datalen > FLASH_MEM_MAX_SIZE_P(spi_flash_pages)) {
                PrintAndLogEx(ERR, "error, filesize is larger than available memory");
                free(data);
                return PM3_EOVFLOW;
            }
            strcpy(spiffsDest, MFULC_KEYS_FILE);
            break;
        }
        case DICTIONARY_MIFARE_ULAES: {
            keylen = MFULAES_KEY_LENGTH;
            res = loadFileDICTIONARY(filename, data, &datalen, keylen, &keycount);
            if (res || !keycount) {
                free(data);
                return PM3_EFILE;
            }
            if (datalen > FLASH_MEM_MAX_SIZE_P(spi_flash_pages)) {
                PrintAndLogEx(ERR, "error, filesize is larger than available memory");
                free(data);
                return PM3_EOVFLOW;
            }
            strcpy(spiffsDest, MFULAES_KEYS_FILE);
            break;
        }
        case DICTIONARY_NONE: {
            res = loadFile_safe(filename, ".bin", (void **)&data, &datalen);
            if (res != PM3_SUCCESS) {
                free(data);
                return PM3_EFILE;
            }

            if (datalen > FLASH_MEM_MAX_SIZE_P(spi_flash_pages)) {
                PrintAndLogEx(ERR, "error, filesize is larger than available memory");
                free(data);
                return PM3_EOVFLOW;
            }
            break;
        }
    }

    // ICEMAN: not needed when we transite to loadxxxx_safe methods
    uint8_t *newdata = realloc(data, datalen);
    if (newdata == NULL) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        free(data);
        return PM3_EMALLOC;
    } else {
        data = newdata;
    }

    //Send to device
    uint32_t bytes_sent = 0;
    uint32_t bytes_remaining = datalen;

    // we will treat dictionary files as spiffs files, so we need to handle this here
    if (d != DICTIONARY_NONE) {
        res = flashmem_spiffs_load(spiffsDest, data, datalen);
        if (res != PM3_SUCCESS) {
            PrintAndLogEx(FAILED, "Failed writing passwrods to file %s", spiffsDest);
            free(data);
            return res;
        }

        if (d == DICTIONARY_T55XX) {
            PrintAndLogEx(SUCCESS, "Wrote "_GREEN_("%u")" passwords to file "_GREEN_("%s"), keycount, spiffsDest);
        } else {
            PrintAndLogEx(SUCCESS, "Wrote "_GREEN_("%u")" keys to file "_GREEN_("%s"), keycount, spiffsDest);
        }
        SendCommandNG(CMD_SPIFFS_UNMOUNT, NULL, 0);
        SendCommandNG(CMD_SPIFFS_MOUNT, NULL, 0);
    } else {
        // fast push mode
        g_conn.block_after_ACK = true;

        while (bytes_remaining > 0) {
            uint32_t bytes_in_packet = MIN(FLASH_MEM_BLOCK_SIZE, bytes_remaining);

            clearCommandBuffer();

            flashmem_old_write_t payload = {
                .startidx = offset + bytes_sent,
                .len = bytes_in_packet,
            };
            memcpy(payload.data,  data + bytes_sent, bytes_in_packet);
            SendCommandNG(CMD_FLASHMEM_WRITE, (uint8_t *)&payload, sizeof(payload));

            bytes_remaining -= bytes_in_packet;
            bytes_sent += bytes_in_packet;

            PacketResponseNG resp;
            if (WaitForResponseTimeout(CMD_FLASHMEM_WRITE, &resp, 2000) == false) {
                PrintAndLogEx(WARNING, "timeout while waiting for reply");
                g_conn.block_after_ACK = false;
                free(data);
                return PM3_ETIMEOUT;
            }

            if (resp.status != PM3_SUCCESS) {
                g_conn.block_after_ACK = false;
                PrintAndLogEx(FAILED, "Flash write fail [offset %u]", bytes_sent);
                free(data);
                return PM3_EFLASH;
            }
        }

        g_conn.block_after_ACK = false;
        PrintAndLogEx(SUCCESS, "Wrote "_GREEN_("%zu")" bytes to offset "_GREEN_("%u"), datalen, offset);
    }

    free(data);
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
        arg_str0("f", "file", "<fn>", "save filename"),
        arg_int0("c", "cols", "<dec>", "column breaks (def 32)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    uint8_t spi_flash_pages = 0;
    int res = pm3_get_flash_pages64k(&spi_flash_pages);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "failed to get flash pages count (%x)", res);
        return res;
    }

    int offset = arg_get_int_def(ctx, 1, 0);
    int len = arg_get_int_def(ctx, 2, FLASH_MEM_MAX_SIZE_P(spi_flash_pages));
    bool view = arg_get_lit(ctx, 3);
    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 4), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);
    int breaks = arg_get_int_def(ctx, 5, 32);
    CLIParserFree(ctx);

    uint8_t *dump = calloc(len, sizeof(uint8_t));
    if (dump == NULL) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        return PM3_EMALLOC;
    }

    PrintAndLogEx(INFO, "downloading "_YELLOW_("%u")" bytes from flash memory", len);
    if (GetFromDevice(FLASH_MEM, dump, len, offset, NULL, 0, NULL, -1, true) == false) {
        PrintAndLogEx(FAILED, "ERROR; downloading from flash memory");
        free(dump);
        return PM3_EFLASH;
    }

    if (view) {
        PrintAndLogEx(INFO, "---- " _CYAN_("data") " ---------------");
        print_hex_break(dump, len, breaks);
    }

    if (filename[0] != '\0') {
        pm3_save_dump(filename, dump, len, jsfRaw);
    }

    free(dump);
    return PM3_SUCCESS;
}

static int CmdFlashMemWipe(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "mem wipe",
                  "Wipe flash memory on device, which fills it with 0xFF\n"
                  _WHITE_("[ ") _RED_("!!! OBS") _WHITE_(" ] use with caution"),
                  "mem wipe -p 0   -> wipes first page"
//                  "mem wipe -i   -> initial total wipe"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_int0("p", NULL, "<dec>", "page memory"),
//        arg_lit0("i", NULL, "initial total wipe"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool initialwipe = false;
    int page = arg_get_int_def(ctx, 1, -1);
//    initialwipe = arg_get_lit(ctx, 2);
    CLIParserFree(ctx);

    uint8_t spi_flash_pages = 0;
    int res = pm3_get_flash_pages64k(&spi_flash_pages);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "failed to get flash pages count (%x)", res);
        return res;
    }

    if (page < 0 || page > (spi_flash_pages - 2)) {
        PrintAndLogEx(WARNING, "page must be between 0 and %d", spi_flash_pages - 2);
        return PM3_EINVARG;
    }

    clearCommandBuffer();
    SendCommandMIX(CMD_FLASHMEM_WIPE, page, initialwipe, 0, NULL, 0);
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_FLASHMEM_WIPE, &resp, 10000) == false) {
        PrintAndLogEx(WARNING, "timeout while waiting for reply");
        return PM3_ETIMEOUT;
    }

    const char *msg = "Flash WIPE ";
    if (resp.status == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "%s ( " _GREEN_("ok")" )", msg);
    } else {
        PrintAndLogEx(FAILED, "%s ( " _RED_("failed") " )", msg);
    }

    return resp.status;
}

static int CmdFlashMemInfo(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "mem info",
                  "Collect signature and verify it from flash memory",
                  "mem info\n"
                  "mem info -v   --> print public keys\n"
                  "mem info -s -p pm3_generic_private_key.pem     --> generate a RSA 1024 signature for your SPI ID\n"
                  "mem info -s -p pm3_generic_private_key.pem -w  --> generate and write a RSA 1024 signature for your SPI ID"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("s", "sign", "create a signature"),
        arg_str0("d", NULL, "<hex>", "flash memory id, 8 hex bytes"),
        arg_str0("p", "pem",  "<fn>", "key in PEM format"),
        arg_lit0("v", "verbose", "verbose output"),
        arg_lit0("w", "write", "write signature to flash memory"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool shall_sign = arg_get_lit(ctx, 1);

    int dlen = 0;
    uint8_t id[8] = {0};
    int res = CLIParamHexToBuf(arg_get_str(ctx, 2), id, sizeof(id), &dlen);

    int pemlen = 0;
    char pem_fn[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 3), (uint8_t *)pem_fn, FILE_PATH_SIZE, &pemlen);

    bool verbose = arg_get_lit(ctx, 4);
    bool shall_write = arg_get_lit(ctx, 5);
    CLIParserFree(ctx);

    if (res) {
        return PM3_EINVARG;
    }

    if (dlen > 0 && dlen < sizeof(id)) {
        PrintAndLogEx(FAILED, "Error parsing flash memory id, expect 8, got " _RED_("%d"), dlen);
        return PM3_EINVARG;
    }

    // set up PK key context now.
    mbedtls_pk_context pkctx;
    mbedtls_pk_init(&pkctx);

    bool got_private = false;

    // PEM
    if (pemlen) {

        // PEM file
        char *path = NULL;
        if (searchFile(&path, RESOURCES_SUBDIR, pem_fn, ".pem", true) != PM3_SUCCESS) {
            if (searchFile(&path, RESOURCES_SUBDIR, pem_fn, "", false) != PM3_SUCCESS) {
                return PM3_EFILE;
            }
        }

        PrintAndLogEx(INFO, "loading file `" _YELLOW_("%s") "`" NOLF, path);

        // load private
        res = mbedtls_pk_parse_keyfile(&pkctx, path, NULL);
        free(path);

        //res = mbedtls_pk_parse_public_keyfile(&pkctx, path);
        if (res == 0) {
            PrintAndLogEx(NORMAL, " ( " _GREEN_("ok") " )");
        } else {
            PrintAndLogEx(NORMAL, " ( " _RED_("fail") " )");
            mbedtls_pk_free(&pkctx);
            return PM3_EFILE;
        }

        mbedtls_rsa_context *rsa = (mbedtls_rsa_context *)pkctx.pk_ctx;
        if (rsa == NULL) {
            PrintAndLogEx(WARNING, "Failed to allocate memory");
            return PM3_EMALLOC;
        }

        got_private = true;

    } else {

        // it not loaded,  we need to setup the context manually
        if (mbedtls_pk_setup(&pkctx,  mbedtls_pk_info_from_type((mbedtls_pk_type_t) MBEDTLS_PK_RSA)) != 0) {
            PrintAndLogEx(FAILED, "failed, mbedtls_pk_setup returned ");
            return PM3_ESOFT;
        }
    }

    // download signature data from device
    rdv40_validation_t mem = {0};
    res = pm3_get_signature(&mem);
    if (res != PM3_SUCCESS) {
        return res;
    }

    // download SPI chip information
    spi_flash_t spi = {0};
    res = pm3_get_flash_info(&spi);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, "Failed to get flash information. Are you sure your device have a external flash?");
        return res;
    }

    // try to verify the found device signature
    signature_e type;
    res = pm3_validate(&mem, &type);

    // Calculate Flash ID hash ( SHA1 )
    uint8_t sha_hash[PM3_RSA_SHA1_LEN] = {0};
    mbedtls_sha1(mem.flashid, sizeof(mem.flashid), sha_hash);

    pm3_print_flash_memory_info(&spi, &mem, sha_hash, &type);

    PrintAndLogEx(
        (res == PM3_SUCCESS) ? SUCCESS : FAILED,
        "Signature............... ( %s )",
        (res == PM3_SUCCESS) ?  _GREEN_("ok") : _RED_("fail")
    );
    PrintAndLogEx(NORMAL, "");

    // Print the hardcoded RSA public keys
    if (verbose) {
        pm3_print_public_keys();
    }

    if (type != SIGN_UNK) {
        PrintAndLogEx(SUCCESS, "Genuine Proxmark3 " _CYAN_("%s") " signature detected :white_check_mark:", rsa_keypairs[type].desc);
    } else {
        PrintAndLogEx(FAILED, "No genuine Proxmark3 signature detected :x:");
    }

    // end here if we not going to create a signature
    if (shall_sign == false) {
        PrintAndLogEx(NORMAL, "");
        return PM3_SUCCESS;
    }

    // enter the Signing process
    mbedtls_rsa_context *rsa = NULL;

    // called with private key .pem file
    if (got_private) {

        rsa = mbedtls_pk_rsa(pkctx);
        rsa->padding = MBEDTLS_RSA_PKCS_V15;
        rsa->hash_id = 0;
        rsa->len = PM3_RSA_KEY_LEN;

        bool is_keyok = (mbedtls_rsa_check_privkey(rsa) == 0);
        if (verbose) {
            PrintAndLogEx(
                (is_keyok) ? SUCCESS : FAILED,
                "RSA private key check... ( %s )",
                (is_keyok) ? _GREEN_("ok") : _YELLOW_("n/a")
            );
        }

        if (is_keyok == false) {
            PrintAndLogEx(FAILED, "No private key available to sign");
            return PM3_ECRYPTO;
        }

        // to be signed
        uint8_t sign[PM3_RSA_KEY_LEN] = {0};

        // Signing (private key)
        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(INFO, "--- " _CYAN_("Enter signing"));

        // use ID from CLI,  otherwise we use FLash ID from device
        if (dlen == 8) {
            mbedtls_sha1(id, sizeof(id), sha_hash);
            PrintAndLogEx(INFO, "Using ID......... %s", sprint_hex_inrow(id, dlen));
        } else {
            PrintAndLogEx(INFO, "Using ID......... %s", sprint_hex_inrow(mem.flashid, sizeof(mem.flashid)));
        }

        PrintAndLogEx(INFO, "Signing.......... %s", sprint_hex_inrow(sha_hash, sizeof(sha_hash)));

        int is_signed = mbedtls_rsa_pkcs1_sign(rsa, NULL, NULL, MBEDTLS_RSA_PRIVATE, MBEDTLS_MD_SHA1, PM3_RSA_SHA1_LEN, sha_hash, sign);
        PrintAndLogEx(
            (is_signed == 0) ? SUCCESS : FAILED,
            "RSA signing...... ( %s )",
            (is_signed == 0) ?  _GREEN_("ok") : _RED_("fail")
        );

        PrintAndLogEx(INFO, "--- " _CYAN_("New signature"));
        for (int i = 0; i < (sizeof(sign) / 32); i++) {
            PrintAndLogEx(INFO, " %s", sprint_hex_inrow(sign + (i * 32), 32));
        }

        if (shall_write) {
            pm3_sign_write(sign, PM3_RSA_KEY_LEN);
        }

        mbedtls_rsa_free(rsa);
        mbedtls_pk_free(&pkctx);
    }

    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"spiffs",   CmdFlashMemSpiFFS,  IfPm3Flash,  "{ SPI File system }"},
    {"help",     CmdHelp,            AlwaysAvailable, "This help"},
    {"-----------", CmdHelp,            IfPm3Flash,      "------------------- " _CYAN_("Operations") " -------------------"},
    {"baudrate", CmdFlashmemSpiBaud, IfPm3Flash,  "Set Flash memory Spi baudrate"},
    {"dump",     CmdFlashMemDump,    IfPm3Flash,  "Dump data from flash memory"},
    {"info",     CmdFlashMemInfo,    IfPm3Flash,  "Flash memory information"},
    {"load",     CmdFlashMemLoad,    IfPm3Flash,  "Load data to flash memory"},
    {"wipe",     CmdFlashMemWipe,    IfPm3Flash,  "Wipe data from flash memory"},
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
