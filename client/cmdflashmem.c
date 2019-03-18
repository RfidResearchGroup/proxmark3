//-----------------------------------------------------------------------------
// Copyright (C) 2018 iceman
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Proxmark3 RDV40 Flash memory commands
//-----------------------------------------------------------------------------
#ifdef WITH_FLASH

#include "cmdflashmem.h"

#include "mbedtls/rsa.h"
#include "mbedtls/sha1.h"
#include "mbedtls/base64.h"

#define MCK 48000000
//#define FLASH_BAUD 24000000
#define FLASH_MINFAST 24000000 //33000000
#define FLASH_BAUD MCK/2
#define FLASH_FASTBAUD MCK
#define FLASH_MINBAUD FLASH_FASTBAUD

#define FASTFLASH (FLASHMEM_SPIBAUDRATE > FLASH_MINFAST)

static int CmdHelp(const char *Cmd);

int usage_flashmem_spibaud(void) {
    PrintAndLogEx(NORMAL, "Usage:  mem spibaud [h] <baudrate>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "           h    this help");
    PrintAndLogEx(NORMAL, "      <baudrate>    SPI baudrate in MHz [24|48]");
    PrintAndLogEx(NORMAL, "           ");
    PrintAndLogEx(NORMAL, "           If >= 24Mhz, FASTREADS instead of READS instruction will be used.");
    PrintAndLogEx(NORMAL, "           Reading Flash ID will virtually always fail under 48Mhz setting");
    PrintAndLogEx(NORMAL, "           Unless you know what you are doing, please stay at 24Mhz");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "           mem spibaud 48");
    return 0;
}

int usage_flashmem_read(void) {
    PrintAndLogEx(NORMAL, "Read flash memory on device");
    PrintAndLogEx(NORMAL, "Usage:  mem read o <offset> l <len>");
    PrintAndLogEx(NORMAL, "  o <offset>    :      offset in memory");
    PrintAndLogEx(NORMAL, "  l <len>       :      length");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "        mem read o 0 l 32");    // read 32 bytes starting at offset 0
    PrintAndLogEx(NORMAL, "        mem read o 1024 l 10"); // read 10 bytes starting at offset 1024
    return 0;
}
int usage_flashmem_load(void) {
    PrintAndLogEx(NORMAL, "Loads binary file into flash memory on device");
    PrintAndLogEx(NORMAL, "Usage:  mem load o <offset> f <file name> m t i");
    PrintAndLogEx(NORMAL, "  o <offset>    :      offset in memory");
    PrintAndLogEx(NORMAL, "  f <filename>  :      file name");
    PrintAndLogEx(NORMAL, "  m             :      upload 6 bytes keys (mifare key dictionary)");
    PrintAndLogEx(NORMAL, "  i             :      upload 8 bytes keys (iClass key dictionary)");
    PrintAndLogEx(NORMAL, "  t             :      upload 4 bytes keys (pwd dictionary)");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "        mem load f myfile");         // upload file myfile at default offset 0
    PrintAndLogEx(NORMAL, "        mem load f myfile o 1024");  // upload file myfile at offset 1024
    PrintAndLogEx(NORMAL, "        mem load f default_keys m");
    PrintAndLogEx(NORMAL, "        mem load f default_pwd t");
    PrintAndLogEx(NORMAL, "        mem load f default_iclass_keys i");
    return 0;
}
int usage_flashmem_save(void) {
    PrintAndLogEx(NORMAL, "Saves flash memory on device into the file");
    PrintAndLogEx(NORMAL, " Usage:  mem save o <offset> l <length> f <file name>");
    PrintAndLogEx(NORMAL, "  o <offset>    :      offset in memory");
    PrintAndLogEx(NORMAL, "  l <length>    :      length");
    PrintAndLogEx(NORMAL, "  f <filename>  :      file name");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "        mem save f myfile");                 // download whole flashmem to file myfile
    PrintAndLogEx(NORMAL, "        mem save f myfile l 4096");          // download 4096 bytes from default offset 0 to file myfile
    PrintAndLogEx(NORMAL, "        mem save f myfile o 1024 l 4096");   // downlowd 4096 bytes from offset 1024 to file myfile
    return 0;
}
int usage_flashmem_wipe(void) {

    PrintAndLogEx(WARNING, "[OBS] use with caution.");
    PrintAndLogEx(NORMAL, "Wipe flash memory on device, which fills memory with 0xFF\n");

    PrintAndLogEx(NORMAL, " Usage:  mem wipe p <page>");
    PrintAndLogEx(NORMAL, "  p <page>    :      0,1,2 page memory");
//  PrintAndLogEx(NORMAL, "  i           :      inital total wipe");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "        mem wipe ");     // wipe page 0,1,2
    PrintAndLogEx(NORMAL, "        mem wipe p 0");  // wipes first page.
    return 0;
}
int usage_flashmem_info(void) {
    PrintAndLogEx(NORMAL, "Collect signature and verify it from flash memory\n");
    PrintAndLogEx(NORMAL, " Usage:  mem info [h|s|w]");
    PrintAndLogEx(NORMAL, "  s    :      create a signature");
    PrintAndLogEx(NORMAL, "  w    :      write signature to flash memory");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "        mem info");
    PrintAndLogEx(NORMAL, "        mem info s");
    return 0;
}

int CmdFlashMemRead(const char *Cmd) {

    uint8_t cmdp = 0;
    bool errors = false;
    uint32_t start_index = 0, len  = 0;

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'o':
                start_index = param_get32ex(Cmd, cmdp + 1, 0, 10);
                cmdp += 2;
                break;
            case 'l':
                len = param_get32ex(Cmd, cmdp + 1, 0, 10);
                cmdp += 2;
                break;
            case 'h':
                return usage_flashmem_read();
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }

    //Validations
    if (errors || cmdp == 0) return usage_flashmem_read();

    if (start_index + len > FLASH_MEM_MAX_SIZE) {
        PrintAndLogDevice(WARNING, "error, start_index + length is larger than available memory");
        return 1;
    }

    UsbCommand c = {CMD_FLASHMEM_READ, {start_index, len, 0}};
    clearCommandBuffer();
    SendCommand(&c);
    return 0;
}

int CmdFlashmemSpiBaudrate(const char *Cmd) {

    char ctmp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) < 1 || ctmp == 'h') return usage_flashmem_spibaud();
    uint32_t baudrate = param_get32ex(Cmd, 0, 0, 10);
    baudrate = baudrate * 1000000;
    if (baudrate != FLASH_BAUD && baudrate != FLASH_MINBAUD) return usage_flashmem_spibaud();
    UsbCommand c = {CMD_FLASHMEM_SET_SPIBAUDRATE, {baudrate, 0, 0}};
    SendCommand(&c);
    return 0;
}

int CmdFlashMemLoad(const char *Cmd) {

    uint32_t start_index = 0;
    char filename[FILE_PATH_SIZE] = {0};
    bool errors = false;
    uint8_t cmdp = 0;
    Dictionary_t d = DICTIONARY_NONE;

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_flashmem_load();
            case 'f':
                if (param_getstr(Cmd, cmdp + 1, filename, FILE_PATH_SIZE) >= FILE_PATH_SIZE) {
                    PrintAndLogEx(FAILED, "Filename too long");
                    errors = true;
                    break;
                }
                cmdp += 2;
                break;
            case 'o':
                start_index = param_get32ex(Cmd, cmdp + 1, 0, 10);
                cmdp += 2;
                break;
            case 'm':
                d = DICTIONARY_MIFARE;
                cmdp++;
                break;
            case 't':
                d = DICTIONARY_T55XX;
                cmdp++;
                break;
            case 'i':
                d = DICTIONARY_ICLASS;
                cmdp++;
                break;
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }

    //Validations
    if (errors || cmdp == 0) return usage_flashmem_load();

    size_t datalen = 0;
    uint16_t keycount = 0;
    int res = 0;
    uint8_t *data = calloc(FLASH_MEM_MAX_SIZE, sizeof(uint8_t));

    switch (d) {
        case DICTIONARY_MIFARE:
            start_index = DEFAULT_MF_KEYS_OFFSET;
            res = loadFileDICTIONARY(filename, "dic", data + 2, &datalen, 6, &keycount);
            if (res || !keycount) {
                free(data);
                return 1;
            }
            data[0] = (keycount >> 0) & 0xFF;
            data[1] = (keycount >> 8) & 0xFF;
            datalen += 2;
            break;
        case DICTIONARY_T55XX:
            start_index = DEFAULT_T55XX_KEYS_OFFSET;
            res = loadFileDICTIONARY(filename, "dic", data + 2, &datalen, 4, &keycount);
            if (res || !keycount) {
                free(data);
                return 1;
            }
            data[0] = (keycount >> 0) & 0xFF;
            data[1] = (keycount >> 8) & 0xFF;
            datalen += 2;
            break;
        case DICTIONARY_ICLASS:
            start_index = DEFAULT_ICLASS_KEYS_OFFSET;
            res = loadFileDICTIONARY(filename, "dic", data + 2, &datalen, 8, &keycount);
            if (res || !keycount) {
                free(data);
                return 1;
            }
            data[0] = (keycount >> 0) & 0xFF;
            data[1] = (keycount >> 8) & 0xFF;
            datalen += 2;
            break;
        default:

            res = loadFile(filename, "bin", data, FLASH_MEM_MAX_SIZE, &datalen);
            //int res = loadFileEML( filename, "eml", data, &datalen);
            if (res) {
                free(data);
                return 1;
            }

            if (datalen > FLASH_MEM_MAX_SIZE) {
                PrintAndLogDevice(WARNING, "error, filesize is larger than available memory");
                free(data);
                return 1;
            }
            break;
    }

    data = realloc(data, datalen);
    if (!data) {
        return 1;
    }

    //Send to device
    uint32_t bytes_sent = 0;
    uint32_t bytes_remaining = datalen;

    while (bytes_remaining > 0) {
        uint32_t bytes_in_packet = MIN(FLASH_MEM_BLOCK_SIZE, bytes_remaining);

        UsbCommand c = {CMD_FLASHMEM_WRITE, {start_index + bytes_sent, bytes_in_packet, 0}};

        memcpy(c.d.asBytes, data + bytes_sent, bytes_in_packet);
        clearCommandBuffer();
        SendCommand(&c);

        bytes_remaining -= bytes_in_packet;
        bytes_sent += bytes_in_packet;

        UsbCommand resp;
        if (!WaitForResponseTimeout(CMD_ACK, &resp, 2000)) {
            PrintAndLogEx(WARNING, "timeout while waiting for reply.");
            free(data);
            return 1;
        }

        uint8_t isok  = resp.arg[0] & 0xFF;
        if (!isok)
            PrintAndLogEx(FAILED, "Flash write fail [offset %u]", bytes_sent);

    }
    free(data);

    PrintAndLogEx(SUCCESS, "Wrote %u bytes to offset %u", datalen, start_index);
    return 0;
}
int CmdFlashMemSave(const char *Cmd) {

    char filename[FILE_PATH_SIZE] = {0};
    uint8_t cmdp = 0;
    bool errors = false;
    uint32_t start_index = 0, len = FLASH_MEM_MAX_SIZE;

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_flashmem_save();
            case 'l':
                len = param_get32ex(Cmd, cmdp + 1, FLASH_MEM_MAX_SIZE, 10);
                cmdp += 2;
                break;
            case 'o':
                start_index = param_get32ex(Cmd, cmdp + 1, 0, 10);
                cmdp += 2;
                break;
            case 'f':
                //File handling
                if (param_getstr(Cmd, cmdp + 1, filename, FILE_PATH_SIZE) >= FILE_PATH_SIZE) {
                    PrintAndLogEx(FAILED, "Filename too long");
                    errors = true;
                    break;
                }
                cmdp += 2;
                break;
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }

    //Validations
    if (errors || cmdp == 0) return usage_flashmem_save();

    uint8_t *dump = calloc(len, sizeof(uint8_t));
    if (!dump) {
        PrintAndLogDevice(WARNING, "error, cannot allocate memory ");
        return 1;
    }

    PrintAndLogEx(NORMAL, "downloading %u bytes from flashmem", len);
    if (!GetFromDevice(FLASH_MEM, dump, len, start_index, NULL, -1, true)) {
        PrintAndLogEx(FAILED, "ERROR; downloading flashmem");
        free(dump);
        return 1;
    }

    saveFile(filename, "bin", dump, len);
    saveFileEML(filename, "eml", dump, len, 16);
    free(dump);
    return 0;
}
int CmdFlashMemWipe(const char *Cmd) {

    uint8_t cmdp = 0;
    bool errors = false;
    bool initalwipe = false;
    uint8_t page = 0;
    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_flashmem_wipe();
            case 'p':
                page = param_get8ex(Cmd, cmdp + 1, 0, 10);
                if (page > 2) {
                    PrintAndLogEx(WARNING, "page must be 0, 1 or 2");
                    errors = true;
                    break;
                }
                cmdp += 2;
                break;
            case 'i':
                initalwipe = true;
                cmdp++;
                break;
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }

    //Validations
    if (errors || cmdp == 0) return usage_flashmem_wipe();

    UsbCommand c = {CMD_FLASHMEM_WIPE, {page, initalwipe, 0}};
    clearCommandBuffer();
    SendCommand(&c);
    UsbCommand resp;
    if (!WaitForResponseTimeout(CMD_ACK, &resp, 8000)) {
        PrintAndLogEx(WARNING, "timeout while waiting for reply.");
        return 1;
    }
    uint8_t isok  = resp.arg[0] & 0xFF;
    if (isok)
        PrintAndLogEx(SUCCESS, "Flash WIPE ok");
    else
        PrintAndLogEx(FAILED, "Flash WIPE failed");

    return 0;
}
int CmdFlashMemInfo(const char *Cmd) {

    uint8_t sha_hash[20] = {0};
    mbedtls_rsa_context rsa;

    uint8_t cmdp = 0;
    bool errors = false,  shall_write = false, shall_sign = false;
    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_flashmem_info();
            case 's': {
                shall_sign = true;
                cmdp++;
                break;
            }
            case 'w':
                shall_write = true;
                cmdp++;
                break;
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }

    //Validations
    if (errors) return usage_flashmem_info();

    UsbCommand c = {CMD_FLASHMEM_INFO, {0, 0, 0}};
    clearCommandBuffer();
    SendCommand(&c);
    UsbCommand resp;
    if (!WaitForResponseTimeout(CMD_ACK, &resp, 2500)) {
        PrintAndLogEx(WARNING, "timeout while waiting for reply.");
        return 1;
    }

    uint8_t isok = resp.arg[0] & 0xFF;
    if (!isok) {
        PrintAndLogEx(FAILED, "failed");
        return 1;
    }

    // validate signature here
    rdv40_validation_t mem;
    memcpy(&mem, (rdv40_validation_t *)resp.d.asBytes, sizeof(rdv40_validation_t));

    // Flash ID hash (sha1)
    mbedtls_sha1(mem.flashid, sizeof(mem.flashid), sha_hash);

    // print header
    PrintAndLogEx(INFO, "\n--- Flash memory Information ---------");
    PrintAndLogEx(INFO, "-------------------------------------------------------------");
    PrintAndLogEx(INFO, "ID            | %s", sprint_hex(mem.flashid, sizeof(mem.flashid)));
    PrintAndLogEx(INFO, "SHA1          | %s", sprint_hex(sha_hash, sizeof(sha_hash)));
    PrintAndLogEx(INFO, "RSA SIGNATURE |");
    print_hex_break(mem.signature, sizeof(mem.signature), 32);

//-------------------------------------------------------------------------------
// Example RSA-1024 keypair, for test purposes  (from common/polarssl/rsa.c)
//

// public key modulus N
#define RSA_N   "9292758453063D803DD603D5E777D788" \
    "8ED1D5BF35786190FA2F23EBC0848AEA" \
    "DDA92CA6C3D80B32C4D109BE0F36D6AE" \
    "7130B9CED7ACDF54CFC7555AC14EEBAB" \
    "93A89813FBF3C4F8066D2D800F7C38A8" \
    "1AE31942917403FF4946B0A83D3D3E05" \
    "EE57C6F5F5606FB5D4BC6CD34EE0801A" \
    "5E94BB77B07507233A0BC7BAC8F90F79"

// public key Exponent E
#define RSA_E   "10001"

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

    PrintAndLogEx(INFO, "KEY length   | %d", KEY_LEN);

    bool is_keyok = (mbedtls_rsa_check_pubkey(&rsa) == 0 || mbedtls_rsa_check_privkey(&rsa) == 0);
    if (is_keyok)
        PrintAndLogEx(SUCCESS, "RSA key validation ok");
    else
        PrintAndLogEx(FAILED, "RSA key validation failed");

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
        if (is_signed == 0)
            PrintAndLogEx(SUCCESS, "RSA Signing ok");
        else
            PrintAndLogEx(FAILED, "RSA Signing failed");

        if (shall_write) {
            // save to mem
            c = (UsbCommand) {CMD_FLASHMEM_WRITE, {FLASH_MEM_SIGNATURE_OFFSET, FLASH_MEM_SIGNATURE_LEN, 0}};
            memcpy(c.d.asBytes, sign, sizeof(sign));
            clearCommandBuffer();
            SendCommand(&c);
            if (!WaitForResponseTimeout(CMD_ACK, &resp, 2000)) {
                PrintAndLogEx(WARNING, "timeout while waiting for reply.");
            } else {

                if (!resp.arg[0])
                    PrintAndLogEx(FAILED, "Writing signature failed");
                else
                    PrintAndLogEx(SUCCESS, "Writing signature ok [offset: %u]", FLASH_MEM_SIGNATURE_OFFSET);

            }
        }
        PrintAndLogEx(INFO, "Signed   | ");
        print_hex_break(sign, sizeof(sign), 32);
    }

    // Verify (public key)
    int is_verified = mbedtls_rsa_pkcs1_verify(&rsa, NULL, NULL, MBEDTLS_RSA_PUBLIC, MBEDTLS_MD_SHA1, 20, sha_hash, from_device);
    if (is_verified == 0)
        PrintAndLogEx(SUCCESS, "RSA Verification ok");
    else
        PrintAndLogEx(FAILED, "RSA Verification failed");

    mbedtls_rsa_free(&rsa);
    return 0;
}

static command_t CommandTable[] = {
    {"help",    CmdHelp,            1, "This help"},
    {"spibaud", CmdFlashmemSpiBaudrate, 1, "Set Flash memory Spi baudrate [rdv40]"},
    {"read",    CmdFlashMemRead,    1, "Read Flash memory [rdv40]"},
    {"info",    CmdFlashMemInfo,    1, "Flash memory information [rdv40]"},
    {"load",    CmdFlashMemLoad,    1, "Load data into flash memory [rdv40]"},
    {"save",    CmdFlashMemSave,    1, "Save data from flash memory [rdv40]"},
    {"wipe",    CmdFlashMemWipe,    1, "Wipe data from flash memory [rdv40]"},
    {NULL, NULL, 0, NULL}
};

int CmdFlashMem(const char *Cmd) {
    clearCommandBuffer();
    CmdsParse(CommandTable, Cmd);
    return 0;
}

int CmdHelp(const char *Cmd) {
    CmdsHelp(CommandTable);
    return 0;
}

#endif
