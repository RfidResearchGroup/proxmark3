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

#include "mbedtls/rsa.h"
#include "mbedtls/sha1.h"
#include "mbedtls/base64.h"

#define MCK 48000000
#define FLASH_MINFAST 24000000 //33000000
#define FLASH_BAUD MCK/2
#define FLASH_FASTBAUD MCK
#define FLASH_MINBAUD FLASH_FASTBAUD

#define FASTFLASH (FLASHMEM_SPIBAUDRATE > FLASH_MINFAST)

static int CmdHelp(const char *Cmd);

static int usage_flashmem_spibaud(void) {
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
    return PM3_SUCCESS;
}

static int usage_flashmem_read(void) {
    PrintAndLogEx(NORMAL, "Read flash memory on device");
    PrintAndLogEx(NORMAL, "Usage:  mem read o <offset> l <len>");
    PrintAndLogEx(NORMAL, "  o <offset>    :      offset in memory");
    PrintAndLogEx(NORMAL, "  l <len>       :      length");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "        mem read o 0 l 32");    // read 32 bytes starting at offset 0
    PrintAndLogEx(NORMAL, "        mem read o 1024 l 10"); // read 10 bytes starting at offset 1024
    return PM3_SUCCESS;
}
static int usage_flashmem_load(void) {
    PrintAndLogEx(NORMAL, "Loads binary file into flash memory on device");
    PrintAndLogEx(NORMAL, "Usage:  mem load [o <offset>] f <file name> [m|t|i]");
    PrintAndLogEx(NORMAL, "Warning: mem area to be written must have been wiped first");
    PrintAndLogEx(NORMAL, "(this is already taken care when loading dictionaries)");
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
    return PM3_SUCCESS;
}
static int usage_flashmem_save(void) {
    PrintAndLogEx(NORMAL, "Saves flash memory on device into the file");
    PrintAndLogEx(NORMAL, " Usage:  mem save [o <offset>] [l <length>] f <file name>");
    PrintAndLogEx(NORMAL, "  o <offset>    :      offset in memory");
    PrintAndLogEx(NORMAL, "  l <length>    :      length");
    PrintAndLogEx(NORMAL, "  f <filename>  :      file name");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "        mem save f myfile");                 // download whole flashmem to file myfile
    PrintAndLogEx(NORMAL, "        mem save f myfile l 4096");          // download 4096 bytes from default offset 0 to file myfile
    PrintAndLogEx(NORMAL, "        mem save f myfile o 1024 l 4096");   // downlowd 4096 bytes from offset 1024 to file myfile
    return PM3_SUCCESS;
}
static int usage_flashmem_wipe(void) {

    PrintAndLogEx(WARNING, "[OBS] use with caution.");
    PrintAndLogEx(NORMAL, "Wipe flash memory on device, which fills memory with 0xFF\n");

    PrintAndLogEx(NORMAL, " Usage:  mem wipe p <page>");
    PrintAndLogEx(NORMAL, "  p <page>    :      0,1,2 page memory");
//  PrintAndLogEx(NORMAL, "  i           :      inital total wipe");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "        mem wipe p 0");  // wipes first page.
    return PM3_SUCCESS;
}
static int usage_flashmem_info(void) {
    PrintAndLogEx(NORMAL, "Collect signature and verify it from flash memory\n");
    PrintAndLogEx(NORMAL, " Usage:  mem info");
//    PrintAndLogEx(NORMAL, "  s    :      create a signature");
//    PrintAndLogEx(NORMAL, "  w    :      write signature to flash memory");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "        mem info");
//    PrintAndLogEx(NORMAL, "        mem info s");
    return PM3_SUCCESS;
}

static int CmdFlashMemRead(const char *Cmd) {

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
    if (errors || cmdp == 0) {
        usage_flashmem_read();
        return PM3_EINVARG;
    }
    if (start_index + len > FLASH_MEM_MAX_SIZE) {
        PrintAndLogDevice(WARNING, "error, start_index + length is larger than available memory");
        return PM3_EOVFLOW;
    }

    clearCommandBuffer();
    SendCommandMIX(CMD_FLASHMEM_READ, start_index, len, 0, NULL, 0);
    return PM3_SUCCESS;
}

static int CmdFlashmemSpiBaudrate(const char *Cmd) {

    char ctmp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) < 1 || ctmp == 'h') {
        return usage_flashmem_spibaud();
    }

    uint32_t baudrate = param_get32ex(Cmd, 0, 0, 10);
    baudrate = baudrate * 1000000;
    if (baudrate != FLASH_BAUD && baudrate != FLASH_MINBAUD) {
        usage_flashmem_spibaud();
        return PM3_EINVARG;
    }
    SendCommandMIX(CMD_FLASHMEM_SET_SPIBAUDRATE, baudrate, 0, 0, NULL, 0);
    return PM3_SUCCESS;
}

static int CmdFlashMemLoad(const char *Cmd) {

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
    if (errors || cmdp == 0) {
        usage_flashmem_load();
        return PM3_EINVARG;
    }
    size_t datalen = 0;
    uint16_t keycount = 0;
    int res = 0;
    uint8_t *data = calloc(FLASH_MEM_MAX_SIZE, sizeof(uint8_t));

    switch (d) {
        case DICTIONARY_MIFARE:
            start_index = DEFAULT_MF_KEYS_OFFSET;
            res = loadFileDICTIONARY(filename, data + 2, &datalen, 6, &keycount);
            if (res || !keycount) {
                free(data);
                return PM3_EFILE;
            }
            data[0] = (keycount >> 0) & 0xFF;
            data[1] = (keycount >> 8) & 0xFF;
            datalen += 2;
            break;
        case DICTIONARY_T55XX:
            start_index = DEFAULT_T55XX_KEYS_OFFSET;
            res = loadFileDICTIONARY(filename, data + 2, &datalen, 4, &keycount);
            if (res || !keycount) {
                free(data);
                return PM3_EFILE;
            }
            data[0] = (keycount >> 0) & 0xFF;
            data[1] = (keycount >> 8) & 0xFF;
            datalen += 2;
            break;
        case DICTIONARY_ICLASS:
            start_index = DEFAULT_ICLASS_KEYS_OFFSET;
            res = loadFileDICTIONARY(filename, data + 2, &datalen, 8, &keycount);
            if (res || !keycount) {
                free(data);
                return PM3_EFILE;
            }
            data[0] = (keycount >> 0) & 0xFF;
            data[1] = (keycount >> 8) & 0xFF;
            datalen += 2;
            break;
        case DICTIONARY_NONE:
            res = loadFile(filename, ".bin", data, FLASH_MEM_MAX_SIZE, &datalen);
            //int res = loadFileEML( filename, data, &datalen);
            if (res) {
                free(data);
                return PM3_EFILE;
            }

            if (datalen > FLASH_MEM_MAX_SIZE) {
                PrintAndLogDevice(WARNING, "error, filesize is larger than available memory");
                free(data);
                return PM3_EOVFLOW;
            }
            break;
    }

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

        SendCommandOLD(CMD_FLASHMEM_WRITE, start_index + bytes_sent, bytes_in_packet, 0, data + bytes_sent, bytes_in_packet);

        bytes_remaining -= bytes_in_packet;
        bytes_sent += bytes_in_packet;

        PacketResponseNG resp;
        if (!WaitForResponseTimeout(CMD_ACK, &resp, 2000)) {
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
    PrintAndLogEx(SUCCESS, "Wrote "_GREEN_("%u")"bytes to offset "_GREEN_("%u"), datalen, start_index);
    return PM3_SUCCESS;
}
static int CmdFlashMemSave(const char *Cmd) {

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
    if (errors || cmdp == 0) {
        usage_flashmem_save();
        return PM3_EINVARG;
    }

    uint8_t *dump = calloc(len, sizeof(uint8_t));
    if (!dump) {
        PrintAndLogDevice(WARNING, "error, cannot allocate memory ");
        return PM3_EMALLOC;
    }

    PrintAndLogEx(INFO, "downloading "_YELLOW_("%u")"bytes from flashmem", len);
    if (!GetFromDevice(FLASH_MEM, dump, len, start_index, NULL, -1, true)) {
        PrintAndLogEx(FAILED, "ERROR; downloading from flashmemory");
        free(dump);
        return PM3_EFLASH;
    }

    saveFile(filename, ".bin", dump, len);
    saveFileEML(filename, dump, len, 16);
    free(dump);
    return PM3_SUCCESS;
}
static int CmdFlashMemWipe(const char *Cmd) {

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
    if (errors || cmdp == 0) {
        usage_flashmem_wipe();
        return PM3_EINVARG;
    }

    clearCommandBuffer();
    SendCommandMIX(CMD_FLASHMEM_WIPE, page, initalwipe, 0, NULL, 0);
    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_ACK, &resp, 8000)) {
        PrintAndLogEx(WARNING, "timeout while waiting for reply.");
        return PM3_ETIMEOUT;
    }
    uint8_t isok  = resp.oldarg[0] & 0xFF;
    if (isok)
        PrintAndLogEx(SUCCESS, "Flash WIPE ok");
    else {
        PrintAndLogEx(FAILED, "Flash WIPE failed");
        return PM3_EFLASH;
    }

    return PM3_SUCCESS;
}
static int CmdFlashMemInfo(const char *Cmd) {

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
    if (errors) {
        usage_flashmem_info();
        return PM3_EINVARG;
    }

    clearCommandBuffer();
    SendCommandNG(CMD_FLASHMEM_INFO, NULL, 0);
    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_ACK, &resp, 2500)) {
        PrintAndLogEx(WARNING, "timeout while waiting for reply.");
        return PM3_ETIMEOUT;
    }

    uint8_t isok = resp.oldarg[0] & 0xFF;
    if (!isok) {
        PrintAndLogEx(FAILED, "failed");
        return PM3_EFLASH;
    }

    // validate signature here
    rdv40_validation_t mem;
    memcpy(&mem, (rdv40_validation_t *)resp.data.asBytes, sizeof(rdv40_validation_t));

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
// RRG Public RSA Key
//

// public key Exponent E
#define RSA_E "010001"

// public key modulus N
#define RSA_N "E28D809BF323171D11D1ACA4C32A5B7E0A8974FD171E75AD120D60E9B76968FF4B0A6364AE50583F9555B8EE1A725F279E949246DF0EFCE4C02B9F3ACDCC623F9337F21C0C066FFB703D8BFCB5067F309E056772096642C2B1A8F50305D5EC33DB7FB5A3C8AC42EB635AE3C148C910750ABAA280CE82DC2F180F49F30A1393B5"

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
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",    CmdHelp,            AlwaysAvailable, "This help"},
    {"spibaud", CmdFlashmemSpiBaudrate, IfPm3Flash,  "Set Flash memory Spi baudrate [rdv40]"},
    {"read",    CmdFlashMemRead,    IfPm3Flash,      "Read Flash memory [rdv40]"},
    {"info",    CmdFlashMemInfo,    IfPm3Flash,      "Flash memory information [rdv40]"},
    {"load",    CmdFlashMemLoad,    IfPm3Flash,      "Load data into flash memory [rdv40]"},
    {"save",    CmdFlashMemSave,    IfPm3Flash,      "Save data from flash memory [rdv40]"},
    {"wipe",    CmdFlashMemWipe,    IfPm3Flash,      "Wipe data from flash memory [rdv40]"},
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
