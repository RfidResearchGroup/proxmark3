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
// SEOS commands
//-----------------------------------------------------------------------------
#include "cmdhfict.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>              // tolower
#include "cliparser.h"
#include "cmdparser.h"          // command_t
#include "comms.h"              // clearCommandBuffer
#include "cmdtrace.h"
#include "ui.h"
#include "cmdhf14a.h"           // manufacture
#include "protocols.h"          // definitions of ISO14A/7816 protocol
#include "iso7816/apduinfo.h"   // GetAPDUCodeDescription
#include "commonutil.h"         // get_sw
#include "protocols.h"          // ISO7816 APDU return codes
#include "mifare/mifaredefault.h"      // AES_KEY_LEN
#include <mbedtls/aes.h>
#include <mbedtls/cmac.h>
//#include <mbedtls/entropy.h>
#include <mbedtls/error.h>

static int CmdHelp(const char *Cmd);


// missing
#define ICT_DESFIRE_FILEKEY         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
#define ICT_DESFIRE_MASTER_APPKEY   "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
#define ICT_BLE_DEFAULT_BASE_KEY    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

#define ICT_MIFARE_A_KEY    "\x9c\x28\xa6\x0f\x72\x49"
#define ICT_MIFARE_B_KEY    "\xc9\x82\x6a\xf0\x27\x94"
#define ICT_MIFARE_SECTOR   14
#define ICT_APP_ID          0x1023f5
#define ICT_REV_APP_ID      0xf52310
#define ICT_FILE_ID         0
#define ICT_FILE_SIZE       128

#define ICT_CT_DESFIRE      0
#define ICT_CT_CLASSIC      1
#define ICT_CT_NFC          2

static int derive_ble_key(uint8_t *unique_data, uint8_t len, uint8_t *app_key) {

    if (unique_data == NULL || app_key == NULL) {
        return PM3_EINVARG;
    }

    uint8_t input[1 + len];
    input[0] = 0x01;
    memcpy(input + 1, unique_data, len);

    uint8_t mac[16];
    memset(mac, 0x00, 16);

    uint8_t key[AES_KEY_LEN];
    memcpy(key, ICT_BLE_DEFAULT_BASE_KEY, sizeof(key));

    //  NIST 800-38B
    mbedtls_aes_cmac_prf_128(key, MBEDTLS_AES_BLOCK_SIZE, input, sizeof(input), mac);

    memcpy(app_key, mac, sizeof(mac));
    return PM3_SUCCESS;
}

static int derive_app_key(uint8_t *uid, uint8_t *app_key) {
    if (uid == NULL || app_key == NULL) {
        return PM3_EINVARG;
    }

/*
    c = b'\x88' + uid
    ch, cl = c[0:4], c[4:8]
    payload = (ch + cl + cl + ch) * 2
    AES.new(ICT_DESFIRE_MASTER_APPKEY, AES.MODE_CBC, iv=b'\0'*16).decrypt(payload)[16:]
*/
    uint8_t input[] = {0x88, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    memcpy(input + 1, uid, 7);

//    uint32_t ch = bytes_to_num(input, 4);
//    uint32_t cl = bytes_to_num(input + 4, 4);
//    uint64_t payload = ((2 * ch) + (2 * cl) * 2);

    uint8_t key[AES_KEY_LEN];
    memcpy(key, ICT_DESFIRE_MASTER_APPKEY, AES_KEY_LEN);

    uint8_t iv[16] = {0};
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);    
    if (mbedtls_aes_setkey_enc(&aes, key, 128)) {
        return PM3_ESOFT;    
    }
   
    uint8_t output[8];
    if (mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, sizeof(input), iv, input, output)) {
        return PM3_ESOFT;
    }
    mbedtls_aes_free(&aes);    
    memcpy(app_key, output, sizeof(output));
    return PM3_SUCCESS;
}

// Might miss payload..
static int diversify_mifare_key(uint8_t *uid, uint8_t *app_key) {
    if (uid == NULL || app_key == NULL) {
        return PM3_EINVARG;
    }

    uint8_t input[8];
    memcpy(input, uid, 4);

    uint32_t big = bytes_to_num(uid, 4);
    big ^= 0xFFFFFFFF;
    num_to_bytes(big, 4, input + 4);

    uint8_t key[AES_KEY_LEN];
//    memcpy(key, ICT_DESFIRE_FILEKEY, AES_KEY_LEN);

    uint8_t iv[16] = {0};
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);    
    if (mbedtls_aes_setkey_enc(&aes, key, 128)) {
        return PM3_ESOFT;    
    }
   
    uint8_t output[8];
    if (mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, sizeof(input), iv, input, output)) {
        return PM3_ESOFT;
    }
    mbedtls_aes_free(&aes);    
    memcpy(app_key, output, sizeof(output));
    return PM3_SUCCESS;
}

static int decrypt_card_sector(uint8_t *uid, uint8_t *sector_data, uint8_t len, uint8_t *plain) {
    if (uid == NULL || sector_data == NULL || plain == NULL) {
        return PM3_EINVARG;
    }

    uint8_t input[len];
    memcpy(input, sector_data, len);

    uint8_t key[AES_KEY_LEN];
    diversify_mifare_key(uid, key);

    uint8_t iv[16] = {0};
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);    
    if (mbedtls_aes_setkey_enc(&aes, key, 128)) {
        return PM3_ESOFT;    
    }
   
    uint8_t output[len];
    if (mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, sizeof(input), iv, input, output)) {
        return PM3_ESOFT;
    }
    mbedtls_aes_free(&aes);    

    memcpy(plain, output, sizeof(output));
    return PM3_SUCCESS;
}

static int derive_mifare_key(uint8_t *uid, const uint8_t *base_key, uint8_t *app_key) {
    if (uid == NULL || base_key == NULL || app_key == NULL) {
        return PM3_EINVARG;
    }
    
    uint8_t diverse[MIFARE_KEY_SIZE];
    diversify_mifare_key(uid, diverse);

    for (uint8_t i=0; i < MIFARE_KEY_SIZE; i++) {
        app_key[i] = base_key[i] ^ diverse[i];
    }

    return PM3_SUCCESS;
}

static int derive_mifare_key_a(uint8_t *uid, uint8_t *app_key) {
    return derive_mifare_key(uid, (const uint8_t*)ICT_MIFARE_A_KEY, app_key);
}

static int derive_mifare_key_b(uint8_t *uid, uint8_t *app_key) {
    return derive_mifare_key(uid, (const uint8_t*)ICT_MIFARE_B_KEY, app_key);
}

static int decrypt_card_file(uint8_t *card_file, uint8_t len, uint8_t *plain) {
     if (card_file == NULL || plain == NULL) {
        return PM3_EINVARG;
    }
 
    uint8_t input[ICT_FILE_SIZE];
    memcpy(input, card_file, len);

    uint8_t key[AES_KEY_LEN];
//    memcpy(key, ICT_DESFIRE_FILEKEY, AES_KEY_LEN);

    uint8_t iv[16] = {0};
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);    
    if (mbedtls_aes_setkey_enc(&aes, key, 128)) {
        return PM3_ESOFT;
    }
   
    uint8_t output[ICT_FILE_SIZE];
    if (mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, ICT_FILE_SIZE, iv, input, output)) {
        return PM3_ESOFT;
    }
    mbedtls_aes_free(&aes);
    memcpy(plain, output, sizeof(output));
    return PM3_SUCCESS;
}

static int encrypt_card_file(uint8_t *card_file, uint8_t len, bool padding, uint8_t *enc) {

    if (len > ICT_FILE_SIZE) {
        return PM3_EINVARG;
    }

    uint8_t input[ICT_FILE_SIZE];
    memcpy(input, card_file, len);

    if (padding) {
        memset(input + len, 0x4C, 128 - len);
    }

    uint8_t key[AES_KEY_LEN];
//    memcpy(key, ICT_DESFIRE_FILEKEY, AES_KEY_LEN);

    uint8_t iv[16] = {0};
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);    
    if (mbedtls_aes_setkey_enc(&aes, key, 128)) {
        return PM3_ESOFT;    
    }
   
    uint8_t output[ICT_FILE_SIZE];
    if (mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, ICT_FILE_SIZE, iv, input, output)) {
        return PM3_ESOFT;
    }
    mbedtls_aes_free(&aes);    
    memcpy(enc, output, sizeof(output));
    return PM3_SUCCESS;
}

static void itc_decode_card_blob(uint8_t *data, uint8_t card_type) {
    if (data == NULL) {
        return;
    }
/*
    uint8_t block[16];
    if (card_type == ICT_CT_NFC)
        memcpy(block, data+16, sizeof(block));
    else
        memcpy(block, data, sizeof(block));

    uint8_t bit_count = data[8];

    uint8_t wiegand[32];

    if (card_type == ICT_CT_DESFIRE || card_type == ICT_CT_NFC) {
        memcpy(wiegand, data + 11, 32-11);
    }

    if (card_type == ICT_CT_CLASSIC) {
        memcpy(wiegand, data + 9, 32-9);
    }

    if (bit_count == 26) {
        fc, cn = decode_wiegand_26(wiegand_payload)
        ct = "Wiegand 26-bit"
    }
    if (bit_count == 34) {
        fc, cn = decode_wiegand_34(wiegand_payload)
        ct = "Wiegand 34-bit"
    }else  {
        return f"Unknown format (bitlength={bit_count})", None, None
    }

    return ct, fc, cn
    */
}
static void itc_encode_card_blob(uint8_t facility_code, uint16_t card_number, uint8_t bit_count) {
/*
    // encode wiegand ..
    uint8_t wiegand[] = {0,0,0,0,0};
    if (bit_count == 26) {
//        wiegand_data = encode_wiegand_26(facility_code, card_number)
    }
    if (bit_count == 34) {
//        wiegand_data = encode_wiegand_34(facility_code, card_number)
    }

    // card binary blog
    uint8_t blob[] = {
        '@', 'I', 'C', 'T', 0x00, 0x80, 0x00, 0x00, bit_count, 0x00, bit_count
    };
    // return b'@ICT' + bytes([0,128,0,0,bit_count, 0, bit_count]) + wiegand_data
    */
}

static int ict_select(void) {
    bool activate_field = true;
    bool keep_field_on = true;
    uint8_t response[PM3_CMD_DATA_SIZE];
    int resplen = 0;

    // ---------------  Select SEOS applet ----------------
    uint8_t aSELECT_AID[80];
    int aSELECT_AID_n = 0;
    param_gethex_to_eol("00a404000aa000000440000101000100", 0, aSELECT_AID, sizeof(aSELECT_AID), &aSELECT_AID_n);
    int res = ExchangeAPDU14a(aSELECT_AID, aSELECT_AID_n, activate_field, keep_field_on, response, sizeof(response), &resplen);
    if (res != PM3_SUCCESS) {
        DropField();
        return res;
    }

    if (resplen < 2) {
        DropField();
        return PM3_ESOFT;
    }

    uint16_t sw = get_sw(response, resplen);
    if (sw != ISO7816_OK) {
        PrintAndLogEx(ERR, "Selecting SEOS applet aid failed (%04x - %s).", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        DropField();
        return PM3_ESOFT;
    }

    activate_field = false;
    keep_field_on = false;
    // ---------------  CC file reading ----------------

    uint8_t aSELECT_FILE_ADF[30];
    int aSELECT_FILE_ADF_n = 0;
    param_gethex_to_eol("80a504001306112b0601040181e43801010201180101020200", 0, aSELECT_FILE_ADF, sizeof(aSELECT_FILE_ADF), &aSELECT_FILE_ADF_n);
    res = ExchangeAPDU14a(aSELECT_FILE_ADF, aSELECT_FILE_ADF_n, activate_field, keep_field_on, response, sizeof(response), &resplen);
    if (res != PM3_SUCCESS) {
        DropField();
        return res;
    }

    sw = get_sw(response, resplen);
    if (sw != ISO7816_OK) {
        PrintAndLogEx(ERR, "Selecting ADF file failed (%04x - %s).", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        DropField();
        return PM3_ESOFT;
    }

    return PM3_SUCCESS;
}

int infoICT(bool verbose) {
    int res = ict_select();
    if (res == PM3_SUCCESS) {
        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(INFO, "--- " _CYAN_("Tag Information") " ---------------------------");
    }
    return PM3_SUCCESS;
}

static int CmdHfIctInfo(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf ict info",
                  "Get info from ICT encoded credential tags (MIFARE Classic / DESfire)",
                  "hf ict info");

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    return infoICT(true);
}

static int CmdHfIctRead(const char *Cmd) {

    // MFC actions
    uint8_t uid[4] = {0x04, 0x01, 0x02, 0x03};
    uint8_t key[MIFARE_KEY_SIZE] = {0};
    derive_mifare_key_a(uid, key);
    derive_mifare_key_b(uid, key);

    uint8_t encsector[48] = {0};
    uint8_t plainsector[48] = {0};
    decrypt_card_sector(uid, encsector, sizeof(encsector), plainsector);

    // DESFIRE Actions
    uint8_t aeskey[AES_KEY_LEN] = {0};
    uint8_t desfireuid[7] = {0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    derive_app_key(desfireuid, aeskey);

    uint8_t uniquedata[16] = {0};
    derive_ble_key(uniquedata, sizeof(uniquedata), aeskey);

    uint8_t encdata[ICT_FILE_SIZE] = {0};
    uint8_t plaindata[ICT_FILE_SIZE] = {0};
    decrypt_card_file(encdata, sizeof(encdata), plaindata);
    encrypt_card_file(plaindata, sizeof(plaindata), true, encdata);

    // blob actions
    uint8_t mfcblob[48] = {0};
    itc_decode_card_blob(mfcblob, ICT_CT_CLASSIC);
    itc_encode_card_blob(101, 1337, 26);

    return PM3_SUCCESS;
}

static int CmdHfIctList(const char *Cmd) {
    return CmdTraceListAlias(Cmd, "hf ict", "14a -c");
}

static command_t CommandTable[] = {
    {"help",    CmdHelp,        AlwaysAvailable, "This help"},
    {"info",    CmdHfIctInfo,   IfPm3NfcBarcode, "Tag information"},
    {"list",    CmdHfIctList,   AlwaysAvailable, "List ICT history"},
    {"reader",  CmdHfIctRead,   AlwaysAvailable, "Act like an IS14443-a reader"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdHFICT(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}
