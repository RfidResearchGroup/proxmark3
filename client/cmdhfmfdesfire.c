//-----------------------------------------------------------------------------
// Copyright (C) 2014 Andy Davies
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency MIFARE commands
//-----------------------------------------------------------------------------

#include "cmdhfmf.h"
#include "util.h"
#include <openssl/des.h>
#include <openssl/aes.h>

static int CmdHelp(const char *Cmd);

//DESFIRE
// Reader 2 Card : 020A, key (1 byte), CRC1 CRC2 ; auth (020a00)
// Card 2 Reader : 02AF, 8 Bytes(b0), CRC1 CRC2
// Reader 2 Card : 03AF, 8 Bytes(b1),8 bytes(b2), CRC1 CRC2
// Card 2 Reader : 0300, 8 bytes(b3), CRC1 CRC2 ; success

//send 020A00, receive enc(nc)

//02AE = error
//receive b3=enc(r4)
//r5=dec(b3)
//n'r=rol(r5)
//verify n'r=nr

int CmdHF14AMfDESAuth(const char *Cmd) {

    uint8_t blockNo = 0;
    //keyNo=0;
    uint32_t cuid = 0;
    uint8_t reply[16] = {0x00};
    //DES_cblock r1_b1;
    uint8_t b1[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t b2[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    DES_cblock nr,  b0, r1, r0;


    uint8_t key[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    //DES_cblock iv={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
    DES_key_schedule ks1;
    DES_cblock key1;

    if (strlen(Cmd) < 1) {
        PrintAndLogEx(NORMAL, "Usage:  hf desfire des-auth k <key number>");
        PrintAndLogEx(NORMAL, "Examples:");
        PrintAndLogEx(NORMAL, "        hf desfire des-auth k 0");
        return 0;
    }

    //Change key to user defined one

    memcpy(key1, key, 8);
    //memcpy(key2,key+8,8);
    DES_set_key((DES_cblock *)key1, &ks1);
    //DES_set_key((DES_cblock *)key2,&ks2);

    //Auth1
    UsbCommand c = {CMD_MIFARE_DES_AUTH1, {blockNo}};
    SendCommand(&c);
    UsbCommand resp;
    if (WaitForResponseTimeout(CMD_ACK, &resp, 1500)) {
        uint8_t isOK  = resp.arg[0] & 0xff;
        cuid  = resp.arg[1];
        uint8_t *data = resp.d.asBytes;

        if (isOK) {
            PrintAndLogEx(NORMAL, "enc(nc)/b0:%s", sprint_hex(data + 2, 8));
            memcpy(b0, data + 2, 8);
        }
    } else {
        PrintAndLogEx(WARNING, "Command execute timeout");
    }

    //Do crypto magic
    DES_random_key(&nr);
    //b1=dec(nr)
    //r0=dec(b0)
    DES_ecb_encrypt(&nr, &b1, &ks1, 0);
    DES_ecb_encrypt(&b0, &r0, &ks1, 0);
    //PrintAndLogEx(NORMAL, "b1:%s",sprint_hex(b1, 8));
    PrintAndLogEx(NORMAL, "r0:%s", sprint_hex(r0, 8));
    //r1=rol(r0)
    memcpy(r1, r0, 8);
    rol(r1, 8);
    PrintAndLogEx(NORMAL, "r1:%s", sprint_hex(r1, 8));
    for (int i = 0; i < 8; i++) {
        b2[i] = (r1[i] ^ b1[i]);
    }
    DES_ecb_encrypt(&b2, &b2, &ks1, 0);
    //PrintAndLogEx(NORMAL, "b1:%s",sprint_hex(b1, 8));
    PrintAndLogEx(NORMAL, "b2:%s", sprint_hex(b2, 8));

    //Auth2
    UsbCommand d = {CMD_MIFARE_DES_AUTH2, {cuid}};
    memcpy(reply, b1, 8);
    memcpy(reply + 8, b2, 8);
    memcpy(d.d.asBytes, reply, 16);
    SendCommand(&d);

    UsbCommand respb;
    if (WaitForResponseTimeout(CMD_ACK, &respb, 1500)) {
        uint8_t  isOK  = respb.arg[0] & 0xff;
        uint8_t *data2 = respb.d.asBytes;

        if (isOK)
            PrintAndLogEx(NORMAL, "b3:%s", sprint_hex(data2 + 2, 8));

    } else {
        PrintAndLogEx(WARNING, "Command execute timeout");
    }
    return 1;
}

//EV1
// Reader 2 Card : 02AA, key (1 byte), CRC1 CRC2 ; auth
// Card 2 Reader : 02AF, 16 Bytes(b0), CRC1 CRC2
// Reader 2 Card : 03AF, 16 Bytes(b1),16Bytes(b2) CRC1 CRC2
// Card 2 Reader : 0300, 16 bytes(b3), CRC1 CRC2 ; success
int CmdHF14AMfAESAuth(const char *Cmd) {

    uint8_t blockNo = 0;
    //keyNo=0;
    uint32_t cuid = 0;
    uint8_t reply[32] = {0x00};
    //DES_cblock r1_b1;
    //unsigned char * b1, b2, nr, b0, r0, r1;

    uint8_t b1[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t b2[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t nr[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t b0[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t r0[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t r1[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    //
    uint8_t key[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t iv[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    AES_KEY key_e;
    AES_KEY key_d;

    if (strlen(Cmd) < 1) {
        PrintAndLogEx(NORMAL, "Usage:  hf desfire aes-auth k <key number>");
        PrintAndLogEx(NORMAL, "Examples:");
        PrintAndLogEx(NORMAL, "        hf desfire aes-auth k 0");
        return 0;
    }

    //Change key to user defined one
    //
    // int private_AES_set_encrypt_key(const unsigned char *userKey, const int bits,AES_KEY *key);
    //int private_AES_set_decrypt_key(const unsigned char *userKey, const int bits,AES_KEY *key);
    //
    //memcpy(key1,key,16);
    //memcpy(key2,key+8,8);
    AES_set_encrypt_key(key, 128, &key_e);
    AES_set_decrypt_key(key, 128, &key_d);

    //Auth1
    UsbCommand c = {CMD_MIFARE_DES_AUTH1, {blockNo}};
    SendCommand(&c);
    UsbCommand resp;
    if (WaitForResponseTimeout(CMD_ACK, &resp, 1500)) {
        uint8_t isOK  = resp.arg[0] & 0xff;
        cuid  = resp.arg[1];
        uint8_t *data = resp.d.asBytes;

        if (isOK) {
            PrintAndLogEx(NORMAL, "enc(nc)/b0:%s", sprint_hex(data + 2, 16));
            memcpy(b0, data + 2, 16);
        }
    } else {
        PrintAndLogEx(WARNING, "Command execute timeout");
    }
    //
    // void AES_cbc_encrypt(const unsigned char *in, unsigned char *out,
    //size_t length, const AES_KEY *key,
    //unsigned char *ivec, const int enc);

    //Do crypto magic
    //DES_random_key(&nr);
    //b1=dec(nr)
    //r0=dec(b0)
    //AES_cbc_encrypt(&nr,&b1,16,&key,0);
    AES_cbc_encrypt(&b0, &r0, 16, &key_d, iv, 0);
    //PrintAndLogEx(NORMAL, "b1:%s",sprint_hex(b1, 8));
    PrintAndLogEx(NORMAL, "r0:%s", sprint_hex(r0, 16));
    //r1=rol(r0)
    memcpy(r1, r0, 16);
    rol(r1, 8);
    PrintAndLogEx(NORMAL, "r1:%s", sprint_hex(r1, 16));
    for (int i = 0; i < 16; i++) {
        b1[i] = (nr[i] ^ b0[i]);
        b2[i] = (r1[i] ^ b1[i]);
    }
    PrintAndLogEx(NORMAL, "nr:%s", sprint_hex(nr, 16));
    AES_cbc_encrypt(&b1, &b1, 16, &key_e, iv, 1);
    AES_cbc_encrypt(&b2, &b2, 16, &key_e, iv, 1);
    PrintAndLogEx(NORMAL, "b1:%s", sprint_hex(b1, 16));
    PrintAndLogEx(NORMAL, "b2:%s", sprint_hex(b2, 16));

    //Auth2
    UsbCommand d = {CMD_MIFARE_DES_AUTH2, {cuid}};
    memcpy(reply, b1, 16);
    memcpy(reply + 16, b2, 16);
    memcpy(d.d.asBytes, reply, 32);
    SendCommand(&d);

    UsbCommand respb;
    if (WaitForResponseTimeout(CMD_ACK, &respb, 1500)) {
        uint8_t  isOK  = respb.arg[0] & 0xff;
        uint8_t *data2 = respb.d.asBytes;

        if (isOK)
            PrintAndLogEx(NORMAL, "b3:%s", sprint_hex(data2 + 2, 16));

    } else {
        PrintAndLogEx(WARNING, "Command execute timeout");
    }
    return 1;
}


//------------------------------------
// Menu Stuff
//------------------------------------
static command_t CommandTable[] = {
    {"help",    CmdHelp,            1, "This help"},
    {"dbg",     CmdHF14AMfDbg,      0, "Set default debug mode"},
    {"des-auth", CmdHF14AMfDESAuth,  0, "Desfire Authentication"},
    {"ev1-auth", CmdHF14AMfAESAuth,  0, "EV1 Authentication"},
    {NULL, NULL, 0, NULL}
};

int CmdHFMFDesfire(const char *Cmd) {
    // flush
    clearCommandBuffer();
    CmdsParse(CommandTable, Cmd);
    return 0;
}

int CmdHelp(const char *Cmd) {
    CmdsHelp(CommandTable);
    return 0;
}
