//-----------------------------------------------------------------------------
// Copyright (C) 2010 Romain Tartiere.
// Copyright (C) 2014 Iceman
// Copyright (C) 2021 Merlok
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency Desfire core functions
//-----------------------------------------------------------------------------

#ifndef __DESFIRECORE_H
#define __DESFIRECORE_H

#include "common.h"
#include "mifare/desfire_crypto.h"
#include "mifare/mifare4.h"

#define DESF_MAX_KEY_LEN        24

#define DESFIRE_GET_ISO_STATUS(x) ( ((uint16_t)(0x91<<8)) + (uint16_t)x )

typedef enum {
    DACNone,
    DACd40,
    DACEV1,
    DACEV2
} DesfireAuthChannel;

typedef enum {
    DCCNative,
    DCCNativeISO,
    DCCISO
} DesfireCommandChannel;

typedef enum {
    DCMNone,
    DCMPlain,
    DCMMACed,
    DCMEncrypted
} DesfireCommunicationMode;


typedef struct DesfireContextS {
    uint8_t keyNum;
    enum DESFIRE_CRYPTOALGO keyType;   // des,2tdea,3tdea,aes
    uint8_t key[DESF_MAX_KEY_LEN];
    
    // KDF finction
    // KDF input
    
    DesfireAuthChannel authChannel;    // none/d40/ev1/ev2
    DesfireCommandChannel cmdChannel;  // native/nativeiso/iso
    DesfireCommunicationMode commMode; // plain/mac/enc

    uint8_t sessionKeyMAC[DESF_MAX_KEY_LEN];
    uint8_t sessionKeyEnc[DESF_MAX_KEY_LEN];  // look at mifare4.h - mf4Session_t
    uint8_t lastIV[DESF_MAX_KEY_LEN];
    //mf4Session_t AESSession;
    uint16_t cntrTx;    // for AES
    uint16_t cntrRx;    // for AES
    uint8_t TI[4];      // for AES
} DesfireContext;

void DesfireClearContext(DesfireContext *ctx);
void DesfireSetKey(DesfireContext *ctx, uint8_t keyNum, enum DESFIRE_CRYPTOALGO keyType, uint8_t *key);

const char *DesfireGetErrorString(int res, uint16_t *sw);

int DesfireSelectAID(DesfireContext *ctx, uint8_t *aid1, uint8_t *aid2);
int DesfireSelectAIDHex(DesfireContext *ctx, uint32_t aid1, bool select_two, uint32_t aid2);
int DesfireExchange(DesfireContext *ctx, uint8_t cmd, uint8_t *data, size_t datalen, uint8_t *respcode, uint8_t *resp, size_t *resplen);
int DesfireExchangeEx(bool activate_field, DesfireContext *ctx, uint8_t cmd, uint8_t *data, size_t datalen, uint8_t *respcode, uint8_t *resp, size_t *resplen, bool enable_chaining);


#endif // __DESFIRECORE_H
