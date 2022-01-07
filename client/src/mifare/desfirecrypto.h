//-----------------------------------------------------------------------------
// Borrowed initially from https://github.com/nfc-tools/libfreefare
// Copyright (C) 2010, Romain Tartiere.
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

#ifndef __DESFIRECRYPTO_H
#define __DESFIRECRYPTO_H

#include "common.h"
#include "desfire.h"
#include "crypto/libpcrypto.h"
#include "mifare/lrpcrypto.h"

#define DESFIRE_GET_ISO_STATUS(x) ( ((uint16_t)(0x91<<8)) + (uint16_t)x )

typedef enum {
    DACNone,
    DACd40,
    DACEV1,
    DACEV2,
    DACLRP,
} DesfireSecureChannel;

typedef enum {
    DCCNative,
    DCCNativeISO,
    DCCISO
} DesfireCommandSet;

typedef enum {
    DCMNone,
    DCMPlain,
    DCMMACed,
    DCMEncrypted,
    DCMEncryptedWithPadding,
    DCMEncryptedPlain
} DesfireCommunicationMode;

typedef enum {
    DCOMasterKey,
    DCOMainKey,
    DCOSessionKeyMac,
    DCOSessionKeyEnc
} DesfireCryptoOpKeyType;

typedef struct {
    uint8_t keyNum;
    DesfireCryptoAlgorithm keyType;   // des/2tdea/3tdea/aes
    uint8_t key[DESFIRE_MAX_KEY_SIZE];
    uint8_t masterKey[DESFIRE_MAX_KEY_SIZE]; // source for kdf

    // KDF function
    uint8_t kdfAlgo;
    uint8_t kdfInputLen;
    uint8_t kdfInput[31];

    DesfireSecureChannel secureChannel; // none/d40/ev1/ev2
    DesfireCommandSet cmdSet;           // native/nativeiso/iso
    DesfireCommunicationMode commMode;  // plain/mac/enc

    bool isoChaining;
    bool appSelected; // for iso auth
    uint32_t selectedAID;

    uint8_t uid[10];
    uint8_t uidlen;

    uint8_t IV[DESFIRE_MAX_KEY_SIZE];
    uint8_t sessionKeyMAC[DESFIRE_MAX_KEY_SIZE];
    uint8_t sessionKeyEnc[DESFIRE_MAX_KEY_SIZE];  // look at mifare4.h - mf4Session_t
    uint8_t lastIV[DESFIRE_MAX_KEY_SIZE];
    uint8_t lastCommand;
    bool lastRequestZeroLen;
    uint16_t cmdCntr;   // for AES
    uint8_t TI[4];      // for AES
} DesfireContext_t;

void DesfireClearContext(DesfireContext_t *ctx);
void DesfireClearSession(DesfireContext_t *ctx);
void DesfireClearIV(DesfireContext_t *ctx);
void DesfireSetKey(DesfireContext_t *ctx, uint8_t keyNum, DesfireCryptoAlgorithm keyType, uint8_t *key);
void DesfireSetKeyNoClear(DesfireContext_t *ctx, uint8_t keyNum, DesfireCryptoAlgorithm keyType, uint8_t *key);
void DesfireSetCommandSet(DesfireContext_t *ctx, DesfireCommandSet cmdSet);
void DesfireSetCommMode(DesfireContext_t *ctx, DesfireCommunicationMode commMode);
void DesfireSetKdf(DesfireContext_t *ctx, uint8_t kdfAlgo, uint8_t *kdfInput, uint8_t kdfInputLen);
bool DesfireIsAuthenticated(DesfireContext_t *dctx);
size_t DesfireGetMACLength(DesfireContext_t *ctx);

size_t DesfireSearchCRCPos(uint8_t *data, size_t datalen, uint8_t respcode, uint8_t crclen);

uint8_t *DesfireGetKey(DesfireContext_t *ctx, DesfireCryptoOpKeyType key_type);
void DesfireCryptoEncDec(DesfireContext_t *ctx, DesfireCryptoOpKeyType key_type, uint8_t *srcdata, size_t srcdatalen, uint8_t *dstdata, bool encode);
void DesfireCryptoEncDecEx(DesfireContext_t *ctx, DesfireCryptoOpKeyType key_type, uint8_t *srcdata, size_t srcdatalen, uint8_t *dstdata, bool dir_to_send, bool encode, uint8_t *iv);
void DesfireCMACGenerateSubkeys(DesfireContext_t *ctx, DesfireCryptoOpKeyType key_type, uint8_t *sk1, uint8_t *sk2);
void DesfireCryptoCMAC(DesfireContext_t *ctx, uint8_t *data, size_t len, uint8_t *cmac);
void DesfireCryptoCMACEx(DesfireContext_t *ctx, DesfireCryptoOpKeyType key_type, uint8_t *data, size_t len, size_t minlen, uint8_t *cmac);
void MifareKdfAn10922(DesfireContext_t *ctx, DesfireCryptoOpKeyType key_type, const uint8_t *data, size_t len);

void DesfireGenSessionKeyLRP(uint8_t *key, uint8_t *rndA, uint8_t *rndB, bool enckey, uint8_t *sessionkey);

void DesfireDESKeySetVersion(uint8_t *key, DesfireCryptoAlgorithm keytype, uint8_t version);
uint8_t DesfireDESKeyGetVersion(const uint8_t *key);

DesfireCryptoAlgorithm DesfireKeyTypeToAlgo(uint8_t keyType);
uint8_t DesfireKeyAlgoToType(DesfireCryptoAlgorithm keyType);
void DesfirePrintCardKeyType(uint8_t keyType);

DesfireCommunicationMode DesfireFileCommModeToCommMode(uint8_t file_comm_mode);
uint8_t DesfireCommModeToFileCommMode(DesfireCommunicationMode comm_mode);

void DesfireGenSessionKeyEV1(const uint8_t rnda[], const uint8_t rndb[], DesfireCryptoAlgorithm keytype, uint8_t *key);
void DesfireGenSessionKeyEV2(uint8_t *key, uint8_t *rndA, uint8_t *rndB, bool enckey, uint8_t *sessionkey);
void DesfireEV2FillIV(DesfireContext_t *ctx, bool ivforcommand, uint8_t *iv);
int DesfireEV2CalcCMAC(DesfireContext_t *ctx, uint8_t cmd, uint8_t *data, size_t datalen, uint8_t *mac);

void DesfireGenTransSessionKeyEV2(uint8_t *key, uint32_t trCntr, uint8_t *uid, bool forMAC, uint8_t *sessionkey);
void DesfireGenTransSessionKeyLRP(uint8_t *key, uint32_t trCntr, uint8_t *uid, bool forMAC, uint8_t *sessionkey);
void DesfireDecodePrevReaderID(DesfireContext_t *ctx, uint8_t *key, uint32_t trCntr, uint8_t *encPrevReaderID, uint8_t *prevReaderID);

int DesfireLRPCalcCMAC(DesfireContext_t *ctx, uint8_t cmd, uint8_t *data, size_t datalen, uint8_t *mac);

int desfire_get_key_length(DesfireCryptoAlgorithm key_type);
size_t desfire_get_key_block_length(DesfireCryptoAlgorithm key_type);
size_t padded_data_length(const size_t nbytes, const size_t block_size);

void desfire_crc32(const uint8_t *data, const size_t len, uint8_t *crc);
void desfire_crc32_append(uint8_t *data, const size_t len);
bool desfire_crc32_check(uint8_t *data, const size_t len, uint8_t *crc);
void iso14443a_crc_append(uint8_t *data, size_t len);
void iso14443a_crc(uint8_t *data, size_t len, uint8_t *pbtCrc);
bool iso14443a_crc_check(uint8_t *data, const size_t len, uint8_t *crc);

#endif // __DESFIRECRYPTO_H
