/*-
 * Copyright (C) 2010, Romain Tartiere.
 * Copyright (C) 2021 Merlok
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 * $Id$
 */

#ifndef __DESFIRECRYPTO_H
#define __DESFIRECRYPTO_H

#include "common.h"
#include "mifare/mifare4.h"

#define CRYPTO_AES_BLOCK_SIZE 16
#define MAX_CRYPTO_BLOCK_SIZE 16
#define DESFIRE_MAX_CRYPTO_BLOCK_SIZE 16
#define DESFIRE_MAX_KEY_SIZE  24

#define DESFIRE_GET_ISO_STATUS(x) ( ((uint16_t)(0x91<<8)) + (uint16_t)x )

enum DESFIRE_CRYPTOALGO {
    T_DES = 0x00,
    T_3DES = 0x01, //aka 2K3DES
    T_3K3DES = 0x02,
    T_AES = 0x03
};

typedef enum DESFIRE_CRYPTOALGO DesfireCryptoAlgorythm;

typedef enum {
    DACNone,
    DACd40,
    DACEV1,
    DACEV2
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
    DCMEncryptedPlain
} DesfireCommunicationMode;


typedef struct DesfireContextS {
    uint8_t keyNum;
    DesfireCryptoAlgorythm keyType;   // des/2tdea/3tdea/aes
    uint8_t key[DESFIRE_MAX_KEY_SIZE];

    // KDF finction
    uint8_t kdfAlgo;
    uint8_t kdfInputLen;
    uint8_t kdfInput[31];

    DesfireSecureChannel secureChannel; // none/d40/ev1/ev2
    DesfireCommandSet cmdSet;           // native/nativeiso/iso
    DesfireCommunicationMode commMode;  // plain/mac/enc

    bool appSelected; // for iso auth

    uint8_t IV[DESFIRE_MAX_KEY_SIZE];
    uint8_t sessionKeyMAC[DESFIRE_MAX_KEY_SIZE];
    uint8_t sessionKeyEnc[DESFIRE_MAX_KEY_SIZE];  // look at mifare4.h - mf4Session_t
    uint8_t lastIV[DESFIRE_MAX_KEY_SIZE];
    uint8_t lastCommand;
    bool lastRequestZeroLen;
    uint16_t cmdCntr;   // for AES
    uint8_t TI[4];      // for AES
} DesfireContext;

void DesfireClearContext(DesfireContext *ctx);
void DesfireClearSession(DesfireContext *ctx);
void DesfireClearIV(DesfireContext *ctx);
void DesfireSetKey(DesfireContext *ctx, uint8_t keyNum, enum DESFIRE_CRYPTOALGO keyType, uint8_t *key);
void DesfireSetCommandSet(DesfireContext *ctx, DesfireCommandSet cmdSet);
void DesfireSetCommMode(DesfireContext *ctx, DesfireCommunicationMode commMode);
void DesfireSetKdf(DesfireContext *ctx, uint8_t kdfAlgo, uint8_t *kdfInput, uint8_t kdfInputLen);
bool DesfireIsAuthenticated(DesfireContext *dctx);
size_t DesfireGetMACLength(DesfireContext *ctx);

size_t DesfireSearchCRCPos(uint8_t *data, size_t datalen, uint8_t respcode, uint8_t crclen);

void DesfireCryptoEncDec(DesfireContext *ctx, bool use_session_key, uint8_t *srcdata, size_t srcdatalen, uint8_t *dstdata, bool encode);
void DesfireCryptoEncDecEx(DesfireContext *ctx, bool use_session_key, uint8_t *srcdata, size_t srcdatalen, uint8_t *dstdata, bool dir_to_send, bool encode, uint8_t *iv);
void DesfireCryptoCMAC(DesfireContext *ctx, uint8_t *srcdata, size_t srcdatalen, uint8_t *cmac);

void DesfireDESKeySetVersion(uint8_t *key, DesfireCryptoAlgorythm keytype, uint8_t version);
uint8_t DesfireDESKeyGetVersion(uint8_t *key);

DesfireCommunicationMode DesfireFileCommModeToCommMode(uint8_t file_comm_mode);
uint8_t DesfireCommModeToFileCommMode(DesfireCommunicationMode comm_mode);

void DesfireGenSessionKeyEV1(const uint8_t rnda[], const uint8_t rndb[], DesfireCryptoAlgorythm keytype, uint8_t *key);
void DesfireGenSessionKeyEV2(uint8_t *key, uint8_t *rndA, uint8_t *rndB, bool enckey, uint8_t *sessionkey);
void DesfireEV2FillIV(DesfireContext *ctx, bool ivforcommand, uint8_t *iv);

void desfire_crc32(const uint8_t *data, const size_t len, uint8_t *crc);
void desfire_crc32_append(uint8_t *data, const size_t len);
bool desfire_crc32_check(uint8_t *data, const size_t len, uint8_t *crc);
void iso14443a_crc_append(uint8_t *data, size_t len);
void iso14443a_crc(uint8_t *data, size_t len, uint8_t *pbtCrc);
bool iso14443a_crc_check(uint8_t *data, const size_t len, uint8_t *crc);

#endif // __DESFIRECRYPTO_H
