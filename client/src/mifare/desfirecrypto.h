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
#include "mifare/desfire_crypto.h"
#include "mifare/mifare4.h"

#define DESF_MAX_KEY_LEN        24

#define DESFIRE_GET_ISO_STATUS(x) ( ((uint16_t)(0x91<<8)) + (uint16_t)x )

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
    DCMEncrypted
} DesfireCommunicationMode;


typedef struct DesfireContextS {
    uint8_t keyNum;
    enum DESFIRE_CRYPTOALGO keyType;   // des/2tdea/3tdea/aes
    uint8_t key[DESF_MAX_KEY_LEN];

    // KDF finction
    uint8_t kdfAlgo;
    uint8_t kdfInputLen;
    uint8_t kdfInput[31];

    DesfireSecureChannel secureChannel; // none/d40/ev1/ev2
    DesfireCommandSet cmdSet;           // native/nativeiso/iso
    DesfireCommunicationMode commMode;  // plain/mac/enc

    uint8_t IV[DESF_MAX_KEY_LEN];
    uint8_t sessionKeyMAC[DESF_MAX_KEY_LEN];
    uint8_t sessionKeyEnc[DESF_MAX_KEY_LEN];  // look at mifare4.h - mf4Session_t
    uint8_t lastIV[DESF_MAX_KEY_LEN];
    //mf4Session_t AESSession;
    uint16_t cntrTx;    // for AES
    uint16_t cntrRx;    // for AES
    uint8_t TI[4];      // for AES
} DesfireContext;

void DesfireClearContext(DesfireContext *ctx);
void DesfireClearSession(DesfireContext *ctx);
void DesfireSetKey(DesfireContext *ctx, uint8_t keyNum, enum DESFIRE_CRYPTOALGO keyType, uint8_t *key);
void DesfireSetCommandSet(DesfireContext *ctx, DesfireCommandSet cmdSet);
void DesfireSetCommMode(DesfireContext *ctx, DesfireCommunicationMode commMode);
void DesfireSetKdf(DesfireContext *ctx, uint8_t kdfAlgo, uint8_t *kdfInput, uint8_t kdfInputLen);
bool DesfireIsAuthenticated(DesfireContext *dctx);


void DesfireCryptoEncDec(DesfireContext *ctx, uint8_t *srcdata, size_t srcdatalen, uint8_t *dstdata, bool encode);


#endif // __DESFIRECRYPTO_H
