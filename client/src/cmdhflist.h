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
// Command: hf mf list. It shows data from arm buffer.
//-----------------------------------------------------------------------------
#ifndef CMDHFLIST_H
#define CMDHFLIST_H

#include "common.h"

typedef struct {
    uint32_t uid;       // UID
    uint32_t nt;        // tag challenge
    uint32_t nt_enc;    // encrypted tag challenge
    uint8_t nt_enc_par; // encrypted tag challenge parity
    uint32_t nr_enc;    // encrypted reader challenge
    uint8_t nr_enc_par; // encrypted reader challenge parity
    uint32_t ar_enc;    // encrypted reader response
    uint8_t ar_enc_par; // encrypted reader response parity
    uint32_t at_enc;    // encrypted tag response
    uint8_t at_enc_par; // encrypted tag response parity
    bool first_auth;    // is first authentication
    uint32_t ks2;       // ar ^ ar_enc
    uint32_t ks3;       // at ^ at_enc
} AuthData_t;

void ClearAuthData(void);

uint8_t iso14443A_CRC_check(bool isResponse, uint8_t *d, uint8_t n);
uint8_t iso14443B_CRC_check(uint8_t *d, uint8_t n);
uint8_t felica_CRC_check(uint8_t *d, uint8_t n);
uint8_t mifare_CRC_check(bool isResponse, uint8_t *data, uint8_t len);
uint8_t iso15693_CRC_check(uint8_t *d, uint8_t n);
uint8_t iclass_CRC_check(bool isResponse, uint8_t *d, uint8_t n);

int applyIso14443a(char *exp, size_t size, uint8_t *cmd, uint8_t cmdsize, bool is_response);

void annotateIclass(char *exp, size_t size, uint8_t *cmd, uint8_t cmdsize, bool isResponse);
void annotateIso15693(char *exp, size_t size, uint8_t *cmd, uint8_t cmdsize);
void annotateTopaz(char *exp, size_t size, uint8_t *cmd, uint8_t cmdsize);
void annotateLegic(char *exp, size_t size, uint8_t *cmd, uint8_t cmdsize);
void annotateFelica(char *exp, size_t size, uint8_t *cmd, uint8_t cmdsize);
void annotateIso7816(char *exp, size_t size, uint8_t *cmd, uint8_t cmdsize);
void annotateIso14443b(char *exp, size_t size, uint8_t *cmd, uint8_t cmdsize);
void annotateIso14443a(char *exp, size_t size, uint8_t *cmd, uint8_t cmdsize, bool is_response);
void annotateMfDesfire(char *exp, size_t size, uint8_t *cmd, uint8_t cmdsize);
const char *mfpGetAnnotationForCode(uint8_t code);
const char *mfpGetEncryptedForCode(uint8_t code);
const char *mfpGetResponseMacedForCode(uint8_t code);
const char *mfpGetCommandMacedForCode(uint8_t code);
void annotateMfPlus(char *exp, size_t size, uint8_t *cmd, uint8_t cmdsize);
void annotateMifare(char *exp, size_t size, uint8_t *cmd, uint8_t cmdsize,
                    const uint8_t *parity, uint8_t paritysize, bool isResponse);
void annotateLTO(char *exp, size_t size, uint8_t *cmd, uint8_t cmdsize);
void annotateCryptoRF(char *exp, size_t size, uint8_t *cmd, uint8_t cmdsize);

void annotateSeos(char *exp, size_t size, uint8_t *cmd, uint8_t cmdsize);

bool DecodeMifareData(uint8_t *cmd, uint8_t cmdsize, uint8_t *parity, bool isResponse, uint8_t *mfData, size_t *mfDataLen, const uint64_t *dicKeys, uint32_t dicKeysCount);
bool NTParityChk(AuthData_t *ad, uint32_t ntx);
bool NestedCheckKey(uint64_t key, AuthData_t *ad, uint8_t *cmd, uint8_t cmdsize, uint8_t *parity);
bool CheckCrypto1Parity(const uint8_t *cmd_enc, uint8_t cmdsize, uint8_t *cmd, const uint8_t *parity_enc);
uint64_t GetCrypto1ProbableKey(AuthData_t *ad);

#endif // CMDHFLIST
