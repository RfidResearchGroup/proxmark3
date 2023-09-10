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
// Generator commands
//-----------------------------------------------------------------------------

#ifndef GENERATOR_H__
#define GENERATOR_H__

#include "common.h"

uint32_t ul_ev1_pwdgen_def(const uint8_t *uid);
uint32_t ul_ev1_pwdgenA(const uint8_t *uid);
uint32_t ul_ev1_pwdgenB(const uint8_t *uid);
uint32_t ul_ev1_pwdgenC(const uint8_t *uid);
uint32_t ul_ev1_pwdgenD(const uint8_t *uid);
uint32_t ul_ev1_pwdgenE(const uint8_t *uid);
uint32_t ul_ev1_pwdgenF(const uint8_t *uid);
uint32_t ul_ev1_pwdgenG(const uint8_t *uid, const uint8_t *mfg);

uint16_t ul_ev1_packgen_def(const uint8_t *uid);
uint16_t ul_ev1_packgenA(const uint8_t *uid);
uint16_t ul_ev1_packgenB(const uint8_t *uid);
uint16_t ul_ev1_packgenC(const uint8_t *uid);
uint16_t ul_ev1_packgenD(const uint8_t *uid);
uint16_t ul_ev1_packgenE(const uint8_t *uid);
uint16_t ul_ev1_packgenG(const uint8_t *uid, const uint8_t *mfg);

uint32_t ul_c_otpgenA(const uint8_t *uid);

int mfc_algo_ving_one(uint8_t *uid, uint8_t sector, uint8_t keytype, uint64_t *key);
int mfc_algo_ving_all(uint8_t *uid, uint8_t *keys);

int mfc_algo_yale_one(uint8_t *uid, uint8_t sector, uint8_t keytype, uint64_t *key);
int mfc_algo_yale_all(uint8_t *uid, uint8_t *keys);

int mfc_algo_saflok_one(uint8_t *uid, uint8_t sector, uint8_t keytype, uint64_t *key);
int mfc_algo_saflok_all(uint8_t *uid, uint8_t *keys);

int mfc_algo_mizip_one(const uint8_t *uid, uint8_t sector, uint8_t keytype, uint64_t *key);
int mfc_algo_mizip_all(uint8_t *uid, uint8_t *keys);

int mfc_algo_di_one(uint8_t *uid, uint8_t sector, uint8_t keytype, uint64_t *key);
int mfc_algo_di_all(uint8_t *uid, uint8_t *keys);

int mfc_algo_sky_one(uint8_t *uid, uint8_t sector, uint8_t keytype, uint64_t *key);
int mfc_algo_sky_all(uint8_t *uid, uint8_t *keys);

int mfc_generate4b_nuid(uint8_t *uid, uint8_t *nuid);

int mfc_algo_touch_one(uint8_t *uid, uint8_t sector, uint8_t keytype, uint64_t *key);

uint32_t lf_t55xx_white_pwdgen(uint32_t id);

int mfdes_kdf_input_gallagher(uint8_t *uid, uint8_t uidLen, uint8_t keyNo, uint32_t aid, uint8_t *kdfInputOut, uint8_t *kdfInputLen);

int generator_selftest(void);
#endif
