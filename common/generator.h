//-----------------------------------------------------------------------------
// Copyright (C) 2019 iceman <iceman at iuse.se>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
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

uint16_t ul_ev1_packgen_def(uint8_t *uid);
uint16_t ul_ev1_packgenA(const uint8_t *uid);
uint16_t ul_ev1_packgenB(uint8_t *uid);
uint16_t ul_ev1_packgenC(uint8_t *uid);
uint16_t ul_ev1_packgenD(const uint8_t *uid);

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
