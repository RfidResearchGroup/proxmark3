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

uint32_t ul_ev1_pwdgenA(uint8_t *uid);
uint32_t ul_ev1_pwdgenB(uint8_t *uid);
uint32_t ul_ev1_pwdgenC(uint8_t *uid);
uint32_t ul_ev1_pwdgenD(uint8_t *uid);

uint16_t ul_ev1_packgenA(uint8_t *uid);
uint16_t ul_ev1_packgenB(uint8_t *uid);
uint16_t ul_ev1_packgenC(uint8_t *uid);
uint16_t ul_ev1_packgenD(uint8_t *uid);

int mfc_algo_ving_one(uint8_t *uid, uint8_t sector, uint64_t *key);
int mfc_algo_ving_all(uint8_t *uid, uint8_t *keys);

int mfc_algo_yale_one(uint8_t *uid, uint8_t sector, uint64_t *key);
int mfc_algo_yale_all(uint8_t *uid, uint8_t *keys);

int mfc_algo_saflok_one(uint8_t *uid, uint8_t sector, uint64_t *key);
int mfc_algo_saflok_all(uint8_t *uid, uint8_t *keys);

int mfc_algo_saflok_one(uint8_t *uid, uint8_t sector, uint64_t *key);
int mfc_algo_saflok_all(uint8_t *uid, uint8_t *keys);

int mfc_algo_mizip_one(uint8_t *uid, uint8_t sector, uint64_t *key);
int mfc_algo_mizip_all(uint8_t *uid, uint8_t *keys);

int mfc_algo_di_one(uint8_t *uid, uint8_t sector, uint64_t *key);
int mfc_algo_di_all(uint8_t *uid, uint8_t *keys);

int mfc_algo_sky_one(uint8_t *uid, uint8_t sector, uint64_t *key);
int mfc_algo_sky_all(uint8_t *uid, uint8_t *keys);

int generator_selftest();
#endif
