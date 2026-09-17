//-----------------------------------------------------------------------------
//  Copyright Iceman 2022
//
//  This program is free software: you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with this program.  If not, see <https://www.gnu.org/licenses/>.
//
//-----------------------------------------------------------------------------
// linear congruential generator (LCG)
//-----------------------------------------------------------------------------

#ifndef RANDOMS_H__
#define RANDOMS_H__

#include <stdlib.h>
#include <stdint.h>

typedef struct generator_s {
    const char *Name;
    void (*Parse)(uint32_t seed, uint8_t key[], const size_t keylen);
} generator_t;
// generator_t array are expected to be NULL terminated

void make_key_rand_n(uint32_t seed, uint8_t key[], const size_t keylen);
void make_key_borland_n(uint32_t seed, uint8_t key[], const size_t keylen);
void make_key_recipies_n(uint32_t seed, uint8_t key[], const size_t keylen);
void make_key_glibc_n(uint32_t seed, uint8_t key[], const size_t keylen);
void make_key_ansic_n(uint32_t seed, uint8_t key[], const size_t keylen);
void make_key_turbopascal_n(uint32_t seed, uint8_t key[], const size_t keylen);
void make_key_posix_rand_r_n(uint32_t seed, uint8_t key[], const size_t keylen);
void make_key_ms_rand_r_n(uint32_t seed, uint8_t key[], const size_t keylen);
#endif

