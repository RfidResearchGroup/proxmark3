/*
 *
 * Various Utilities
 *
 * Copyright (C) 2010, Flavio D. Garcia, Peter van Rossum, Roel Verdult
 * and Ronny Wichers Schreur. Radboud University Nijmegen
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef _UTIL_H_
#define _UTIL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

#define AEND  "\x1b[0m"

#define _BLUE_(s) "\x1b[34m" s AEND
#define _RED_(s) "\x1b[31m" s AEND
#define _GREEN_(s) "\x1b[32m" s AEND
#define _YELLOW_(s) "\x1b[33m" s AEND
#define _MAGENTA_(s) "\x1b[35m" s AEND
#define _CYAN_(s) "\x1b[36m" s AEND
#define _WHITE_(s) "\x1b[37m" s AEND

void num_to_bytes(uint64_t n, size_t len, uint8_t *dst);
void print_bytes(const uint8_t *pbtData, const size_t szLen);

#ifdef __cplusplus
}
#endif
#endif // _UTIL_H_
