/*-
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

#ifndef __LRPCRYPTO_H
#define __LRPCRYPTO_H

#include "common.h"
#include "crypto/libpcrypto.h"

typedef struct {
    uint8_t key[CRYPTO_AES128_KEY_SIZE];
} LRPContext;

void LRPSetKey(LRPContext *ctx);


#endif // __LRPCRYPTO_H
