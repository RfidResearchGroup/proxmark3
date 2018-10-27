/*
 *  AES-CMAC from NIST Special Publication 800-38B — Recommendation for block cipher modes of operation: The CMAC mode for authentication.
 *
 *  Copyright (C) 2006-2014, Brainspark B.V.
 *  Copyright (C) 2014, Anargyros Plemenos
 *  Tests added Merkok, 2018
 *
 *  This file is part of PolarSSL (http://www.polarssl.org)
 *  Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>
 *
 *  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 *  Reference : https://polarssl.org/discussions/generic/authentication-token
 *  NIST Special Publication 800-38B — Recommendation for block cipher modes of operation: The CMAC mode for authentication.
 *  Tests here:
 *  https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_CMAC.pdf
*/

#include <stdint.h>
#include <stddef.h>
#include "aes.h"

typedef struct aes_cmac_128_context {
    aes_context aes_key;

    uint8_t K1[16];
    uint8_t K2[16];

    uint8_t X[16];

    uint8_t last[16];
    size_t last_len;
}
aes_cmac128_context;

/*
 * \brief AES-CMAC-128 context setup
 *
 * \param ctx      context to be initialized
 * \param key      secret key for AES-128
 */
void aes_cmac128_starts(aes_cmac128_context *ctx, const uint8_t K[16]);

/*
 * \brief AES-CMAC-128 process message
 *
 * \param ctx      context to be initialized
 * \param _msg     the given message
 * \param _msg_len the length of message
 */
void aes_cmac128_update(aes_cmac128_context *ctx, const uint8_t *_msg, size_t _msg_len);

/*
 * \brief AES-CMAC-128 compute T
 *
 * \param ctx      context to be initialized
 * \param T        the generated MAC which is used to validate the message
 */
void aes_cmac128_final(aes_cmac128_context *ctx, uint8_t T[16]);

/**
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if the test failed
 */
int aes_cmac_self_test( int verbose );

