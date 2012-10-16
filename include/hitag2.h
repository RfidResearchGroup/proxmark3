//-----------------------------------------------------------------------------
// (c) 2012 Roel Verdult
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Hitag2 type prototyping
//-----------------------------------------------------------------------------

#ifndef _HITAG2_H_
#define _HITAG2_H_

typedef enum {
	RHT2F_PASSWORD            = 21,
	RHT2F_AUTHENTICATE        = 22,
  RHT2F_CRYPTO              = 23,
  RHT2F_TEST_AUTH_ATTEMPTS  = 25,
} hitag_function;

typedef struct {
	byte_t password[4];
} PACKED rht2d_password;

typedef struct {
	byte_t NrAr[8];
} PACKED rht2d_authenticate;

typedef struct {
	byte_t key[4];
} PACKED rht2d_crypto;

typedef union {
	rht2d_password pwd;
	rht2d_authenticate auth;
  rht2d_crypto crypto;
} hitag_data;

#endif
