//-----------------------------------------------------------------------------
// (c) 2012 Roel Verdult
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Hitag2 type prototyping
//-----------------------------------------------------------------------------
// HitagS added 
//-----------------------------------------------------------------------------

#ifndef _HITAG2_H_
#define _HITAG2_H_

#ifdef _MSC_VER
#define PACKED
#else
#define PACKED __attribute__((packed))
#endif

typedef enum {
	RHTSF_CHALLENGE			  = 01,
	RHTSF_KEY				  = 02,
	WHTSF_CHALLENGE           = 03,
	WHTSF_KEY                 = 04,
	RHT2F_PASSWORD            = 21,
	RHT2F_AUTHENTICATE        = 22,
	RHT2F_CRYPTO              = 23,
	WHT2F_CRYPTO              = 24,
	RHT2F_TEST_AUTH_ATTEMPTS  = 25,
	RHT2F_UID_ONLY            = 26,
} hitag_function;

typedef struct {
	byte_t password[4];
} PACKED rht2d_password;

typedef struct {
	byte_t NrAr[8];
	byte_t data[4];
} PACKED rht2d_authenticate;

typedef struct {
	byte_t key[6];
	byte_t data[4];
} PACKED rht2d_crypto;

typedef union {
	rht2d_password pwd;
	rht2d_authenticate auth;
	rht2d_crypto crypto;
} hitag_data;

#endif
