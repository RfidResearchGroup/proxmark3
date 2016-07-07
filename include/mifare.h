//-----------------------------------------------------------------------------
// (c) 2012 Roel Verdult
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// MIFARE type prototyping
//-----------------------------------------------------------------------------

#ifndef _MIFARE_H_
#define _MIFARE_H_

#include "common.h"

//-----------------------------------------------------------------------------
// ISO 14443A
//-----------------------------------------------------------------------------
typedef struct {
	byte_t uid[10];
	byte_t uidlen;
	byte_t atqa[2];
	byte_t sak;
	byte_t ats_len;
	byte_t ats[256];
} __attribute__((__packed__)) iso14a_card_select_t;

typedef enum ISO14A_COMMAND {
	ISO14A_CONNECT = 			(1 << 0),
	ISO14A_NO_DISCONNECT =		(1 << 1),
	ISO14A_APDU = 				(1 << 2),
	ISO14A_RAW =				(1 << 3),
	ISO14A_REQUEST_TRIGGER =	(1 << 4),
	ISO14A_APPEND_CRC =			(1 << 5),
	ISO14A_SET_TIMEOUT =		(1 << 6),
	ISO14A_NO_SELECT =			(1 << 7),
	ISO14A_TOPAZMODE =			(1 << 8)
} iso14a_command_t;


//-----------------------------------------------------------------------------
// ISO 14443B
//-----------------------------------------------------------------------------
typedef struct {
	byte_t uid[10];
	byte_t uidlen;
	byte_t atqb[7];
	byte_t chipid;
	byte_t cid;
} __attribute__((__packed__)) iso14b_card_select_t;


typedef enum ISO14B_COMMAND {
	ISO14B_CONNECT = 			(1 << 0),
	ISO14B_DISCONNECT =			(1 << 1),
	ISO14B_APDU = 				(1 << 2),
	ISO14B_RAW =				(1 << 3),
	ISO14B_REQUEST_TRIGGER =	(1 << 4),
	ISO14B_APPEND_CRC =			(1 << 5),
	ISO14B_SELECT_STD =			(1 << 6),
	ISO14B_SELECT_SR =			(1 << 7)
} iso14b_command_t;

//-----------------------------------------------------------------------------
// "hf 14a sim x", "hf mf sim x" attacks
//-----------------------------------------------------------------------------
typedef struct {
  uint32_t cuid;
  uint8_t  sector;
  uint8_t  keytype;
  uint32_t nonce;
  uint32_t ar;
  uint32_t nr;
  uint32_t nonce2;
  uint32_t ar2;
  uint32_t nr2;
} nonces_t;

#endif // _MIFARE_H_
