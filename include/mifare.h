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
	ISO14A_CONNECT = 1,
	ISO14A_NO_DISCONNECT = 2,
	ISO14A_APDU = 4,
	ISO14A_RAW = 8,
	ISO14A_REQUEST_TRIGGER = 0x10,
	ISO14A_APPEND_CRC = 0x20,
	ISO14A_SET_TIMEOUT = 0x40
} iso14a_command_t;

#endif // _MIFARE_H_
