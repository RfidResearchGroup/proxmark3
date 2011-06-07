//-----------------------------------------------------------------------------
// Hagen Fritsch - June 2010
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.

//-----------------------------------------------------------------------------
// Interlib Definitions
//-----------------------------------------------------------------------------

#ifndef __COMMON_H
#define __COMMON_H

#include <stdint.h>

//-----------------------------------------------------------------------------
// ISO 14443A
//-----------------------------------------------------------------------------
typedef struct {
	uint8_t atqa[2];
	uint8_t  sak;
	uint8_t  ats_len;
	uint8_t  ats[20]; //FIXME: size?
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

#endif
