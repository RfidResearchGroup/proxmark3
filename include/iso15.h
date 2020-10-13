//-----------------------------------------------------------------------------
// (c) 2020 Iceman
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// ISO 15693 type prototyping
//-----------------------------------------------------------------------------

#ifndef _ISO15_H_
#define _ISO15_H_

#include "common.h"
typedef struct {
    uint8_t uid[10];
    uint8_t uidlen;
    uint8_t atqb[7];
    uint8_t chipid;
    uint8_t cid;
} PACKED iso14b_card_select_t;

typedef enum ISO15_COMMAND {
    ISO15_CONNECT = (1 << 0),
    ISO15_NO_DISCONNECT = (1 << 1),
    ISO15_RAW = (1 << 2),
    ISO15_APPEND_CRC = (1 << 3),
    ISO15_HIGH_SPEED = (1 << 4),
    ISO15_READ_RESPONSE = (1 << 5)
} iso15_command_t;


#endif // _ISO15_H_
