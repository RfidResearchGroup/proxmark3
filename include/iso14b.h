//-----------------------------------------------------------------------------
// (c) 2020 Iceman
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// ISO 14443B type prototyping
//-----------------------------------------------------------------------------

#ifndef _ISO14B_H_
#define _ISO14B_H_

#include "common.h"
typedef struct {
    uint8_t uid[10];
    uint8_t uidlen;
    uint8_t atqb[7];
    uint8_t chipid;
    uint8_t cid;
} PACKED iso14b_card_select_t;

typedef struct {
    uint8_t uid[4];
    uint8_t pc;
    uint8_t fc;
} PACKED iso14b_cts_card_select_t;

typedef enum ISO14B_COMMAND {
    ISO14B_CONNECT = (1 << 0),
    ISO14B_DISCONNECT = (1 << 1),
    ISO14B_APDU = (1 << 2),
    ISO14B_RAW = (1 << 3),
    ISO14B_REQUEST_TRIGGER = (1 << 4),
    ISO14B_APPEND_CRC = (1 << 5),
    ISO14B_SELECT_STD = (1 << 6),
    ISO14B_SELECT_SR = (1 << 7),
    ISO14B_SET_TIMEOUT = (1 << 8),
    ISO14B_SEND_CHAINING = (1 << 9),
    ISO14B_SELECT_CTS = (1 << 10),
    ISO14B_CLEARTRACE = (1 << 11),
} iso14b_command_t;

#endif // _ISO14B_H_
