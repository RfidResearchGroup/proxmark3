//-----------------------------------------------------------------------------
// Iceman, 2014
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency MIFARE Desfire commands
//-----------------------------------------------------------------------------
#ifndef __MFDESFIRE_H
#define __MFDESFIRE_H

#include "common.h"

int CmdHFMFDes(const char *Cmd);

char *getCardSizeStr(uint8_t fsize);
char *getProtocolStr(uint8_t id);
char *getVersionStr(uint8_t major, uint8_t minor);
int getKeySettings(uint8_t *aid);

// Ev1 card limits
#define MAX_NUM_KEYS                0x0F
#define MAX_APPLICATION_COUNT       28
#define MAX_FILE_COUNT              32
#define MAX_FRAME_SIZE              60
#define FRAME_PAYLOAD_SIZE          (MAX_FRAME_SIZE - 5)

#define NOT_YET_AUTHENTICATED       0xFF



#endif
