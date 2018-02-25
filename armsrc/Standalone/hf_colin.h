//-----------------------------------------------------------------------------
// Colin Brigato 2016, 2017
// Christian Herrmann, 2017
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// StandAlone Mod
//-----------------------------------------------------------------------------

#ifndef __HF_COLIN_H
#define __HF_COLIN_H

#include "iso14443a.h"
#include "printf.h"
#include "protocols.h"
#include "standalone.h" // standalone definitions
#include <stdbool.h>    // for bool

#define _RED_ "\x1b[31m"
#define _GREEN_ "\x1b[32m"
#define _YELLOW_ "\x1b[33m"
#define _BLUE_ "\x1b[34m"
#define _MAGENTA_ "\x1b[35m"
#define _CYAN_ "\x1b[36m"
#define _WHITE_ "\x1b[0m"
#define _ORANGE_ _YELLOW_

/*
#define _WHITE_ 0xc0
#define _GREEN_ 0xc1
#define _RED_ 0xc2
#define _BLUE_ 0xc3
#define _YELLOW_ 0xc4
#define _ORANGE_ 0xc5
#define _CYAN_ 0xc6
*/
/*
#define BRIGHT 1
#define RED 31
#define BG_BLACK 40
printf("%c[%d;%d;%dmHello World", 0x1B, BRIGHT, RED, BG_BLACK);
*/
/*
#define _ESC_ 0x1B
#define _WHITE_ 0xc0
#define _GREEN_ 0xc1
#define _RED_ 0xc2
#define _BLUE_ 0xc3
#define _YELLOW_ 0xc4
#define _ORANGE_ 0xc5
#define _CYAN_ 0xc6
*/

int cjat91_saMifareChkKeys(uint8_t blockNo, uint8_t keyType, bool clearTrace, uint8_t keyCount, uint8_t *datain, uint64_t *key);
void e_MifareECardLoad(uint32_t arg0, uint32_t arg1, uint32_t arg2, uint8_t *datain);
void saMifareMakeTag(void);
int saMifareCSetBlock(uint32_t arg0, uint32_t arg1, uint32_t arg2, uint8_t *datain);

#endif /* __HF_COLIN_H */