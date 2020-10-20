//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
// 2016, 2017 marshmellow, iceman
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency EM4x05 commands
//-----------------------------------------------------------------------------

#ifndef CMDLFEM4X05_H__
#define CMDLFEM4X05_H__

#include "common.h"


#define EM_SERIAL_BLOCK 1
#define EM_CONFIG_BLOCK 4
#define EM4305_PROT1_BLOCK 14
#define EM4305_PROT2_BLOCK 15
#define EM4469_PROT_BLOCK 3


#define EM4305_INFO_BLOCK          0x00
#define EM4305_UID_BLOCK           0x01
#define EM4305_PWD_BLOCK           0x02
#define EM4305_CONFIGURATION_BLOCK 0x04


// config blocks
#define EM4305_DEFAULT_CONFIG_BLOCK      0x0002008F  // ASK/ BIPHASE , data rate 32, 4 data blocks

#define EM4305_EM_UNIQUE_CONFIG_BLOCK    0x0001805F  // ASK, EM4x02/unique - manchester, data rate 64, 2 data blocks
#define EM4305_PAXTON_CONFIG_BLOCK       0x0001805F  // ASK, EM4x02/paxton - manchester, data rate 64, 2 data blocks
#define EM4305_VISA2000_CONFIG_BLOCK     0x0001805F  // ASK, data rate 64, 3 data blocks
#define EM4305_VIKING_CONFIG_BLOCK       0x0001805F  // ASK, data rate 32, Manchester, 2 data blocks
#define EM4305_NORALSY_CONFIG_BLOCK      0x0001805F  // ASK, data rate 32, 3 data blocks
#define EM4305_PRESCO_CONFIG_BLOCK       0x0001805F  // ASK, data rate 32, Manchester, 4 data blocks
#define EM4305_SECURAKEY_CONFIG_BLOCK    0x0001805F  // ASK, Manchester, data rate 40, 3 data blocks


typedef enum {
    EM_UNKNOWN,
    EM_4205,
    EM_4305,
    EM_4X69,
} em_tech_type_t;

int CmdLFEM4X05(const char *Cmd);

bool em4x05_isblock0(uint32_t *word);
int em4x05_read_word_ext(uint8_t addr, uint32_t pwd, bool usePwd, uint32_t *word);

int CmdEM4x05Demod(const char *Cmd);
int CmdEM4x05Dump(const char *Cmd);
int CmdEM4x05Read(const char *Cmd);
int CmdEM4x05Write(const char *Cmd);
int CmdEM4x05Wipe(const char *Cmd);
int CmdEM4x05Info(const char *Cmd);
int CmdEM4x05Chk(const char *Cmd);
int CmdEM4x05Unlock(const char *Cmd);
int CmdEM4x05Sniff(const char *Cmd);
int CmdEM4x05Brute(const char *Cmd);

#endif
