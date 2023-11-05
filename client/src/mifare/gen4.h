//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------
// High frequency ISO14443A commands
//-----------------------------------------------------------------------------
#ifndef __GEN4_H
#define __GEN4_H

#define GEN4_CMD_CONFIG_GTU                0x32
#define GEN4_CMD_CONFIG_ATS                0x34
#define GEN4_CMD_CONFIG_ATQA_SAK           0x35
#define GEN4_CMD_CONFIG_UID_LEN            0x68
#define GEN4_CMD_CONFIG_UL_ENABLE          0x69
#define GEN4_CMD_CONFIG_UL_MODE            0x6A
#define GEN4_CMD_CONFIG_UL_SECTOR_COUNT    0x6A
#define GEN4_CMD_DUMP_CONFIG               0xC6
#define GEN4_CMD_FACTORY_TEST              0xCC
#define GEN4_CMD_WRITE_BLOCK               0xCD
#define GEN4_CMD_READ_BLOCK                0xCE
#define GEN4_CMD_BL0_DIRECT_WRITE_EN       0xCF
#define GEN4_CMD_SET_CONFIG                0xF0
#define GEN4_CMD_SET_CONFIG_PERMANENT      0xF1
#define GEN4_CMD_CHANGE_PASSWORD           0xFE

#endif