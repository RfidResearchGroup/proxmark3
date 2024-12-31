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
// RDV4 flash constants
//-----------------------------------------------------------------------------

#ifndef __PMFLASH_H
#define __PMFLASH_H

#include "common.h"

// RDV40 Section
// 256KB divided into 4K sectors.
// +--------+-------------+---------+--------------------------+
// | Sector | 256KB addr* |  Size   | Description              |
// +--------+-------------+---------+--------------------------+
// | N      |   0x3F000   | 1 * 4KB | signature                |
// | N-1    |   0x3E000   | 1 * 4KB | reserved for future use  |
// +--------+-------------+---------+--------------------------+
//
// * For different memory size than 256KB the address is not valid.
//   Please instead refer to Sector number, where N is the last
//   4KB secotr of the memory in question.

#ifndef FLASH_MEM_BLOCK_SIZE
# define FLASH_MEM_BLOCK_SIZE   256
#endif

#ifndef FLASH_MEM_MAX_SIZE_P
# define FLASH_MEM_MAX_SIZE_P(p64k) (1024 * 64 * (p64k))
#endif

#ifndef FLASH_MEM_MAX_4K_SECTOR_P
# define FLASH_MEM_MAX_4K_SECTOR_P(p64k)  (FLASH_MEM_MAX_SIZE_P(p64k) - 4096)
#endif

#define FLASH_RESERVED_TRAILING_4K_SECTORS 2

#ifndef FLASH_MEM_ID_LEN
# define FLASH_MEM_ID_LEN 8
#endif

#ifndef FLASH_MEM_SIGNATURE_LEN
# define FLASH_MEM_SIGNATURE_LEN 128
#endif

// -1 for historical compatibility with already released Proxmark3 RDV4.0 devices
#ifndef FLASH_MEM_SIGNATURE_OFFSET_P
# define FLASH_MEM_SIGNATURE_OFFSET_P(p64k) (FLASH_MEM_MAX_SIZE_P(p64k) - FLASH_MEM_SIGNATURE_LEN - 1)
#endif

#ifndef T55XX_CONFIG_LEN
# define T55XX_CONFIG_LEN sizeof( t55xx_configurations_t )
#endif

#define T55XX_CONFIG_FILE "cfg_t55xx.bin"

// T55XX PWD stored in spiffs
#define T55XX_KEYS_FILE "dict_t55xx.bin"
#define T55XX_KEY_LENGTH 4

// iClass keys stored in spiffs
#define ICLASS_KEYS_FILE "dict_iclass.bin"
#define ICLASS_KEY_LENGTH 8

// Mifare keys stored in spiffs
#define MF_KEYS_FILE "dict_mf.bin"
#define MF_KEY_LENGTH 6

// RDV40,  validation structure to help identifying that client/firmware is talking with RDV40
typedef struct {
    uint8_t magic[4];
    uint8_t flashid[FLASH_MEM_ID_LEN];
    uint8_t signature[FLASH_MEM_SIGNATURE_LEN];
} PACKED rdv40_validation_t;


#endif // __PMFLASH_H
