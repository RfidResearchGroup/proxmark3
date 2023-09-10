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
// 256kb divided into 4k sectors.
//
// 0x3F000 - 1 4kb sector = signature
// 0x3E000 - 1 4kb sector = settings
// 0x3D000 - 1 4kb sector = default T55XX keys dictionary
// 0x3B000 - 1 4kb sector = default ICLASS keys dictionary
// 0x38000 - 3 4kb sectors = default MFC keys dictionary
//
#ifndef FLASH_MEM_BLOCK_SIZE
# define FLASH_MEM_BLOCK_SIZE   256
#endif

#ifndef FLASH_MEM_MAX_SIZE
# define FLASH_MEM_MAX_SIZE     0x40000  // (262144)
#endif

#ifndef FLASH_MEM_MAX_4K_SECTOR
# define FLASH_MEM_MAX_4K_SECTOR   0x3F000
#endif

#ifndef FLASH_MEM_ID_LEN
# define FLASH_MEM_ID_LEN 8
#endif

#ifndef FLASH_MEM_SIGNATURE_LEN
# define FLASH_MEM_SIGNATURE_LEN 128
#endif

#ifndef FLASH_MEM_SIGNATURE_OFFSET
// -1 for historical compatibility with already released Proxmark3 RDV4.0 devices
# define FLASH_MEM_SIGNATURE_OFFSET (FLASH_MEM_MAX_SIZE - FLASH_MEM_SIGNATURE_LEN - 1)
#endif

#ifndef T55XX_CONFIG_LEN
# define T55XX_CONFIG_LEN sizeof( t55xx_configurations_t )
#endif

#ifndef T55XX_CONFIG_OFFSET
# define T55XX_CONFIG_OFFSET (FLASH_MEM_MAX_4K_SECTOR - 0x2000)
#endif

// Reserved space for T55XX PWD = 4 kb
#ifndef DEFAULT_T55XX_KEYS_OFFSET
# define DEFAULT_T55XX_KEYS_LEN (0x1000)
# define DEFAULT_T55XX_KEYS_OFFSET (T55XX_CONFIG_OFFSET - DEFAULT_T55XX_KEYS_LEN)
# define DEFAULT_T55XX_KEYS_MAX ((DEFAULT_T55XX_KEYS_LEN - 2) / 4)
#endif

// Reserved space for iClass keys = 4 kb
#ifndef DEFAULT_ICLASS_KEYS_OFFSET
# define DEFAULT_ICLASS_KEYS_LEN (0x1000)
# define DEFAULT_ICLASS_KEYS_OFFSET (DEFAULT_T55XX_KEYS_OFFSET - DEFAULT_ICLASS_KEYS_LEN)
# define DEFAULT_ICLASS_KEYS_MAX ((DEFAULT_ICLASS_KEYS_LEN - 2) / 8)
#endif

// Reserved space for MIFARE Keys = 12 kb
#ifndef DEFAULT_MF_KEYS_OFFSET
# define DEFAULT_MF_KEYS_LEN (0x3000)
# define DEFAULT_MF_KEYS_OFFSET (DEFAULT_ICLASS_KEYS_OFFSET - DEFAULT_MF_KEYS_LEN)
# define DEFAULT_MF_KEYS_MAX ((DEFAULT_MF_KEYS_LEN - 2) / 6)
#endif

// RDV40,  validation structure to help identifying that client/firmware is talking with RDV40
typedef struct {
    uint8_t magic[4];
    uint8_t flashid[FLASH_MEM_ID_LEN];
    uint8_t signature[FLASH_MEM_SIGNATURE_LEN];
} PACKED rdv40_validation_t;

// SPIFFS current allocates 192KB of the 256KB available.
#ifndef FLASH_SPIFFS_ALLOCATED_SIZE
# define FLASH_SPIFFS_ALLOCATED_SIZE (1024 * 192)
#endif

#endif // __PMFLASH_H
