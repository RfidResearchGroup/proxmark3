//-----------------------------------------------------------------------------
// Hagen Fritsch - June 2010
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//
//-----------------------------------------------------------------------------
// Interlib Definitions
//-----------------------------------------------------------------------------

#ifndef __COMMON_H
#define __COMMON_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <at91sam7s512.h>
typedef unsigned char byte_t;

// debug
#define DBG_NONE          0 // no messages
#define DBG_ERROR         1 // errors only
#define DBG_INFO          2 // errors + info messages
#define DBG_DEBUG         3 // errors + info + debug messages
#define DBG_EXTENDED      4 // errors + info + debug + breaking debug messages
extern int DBGLEVEL;

// Flashmem spi baudrate
extern uint32_t FLASHMEM_SPIBAUDRATE;

// reader voltage field detector
#define MF_MINFIELDV      4000

#ifndef MIN
# define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif

#ifndef MAX
# define MAX(a, b) (((a) > (b)) ? (a) : (b))
#endif

#ifndef ABS
# define ABS(a) ( ((a)<0) ? -(a) : (a) )
#endif
#define RAMFUNC __attribute((long_call, section(".ramfunc")))

// RDV40 Section
// 256kb divided into 4k sectors.
//
// 0x3F000 - 1 4kb sector = signature
// 0x3E000 - 1 4kb sector = settings
// 0x3D000 - 1 4kb sector = default T55XX keys dictionary
// 0x3B000 - 1 4kb sector = default ICLASS keys dictionary
// 0x39000 - 2 4kb sectors = default MFC keys dictionary
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
# define T55XX_CONFIG_LEN sizeof( t55xx_config )
#endif

#ifndef T55XX_CONFIG_OFFSET
# define T55XX_CONFIG_OFFSET (FLASH_MEM_MAX_4K_SECTOR - 0x2000)
#endif

// Reserved space for T55XX PWD = 4 kb
#ifndef DEFAULT_T55XX_KEYS_OFFSET
# define DEFAULT_T55XX_KEYS_OFFSET (FLASH_MEM_MAX_4K_SECTOR - 0x3000)
#endif

// Reserved space for iClass keys = 4 kb
#ifndef DEFAULT_ICLASS_KEYS_OFFSET
# define DEFAULT_ICLASS_KEYS_OFFSET (FLASH_MEM_MAX_4K_SECTOR - 0x4000)
#endif

// Reserved space for MIFARE Keys = 8 kb
#ifndef DEFAULT_MF_KEYS_OFFSET
# define DEFAULT_MF_KEYS_OFFSET (FLASH_MEM_MAX_4K_SECTOR - 0x6000)
#endif



// RDV40,  validation structure to help identifying that client/firmware is talking with RDV40
typedef struct {
    uint8_t magic[4];
    uint8_t flashid[FLASH_MEM_ID_LEN];
    uint8_t signature[FLASH_MEM_SIGNATURE_LEN];
} __attribute__((__packed__)) rdv40_validation_t;


#ifdef __cplusplus
}
#endif
#endif
