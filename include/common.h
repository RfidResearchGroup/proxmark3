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
// 0 - no debug messages 1 - error messages 2 - all messages 4 - extended debug mode
#define MF_DBG_NONE          0
#define MF_DBG_ERROR         1
#define MF_DBG_ALL           2
#define MF_DBG_EXTENDED      4
extern int MF_DBGLEVEL;

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
// last 4k sector = signature
// second last 4k sector = settings
// third last 4k sector = default MF keys dictionary
// forth last 4k sector = default LF keys dictionary

#ifndef FLASH_MEM_BLOCK_SIZE
# define FLASH_MEM_BLOCK_SIZE   256
#endif

#ifndef FLASH_MEM_MAX_SIZE
# define FLASH_MEM_MAX_SIZE     0x3FFFF  // (262143)
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
# define FLASH_MEM_SIGNATURE_OFFSET (FLASH_MEM_MAX_SIZE - FLASH_MEM_SIGNATURE_LEN)
#endif

#ifdef WITH_FLASH
#ifndef T55XX_CONFIG_LEN
# define T55XX_CONFIG_LEN sizeof( t55xx_config )
#endif

#ifndef T55XX_CONFIG_OFFSET
# define T55XX_CONFIG_OFFSET (FLASH_MEM_MAX_4K_SECTOR - 0x2000)
#endif

#ifndef DEFAULT_T55XX_KEYS_OFFSET
# define DEFAULT_T55XX_KEYS_OFFSET (FLASH_MEM_MAX_4K_SECTOR - 0x3000)
#endif

#ifndef DEFAULT_MF_KEYS_OFFSET
# define DEFAULT_MF_KEYS_OFFSET (FLASH_MEM_MAX_4K_SECTOR - 0x4000)
#endif

#ifndef DEFAULT_ICLASS_KEYS_OFFSET
# define DEFAULT_ICLASS_KEYS_OFFSET (FLASH_MEM_MAX_4K_SECTOR - 0x5000)
#endif
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
