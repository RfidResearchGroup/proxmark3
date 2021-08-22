#ifndef __DESFIRE_H
#define __DESFIRE_H

#include "common.h"

#define DESFIRE_MAX_CRYPTO_BLOCK_SIZE 16
#define DESFIRE_MAX_KEY_SIZE  24
#define DESFIRE_MAC_LENGTH 4
#define DESFIRE_CMAC_LENGTH 8

typedef enum {
    T_DES = 0x00,
    T_3DES = 0x01, //aka 2K3DES
    T_3K3DES = 0x02,
    T_AES = 0x03
} DesfireCryptoAlgorithm;

#endif
