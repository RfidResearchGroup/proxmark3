//-----------------------------------------------------------------------------
// (c) 2012 Roel Verdult
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// MIFARE type prototyping
//-----------------------------------------------------------------------------

#ifndef _MIFARE_H_
#define _MIFARE_H_

#include "common.h"

#define MF_KEY_A 0
#define MF_KEY_B 1

#define MF_MAD1_SECTOR 0x00
#define MF_MAD2_SECTOR 0x10

//-----------------------------------------------------------------------------
// Common types, used by client and ARM
//-----------------------------------------------------------------------------
// New Ultralight/NTAG dump file format
// Length must be aligned to 4 bytes (UL/NTAG page)
#define MFU_DUMP_PREFIX_LENGTH 56

typedef struct {
    uint8_t version[8];
    uint8_t tbo[2];
    uint8_t tbo1[1];
    uint8_t pages;                  // max page number in dump
    uint8_t signature[32];
    uint8_t counter_tearing[3][4];  // 3 bytes counter, 1 byte tearing flag
    uint8_t data[1024];
} PACKED mfu_dump_t;

//-----------------------------------------------------------------------------
// ISO 14443A
//-----------------------------------------------------------------------------
typedef struct {
    uint8_t uid[10];
    uint8_t uidlen;
    uint8_t atqa[2];
    uint8_t sak;
    uint8_t ats_len;
    uint8_t ats[256];
} PACKED iso14a_card_select_t;

typedef enum ISO14A_COMMAND {
    ISO14A_CONNECT = (1 << 0),
    ISO14A_NO_DISCONNECT = (1 << 1),
    ISO14A_APDU = (1 << 2),
    ISO14A_RAW = (1 << 3),
    ISO14A_REQUEST_TRIGGER = (1 << 4),
    ISO14A_APPEND_CRC = (1 << 5),
    ISO14A_SET_TIMEOUT = (1 << 6),
    ISO14A_NO_SELECT = (1 << 7),
    ISO14A_TOPAZMODE = (1 << 8),
    ISO14A_NO_RATS = (1 << 9),
    ISO14A_SEND_CHAINING = (1 << 10)
} iso14a_command_t;

typedef struct {
    uint8_t *response;
    uint8_t *modulation;
    uint16_t response_n;
    uint16_t modulation_n;
    uint32_t ProxToAirDuration;
    uint8_t  par; // enough for precalculated parity of 8 Byte responses
} PACKED tag_response_info_t;

// DESFIRE_RAW flag enums
typedef enum DESFIRE_COMMAND {
    NONE         = 0x00,
    INIT         = 0x01,
    DISCONNECT   = 0x02,
    CLEARTRACE   = 0x04,
    BAR          = 0x10,
} desfire_command_t;

typedef enum {
    MFDES_AUTH_DES = 1,
    MFDES_AUTH_ISO = 2,
    MFDES_AUTH_AES = 3,
    MFDES_AUTH_PICC = 4
} mifare_des_authmode_t;

typedef enum {
    MFDES_ALGO_DES = 1,
    MFDES_ALGO_3DES = 2,
    MFDES_ALGO_3K3DES = 3,
    MFDES_ALGO_AES = 4
} mifare_des_authalgo_t;

typedef enum {
    MFDES_KDF_ALGO_NONE = 0,
    MFDES_KDF_ALGO_AN10922 = 1,
    MFDES_KDF_ALGO_GALLAGHER = 2,
} mifare_des_kdf_algo_t;

//-----------------------------------------------------------------------------
// "hf 14a sim x", "hf mf sim x" attacks
//-----------------------------------------------------------------------------
typedef struct {
    uint32_t cuid;
    uint32_t nonce;
    uint32_t ar;
    uint32_t nr;
    uint32_t at;
    uint32_t nonce2;
    uint32_t ar2;
    uint32_t nr2;
    uint8_t  sector;
    uint8_t  keytype;
    enum {
        EMPTY,
        FIRST,
        SECOND,
    } state;
} PACKED nonces_t;

//-----------------------------------------------------------------------------
// ISO 7618  Smart Card
//-----------------------------------------------------------------------------
typedef struct {
    uint8_t atr_len;
    uint8_t atr[30];
} PACKED smart_card_atr_t;

typedef enum SMARTCARD_COMMAND {
    SC_CONNECT = (1 << 0),
    SC_NO_DISCONNECT = (1 << 1),
    SC_RAW = (1 << 2),
    SC_SELECT = (1 << 3),
    SC_RAW_T0 = (1 << 4),
    SC_CLEARLOG = (1 << 5),
    SC_LOG = (1 << 6),
} smartcard_command_t;


#endif // _MIFARE_H_
