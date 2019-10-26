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
//-----------------------------------------------------------------------------
// ISO 14443B
//-----------------------------------------------------------------------------
typedef struct {
    uint8_t uid[10];
    uint8_t uidlen;
    uint8_t atqb[7];
    uint8_t chipid;
    uint8_t cid;
} PACKED iso14b_card_select_t;

typedef enum ISO14B_COMMAND {
    ISO14B_CONNECT = (1 << 0),
    ISO14B_DISCONNECT = (1 << 1),
    ISO14B_APDU = (1 << 2),
    ISO14B_RAW = (1 << 3),
    ISO14B_REQUEST_TRIGGER = (1 << 4),
    ISO14B_APPEND_CRC = (1 << 5),
    ISO14B_SELECT_STD = (1 << 6),
    ISO14B_SELECT_SR = (1 << 7),
    ISO14B_SET_TIMEOUT = (1 << 8),
} iso14b_command_t;

typedef enum ISO15_COMMAND {
    ISO15_CONNECT = (1 << 0),
    ISO15_NO_DISCONNECT = (1 << 1),
    ISO15_RAW = (1 << 2),
    ISO15_APPEND_CRC = (1 << 3),
    ISO15_HIGH_SPEED = (1 << 4),
    ISO15_READ_RESPONSE = (1 << 5)
} iso15_command_t;

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
} smartcard_command_t;

//-----------------------------------------------------------------------------
// FeliCa
//-----------------------------------------------------------------------------
// IDm  = ID manufacturer
// mc = manufactureCode
// mc1 mc2 u1 u2 u3 u4 u5 u6
// PMm  = Product manufacturer
// icCode =
//    ic1 = ROM
//    ic2 = IC
// maximum response time =
//    B3(request service)
//    B4(request response)
//    B5(authenticate)
//    B6(read)
//    B7(write)
//    B8()

// ServiceCode  2bytes  (access-rights)
// FileSystem = 1 Block = 16 bytes
typedef struct {
    uint8_t IDm[8];
    uint8_t code[2];
    uint8_t uid[6];
    uint8_t PMm[8];
    uint8_t iccode[2];
    uint8_t mrt[6];
    uint8_t servicecode[2];
} PACKED felica_card_select_t;

typedef struct {
    uint8_t sync[2];
    uint8_t length[1];
    uint8_t cmd_code[1];
    uint8_t IDm[8];
    uint8_t node_number[1];
    uint8_t node_key_versions[2];
} PACKED felica_request_service_response_t;

typedef struct {
    uint8_t sync[2];
    uint8_t length[1];
    uint8_t cmd_code[1];
    uint8_t IDm[8];
    uint8_t mode[1];
} PACKED felica_request_request_response_t;

typedef struct {
    uint8_t sync[2];
    uint8_t length[1];
    uint8_t cmd_code[1];
    uint8_t IDm[8];
    uint8_t status_flag1[1];
    uint8_t status_flag2[1];
    uint8_t number_of_block[1];
    uint8_t block_data[16];
    uint8_t block_element_number[1];
} PACKED felica_read_without_encryption_response_t;

typedef enum FELICA_COMMAND {
    FELICA_CONNECT = (1 << 0),
    FELICA_NO_DISCONNECT = (1 << 1),
    FELICA_RAW = (1 << 3),
    FELICA_APPEND_CRC = (1 << 5),
    FELICA_NO_SELECT = (1 << 6),
} felica_command_t;

#endif // _MIFARE_H_
