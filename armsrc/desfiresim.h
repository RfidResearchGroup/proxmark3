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
// DESFire emulation data structures and function prototypes
//-----------------------------------------------------------------------------

#ifndef __DESFIRESIM_H
#define __DESFIRESIM_H

#include "common.h"
#include "desfire.h"
#include "desfire_crypto.h"

// DESFire emulator memory layout (4KB BigBuf optimized for red team use)
#define DESFIRE_EMU_MEMORY_SIZE         4096
#define DESFIRE_CARD_HEADER_SIZE        32
#define DESFIRE_APP_DIR_SIZE            168   // 28 apps * 6 bytes each
#define DESFIRE_APP_DATA_SIZE           3896  // 4096 - 32 - 168 = 3896
#define DESFIRE_MAX_APPS                28    // EV1 standard limit
#define DESFIRE_MAX_FILES_PER_APP       16
#define DESFIRE_MAX_KEYS_PER_APP        14
#define DESFIRE_MAX_RESPONSE_SIZE       256   // Maximum response size for bounds checking

// Memory offsets
#define DESFIRE_CARD_HEADER_OFFSET      0x0000
#define DESFIRE_APP_DIR_OFFSET          0x0020
#define DESFIRE_APP_DATA_OFFSET         0x00C8  // 0x0020 + 168

// DESFire authentication constants
#define DESFIRE_NOT_YET_AUTHENTICATED   0xFF

// DESFire command constants (reuse existing from protocols.h where possible)
#ifndef MFDES_SELECT_APPLICATION
#define MFDES_SELECT_APPLICATION        0x5A
#endif
#ifndef MFDES_GET_APPLICATION_IDS  
#define MFDES_GET_APPLICATION_IDS       0x6A
#endif
#ifndef MFDES_GET_FILE_IDS
#define MFDES_GET_FILE_IDS              0x6F
#endif
#define MFDES_GET_FILE_ISO_IDS          0x61
#define MFDES_AUTHENTICATE              0x0A
#define MFDES_AUTHENTICATE_3DES         0x1A
#define MFDES_AUTHENTICATE_AES          0xAA
#define MFDES_READ_DATA                 0xBD
#define MFDES_WRITE_DATA                0x3D
#define MFDES_GET_FILE_SETTINGS         0xF5
#define MFDES_CREATE_APPLICATION        0xCA
#define MFDES_DELETE_APPLICATION        0xDA
#define MFDES_CREATE_STD_DATA_FILE      0xCD
#define MFDES_CREATE_BACKUP_DATA_FILE   0xCB
#define MFDES_CREATE_VALUE_FILE         0xCC
#define MFDES_CREATE_LINEAR_RECORD_FILE 0xC1
#define MFDES_CREATE_CYCLIC_RECORD_FILE 0xC0
#define MFDES_DELETE_FILE               0xDF
#define MFDES_GET_VALUE                 0x6C
#define MFDES_CREDIT                    0x0C
#define MFDES_DEBIT                     0xDC
#define MFDES_LIMITED_CREDIT            0x1C
#define MFDES_WRITE_RECORD              0x3B
#define MFDES_READ_RECORDS              0xBB
#define MFDES_CLEAR_RECORD_FILE         0xEB
#define MFDES_COMMIT_TRANSACTION        0xC7
#define MFDES_ABORT_TRANSACTION         0xA7
#define MFDES_GET_KEY_SETTINGS          0x45
#define MFDES_GET_FREE_MEM              0x6E
#define MFDES_GET_DF_NAMES              0x6D
#define MFDES_GET_CARD_UID              0x51
#define MFDES_SET_CONFIGURATION         0x5C
#define MFDES_AUTHENTICATE_EV2_FIRST    0x71
#define MFDES_AUTHENTICATE_EV2_NONFIRST 0x77
#define MFDES_COMMIT_READER_ID          0xC8

// DESFire status codes
#define MFDES_OPERATION_OK              0x00
#define MFDES_AUTHENTICATION_ERROR      0xAE
#define MFDES_ADDITIONAL_FRAME          0xAF
#define MFDES_APPLICATION_NOT_FOUND     0xA0
#define MFDES_FILE_NOT_FOUND            0xF0
#define MFDES_PARAMETER_ERROR           0x9E
#define MFDES_COMMAND_ABORTED           0xCA
#define MFDES_DUPLICATE_ERROR           0x0E

// File types
typedef enum {
    DESFIRE_FILE_TYPE_STANDARD = 0x00,
    DESFIRE_FILE_TYPE_BACKUP = 0x01,
    DESFIRE_FILE_TYPE_VALUE = 0x02,
    DESFIRE_FILE_TYPE_LINEAR_RECORD = 0x03,
    DESFIRE_FILE_TYPE_CYCLIC_RECORD = 0x04
} desfire_file_type_t;

// Authentication states
typedef enum {
    DESFIRE_AUTH_NONE = 0,
    DESFIRE_AUTH_CHALLENGE_SENT,
    DESFIRE_AUTH_RESPONSE_RECEIVED,
    DESFIRE_AUTH_AUTHENTICATED
} desfire_auth_state_t;

// DESFire card header (32 bytes at offset 0x0000)
typedef struct {
    uint8_t version[8];           // DESFire version response
    uint8_t uid[10];              // Card UID
    uint8_t uidlen;               // UID length
    uint8_t num_apps;             // Number of applications (max 2)
    uint8_t master_key[16];       // Master key (up to AES-128)
    uint8_t master_key_type;      // Key type (0=DES, 1=3DES, 3=AES)
    uint8_t key_settings;         // Master key settings
    uint8_t reserved[2];          // Reserved for future use
} PACKED desfire_card_t;

// Application directory entry (6 bytes each, max 2 entries)
typedef struct {
    uint8_t aid[3];               // Application ID
    uint16_t offset;              // Offset in emulator memory
    uint8_t auth_key;             // Currently authenticated key (0xFF = none)
} PACKED desfire_app_dir_t;

// Application header in memory (8 bytes + variable data)
typedef struct {
    uint8_t aid[3];               // Application ID
    uint8_t key_settings;         // Key settings
    uint8_t num_keys;             // Number of keys (1-14)
    uint8_t num_files;            // Number of files (0-16)
    uint8_t auth_key;             // Currently authenticated key
    uint8_t reserved;             // Reserved
    // Followed by: keys array, file headers, file data
} PACKED desfire_app_t;

// File header (20 bytes - expanded for ISO support)
typedef struct {
    uint8_t file_no;              // File number (0-31)
    uint8_t file_type;            // File type (standard/backup/value/record)
    uint8_t comm_settings;        // Communication settings
    uint8_t has_iso_id;           // 1 if ISO file ID is present
    uint16_t access_rights;       // Access rights (4 nibbles)
    uint16_t iso_file_id;         // ISO file ID (if present)
    union {
        struct {                  // For standard/backup files
            uint32_t size;        // File size
        } data;
        struct {                  // For value files
            int32_t lower_limit;  // Lower limit
            int32_t upper_limit;  // Upper limit
            int32_t value;        // Current value
            uint8_t limited_credit_enabled;
        } value;
        struct {                  // For record files
            uint32_t record_size; // Size of one record
            uint32_t max_records; // Maximum number of records
            uint32_t current_records; // Current number of records
        } record;
    } settings;
    uint16_t offset;              // Offset to file data
} PACKED desfire_file_t;

// Enhanced runtime simulation state with full crypto support
typedef struct {
    uint8_t selected_app[3];      // Currently selected AID (000000 = PICC level)
    desfire_auth_state_t auth_state;  // Authentication state
    
    // Enhanced authentication context
    struct desfire_tag *crypto_ctx;  // Full DESFire crypto context
    uint8_t auth_keyno;               // Key number being authenticated
    uint8_t auth_scheme;              // Authentication scheme (DES/3DES/AES)
    uint8_t current_auth_step;        // Multi-step authentication tracking
    
    // Challenge/response state for multi-step auth
    uint8_t challenge[16];            // Current challenge data
    uint8_t response[32];             // Response buffer for complex auth
    uint8_t challenge_len;            // Challenge length (8 for DES/3DES, 16 for AES)
    uint8_t response_len;             // Response length
    
    // Session management
    uint8_t session_active;           // Boolean: is authenticated session active
    uint8_t secure_channel;           // Secure channel type (none/EV1/EV2/LRP)
    uint8_t comm_mode;                // Communication mode (plain/MAC/encrypted)
    uint16_t cmd_counter;             // Command counter for EV2/LRP
    uint8_t transaction_id[4];        // Transaction identifier for EV2
    uint8_t session_key[24];          // Session key storage
    
    // Key management cache
    uint8_t cached_key_type[DESFIRE_MAX_KEYS_PER_APP];  // Key types per app
    uint8_t cached_key_data[DESFIRE_MAX_KEYS_PER_APP * 24];  // Key data cache
    uint8_t cached_key_valid[DESFIRE_MAX_KEYS_PER_APP];      // Key validity flags
} desfire_sim_state_t;

// Function prototypes for DESFire emulation

// Memory management
void DesfireSimInit(void);
desfire_card_t *DesfireGetCard(void);
desfire_app_dir_t *DesfireGetAppDir(void);
desfire_app_t *DesfireFindApp(uint8_t *aid);
desfire_file_t *DesfireFindFile(desfire_app_t *app, uint8_t file_no);

// Command handlers  
uint8_t HandleDesfireGetVersion(uint8_t *response, uint8_t *response_len);
uint8_t HandleDesfireSelectApp(uint8_t *aid, uint8_t *response, uint8_t *response_len);
uint8_t HandleDesfireGetAppIDs(uint8_t *response, uint8_t *response_len);
uint8_t HandleDesfireGetFileIDs(uint8_t *response, uint8_t *response_len);
// Enhanced authentication handlers
uint8_t HandleDesfireAuthenticate(uint8_t keyno, uint8_t *data, uint8_t len, uint8_t *response, uint8_t *response_len);
uint8_t HandleDesfireAuthenticateISO(uint8_t keyno, uint8_t *data, uint8_t len, uint8_t *response, uint8_t *response_len);
uint8_t HandleDesfireAuthenticateAES(uint8_t keyno, uint8_t *data, uint8_t len, uint8_t *response, uint8_t *response_len);
uint8_t HandleDesfireAdditionalFrame(uint8_t *data, uint8_t len, uint8_t *response, uint8_t *response_len);

// Authentication state management
void DesfireInitCryptoContext(void);
void DesfireClearSession(void);
bool DesfireIsAuthenticated(void);
uint8_t DesfireGetAuthKeyType(uint8_t *aid, uint8_t keyno);
void DesfireSetSessionKey(uint8_t *session_key, uint8_t key_type);
bool DesfireValidateMAC(uint8_t *data, uint8_t len, uint8_t *mac);
void DesfireCalculateMAC(uint8_t *data, uint8_t len, uint8_t *mac);
uint8_t HandleDesfireReadData(uint8_t file_no, uint32_t offset, uint32_t length, uint8_t *response, uint8_t *response_len);
uint8_t HandleDesfireCreateApp(uint8_t *aid, uint8_t key_settings, uint8_t num_keys, uint8_t *response, uint8_t *response_len);
uint8_t HandleDesfireDeleteApp(uint8_t *aid, uint8_t *response, uint8_t *response_len);
uint8_t HandleDesfireCreateStdDataFile(uint8_t *data, uint8_t len, uint8_t *response, uint8_t *response_len);
uint8_t HandleDesfireCreateBackupDataFile(uint8_t *data, uint8_t len, uint8_t *response, uint8_t *response_len);
uint8_t HandleDesfireCreateValueFile(uint8_t *data, uint8_t len, uint8_t *response, uint8_t *response_len);
uint8_t HandleDesfireCreateLinearRecordFile(uint8_t *data, uint8_t len, uint8_t *response, uint8_t *response_len);
uint8_t HandleDesfireCreateCyclicRecordFile(uint8_t *data, uint8_t len, uint8_t *response, uint8_t *response_len);
uint8_t HandleDesfireDeleteFile(uint8_t file_no, uint8_t *response, uint8_t *response_len);
uint8_t HandleDesfireGetFileSettings(uint8_t file_no, uint8_t *response, uint8_t *response_len);
uint8_t HandleDesfireWriteData(uint8_t file_no, uint32_t offset, uint32_t length, uint8_t *data, uint8_t *response, uint8_t *response_len);
uint8_t HandleDesfireGetValue(uint8_t file_no, uint8_t *response, uint8_t *response_len);
uint8_t HandleDesfireCredit(uint8_t file_no, int32_t value, uint8_t *response, uint8_t *response_len);
uint8_t HandleDesfireDebit(uint8_t file_no, int32_t value, uint8_t *response, uint8_t *response_len);
uint8_t HandleDesfireLimitedCredit(uint8_t file_no, int32_t value, uint8_t *response, uint8_t *response_len);
uint8_t HandleDesfireWriteRecord(uint8_t file_no, uint32_t offset, uint32_t length, uint8_t *data, uint8_t *response, uint8_t *response_len);
uint8_t HandleDesfireReadRecords(uint8_t file_no, uint32_t offset, uint32_t length, uint8_t *response, uint8_t *response_len);
uint8_t HandleDesfireClearRecordFile(uint8_t file_no, uint8_t *response, uint8_t *response_len);
uint8_t HandleDesfireGetKeySettings(uint8_t *response, uint8_t *response_len);
uint8_t HandleDesfireGetCardUID(uint8_t *response, uint8_t *response_len);
uint8_t HandleDesfireSetConfiguration(uint8_t option, uint8_t *data, uint8_t len, uint8_t *response, uint8_t *response_len);
uint8_t HandleDesfireGetDFNames(uint8_t *response, uint8_t *response_len);
uint8_t HandleDesfireGetFreeMem(uint8_t *response, uint8_t *response_len);
uint8_t HandleDesfireGetFileISOIDs(uint8_t *response, uint8_t *response_len);

// Utility functions
uint8_t DesfireGetCardVersion(void);
uint8_t DesfireGetKeySize(uint8_t key_type);
bool DesfireCheckAccess(desfire_file_t *file, uint8_t operation, uint8_t auth_key);
void DesfireGenerateChallenge(uint8_t *challenge, uint8_t len);
uint8_t DesfireGetKeyForAuth(uint8_t *aid, uint8_t keyno, uint8_t key_type, uint8_t *key_out);

// Global simulation state
extern desfire_sim_state_t g_desfire_state;

// DESFire emulator memory management functions
void DesfireEmlClear(void);
int DesfireEmlSet(const uint8_t *data, uint32_t offset, uint32_t length);
int DesfireEmlGet(uint8_t *data, uint32_t offset, uint32_t length);

#endif