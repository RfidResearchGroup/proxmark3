//-----------------------------------------------------------------------------
// Borrowed initially from https://github.com/nfc-tools/libfreefare
// Copyright (C) 2010, Romain Tartiere.
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

#ifndef __DESFIRE_CRYPTO_H
#define __DESFIRE_CRYPTO_H

#include "common.h"
#include "mifare.h"
#include "desfire.h"
#include "mbedtls/aes.h"
#include "mbedtls/des.h"

/* Mifare DESFire EV1 Application crypto operations */
//#define APPLICATION_CRYPTO_DES    0x00
//#define APPLICATION_CRYPTO_3K3DES 0x40
//#define APPLICATION_CRYPTO_AES    0x80

typedef enum {
    MCD_SEND,
    MCD_RECEIVE
} MifareCryptoDirection;

typedef enum {
    MCO_ENCYPHER,
    MCO_DECYPHER
} MifareCryptoOperation;

#define MDCM_MASK 0x000F

#define CMAC_NONE 0

// Data send to the PICC is used to update the CMAC
#define CMAC_COMMAND 0x010
// Data received from the PICC is used to update the CMAC
#define CMAC_VERIFY  0x020

// MAC the command (when MDCM_MACED)
#define MAC_COMMAND 0x100
// The command returns a MAC to verify (when MDCM_MACED)
#define MAC_VERIFY  0x200

#define ENC_COMMAND 0x1000
#define NO_CRC      0x2000

#define MAC_MASK   0x0F0
#define CMAC_MACK  0xF00

/* Communication mode */
#define MDCM_PLAIN      0x00
#define MDCM_MACED      0x01
#define MDCM_ENCIPHERED 0x03

/* Error code managed by the library */
#define CRYPTO_ERROR            0x01

typedef enum {
    AS_LEGACY,
    AS_NEW
} DesfireAuthScheme;

/*
typedef enum {
    MDFT_STANDARD_DATA_FILE             = 0x00,
    MDFT_BACKUP_DATA_FILE               = 0x01,
    MDFT_VALUE_FILE_WITH_BACKUP         = 0x02,
    MDFT_LINEAR_RECORD_FILE_WITH_BACKUP = 0x03,
    MDFT_CYCLIC_RECORD_FILE_WITH_BACKUP = 0x04
} DesfireFileType;

typedef enum {
    OPERATION_OK                        = 0x00,
    NO_CHANGES                          = 0x0c,
    OUT_OF_EEPROM_ERROR                 = 0x0e,
    ILLEGAL_COMMAND_CODE                = 0x1c,
    INTEGRITY_ERROR                     = 0x1e,
    NO_SUCH_KEY                         = 0x40,
    LENGTH_ERROR                        = 0x7e,
    PERMISSION_DENIED                   = 0x9d,
    PARAMETER_ERROR                     = 0x9e,
    APPLICATION_NOT_FOUND               = 0xa0,
    APPL_INTEGRITY_ERROR                = 0xa1,
    AUTHENTICATION_ERROR                = 0xae,
    ADDITIONAL_FRAME                    = 0xaf,
    BOUNDARY_ERROR                      = 0xbe,
    PICC_INTEGRITY_ERROR                = 0xc1,
    COMMAND_ABORTED                     = 0xca,
    PICC_DISABLED_ERROR                 = 0xcd,
    COUNT_ERROR                         = 0xce,
    DUPLICATE_ERROR                     = 0xde,
    EEPROM_ERROR                        = 0xee,
    FILE_NOT_FOUND                      = 0xf0,
    FILE_INTEGRITY_ERROR                = 0xf1
} DesfireStatus;

typedef enum {
    CREATE_APPLICATION                  = 0xca,
    DELETE_APPLICATION                  = 0xda,
    GET_APPLICATION_IDS                 = 0x6a,
    SELECT_APPLICATION                  = 0x5a,
    FORMAT_PICC                         = 0xfc,
    GET_VERSION                         = 0x60,
    READ_DATA                           = 0xbd,
    WRITE_DATA                          = 0x3d,
    GET_VALUE                           = 0x6c,
    CREDIT                              = 0x0c,
    DEBIT                               = 0xdc,
    LIMITED_CREDIT                      = 0x1c,
    WRITE_RECORD                        = 0x3b,
    READ_RECORDS                        = 0xbb,
    CLEAR_RECORD_FILE                   = 0xeb,
    COMMIT_TRANSACTION                  = 0xc7,
    ABORT_TRANSACTION                   = 0xa7,
    GET_FREE_MEMORY                     = 0x6e,
    GET_FILE_IDS                        = 0x6f,
    GET_FILE_SETTINGS                   = 0xf5,
    GET_DF_NAMES                        = 0x6d,
    CHANGE_FILE_SETTINGS                = 0x5f,
    CREATE_STD_DATA_FILE                = 0xcd,
    CREATE_BACKUP_DATA_FILE             = 0xcb,
    CREATE_VALUE_FILE                   = 0xcc,
    CREATE_LINEAR_RECORD_FILE           = 0xc1,
    CREATE_CYCLIC_RECORD_FILE           = 0xc0,
    DELETE_FILE                         = 0xdf,
    AUTHENTICATE                        = 0x0a,  // AUTHENTICATE_NATIVE
    AUTHENTICATE_ISO                    = 0x1a,  // AUTHENTICATE_STANDARD
    AUTHENTICATE_AES                    = 0xaa,
    CHANGE_KEY_SETTINGS                 = 0x54,
    GET_KEY_SETTINGS                    = 0x45,
    CHANGE_KEY                          = 0xc4,
    GET_KEY_VERSION                     = 0x64,
    AUTHENTICATION_FRAME                = 0xAF
} DesfireCmd;
*/

#define DESFIRE_KEY(key) ((struct desfire_key *) key)
struct desfire_key {
    DesfireCryptoAlgorithm type;
    uint8_t data[24];
    uint8_t cmac_sk1[24];
    uint8_t cmac_sk2[24];
    uint8_t aes_version;
};
typedef struct desfire_key *desfirekey_t;

#define DESFIRE(tag) ((struct desfire_tag *) tag)
struct desfire_tag {
    iso14a_card_select_t info;
    int active;
    uint8_t last_picc_error;
    uint8_t last_internal_error;
    uint8_t last_pcd_error;
    desfirekey_t session_key;
    DesfireAuthScheme authentication_scheme;
    uint8_t authenticated_key_no;

    uint8_t ivect[DESFIRE_MAX_CRYPTO_BLOCK_SIZE];
    uint8_t cmac[16];
    uint8_t *crypto_buffer;
    size_t crypto_buffer_size;
    uint32_t selected_application;
};
typedef struct desfire_tag *desfiretag_t;
void des_encrypt(void *out, const void *in, const void *key);
void des_decrypt(void *out, const void *in, const void *key);
void tdes_nxp_receive(const void *in, void *out, size_t length, const void *key, unsigned char iv[8], int keymode);
void tdes_nxp_send(const void *in, void *out, size_t length, const void *key, unsigned char iv[8], int keymode);
void Desfire_des_key_new(const uint8_t value[8], desfirekey_t key);
void Desfire_3des_key_new(const uint8_t value[16], desfirekey_t key);
void Desfire_des_key_new_with_version(const uint8_t value[8], desfirekey_t key);
void Desfire_3des_key_new_with_version(const uint8_t value[16], desfirekey_t key);
void Desfire_3k3des_key_new(const uint8_t value[24], desfirekey_t key);
void Desfire_3k3des_key_new_with_version(const uint8_t value[24], desfirekey_t key);
void Desfire_2k3des_key_new_with_version(const uint8_t value[16], desfirekey_t key);
void Desfire_aes_key_new(const uint8_t value[16], desfirekey_t key);
void Desfire_aes_key_new_with_version(const uint8_t value[16], uint8_t version, desfirekey_t key);
uint8_t Desfire_key_get_version(desfirekey_t key);
void Desfire_key_set_version(desfirekey_t key, uint8_t version);
void Desfire_session_key_new(const uint8_t rnda[], const uint8_t rndb[], desfirekey_t authkey, desfirekey_t key);

void *mifare_cryto_preprocess_data(desfiretag_t tag, void *data, size_t *nbytes, size_t offset, int communication_settings);
void *mifare_cryto_postprocess_data(desfiretag_t tag, void *data, size_t *nbytes, int communication_settings);
void mifare_cypher_single_block(desfirekey_t  key, uint8_t *data, uint8_t *ivect, MifareCryptoDirection direction, MifareCryptoOperation operation, size_t block_size);
void mifare_cypher_blocks_chained(desfiretag_t tag, desfirekey_t key, uint8_t *ivect, uint8_t *data, size_t data_size, MifareCryptoDirection direction, MifareCryptoOperation operation);
size_t key_block_size(const desfirekey_t  key);
size_t padded_data_length(const size_t nbytes, const size_t block_size);
size_t maced_data_length(const desfirekey_t  key, const size_t nbytes);
size_t enciphered_data_length(const desfiretag_t tag, const size_t nbytes, int communication_settings);
void cmac_generate_subkeys(desfirekey_t key);
void cmac(const desfirekey_t  key, uint8_t *ivect, const uint8_t *data, size_t len, uint8_t *cmac);

#endif
