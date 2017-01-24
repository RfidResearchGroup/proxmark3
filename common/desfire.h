#ifndef __DESFIRE_H
#define __DESFIRE_H

#include <string.h>
#include <stdarg.h>
#include "aes.h"
#include "mifare.h"

#define MAX_CRYPTO_BLOCK_SIZE 16
/* Mifare DESFire EV1 Application crypto operations */
#define APPLICATION_CRYPTO_DES    0x00
#define APPLICATION_CRYPTO_3K3DES 0x40
#define APPLICATION_CRYPTO_AES    0x80

#define MAC_LENGTH 4
#define CMAC_LENGTH 8

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


enum DESFIRE_AUTH_SCHEME {
	AS_LEGACY,
	AS_NEW
};

enum DESFIRE_CRYPTOALGO {
	T_DES = 0x00,
	T_3DES = 0x01,
	T_3K3DES = 0x02,
	T_AES = 0x03
};


#define DESFIRE_KEY(key) ((struct desfire_key *) key)
struct desfire_key {
    enum DESFIRE_CRYPTOALGO type;
    uint8_t data[24];
    // DES_key_schedule ks1;
    // DES_key_schedule ks2;
    // DES_key_schedule ks3;
	AesCtx aes_ks;
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
	enum DESFIRE_AUTH_SCHEME authentication_scheme;
    uint8_t authenticated_key_no;
    
	uint8_t ivect[MAX_CRYPTO_BLOCK_SIZE];
    uint8_t cmac[16];
    uint8_t *crypto_buffer;
    size_t crypto_buffer_size;
    uint32_t selected_application;
};
typedef struct desfire_tag *desfiretag_t;


/* File types */
enum DESFIRE_FILE_TYPES {
    MDFT_STANDARD_DATA_FILE             = 0x00,
    MDFT_BACKUP_DATA_FILE               = 0x01,
    MDFT_VALUE_FILE_WITH_BACKUP         = 0x02,
    MDFT_LINEAR_RECORD_FILE_WITH_BACKUP = 0x03,
    MDFT_CYCLIC_RECORD_FILE_WITH_BACKUP = 0x04
};

enum DESFIRE_STATUS {
    OPERATION_OK 				= 0x00,
    NO_CHANGES 					= 0x0c,
    OUT_OF_EEPROM_ERROR 		= 0x0e,
    ILLEGAL_COMMAND_CODE 		= 0x1c,
    INTEGRITY_ERROR 			= 0x1e,
    NO_SUCH_KEY 				= 0x40,
    LENGTH_ERROR 				= 0x7e,
    PERMISSION_DENIED 			= 0x9d,
    PARAMETER_ERROR 			= 0x9e,
    APPLICATION_NOT_FOUND 		= 0xa0,
    APPL_INTEGRITY_ERROR 		= 0xa1,
    AUTHENTICATION_ERROR 		= 0xae,
    ADDITIONAL_FRAME 			= 0xaf,
    BOUNDARY_ERROR 				= 0xbe,
    PICC_INTEGRITY_ERROR 		= 0xc1,
    COMMAND_ABORTED 			= 0xca,
    PICC_DISABLED_ERROR 		= 0xcd,
    COUNT_ERROR 				= 0xce,
    DUPLICATE_ERROR 			= 0xde,
    EEPROM_ERROR 				= 0xee,
    FILE_NOT_FOUND 				= 0xf0,
    FILE_INTEGRITY_ERROR 		= 0xf1
};

enum DESFIRE_CMD {
    CREATE_APPLICATION 			= 0xca,
    DELETE_APPLICATION 			= 0xda,
    GET_APPLICATION_IDS 		= 0x6a,
    SELECT_APPLICATION 			= 0x5a,
    FORMAT_PICC 				= 0xfc,
    GET_VERSION 				= 0x60,
    READ_DATA 					= 0xbd,
    WRITE_DATA					= 0x3d,
    GET_VALUE 					= 0x6c,
    CREDIT 						= 0x0c,
    DEBIT 						= 0xdc,
    LIMITED_CREDIT 				= 0x1c,
    WRITE_RECORD 				= 0x3b,
    READ_RECORDS 				= 0xbb,
    CLEAR_RECORD_FILE 			= 0xeb,
    COMMIT_TRANSACTION 			= 0xc7,
    ABORT_TRANSACTION 			= 0xa7,
    GET_FREE_MEMORY             = 0x6e,
	GET_FILE_IDS 				= 0x6f,
    GET_FILE_SETTINGS 			= 0xf5,
    CHANGE_FILE_SETTINGS 		= 0x5f,
    CREATE_STD_DATA_FILE 		= 0xcd,
    CREATE_BACKUP_DATA_FILE 	= 0xcb,
    CREATE_VALUE_FILE 			= 0xcc,
    CREATE_LINEAR_RECORD_FILE 	= 0xc1,
    CREATE_CYCLIC_RECORD_FILE 	= 0xc0,
    DELETE_FILE 				= 0xdf,
    AUTHENTICATE	 			= 0x0a,  // AUTHENTICATE_NATIVE
	AUTHENTICATE_ISO 			= 0x1a,  // AUTHENTICATE_STANDARD
	AUTHENTICATE_AES 			= 0xaa,
    CHANGE_KEY_SETTINGS 		= 0x54,
    GET_KEY_SETTINGS 			= 0x45,
    CHANGE_KEY 					= 0xc4,
    GET_KEY_VERSION 			= 0x64,
    AUTHENTICATION_FRAME 		= 0xAF
};

#endif

