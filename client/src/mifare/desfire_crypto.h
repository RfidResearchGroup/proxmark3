#ifndef __DESFIRE_CRYPTO_H
#define __DESFIRE_CRYPTO_H

#include "common.h"
#include "mifare.h" // structs
//#include "../../armsrc/printf.h"
//#include "../../armsrc/desfire.h"
//#include "../../armsrc/iso14443a.h"


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

enum DESFIRE_CRYPTOALGO {
    T_DES = 0x00,
    T_3DES = 0x01, //aka 2K3DES
    T_3K3DES = 0x02,
    T_AES = 0x03
};

enum DESFIRE_AUTH_SCHEME {
    AS_LEGACY,
    AS_NEW
};



#define DESFIRE_KEY(key) ((struct desfire_key *) key)
struct desfire_key {
    enum DESFIRE_CRYPTOALGO type;
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
    enum DESFIRE_AUTH_SCHEME authentication_scheme;
    uint8_t authenticated_key_no;

    uint8_t ivect[MAX_CRYPTO_BLOCK_SIZE];
    uint8_t cmac[16];
    uint8_t *crypto_buffer;
    size_t crypto_buffer_size;
    uint32_t selected_application;
};
typedef struct desfire_tag *desfiretag_t;

typedef unsigned long DES_KS[16][2];   /* Single-key DES key schedule */
typedef unsigned long DES3_KS[48][2];  /* Triple-DES key schedule */

extern int Asmversion; /* 1 if we're linked with an asm version, 0 if C */

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
