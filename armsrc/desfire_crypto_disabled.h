#ifndef __DESFIRE_CRYPTO_H
#define __DESFIRE_CRYPTO_H

#include "common.h"
#include "desfire.h"

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
