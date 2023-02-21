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
/*
 * This implementation was written based on information provided by the
 * following documents:
 *
 * NIST Special Publication 800-38B
 * Recommendation for Block Cipher Modes of Operation: The CMAC Mode for Authentication
 * May 2005
 */
#include "desfire_crypto.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "commonutil.h"
#include "crc32.h"
#include "crc.h"
#include "crc16.h"        // crc16 ccitt
#include "printf.h"
#include "iso14443a.h"
#include "dbprint.h"
#include "BigBuf.h"

#ifndef AddCrc14A
# define AddCrc14A(data, len) compute_crc(CRC_14443_A, (data), (len), (data)+(len), (data)+(len)+1)
#endif

static mbedtls_des_context ctx;
static mbedtls_des3_context ctx3;
static mbedtls_aes_context actx;

static void update_key_schedules(desfirekey_t key);

static void update_key_schedules(desfirekey_t key) {
    // DES_set_key ((DES_cblock *)key->data, &(key->ks1));
    // DES_set_key ((DES_cblock *)(key->data + 8), &(key->ks2));
    // if (T_3K3DES == key->type) {
    // DES_set_key ((DES_cblock *)(key->data + 16), &(key->ks3));
    // }
}

/******************************************************************************/
void des_encrypt(void *out, const void *in, const void *key) {
    mbedtls_des_setkey_enc(&ctx, key);
    mbedtls_des_crypt_ecb(&ctx, in, out);
}

void des_decrypt(void *out, const void *in, const void *key) {
    mbedtls_des_setkey_dec(&ctx, key);
    mbedtls_des_crypt_ecb(&ctx, in, out);
}

void tdes_nxp_receive(const void *in, void *out, size_t length, const void *key, unsigned char iv[8], int keymode) {
    if (length % 8) return;
    if (keymode == 2)
        mbedtls_des3_set2key_dec(&ctx3, key);
    else
        mbedtls_des3_set3key_dec(&ctx3, key);

    uint8_t i;
    unsigned char temp[8];
    uint8_t *tin = (uint8_t *) in;
    uint8_t *tout = (uint8_t *) out;

    while (length > 0) {
        memcpy(temp, tin, 8);

        mbedtls_des3_crypt_ecb(&ctx3, tin, tout);

        for (i = 0; i < 8; i++)
            tout[i] = (unsigned char)(tout[i] ^ iv[i]);

        memcpy(iv, temp, 8);

        tin  += 8;
        tout += 8;
        length -= 8;
    }
}

void tdes_nxp_send(const void *in, void *out, size_t length, const void *key, unsigned char iv[8], int keymode) {
    if (length % 8) return;
    if (keymode == 2)
        mbedtls_des3_set2key_enc(&ctx3, key);
    else
        mbedtls_des3_set3key_enc(&ctx3, key);

    uint8_t i;
    uint8_t *tin = (uint8_t *) in;
    uint8_t *tout = (uint8_t *) out;

    while (length > 0) {
        for (i = 0; i < 8; i++) {
            tin[i] = (unsigned char)(tin[i] ^ iv[i]);
        }

        mbedtls_des3_crypt_ecb(&ctx3, tin, tout);

        memcpy(iv, tout, 8);

        tin  += 8;
        tout += 8;
        length -= 8;
    }
}



void Desfire_des_key_new(const uint8_t value[8], desfirekey_t key) {
    uint8_t data[8];
    memcpy(data, value, 8);
    for (int n = 0; n < 8; n++) {
        data[n] &= 0xFE;
    }
    Desfire_des_key_new_with_version(data, key);
}

void Desfire_des_key_new_with_version(const uint8_t value[8], desfirekey_t key) {
    if (key != NULL) {
        key->type = T_DES;
        memcpy(key->data, value, 8);
        memcpy(key->data + 8, value, 8);
        update_key_schedules(key);
    }
}

void Desfire_3des_key_new(const uint8_t value[16], desfirekey_t key) {
    uint8_t data[16];
    memcpy(data, value, 16);
    for (int n = 0; n < 8; n++) {
        data[n] &= 0xFE;
    }
    for (int n = 8; n < 16; n++) {
        data[n] |= 0x01;
    }
    Desfire_3des_key_new_with_version(data, key);
}

void Desfire_3des_key_new_with_version(const uint8_t value[16], desfirekey_t key) {
    if (key != NULL) {
        key->type = T_3DES;
        memcpy(key->data, value, 16);
        update_key_schedules(key);
    }
}

void Desfire_3k3des_key_new(const uint8_t value[24], desfirekey_t key) {
    uint8_t data[24];
    memcpy(data, value, 24);
    for (int n = 0; n < 8; n++) {
        data[n] &= 0xFE;
    }
    Desfire_3k3des_key_new_with_version(data, key);
}

void Desfire_3k3des_key_new_with_version(const uint8_t value[24], desfirekey_t key) {
    if (key != NULL) {
        key->type = T_3K3DES;
        memcpy(key->data, value, 24);
        update_key_schedules(key);
    }
}

void Desfire_aes_key_new(const uint8_t value[16], desfirekey_t key) {
    Desfire_aes_key_new_with_version(value, 0, key);
}

void Desfire_aes_key_new_with_version(const uint8_t value[16], uint8_t version, desfirekey_t key) {

    if (key != NULL) {
        memcpy(key->data, value, 16);
        key->type = T_AES;
        key->aes_version = version;
    }
}

uint8_t Desfire_key_get_version(desfirekey_t key) {
    uint8_t version = 0;

    for (int n = 0; n < 8; n++) {
        version |= ((key->data[n] & 1) << (7 - n));
    }
    return version;
}

void Desfire_key_set_version(desfirekey_t key, uint8_t version) {
    for (int n = 0; n < 8; n++) {
        uint8_t version_bit = ((version & (1 << (7 - n))) >> (7 - n));
        key->data[n] &= 0xFE;
        key->data[n] |= version_bit;
        if (key->type == T_DES) {
            key->data[n + 8] = key->data[n];
        } else {
            // Write ~version to avoid turning a 3DES key into a DES key
            key->data[n + 8] &= 0xFE;
            key->data[n + 8] |= ~version_bit;
        }
    }
}

void Desfire_session_key_new(const uint8_t rnda[], const uint8_t rndb[], desfirekey_t authkey, desfirekey_t key) {

    uint8_t buffer[24];

    switch (authkey->type) {
        case T_DES:
            memcpy(buffer, rnda, 4);
            memcpy(buffer + 4, rndb, 4);
            Desfire_des_key_new_with_version(buffer, key);
            break;
        case T_3DES:
            memcpy(buffer, rnda, 4);
            memcpy(buffer + 4, rndb, 4);
            memcpy(buffer + 8, rnda + 4, 4);
            memcpy(buffer + 12, rndb + 4, 4);
            Desfire_3des_key_new_with_version(buffer, key);
            break;
        case T_3K3DES:
            memcpy(buffer, rnda, 4);
            memcpy(buffer + 4, rndb, 4);
            memcpy(buffer + 8, rnda + 6, 4);
            memcpy(buffer + 12, rndb + 6, 4);
            memcpy(buffer + 16, rnda + 12, 4);
            memcpy(buffer + 20, rndb + 12, 4);
            Desfire_3k3des_key_new(buffer, key);
            break;
        case T_AES:
            memcpy(buffer, rnda, 4);
            memcpy(buffer + 4, rndb, 4);
            memcpy(buffer + 8, rnda + 12, 4);
            memcpy(buffer + 12, rndb + 12, 4);
            Desfire_aes_key_new(buffer, key);
            break;
    }
}

static size_t key_macing_length(desfirekey_t key);

// iceman,  see memxor inside string.c, dest/src swapped..
static void xor(const uint8_t *ivect, uint8_t *data, const size_t len) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= ivect[i];
    }
}

void cmac_generate_subkeys(desfirekey_t key) {
    int kbs = key_block_size(key);
    const uint8_t R = (kbs == 8) ? 0x1B : 0x87;

    uint8_t l[kbs];
    memset(l, 0, kbs);

    uint8_t ivect[kbs];
    memset(ivect, 0, kbs);

    mifare_cypher_blocks_chained(NULL, key, ivect, l, kbs, MCD_RECEIVE, MCO_ENCYPHER);

    bool txor = false;

    // Used to compute CMAC on complete blocks
    memcpy(key->cmac_sk1, l, kbs);

    txor = l[0] & 0x80;

    lsl(key->cmac_sk1, kbs);

    if (txor) {
        key->cmac_sk1[kbs - 1] ^= R;
    }

    // Used to compute CMAC on the last block if non-complete
    memcpy(key->cmac_sk2, key->cmac_sk1, kbs);

    txor = key->cmac_sk1[0] & 0x80;

    lsl(key->cmac_sk2, kbs);

    if (txor) {
        key->cmac_sk2[kbs - 1] ^= R;
    }
}

void cmac(const desfirekey_t key, uint8_t *ivect, const uint8_t *data, size_t len, uint8_t *cmac) {
    int kbs = key_block_size(key);
    if (kbs == 0) {
        return;
    }

    uint8_t *buffer = BigBuf_malloc(padded_data_length(len, kbs));

    memcpy(buffer, data, len);

    if ((!len) || (len % kbs)) {
        buffer[len++] = 0x80;
        while (len % kbs) {
            buffer[len++] = 0x00;
        }
        xor(key->cmac_sk2, buffer + len - kbs, kbs);
    } else {
        xor(key->cmac_sk1, buffer + len - kbs, kbs);
    }

    mifare_cypher_blocks_chained(NULL, key, ivect, buffer, len, MCD_SEND, MCO_ENCYPHER);

    memcpy(cmac, ivect, kbs);
    //free(buffer);
}

size_t key_block_size(const desfirekey_t key) {
    if (key == NULL) {
        return 0;
    }

    size_t block_size = 8;
    switch (key->type) {
        case T_DES:
        case T_3DES:
        case T_3K3DES:
            block_size = 8;
            break;
        case T_AES:
            block_size = 16;
            break;
    }
    return block_size;
}

/*
 * Size of MACing produced with the key.
 */
static size_t key_macing_length(const desfirekey_t key) {
    size_t mac_length = DESFIRE_MAC_LENGTH;
    switch (key->type) {
        case T_DES:
        case T_3DES:
            mac_length = DESFIRE_MAC_LENGTH;
            break;
        case T_3K3DES:
        case T_AES:
            mac_length = DESFIRE_CMAC_LENGTH;
            break;
    }
    return mac_length;
}

/*
 * Size required to store nbytes of data in a buffer of size n*block_size.
 */
size_t padded_data_length(const size_t nbytes, const size_t block_size) {
    if ((!nbytes) || (nbytes % block_size))
        return ((nbytes / block_size) + 1) * block_size;
    else
        return nbytes;
}

/*
 * Buffer size required to MAC nbytes of data
 */
size_t maced_data_length(const desfirekey_t key, const size_t nbytes) {
    return nbytes + key_macing_length(key);
}
/*
 * Buffer size required to encipher nbytes of data and a two bytes CRC.
 */
size_t enciphered_data_length(const desfiretag_t tag, const size_t nbytes, int communication_settings) {
    size_t crc_length = 0;
    if (!(communication_settings & NO_CRC)) {
        switch (DESFIRE(tag)->authentication_scheme) {
            case AS_LEGACY:
                crc_length = 2;
                break;
            case AS_NEW:
                crc_length = 4;
                break;
        }
    }

    size_t block_size = DESFIRE(tag)->session_key ? key_block_size(DESFIRE(tag)->session_key) : 1;

    return padded_data_length(nbytes + crc_length, block_size);
}

void *mifare_cryto_preprocess_data(desfiretag_t tag, void *data, size_t *nbytes, size_t offset, int communication_settings) {
    uint8_t *res = data;
    uint8_t mac[4];
    size_t edl;
    bool append_mac = true;
    desfirekey_t key = DESFIRE(tag)->session_key;

    if (!key)
        return data;

    switch (communication_settings & MDCM_MASK) {
        case MDCM_PLAIN:
            if (AS_LEGACY == DESFIRE(tag)->authentication_scheme)
                break;

            /*
             * When using new authentication methods, PLAIN data transmission from
             * the PICC to the PCD are CMACed, so we have to maintain the
             * cryptographic initialisation vector up-to-date to check data
             * integrity later.
             *
             * The only difference with CMACed data transmission is that the CMAC
             * is not appended to the data send by the PCD to the PICC.
             */

            append_mac = false;

        /* pass through */
        case MDCM_MACED:
            switch (DESFIRE(tag)->authentication_scheme) {
                case AS_LEGACY:
                    if (!(communication_settings & MAC_COMMAND))
                        break;

                    /* pass through */
                    edl = padded_data_length(*nbytes - offset, key_block_size(DESFIRE(tag)->session_key)) + offset;

                    // Fill in the crypto buffer with data ...
                    memcpy(res, data, *nbytes);
                    // ... and 0 padding
                    memset(res + *nbytes, 0, edl - *nbytes);

                    mifare_cypher_blocks_chained(tag, NULL, NULL, res + offset, edl - offset, MCD_SEND, MCO_ENCYPHER);

                    memcpy(mac, res + edl - 8, 4);

                    // Copy again provided data (was overwritten by mifare_cypher_blocks_chained)
                    memcpy(res, data, *nbytes);

                    if (!(communication_settings & MAC_COMMAND))
                        break;
                    // Append MAC
                    size_t bla = maced_data_length(DESFIRE(tag)->session_key, *nbytes - offset) + offset;
                    (void)bla++;

                    memcpy(res + *nbytes, mac, 4);

                    *nbytes += 4;
                    break;
                case AS_NEW:
                    if (!(communication_settings & CMAC_COMMAND))
                        break;
                    cmac(key, DESFIRE(tag)->ivect, res, *nbytes, DESFIRE(tag)->cmac);

                    if (append_mac) {
                        size_t len = maced_data_length(key, *nbytes);
                        (void)++len;
                        memcpy(res, data, *nbytes);
                        memcpy(res + *nbytes, DESFIRE(tag)->cmac, DESFIRE_CMAC_LENGTH);
                        *nbytes += DESFIRE_CMAC_LENGTH;
                    }
                    break;
            }

            break;
        case MDCM_ENCIPHERED:
            /*  |<-------------- data -------------->|
             *  |<--- offset -->|                    |
             *  +---------------+--------------------+-----+---------+
             *  | CMD + HEADERS | DATA TO BE SECURED | CRC | PADDING |
             *  +---------------+--------------------+-----+---------+ ----------------
             *  |               |<~~~~v~~~~~~~~~~~~~>|  ^  |         |   (DES / 3DES)
             *  |               |     `---- crc16() ----'  |         |
             *  |               |                    |  ^  |         | ----- *or* -----
             *  |<~~~~~~~~~~~~~~~~~~~~v~~~~~~~~~~~~~>|  ^  |         |  (3K3DES / AES)
             *                  |     `---- crc32() ----'  |         |
             *                  |                                    | ---- *then* ----
             *                  |<---------------------------------->|
             *                            encypher()/decypher()
             */

            if (!(communication_settings & ENC_COMMAND))
                break;
            edl = enciphered_data_length(tag, *nbytes - offset, communication_settings) + offset;

            // Fill in the crypto buffer with data ...
            memcpy(res, data, *nbytes);
            if (!(communication_settings & NO_CRC)) {
                // ... CRC ...
                switch (DESFIRE(tag)->authentication_scheme) {
                    case AS_LEGACY:
                        AddCrc14A(res + offset, *nbytes - offset);
                        *nbytes += 2;
                        break;
                    case AS_NEW:
                        crc32_append(res, *nbytes);
                        *nbytes += 4;
                        break;
                }
            }
            // ... and padding
            memset(res + *nbytes, 0, edl - *nbytes);

            *nbytes = edl;

            mifare_cypher_blocks_chained(tag, NULL, NULL, res + offset, *nbytes - offset, MCD_SEND, (AS_NEW == DESFIRE(tag)->authentication_scheme) ? MCO_ENCYPHER : MCO_DECYPHER);
            break;
        default:

            *nbytes = -1;
            res = NULL;
            break;
    }

    return res;

}

void *mifare_cryto_postprocess_data(desfiretag_t tag, void *data, size_t *nbytes, int communication_settings) {
    void *res = data;
    void *edata = NULL;
    uint8_t first_cmac_byte = 0x00;

    desfirekey_t key = DESFIRE(tag)->session_key;

    if (!key)
        return data;

    // Return directly if we just have a status code.
    if (1 == *nbytes)
        return res;

    switch (communication_settings & MDCM_MASK) {
        case MDCM_PLAIN:

            if (AS_LEGACY == DESFIRE(tag)->authentication_scheme)
                break;

        /* pass through */
        case MDCM_MACED:
            switch (DESFIRE(tag)->authentication_scheme) {
                case AS_LEGACY:
                    if (communication_settings & MAC_VERIFY) {
                        *nbytes -= key_macing_length(key);
                        if (*nbytes == 0) {
                            *nbytes = -1;
                            res = NULL;
#ifdef WITH_DEBUG
                            Dbprintf("No room for MAC!");
#endif
                            break;
                        }

                        size_t edl = enciphered_data_length(tag, *nbytes - 1, communication_settings);
                        edata = BigBuf_malloc(edl);

                        memcpy(edata, data, *nbytes - 1);
                        memset((uint8_t *)edata + *nbytes - 1, 0, edl - *nbytes + 1);

                        mifare_cypher_blocks_chained(tag, NULL, NULL, edata, edl, MCD_SEND, MCO_ENCYPHER);

                        if (0 != memcmp((uint8_t *)data + *nbytes - 1, (uint8_t *)edata + edl - 8, 4)) {
#ifdef WITH_DEBUG
                            Dbprintf("MACing not verified");
                            hexdump((uint8_t *)data + *nbytes - 1, key_macing_length(key), "Expect ", 0);
                            hexdump((uint8_t *)edata + edl - 8, key_macing_length(key), "Actual ", 0);
#endif
                            DESFIRE(tag)->last_pcd_error = CRYPTO_ERROR;
                            *nbytes = -1;
                            res = NULL;
                        }
                    }
                    break;
                case AS_NEW:
                    if (!(communication_settings & CMAC_COMMAND))
                        break;
                    if (communication_settings & CMAC_VERIFY) {
                        if (*nbytes < 9) {
                            *nbytes = -1;
                            res = NULL;
                            break;
                        }
                        first_cmac_byte = ((uint8_t *)data)[*nbytes - 9];
                        ((uint8_t *)data)[*nbytes - 9] = ((uint8_t *)data)[*nbytes - 1];
                    }

                    int n = (communication_settings & CMAC_VERIFY) ? 8 : 0;
                    cmac(key, DESFIRE(tag)->ivect, ((uint8_t *)data), *nbytes - n, DESFIRE(tag)->cmac);

                    if (communication_settings & CMAC_VERIFY) {
                        ((uint8_t *)data)[*nbytes - 9] = first_cmac_byte;
                        if (0 != memcmp(DESFIRE(tag)->cmac, (uint8_t *)data + *nbytes - 9, 8)) {
#ifdef WITH_DEBUG
                            Dbprintf("CMAC NOT verified :-(");
                            hexdump((uint8_t *)data + *nbytes - 9, 8, "Expect ", 0);
                            hexdump(DESFIRE(tag)->cmac, 8, "Actual ", 0);
#endif
                            DESFIRE(tag)->last_pcd_error = CRYPTO_ERROR;
                            *nbytes = -1;
                            res = NULL;
                        } else {
                            *nbytes -= 8;
                        }
                    }
                    break;
            }

            free(edata);

            break;
        case MDCM_ENCIPHERED:
            (*nbytes)--;
            bool verified = false;
            int crc_pos = 0x00;
            int end_crc_pos = 0x00;
            uint8_t x;

            /*
             * AS_LEGACY:
             * ,-----------------+-------------------------------+--------+
             * \     BLOCK n-1   |              BLOCK n          | STATUS |
             * /  PAYLOAD | CRC0 | CRC1 | 0x80? | 0x000000000000 | 0x9100 |
             * `-----------------+-------------------------------+--------+
             *
             *         <------------ DATA ------------>
             * FRAME = PAYLOAD + CRC(PAYLOAD) + PADDING
             *
             * AS_NEW:
             * ,-------------------------------+-----------------------------------------------+--------+
             * \                 BLOCK n-1     |                  BLOCK n                      | STATUS |
             * /  PAYLOAD | CRC0 | CRC1 | CRC2 | CRC3 | 0x80? | 0x0000000000000000000000000000 | 0x9100 |
             * `-------------------------------+-----------------------------------------------+--------+
             * <----------------------------------- DATA ------------------------------------->|
             *
             *         <----------------- DATA ---------------->
             * FRAME = PAYLOAD + CRC(PAYLOAD + STATUS) + PADDING + STATUS
             *                                    `------------------'
             */

            mifare_cypher_blocks_chained(tag, NULL, NULL, res, *nbytes, MCD_RECEIVE, MCO_DECYPHER);

            /*
             * Look for the CRC and ensure it is followed by NULL padding.  We
             * can't start by the end because the CRC is supposed to be 0 when
             * verified, and accumulating 0's in it should not change it.
             */
            switch (DESFIRE(tag)->authentication_scheme) {
                case AS_LEGACY:
                    crc_pos = *nbytes - 8 - 1; // The CRC can be over two blocks
                    if (crc_pos < 0) {
                        /* Single block */
                        crc_pos = 0;
                    }
                    break;
                case AS_NEW:
                    /* Move status between payload and CRC */
                    res = DESFIRE(tag)->crypto_buffer;
                    memcpy(res, data, *nbytes);

                    crc_pos = (*nbytes) - 16 - 3;
                    if (crc_pos < 0) {
                        /* Single block */
                        crc_pos = 0;
                    }
                    memcpy((uint8_t *)res + crc_pos + 1, (uint8_t *)res + crc_pos, *nbytes - crc_pos);
                    ((uint8_t *)res)[crc_pos] = 0x00;
                    crc_pos++;
                    *nbytes += 1;
                    break;
            }

            do {
                uint16_t crc_16 = 0x00;
                uint32_t crc = 0x00;
                switch (DESFIRE(tag)->authentication_scheme) {
                    case AS_LEGACY:
                        AddCrc14A((uint8_t *)res, end_crc_pos);
                        end_crc_pos = crc_pos + 2;
                        //


                        crc = crc_16;
                        break;
                    case AS_NEW:
                        end_crc_pos = crc_pos + 4;
                        crc32_ex(res, end_crc_pos, (uint8_t *)&crc);
                        break;
                }
                if (!crc) {
                    verified = true;
                    for (int n = end_crc_pos; n < *nbytes - 1; n++) {
                        uint8_t byte = ((uint8_t *)res)[n];
                        if (!((0x00 == byte) || ((0x80 == byte) && (n == end_crc_pos))))
                            verified = false;
                    }
                }
                if (verified) {
                    *nbytes = crc_pos;
                    switch (DESFIRE(tag)->authentication_scheme) {
                        case AS_LEGACY:
                            ((uint8_t *)data)[(*nbytes)++] = 0x00;
                            break;
                        case AS_NEW:
                            /* The status byte was already before the CRC */
                            break;
                    }
                } else {
                    switch (DESFIRE(tag)->authentication_scheme) {
                        case AS_LEGACY:
                            break;
                        case AS_NEW:
                            x = ((uint8_t *)res)[crc_pos - 1];
                            ((uint8_t *)res)[crc_pos - 1] = ((uint8_t *)res)[crc_pos];
                            ((uint8_t *)res)[crc_pos] = x;
                            break;
                    }
                    crc_pos++;
                }
            } while (!verified && (end_crc_pos < *nbytes));

            if (!verified) {
#ifdef WITH_DEBUG
                /* FIXME In some configurations, the file is transmitted PLAIN */
                Dbprintf("CRC not verified in decyphered stream");
#endif
                DESFIRE(tag)->last_pcd_error = CRYPTO_ERROR;
                *nbytes = -1;
                res = NULL;
            }

            break;
        default:
            Dbprintf("Unknown communication settings");
            *nbytes = -1;
            res = NULL;
            break;

    }
    return res;
}


void mifare_cypher_single_block(desfirekey_t key, uint8_t *data, uint8_t *ivect, MifareCryptoDirection direction, MifareCryptoOperation operation, size_t block_size) {
    uint8_t ovect[DESFIRE_MAX_CRYPTO_BLOCK_SIZE];
    if (direction == MCD_SEND) {
        xor(ivect, data, block_size);
    } else {
        memcpy(ovect, data, block_size);
    }

    uint8_t edata[DESFIRE_MAX_CRYPTO_BLOCK_SIZE] = {0};

    switch (key->type) {
        case T_DES:
            switch (operation) {
                case MCO_ENCYPHER:
                    //DES_ecb_encrypt ((DES_cblock *) data, (DES_cblock *) edata, &(key->ks1), DES_ENCRYPT);
                    des_encrypt(edata, data, key->data);
                    break;
                case MCO_DECYPHER:
                    //DES_ecb_encrypt ((DES_cblock *) data, (DES_cblock *) edata, &(key->ks1), DES_DECRYPT);
                    des_decrypt(edata, data, key->data);
                    break;
            }
            break;
        case T_3DES:
            switch (operation) {
                case MCO_ENCYPHER:
                    mbedtls_des3_set2key_enc(&ctx3, key->data);
                    mbedtls_des3_crypt_ecb(&ctx3, data, edata);
                    // DES_ecb_encrypt ((DES_cblock *) data,  (DES_cblock *) edata, &(key->ks1), DES_ENCRYPT);
                    // DES_ecb_encrypt ((DES_cblock *) edata, (DES_cblock *) data,  &(key->ks2), DES_DECRYPT);
                    // DES_ecb_encrypt ((DES_cblock *) data,  (DES_cblock *) edata, &(key->ks1), DES_ENCRYPT);
                    break;
                case MCO_DECYPHER:
                    mbedtls_des3_set2key_dec(&ctx3, key->data);
                    mbedtls_des3_crypt_ecb(&ctx3, data, edata);
                    // DES_ecb_encrypt ((DES_cblock *) data,  (DES_cblock *) edata, &(key->ks1), DES_DECRYPT);
                    // DES_ecb_encrypt ((DES_cblock *) edata, (DES_cblock *) data,  &(key->ks2), DES_ENCRYPT);
                    // DES_ecb_encrypt ((DES_cblock *) data,  (DES_cblock *) edata, &(key->ks1), DES_DECRYPT);
                    break;
            }
            break;
        case T_3K3DES:
            switch (operation) {
                case MCO_ENCYPHER:
                    mbedtls_des3_set3key_enc(&ctx3, key->data);
                    mbedtls_des3_crypt_ecb(&ctx3, data, edata);
                    // DES_ecb_encrypt ((DES_cblock *) data,  (DES_cblock *) edata, &(key->ks1), DES_ENCRYPT);
                    // DES_ecb_encrypt ((DES_cblock *) edata, (DES_cblock *) data,  &(key->ks2), DES_DECRYPT);
                    // DES_ecb_encrypt ((DES_cblock *) data,  (DES_cblock *) edata, &(key->ks3), DES_ENCRYPT);
                    break;
                case MCO_DECYPHER:
                    mbedtls_des3_set3key_dec(&ctx3, key->data);
                    mbedtls_des3_crypt_ecb(&ctx3, data, edata);
                    // DES_ecb_encrypt ((DES_cblock *) data,  (DES_cblock *) edata, &(key->ks3), DES_DECRYPT);
                    // DES_ecb_encrypt ((DES_cblock *) edata, (DES_cblock *) data,  &(key->ks2), DES_ENCRYPT);
                    // DES_ecb_encrypt ((DES_cblock *) data,  (DES_cblock *) edata, &(key->ks1), DES_DECRYPT);
                    break;
            }
            break;
        case T_AES:
            switch (operation) {
                case MCO_ENCYPHER: {
                    mbedtls_aes_init(&actx);
                    mbedtls_aes_setkey_enc(&actx, key->data, 128);
                    mbedtls_aes_crypt_cbc(&actx, MBEDTLS_AES_ENCRYPT, sizeof(edata), ivect, data, edata);
                    break;
                }
                case MCO_DECYPHER: {
                    mbedtls_aes_init(&actx);
                    mbedtls_aes_setkey_dec(&actx, key->data, 128);
                    mbedtls_aes_crypt_cbc(&actx, MBEDTLS_AES_DECRYPT, sizeof(edata), ivect, edata, data);
                    break;
                }
            }
            break;
    }

    memcpy(data, edata, block_size);

    if (direction == MCD_SEND) {
        memcpy(ivect, data, block_size);
    } else {
        xor(ivect, data, block_size);
        memcpy(ivect, ovect, block_size);
    }
}

/*
 * This function performs all CBC cyphering / deciphering.
 *
 * The tag argument may be NULL, in which case both key and ivect shall be set.
 * When using the tag session_key and ivect for processing data, these
 * arguments should be set to NULL.
 *
 * Because the tag may contain additional data, one may need to call this
 * function with tag, key and ivect defined.
 */
void mifare_cypher_blocks_chained(desfiretag_t tag, desfirekey_t key, uint8_t *ivect, uint8_t *data, size_t data_size, MifareCryptoDirection direction, MifareCryptoOperation operation) {
    size_t block_size;

    if (tag) {
        if (key == NULL) {
            key = DESFIRE(tag)->session_key;
        }
        if (ivect == NULL) {
            ivect = DESFIRE(tag)->ivect;
        }

        switch (DESFIRE(tag)->authentication_scheme) {
            case AS_LEGACY:
                memset(ivect, 0, DESFIRE_MAX_CRYPTO_BLOCK_SIZE);
                break;
            case AS_NEW:
                break;
        }
    }

    block_size = key_block_size(key);

    size_t offset = 0;
    while (offset < data_size) {
        mifare_cypher_single_block(key, data + offset, ivect, direction, operation, block_size);
        offset += block_size;
    }
}
