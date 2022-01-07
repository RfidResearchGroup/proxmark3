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

#ifndef ELITE_CRACK_H
#define ELITE_CRACK_H

//Crack status, see below
#define LOCLASS_CRACKED         0x0100
#define LOCLASS_BEING_CRACKED   0x0200
#define LOCLASS_CRACK_FAILED    0x0400

/**
  This is how we expect each 'entry' in a dumpfile to look
**/
typedef struct {
    uint8_t csn[8];
    uint8_t cc_nr[12];
    uint8_t mac[4];
} loclass_dumpdata_t;


void permutekey(const uint8_t key[8], uint8_t dest[8]);
/**
 * Permutes  a key from iclass specific format to NIST format
 * @brief permutekey_rev
 * @param key
 * @param dest
 */
void permutekey_rev(const uint8_t key[8], uint8_t dest[8]);

/**
 * Perform a bruteforce against a file which has been saved by pm3
 *
 * @brief bruteforceFile
 * @param filename
 * @param keytable an arrah (128 x 16 bit ints). This is where the keydata is stored.
 * OBS! the upper part of the 16 bits store crack-status,
 * @return
 */
int bruteforceFile(const char *filename, uint16_t keytable[]);
/**
 *
 * @brief Same as above, if you don't care about the returned keytable (results only printed on screen)
 * @param filename
 * @return
 */
int bruteforceFileNoKeys(const char *filename);
/**
 * @brief Same as bruteforcefile, but uses a an array of loclass_dumpdata_t instead
 * @param dump
 * @param dumpsize
 * @param keytable
 * @return
 */
int bruteforceDump(uint8_t dump[], size_t dumpsize, uint16_t keytable[]);

/**
 * @brief Performs brute force attack against a dump-data item, containing csn, cc_nr and mac.
 *This method calculates the hash1 for the CSN, and determines what bytes need to be bruteforced
 *on the fly. If it finds that more than three bytes need to be bruteforced, it aborts.
 *It updates the keytable with the findings, also using the upper half of the 16-bit ints
 *to signal if the particular byte has been cracked or not.
 *
 * @param loclass_dumpdata_t The dumpdata from iclass reader attack.
 * @param keytable where to write found values.
 * @return
 */
int bruteforceItem(loclass_dumpdata_t item, uint16_t keytable[]);
/**
 * Hash1 takes CSN as input, and determines what bytes in the keytable will be used
 * when constructing the K_sel.
 * @param csn the CSN used
 * @param k output
 */
void hash1(const uint8_t *csn, uint8_t *k);
void hash2(uint8_t *key64, uint8_t *outp_keytable);
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
int calculateMasterKey(uint8_t first16bytes[], uint8_t kcus[]);

/**
 * @brief Test function
 * @return
 */
int testElite(bool slowtests);

/**
      Here are some pretty optimal values that can be used to recover necessary data in only
      eight auth attempts.
// CSN                                        HASH1                                      Bytes recovered //
{ {0x00,0x0B,0x0F,0xFF,0xF7,0xFF,0x12,0xE0} , {0x01,0x01,0x00,0x00,0x45,0x01,0x45,0x45 } ,{0,1 }},
{ {0x00,0x13,0x94,0x7e,0x76,0xff,0x12,0xe0} , {0x02,0x0c,0x01,0x00,0x45,0x01,0x45,0x45} , {2,12}},
{ {0x2a,0x99,0xac,0x79,0xec,0xff,0x12,0xe0} , {0x07,0x45,0x0b,0x00,0x45,0x01,0x45,0x45} , {7,11}},
{ {0x17,0x12,0x01,0xfd,0xf7,0xff,0x12,0xe0} , {0x03,0x0f,0x00,0x00,0x45,0x01,0x45,0x45} , {3,15}},
{ {0xcd,0x56,0x01,0x7c,0x6f,0xff,0x12,0xe0} , {0x04,0x00,0x08,0x00,0x45,0x01,0x45,0x45} , {4,8}},
{ {0x4b,0x5e,0x0b,0x72,0xef,0xff,0x12,0xe0} , {0x0e,0x06,0x08,0x00,0x45,0x01,0x45,0x45} , {6,14}},
{ {0x00,0x73,0xd8,0x75,0x58,0xff,0x12,0xe0} , {0x0b,0x09,0x0f,0x00,0x45,0x01,0x05,0x45} , {9,5}},
{ {0x0c,0x90,0x32,0xf3,0x5d,0xff,0x12,0xe0} , {0x0d,0x0f,0x0a,0x00,0x45,0x01,0x05,0x45} , {10,13}},

**/

#endif
