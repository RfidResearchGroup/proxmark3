//-----------------------------------------------------------------------------
// Copyright (C) Gerhard de Koning Gans - May 2008
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
// Work with mifare cards.
//-----------------------------------------------------------------------------
#include "mifareutil.h"

#include "appmain.h"  // tearoff hook
#include "string.h"
#include "BigBuf.h"
#include "iso14443a.h"
#include "ticks.h"
#include "dbprint.h"
#include "parity.h"
#include "commonutil.h"
#include "crc16.h"
#include "protocols.h"
#include "desfire_crypto.h"

// crypto1 helpers
void mf_crypto1_decryptEx(struct Crypto1State *pcs, const uint8_t *data_in, int len, uint8_t *data_out) {
    if (len != 1) {
        for (int i = 0; i < len; i++)
            data_out[i] = crypto1_byte(pcs, 0x00, 0) ^ data_in[i];
    } else {
        uint8_t bt = 0;
        bt |= (crypto1_bit(pcs, 0, 0) ^ BIT(data_in[0], 0)) << 0;
        bt |= (crypto1_bit(pcs, 0, 0) ^ BIT(data_in[0], 1)) << 1;
        bt |= (crypto1_bit(pcs, 0, 0) ^ BIT(data_in[0], 2)) << 2;
        bt |= (crypto1_bit(pcs, 0, 0) ^ BIT(data_in[0], 3)) << 3;
        data_out[0] = bt;
    }
    return;
}

void mf_crypto1_decrypt(struct Crypto1State *pcs, uint8_t *data, int len) {
    mf_crypto1_decryptEx(pcs, data, len, data);
}

void mf_crypto1_encrypt(struct Crypto1State *pcs, uint8_t *data, uint16_t len, uint8_t *par) {
    mf_crypto1_encryptEx(pcs, data, NULL, data, len, par);
}

void mf_crypto1_encryptEx(struct Crypto1State *pcs, const uint8_t *data_in, uint8_t *keystream, uint8_t *data_out, uint16_t len, uint8_t *par) {
    int i;
    par[0] = 0;

    for (i = 0; i < len; i++) {
        uint8_t bt = data_in[i];
        data_out[i] = crypto1_byte(pcs, keystream ? keystream[i] : 0x00, 0) ^ data_in[i];
        if ((i & 0x0007) == 0)
            par[ i >> 3 ] = 0;
        par[ i >> 3 ] |= (((filter(pcs->odd) ^ oddparity8(bt)) & 0x01) << (7 - (i & 0x0007)));
    }
}

uint8_t mf_crypto1_encrypt4bit(struct Crypto1State *pcs, uint8_t data) {
    uint8_t bt = 0;
    bt |= (crypto1_bit(pcs, 0, 0) ^ BIT(data, 0)) << 0;
    bt |= (crypto1_bit(pcs, 0, 0) ^ BIT(data, 1)) << 1;
    bt |= (crypto1_bit(pcs, 0, 0) ^ BIT(data, 2)) << 2;
    bt |= (crypto1_bit(pcs, 0, 0) ^ BIT(data, 3)) << 3;
    return bt;
}

// send X byte basic commands
uint16_t mifare_sendcmd(uint8_t cmd, uint8_t *data, uint8_t data_size, uint8_t *answer, uint16_t answer_len, uint8_t *answer_parity, uint32_t *timing) {

    uint8_t dcmd[data_size + 3];
    dcmd[0] = cmd;
    if (data_size > 0) {
        memcpy(dcmd + 1, data, data_size);
    }

    AddCrc14A(dcmd, data_size + 1);
    ReaderTransmit(dcmd, sizeof(dcmd), timing);
    uint16_t len = ReaderReceive(answer, answer_len, answer_parity);
    if (len == 0) {
        if (g_dbglevel >= DBG_ERROR) Dbprintf("%02X Cmd failed. Card timeout.", cmd);
        len = ReaderReceive(answer, answer_len, answer_parity);
    }
    return len;
}

// send 2 byte commands
uint16_t mifare_sendcmd_short(struct Crypto1State *pcs, uint8_t crypted, uint8_t cmd, uint8_t data, uint8_t *answer, uint16_t answer_len, uint8_t *answer_parity, uint32_t *timing) {
    uint16_t pos;
    uint8_t dcmd[4] = {cmd, data, 0x00, 0x00};
    uint8_t ecmd[4] = {0x00, 0x00, 0x00, 0x00};
    uint8_t par[1] = {0x00}; // 1 Byte parity is enough here
    AddCrc14A(dcmd, 2);
    memcpy(ecmd, dcmd, sizeof(dcmd));

    if (pcs && crypted) {
        par[0] = 0;
        for (pos = 0; pos < 4; pos++) {
            ecmd[pos] = crypto1_byte(pcs, 0x00, 0) ^ dcmd[pos];
            par[0] |= (((filter(pcs->odd) ^ oddparity8(dcmd[pos])) & 0x01) << (7 - pos));
        }
        ReaderTransmitPar(ecmd, sizeof(ecmd), par, timing);
    } else {
        ReaderTransmit(dcmd, sizeof(dcmd), timing);
    }

    uint16_t len = ReaderReceive(answer, answer_len, par);

    if (answer_parity) {
        *answer_parity = par[0];
    }

    if (pcs && (crypted == CRYPT_ALL)) {
        if (len == 1) {
            uint16_t res = 0;
            res |= (crypto1_bit(pcs, 0, 0) ^ BIT(answer[0], 0)) << 0;
            res |= (crypto1_bit(pcs, 0, 0) ^ BIT(answer[0], 1)) << 1;
            res |= (crypto1_bit(pcs, 0, 0) ^ BIT(answer[0], 2)) << 2;
            res |= (crypto1_bit(pcs, 0, 0) ^ BIT(answer[0], 3)) << 3;
            answer[0] = res;
        } else {
            for (pos = 0; pos < len; pos++) {
                answer[pos] = crypto1_byte(pcs, 0x00, 0) ^ answer[pos];
            }
        }
    }
    return len;
}

// mifare classic commands
int mifare_classic_auth(struct Crypto1State *pcs, uint32_t uid, uint8_t blockNo, uint8_t keyType, uint64_t ui64Key, uint8_t isNested) {
    return mifare_classic_authex(pcs, uid, blockNo, keyType, ui64Key, isNested, NULL, NULL);
}
int mifare_classic_authex(struct Crypto1State *pcs, uint32_t uid, uint8_t blockNo, uint8_t keyType, uint64_t ui64Key, uint8_t isNested, uint32_t *ntptr, uint32_t *timing) {
    return mifare_classic_authex_cmd(pcs, uid, blockNo, MIFARE_AUTH_KEYA + (keyType & 0xF), ui64Key, isNested, ntptr, NULL, NULL, timing, false, false);
}
int mifare_classic_authex_cmd(struct Crypto1State *pcs, uint32_t uid, uint8_t blockNo, uint8_t cmd, uint64_t ui64Key, uint8_t isNested,
                              uint32_t *ntptr, uint32_t *ntencptr, uint8_t *ntencparptr, uint32_t *timing, bool corruptnrar, bool corruptnrarparity) {
    // "random" reader nonce:
    uint8_t nr[4];
    num_to_bytes(prng_successor(GetTickCount(), 32), 4, nr);

    uint8_t receivedAnswer[MAX_MIFARE_FRAME_SIZE] = {0x00};
    uint8_t receivedAnswerPar[MAX_MIFARE_PARITY_SIZE] = {0x00};

    // Transmit MIFARE_CLASSIC_AUTH, 0x60 for key A, 0x61 for key B, or 0x80 for GDM backdoor
    int len = mifare_sendcmd_short(pcs, isNested, cmd, blockNo, receivedAnswer, sizeof(receivedAnswer), receivedAnswerPar, timing);
    if (len != 4) return 1;

    // Save the tag nonce (nt)
    uint32_t nt = bytes_to_num(receivedAnswer, 4);
    if (ntencptr) {
        *ntencptr = nt;
    }

    if (ntencparptr) {
        *ntencparptr = receivedAnswerPar[0];
    }

    //  ----------------------------- crypto1 create
    if (isNested) {
        crypto1_deinit(pcs);
    }

    // Init cipher with key
    crypto1_init(pcs, ui64Key);

    if (isNested == AUTH_NESTED) {
        // decrypt nt with help of new key
        nt = crypto1_word(pcs, nt ^ uid, 1) ^ nt;
    } else {
        // Load (plain) uid^nt into the cipher
        crypto1_word(pcs, nt ^ uid, 0);
    }

    // some statistic
//    if (!ntptr && (g_dbglevel >= DBG_EXTENDED))
    uint32_t nr32 = nr[0] << 24 | nr[1] << 16 | nr[2] << 8 | nr[3];
    if (g_dbglevel >= DBG_EXTENDED) {
        if (!isNested) {
            Dbprintf("auth        cmd: %02x %02x | uid: %08x | nr: %08x %s| nt: %08x %s %5i| par: %i%i%i%i %s",
                     cmd, blockNo, uid,
                     nr32, validate_prng_nonce(nr32) ? "@" : " ",
                     nt, validate_prng_nonce(nt) ? "@idx" : " idx",
                     validate_prng_nonce(nt) ? nonce16_index(nt >> 16) : -1,
                     (receivedAnswerPar[0] >> 7) & 1,
                     (receivedAnswerPar[0] >> 6) & 1,
                     (receivedAnswerPar[0] >> 5) & 1,
                     (receivedAnswerPar[0] >> 4) & 1,
                     validate_parity_nonce(nt, receivedAnswerPar[0], nt) ? "ok " : "bad");
        } else {
            Dbprintf("auth nested cmd: %02x %02x | uid: %08x | nr: %08x %s| nt: %08x %s %5i| par: %i%i%i%i %s| ntenc: %08x %s| parerr: %i%i%i%i",
                     cmd, blockNo, uid,
                     nr32, validate_prng_nonce(nr32) ? "@" : " ",
                     nt, validate_prng_nonce(nt) ? "@idx" : " idx",
                     validate_prng_nonce(nt) ? nonce16_index(nt >> 16) : -1,
                     (receivedAnswerPar[0] >> 7) & 1,
                     (receivedAnswerPar[0] >> 6) & 1,
                     (receivedAnswerPar[0] >> 5) & 1,
                     (receivedAnswerPar[0] >> 4) & 1,
                     validate_parity_nonce(*ntencptr, receivedAnswerPar[0], nt) ? "ok " : "bad",
                     *ntencptr, validate_prng_nonce(*ntencptr) ? "@" : " ",
                     ((receivedAnswerPar[0] >> 7) & 1) ^ oddparity8((*ntencptr >> 24) & 0xFF),
                     ((receivedAnswerPar[0] >> 6) & 1) ^ oddparity8((*ntencptr >> 16) & 0xFF),
                     ((receivedAnswerPar[0] >> 5) & 1) ^ oddparity8((*ntencptr >> 8) & 0xFF),
                     ((receivedAnswerPar[0] >> 4) & 1) ^ oddparity8((*ntencptr >> 0) & 0xFF)
                    );
        }
    }
    // save Nt
    if (ntptr) {
        *ntptr = nt;
    }

    // Generate (encrypted) nr+parity by loading it into the cipher (Nr)
    uint32_t pos;
    uint8_t par[1] = {0x00};
    uint8_t mf_nr_ar[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    for (pos = 0; pos < 4; pos++) {
        mf_nr_ar[pos] = crypto1_byte(pcs, nr[pos], 0) ^ nr[pos];
        par[0] |= (((filter(pcs->odd) ^ oddparity8(nr[pos])) & 0x01) << (7 - pos));
    }
    // Skip 32 bits in pseudo random generator
    nt = prng_successor(nt, 32);

    //  ar+parity
    if (corruptnrar) {
        Dbprintf("Corrupting nRaR...");
        nt ^= 1;
    }

    for (pos = 4; pos < 8; pos++) {
        nt = prng_successor(nt, 8);
        mf_nr_ar[pos] = crypto1_byte(pcs, 0x00, 0) ^ (nt & 0xff);
        par[0] |= (((filter(pcs->odd) ^ oddparity8(nt & 0xff)) & 0x01) << (7 - pos));
    }

    if (corruptnrarparity) {
        Dbprintf("Corrupting nRaR parity...");
        par[0] ^= 1;
    }

    // Transmit reader nonce and reader answer
    ReaderTransmitPar(mf_nr_ar, sizeof(mf_nr_ar), par, NULL);

    // save standard timeout
    uint32_t save_timeout = iso14a_get_timeout();

    // set timeout for authentication response
    if (save_timeout > 106) {
        iso14a_set_timeout(106);
    }

    // Receive 4 byte tag answer
    len = ReaderReceive(receivedAnswer, sizeof(receivedAnswer), receivedAnswerPar);

    iso14a_set_timeout(save_timeout);

    if (len == 0) {
        if (g_dbglevel >= DBG_EXTENDED) Dbprintf("Authentication failed. Card timeout");
        return 2;
    }

    // Supplied tag nonce
    uint32_t ntpp = prng_successor(nt, 32) ^ crypto1_word(pcs, 0, 0);
    if (ntpp != bytes_to_num(receivedAnswer, 4)) {
        if (g_dbglevel >= DBG_EXTENDED) Dbprintf("Authentication failed. Error card response");
        return 3;
    }
    return 0;
}

int mifare_classic_readblock(struct Crypto1State *pcs, uint8_t blockNo, uint8_t *blockData) {
    return mifare_classic_readblock_ex(pcs, blockNo, blockData, ISO14443A_CMD_READBLOCK);
}
int mifare_classic_readblock_ex(struct Crypto1State *pcs, uint8_t blockNo, uint8_t *blockData, uint8_t iso_byte) {

    uint8_t receivedAnswer[MAX_MIFARE_FRAME_SIZE] = {0x00};
    uint8_t receivedAnswerPar[MAX_MIFARE_PARITY_SIZE] = {0x00};

    uint16_t len = mifare_sendcmd_short(pcs, 1, iso_byte, blockNo, receivedAnswer, sizeof(receivedAnswer), receivedAnswerPar, NULL);
    if (len == 1) {
        if (g_dbglevel >= DBG_ERROR) {
            Dbprintf("Block " _YELLOW_("%3d") " Cmd 0x%02x Cmd Error %02x", blockNo, iso_byte, receivedAnswer[0]);
        }
        return 1;
    }
    if (len != 18) {
        if (g_dbglevel >= DBG_ERROR) {
            Dbprintf("Block " _YELLOW_("%3d") " Cmd 0x%02x Wrong response len, expected 18 got " _RED_("%d"), blockNo, iso_byte, len);
        }
        return 2;
    }

    uint8_t bt[2] = {0x00, 0x00};
    memcpy(bt, receivedAnswer + 16, 2);
    AddCrc14A(receivedAnswer, 16);
    if (bt[0] != receivedAnswer[16] || bt[1] != receivedAnswer[17]) {
        if (g_dbglevel >= DBG_INFO) Dbprintf("CRC response error");
        return 3;
    }

    memcpy(blockData, receivedAnswer, 16);
    return 0;
}

// mifare ultralight commands
int mifare_ul_ev1_auth(uint8_t *keybytes, uint8_t *pack) {

    uint16_t len = 0;
    uint8_t resp[4] = {0x00, 0x00, 0x00, 0x00};
    uint8_t respPar[1] = {0x00};
    uint8_t key[4] = {0x00, 0x00, 0x00, 0x00};
    memcpy(key, keybytes, 4);

    if (g_dbglevel >= DBG_EXTENDED)
        Dbprintf("EV1 Auth : %02x%02x%02x%02x", key[0], key[1], key[2], key[3]);

    len = mifare_sendcmd(MIFARE_ULEV1_AUTH, key, sizeof(key), resp, sizeof(resp), respPar, NULL);

    if (len != 4) {
        if (g_dbglevel >= DBG_ERROR) Dbprintf("Cmd Error: %02x %u", resp[0], len);
        return 0;
    }

    if (g_dbglevel >= DBG_EXTENDED)
        Dbprintf("Auth Resp: %02x%02x%02x%02x", resp[0], resp[1], resp[2], resp[3]);

    memcpy(pack, resp, 4);
    return 1;
}

int mifare_ultra_auth(uint8_t *keybytes) {

    /// 3des2k
    uint8_t random_a[8] = {1, 1, 1, 1, 1, 1, 1, 1};
    uint8_t random_b[8] = {0x00};
    uint8_t enc_random_b[8] = {0x00};
    uint8_t rnd_ab[16] = {0x00};
    uint8_t IV[8] = {0x00};
    uint8_t key[16] = {0x00};
    memcpy(key, keybytes, 16);

    uint16_t len = 0;
    uint8_t resp[19] = {0x00};
    uint8_t respPar[3] = {0, 0, 0};

    // REQUEST AUTHENTICATION
    len = mifare_sendcmd_short(NULL, CRYPT_NONE, MIFARE_ULC_AUTH_1, 0x00, resp, sizeof(resp), respPar, NULL);
    if (len != 11) {
        if (g_dbglevel >= DBG_ERROR) Dbprintf("Cmd Error: %02x", resp[0]);
        return 0;
    }

    // tag nonce.
    memcpy(enc_random_b, resp + 1, 8);

    // decrypt nonce.
    tdes_nxp_receive((void *)enc_random_b, (void *)random_b, sizeof(random_b), (const void *)key, IV, 2);
    rol(random_b, 8);
    memcpy(rnd_ab, random_a, 8);
    memcpy(rnd_ab + 8, random_b, 8);

    if (g_dbglevel >= DBG_EXTENDED) {
        Dbprintf("enc_B: %02x %02x %02x %02x %02x %02x %02x %02x",
                 enc_random_b[0], enc_random_b[1], enc_random_b[2], enc_random_b[3], enc_random_b[4], enc_random_b[5], enc_random_b[6], enc_random_b[7]);

        Dbprintf("    B: %02x %02x %02x %02x %02x %02x %02x %02x",
                 random_b[0], random_b[1], random_b[2], random_b[3], random_b[4], random_b[5], random_b[6], random_b[7]);

        Dbprintf("rnd_ab: %02x %02x %02x %02x %02x %02x %02x %02x",
                 rnd_ab[0], rnd_ab[1], rnd_ab[2], rnd_ab[3], rnd_ab[4], rnd_ab[5], rnd_ab[6], rnd_ab[7]);

        Dbprintf("rnd_ab: %02x %02x %02x %02x %02x %02x %02x %02x",
                 rnd_ab[8], rnd_ab[9], rnd_ab[10], rnd_ab[11], rnd_ab[12], rnd_ab[13], rnd_ab[14], rnd_ab[15]);
    }

    // encrypt    out, in, length, key, iv
    tdes_nxp_send(rnd_ab, rnd_ab, sizeof(rnd_ab), key, enc_random_b, 2);

    len = mifare_sendcmd(MIFARE_ULC_AUTH_2, rnd_ab, sizeof(rnd_ab), resp, sizeof(resp), respPar, NULL);
    if (len != 11) {
        if (g_dbglevel >= DBG_ERROR) Dbprintf("Cmd Error: %02x", resp[0]);
        return 0;
    }

    uint8_t enc_resp[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };
    uint8_t resp_random_a[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };
    memcpy(enc_resp, resp + 1, 8);

    // decrypt    out, in, length, key, iv
    tdes_nxp_receive(enc_resp, resp_random_a, 8, key, enc_random_b, 2);
    if (memcmp(resp_random_a, random_a, 8) != 0) {
        if (g_dbglevel >= DBG_ERROR) Dbprintf("failed authentication");
        return 0;
    }

    if (g_dbglevel >= DBG_EXTENDED) {
        Dbprintf("e_AB: %02x %02x %02x %02x %02x %02x %02x %02x",
                 rnd_ab[0], rnd_ab[1], rnd_ab[2], rnd_ab[3],
                 rnd_ab[4], rnd_ab[5], rnd_ab[6], rnd_ab[7]);

        Dbprintf("e_AB: %02x %02x %02x %02x %02x %02x %02x %02x",
                 rnd_ab[8], rnd_ab[9], rnd_ab[10], rnd_ab[11],
                 rnd_ab[12], rnd_ab[13], rnd_ab[14], rnd_ab[15]);

        Dbprintf("a: %02x %02x %02x %02x %02x %02x %02x %02x",
                 random_a[0], random_a[1], random_a[2], random_a[3],
                 random_a[4], random_a[5], random_a[6], random_a[7]);

        Dbprintf("b: %02x %02x %02x %02x %02x %02x %02x %02x",
                 resp_random_a[0], resp_random_a[1], resp_random_a[2], resp_random_a[3],
                 resp_random_a[4], resp_random_a[5], resp_random_a[6], resp_random_a[7]);
    }
    return 1;
}

int mifare_ultra_aes_auth(uint8_t keyno, uint8_t *keybytes) {

    /// aes-128
    uint8_t random_a[16] = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
    uint8_t random_b[16] = { 0 };
    uint8_t rnd_ab[32] = { 0 };
    uint8_t enc_rnd_ab[32] = { 0 };
    uint8_t IV[16] = { 0 };
    uint8_t key[16] = { 0 };
    memcpy(key, keybytes, sizeof(key));

    uint16_t len = 0;

    // 1 cmd + 16 bytes + 2 crc
    uint8_t resp[19] = {0x00};
    uint8_t respPar[5] = {0};


    // setup AES
    mbedtls_aes_context actx;
    mbedtls_aes_init(&actx);
    mbedtls_aes_init(&actx);
    mbedtls_aes_setkey_dec(&actx, key, 128);

    // Send REQUEST AUTHENTICATION / receive tag nonce
    len = mifare_sendcmd_short(NULL, CRYPT_NONE, MIFARE_ULAES_AUTH_1, keyno, resp, sizeof(resp), respPar, NULL);
    if (len != 19) {
        if (g_dbglevel >= DBG_ERROR) Dbprintf("Cmd Error: %02x - expected 19 got " _RED_("%u"), resp[0], len);
        return 0;
    }

    // decrypt tag nonce.
    mbedtls_aes_crypt_cbc(&actx, MBEDTLS_AES_DECRYPT, sizeof(random_b), IV, resp + 1, random_b);

    rol(random_b, 16);
    memcpy(rnd_ab, random_a, 16);
    memcpy(rnd_ab + 16, random_b, 16);

    if (g_dbglevel >= DBG_EXTENDED) {
        Dbprintf("enc_B:");
        Dbhexdump(16, resp + 1, false);

        Dbprintf("B:");
        Dbhexdump(16, random_b, false);

        Dbprintf("rnd_ab:");
        Dbhexdump(32, rnd_ab, false);
    }

    // encrypt reader response
    memset(IV, 0, 16);
    mbedtls_aes_setkey_enc(&actx, key, 128);
    mbedtls_aes_crypt_cbc(&actx, MBEDTLS_AES_ENCRYPT, sizeof(enc_rnd_ab), IV, rnd_ab, enc_rnd_ab);

    // send & receive
    len = mifare_sendcmd(MIFARE_ULAES_AUTH_2, enc_rnd_ab, sizeof(enc_rnd_ab), resp, sizeof(resp), respPar, NULL);
    if (len != 19) {
        if (g_dbglevel >= DBG_ERROR) Dbprintf("Cmd Error: %02x - expected 19 got " _RED_("%u"), resp[0], len);
        return 0;
    }

    memset(IV, 0, 16);
    mbedtls_aes_setkey_dec(&actx, key, 128);
    mbedtls_aes_crypt_cbc(&actx, MBEDTLS_AES_DECRYPT, sizeof(random_b), IV, resp + 1, random_b);

    if (memcmp(random_b, random_a, 16) != 0) {
        if (g_dbglevel >= DBG_ERROR) Dbprintf("failed authentication");
        return 0;
    }

    if (g_dbglevel >= DBG_EXTENDED) {

        Dbprintf("e_AB:");
        Dbhexdump(32, enc_rnd_ab, false);

        Dbprintf("A:");
        Dbhexdump(16, random_a, false);

        Dbprintf("B:");
        Dbhexdump(16, random_b, false);
    }

    mbedtls_aes_free(&actx);
    return 1;
}

static int mifare_ultra_readblockEx(uint8_t blockNo, uint8_t *blockData) {
    uint16_t len = 0;
    uint8_t bt[2] = {0x00, 0x00};
    uint8_t receivedAnswer[MAX_FRAME_SIZE] = {0x00};
    uint8_t receivedAnswerPar[MAX_PARITY_SIZE] = {0x00};

    len = mifare_sendcmd_short(NULL, CRYPT_NONE, ISO14443A_CMD_READBLOCK, blockNo, receivedAnswer, sizeof(receivedAnswer), receivedAnswerPar, NULL);
    if (len == 1) {
        if (g_dbglevel >= DBG_ERROR) Dbprintf("Cmd Error: %02x", receivedAnswer[0]);
        return 1;
    }
    if (len != 18) {
        if (g_dbglevel >= DBG_ERROR) Dbprintf("Cmd Error: card timeout. len: %x", len);
        return 2;
    }

    memcpy(bt, receivedAnswer + 16, 2);
    AddCrc14A(receivedAnswer, 16);
    if (bt[0] != receivedAnswer[16] || bt[1] != receivedAnswer[17]) {
        if (g_dbglevel >= DBG_ERROR) Dbprintf("Cmd CRC response error.");
        return 3;
    }

    memcpy(blockData, receivedAnswer, 16);
    return 0;
}
int mifare_ultra_readblock(uint8_t blockNo, uint8_t *blockData) {
#define MFU_MAX_RETRIES 5
    uint8_t res;

    for (uint8_t retries = 0; retries < MFU_MAX_RETRIES; ++retries) {
        res = mifare_ultra_readblockEx(blockNo, blockData);

        // break if OK,  or NACK.
        switch (res) {
            case 0:
            case 1:
                return res;
            default:
                continue;
        }
    }
    return res;
}

int mifare_classic_writeblock(struct Crypto1State *pcs, uint8_t blockNo, uint8_t *blockData) {
    return mifare_classic_writeblock_ex(pcs, blockNo, blockData, ISO14443A_CMD_WRITEBLOCK);
}
int mifare_classic_writeblock_ex(struct Crypto1State *pcs, uint8_t blockNo, uint8_t *blockData, uint8_t cmd) {

    // variables
    uint8_t receivedAnswer[MAX_MIFARE_FRAME_SIZE] = {0x00};
    uint8_t receivedAnswerPar[MAX_MIFARE_PARITY_SIZE] = {0x00};

    // cmd is ISO14443A_CMD_WRITEBLOCK for normal tags, but could also be
    // MIFARE_MAGIC_GDM_WRITEBLOCK or MIFARE_MAGIC_GDM_WRITE_CFG for certain magic tags
    uint16_t len = mifare_sendcmd_short(pcs, 1, cmd, blockNo, receivedAnswer, sizeof(receivedAnswer), receivedAnswerPar, NULL);

    if ((len != 1) || (receivedAnswer[0] != 0x0A)) {   //  0x0a - ACK
        if (g_dbglevel >= DBG_INFO) Dbprintf("Cmd Error: %02x", receivedAnswer[0]);
        return PM3_EFAILED;
    }

    uint8_t d_block[18], d_block_enc[18];
    memcpy(d_block, blockData, 16);
    AddCrc14A(d_block, 16);

    if (pcs) {
        // enough for 18 Bytes to send
        uint8_t par[3] = {0x00, 0x00, 0x00};
        // crypto
        for (uint32_t pos = 0; pos < 18; pos++) {
            d_block_enc[pos] = crypto1_byte(pcs, 0x00, 0) ^ d_block[pos];
            par[pos >> 3] |= (((filter(pcs->odd) ^ oddparity8(d_block[pos])) & 0x01) << (7 - (pos & 0x0007)));
        }

        ReaderTransmitPar(d_block_enc, sizeof(d_block_enc), par, NULL);
    } else {
        ReaderTransmit(d_block, sizeof(d_block), NULL);
    }

    // tearoff occurred
    if (tearoff_hook() == PM3_ETEAROFF) {
        return PM3_ETEAROFF;
    } else {
        // Receive the response
        len = ReaderReceive(receivedAnswer, sizeof(receivedAnswer), receivedAnswerPar);

        uint8_t res = 0;
        if (pcs) {
            res |= (crypto1_bit(pcs, 0, 0) ^ BIT(receivedAnswer[0], 0)) << 0;
            res |= (crypto1_bit(pcs, 0, 0) ^ BIT(receivedAnswer[0], 1)) << 1;
            res |= (crypto1_bit(pcs, 0, 0) ^ BIT(receivedAnswer[0], 2)) << 2;
            res |= (crypto1_bit(pcs, 0, 0) ^ BIT(receivedAnswer[0], 3)) << 3;
        } else {
            res = receivedAnswer[0];
        }

        if ((len != 1) || (res != 0x0A)) {
            if (g_dbglevel >= DBG_INFO) Dbprintf("Cmd send data2 Error: %02x", res);
            return PM3_EFAILED;
        }
    }
    return PM3_SUCCESS;
}

int mifare_classic_value(struct Crypto1State *pcs, uint8_t blockNo, uint8_t *blockData, uint8_t action) {
    // variables
    uint16_t len = 0;
    uint32_t pos = 0;
    uint8_t par[3] = {0x00, 0x00, 0x00}; // enough for 18 Bytes to send

    uint8_t d_block[18], d_block_enc[18];
    uint8_t receivedAnswer[MAX_MIFARE_FRAME_SIZE] = {0x00};
    uint8_t receivedAnswerPar[MAX_MIFARE_PARITY_SIZE] = {0x00};

    uint8_t command = MIFARE_CMD_INC;

    if (action == 0x01)
        command = MIFARE_CMD_DEC;
    if (action == 0x02)
        command = MIFARE_CMD_RESTORE;

    // Send increment or decrement command
    len = mifare_sendcmd_short(pcs, 1, command, blockNo, receivedAnswer, sizeof(receivedAnswer), receivedAnswerPar, NULL);

    if ((len != 1) || (receivedAnswer[0] != 0x0A)) {   //  0x0a - ACK
        if (g_dbglevel >= DBG_INFO) Dbprintf("Cmd Error: %02x", receivedAnswer[0]);
        return PM3_EFAILED;
    }

    memcpy(d_block, blockData, 4);
    AddCrc14A(d_block, 4);

    // crypto
    for (pos = 0; pos < 6; pos++) {
        d_block_enc[pos] = crypto1_byte(pcs, 0x00, 0) ^ d_block[pos];
        par[pos >> 3] |= (((filter(pcs->odd) ^ oddparity8(d_block[pos])) & 0x01) << (7 - (pos & 0x0007)));
    }

    ReaderTransmitPar(d_block_enc, 6, par, NULL);

    // Receive the response NO Response means OK ... i.e. NOT NACK
    len = ReaderReceive(receivedAnswer, sizeof(receivedAnswer), receivedAnswerPar);

    if (len != 0) { // Something not right, len == 0 (no response is ok as its waiting for transfer
        uint8_t res = 0;
        res |= (crypto1_bit(pcs, 0, 0) ^ BIT(receivedAnswer[0], 0)) << 0;
        res |= (crypto1_bit(pcs, 0, 0) ^ BIT(receivedAnswer[0], 1)) << 1;
        res |= (crypto1_bit(pcs, 0, 0) ^ BIT(receivedAnswer[0], 2)) << 2;
        res |= (crypto1_bit(pcs, 0, 0) ^ BIT(receivedAnswer[0], 3)) << 3;

        if ((len != 1) || (res != 0x0A)) {
            if (g_dbglevel >= DBG_INFO) Dbprintf("Cmd send data2 Error: %02x", res);
            return PM3_EFAILED;
        }
    }

    return PM3_SUCCESS;
}

int mifare_ultra_writeblock_compat(uint8_t blockNo, uint8_t *blockData) {
    // variables
    uint16_t len = 0;

    uint8_t d_block[18];
    uint8_t receivedAnswer[MAX_MIFARE_FRAME_SIZE] = {0x00};
    uint8_t receivedAnswerPar[MAX_MIFARE_PARITY_SIZE] = {0x00};

    len = mifare_sendcmd_short(NULL, CRYPT_NONE, ISO14443A_CMD_WRITEBLOCK, blockNo, receivedAnswer, sizeof(receivedAnswer), receivedAnswerPar, NULL);

    if (receivedAnswer[0] != 0x0A) {   //  0x0a - ACK
        if (g_dbglevel >= DBG_INFO) {
            Dbprintf("Cmd Send Error: %02x %d", receivedAnswer[0], len);
        }
        return PM3_EFAILED;
    }

    memcpy(d_block, blockData, 16);
    AddCrc14A(d_block, 16);

    ReaderTransmit(d_block, sizeof(d_block), NULL);

    // Receive the response
    len = ReaderReceive(receivedAnswer, sizeof(receivedAnswer), receivedAnswerPar);

    if (receivedAnswer[0] != 0x0A) {   //  0x0a - ACK
        if (g_dbglevel >= DBG_INFO) {
            Dbprintf("Cmd Send Data Error: %02x %d", receivedAnswer[0], len);
        }
        return PM3_EFAILED;
    }
    return PM3_SUCCESS;
}

int mifare_ultra_writeblock(uint8_t blockNo, uint8_t *blockData) {
    uint16_t len = 0;
    uint8_t block[5] = {blockNo, 0x00, 0x00, 0x00, 0x00 };
    uint8_t receivedAnswer[MAX_MIFARE_FRAME_SIZE] = {0x00};
    uint8_t receivedAnswerPar[MAX_MIFARE_PARITY_SIZE] = {0x00};

    // command MIFARE_CLASSIC_WRITEBLOCK
    memcpy(block + 1, blockData, 4);

    len = mifare_sendcmd(MIFARE_ULC_WRITE, block, sizeof(block), receivedAnswer, sizeof(receivedAnswer), receivedAnswerPar, NULL);

    if (receivedAnswer[0] != 0x0A) {   //  0x0a - ACK
        if (g_dbglevel >= DBG_INFO) {
            Dbprintf("Cmd Send Error: %02x %d", receivedAnswer[0], len);
        }
        return PM3_EFAILED;
    }
    return PM3_SUCCESS;
}

int mifare_classic_halt(struct Crypto1State *pcs) {
    uint8_t receivedAnswer[4] = {0x00, 0x00, 0x00, 0x00};
    uint16_t len = mifare_sendcmd_short(pcs, (pcs == NULL) ? CRYPT_NONE : CRYPT_ALL, ISO14443A_CMD_HALT, 0x00, receivedAnswer, sizeof(receivedAnswer), NULL, NULL);
    if (len != 0) {
        if (g_dbglevel >= DBG_EXTENDED) Dbprintf("halt warning. response len: %x", len);
        return 1;
    }
    return 0;
}

int mifare_ultra_halt(void) {
    return mifare_classic_halt(NULL);
}


// Mifare Memory Structure: up to 32 Sectors with 4 blocks each (1k and 2k cards),
// plus evtl. 8 sectors with 16 blocks each (4k cards)
uint8_t NumBlocksPerSector(uint8_t sectorNo) {
    return (sectorNo < 32) ? 4 : 16;
}

uint8_t FirstBlockOfSector(uint8_t sectorNo) {
    if (sectorNo < 32)
        return sectorNo * 4;
    else
        return 32 * 4 + (sectorNo - 32) * 16;
}

// work with emulator memory
void emlSetMem_xt(uint8_t *data, int blockNum, int blocksCount, int block_width) {
    uint32_t offset = blockNum * block_width;
    uint32_t len =  blocksCount * block_width;
    emlSet(data, offset, len);
}

void emlGetMem(uint8_t *data, int blockNum, int blocksCount) {
    emlGet(data, (blockNum * 16), (blocksCount * 16));
}

bool emlCheckValBl(int blockNum) {
    uint8_t *mem = BigBuf_get_EM_addr();
    uint8_t *d = mem + (blockNum * 16);

    if ((d[0] != (d[4] ^ 0xff)) || (d[0] != d[8]) ||
            (d[1] != (d[5] ^ 0xff)) || (d[1] != d[9]) ||
            (d[2] != (d[6] ^ 0xff)) || (d[2] != d[10]) ||
            (d[3] != (d[7] ^ 0xff)) || (d[3] != d[11]) ||
            (d[12] != (d[13] ^ 0xff)) || (d[12] != d[14]) ||
            (d[12] != (d[15] ^ 0xff))) {
        return false;
    }
    return true;
}

int emlGetValBl(uint32_t *blReg, uint8_t *blBlock, int blockNum) {
    uint8_t *mem = BigBuf_get_EM_addr();
    uint8_t *d = mem + blockNum * 16;

    if (emlCheckValBl(blockNum) == false) {
        return PM3_ESOFT;
    }

    memcpy(blReg, d, 4);
    *blBlock = d[12];
    return PM3_SUCCESS;
}

void emlSetValBl(uint32_t blReg, uint8_t blBlock, int blockNum) {
    uint8_t *mem = BigBuf_get_EM_addr();
    uint8_t *d = mem + blockNum * 16;

    memcpy(d + 0, &blReg, 4);
    memcpy(d + 8, &blReg, 4);
    blReg = blReg ^ 0xFFFFFFFF;
    memcpy(d + 4, &blReg, 4);

    d[12] = blBlock;
    d[13] = blBlock ^ 0xFF;
    d[14] = blBlock;
    d[15] = blBlock ^ 0xFF;
}

uint64_t emlGetKey(int sectorNum, int keyType) {
    uint8_t key[6] = {0x00};
    uint8_t *mem = BigBuf_get_EM_addr();
    memcpy(key, mem + 16 * (FirstBlockOfSector(sectorNum) + NumBlocksPerSector(sectorNum) - 1) + keyType * 10, 6);
    return bytes_to_num(key, 6);
}

void emlClearMem(void) {
    const uint8_t trailer[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x07, 0x80, 0x69, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    const uint8_t uid[]   =   {0xe6, 0x84, 0x87, 0xf3, 0x16, 0x88, 0x04, 0x00, 0x46, 0x8e, 0x45, 0x55, 0x4d, 0x70, 0x41, 0x04};
    uint8_t *mem = BigBuf_get_EM_addr();
    memset(mem, 0, CARD_MEMORY_SIZE);

    // fill sectors trailer data
    for (uint16_t b = 3; b < MIFARE_4K_MAXBLOCK; ((b < MIFARE_2K_MAXBLOCK - 4) ? (b += 4) : (b += 16))) {
        emlSetMem_xt((uint8_t *)trailer, b, 1, 16);
    }

    // uid
    emlSetMem_xt((uint8_t *)uid, 0, 1, 16);
    return;
}

uint8_t SectorTrailer(uint8_t blockNo) {
    if (blockNo <= MIFARE_2K_MAXBLOCK) {
        if (g_dbglevel >= DBG_EXTENDED) {
            Dbprintf("Sector Trailer for block %d : %d", blockNo, (blockNo | 0x03));
        }
        return (blockNo | 0x03);
    } else {
        if (g_dbglevel >= DBG_EXTENDED) {
            Dbprintf("Sector Trailer for block %d : %d", blockNo, (blockNo | 0x0F));
        }
        return (blockNo | 0x0F);
    }
}

bool IsSectorTrailer(uint8_t blockNo) {
    return (blockNo == SectorTrailer(blockNo));
}

// Mifare desfire commands
int mifare_sendcmd_special(struct Crypto1State *pcs, uint8_t crypted, uint8_t cmd, uint8_t *data, uint8_t *answer, uint16_t answer_len, uint8_t *answer_parity, uint32_t *timing) {
    uint8_t dcmd[5] = {cmd, data[0], data[1], 0x00, 0x00};
    AddCrc14A(dcmd, 3);

    ReaderTransmit(dcmd, sizeof(dcmd), NULL);
    int len = ReaderReceive(answer, answer_len, answer_parity);
    if (!len) {
        if (g_dbglevel >= DBG_ERROR) Dbprintf("Authentication failed. Card timeout.");
        return 1;
    }
    return len;
}

int mifare_sendcmd_special2(struct Crypto1State *pcs, uint8_t crypted, uint8_t cmd, uint8_t *data, uint8_t *answer, uint16_t answer_len, uint8_t *answer_parity, uint32_t *timing) {
    uint8_t dcmd[20] = {0x00};
    dcmd[0] = cmd;
    memcpy(dcmd + 1, data, 17);
    AddCrc14A(dcmd, 18);

    ReaderTransmit(dcmd, sizeof(dcmd), NULL);
    int len = ReaderReceive(answer, answer_len, answer_parity);
    if (!len) {
        if (g_dbglevel >= DBG_ERROR) Dbprintf("Authentication failed. Card timeout.");
        return 1;
    }
    return len;
}

int mifare_desfire_des_auth1(uint32_t uid, uint8_t *blockData) {

    int len;
    // load key, keynumber
    uint8_t data[2] = {MFDES_AUTHENTICATE, 0x00};
    uint8_t receivedAnswer[MAX_FRAME_SIZE] = {0x00};
    uint8_t receivedAnswerPar[MAX_PARITY_SIZE] = {0x00};

    len = mifare_sendcmd_special(NULL, 1, 0x02, data, receivedAnswer, sizeof(receivedAnswer), receivedAnswerPar, NULL);
    if (len == 1) {
        if (g_dbglevel >= DBG_INFO) {
            Dbprintf("Cmd Error: %02x", receivedAnswer[0]);
        }
        return PM3_EFAILED;
    }

    if (len == 12) {
        if (g_dbglevel >= DBG_EXTENDED) {
            Dbprintf("Auth1 Resp: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                     receivedAnswer[0], receivedAnswer[1], receivedAnswer[2], receivedAnswer[3], receivedAnswer[4],
                     receivedAnswer[5], receivedAnswer[6], receivedAnswer[7], receivedAnswer[8], receivedAnswer[9],
                     receivedAnswer[10], receivedAnswer[11]);
        }
        memcpy(blockData, receivedAnswer, 12);
        return PM3_SUCCESS;
    }
    return PM3_EFAILED;
}

int mifare_desfire_des_auth2(uint32_t uid, uint8_t *key, uint8_t *blockData) {

    int len;
    uint8_t data[17] = {MFDES_ADDITIONAL_FRAME};
    memcpy(data + 1, key, 16);

    uint8_t receivedAnswer[MAX_FRAME_SIZE] = {0x00};
    uint8_t receivedAnswerPar[MAX_PARITY_SIZE] = {0x00};

    len = mifare_sendcmd_special2(NULL, 1, 0x03, data, receivedAnswer, sizeof(receivedAnswer), receivedAnswerPar, NULL);

    if ((receivedAnswer[0] == 0x03) && (receivedAnswer[1] == 0xae)) {
        if (g_dbglevel >= DBG_ERROR) {
            Dbprintf("Auth Error: %02x %02x", receivedAnswer[0], receivedAnswer[1]);
        }
        return PM3_EFAILED;
    }

    if (len == 12) {
        if (g_dbglevel >= DBG_EXTENDED) {
            Dbprintf("Auth2 Resp: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                     receivedAnswer[0], receivedAnswer[1], receivedAnswer[2], receivedAnswer[3], receivedAnswer[4],
                     receivedAnswer[5], receivedAnswer[6], receivedAnswer[7], receivedAnswer[8], receivedAnswer[9],
                     receivedAnswer[10], receivedAnswer[11]);
        }
        memcpy(blockData, receivedAnswer, 12);
        return PM3_SUCCESS;
    }
    return PM3_EFAILED;
}

bool validate_prng_nonce(uint32_t nonce) {
    uint16_t x = nonce >> 16;
    x = (x & 0xff) << 8 | x >> 8;
    for (uint8_t i = 0; i < 16; i++) {
        x = x >> 1 | (x ^ x >> 2 ^ x >> 3 ^ x >> 5) << 15;
    }
    x = (x & 0xff) << 8 | x >> 8;
    return x == (nonce & 0xFFFF);
}

bool validate_parity_nonce(uint32_t ntenc, uint8_t ntparenc, uint32_t nt) {
    uint32_t ks = nt ^ ntenc;
    ntparenc >>= 4;
    uint8_t ksp = (((ks >> 16) & 1) << 3) | (((ks >> 8) & 1) << 2) | (((ks >> 0) & 1) << 1);
    uint8_t ntpar = ntparenc ^ ksp;
    return (((ntpar >> 3) & 1) == oddparity8((nt >> 24) & 0xFF)) &&
           (((ntpar >> 2) & 1) == oddparity8((nt >> 16) & 0xFF)) &&
           (((ntpar >> 1) & 1) == oddparity8((nt >> 8) & 0xFF));
}

int nonce16_distance(uint16_t x, uint16_t y) {
    if (x == y)
        return 0;
    x = (x & 0xff) << 8 | x >> 8;
    y = (y & 0xff) << 8 | y >> 8;
    uint16_t i = 1;
    for (; i; i++) {
        x = x >> 1 | (x ^ x >> 2 ^ x >> 3 ^ x >> 5) << 15;
        if (x == y)
            return i;
    }
    // never reached
    return -1;
}

int nonce_distance(uint32_t from, uint32_t to) {
    if (!validate_prng_nonce(from) || !validate_prng_nonce(to))
        return -1;
    return nonce16_distance(from >> 16, to >> 16);
}

int nonce16_index(uint16_t nt) {
    return nonce16_distance(0x0100, nt) + 1;
}
