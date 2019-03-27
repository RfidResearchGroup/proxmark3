//-----------------------------------------------------------------------------
// Merlok, May 2011, 2012
// Many authors, whom made it possible
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Work with mifare cards.
//-----------------------------------------------------------------------------
#include "mifareutil.h"

int MF_DBGLEVEL = MF_DBG_ERROR;

// crypto1 helpers
void mf_crypto1_decryptEx(struct Crypto1State *pcs, uint8_t *data_in, int len, uint8_t *data_out) {
    uint8_t bt = 0;
    int i;

    if (len != 1) {
        for (i = 0; i < len; i++)
            data_out[i] = crypto1_byte(pcs, 0x00, 0) ^ data_in[i];
    } else {
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
    uint8_t bt = 0;
    int i;
    par[0] = 0;

    for (i = 0; i < len; i++) {
        bt = data[i];
        data[i] = crypto1_byte(pcs, 0x00, 0) ^ data[i];
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
int mifare_sendcmd(uint8_t cmd, uint8_t *data, uint8_t data_size, uint8_t *answer, uint8_t *answer_parity, uint32_t *timing) {
    uint8_t dcmd[data_size + 3];
    dcmd[0] = cmd;
    memcpy(dcmd + 1, data, data_size);
    AddCrc14A(dcmd, data_size + 1);
    ReaderTransmit(dcmd, sizeof(dcmd), timing);
    int len = ReaderReceive(answer, answer_parity);
    if (!len) {
        if (MF_DBGLEVEL >= MF_DBG_ERROR) Dbprintf("%02X Cmd failed. Card timeout.", cmd);
        len = ReaderReceive(answer, answer_parity);
    }
    return len;
}

// send 2 byte commands
int mifare_sendcmd_short(struct Crypto1State *pcs, uint8_t crypted, uint8_t cmd, uint8_t data, uint8_t *answer, uint8_t *answer_parity, uint32_t *timing) {
    uint16_t pos, res;
    uint8_t dcmd[4] = {cmd, data, 0x00, 0x00};
    uint8_t ecmd[4] = {0x00, 0x00, 0x00, 0x00};
    uint8_t par[1] = {0x00}; // 1 Byte parity is enough here
    AddCrc14A(dcmd, 2);
    memcpy(ecmd, dcmd, sizeof(dcmd));

    if (crypted) {
        par[0] = 0;
        for (pos = 0; pos < 4; pos++) {
            ecmd[pos] = crypto1_byte(pcs, 0x00, 0) ^ dcmd[pos];
            par[0] |= (((filter(pcs->odd) ^ oddparity8(dcmd[pos])) & 0x01) << (7 - pos));
        }
        ReaderTransmitPar(ecmd, sizeof(ecmd), par, timing);
    } else {
        ReaderTransmit(dcmd, sizeof(dcmd), timing);
    }

    int len = ReaderReceive(answer, par);

    if (answer_parity) *answer_parity = par[0];

    if (crypted == CRYPT_ALL) {
        if (len == 1) {
            res = 0;
            res |= (crypto1_bit(pcs, 0, 0) ^ BIT(answer[0], 0)) << 0;
            res |= (crypto1_bit(pcs, 0, 0) ^ BIT(answer[0], 1)) << 1;
            res |= (crypto1_bit(pcs, 0, 0) ^ BIT(answer[0], 2)) << 2;
            res |= (crypto1_bit(pcs, 0, 0) ^ BIT(answer[0], 3)) << 3;
            answer[0] = res;
        } else {
            for (pos = 0; pos < len; pos++)
                answer[pos] = crypto1_byte(pcs, 0x00, 0) ^ answer[pos];
        }
    }
    return len;
}

// mifare classic commands
int mifare_classic_auth(struct Crypto1State *pcs, uint32_t uid, uint8_t blockNo, uint8_t keyType, uint64_t ui64Key, uint8_t isNested) {
    return mifare_classic_authex(pcs, uid, blockNo, keyType, ui64Key, isNested, NULL, NULL);
}

int mifare_classic_authex(struct Crypto1State *pcs, uint32_t uid, uint8_t blockNo, uint8_t keyType, uint64_t ui64Key, uint8_t isNested, uint32_t *ntptr, uint32_t *timing) {
    int len;
    uint32_t pos, nt, ntpp; // Supplied tag nonce
    uint8_t par[1] = {0x00};
    uint8_t nr[4];
    uint8_t mf_nr_ar[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    uint8_t receivedAnswer[MAX_MIFARE_FRAME_SIZE] = {0x00};
    uint8_t receivedAnswerPar[MAX_MIFARE_PARITY_SIZE] = {0x00};

    // "random" reader nonce:
    num_to_bytes(prng_successor(GetTickCount(), 32), 4, nr);

    // Transmit MIFARE_CLASSIC_AUTH
    len = mifare_sendcmd_short(pcs, isNested, 0x60 + (keyType & 0x01), blockNo, receivedAnswer, receivedAnswerPar, timing);
    if (len != 4) return 1;

    // Save the tag nonce (nt)
    nt = bytes_to_num(receivedAnswer, 4);

    //  ----------------------------- crypto1 create
    if (isNested)
        crypto1_destroy(pcs);

    // Init cipher with key
    crypto1_create(pcs, ui64Key);

    if (isNested == AUTH_NESTED) {
        // decrypt nt with help of new key
        nt = crypto1_word(pcs, nt ^ uid, 1) ^ nt;
    } else {
        // Load (plain) uid^nt into the cipher
        crypto1_word(pcs, nt ^ uid, 0);
    }

    // some statistic
    if (!ntptr && (MF_DBGLEVEL >= MF_DBG_EXTENDED))
        Dbprintf("auth uid: %08x | nr: %08x | nt: %08x", uid, nr, nt);

    // save Nt
    if (ntptr)
        *ntptr = nt;

    // Generate (encrypted) nr+parity by loading it into the cipher (Nr)
    par[0] = 0;
    for (pos = 0; pos < 4; pos++) {
        mf_nr_ar[pos] = crypto1_byte(pcs, nr[pos], 0) ^ nr[pos];
        par[0] |= (((filter(pcs->odd) ^ oddparity8(nr[pos])) & 0x01) << (7 - pos));
    }

    // Skip 32 bits in pseudo random generator
    nt = prng_successor(nt, 32);

    //  ar+parity
    for (pos = 4; pos < 8; pos++) {
        nt = prng_successor(nt, 8);
        mf_nr_ar[pos] = crypto1_byte(pcs, 0x00, 0) ^ (nt & 0xff);
        par[0] |= (((filter(pcs->odd) ^ oddparity8(nt & 0xff)) & 0x01) << (7 - pos));
    }

    // Transmit reader nonce and reader answer
    ReaderTransmitPar(mf_nr_ar, sizeof(mf_nr_ar), par, NULL);

    // Receive 4 byte tag answer
    len = ReaderReceive(receivedAnswer, receivedAnswerPar);
    if (!len) {
        if (MF_DBGLEVEL >= MF_DBG_EXTENDED) Dbprintf("Authentication failed. Card timeout.");
        return 2;
    }

    ntpp = prng_successor(nt, 32) ^ crypto1_word(pcs, 0, 0);

    if (ntpp != bytes_to_num(receivedAnswer, 4)) {
        if (MF_DBGLEVEL >= MF_DBG_EXTENDED) Dbprintf("Authentication failed. Error card response.");
        return 3;
    }
    return 0;
}

int mifare_classic_readblock(struct Crypto1State *pcs, uint32_t uid, uint8_t blockNo, uint8_t *blockData) {

    int len;
    uint8_t bt[2] = {0x00, 0x00};
    uint8_t receivedAnswer[MAX_MIFARE_FRAME_SIZE] = {0x00};
    uint8_t receivedAnswerPar[MAX_MIFARE_PARITY_SIZE] = {0x00};

    len = mifare_sendcmd_short(pcs, 1, ISO14443A_CMD_READBLOCK, blockNo, receivedAnswer, receivedAnswerPar, NULL);
    if (len == 1) {
        if (MF_DBGLEVEL >= MF_DBG_ERROR) Dbprintf("Cmd Error: %02x", receivedAnswer[0]);
        return 1;
    }
    if (len != 18) {
        if (MF_DBGLEVEL >= MF_DBG_ERROR) Dbprintf("Cmd Error: wrong response len: %x  (expected 18)", len);
        return 2;
    }

    memcpy(bt, receivedAnswer + 16, 2);
    AddCrc14A(receivedAnswer, 16);
    if (bt[0] != receivedAnswer[16] || bt[1] != receivedAnswer[17]) {
        if (MF_DBGLEVEL >= MF_DBG_ALL) Dbprintf("Cmd CRC response error.");
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

    if (MF_DBGLEVEL >= MF_DBG_EXTENDED)
        Dbprintf("EV1 Auth : %02x%02x%02x%02x", key[0], key[1], key[2], key[3]);

    len = mifare_sendcmd(MIFARE_ULEV1_AUTH, key, sizeof(key), resp, respPar, NULL);

    if (len != 4) {
        if (MF_DBGLEVEL >= MF_DBG_ERROR) Dbprintf("Cmd Error: %02x %u", resp[0], len);
        return 0;
    }

    if (MF_DBGLEVEL >= MF_DBG_EXTENDED)
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
    len = mifare_sendcmd_short(NULL, 1, MIFARE_ULC_AUTH_1, 0x00, resp, respPar, NULL);
    if (len != 11) {
        if (MF_DBGLEVEL >= MF_DBG_ERROR) Dbprintf("Cmd Error: %02x", resp[0]);
        return 0;
    }

    // tag nonce.
    memcpy(enc_random_b, resp + 1, 8);

    // decrypt nonce.
    tdes_2key_dec((void *)random_b, (void *)enc_random_b, sizeof(random_b), (const void *)key, IV);
    rol(random_b, 8);
    memcpy(rnd_ab, random_a, 8);
    memcpy(rnd_ab + 8, random_b, 8);

    if (MF_DBGLEVEL >= MF_DBG_EXTENDED) {
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
    tdes_2key_enc(rnd_ab, rnd_ab, sizeof(rnd_ab), key, enc_random_b);

    len = mifare_sendcmd(MIFARE_ULC_AUTH_2, rnd_ab, sizeof(rnd_ab), resp, respPar, NULL);
    if (len != 11) {
        if (MF_DBGLEVEL >= MF_DBG_ERROR) Dbprintf("Cmd Error: %02x", resp[0]);
        return 0;
    }

    uint8_t enc_resp[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };
    uint8_t resp_random_a[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };
    memcpy(enc_resp, resp + 1, 8);

    // decrypt    out, in, length, key, iv
    tdes_2key_dec(resp_random_a, enc_resp, 8, key, enc_random_b);
    if (memcmp(resp_random_a, random_a, 8) != 0) {
        if (MF_DBGLEVEL >= MF_DBG_ERROR) Dbprintf("failed authentication");
        return 0;
    }

    if (MF_DBGLEVEL >= MF_DBG_EXTENDED) {
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

int mifare_ultra_readblockEx(uint8_t blockNo, uint8_t *blockData) {
    uint16_t len = 0;
    uint8_t bt[2] = {0x00, 0x00};
    uint8_t receivedAnswer[MAX_FRAME_SIZE] = {0x00};
    uint8_t receivedAnswerPar[MAX_PARITY_SIZE] = {0x00};

    len = mifare_sendcmd_short(NULL, 1, ISO14443A_CMD_READBLOCK, blockNo, receivedAnswer, receivedAnswerPar, NULL);
    if (len == 1) {
        if (MF_DBGLEVEL >= MF_DBG_ERROR) Dbprintf("Cmd Error: %02x", receivedAnswer[0]);
        return 1;
    }
    if (len != 18) {
        if (MF_DBGLEVEL >= MF_DBG_ERROR) Dbprintf("Cmd Error: card timeout. len: %x", len);
        return 2;
    }

    memcpy(bt, receivedAnswer + 16, 2);
    AddCrc14A(receivedAnswer, 16);
    if (bt[0] != receivedAnswer[16] || bt[1] != receivedAnswer[17]) {
        if (MF_DBGLEVEL >= MF_DBG_ERROR) Dbprintf("Cmd CRC response error.");
        return 3;
    }

    memcpy(blockData, receivedAnswer, 14);
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

int mifare_classic_writeblock(struct Crypto1State *pcs, uint32_t uid, uint8_t blockNo, uint8_t *blockData) {
    // variables
    uint16_t len = 0;
    uint32_t pos = 0;
    uint8_t par[3] = {0x00, 0x00, 0x00}; // enough for 18 Bytes to send
    uint8_t res = 0;

    uint8_t d_block[18], d_block_enc[18];
    uint8_t receivedAnswer[MAX_MIFARE_FRAME_SIZE] = {0x00};
    uint8_t receivedAnswerPar[MAX_MIFARE_PARITY_SIZE] = {0x00};

    // command MIFARE_CLASSIC_WRITEBLOCK
    len = mifare_sendcmd_short(pcs, 1, ISO14443A_CMD_WRITEBLOCK, blockNo, receivedAnswer, receivedAnswerPar, NULL);

    if ((len != 1) || (receivedAnswer[0] != 0x0A)) {   //  0x0a - ACK
        if (MF_DBGLEVEL >= MF_DBG_ERROR) Dbprintf("Cmd Error: %02x", receivedAnswer[0]);
        return 1;
    }

    memcpy(d_block, blockData, 16);
    AddCrc14A(d_block, 16);

    // crypto
    for (pos = 0; pos < 18; pos++) {
        d_block_enc[pos] = crypto1_byte(pcs, 0x00, 0) ^ d_block[pos];
        par[pos >> 3] |= (((filter(pcs->odd) ^ oddparity8(d_block[pos])) & 0x01) << (7 - (pos & 0x0007)));
    }

    ReaderTransmitPar(d_block_enc, sizeof(d_block_enc), par, NULL);

    // Receive the response
    len = ReaderReceive(receivedAnswer, receivedAnswerPar);

    res = 0;
    res |= (crypto1_bit(pcs, 0, 0) ^ BIT(receivedAnswer[0], 0)) << 0;
    res |= (crypto1_bit(pcs, 0, 0) ^ BIT(receivedAnswer[0], 1)) << 1;
    res |= (crypto1_bit(pcs, 0, 0) ^ BIT(receivedAnswer[0], 2)) << 2;
    res |= (crypto1_bit(pcs, 0, 0) ^ BIT(receivedAnswer[0], 3)) << 3;

    if ((len != 1) || (res != 0x0A)) {
        if (MF_DBGLEVEL >= MF_DBG_ERROR) Dbprintf("Cmd send data2 Error: %02x", res);
        return 2;
    }
    return 0;
}

/* // command not needed, but left for future testing
int mifare_ultra_writeblock_compat(uint8_t blockNo, uint8_t *blockData) {
    uint16_t len;
    uint8_t par[3] = {0};  // enough for 18 parity bits
    uint8_t d_block[18] = {0x00};
    uint8_t receivedAnswer[MAX_FRAME_SIZE];
    uint8_t receivedAnswerPar[MAX_PARITY_SIZE];

    len = mifare_sendcmd_short(NULL, true, ISO14443A_CMD_WRITEBLOCK, blockNo, receivedAnswer, receivedAnswerPar, NULL);

    if ((len != 1) || (receivedAnswer[0] != 0x0A)) {   //  0x0a - ACK
        if (MF_DBGLEVEL >= MF_DBG_ERROR)
            Dbprintf("Cmd Addr Error: %02x", receivedAnswer[0]);
        return 1;
    }

    memcpy(d_block, blockData, 16);
    AddCrc14A(d_block, 16);

    ReaderTransmitPar(d_block, sizeof(d_block), par, NULL);

    len = ReaderReceive(receivedAnswer, receivedAnswerPar);

    if ((len != 1) || (receivedAnswer[0] != 0x0A)) {   //  0x0a - ACK
        if (MF_DBGLEVEL >= MF_DBG_ERROR)
            Dbprintf("Cmd Data Error: %02x %d", receivedAnswer[0],len);
        return 2;
    }
    return 0;
}
*/

int mifare_ultra_writeblock(uint8_t blockNo, uint8_t *blockData) {
    uint16_t len = 0;
    uint8_t block[5] = {blockNo, 0x00, 0x00, 0x00, 0x00 };
    uint8_t receivedAnswer[MAX_MIFARE_FRAME_SIZE] = {0x00};
    uint8_t receivedAnswerPar[MAX_MIFARE_PARITY_SIZE] = {0x00};

    // command MIFARE_CLASSIC_WRITEBLOCK
    memcpy(block + 1, blockData, 4);

    len = mifare_sendcmd(MIFARE_ULC_WRITE, block, sizeof(block), receivedAnswer, receivedAnswerPar, NULL);

    if (receivedAnswer[0] != 0x0A) {   //  0x0a - ACK
        if (MF_DBGLEVEL >= MF_DBG_ERROR)
            Dbprintf("Cmd Send Error: %02x %d", receivedAnswer[0], len);
        return 1;
    }
    return 0;
}
int mifare_classic_halt_ex(struct Crypto1State *pcs) {
    uint8_t receivedAnswer[4] = {0x00, 0x00, 0x00, 0x00};
    uint16_t len = mifare_sendcmd_short(pcs, (pcs == NULL) ? CRYPT_NONE : CRYPT_ALL, ISO14443A_CMD_HALT, 0x00, receivedAnswer, NULL, NULL);
    if (len != 0) {
        if (MF_DBGLEVEL >= MF_DBG_EXTENDED) Dbprintf("halt warning. response len: %x", len);
        return 1;
    }
    return 0;
}
int mifare_classic_halt(struct Crypto1State *pcs, uint32_t uid) {
    return mifare_classic_halt_ex(pcs);
}

int mifare_ultra_halt() {
    uint16_t len = 0;
    uint8_t receivedAnswer[4] = {0x00, 0x00, 0x00, 0x00};
    len = mifare_sendcmd_short(NULL, CRYPT_NONE, ISO14443A_CMD_HALT, 0x00, receivedAnswer, NULL, NULL);
    if (len != 0) {
        if (MF_DBGLEVEL >= MF_DBG_EXTENDED) Dbprintf("halt warning. response len: %x", len);
        return 1;
    }
    return 0;
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
void emlSetMem(uint8_t *data, int blockNum, int blocksCount) {
    emlSetMem_xt(data, blockNum, blocksCount, 16);
}

void emlSetMem_xt(uint8_t *data, int blockNum, int blocksCount, int blockBtWidth) {
    uint8_t *emCARD = BigBuf_get_EM_addr();
    memcpy(emCARD + blockNum * blockBtWidth, data, blocksCount * blockBtWidth);
}

void emlGetMem(uint8_t *data, int blockNum, int blocksCount) {
    uint8_t *emCARD = BigBuf_get_EM_addr();
    memcpy(data, emCARD + blockNum * 16, blocksCount * 16);
}

void emlGetMemBt(uint8_t *data, int bytePtr, int byteCount) {
    uint8_t *emCARD = BigBuf_get_EM_addr();
    memcpy(data, emCARD + bytePtr, byteCount);
}

int emlCheckValBl(int blockNum) {
    uint8_t *emCARD = BigBuf_get_EM_addr();
    uint8_t *data = emCARD + blockNum * 16;

    if ((data[0] != (data[4] ^ 0xff)) || (data[0] != data[8]) ||
            (data[1] != (data[5] ^ 0xff)) || (data[1] != data[9]) ||
            (data[2] != (data[6] ^ 0xff)) || (data[2] != data[10]) ||
            (data[3] != (data[7] ^ 0xff)) || (data[3] != data[11]) ||
            (data[12] != (data[13] ^ 0xff)) || (data[12] != data[14]) ||
            (data[12] != (data[15] ^ 0xff))
       )
        return 1;
    return 0;
}

int emlGetValBl(uint32_t *blReg, uint8_t *blBlock, int blockNum) {
    uint8_t *emCARD = BigBuf_get_EM_addr();
    uint8_t *data = emCARD + blockNum * 16;

    if (emlCheckValBl(blockNum))
        return 1;

    memcpy(blReg, data, 4);
    *blBlock = data[12];
    return 0;
}

int emlSetValBl(uint32_t blReg, uint8_t blBlock, int blockNum) {
    uint8_t *emCARD = BigBuf_get_EM_addr();
    uint8_t *data = emCARD + blockNum * 16;

    memcpy(data + 0, &blReg, 4);
    memcpy(data + 8, &blReg, 4);
    blReg = blReg ^ 0xffffffff;
    memcpy(data + 4, &blReg, 4);

    data[12] = blBlock;
    data[13] = blBlock ^ 0xff;
    data[14] = blBlock;
    data[15] = blBlock ^ 0xff;

    return 0;
}

uint64_t emlGetKey(int sectorNum, int keyType) {
    uint8_t key[6] = {0x00};
    uint8_t *emCARD = BigBuf_get_EM_addr();
    memcpy(key, emCARD + 16 * (FirstBlockOfSector(sectorNum) + NumBlocksPerSector(sectorNum) - 1) + keyType * 10, 6);
    return bytes_to_num(key, 6);
}

void emlClearMem(void) {
    const uint8_t trailer[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x07, 0x80, 0x69, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    const uint8_t uid[]   =   {0xe6, 0x84, 0x87, 0xf3, 0x16, 0x88, 0x04, 0x00, 0x46, 0x8e, 0x45, 0x55, 0x4d, 0x70, 0x41, 0x04};
    uint8_t *emCARD = BigBuf_get_EM_addr();
    memset(emCARD, 0, CARD_MEMORY_SIZE);

    // fill sectors trailer data
    for (uint16_t b = 3; b < 256; ((b < 127) ? (b += 4) : (b += 16)))
        emlSetMem((uint8_t *)trailer, b, 1);

    // uid
    emlSetMem((uint8_t *)uid, 0, 1);
    return;
}


// Mifare desfire commands
int mifare_sendcmd_special(struct Crypto1State *pcs, uint8_t crypted, uint8_t cmd, uint8_t *data, uint8_t *answer, uint8_t *answer_parity, uint32_t *timing) {
    uint8_t dcmd[5] = {cmd, data[0], data[1], 0x00, 0x00};
    AddCrc14A(dcmd, 3);

    ReaderTransmit(dcmd, sizeof(dcmd), NULL);
    int len = ReaderReceive(answer, answer_parity);
    if (!len) {
        if (MF_DBGLEVEL >= MF_DBG_ERROR) Dbprintf("Authentication failed. Card timeout.");
        return 1;
    }
    return len;
}

int mifare_sendcmd_special2(struct Crypto1State *pcs, uint8_t crypted, uint8_t cmd, uint8_t *data, uint8_t *answer, uint8_t *answer_parity, uint32_t *timing) {
    uint8_t dcmd[20] = {0x00};
    dcmd[0] = cmd;
    memcpy(dcmd + 1, data, 17);
    AddCrc14A(dcmd, 18);

    ReaderTransmit(dcmd, sizeof(dcmd), NULL);
    int len = ReaderReceive(answer, answer_parity);
    if (!len) {
        if (MF_DBGLEVEL >= MF_DBG_ERROR) Dbprintf("Authentication failed. Card timeout.");
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

    len = mifare_sendcmd_special(NULL, 1, 0x02, data, receivedAnswer, receivedAnswerPar, NULL);
    if (len == 1) {
        if (MF_DBGLEVEL >= MF_DBG_ERROR)
            Dbprintf("Cmd Error: %02x", receivedAnswer[0]);
        return 1;
    }

    if (len == 12) {
        if (MF_DBGLEVEL >= MF_DBG_EXTENDED) {
            Dbprintf("Auth1 Resp: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                     receivedAnswer[0], receivedAnswer[1], receivedAnswer[2], receivedAnswer[3], receivedAnswer[4],
                     receivedAnswer[5], receivedAnswer[6], receivedAnswer[7], receivedAnswer[8], receivedAnswer[9],
                     receivedAnswer[10], receivedAnswer[11]);
        }
        memcpy(blockData, receivedAnswer, 12);
        return 0;
    }
    return 1;
}

int mifare_desfire_des_auth2(uint32_t uid, uint8_t *key, uint8_t *blockData) {

    int len;
    uint8_t data[17] = {MFDES_AUTHENTICATION_FRAME};
    memcpy(data + 1, key, 16);

    uint8_t receivedAnswer[MAX_FRAME_SIZE] = {0x00};
    uint8_t receivedAnswerPar[MAX_PARITY_SIZE] = {0x00};

    len = mifare_sendcmd_special2(NULL, 1, 0x03, data, receivedAnswer, receivedAnswerPar, NULL);

    if ((receivedAnswer[0] == 0x03) && (receivedAnswer[1] == 0xae)) {
        if (MF_DBGLEVEL >= MF_DBG_ERROR)
            Dbprintf("Auth Error: %02x %02x", receivedAnswer[0], receivedAnswer[1]);
        return 1;
    }

    if (len == 12) {
        if (MF_DBGLEVEL >= MF_DBG_EXTENDED) {
            Dbprintf("Auth2 Resp: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                     receivedAnswer[0], receivedAnswer[1], receivedAnswer[2], receivedAnswer[3], receivedAnswer[4],
                     receivedAnswer[5], receivedAnswer[6], receivedAnswer[7], receivedAnswer[8], receivedAnswer[9],
                     receivedAnswer[10], receivedAnswer[11]);
        }
        memcpy(blockData, receivedAnswer, 12);
        return 0;
    }
    return 1;
}
