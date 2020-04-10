#include "mifaredesfire.h"

#include "common.h"
#include "proxmark3_arm.h"
#include "string.h"
#include "BigBuf.h"
#include "desfire_key.h"
#include "mifareutil.h"
#include "des.h"
#include "cmd.h"
#include "dbprint.h"
#include "fpgaloader.h"
#include "iso14443a.h"
#include "crc16.h"
#include "mbedtls/aes.h"
#include "commonutil.h"
#include "util.h"
#include "mifare.h"
#include "ticks.h"

#define MAX_APPLICATION_COUNT 28
#define MAX_FILE_COUNT 16
#define MAX_DESFIRE_FRAME_SIZE 60
#define NOT_YET_AUTHENTICATED 255
#define FRAME_PAYLOAD_SIZE (MAX_DESFIRE_FRAME_SIZE - 5)
#define RECEIVE_SIZE 64

// the block number for the ISO14443-4 PCB
uint8_t pcb_blocknum = 0;
// Deselect card by sending a s-block. the crc is precalced for speed
static  uint8_t deselect_cmd[] = {0xc2, 0xe0, 0xb4};

//static uint8_t __msg[MAX_FRAME_SIZE] = { 0x0A, 0x00, 0x00, /* ..., */ 0x00 };
/*                                       PCB   CID   CMD    PAYLOAD    */
//static uint8_t __res[MAX_FRAME_SIZE];


bool InitDesfireCard() {

    pcb_blocknum = 0;

    iso14a_card_select_t card;

    iso14443a_setup(FPGA_HF_ISO14443A_READER_LISTEN);
    set_tracing(true);

    if (!iso14443a_select_card(NULL, &card, NULL, true, 0, false)) {
        if (DBGLEVEL >= DBG_ERROR) DbpString("Can't select card");
        OnError(1);
        return false;
    }
    return true;
}

void MifareSendCommand(uint8_t *datain) {
    struct p {
        uint8_t flags;
        uint8_t datalen;
        uint8_t datain[FRAME_PAYLOAD_SIZE];
    } PACKED;
    struct p *payload = (struct p *) datain;

    uint8_t resp[RECEIVE_SIZE];
    memset(resp, 0, sizeof(resp));

    if (DBGLEVEL >= DBG_EXTENDED) {
        Dbprintf(" flags : %02X", payload->flags);
        Dbprintf(" len   : %02X", payload->datalen);
        print_result(" RX    : ", payload->datain, payload->datalen);
    }

    if (payload->flags & CLEARTRACE)
        clear_trace();

    if (payload->flags & INIT) {
        if (!InitDesfireCard()) {
            return;
        }
    }

    int len = DesfireAPDU(payload->datain, payload->datalen, resp);
    if (DBGLEVEL >= DBG_EXTENDED)
        print_result("RESP <--: ", resp, len);

    if (!len) {
        OnError(2);
        return;
    }

    if (payload->flags & DISCONNECT)
        OnSuccess();

    //reply_mix(CMD_ACK, 1, len, 0, resp, len);
    LED_B_ON();
    struct r {
        uint8_t len;
        uint8_t data[RECEIVE_SIZE];
    } PACKED;

    struct r rpayload;
    rpayload.len=len;
    memcpy(rpayload.data,resp,rpayload.len);
    reply_ng(CMD_HF_DESFIRE_COMMAND, PM3_SUCCESS, (uint8_t *)&rpayload, sizeof(payload));
    LED_B_OFF();
}

void MifareDesfireGetInformation() {

    LEDsoff();

    int len = 0;
    iso14a_card_select_t card;
    uint8_t resp[PM3_CMD_DATA_SIZE] = {0x00};

    struct p {
        uint8_t isOK;
        uint8_t uid[7];
        uint8_t versionHW[7];
        uint8_t versionSW[7];
        uint8_t details[14];
    } PACKED payload;

    /*
        1 = PCB                 1
        2 = cid                 2
        3 = desfire command     3
        4-5 = crc               4  key
                                5-6 crc
        PCB == 0x0A because sending CID byte.
        CID == 0x00 first card?
    */
    clear_trace();
    set_tracing(true);
    iso14443a_setup(FPGA_HF_ISO14443A_READER_LISTEN);

    // card select - information
    if (!iso14443a_select_card(NULL, &card, NULL, true, 0, false)) {
        if (DBGLEVEL >= DBG_ERROR) DbpString("Can't select card");
        payload.isOK = 1;  // 2 == can not select
        reply_ng(CMD_HF_DESFIRE_INFO, PM3_ESOFT, (uint8_t *)&payload, sizeof(payload));
        switch_off();
        return;
    }

    if (card.uidlen != 7) {
        if (DBGLEVEL >= DBG_ERROR) Dbprintf("Wrong UID size. Expected 7byte got %d", card.uidlen);
        payload.isOK = 2;  // 2 == WRONG UID
        reply_ng(CMD_HF_DESFIRE_INFO, PM3_ESOFT, (uint8_t *)&payload, sizeof(payload));
        switch_off();
        return;
    }
    // add uid.
    memcpy(payload.uid, card.uid, sizeof(payload.uid));

    LED_A_ON();
    uint8_t cmd[] = {0x90, GET_VERSION, 0x00, 0x00, 0x00};
    size_t cmd_len = sizeof(cmd);

    len =  DesfireAPDU(cmd, cmd_len, resp);
    if (!len) {
        print_result("ERROR <--: ", resp, len);
        payload.isOK = 3;  // 3 == DOESNT ANSWER TO GET_VERSION
        reply_ng(CMD_HF_DESFIRE_INFO, PM3_ESOFT, (uint8_t *)&payload, sizeof(payload));
        switch_off();
        return;
    }

    memcpy(payload.versionHW, resp + 1, sizeof(payload.versionHW));

    // ADDITION_FRAME 1
    cmd[1] = ADDITIONAL_FRAME;
    len =  DesfireAPDU(cmd, cmd_len, resp);
    if (!len) {
        print_result("ERROR <--: ", resp, len);
        payload.isOK = 3;  // 3 == DOESNT ANSWER TO GET_VERSION
        reply_ng(CMD_HF_DESFIRE_INFO, PM3_ESOFT, (uint8_t *)&payload, sizeof(payload));
        switch_off();
        return;
    }
    memcpy(payload.versionSW, resp + 1,  sizeof(payload.versionSW));

    // ADDITION_FRAME 2
    len =  DesfireAPDU(cmd, cmd_len, resp);
    if (!len) {
        print_result("ERROR <--: ", resp, len);
        payload.isOK = 3;  // 3 == DOESNT ANSWER TO GET_VERSION
        reply_ng(CMD_HF_DESFIRE_INFO, PM3_ESOFT, (uint8_t *)&payload, sizeof(payload));
        switch_off();
        return;
    }

    memcpy(payload.details, resp + 1,  sizeof(payload.details));

    LED_B_ON();
    reply_ng(CMD_HF_DESFIRE_INFO, PM3_SUCCESS, (uint8_t *)&payload, sizeof(payload));
    LED_B_OFF();

    // reset the pcb_blocknum,
    pcb_blocknum = 0;
    OnSuccess();
}

typedef enum {
    MFDES_AUTH_DES = 1,
    MFDES_AUTH_ISO = 2,
    MFDES_AUTH_AES = 3,
    MFDES_AUTH_PICC = 4
} mifare_des_authmode_t;

typedef enum {
    MFDES_ALGO_DES = 1,
    MFDES_ALGO_3DES = 2,
    MFDES_ALGO_3K3DES = 3,
    MFDES_ALGO_AES = 4
} mifare_des_authalgo_t;

void MifareDES_Auth1(uint8_t *datain) {
    int len = 0;
    struct p {
        uint8_t mode;
        uint8_t algo;
        uint8_t keyno;
        uint8_t key[24];
        uint8_t keylen;
    } PACKED;
    struct p *payload = (struct p *) datain;

    // 3 different way to authenticate   AUTH (CRC16) , AUTH_ISO (CRC32) , AUTH_AES (CRC32)
    // 4 different crypto arg1   DES, 3DES, 3K3DES, AES
    // 3 different communication modes,  PLAIN,MAC,CRYPTO

    mbedtls_aes_context ctx;

    uint8_t keybytes[24];
    uint8_t resp[256] = {0x00};
    uint8_t cmd[40] = {0x00};

    // Crypt constants
    uint8_t IV[16] = {0x00};
    uint8_t RndA[16] = {0x00};
    uint8_t RndB[16] = {0x00};
    uint8_t encRndB[16] = {0x00};
    uint8_t rotRndB[16] = {0x00}; //RndB'
    uint8_t both[32] = {0x00}; // ek/dk_keyNo(RndA+RndB')

    // Generate Random Value
    uint32_t value = prng_successor(GetTickCount(), 32);
    num_to_bytes(value, 4, &RndA[0]);
    value = prng_successor(GetTickCount(), 32);
    num_to_bytes(value, 4, &RndA[4]);
    value = prng_successor(GetTickCount(), 32);
    num_to_bytes(value, 4, &RndA[8]);
    value = prng_successor(GetTickCount(), 32);
    num_to_bytes(value, 4, &RndA[12]);

    // Default Keys
    uint8_t PICC_MASTER_KEY8[8] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
    uint8_t PICC_MASTER_KEY16[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    //uint8_t null_key_data16[16] = {0x00};
    //uint8_t new_key_data8[8]  = { 0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77};
    //uint8_t new_key_data16[16]  = { 0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};


    //InitDesfireCard();

    // Part 1
    LED_A_ON();
    LED_B_OFF();
    LED_C_OFF();

    if (payload->key==NULL)
    {
            if (payload->mode==MFDES_AUTH_DES || payload->mode==MFDES_AUTH_PICC)
            {
                memcpy(keybytes, PICC_MASTER_KEY8, 8);
            }
            else if (payload->mode==MFDES_AUTH_AES)
            {
                memcpy(keybytes, PICC_MASTER_KEY16, 16);
            }
    }
    else {
        memcpy(keybytes, payload->key, payload->keylen);
        }

    struct desfire_key defaultkey = {0};
    desfirekey_t key = &defaultkey;

    if (payload->algo==MFDES_ALGO_AES) {
            mbedtls_aes_init(&ctx);
            Desfire_aes_key_new(keybytes, key);
    }
    else if (payload->algo == MFDES_ALGO_3DES) {
        key->type=T_3DES;
        Desfire_3des_key_new_with_version(keybytes, key);
    }
    else if (payload->algo == MFDES_ALGO_DES) {
        key->type=T_DES;
        Desfire_des_key_new(keybytes, key);
    }
    else if (payload->algo == MFDES_ALGO_3K3DES) {
        Desfire_3k3des_key_new_with_version(keybytes, key);
    }

    uint8_t subcommand=AUTHENTICATE;

    if (payload->mode==MFDES_AUTH_AES)
        subcommand=AUTHENTICATE_AES;
    else if (payload->mode==MFDES_AUTH_ISO)
        subcommand=AUTHENTICATE_ISO;

    if (payload->mode != MFDES_AUTH_PICC) {
        // Let's send our auth command
        cmd[0] = 0x90;
        cmd[1] = subcommand;
        cmd[2] = 0x0;
        cmd[3] = 0x0;
        cmd[4] = 0x1;
        cmd[5] = payload->keyno;
        cmd[6] = 0x0;
        len = DesfireAPDU(cmd, 7, resp);
    }
    else {
        cmd[0] = AUTHENTICATE;
        cmd[1] = payload->keyno;
        len = DesfireAPDU(cmd, 2, resp);
    }

    if (!len) {
        if (DBGLEVEL >= DBG_ERROR) {
            DbpString("Authentication failed. Card timeout.");
        }
        OnErrorNG(CMD_HF_DESFIRE_AUTH1,3);
        return;
    }

    if (resp[2] == (uint8_t)0xaf) {
        DbpString("Authentication failed. Invalid key number.");
        OnErrorNG(CMD_HF_DESFIRE_AUTH1,3);
        return;
    }

    // Part 2
    if (payload->mode != MFDES_AUTH_PICC) {
        memcpy(encRndB, resp + 1, payload->keylen);
    } else {
        memcpy(encRndB, resp + 2, payload->keylen);
    }

    // Part 3
    if (payload->algo==MFDES_ALGO_AES) {
        if (mbedtls_aes_setkey_dec(&ctx, key->data, 128) != 0) {
            if (DBGLEVEL >= DBG_EXTENDED) {
                DbpString("mbedtls_aes_setkey_dec failed");
            }
            OnErrorNG(CMD_HF_DESFIRE_AUTH1,7);
            return;
        }
        mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT, 16, IV, encRndB, RndB);
    }
    else if (payload->algo == MFDES_ALGO_3DES)
        tdes_dec(&RndB, &encRndB, key->data);
    else if (payload->algo == MFDES_ALGO_DES)
        des_dec(&RndB, &encRndB, key->data);

    // - Rotate RndB by 8 bits
    memcpy(rotRndB, RndB, payload->keylen);
    rol(rotRndB, payload->keylen);

    uint8_t encRndA[16] = {0x00};

    // - Encrypt our response
    if (payload->mode==MFDES_AUTH_DES || payload->mode==MFDES_AUTH_PICC) {
        if (payload->algo == MFDES_ALGO_3DES)
            tdes_dec(&encRndA, &RndA, key->data);
        else if (payload->algo == MFDES_ALGO_DES)
            des_dec(&encRndA, &RndA, key->data);

        memcpy(both, encRndA, 8);

        for (int x = 0; x < 8; x++) {
            rotRndB[x] = rotRndB[x] ^ encRndA[x];
        }

        if (payload->algo == MFDES_ALGO_3DES)
            tdes_dec(&encRndB, &rotRndB, key->data);
        else if (payload->algo == MFDES_ALGO_DES)
            des_dec(&encRndB, &rotRndB, key->data);

        memcpy(both + 8, encRndB, 8);
    }
    else if (payload->mode==MFDES_AUTH_AES || payload->mode==MFDES_AUTH_ISO) {
        uint8_t tmp[32] = {0x00};
        memcpy(tmp, RndA, 16);
        memcpy(tmp + 16, rotRndB, 16);
        if (payload->algo==MFDES_ALGO_AES) {
            if (mbedtls_aes_setkey_enc(&ctx, key->data, 128) != 0) {
                if (DBGLEVEL >= DBG_EXTENDED) {
                    DbpString("mbedtls_aes_setkey_enc failed");
                }
                OnErrorNG(CMD_HF_DESFIRE_AUTH1,7);
                return;
            }
            mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT, 32, IV, tmp, both);
        }
    }

    if (payload->mode != MFDES_AUTH_PICC) {
        cmd[0] = 0x90;
        cmd[1] = ADDITIONAL_FRAME;
        cmd[2] = 0x00;
        cmd[3] = 0x00;
        cmd[4] = (payload->keylen * 2);
        memcpy(cmd + 5, both, payload->keylen * 2);
        cmd[(payload->keylen * 2) + 5] = 0x0;
        len = DesfireAPDU(cmd, 5 + (payload->keylen * 2) + 1, resp);
    } else {
        cmd[0] = ADDITIONAL_FRAME;
        memcpy(cmd + 1, both, 16);
        len = DesfireAPDU(cmd, 1 + 16, resp);
    }

    if (!len) {
        if (DBGLEVEL >= DBG_ERROR) {
            DbpString("Authentication failed. Card timeout.");
        }
        OnErrorNG(CMD_HF_DESFIRE_AUTH1,3);
        return;
    }

    if (payload->mode != MFDES_AUTH_PICC) {
        if ((resp[len - 4] != 0x91) || (resp[len - 3] != 0x00)) {
            DbpString("Authentication failed.");
            OnErrorNG(CMD_HF_DESFIRE_AUTH1,6);
            return;
        }
    }
    else {
        if (resp[1] != 0x00) {
            DbpString("Authentication failed.");
            OnErrorNG(CMD_HF_DESFIRE_AUTH1,6);
            return;
        }
    }

    // Part 4
    struct desfire_key sessionKey = {0};
    desfirekey_t skey = &sessionKey;
    Desfire_session_key_new(RndA, RndB, key, skey);
    if (DBGLEVEL >= DBG_EXTENDED)
        print_result("SESSIONKEY : ", skey->data, payload->keylen);

    if (payload->mode != MFDES_AUTH_PICC) {
        memcpy(encRndA, resp + 1, payload->keylen);
    }
    else {
        memcpy(encRndA, resp + 2, payload->keylen);
    }

    if (payload->mode==MFDES_AUTH_DES || payload->mode==MFDES_AUTH_PICC) {
        if (payload->algo == MFDES_ALGO_3DES)
            tdes_dec(&encRndA, &encRndA, key->data);
        else if (payload->algo == MFDES_ALGO_DES)
            des_dec(&encRndA, &encRndA, key->data);
    }
    else if (payload->mode==MFDES_AUTH_AES) {
        if (mbedtls_aes_setkey_dec(&ctx, key->data, 128) != 0) {
            if (DBGLEVEL >= DBG_EXTENDED) {
                DbpString("mbedtls_aes_setkey_dec failed");
            }
            OnErrorNG(CMD_HF_DESFIRE_AUTH1,7);
            return;
        }
        mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT, 16, IV, encRndA, encRndA);
    }

    rol(RndA, payload->keylen);
    if (DBGLEVEL >= DBG_EXTENDED) {
        print_result("RndA : ", RndA, payload->keylen);
        print_result("encRndA : ", encRndA, payload->keylen);
    }
    for (int x = 0; x < payload->keylen; x++) {
        if (RndA[x] != encRndA[x]) {
            DbpString("Authentication failed. Cannot verify Session Key.");
            OnErrorNG(CMD_HF_DESFIRE_AUTH1,4);
            return;
        }
    }
        //Change the selected key to a new value.

        /*
         // Current key is a 3DES key, change it to a DES key
         if (payload->algo == 2) {
        cmd[0] = 0x90;
        cmd[1] = CHANGE_KEY;
        cmd[2] = payload->keyno;

        uint8_t newKey[16] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77};

        uint8_t first, second;
        uint8_t buff1[8] = {0x00};
        uint8_t buff2[8] = {0x00};
        uint8_t buff3[8] = {0x00};

        memcpy(buff1,newKey, 8);
        memcpy(buff2,newKey + 8, 8);

        compute_crc(CRC_14443_A, newKey, 16, &first, &second);
        memcpy(buff3, &first, 1);
        memcpy(buff3 + 1, &second, 1);

         tdes_dec(&buff1, &buff1, skey->data);
         memcpy(cmd+2,buff1,8);

         for (int x = 0; x < 8; x++) {
         buff2[x] = buff2[x] ^ buff1[x];
         }
         tdes_dec(&buff2, &buff2, skey->data);
         memcpy(cmd+10,buff2,8);

         for (int x = 0; x < 8; x++) {
         buff3[x] = buff3[x] ^ buff2[x];
         }
         tdes_dec(&buff3, &buff3, skey->data);
         memcpy(cmd+19,buff3,8);

         // The command always times out on the first attempt, this will retry until a response
         // is recieved.
         len = 0;
         while(!len) {
         len = DesfireAPDU(cmd,27,resp);
         }

         } else {
            // Current key is a DES key, change it to a 3DES key
            if (payload->algo == 1) {
                cmd[0] = 0x90;
                cmd[1] = CHANGE_KEY;
                cmd[2] = payload->keyno;

                uint8_t newKey[16] = {0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f};

                uint8_t first, second;
                uint8_t buff1[8] = {0x00};
                uint8_t buff2[8] = {0x00};
                uint8_t buff3[8] = {0x00};

                memcpy(buff1,newKey, 8);
                memcpy(buff2,newKey + 8, 8);

                compute_crc(CRC_14443_A, newKey, 16, &first, &second);
                memcpy(buff3, &first, 1);
                memcpy(buff3 + 1, &second, 1);

        des_dec(&buff1, &buff1, skey->data);
        memcpy(cmd+3,buff1,8);

        for (int x = 0; x < 8; x++) {
            buff2[x] = buff2[x] ^ buff1[x];
        }
        des_dec(&buff2, &buff2, skey->data);
        memcpy(cmd+11,buff2,8);

        for (int x = 0; x < 8; x++) {
            buff3[x] = buff3[x] ^ buff2[x];
        }
        des_dec(&buff3, &buff3, skey->data);
        memcpy(cmd+19,buff3,8);

        // The command always times out on the first attempt, this will retry until a response
        // is recieved.
        len = 0;
        while(!len) {
            len = DesfireAPDU(cmd,27,resp);
        }
            }
         }
        */


    //OnSuccess();
    //reply_old(CMD_ACK, 1, 0, 0, skey->data, payload->keylen);
    //reply_mix(CMD_ACK, 1, len, 0, resp, len);

    LED_B_ON();
    struct r {
        uint8_t sessionkeylen;
        uint8_t sessionkey[24];
    } PACKED;

    struct r rpayload;
    rpayload.sessionkeylen=payload->keylen;
    memcpy(rpayload.sessionkey,skey->data,rpayload.sessionkeylen);
    reply_ng(CMD_HF_DESFIRE_AUTH1, PM3_SUCCESS, (uint8_t *)&rpayload, sizeof(payload));
    LED_B_OFF();
}

// 3 different ISO ways to send data to a DESFIRE (direct, capsuled, capsuled ISO)
// cmd  =  cmd bytes to send
// cmd_len = length of cmd
// dataout = pointer to response data array
int DesfireAPDU(uint8_t *cmd, size_t cmd_len, uint8_t *dataout) {

    size_t len = 0;
    size_t wrappedLen = 0;
    uint8_t wCmd[PM3_CMD_DATA_SIZE] = {0x00};
    uint8_t resp[MAX_FRAME_SIZE];
    uint8_t par[MAX_PARITY_SIZE];

    wrappedLen = CreateAPDU(cmd, cmd_len, wCmd);

    if (DBGLEVEL >= DBG_EXTENDED)
        print_result("WCMD <--: ", wCmd, wrappedLen);

    ReaderTransmit(wCmd, wrappedLen, NULL);

    len = ReaderReceive(resp, par);
    if (!len) {
        if (DBGLEVEL >= DBG_EXTENDED) Dbprintf("fukked");
        return false; //DATA LINK ERROR
    }
    // if we received an I- or R(ACK)-Block with a block number equal to the
    // current block number, toggle the current block number
    if (len >= 4 // PCB+CID+CRC = 4 bytes
            && ((resp[0] & 0xC0) == 0 // I-Block
                || (resp[0] & 0xD0) == 0x80) // R-Block with ACK bit set to 0
            && (resp[0] & 0x01) == pcb_blocknum) { // equal block numbers
        pcb_blocknum ^= 1;  //toggle next block
    }

    memcpy(dataout, resp, len);
    return len;
}

// CreateAPDU
size_t CreateAPDU(uint8_t *datain, size_t len, uint8_t *dataout) {

    size_t cmdlen = MIN(len + 3, PM3_CMD_DATA_SIZE - 1);

    uint8_t cmd[cmdlen];
    memset(cmd, 0, cmdlen);

    cmd[0] = 0x02;  //  0x0A = send cid,  0x02 = no cid.
    cmd[0] |= pcb_blocknum; // OR the block number into the PCB

    if (DBGLEVEL >= DBG_EXTENDED) Dbprintf("pcb_blocknum %d == %d ", pcb_blocknum, cmd[0]);

    //cmd[1] = 0x90;  //  CID: 0x00 //TODO: allow multiple selected cards

    memcpy(cmd + 1, datain, len);
    AddCrc14A(cmd, len + 1);

    /*
    hf 14a apdu -sk 90 60 00 00 00
    hf 14a apdu -k 90 AF 00 00 00
    hf 14a apdu 90AF000000
    */
    memcpy(dataout, cmd, cmdlen);
    return cmdlen;
}

// crc_update(&desfire_crc32, 0, 1); /* CMD_WRITE */
// crc_update(&desfire_crc32, addr, addr_sz);
// crc_update(&desfire_crc32, byte, 8);
// uint32_t crc = crc_finish(&desfire_crc32);

void OnSuccess() {
    pcb_blocknum = 0;
    ReaderTransmit(deselect_cmd, 3, NULL);
    if (mifare_ultra_halt()) {
        if (DBGLEVEL >= DBG_ERROR) Dbprintf("Halt error");
    }
    switch_off();
}

void OnError(uint8_t reason) {
    reply_mix(CMD_ACK, 0, reason, 0, 0, 0);
    OnSuccess();
}

void OnErrorNG(uint16_t cmd, uint8_t reason) {
    reply_ng(cmd, reason, NULL, 0);
    OnSuccess();
}