//-----------------------------------------------------------------------------
// Borrowed initially from https://nethemba.com/tag/darkside-attack/
// Copyright (C) mifare@nethemba.com, 2010
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
// mifare commands
//-----------------------------------------------------------------------------
#include "mifarehost.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "comms.h"
#include "commonutil.h"
#include "mifare4.h"
#include "ui.h"                 // PrintAndLog...
#include "crapto1/crapto1.h"
#include "crc16.h"
#include "protocols.h"
#include "mfkey.h"
#include "util_posix.h"         // msclock
#include "cmdparser.h"          // detection of flash capabilities
#include "cmdflashmemspiffs.h"  // upload to flash mem
#include "mifaredefault.h"      // default keys
#include "protocol_vigik.h"     // VIGIK struct
#include "crypto/libpcrypto.h"
#include "util.h" // xor
#include "mbedtls/sha1.h"       // SHA1

int mfDarkside(uint8_t blockno, uint8_t key_type, uint64_t *key) {
    uint32_t uid = 0;
    uint32_t nt = 0, nr = 0, ar = 0;
    uint64_t par_list = 0, ks_list = 0;
    uint64_t *keylist = NULL, *last_keylist = NULL;
    bool first_run = true;

    // message
    PrintAndLogEx(INFO, "Expected execution time is about 25seconds on average");
    PrintAndLogEx(INFO, "Press pm3-button to abort");

    while (true) {
        clearCommandBuffer();
        struct {
            uint8_t first_run;
            uint8_t blockno;
            uint8_t key_type;
        } PACKED payload;
        payload.first_run = first_run;
        payload.blockno = blockno;
        payload.key_type = key_type;
        SendCommandNG(CMD_HF_MIFARE_READER, (uint8_t *)&payload, sizeof(payload));

        //flush queue
        while (kbd_enter_pressed()) {
            SendCommandNG(CMD_BREAK_LOOP, NULL, 0);
            return PM3_EOPABORTED;
        }

        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(INFO, "Running darkside " NOLF);

        // wait cycle
        while (true) {
            PrintAndLogEx(NORMAL, "." NOLF);

            if (kbd_enter_pressed()) {
                SendCommandNG(CMD_BREAK_LOOP, NULL, 0);
                return PM3_EOPABORTED;
            }

            PacketResponseNG resp;
            if (WaitForResponseTimeout(CMD_HF_MIFARE_READER, &resp, 2000)) {
                if (resp.status == PM3_EOPABORTED) {
                    return resp.status;
                }

                struct p {
                    int32_t isOK;
                    uint8_t cuid[4];
                    uint8_t nt[4];
                    uint8_t par_list[8];
                    uint8_t ks_list[8];
                    uint8_t nr[4];
                    uint8_t ar[4];
                } PACKED;

                struct p *package = (struct p *) resp.data.asBytes;

                if (package->isOK == -6) {
                    *key = 0101;
                    return 1;
                }

                if (package->isOK < 0)
                    return package->isOK;


                uid = (uint32_t)bytes_to_num(package->cuid, sizeof(package->cuid));
                nt = (uint32_t)bytes_to_num(package->nt, sizeof(package->nr));
                par_list = bytes_to_num(package->par_list, sizeof(package->par_list));
                ks_list = bytes_to_num(package->ks_list, sizeof(package->ks_list));
                nr = (uint32_t)bytes_to_num(package->nr, 4);
                ar = (uint32_t)bytes_to_num(package->ar, 4);
                break;
            }
        }
        PrintAndLogEx(NORMAL, "");

        if (par_list == 0 && first_run == true) {
            PrintAndLogEx(SUCCESS, "Parity is all zero. Most likely this card sends NACK on every authentication.");
        }
        first_run = false;

        uint32_t keycount = nonce2key(uid, nt, nr, ar, par_list, ks_list, &keylist);

        if (keycount == 0) {
            PrintAndLogEx(FAILED, "Key not found (lfsr_common_prefix list is null). Nt = %08x", nt);
            PrintAndLogEx(FAILED, "This is expected to happen in 25%% of all cases.");
            PrintAndLogEx(FAILED, "Trying again with a different reader nonce...");
            continue;
        }

        // only parity zero attack
        if (par_list == 0) {
            qsort(keylist, keycount, sizeof(*keylist), compare_uint64);
            keycount = intersection(last_keylist, keylist);
            if (keycount == 0) {
                free(last_keylist);
                last_keylist = keylist;
                PrintAndLogEx(FAILED, "No candidates found, trying again");
                continue;
            }
        }

        PrintAndLogEx(SUCCESS, "found " _YELLOW_("%u") " candidate key%s", keycount, (keycount > 1) ? "s" : "");

        *key = UINT64_C(-1);
        uint8_t keyBlock[PM3_CMD_DATA_SIZE];
        uint32_t max_keys = KEYS_IN_BLOCK;
        for (uint32_t i = 0; i < keycount; i += max_keys) {

            uint8_t size = keycount - i > max_keys ? max_keys : keycount - i;
            register uint8_t j;
            for (j = 0; j < size; j++) {
                if (par_list == 0) {
                    num_to_bytes(last_keylist[i * max_keys + j], 6, keyBlock + (j * 6));
                } else {
                    num_to_bytes(keylist[i * max_keys + j], 6, keyBlock + (j * 6));
                }
            }

            if (mfCheckKeys(blockno, key_type - 0x60, false, size, keyBlock, key) == PM3_SUCCESS) {
                break;
            }
        }

        if (*key != UINT64_C(-1)) {
            break;
        } else {
            PrintAndLogEx(FAILED, "All key candidates failed. Restarting darkside");
            free(last_keylist);
            last_keylist = keylist;
            first_run = true;
        }
    }
    free(last_keylist);
    free(keylist);
    return PM3_SUCCESS;
}

int mfCheckKeys(uint8_t blockNo, uint8_t keyType, bool clear_trace, uint8_t keycnt, uint8_t *keyBlock, uint64_t *key) {
    *key = -1;
    clearCommandBuffer();
    uint8_t data[PM3_CMD_DATA_SIZE] = {0};
    data[0] = keyType;
    data[1] = blockNo;
    data[2] = clear_trace;
    data[3] = 0;
    data[4] = keycnt;
    memcpy(data + 5, keyBlock, 6 * keycnt);
    SendCommandNG(CMD_HF_MIFARE_CHKKEYS, data, (5 + 6 * keycnt));

    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_HF_MIFARE_CHKKEYS, &resp, 2500)) {
        return PM3_ETIMEOUT;
    }
    if (resp.status != PM3_SUCCESS) {
        return resp.status;
    }

    struct kr {
        uint8_t key[6];
        bool found;
    } PACKED;
    struct kr *keyresult = (struct kr *)&resp.data.asBytes;
    if (!keyresult->found) {
        return PM3_ESOFT;
    }

    *key = bytes_to_num(keyresult->key, sizeof(keyresult->key));
    return PM3_SUCCESS;
}

// Sends chunks of keys to device.
// 0 == ok all keys found
// 1 ==
// 2 == Time-out, aborting
int mfCheckKeys_fast(uint8_t sectorsCnt, uint8_t firstChunk, uint8_t lastChunk, uint8_t strategy,
                     uint32_t size, uint8_t *keyBlock, sector_t *e_sector, bool use_flashmemory) {

    uint64_t t2 = msclock();

    // send keychunk
    clearCommandBuffer();
    SendCommandOLD(CMD_HF_MIFARE_CHKKEYS_FAST, (sectorsCnt | (firstChunk << 8) | (lastChunk << 12)), ((use_flashmemory << 8) | strategy), size, keyBlock, 6 * size);
    PacketResponseNG resp;

    uint32_t timeout = 0;
    while (!WaitForResponseTimeout(CMD_ACK, &resp, 2000)) {

        PrintAndLogEx((timeout == 0) ? INFO : NORMAL, "." NOLF);
        fflush(stdout);

        timeout++;

        // max timeout for one chunk of 85keys, 60*3sec = 180seconds
        // s70 with 40*2 keys to check, 80*85 = 6800 auth.
        // takes about 97s, still some margin before abort
        if (timeout > 180) {
            PrintAndLogEx(WARNING, "\nNo response from Proxmark3. Aborting...");
            return PM3_ETIMEOUT;
        }
    }
    t2 = msclock() - t2;

    if (timeout) {
        PrintAndLogEx(NORMAL, "");
    }

    // time to convert the returned data.
    uint8_t curr_keys = resp.oldarg[0];

    PrintAndLogEx(INFO, "Chunk %.1fs | found %u/%u keys (%u)", (float)(t2 / 1000.0), curr_keys, (sectorsCnt << 1), size);

    // all keys?
    if (curr_keys == sectorsCnt * 2 || lastChunk) {

        // success array. each byte is status of key
        uint8_t arr[80];
        uint64_t foo = 0;
        uint16_t bar = 0;
        foo = bytes_to_num(resp.data.asBytes + 480, 8);
        bar = (resp.data.asBytes[489]  << 8 | resp.data.asBytes[488]);

        for (uint8_t i = 0; i < 64; i++)
            arr[i] = (foo >> i) & 0x1;

        for (uint8_t i = 0; i < 16; i++)
            arr[i + 64] = (bar >> i) & 0x1;

        // initialize storage for found keys
        icesector_t *tmp = calloc(sectorsCnt, sizeof(icesector_t));
        if (tmp == NULL)
            return PM3_EMALLOC;

        memcpy(tmp, resp.data.asBytes, sectorsCnt * sizeof(icesector_t));

        for (int i = 0; i < sectorsCnt; i++) {
            // key A
            if (!e_sector[i].foundKey[0]) {
                e_sector[i].Key[0] =  bytes_to_num(tmp[i].keyA, 6);
                e_sector[i].foundKey[0] = arr[(i * 2) ];
            }
            // key B
            if (!e_sector[i].foundKey[1]) {
                e_sector[i].Key[1] =  bytes_to_num(tmp[i].keyB, 6);
                e_sector[i].foundKey[1] = arr[(i * 2) + 1 ];
            }
        }
        free(tmp);

        if (curr_keys == sectorsCnt * 2)
            return PM3_SUCCESS;
        if (lastChunk)
            return PM3_ESOFT;
    }
    return PM3_ESOFT;
}

// Trigger device to use a binary file on flash mem as keylist for mfCheckKeys.
// As of now,  255 keys possible in the file
// 6 * 255 = 1500 bytes
int mfCheckKeys_file(uint8_t *destfn, uint64_t *key) {
    *key = -1;
    clearCommandBuffer();

    struct {
        uint8_t filename[32];
    } PACKED payload_file;

    memcpy(payload_file.filename, destfn, sizeof(payload_file.filename) - 1);

    PacketResponseNG resp;
    clearCommandBuffer();
    SendCommandNG(CMD_HF_MIFARE_CHKKEYS_FILE, (uint8_t *)&payload_file, sizeof(payload_file));

    uint8_t retry = 10;

    while (!WaitForResponseTimeout(CMD_HF_MIFARE_CHKKEYS, &resp, 2000)) {

        //flush queue
        while (kbd_enter_pressed()) {
            SendCommandNG(CMD_BREAK_LOOP, NULL, 0);
            return PM3_EOPABORTED;
        }

        retry--;
        if (retry == 0) {
            PrintAndLogEx(WARNING, "Chk keys file, command execution time out");
            SendCommandNG(CMD_BREAK_LOOP, NULL, 0);
            return PM3_ETIMEOUT;
        }
    }

    if (resp.status != PM3_SUCCESS) return resp.status;

    struct kr {
        uint8_t key[6];
        bool found;
    } PACKED;
    struct kr *keyresult = (struct kr *)&resp.data.asBytes;
    if (!keyresult->found) return PM3_ESOFT;

    *key = bytes_to_num(keyresult->key, sizeof(keyresult->key));
    return PM3_SUCCESS;
}

// PM3 imp of J-Run mf_key_brute (part 2)
// ref: https://github.com/J-Run/mf_key_brute
int mfKeyBrute(uint8_t blockNo, uint8_t keyType, const uint8_t *key, uint64_t *resultkey) {

    uint64_t key64;
    uint8_t found = false;
    uint8_t candidates[CANDIDATE_SIZE] = {0x00};
    uint8_t keyBlock[KEYBLOCK_SIZE] = {0x00};

    memset(candidates, 0, sizeof(candidates));
    memset(keyBlock, 0, sizeof(keyBlock));

    // Generate all possible keys for the first two unknown bytes.
    for (uint16_t i = 0; i < 0xFFFF; ++i) {
        uint32_t j = i * 6;
        candidates[0 + j] = i >> 8;
        candidates[1 + j] = i;
        candidates[2 + j] = key[2];
        candidates[3 + j] = key[3];
        candidates[4 + j] = key[4];
        candidates[5 + j] = key[5];
    }
    uint32_t counter, i;
    for (i = 0, counter = 1; i < CANDIDATE_SIZE; i += KEYBLOCK_SIZE, ++counter) {

        key64 = 0;

        // copy candidatekeys to test key block
        memcpy(keyBlock, candidates + i, KEYBLOCK_SIZE);

        // check a block of generated key candidates.
        if (mfCheckKeys(blockNo, keyType, true, KEYS_IN_BLOCK, keyBlock, &key64) == PM3_SUCCESS) {
            *resultkey = key64;
            found = true;
            break;
        }

        // progress
        if (counter % 20 == 0)
            PrintAndLogEx(SUCCESS, "tried %s.. \t %u keys", sprint_hex(candidates + i, 6),  counter * KEYS_IN_BLOCK);
    }
    return found;
}

// Compare 16 Bits out of cryptostate
inline static int Compare16Bits(const void *a, const void *b) {
    if ((*(uint64_t *)b & 0x00ff000000ff0000) == (*(uint64_t *)a & 0x00ff000000ff0000)) return 0;
    if ((*(uint64_t *)b & 0x00ff000000ff0000) > (*(uint64_t *)a & 0x00ff000000ff0000)) return 1;
    return -1;
}

// wrapper function for multi-threaded lfsr_recovery32
static void
#ifdef __has_attribute
#if __has_attribute(force_align_arg_pointer)
__attribute__((force_align_arg_pointer))
#endif
#endif
*nested_worker_thread(void *arg) {
    struct Crypto1State *p1;
    StateList_t *statelist = arg;
    statelist->head.slhead = lfsr_recovery32(statelist->ks1, statelist->nt_enc ^ statelist->uid);

    for (p1 = statelist->head.slhead; p1->odd | p1->even; p1++) {};

    statelist->len = p1 - statelist->head.slhead;
    statelist->tail.sltail = --p1;

    qsort(statelist->head.slhead, statelist->len, sizeof(uint64_t), Compare16Bits);

    return statelist->head.slhead;
}

int mfnested(uint8_t blockNo, uint8_t keyType, uint8_t *key, uint8_t trgBlockNo, uint8_t trgKeyType, uint8_t *resultKey, bool calibrate) {

    uint32_t uid;
    StateList_t statelists[2];
    struct Crypto1State *p1, *p2, *p3, *p4;

    struct {
        uint8_t block;
        uint8_t keytype;
        uint8_t target_block;
        uint8_t target_keytype;
        bool calibrate;
        uint8_t key[6];
    } PACKED payload;
    payload.block = blockNo;
    payload.keytype = keyType;
    payload.target_block = trgBlockNo;
    payload.target_keytype = trgKeyType;
    payload.calibrate = calibrate;
    memcpy(payload.key, key, sizeof(payload.key));

    PacketResponseNG resp;
    clearCommandBuffer();
    SendCommandNG(CMD_HF_MIFARE_NESTED, (uint8_t *)&payload, sizeof(payload));

    if (WaitForResponseTimeout(CMD_HF_MIFARE_NESTED, &resp, 2000) == false) {
        SendCommandNG(CMD_BREAK_LOOP, NULL, 0);
        return PM3_ETIMEOUT;
    }

    struct p {
        int16_t isOK;
        uint8_t block;
        uint8_t keytype;
        uint8_t cuid[4];
        uint8_t nt_a[4];
        uint8_t ks_a[4];
        uint8_t nt_b[4];
        uint8_t ks_b[4];
    } PACKED;
    struct p *package = (struct p *)resp.data.asBytes;

    // error during nested on device side
    if (package->isOK != PM3_SUCCESS)
        return package->isOK;

    memcpy(&uid, package->cuid, sizeof(package->cuid));

    for (uint8_t i = 0; i < 2; i++) {
        statelists[i].blockNo = package->block;
        statelists[i].keyType = package->keytype;
        statelists[i].uid = uid;
    }

    memcpy(&statelists[0].nt_enc,  package->nt_a, sizeof(package->nt_a));
    memcpy(&statelists[0].ks1, package->ks_a, sizeof(package->ks_a));

    memcpy(&statelists[1].nt_enc,  package->nt_b, sizeof(package->nt_b));
    memcpy(&statelists[1].ks1, package->ks_b, sizeof(package->ks_b));

    // calc keys
    pthread_t thread_id[2];

    // create and run worker threads
    for (uint8_t i = 0; i < 2; i++)
        pthread_create(thread_id + i, NULL, nested_worker_thread, &statelists[i]);

    // wait for threads to terminate:
    for (uint8_t i = 0; i < 2; i++)
        pthread_join(thread_id[i], (void *)&statelists[i].head.slhead);

    // the first 16 Bits of the cryptostate already contain part of our key.
    // Create the intersection of the two lists based on these 16 Bits and
    // roll back the cryptostate
    p1 = p3 = statelists[0].head.slhead;
    p2 = p4 = statelists[1].head.slhead;

    while (p1 <= statelists[0].tail.sltail && p2 <= statelists[1].tail.sltail) {
        if (Compare16Bits(p1, p2) == 0) {

            struct Crypto1State savestate;
            savestate = *p1;
            while (Compare16Bits(p1, &savestate) == 0 && p1 <= statelists[0].tail.sltail) {
                *p3 = *p1;
                lfsr_rollback_word(p3, statelists[0].nt_enc ^ statelists[0].uid, 0);
                p3++;
                p1++;
            }
            savestate = *p2;
            while (Compare16Bits(p2, &savestate) == 0 && p2 <= statelists[1].tail.sltail) {
                *p4 = *p2;
                lfsr_rollback_word(p4, statelists[1].nt_enc ^ statelists[1].uid, 0);
                p4++;
                p2++;
            }
        } else {
            while (Compare16Bits(p1, p2) == -1) p1++;
            while (Compare16Bits(p1, p2) == 1) p2++;
        }
    }

    p3->odd = -1;
    p3->even = -1;
    p4->odd = -1;
    p4->even = -1;
    statelists[0].len = p3 - statelists[0].head.slhead;
    statelists[1].len = p4 - statelists[1].head.slhead;
    statelists[0].tail.sltail = --p3;
    statelists[1].tail.sltail = --p4;

    // the statelists now contain possible keys. The key we are searching for must be in the
    // intersection of both lists
    qsort(statelists[0].head.keyhead, statelists[0].len, sizeof(uint64_t), compare_uint64);
    qsort(statelists[1].head.keyhead, statelists[1].len, sizeof(uint64_t), compare_uint64);
    // Create the intersection
    statelists[0].len = intersection(statelists[0].head.keyhead, statelists[1].head.keyhead);

    //statelists[0].tail.keytail = --p7;
    uint32_t keycnt = statelists[0].len;
    if (keycnt == 0) goto out;

    PrintAndLogEx(SUCCESS, "Found " _YELLOW_("%u") " key candidates", keycnt);

    memset(resultKey, 0, 6);
    uint64_t key64 = -1;

    // The list may still contain several key candidates. Test each of them with mfCheckKeys
    uint32_t max_keys = keycnt > KEYS_IN_BLOCK ? KEYS_IN_BLOCK : keycnt;
    uint8_t keyBlock[PM3_CMD_DATA_SIZE] = {0x00};

    for (uint32_t i = 0; i < keycnt; i += max_keys) {

        uint64_t start_time = msclock();

        uint8_t size = keycnt - i > max_keys ? max_keys : keycnt - i;

        register uint8_t j;
        for (j = 0; j < size; j++) {
            crypto1_get_lfsr(statelists[0].head.slhead + i, &key64);
            num_to_bytes(key64, 6, keyBlock + j * 6);
        }

        if (mfCheckKeys(statelists[0].blockNo, statelists[0].keyType, false, size, keyBlock, &key64) == PM3_SUCCESS) {
            free(statelists[0].head.slhead);
            free(statelists[1].head.slhead);
            num_to_bytes(key64, 6, resultKey);

            PrintAndLogEx(SUCCESS, "\nTarget block %4u key type %c -- found valid key [ " _GREEN_("%s") " ]",
                          package->block,
                          package->keytype ? 'B' : 'A',
                          sprint_hex_inrow(resultKey, 6)
                         );
            return PM3_SUCCESS;
        }

        float bruteforce_per_second = (float)(i + max_keys) / ((msclock() - start_time) / 1000.0);
        PrintAndLogEx(INPLACE, "%6d/%u keys | %5.1f keys/sec | worst case %6.1f seconds remaining", i, keycnt, bruteforce_per_second, (keycnt - i) / bruteforce_per_second);
    }

out:
    PrintAndLogEx(SUCCESS, "\nTarget block %4u key type %c",
                  package->block,
                  package->keytype ? 'B' : 'A'
                 );

    free(statelists[0].head.slhead);
    free(statelists[1].head.slhead);
    return PM3_ESOFT;
}

int mfStaticNested(uint8_t blockNo, uint8_t keyType, uint8_t *key, uint8_t trgBlockNo, uint8_t trgKeyType, uint8_t *resultKey) {

    uint32_t uid;
    StateList_t statelists[2];
    struct Crypto1State *p1, * p2, * p3, * p4;

    struct {
        uint8_t block;
        uint8_t keytype;
        uint8_t target_block;
        uint8_t target_keytype;
        uint8_t key[6];
    } PACKED payload;
    payload.block = blockNo;
    payload.keytype = keyType;
    payload.target_block = trgBlockNo;
    payload.target_keytype = trgKeyType;
    memcpy(payload.key, key, sizeof(payload.key));

    PacketResponseNG resp;
    clearCommandBuffer();
    SendCommandNG(CMD_HF_MIFARE_STATIC_NESTED, (uint8_t *)&payload, sizeof(payload));

    if (WaitForResponseTimeout(CMD_HF_MIFARE_STATIC_NESTED, &resp, 2000) == false)
        return PM3_ETIMEOUT;

    if (resp.status != PM3_SUCCESS)
        return resp.status;

    struct p {
        uint8_t block;
        uint8_t keytype;
        uint8_t cuid[4];
        uint8_t nt_a[4];
        uint8_t ks_a[4];
        uint8_t nt_b[4];
        uint8_t ks_b[4];
    } PACKED;
    struct p *package = (struct p *)resp.data.asBytes;

    memcpy(&uid, package->cuid, sizeof(package->cuid));

    for (uint8_t i = 0; i < 2; i++) {
        statelists[i].blockNo = package->block;
        statelists[i].keyType = package->keytype;
        statelists[i].uid = uid;
    }

    memcpy(&statelists[0].nt_enc, package->nt_a, sizeof(package->nt_a));
    memcpy(&statelists[0].ks1, package->ks_a, sizeof(package->ks_a));

    memcpy(&statelists[1].nt_enc, package->nt_b, sizeof(package->nt_b));
    memcpy(&statelists[1].ks1, package->ks_b, sizeof(package->ks_b));

    // calc keys
    pthread_t thread_id[2];

    // create and run worker threads
    for (uint8_t i = 0; i < 2; i++)
        pthread_create(thread_id + i, NULL, nested_worker_thread, &statelists[i]);

    // wait for threads to terminate:
    for (uint8_t i = 0; i < 2; i++)
        pthread_join(thread_id[i], (void *)&statelists[i].head.slhead);

    // the first 16 Bits of the cryptostate already contain part of our key.
    // Create the intersection of the two lists based on these 16 Bits and
    // roll back the cryptostate
    p1 = p3 = statelists[0].head.slhead;
    p2 = p4 = statelists[1].head.slhead;

    while (p1 <= statelists[0].tail.sltail && p2 <= statelists[1].tail.sltail) {
        if (Compare16Bits(p1, p2) == 0) {

            struct Crypto1State savestate;
            savestate = *p1;
            while (Compare16Bits(p1, &savestate) == 0 && p1 <= statelists[0].tail.sltail) {
                *p3 = *p1;
                lfsr_rollback_word(p3, statelists[0].nt_enc ^ statelists[0].uid, 0);
                p3++;
                p1++;
            }
            savestate = *p2;
            while (Compare16Bits(p2, &savestate) == 0 && p2 <= statelists[1].tail.sltail) {
                *p4 = *p2;
                lfsr_rollback_word(p4, statelists[1].nt_enc ^ statelists[1].uid, 0);
                p4++;
                p2++;
            }
        } else {
            while (Compare16Bits(p1, p2) == -1) p1++;
            while (Compare16Bits(p1, p2) == 1) p2++;
        }
    }

    p3->odd = -1;
    p3->even = -1;
    p4->odd = -1;
    p4->even = -1;
    statelists[0].len = p3 - statelists[0].head.slhead;
    statelists[1].len = p4 - statelists[1].head.slhead;
    statelists[0].tail.sltail = --p3;
    statelists[1].tail.sltail = --p4;

    // the statelists now contain possible keys. The key we are searching for must be in the
    // intersection of both lists
    qsort(statelists[0].head.keyhead, statelists[0].len, sizeof(uint64_t), compare_uint64);
    qsort(statelists[1].head.keyhead, statelists[1].len, sizeof(uint64_t), compare_uint64);
    // Create the intersection
    statelists[0].len = intersection(statelists[0].head.keyhead, statelists[1].head.keyhead);


    /*

        memcpy(&uid, package->cuid, sizeof(package->cuid));

        statelists[0].blockNo = package->block;
        statelists[0].keyType = package->keytype;
        statelists[0].uid = uid;

        memcpy(&statelists[0].nt_enc, package->nt, sizeof(package->nt));
        memcpy(&statelists[0].ks1, package->ks, sizeof(package->ks));

        // calc keys
        pthread_t t;

        // create and run worker thread
        pthread_create(&t, NULL, nested_worker_thread, &statelists[0]);

        // wait for thread to terminate:
        pthread_join(t, (void *)&statelists[0].head.slhead);

        // the first 16 Bits of the cryptostate already contain part of our key.
        p1 = p3 = statelists[0].head.slhead;

        // create key candidates.
        while (p1 <= statelists[0].tail.sltail) {
            struct Crypto1State savestate;
            savestate = *p1;
            while (Compare16Bits(p1, &savestate) == 0 && p1 <= statelists[0].tail.sltail) {
                *p3 = *p1;
                lfsr_rollback_word(p3, statelists[0].nt_enc ^ statelists[0].uid, 0);
                p3++;
                p1++;
            }
        }

        p3->odd = -1;
        p3->even = -1;
        statelists[0].len = p3 - statelists[0].head.slhead;
        statelists[0].tail.sltail = --p3;
    */

    uint32_t keycnt = statelists[0].len;
    if (keycnt == 0) goto out;

    PrintAndLogEx(SUCCESS, "Found " _YELLOW_("%u") " key candidates", keycnt);

    memset(resultKey, 0, 6);

    // The list may still contain several key candidates. Test each of them with mfCheckKeys
    uint32_t maxkeysinblock = IfPm3Flash() ? 1000 : KEYS_IN_BLOCK;
    uint32_t max_keys_chunk = keycnt > maxkeysinblock ? maxkeysinblock : keycnt;

    uint8_t *mem = NULL;
    uint8_t *p_keyblock = NULL;

    // if RDV4 and more than 10 candidate keys
    if (IfPm3Flash() && keycnt > 70) {

        // used for mfCheckKeys_file, which needs a header
        mem = calloc((maxkeysinblock * 6) + 5, sizeof(uint8_t));
        if (mem == NULL) {
            free(statelists[0].head.slhead);
            return PM3_EMALLOC;
        }

        mem[0] = statelists[0].keyType;
        mem[1] = statelists[0].blockNo;
        mem[2] = 1;
        mem[3] = ((max_keys_chunk >> 8) & 0xFF);
        mem[4] = (max_keys_chunk & 0xFF);

        p_keyblock = mem + 5;
    } else {

        // used for mfCheckKeys, which adds its own header.
        mem = calloc((maxkeysinblock * 6), sizeof(uint8_t));
        if (mem == NULL) {
            free(statelists[0].head.slhead);
            return PM3_EMALLOC;
        }
        p_keyblock = mem;
    }

    uint8_t fn[32] = "static_nested_000.bin";

    uint64_t start_time = msclock();
    for (uint32_t i = 0; i < keycnt; i += max_keys_chunk) {

        //flush queue
        while (kbd_enter_pressed()) {
            SendCommandNG(CMD_BREAK_LOOP, NULL, 0);
            PrintAndLogEx(NORMAL, "");
            free(mem);
            return PM3_EOPABORTED;
        }

        int res = 0;
        uint64_t key64 = 0;
        uint32_t chunk = keycnt - i > max_keys_chunk ? max_keys_chunk : keycnt - i;

        // copy x keys to device.
        for (uint32_t j = 0; j < chunk; j++) {
            crypto1_get_lfsr(statelists[0].head.slhead + i + j, &key64);
            num_to_bytes(key64, 6, p_keyblock + j * 6);
        }

        // check a block of generated key candidates.
        if (IfPm3Flash() && keycnt > 70) {

            mem[3] = ((chunk >> 8) & 0xFF);
            mem[4] = (chunk & 0xFF);

            // upload to flash.
            res = flashmem_spiffs_load((char *)fn, mem, 5 + (chunk * 6));
            if (res != PM3_SUCCESS) {
                PrintAndLogEx(WARNING, "\nSPIFFS upload failed");
                free(mem);
                return res;
            }
            res = mfCheckKeys_file(fn, &key64);
        } else {
            res = mfCheckKeys(statelists[0].blockNo, statelists[0].keyType, true, chunk, mem, &key64);
        }

        if (res == PM3_SUCCESS) {
            p_keyblock = NULL;
            free(statelists[0].head.slhead);
            free(mem);

            num_to_bytes(key64, 6, resultKey);

            if (IfPm3Flash() && keycnt > 70)
                PrintAndLogEx(NORMAL, "");

            PrintAndLogEx(SUCCESS, "target block %4u key type %c -- found valid key [ " _GREEN_("%s") " ]",
                          package->block,
                          package->keytype ? 'B' : 'A',
                          sprint_hex_inrow(resultKey, 6)
                         );
            return PM3_SUCCESS;
        } else if (res == PM3_ETIMEOUT || res == PM3_EOPABORTED) {
            PrintAndLogEx(NORMAL, "");
            free(mem);
            return res;
        }

        float bruteforce_per_second = (float)(i + max_keys_chunk) / ((msclock() - start_time) / 1000.0);
        PrintAndLogEx(INPLACE, "%6u/%u keys | %5.1f keys/sec | worst case %6.1f seconds", i, keycnt, bruteforce_per_second, (keycnt - i) / bruteforce_per_second);
    }

    p_keyblock = NULL;
    free(mem);

out:

    PrintAndLogEx(SUCCESS, "\nTarget block %4u key type %c",
                  package->block,
                  package->keytype ? 'B' : 'A'
                 );

    free(statelists[0].head.slhead);
    free(statelists[1].head.slhead);
    return PM3_ESOFT;
}

// MIFARE
int mfReadSector(uint8_t sectorNo, uint8_t keyType, const uint8_t *key, uint8_t *data) {

    clearCommandBuffer();
    SendCommandMIX(CMD_HF_MIFARE_READSC, sectorNo, keyType, 0, (uint8_t *)key, MIFARE_KEY_SIZE);
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_ACK, &resp, 1500)) {
        uint8_t isOK  = resp.oldarg[0] & 0xFF;

        if (isOK) {
            memcpy(data, resp.data.asBytes, mfNumBlocksPerSector(sectorNo) * MFBLOCK_SIZE);
            return PM3_SUCCESS;
        } else {
            return PM3_EUNDEF;
        }
    } else {
        PrintAndLogEx(DEBUG, "Command execute timeout");
        return PM3_ETIMEOUT;
    }
    return PM3_SUCCESS;
}

int mfReadBlock(uint8_t blockNo, uint8_t keyType, const uint8_t *key, uint8_t *data) {
    mf_readblock_t payload = {
        .blockno = blockNo,
        .keytype = keyType
    };
    memcpy(payload.key, key, sizeof(payload.key));

    clearCommandBuffer();
    SendCommandNG(CMD_HF_MIFARE_READBL, (uint8_t *)&payload, sizeof(mf_readblock_t));
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_HF_MIFARE_READBL, &resp, 1500)) {
        memcpy(data, resp.data.asBytes, MFBLOCK_SIZE);

        if (resp.status != PM3_SUCCESS) {
            PrintAndLogEx(DEBUG, "failed reading block");
            return PM3_ESOFT;
        }
    } else {
        PrintAndLogEx(DEBUG, "Command execute timeout");
        return PM3_ETIMEOUT;
    }
    return PM3_SUCCESS;
}

// EMULATOR
int mfEmlGetMem(uint8_t *data, int blockNum, int blocksCount) {

    size_t size = blocksCount * MFBLOCK_SIZE;
    if (size > PM3_CMD_DATA_SIZE) {
        return PM3_ESOFT;
    }

    struct {
        uint8_t blockno;
        uint8_t blockcnt;
    } PACKED payload;

    payload.blockno = blockNum;
    payload.blockcnt = blocksCount;

    clearCommandBuffer();
    SendCommandNG(CMD_HF_MIFARE_EML_MEMGET, (uint8_t *)&payload, sizeof(payload));

    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_HF_MIFARE_EML_MEMGET, &resp, 1500) == 0) {
        PrintAndLogEx(WARNING, "Command execute timeout");
        return PM3_ETIMEOUT;
    }

    if (resp.status == PM3_SUCCESS)
        memcpy(data, resp.data.asBytes, size);

    return resp.status;
}

int mfEmlSetMem(uint8_t *data, int blockNum, int blocksCount) {
    return mfEmlSetMem_xt(data, blockNum, blocksCount, MFBLOCK_SIZE);
}

int mfEmlSetMem_xt(uint8_t *data, int blockNum, int blocksCount, int blockBtWidth) {

    struct p {
        uint8_t blockno;
        uint8_t blockcnt;
        uint8_t blockwidth;
        uint8_t data[];
    } PACKED;

    size_t size = ((size_t) blocksCount) * blockBtWidth;
    if (size > (PM3_CMD_DATA_SIZE - sizeof(struct p))) {
        return PM3_EINVARG;
    }

    size_t paylen = sizeof(struct p) + size;
    struct p *payload = calloc(1, paylen);

    payload->blockno = blockNum;
    payload->blockcnt = blocksCount;
    payload->blockwidth = blockBtWidth;
    memcpy(payload->data, data, size);

    clearCommandBuffer();
    SendCommandNG(CMD_HF_MIFARE_EML_MEMSET, (uint8_t *)payload, paylen);
    free(payload);
    return PM3_SUCCESS;
}

// "MAGIC" CARD
int mfCSetUID(uint8_t *uid, uint8_t uidlen, const uint8_t *atqa, const uint8_t *sak, uint8_t *old_uid, uint8_t *verifed_uid, uint8_t wipecard) {

    uint8_t params = MAGIC_SINGLE;
    uint8_t block0[MFBLOCK_SIZE];
    memset(block0, 0x00, sizeof(block0));

    int res = mfCGetBlock(0, block0, params);
    if (res == 0) {
        PrintAndLogEx(SUCCESS, "old block 0... %s", sprint_hex_inrow(block0, sizeof(block0)));
        if (old_uid) {
            memcpy(old_uid, block0, uidlen);
        }
    } else {
        PrintAndLogEx(INFO, "couldn't get old data. Will write over the last bytes of block 0");
    }

    // fill in the new values
    // UID
    memcpy(block0, uid, uidlen);
    // Mifare UID BCC
    if (uidlen == 4) {
        block0[4] = block0[0] ^ block0[1] ^ block0[2] ^ block0[3];

        // mifare classic SAK(byte 5) and ATQA(byte 6 and 7, reversed)
        if (sak)
            block0[5] = sak[0];

        if (atqa) {
            block0[6] = atqa[1];
            block0[7] = atqa[0];
        }

    } else if (uidlen == 7) {
        block0[7] = block0[0] ^ block0[1] ^ block0[2] ^ block0[3] ^ block0[4] ^ block0[5] ^ block0[6];

        // mifare classic SAK(byte 8) and ATQA(byte 9 and 10, reversed)
        if (sak)
            block0[8] = sak[0];

        if (atqa) {
            block0[9] = atqa[1];
            block0[10] = atqa[0];
        }
    }

    PrintAndLogEx(SUCCESS, "new block 0... %s", sprint_hex_inrow(block0, 16));

    if (wipecard) {
        params |= MAGIC_WIPE;
    }

    res = mfCSetBlock(0, block0, NULL, params);
    if (res == PM3_SUCCESS) {
        params = MAGIC_SINGLE;
        memset(block0, 0, sizeof(block0));
        res = mfCGetBlock(0, block0, params);
        if (res == 0) {
            if (verifed_uid) {
                memcpy(verifed_uid, block0, uidlen);
            }
        }
    }
    return res;
}

int mfCWipe(uint8_t *uid, const uint8_t *atqa, const uint8_t *sak) {
    uint8_t block0[MFBLOCK_SIZE] = {0x00, 0x56, 0x78, 0xBB, 0x95, 0x08, 0x04, 0x00, 0x02, 0xB2, 0x1E, 0x24, 0x23, 0x27, 0x1E, 0x1D};
    // uint8_t block0[MFBLOCK_SIZE] = {0x04, 0x03, 0x02, 0x01, 0x04, 0x08, 0x04, 0x00, 0x64, 0xB9, 0x95, 0x11, 0x4D, 0x20, 0x42, 0x09};
    uint8_t blockD[MFBLOCK_SIZE] = {0x00};
    // default transport ACL
    uint8_t blockK[MFBLOCK_SIZE] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x07, 0x80, 0x69, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    uint8_t params = MAGIC_SINGLE;

    if (uid != NULL) {
        memcpy(block0, uid, 4);
        block0[4] = block0[0] ^ block0[1] ^ block0[2] ^ block0[3];
    }
    if (sak != NULL)
        block0[5] = sak[0];

    if (atqa != NULL) {
        block0[6] = atqa[1];
        block0[7] = atqa[0];
    }
    int res;
    for (int blockNo = 0; blockNo < 4 * 16; blockNo++) {
        for (int retry = 0; retry < 3; retry++) {

            PrintAndLogEx(INPLACE, "wipe block %d", blockNo);

            if (blockNo == 0) {
                res = mfCSetBlock(blockNo, block0, NULL, params);
            } else {
                if (mfIsSectorTrailer(blockNo))
                    res = mfCSetBlock(blockNo, blockK, NULL, params);
                else
                    res = mfCSetBlock(blockNo, blockD, NULL, params);
            }

            if (res == PM3_SUCCESS)
                break;

            PrintAndLogEx(WARNING, "retry block %d ...", blockNo);
        }

        if (res) {
            PrintAndLogEx(ERR, "error setting block %d (%d)", blockNo, res);
            return res;
        }
    }
    DropField();
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}

int mfCSetBlock(uint8_t blockNo, uint8_t *data, uint8_t *uid, uint8_t params) {
    clearCommandBuffer();
    SendCommandMIX(CMD_HF_MIFARE_CSETBL, params, blockNo, 0, data, MFBLOCK_SIZE);
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_ACK, &resp, 3500)) {
        uint8_t isOK  = resp.oldarg[0] & 0xff;
        if (uid != NULL) {
            memcpy(uid, resp.data.asBytes, 4);
        }

        if (!isOK) {
            return PM3_EUNDEF;
        }
    } else {
        PrintAndLogEx(WARNING, "command execute timeout");
        return PM3_ETIMEOUT;
    }
    return PM3_SUCCESS;
}

int mfCGetBlock(uint8_t blockNo, uint8_t *data, uint8_t params) {
    clearCommandBuffer();
    SendCommandMIX(CMD_HF_MIFARE_CGETBL, params, blockNo, 0, NULL, 0);
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_ACK, &resp, 1500)) {
        uint8_t isOK  = resp.oldarg[0] & 0xff;
        if (!isOK) {
            return PM3_EUNDEF;
        }
        memcpy(data, resp.data.asBytes, MFBLOCK_SIZE);
    } else {
        PrintAndLogEx(WARNING, "command execute timeout");
        return PM3_ETIMEOUT;
    }
    return PM3_SUCCESS;
}

int mfGen3UID(uint8_t *uid, uint8_t uidlen, uint8_t *oldUid) {
    clearCommandBuffer();
    SendCommandMIX(CMD_HF_MIFARE_GEN3UID, uidlen, 0, 0, uid, uidlen);
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_HF_MIFARE_GEN3UID, &resp, 3500)) {
        if (resp.status == PM3_SUCCESS && oldUid) {
            memcpy(oldUid, resp.data.asBytes, uidlen);
        }
        return resp.status;
    } else {
        PrintAndLogEx(WARNING, "Command execute timeout");
        return PM3_ETIMEOUT;
    }
}

int mfGen3Block(uint8_t *block, int blockLen, uint8_t *newBlock) {
    clearCommandBuffer();
    SendCommandMIX(CMD_HF_MIFARE_GEN3BLK, blockLen, 0, 0, block, MFBLOCK_SIZE);
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_HF_MIFARE_GEN3BLK, &resp, 3500)) {
        if (resp.status == PM3_SUCCESS && newBlock) {
            memcpy(newBlock, resp.data.asBytes, MFBLOCK_SIZE);
        }
        return resp.status;
    } else {
        PrintAndLogEx(WARNING, "Command execute timeout");
        return PM3_ETIMEOUT;
    }
}

int mfGen3Freeze(void) {
    clearCommandBuffer();
    SendCommandNG(CMD_HF_MIFARE_GEN3FREEZ, NULL, 0);
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_HF_MIFARE_GEN3FREEZ, &resp, 3500)) {
        return resp.status;
    } else {
        PrintAndLogEx(WARNING, "Command execute timeout");
        return PM3_ETIMEOUT;
    }
}

int mfG4GetBlock(uint8_t *pwd, uint8_t blockno, uint8_t *data, uint8_t workFlags) {
    struct p {
        uint8_t blockno;
        uint8_t pwd[4];
        uint8_t workFlags;
    } PACKED payload;
    payload.blockno = blockno;
    memcpy(payload.pwd, pwd, sizeof(payload.pwd));
    payload.workFlags = workFlags;

    clearCommandBuffer();
    SendCommandNG(CMD_HF_MIFARE_G4_RDBL, (uint8_t *)&payload, sizeof(payload));
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_HF_MIFARE_G4_RDBL, &resp, 1500)) {
        if (resp.status != PM3_SUCCESS) {
            return PM3_EUNDEF;
        }
        memcpy(data, resp.data.asBytes, MFBLOCK_SIZE);
    } else {
        PrintAndLogEx(WARNING, "command execute timeout");
        return PM3_ETIMEOUT;
    }
    return PM3_SUCCESS;
}

int mfG4SetBlock(uint8_t *pwd, uint8_t blockno, uint8_t *data, uint8_t workFlags) {
    struct p {
        uint8_t blockno;
        uint8_t pwd[4];
        uint8_t data[MFBLOCK_SIZE];
        uint8_t workFlags;
    } PACKED payload;
    payload.blockno = blockno;
    memcpy(payload.pwd, pwd, sizeof(payload.pwd));
    memcpy(payload.data, data, sizeof(payload.data));
    payload.workFlags = workFlags;

    clearCommandBuffer();
    SendCommandNG(CMD_HF_MIFARE_G4_WRBL, (uint8_t *)&payload, sizeof(payload));
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_HF_MIFARE_G4_WRBL, &resp, 1500)) {
        if (resp.status != PM3_SUCCESS) {
            return PM3_EUNDEF;
        }
    } else {
        PrintAndLogEx(WARNING, "command execute timeout");
        return PM3_ETIMEOUT;
    }
    return PM3_SUCCESS;
}


// variables
uint32_t cuid = 0;    // uid part used for crypto1.

void mf_crypto1_decrypt(struct Crypto1State *pcs, uint8_t *data, int len, bool isEncrypted) {
    if (len != 1) {
        for (int i = 0; i < len; i++)
            data[i] = crypto1_byte(pcs, 0x00, isEncrypted) ^ data[i];
    } else {
        uint8_t bt = 0;
        bt |= (crypto1_bit(pcs, 0, isEncrypted) ^ BIT(data[0], 0)) << 0;
        bt |= (crypto1_bit(pcs, 0, isEncrypted) ^ BIT(data[0], 1)) << 1;
        bt |= (crypto1_bit(pcs, 0, isEncrypted) ^ BIT(data[0], 2)) << 2;
        bt |= (crypto1_bit(pcs, 0, isEncrypted) ^ BIT(data[0], 3)) << 3;
        data[0] = bt;
    }
}

int tryDecryptWord(uint32_t nt, uint32_t ar_enc, uint32_t at_enc, uint8_t *data, int len) {
    PrintAndLogEx(SUCCESS, "encrypted data... %s", sprint_hex(data, len));
    struct Crypto1State *s;
    uint32_t ks2 = ar_enc ^ prng_successor(nt, 64);
    uint32_t ks3 = at_enc ^ prng_successor(nt, 96);
    s = lfsr_recovery64(ks2, ks3);
    mf_crypto1_decrypt(s, data, len, false);
    PrintAndLogEx(SUCCESS, "decrypted data... " _YELLOW_("%s"), sprint_hex(data, len));
    PrintAndLogEx(NORMAL, "");
    crypto1_destroy(s);
    return PM3_SUCCESS;
}

/* Detect Tag Prng,
* function performs a partial AUTH,  where it tries to authenticate against block0, key A, but only collects tag nonce.
* the tag nonce is check to see if it has a predictable PRNG.
* @returns
*   TRUE if tag uses WEAK prng (ie Now the NACK bug also needs to be present for Darkside attack)
*   FALSE is tag uses HARDEND prng (ie hardnested attack possible, with known key)
*/
int detect_classic_prng(void) {

    PacketResponseNG resp, respA;
    uint8_t cmd[] = {MIFARE_AUTH_KEYA, 0x00};
    uint32_t flags = ISO14A_CONNECT | ISO14A_RAW | ISO14A_APPEND_CRC | ISO14A_NO_RATS;

    clearCommandBuffer();
    SendCommandMIX(CMD_HF_ISO14443A_READER, flags, sizeof(cmd), 0, cmd, sizeof(cmd));

    if (WaitForResponseTimeout(CMD_ACK, &resp, 2000) == false) {
        PrintAndLogEx(WARNING, "PRNG UID: Reply timeout.");
        return PM3_ETIMEOUT;
    }

    // if select tag failed.
    if (resp.oldarg[0] == 0) {
        PrintAndLogEx(ERR, "error:  selecting tag failed,  can't detect prng\n");
        return PM3_ERFTRANS;
    }
    if (WaitForResponseTimeout(CMD_ACK, &respA, 2500) == false) {
        PrintAndLogEx(WARNING, "PRNG data: Reply timeout.");
        return PM3_ETIMEOUT;
    }

    // check respA
    if (respA.oldarg[0] != 4) {
        PrintAndLogEx(ERR, "PRNG data error: Wrong length: %"PRIu64, respA.oldarg[0]);
        return PM3_ESOFT;
    }

    uint32_t nonce = bytes_to_num(respA.data.asBytes, respA.oldarg[0]);
    return validate_prng_nonce(nonce);
}
/* Detect Mifare Classic NACK bug

returns:
0 = error during test / aborted
1 = has nack bug
2 = has not nack bug
3 = always leak nacks  (clones)
*/
int detect_classic_nackbug(bool verbose) {

    clearCommandBuffer();
    SendCommandNG(CMD_HF_MIFARE_NACK_DETECT, NULL, 0);
    PacketResponseNG resp;

    PrintAndLogEx(INFO, "Checking for NACK bug");

    if (verbose)
        PrintAndLogEx(SUCCESS, "press pm3-button on the Proxmark3 device to abort both Proxmark3 and client.\n");

    PrintAndLogEx(INFO, "." NOLF);

    while (true) {

        PrintAndLogEx(NORMAL, "." NOLF);
        if (kbd_enter_pressed()) {
            return PM3_EOPABORTED;
        }

        if (WaitForResponseTimeout(CMD_HF_MIFARE_NACK_DETECT, &resp, 500)) {

            PrintAndLogEx(NORMAL, "");

            if (resp.status == PM3_EOPABORTED) {
                PrintAndLogEx(WARNING, "button pressed. Aborted.");
                return PM3_EOPABORTED;
            }

            uint8_t ok = resp.data.asBytes[0];
            uint8_t nacks = resp.data.asBytes[1];
            uint16_t auths = bytes_to_num(resp.data.asBytes + 2, 2);

            if (verbose) {
                PrintAndLogEx(SUCCESS, "num of auth requests  : %u", auths);
                PrintAndLogEx(SUCCESS, "num of received NACK  : %u", nacks);
            }
            switch (ok) {
                case 96 :
                case 98 : {
                    if (verbose)
                        PrintAndLogEx(FAILED, "card random number generator is not predictable.");
                    PrintAndLogEx(WARNING, "detection failed");
                    return PM3_SUCCESS;
                }
                case 97 : {
                    if (verbose) {
                        PrintAndLogEx(FAILED, "card random number generator seems to be based on the well-known generating polynomial");
                        PrintAndLogEx(FAILED, "with 16 effective bits only, but shows unexpected behavior, try again.");
                    }
                    return PM3_SUCCESS;
                }
                case  2 :
                    PrintAndLogEx(SUCCESS, "NACK test: " _GREEN_("always leak NACK"));
                    return PM3_SUCCESS;
                case  1 :
                    PrintAndLogEx(SUCCESS, "NACK test: " _GREEN_("detected"));
                    return PM3_SUCCESS;
                case  0 :
                    PrintAndLogEx(SUCCESS, "NACK test: " _GREEN_("no bug"));
                    return PM3_SUCCESS;
                default :
                    PrintAndLogEx(ERR, "errorcode from device " _RED_("[%i]"), ok);
                    return PM3_EUNDEF;
            }
            break;
        }
    }
    return PM3_SUCCESS;
}

/* Detect Mifare Classic Static / Fixed nonce
detects special magic cards that has a static / fixed nonce
returns:
0  = has normal nonce
1  = has static/fixed nonce
2  = cmd failed
*/
int detect_classic_static_nonce(void) {

    clearCommandBuffer();
    SendCommandNG(CMD_HF_MIFARE_STATIC_NONCE, NULL, 0);
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_HF_MIFARE_STATIC_NONCE, &resp, 1000)) {

        if (resp.status == PM3_ESOFT)
            return NONCE_FAIL;

        return resp.data.asBytes[0];
    }
    return NONCE_FAIL;
}

/* try to see if card responses to "Chinese magic backdoor" commands. */
int detect_mf_magic(bool is_mfc) {

    uint8_t isGeneration = 0;
    PacketResponseNG resp;
    clearCommandBuffer();
    uint8_t payload[] = { is_mfc };
    SendCommandNG(CMD_HF_MIFARE_CIDENT, payload, sizeof(payload));
    if (WaitForResponseTimeout(CMD_HF_MIFARE_CIDENT, &resp, 1500)) {
        if (resp.status == PM3_SUCCESS)
            isGeneration = resp.data.asBytes[0];
    }

    switch (isGeneration) {
        case MAGIC_GEN_1A:
            PrintAndLogEx(SUCCESS, "Magic capabilities : " _GREEN_("Gen 1a"));
            break;
        case MAGIC_GEN_1B:
            PrintAndLogEx(SUCCESS, "Magic capabilities : " _GREEN_("Gen 1b"));
            break;
        case MAGIC_GEN_2:
            PrintAndLogEx(SUCCESS, "Magic capabilities : " _GREEN_("Gen 2 / CUID"));
            break;
        case MAGIC_GEN_3:
            PrintAndLogEx(SUCCESS, "Magic capabilities : possibly " _GREEN_("Gen 3 / APDU"));
            break;
        case MAGIC_GEN_4GTU:
            PrintAndLogEx(SUCCESS, "Magic capabilities : " _GREEN_("Gen 4 GTU"));
            break;
        case MAGIC_GEN_4GDM:
            PrintAndLogEx(SUCCESS, "Magic capabilities : " _GREEN_("Gen 4 GDM"));
            break;
        case MAGIC_GEN_UNFUSED:
            PrintAndLogEx(SUCCESS, "Magic capabilities : " _GREEN_("Write Once / FUID"));
            break;
        case MAGIC_SUPER_GEN1:
            PrintAndLogEx(SUCCESS, "Magic capabilities : " _GREEN_("Super card (") _CYAN_("Gen 1") _GREEN_(")"));
            break;
        case MAGIC_SUPER_GEN2:
            PrintAndLogEx(SUCCESS, "Magic capabilities : " _GREEN_("Super card (") _CYAN_("Gen 2") _GREEN_(")"));
            break;
        case MAGIC_NTAG21X:
            PrintAndLogEx(SUCCESS, "Magic capabilities : " _GREEN_("NTAG21x"));
            break;
        case MAGIC_QL88:
            PrintAndLogEx(SUCCESS, "Magic capabilities : " _GREEN_("QL88"));
        default:
            break;
    }
    return isGeneration;
}

bool detect_mfc_ev1_signature(void) {
    uint64_t key = 0;
    int res = mfCheckKeys(69, MF_KEY_B, false, 1, (uint8_t *)g_mifare_signature_key_b, &key);
    return (res == PM3_SUCCESS);
}

int read_mfc_ev1_signature(uint8_t *signature) {
    if (signature == NULL) {
        return PM3_EINVARG;
    }
    uint8_t sign[32] = {0};
    int res = mfReadBlock(69, MF_KEY_B, g_mifare_signature_key_b, sign);
    if (res == PM3_SUCCESS) {
        res = mfReadBlock(70, MF_KEY_B, g_mifare_signature_key_b, sign + 16);
        if (res ==  PM3_SUCCESS) {
            memcpy(signature, sign, sizeof(sign));
        }
    }
    return res;
}

int convert_mfc_2_arr(uint8_t *in, uint16_t ilen, uint8_t *out, uint16_t *olen) {
    if (in == NULL || out == NULL)
        return PM3_EINVARG;

    uint8_t blockno = 0;
    while (ilen) {

        if (mfIsSectorTrailer(blockno) == false) {
            memcpy(out, in, MFBLOCK_SIZE);
            out += MFBLOCK_SIZE;
            *olen += MFBLOCK_SIZE;
        }
        blockno++;
        in += MFBLOCK_SIZE;
        ilen -= MFBLOCK_SIZE;
    }
    return PM3_SUCCESS;
}

static const vigik_pk_t vigik_rsa_pk[] = {
    {"La Poste Service Universel", 0x07AA, "AB9953CBFCCD9375B6C028ADBAB7584BED15B9CA037FADED9765996F9EA1AB983F3041C90DA3A198804FF90D5D872A96A4988F91F2243B821E01C5021E3ED4E1BA83B7CFECAB0E766D8563164DE0B2412AE4E6EA63804DF5C19C7AA78DC14F608294D732D7C8C67A88C6F84C0F2E3FAFAE34084349E11AB5953AC68729D07715"},
    {"La Poste Service Universel", 0x07AA, "1577D02987C63A95B51AE149430834AEAF3F2E0F4CF8C6887AC6C8D732D79482604FC18DA77A9CC1F54D8063EAE6E42A41B2E04D1663856D760EABECCFB783BAE1D43E1E02C5011E823B24F2918F98A4962A875D0DF94F8098A1A30DC941303F98ABA19E6F996597EDAD7F03CAB915ED4B58B7BAAD28C0B67593CDFCCB5399AB"},

    {"La Poste Autres Services", 0x07AB, "A6D99B8D902893B04F3F8DE56CB6BF24338FEE897C1BCE6DFD4EBD05B7B1A07FD2EB564BB4F7D35DBFE0A42966C2C137AD156E3DAB62904592BCA20C0BC7B8B1E261EF82D53F52D203843566305A49A22062DECC38C2FE3864CAD08E79219487651E2F79F1C9392B48CAFE1BFFAFF4802AE451E7A283E55A4026AD1E82DF1A15"},
    {"La Poste Autres Services", 0x07AB, "151adf821ead26405ae583a2e751e42a80f4afff1bfeca482b39c9f1792f1e65879421798ed0ca6438fec238ccde6220a2495a3066358403d2523fd582ef61e2b1b8c70b0ca2bc92459062ab3d6e15ad37c1c26629a4e0bf5dd3f7b44b56ebd27fa0b1b705bd4efd6dce1b7c89ee8f3324bfb66ce58d3f4fb09328908d9bd9a6"},

    {"France Telecom", 0x07AC, "C44DBCD92F9DCF42F4902A87335DBB35D2FF530CDB09814CFA1F4B95A1BD018D099BC6AB69F667B4922AE1ED826E72951AA3E0EAAA7D49A695F04F8CDAAE2D18D10D25BD529CBB05ABF070DC7C041EC35C2BA7F58CC4C349983CC6E11A5CBE828FB8ECBC26F08E1094A6B44C8953C8E1BAFD214DF3E69F430A98CCC75C03669D"},
    {"France Telecom", 0x07AC, "9d66035cc7cc980a439fe6f34d21fdbae1c853894cb4a694108ef026bcecb88f82be5c1ae1c63c9849c3c48cf5a72b5cc31e047cdc70f0ab05bb9c52bd250dd1182daeda8c4ff095a6497daaeae0a31a95726e82ede12a92b467f669abc69b098d01bda1954b1ffa4c8109db0c53ffd235bb5d33872a90f442cf9d2fd9bc4dc4"},

    {"EDF-GDF", 0x07AD, "B35193DBD2F88A21CDCFFF4BF84F7FC036A991A363DCB3E802407A5E5879DC2127EECFC520779E79E911394882482C87D09A88B0711CBC2973B77FFDAE40EA0001F595072708C558B484AB89D02BCBCB971FF1B80371C0BE30CB13661078078BB68EBCCA524B9DD55EBF7D47D9355AFC95511350CC1103A5DEE847868848B235"},
    {"EDF-GDF", 0x07AD, "35b248888647e8dea50311cc50135195fc5a35d9477dbf5ed59d4b52cabc8eb68b0778106613cb30bec07103b8f11f97cbcb2bd089ab84b458c508270795f50100ea40aefd7fb77329bc1c71b0889ad0872c4882483911e9799e7720c5cfee2721dc79585e7a4002e8b3dc63a391a936c07f4ff84bffcfcd218af8d2db9351b3"},
    {NULL, 0, NULL}
};

const char *vigik_get_service(uint16_t service_code) {
    for (int i = 0; i < ARRAYLEN(vigik_rsa_pk); ++i)
        if (service_code == vigik_rsa_pk[i].code)
            return vigik_rsa_pk[i].desc;

    //No match, return default
    return vigik_rsa_pk[ARRAYLEN(vigik_rsa_pk) - 1].desc;
}


int vigik_verify(mfc_vigik_t *d) {
#define PUBLIC_VIGIK_KEYLEN 128

    // iso9796
    // Exponent V = 2
    // n = The public modulus n is the product of the secret prime factors p and q. Its length is 1024 bits.

    if (g_debugMode == DEBUG) {
        PrintAndLogEx(INFO, "Raw");
        print_hex_noascii_break((uint8_t *)d, sizeof(*d) - sizeof(d->rsa_signature), MFBLOCK_SIZE * 2);

        PrintAndLogEx(INFO, "Raw signature");
        print_hex_noascii_break(d->rsa_signature, sizeof(d->rsa_signature), MFBLOCK_SIZE * 2);
    }

    /*
        int dl = 0;

            param_gethex_to_eol("1C07D46DA3849326D24B3468BD76673F4F3C41827DC413E81E4F3C7804FAC727213059B21D047510D6432448643A92EBFC67FBEDDAB468D13D948B172F5EBC79A0E3FEFDFAF4E81FC7108E070F1E3CD0", 0, signature, PUBLIC_VIGIK_KEYLEN, &dl);

        param_gethex_to_eol("1AB86FE0C17FFFFE4379D5E15A4B2FAFFEFCFA0F1F3F7FA03E7DDDF1E3C78FFFB1F0E23F7FFF51584771C5C18307FEA36CA74E60AA6B0409ACA66A9EC155F4E9112345708A2B8457E722608EE1157408", 0, signature, PUBLIC_VIGIK_KEYLEN, &dl);
        signature_len = dl;
        */

    uint8_t rev_sig[128];
    reverse_array_copy(d->rsa_signature, sizeof(d->rsa_signature), rev_sig);

    PrintAndLogEx(INFO, "Raw signature reverse");
    print_hex_noascii_break(rev_sig, sizeof(d->rsa_signature), MFBLOCK_SIZE * 2);

    // t = 0xBC  = Implicitly known
    // t = 0xCC  = look at byte before to determine hash function
    // uint8_t T[] = {0x33, 0xCC};

    // Success decrypt would mean  0x4b BB ... BB BA padding
    // padding, message,  hash, 8 bits or 16 bits

    // signature = h( C || M1 || h(M2) )
    // 1024 - 786 - 160 - 16 -1
    // salt C
    // message M = 96 bytes,  768 bits
    // sha1 hash H = 20 bytes, 160 bits
    // padding = 20 bytes, 96 bits

    uint8_t i;
    bool is_valid = false;

    for (i = 0; i < ARRAYLEN(vigik_rsa_pk); i++) {
        if (vigik_rsa_pk[i].desc == NULL) {
            break;
        }

        mbedtls_mpi RN, E;
        mbedtls_mpi_init(&RN);

        // exponent 2 = even
        mbedtls_mpi_init(&E);
        mbedtls_mpi_add_int(&E, &E, 2);

        int dl = 0;
        uint8_t n[PUBLIC_VIGIK_KEYLEN];
        memset(n, 0, sizeof(n));
        param_gethex_to_eol(vigik_rsa_pk[i].n, 0, n, PUBLIC_VIGIK_KEYLEN, &dl);

        // convert
        mbedtls_mpi N, s, sqr, res;
        mbedtls_mpi_init(&N);
        mbedtls_mpi_init(&s);
        mbedtls_mpi_init(&sqr);
        mbedtls_mpi_init(&res);

        mbedtls_mpi_read_binary(&N, (const unsigned char *)n, PUBLIC_VIGIK_KEYLEN);

        //mbedtls_mpi_read_binary(&s, (const unsigned char*)signature, signature_len);
        mbedtls_mpi_read_binary(&s, (const unsigned char *)rev_sig, sizeof(d->rsa_signature));

        // check is sign < (N/2)

        mbedtls_mpi n_2;
        mbedtls_mpi_init(&n_2);
        mbedtls_mpi_copy(&n_2, &N);
        mbedtls_mpi_shift_r(&n_2, 1);
        bool is_less = (mbedtls_mpi_cmp_mpi(&s, &n_2) > 0) ? false : true;
        PrintAndLogEx(DEBUG, "z < (N/2) ..... %s", (is_less) ? _GREEN_("YES") : _RED_("NO"));
        mbedtls_mpi_free(&n_2);


        if (is_less) {
            mbedtls_mpi_exp_mod(&sqr, &s, &E, &N, &RN);
        } else {
            continue;
        }

        /*
            if v is even and
            ⎯ if J* mod 8 = 1, then f* = n–J*.
            ⎯ if J* mod 8 = 4, then f* = J*,
            ⎯ if J* mod 8 = 6, then f* = 2J*,
            ⎯ if J* mod 8 = 7, then f* = 2(n–J*),
        */
        uint8_t b2 = mbedtls_mpi_get_bit(&sqr, 2);
        uint8_t b1 = mbedtls_mpi_get_bit(&sqr, 1);
        uint8_t b0 = mbedtls_mpi_get_bit(&sqr, 0);
        uint8_t lsb = (b2 << 2) | (b1 << 1) | b0;

        /*
        //1
        mbedtls_mpi_sub_mpi(&res, &N, &sqr);
        mbedtls_mpi_write_file( "[=] 1... ", &res, 16, NULL );
        // 4
        mbedtls_mpi_copy(&res, &sqr);
        mbedtls_mpi_write_file( "[=] 4... ", &res, 16, NULL );
        // 6
        mbedtls_mpi_mul_int(&res, &sqr, 2);
        mbedtls_mpi_write_file( "[=] 6... ", &res, 16, NULL );
        // 7
        mbedtls_mpi foo;
        mbedtls_mpi_init(&foo);
        mbedtls_mpi_sub_mpi(&foo, &N, &sqr);
        mbedtls_mpi_mul_int(&res, &foo, 2);
        mbedtls_mpi_free(&foo);
        mbedtls_mpi_write_file( "[=] 7... ", &res, 16, NULL );
        */

        switch (lsb) {
            case 1: {
                mbedtls_mpi_sub_mpi(&res, &N, &sqr);
                break;
            }
            case 4: {
                mbedtls_mpi_copy(&res, &sqr);
                break;
            }
            case 6: {
                mbedtls_mpi_mul_int(&res, &sqr, 2);
                break;
            }
            case 7: {
                mbedtls_mpi foo2;
                mbedtls_mpi_init(&foo2);
                mbedtls_mpi_sub_mpi(&foo2, &N, &sqr);
                mbedtls_mpi_mul_int(&res, &foo2, 2);
                mbedtls_mpi_free(&foo2);
                break;
            }
            default: {
                continue;
            }
        }

        PrintAndLogEx(DEBUG, "LSB............ " _GREEN_("%u"), lsb);
        if (g_debugMode == DEBUG) {
            mbedtls_mpi_write_file("[=] N.............. ", &N, 16, NULL);
            mbedtls_mpi_write_file("[=] signature...... ", &s, 16, NULL);
            mbedtls_mpi_write_file("[=] square mod n... ", &sqr, 16, NULL);
            mbedtls_mpi_write_file("[=] n-fs........... ", &res, 16, NULL);
        }


        uint8_t nfs[128] = {0};
        mbedtls_mpi_write_binary(&res, nfs, sizeof(nfs));

        // xor 0xDC01
        int count_zero = 0;
        for (int x = 0; x < sizeof(nfs); x += 2) {
            nfs[x] ^= 0xDC;
            nfs[x + 1] ^= 0x01;

            if (nfs[x] == 0x00)
                count_zero++;
            if (nfs[x + 1] == 0x00)
                count_zero++;
        }

        if (count_zero > 10)  {
            PrintAndLogEx(INFO, "");
            PrintAndLogEx(INFO, "Message XORED");
            print_hex_noascii_break(nfs, sizeof(nfs), 32);
            PrintAndLogEx(INFO, "\n");
            is_valid = true;
            break;
        }

        /*
        if (bar == 0) {
            typedef struct vigik_rsa_s {
                uint8_t rsa[127];
                uint8_t hash;
            } vigik_rsa_t;

            vigik_rsa_t ts;
            memcpy(&ts, nfs, sizeof(ts));

            if ( ts.hash == 0xCC ) {
                PrintAndLogEx(INFO, "Hash byte... 0x%02X", ts.hash);
                switch(ts.rsa[126]) {
                    case 0x11:
                        PrintAndLogEx(INFO, "Hash algo ( 0x%02X ) - SHA1");
                        break;
                    case 0x22:
                        PrintAndLogEx(INFO, "Hash algo ( 0x%02X ) - RIPEMD");
                        break;
                    case 0x33:
                        PrintAndLogEx(INFO, "Hash algo ( 0x%02X ) - SHA1");
                        break;
                    default:
                        PrintAndLogEx(INFO, "Hash algo ( 0x%02X ) - " _RED_("err"));
                        break;
                }
            } else if ( ts.hash == 0xBC) {
                PrintAndLogEx(INFO, "Hash byte... 0x%02X - " _GREEN_("implict"), ts.hash);
            } else {
                PrintAndLogEx(INFO, "Hash byte... 0x%02x - " _RED_("err"), ts.hash);
            }

            PrintAndLogEx(INFO, "Message w padding");
            print_hex_noascii_break(ts.rsa, sizeof(ts.rsa) - 20, 32);
        }
        */

        mbedtls_mpi_free(&N);
        mbedtls_mpi_free(&s);
        mbedtls_mpi_free(&res);
        mbedtls_mpi_free(&RN);
        mbedtls_mpi_free(&E);
    }

    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Tag Signature"));
    PrintAndLogEx(INFO, "RSA: 1024bit");

    if (is_valid == false || i == ARRAYLEN(vigik_rsa_pk)) {
        PrintAndLogEx(INFO, "Signature:");
        print_hex_noascii_break(d->rsa_signature, sizeof(d->rsa_signature),  MFBLOCK_SIZE * 2);
        PrintAndLogEx(SUCCESS, "Signature verification: " _RED_("failed"));
        return PM3_ESOFT;
    }

    PrintAndLogEx(INFO, "Signature public key name: " _YELLOW_("%s"), vigik_rsa_pk[i].desc);
    PrintAndLogEx(INFO, "Signature public key value:");
    PrintAndLogEx(INFO, "%.64s", vigik_rsa_pk[i].n);
    PrintAndLogEx(INFO, "%.64s", vigik_rsa_pk[i].n + 64);
    PrintAndLogEx(INFO, "%.64s", vigik_rsa_pk[i].n + 128);
    PrintAndLogEx(INFO, "%.64s", vigik_rsa_pk[i].n + 192);

    PrintAndLogEx(INFO, "Signature:");
    print_hex_noascii_break(d->rsa_signature, sizeof(d->rsa_signature),  MFBLOCK_SIZE * 2);

    PrintAndLogEx(SUCCESS, "Signature verification: " _GREEN_("successful"));

    return PM3_SUCCESS;
}

int vigik_annotate(mfc_vigik_t *d) {
    if (d == NULL)
        return PM3_EINVARG;

    PrintAndLogEx(INFO, "Manufacture......... %s", sprint_hex(d->b0, sizeof(d->b0)));
    PrintAndLogEx(INFO, "MAD................. %s", sprint_hex(d->mad, sizeof(d->mad)));
    PrintAndLogEx(INFO, "Counters............ %u", d->counters);
    PrintAndLogEx(INFO, "rtf................. %s", sprint_hex(d->rtf, sizeof(d->rtf)));
    PrintAndLogEx(INFO, "Service code........ 0x%08x / %u  - " _YELLOW_("%s"), d->service_code, d->service_code, vigik_get_service(d->service_code));
    PrintAndLogEx(INFO, "Info flag........... %u -", d->info_flag); // ,  sprint_bin(d->info_flag, 1));
    PrintAndLogEx(INFO, "Key version......... %u", d->key_version);
    PrintAndLogEx(INFO, "PTR Counter......... %u", d->ptr_counter);
    PrintAndLogEx(INFO, "Counter num......... %u", d->counter_num);
    PrintAndLogEx(INFO, "Slot access date.... %s", sprint_hex(d->slot_access_date, sizeof(d->slot_access_date)));
    PrintAndLogEx(INFO, "Slot dst duration... %u", d->slot_dst_duration);
    PrintAndLogEx(INFO, "Other Slots......... %s", sprint_hex(d->other_slots, sizeof(d->other_slots)));
    PrintAndLogEx(INFO, "Services counter.... %u", d->services_counter);
    PrintAndLogEx(INFO, "Loading date........ %s", sprint_hex(d->loading_date, sizeof(d->loading_date)));
    PrintAndLogEx(INFO, "Reserved null....... %u", d->reserved_null);
    PrintAndLogEx(INFO, "----------------------------------------------------------------");
    PrintAndLogEx(INFO, "");
    vigik_verify(d);
    PrintAndLogEx(INFO, "----------------------------------------------------------------");
    PrintAndLogEx(INFO, "");
    return PM3_SUCCESS;

}
