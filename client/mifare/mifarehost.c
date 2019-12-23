// Merlok, 2011, 2012, 2019
// people from mifare@nethemba.com, 2010
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
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
#include "ui.h"         // PrintAndLog...
#include "crapto1/crapto1.h"
#include "crc16.h"
#include "protocols.h"
#include "mfkey.h"
#include "util_posix.h"  // msclock

int mfDarkside(uint8_t blockno, uint8_t key_type, uint64_t *key) {
    uint32_t uid = 0;
    uint32_t nt = 0, nr = 0, ar = 0;
    uint64_t par_list = 0, ks_list = 0;
    uint64_t *keylist = NULL, *last_keylist = NULL;
    bool first_run = true;

    // message
    PrintAndLogEx(NORMAL, "--------------------------------------------------------------------------------\n");
    PrintAndLogEx(NORMAL, "executing Darkside attack. Expected execution time: 25sec on average");
    PrintAndLogEx(NORMAL, "press pm3-button on the Proxmark3 device to abort both Proxmark3 and client.");
    PrintAndLogEx(NORMAL, "--------------------------------------------------------------------------------\n");

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
            return PM3_EOPABORTED;
        }

        // wait cycle
        while (true) {
            printf(".");
            fflush(stdout);
            if (kbd_enter_pressed()) {
                return PM3_EOPABORTED;
            }

            PacketResponseNG resp;
            if (WaitForResponseTimeout(CMD_HF_MIFARE_READER, &resp, 2000)) {
                if (resp.status == PM3_EOPABORTED) {
                    return -1;
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
        PrintAndLogEx(NORMAL, "\n");

        if (par_list == 0 && first_run == true) {
            PrintAndLogEx(SUCCESS, "Parity is all zero. Most likely this card sends NACK on every authentication.");
        }
        first_run = false;

        uint32_t keycount = nonce2key(uid, nt, nr, ar, par_list, ks_list, &keylist);

        if (keycount == 0) {
            PrintAndLogEx(FAILED, "key not found (lfsr_common_prefix list is null). Nt=%08x", nt);
            PrintAndLogEx(FAILED, "this is expected to happen in 25%% of all cases. Trying again with a different reader nonce...");
            continue;
        }

        // only parity zero attack
        if (par_list == 0) {
            qsort(keylist, keycount, sizeof(*keylist), compare_uint64);
            keycount = intersection(last_keylist, keylist);
            if (keycount == 0) {
                free(last_keylist);
                last_keylist = keylist;
                PrintAndLogEx(FAILED, "no candidates found, trying again");
                continue;
            }
        }

        PrintAndLogEx(SUCCESS, "found %u candidate key%s\n", keycount, (keycount > 1) ? "s." : ".");

        *key = UINT64_C(-1);
        uint8_t keyBlock[PM3_CMD_DATA_SIZE];
        uint32_t max_keys = KEYS_IN_BLOCK;
        for (uint32_t i = 0; i < keycount; i += max_keys) {

            uint32_t size = keycount - i > max_keys ? max_keys : keycount - i;
            for (uint32_t j = 0; j < size; j++) {
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
            PrintAndLogEx(FAILED, "all candidate keys failed. Restarting darkside attack");
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
    data[3] = keycnt;
    memcpy(data + 4, keyBlock, 6 * keycnt);
    SendCommandNG(CMD_HF_MIFARE_CHKKEYS, data, (4 + 6 * keycnt));

    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_HF_MIFARE_CHKKEYS, &resp, 2500)) return PM3_ETIMEOUT;
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

// Sends chunks of keys to device.
// 0 == ok all keys found
// 1 ==
// 2 == Time-out, aborting
int mfCheckKeys_fast(uint8_t sectorsCnt, uint8_t firstChunk, uint8_t lastChunk, uint8_t strategy,
                     uint32_t size, uint8_t *keyBlock, sector_t *e_sector, bool use_flashmemory) {

    uint64_t t2 = msclock();
    uint32_t timeout = 0;

    // send keychunk
    clearCommandBuffer();
    SendCommandOLD(CMD_HF_MIFARE_CHKKEYS_FAST, (sectorsCnt | (firstChunk << 8) | (lastChunk << 12)), ((use_flashmemory << 8) | strategy), size, keyBlock, 6 * size);
    PacketResponseNG resp;

    while (!WaitForResponseTimeout(CMD_ACK, &resp, 2000)) {
        timeout++;
        printf(".");
        fflush(stdout);
        // max timeout for one chunk of 85keys, 60*3sec = 180seconds
        // s70 with 40*2 keys to check, 80*85 = 6800 auth.
        // takes about 97s, still some margin before abort
        if (timeout > 180) {
            PrintAndLogEx(WARNING, "\nNo response from Proxmark3. Aborting...");
            return PM3_ETIMEOUT;
        }
    }
    t2 = msclock() - t2;

    // time to convert the returned data.
    uint8_t curr_keys = resp.oldarg[0];

    PrintAndLogEx(SUCCESS, "\nChunk: %.1fs | found %u/%u keys (%u)", (float)(t2 / 1000.0), curr_keys, (sectorsCnt << 1), size);

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

// PM3 imp of J-Run mf_key_brute (part 2)
// ref: https://github.com/J-Run/mf_key_brute
int mfKeyBrute(uint8_t blockNo, uint8_t keyType, uint8_t *key, uint64_t *resultkey) {

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

        // check a block of generated candidate keys.
        if (mfCheckKeys(blockNo, keyType, true, KEYS_IN_BLOCK, keyBlock, &key64) == PM3_SUCCESS) {
            *resultkey = key64;
            found = true;
            break;
        }

        // progress
        if (counter % 20 == 0)
            PrintAndLogEx(SUCCESS, "tried : %s.. \t %u keys", sprint_hex(candidates + i, 6),  counter * KEYS_IN_BLOCK);
    }
    return found;
}

// Compare 16 Bits out of cryptostate
static int Compare16Bits(const void *a, const void *b) {
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
    statelist->head.slhead = lfsr_recovery32(statelist->ks1, statelist->nt ^ statelist->uid);

    for (p1 = statelist->head.slhead; * (uint64_t *)p1 != 0; p1++) {};

    statelist->len = p1 - statelist->head.slhead;
    statelist->tail.sltail = --p1;
    qsort(statelist->head.slhead, statelist->len, sizeof(uint64_t), Compare16Bits);

    return statelist->head.slhead;
}

int mfnested(uint8_t blockNo, uint8_t keyType, uint8_t *key, uint8_t trgBlockNo, uint8_t trgKeyType, uint8_t *resultKey, bool calibrate) {
    uint16_t i;
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

    if (!WaitForResponseTimeout(CMD_HF_MIFARE_NESTED, &resp, 2000)) {
        SendCommandNG(CMD_BREAK_LOOP, NULL, 0);
        return PM3_ETIMEOUT;
    }

    if (resp.status != PM3_SUCCESS)
        return PM3_ESOFT;

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

    // error during nested
    if (package->isOK) return package->isOK;

    memcpy(&uid, package->cuid, sizeof(package->cuid));

    for (i = 0; i < 2; i++) {
        statelists[i].blockNo = package->block;
        statelists[i].keyType = package->keytype;
        statelists[i].uid = uid;
    }

    memcpy(&statelists[0].nt,  package->nt_a, sizeof(package->nt_a));
    memcpy(&statelists[0].ks1, package->ks_a, sizeof(package->ks_a));

    memcpy(&statelists[1].nt,  package->nt_b, sizeof(package->nt_b));
    memcpy(&statelists[1].ks1, package->ks_b, sizeof(package->ks_b));


    // calc keys
    pthread_t thread_id[2];

    // create and run worker threads
    for (i = 0; i < 2; i++)
        pthread_create(thread_id + i, NULL, nested_worker_thread, &statelists[i]);

    // wait for threads to terminate:
    for (i = 0; i < 2; i++)
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
                lfsr_rollback_word(p3, statelists[0].nt ^ statelists[0].uid, 0);
                p3++;
                p1++;
            }
            savestate = *p2;
            while (Compare16Bits(p2, &savestate) == 0 && p2 <= statelists[1].tail.sltail) {
                *p4 = *p2;
                lfsr_rollback_word(p4, statelists[1].nt ^ statelists[1].uid, 0);
                p4++;
                p2++;
            }
        } else {
            while (Compare16Bits(p1, p2) == -1) p1++;
            while (Compare16Bits(p1, p2) == 1) p2++;
        }
    }

    *(uint64_t *)p3 = -1;
    *(uint64_t *)p4 = -1;
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

    memset(resultKey, 0, 6);
    uint64_t key64 = -1;

    // The list may still contain several key candidates. Test each of them with mfCheckKeys
    uint32_t max_keys = keycnt > KEYS_IN_BLOCK ? KEYS_IN_BLOCK : keycnt;
    uint8_t keyBlock[PM3_CMD_DATA_SIZE] = {0x00};

    for (i = 0; i < keycnt; i += max_keys) {

        int size = keycnt - i > max_keys ? max_keys : keycnt - i;

        for (int j = 0; j < size; j++) {
            crypto1_get_lfsr(statelists[0].head.slhead + i, &key64);
            num_to_bytes(key64, 6, keyBlock + i * 6);
        }

        if (mfCheckKeys(statelists[0].blockNo, statelists[0].keyType, false, size, keyBlock, &key64) == PM3_SUCCESS) {
            free(statelists[0].head.slhead);
            free(statelists[1].head.slhead);
            num_to_bytes(key64, 6, resultKey);

            PrintAndLogEx(SUCCESS, "target block:%3u key type: %c  -- found valid key [ %012" PRIx64 " ]",
                          (uint16_t)resp.oldarg[2] & 0xff,
                          (resp.oldarg[2] >> 8) ? 'B' : 'A',
                          key64
                         );
            return -5;
        }
    }

out:
    PrintAndLogEx(SUCCESS, "target block:%3u key type: %c",
                  (uint16_t)resp.oldarg[2] & 0xff,
                  (resp.oldarg[2] >> 8) ? 'B' : 'A'
                 );

    free(statelists[0].head.slhead);
    free(statelists[1].head.slhead);
    return -4;
}

// MIFARE
int mfReadSector(uint8_t sectorNo, uint8_t keyType, uint8_t *key, uint8_t *data) {

    clearCommandBuffer();
    SendCommandOLD(CMD_HF_MIFARE_READSC, sectorNo, keyType, 0, key, 6);

    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_ACK, &resp, 1500)) {
        uint8_t isOK  = resp.oldarg[0] & 0xff;

        if (isOK) {
            memcpy(data, resp.data.asBytes, mfNumBlocksPerSector(sectorNo) * 16);
            return PM3_SUCCESS;
        } else {
            return PM3_EUNDEF;
        }
    } else {
        PrintAndLogEx(ERR, "Command execute timeout");
        return PM3_ETIMEOUT;
    }

    return PM3_SUCCESS;
}

// EMULATOR
int mfEmlGetMem(uint8_t *data, int blockNum, int blocksCount) {

    size_t size = blocksCount * 16;
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
    return mfEmlSetMem_xt(data, blockNum, blocksCount, 16);
}

int mfEmlSetMem_xt(uint8_t *data, int blockNum, int blocksCount, int blockBtWidth) {

    struct p {
        uint8_t blockno;
        uint8_t blockcnt;
        uint8_t blockwidth;
        uint8_t data[];
    } PACKED;

    size_t size = blocksCount * blockBtWidth;
    if (size > (PM3_CMD_DATA_SIZE - sizeof(struct p))) {
        return PM3_ESOFT;
    }

    struct p *payload = calloc(1, sizeof(struct p) + size);
    payload->blockno = blockNum;
    payload->blockcnt = blocksCount;
    payload->blockwidth = blockBtWidth;
    memcpy(payload->data, data, size);

    clearCommandBuffer();
    SendCommandNG(CMD_HF_MIFARE_EML_MEMSET, (uint8_t *)payload, sizeof(payload) + size);
    free(payload);
    return PM3_SUCCESS;
}

// "MAGIC" CARD
int mfCSetUID(uint8_t *uid, uint8_t *atqa, uint8_t *sak, uint8_t *oldUID, uint8_t wipecard) {

    uint8_t params = MAGIC_SINGLE;
    uint8_t block0[16];
    memset(block0, 0x00, sizeof(block0));

    int old = mfCGetBlock(0, block0, params);
    if (old == 0)
        PrintAndLogEx(SUCCESS, "old block 0:  %s", sprint_hex(block0, sizeof(block0)));
    else
        PrintAndLogEx(FAILED, "couldn't get old data. Will write over the last bytes of Block 0.");

    // fill in the new values
    // UID
    memcpy(block0, uid, 4);
    // Mifare UID BCC
    block0[4] = block0[0] ^ block0[1] ^ block0[2] ^ block0[3];
    // mifare classic SAK(byte 5) and ATQA(byte 6 and 7, reversed)
    if (sak != NULL)
        block0[5] = sak[0];

    if (atqa != NULL) {
        block0[6] = atqa[1];
        block0[7] = atqa[0];
    }
    PrintAndLogEx(SUCCESS, "new block 0:  %s", sprint_hex(block0, 16));

    if (wipecard)      params |= MAGIC_WIPE;
    if (oldUID == NULL) params |= MAGIC_UID;

    return mfCSetBlock(0, block0, oldUID, params);
}

int mfCWipe(uint8_t *uid, uint8_t *atqa, uint8_t *sak) {
    uint8_t block0[16] = {0x01, 0x02, 0x03, 0x04, 0x04, 0x08, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xBE, 0xAF};
    uint8_t blockD[16] = {0x00};
    uint8_t blockK[16] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x08, 0x77, 0x8F, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
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
            PrintAndLogEx(WARNING, "Retry block[%d]...", blockNo);
        }

        if (res) {
            PrintAndLogEx(ERR, "Error setting block[%d]: %d", blockNo, res);
            return res;
        }
    }
    DropField();

    return PM3_SUCCESS;
}

int mfCSetBlock(uint8_t blockNo, uint8_t *data, uint8_t *uid, uint8_t params) {

    clearCommandBuffer();
    SendCommandOLD(CMD_HF_MIFARE_CSETBL, params, blockNo, 0, data, 16);
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_ACK, &resp, 1500)) {
        uint8_t isOK  = resp.oldarg[0] & 0xff;
        if (uid != NULL)
            memcpy(uid, resp.data.asBytes, 4);
        if (!isOK)
            return PM3_EUNDEF;
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
        if (!isOK)
            return PM3_EUNDEF;
        memcpy(data, resp.data.asBytes, 16);
    } else {
        PrintAndLogEx(WARNING, "command execute timeout");
        return PM3_ETIMEOUT;
    }
    return PM3_SUCCESS;
}

// SNIFFER
// [iceman] so many global variables....

// constants
static uint8_t trailerAccessBytes[4] = {0x08, 0x77, 0x8F, 0x00};

// variables
char logHexFileName[FILE_PATH_SIZE] = {0x00};
static uint8_t traceCard[4096] = {0x00};
static char traceFileName[FILE_PATH_SIZE] = {0x00};
static int traceState = TRACE_IDLE;
static uint8_t traceCurBlock = 0;
static uint8_t traceCurKey = 0;

struct Crypto1State *traceCrypto1 = NULL;
struct Crypto1State *revstate = NULL;

uint32_t cuid = 0;    // uid part used for crypto1.

int isTraceCardEmpty(void) {
    return ((traceCard[0] == 0) && (traceCard[1] == 0) && (traceCard[2] == 0) && (traceCard[3] == 0));
}

int isBlockEmpty(int blockN) {
    for (int i = 0; i < 16; i++)
        if (traceCard[blockN * 16 + i] != 0) return 0;

    return 1;
}

int isBlockTrailer(int blockN) {
    return ((blockN & 0x03) == 0x03);
}

int loadTraceCard(uint8_t *tuid, uint8_t uidlen) {
    FILE *f;
    char buf[64] = {0x00};
    uint8_t buf8[64] = {0x00};
    int i, blockNum;
    uint32_t tmp;

    if (!isTraceCardEmpty())
        saveTraceCard();

    memset(traceCard, 0x00, 4096);
    memcpy(traceCard, tuid, uidlen);

    FillFileNameByUID(traceFileName, tuid, ".eml", uidlen);

    f = fopen(traceFileName, "r");
    if (!f) return PM3_EFILE;

    blockNum = 0;

    while (!feof(f)) {

        memset(buf, 0, sizeof(buf));
        if (fgets(buf, sizeof(buf), f) == NULL) {
            PrintAndLogEx(FAILED, "No trace file found or reading error.");
            fclose(f);
            return PM3_EFILE;
        }

        if (strlen(buf) < 32) {
            if (feof(f)) break;
            PrintAndLogEx(FAILED, "File content error. Block data must include 32 HEX symbols");
            fclose(f);
            return PM3_EFILE;
        }
        for (i = 0; i < 32; i += 2) {
            sscanf(&buf[i], "%02X", &tmp);
            buf8[i / 2] = tmp & 0xFF;
        }

        memcpy(traceCard + blockNum * 16, buf8, 16);

        blockNum++;
    }
    fclose(f);
    return PM3_SUCCESS;
}

int saveTraceCard(void) {

    if ((!strlen(traceFileName)) || (isTraceCardEmpty())) return PM3_ESOFT;

    FILE *f;
    f = fopen(traceFileName, "w+");
    if (!f) return PM3_EFILE;

    // given 4096 tracecard size,  these loop will only match a 1024, 1kb card memory
    // 4086/16 == 256blocks.
    for (uint16_t i = 0; i < 256; i++) {  // blocks
        for (uint8_t j = 0; j < 16; j++)  // bytes
            fprintf(f, "%02X", *(traceCard + i * 16 + j));

        // no extra line in the end
        if (i < 255)
            fprintf(f, "\n");
    }
    fflush(f);
    fclose(f);
    return PM3_SUCCESS;
}
//
int mfTraceInit(uint8_t *tuid, uint8_t uidlen, uint8_t *atqa, uint8_t sak, bool wantSaveToEmlFile) {

    if (traceCrypto1)
        crypto1_destroy(traceCrypto1);

    traceCrypto1 = NULL;

    if (wantSaveToEmlFile)
        loadTraceCard(tuid, uidlen);

    traceCard[4] = traceCard[0] ^ traceCard[1] ^ traceCard[2] ^ traceCard[3];
    traceCard[5] = sak;
    memcpy(&traceCard[6], atqa, 2);
    traceCurBlock = 0;
    cuid = bytes_to_num(tuid + (uidlen - 4), 4);
    traceState = TRACE_IDLE;
    return PM3_SUCCESS;
}

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

int mfTraceDecode(uint8_t *data_src, int len, bool wantSaveToEmlFile) {
    if (traceState == TRACE_ERROR)
        return PM3_ESOFT;

    if (len > 255) {
        traceState = TRACE_ERROR;
        return PM3_ESOFT;
    }

    uint8_t data[255];
    memset(data, 0x00, sizeof(data));

    memcpy(data, data_src, len);

    if ((traceCrypto1) && ((traceState == TRACE_IDLE) || (traceState > TRACE_AUTH_OK))) {
        mf_crypto1_decrypt(traceCrypto1, data, len, 0);
        PrintAndLogEx(NORMAL, "DEC| %s", sprint_hex(data, len));
        AddLogHex(logHexFileName, "DEC| ", data, len);
    }

    switch (traceState) {
        case TRACE_IDLE:
            // check packet crc16!
            if ((len >= 4) && (!check_crc(CRC_14443_A, data, len))) {
                PrintAndLogEx(NORMAL, "DEC| CRC ERROR!!!");
                AddLogLine(logHexFileName, "DEC| ", "CRC ERROR!!!");
                traceState = TRACE_ERROR;  // do not decrypt the next commands
                return PM3_ESOFT;
            }

            // AUTHENTICATION
            if ((len == 4) && ((data[0] == MIFARE_AUTH_KEYA) || (data[0] == MIFARE_AUTH_KEYB))) {
                traceState = TRACE_AUTH1;
                traceCurBlock = data[1];
                traceCurKey = data[0] == 60 ? 1 : 0;
                return PM3_SUCCESS;
            }

            // READ
            if ((len == 4) && ((data[0] == ISO14443A_CMD_READBLOCK))) {
                traceState = TRACE_READ_DATA;
                traceCurBlock = data[1];
                return PM3_SUCCESS;
            }

            // WRITE
            if ((len == 4) && ((data[0] == ISO14443A_CMD_WRITEBLOCK))) {
                traceState = TRACE_WRITE_OK;
                traceCurBlock = data[1];
                return PM3_SUCCESS;
            }

            // HALT
            if ((len == 4) && ((data[0] == ISO14443A_CMD_HALT) && (data[1] == 0x00))) {
                traceState = TRACE_ERROR;  // do not decrypt the next commands
                return PM3_SUCCESS;
            }
            return PM3_SUCCESS;

        case TRACE_READ_DATA:
            if (len == 18) {
                traceState = TRACE_IDLE;

                if (isBlockTrailer(traceCurBlock)) {
                    memcpy(traceCard + traceCurBlock * 16 + 6, data + 6, 4);
                } else {
                    memcpy(traceCard + traceCurBlock * 16, data, 16);
                }
                if (wantSaveToEmlFile) saveTraceCard();
                return PM3_SUCCESS;
            } else {
                traceState = TRACE_ERROR;
                return PM3_ESOFT;
            }
            break;
        case TRACE_WRITE_OK:
            if ((len == 1) && (data[0] == 0x0a)) {
                traceState = TRACE_WRITE_DATA;
                return PM3_SUCCESS;
            } else {
                traceState = TRACE_ERROR;
                return PM3_ESOFT;
            }
            break;
        case TRACE_WRITE_DATA:
            if (len == 18) {
                traceState = TRACE_IDLE;
                memcpy(traceCard + traceCurBlock * 16, data, 16);
                if (wantSaveToEmlFile) saveTraceCard();
                return PM3_SUCCESS;
            } else {
                traceState = TRACE_ERROR;
                return PM3_ESOFT;
            }
            break;
        case TRACE_AUTH1:
            if (len == 4) {
                traceState = TRACE_AUTH2;
                //nt = bytes_to_num(data, 4);
                return PM3_SUCCESS;
            } else {
                traceState = TRACE_ERROR;
                return PM3_ESOFT;
            }
            break;
        case TRACE_AUTH2:
            if (len == 8) {
                traceState = TRACE_AUTH_OK;
                //nr_enc = bytes_to_num(data, 4);
                //ar_enc = bytes_to_num(data + 4, 4);
                return PM3_SUCCESS;
            } else {
                traceState = TRACE_ERROR;
                return PM3_ESOFT;
            }
            break;
        case TRACE_AUTH_OK:
            if (len == 4) {
                uint32_t nt = 0;      // tag challenge
                uint32_t nr_enc = 0;  // encrypted reader challenge
                uint32_t ar_enc = 0;  // encrypted reader response
                uint32_t at_enc = 0;  // encrypted tag response
                traceState = TRACE_IDLE;
                // encrypted tag response
                at_enc = bytes_to_num(data, 4);

                //  mfkey64 recover key.
                uint64_t key = 0;
                uint32_t ks2 = ar_enc ^ prng_successor(nt, 64);
                uint32_t ks3 = at_enc ^ prng_successor(nt, 96);
                revstate = lfsr_recovery64(ks2, ks3);
                lfsr_rollback_word(revstate, 0, 0);
                lfsr_rollback_word(revstate, 0, 0);
                lfsr_rollback_word(revstate, nr_enc, 1);
                lfsr_rollback_word(revstate, cuid ^ nt, 0);
                crypto1_get_lfsr(revstate, &key);
                PrintAndLogEx(SUCCESS, "found Key: [%012" PRIx64 "]", key);

                //if ( tryMfk64(cuid, nt, nr_enc, ar_enc, at_enc, &key) )
                AddLogUint64(logHexFileName, "Found Key: ", key);

                int blockShift = ((traceCurBlock & 0xFC) + 3) * 16;
                if (isBlockEmpty((traceCurBlock & 0xFC) + 3))
                    memcpy(traceCard + blockShift + 6, trailerAccessBytes, 4);

                // keytype A/B
                if (traceCurKey)
                    num_to_bytes(key, 6, traceCard + blockShift + 10);
                else
                    num_to_bytes(key, 6, traceCard + blockShift);

                if (wantSaveToEmlFile)
                    saveTraceCard();

                if (traceCrypto1)
                    crypto1_destroy(traceCrypto1);

                // set cryptosystem state
                traceCrypto1 = lfsr_recovery64(ks2, ks3);

            } else {
                PrintAndLogEx(NORMAL, "[!] nested key recovery not implemented!\n");
                //at_enc = bytes_to_num(data, 4);
                crypto1_destroy(traceCrypto1);
                traceState = TRACE_ERROR;
            }
            break;
        default:
            traceState = TRACE_ERROR;
            return PM3_ESOFT;
    }
    return PM3_SUCCESS;
}

int tryDecryptWord(uint32_t nt, uint32_t ar_enc, uint32_t at_enc, uint8_t *data, int len) {
    PrintAndLogEx(SUCCESS, "\nencrypted data: [%s]", sprint_hex(data, len));
    struct Crypto1State *s;
    uint32_t ks2 = ar_enc ^ prng_successor(nt, 64);
    uint32_t ks3 = at_enc ^ prng_successor(nt, 96);
    s = lfsr_recovery64(ks2, ks3);
    mf_crypto1_decrypt(s, data, len, false);
    PrintAndLogEx(SUCCESS, "decrypted data: [%s]", sprint_hex(data, len));
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

    if (!WaitForResponseTimeout(CMD_ACK, &resp, 2000)) {
        PrintAndLogEx(WARNING, "PRNG UID: Reply timeout.");
        return PM3_ETIMEOUT;
    }

    // if select tag failed.
    if (resp.oldarg[0] == 0) {
        PrintAndLogEx(ERR, "error:  selecting tag failed,  can't detect prng\n");
        return PM3_ERFTRANS;
    }
    if (!WaitForResponseTimeout(CMD_ACK, &respA, 2500)) {
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

    if (verbose)
        PrintAndLogEx(SUCCESS, "press pm3-button on the Proxmark3 device to abort both Proxmark3 and client.\n");

    while (true) {
        printf(".");
        fflush(stdout);
        if (kbd_enter_pressed()) {
            return PM3_EOPABORTED;
        }

        if (WaitForResponseTimeout(CMD_HF_MIFARE_NACK_DETECT, &resp, 500)) {

            if (resp.status == PM3_EOPABORTED) {
                PrintAndLogEx(WARNING, "button pressed. Aborted.");
                return PM3_EOPABORTED;
            }

            uint8_t ok = resp.data.asBytes[0];
            uint8_t nacks = resp.data.asBytes[1];
            uint16_t auths = bytes_to_num(resp.data.asBytes + 2, 2);
            PrintAndLogEx(NORMAL, "");

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
                        PrintAndLogEx(NORMAL, "[- ]with 16 effective bits only, but shows unexpected behavior, try again.");
                    }
                    return PM3_SUCCESS;
                }
                case  2 :
                    PrintAndLogEx(SUCCESS, _GREEN_("always leak NACK detected"));
                    return PM3_SUCCESS;
                case  1 :
                    PrintAndLogEx(SUCCESS, _GREEN_("NACK bug detected"));
                    return PM3_SUCCESS;
                case  0 :
                    PrintAndLogEx(SUCCESS, "No NACK bug detected");
                    return PM3_SUCCESS;
                default :
                    PrintAndLogEx(ERR, "errorcode from device [%i]", ok);
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

    if (WaitForResponseTimeout(CMD_HF_MIFARE_STATIC_NONCE, &resp, 500)) {

        if (resp.status == PM3_ESOFT)
            return 2;

        if (resp.data.asBytes[0] == 0)
            return 0;

        if (resp.data.asBytes[0] != 0)
            return 1;
    }
    return 2;
}

/* try to see if card responses to "chinese magic backdoor" commands. */
void detect_classic_magic(void) {

    uint8_t isGeneration = 0;
    PacketResponseNG resp;
    clearCommandBuffer();
    SendCommandNG(CMD_HF_MIFARE_CIDENT, NULL, 0);
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
            PrintAndLogEx(SUCCESS, "Magic capabilities : "  _GREEN_("Gen 2 / CUID"));
            break;
        case MAGIC_GEN_UNFUSED:
            PrintAndLogEx(SUCCESS, "Magic capabilities : " _GREEN_("Write Once / FUID"));
            break;
        default:
            break;
    }
}
