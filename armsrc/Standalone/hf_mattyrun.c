//-----------------------------------------------------------------------------
// Copyright (C) Matías A. Ré Medina 2016
// Copyright (C) Michael Roland 2024
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
// main code for HF MIFARE Classic chk/ecfill/sim aka MattyRun
//-----------------------------------------------------------------------------

#include "hf_mattyrun.h"

#include <inttypes.h>

#include "appmain.h"
#include "BigBuf.h"
#include "commonutil.h"
#include "crc16.h"
#include "dbprint.h"
#include "fpgaloader.h"
#include "iso14443a.h"
#include "mifarecmd.h"
#include "mifaresim.h"  // mifare1ksim
#include "mifareutil.h"
#include "proxmark3_arm.h"
#include "standalone.h" // standalone definitions
#include "string.h"
#include "ticks.h"
#include "util.h"

/* 
 * `hf_mattyrun` tries to dump MIFARE Classic cards into emulator memory and emulates them.
 * 
 * This standalone mode uses a predefined dictionary to authenticate to MIFARE Classic
 * cards (cf. `hf mf chk`) and to dump the card into emulator memory (cf. `hf mf ecfill`).
 * Once a card has been dumped, the card is emulated (cf. `hf mf sim`). Emulation will
 * start even if only a partial dump could be retrieved from the card (e.g. due to missing
 * keys).
 * 
 * This standalone mode is specifically designed for devices without flash. However,
 * users can pass data to/from the standalone mode through emulator memory (assuming
 * continuous (battery) power supply):
 * 
 * - Keys can be added to the dictionary by loading them into the emulator before
 *   starting the standalone mode. You can use `hf mf eload -f dump_file` to load
 *   any existing card dump. All keys from the key slots in the sector trailers
 *   are added to the dictionary. Note that you can fill both keys in all sector
 *   trailers available for a 4K card to store your user dictionary. Sector and key
 *   type are ignored during chk; all user keys will be tested for all sectors and
 *   for both key types.
 * 
 * - Once a card has been cloned into emulator memory, you can extract the dump by
 *   ending the standalone mode and retrieving the emulator memory (`hf mf eview`
 *   or `hf mf esave [--mini|--1k|--2k|--4k] -f dump_file`).
 * 
 * This standalone mode will log status information via USB. In addition, the LEDs
 * display status information:
 * 
 * - Waiting for card: LED C is on, LED D blinks.
 * - Tying to authenticate: LED C and D are on; LED D will blink on errors.
 * - Nested attack (NOT IMPLEMENTED!): LED B is on.
 * - Loading card data into emulator memory: LED B and C are on.
 * - Starting emulation: LED A, B, and C are on. LED D is on if only a partial
 *   dump is available.
 * - Emulation started: All LEDS are off.
 * 
 * You can use the user button to interact with the standalone mode. During
 * emulation, (short) pressing the button ends emulation and returns to card
 * discovery. Long pressing the button ends the standalone mode.
 * 
 * Developers can configure the behavior of the standalone mode through the below
 * constants:
 * 
 * - MATTYRUN_PRINT_KEYS: Activate display of actually used key dictionary on startup.
 * - MATTYRUN_NO_ECFILL: Do not load and emulate card (only discovered keys are stored).
 * - MATTYRUN_MFC_DEFAULT_KEYS: Compiled-in default dictionary defined in a separate
 *   header file (`hf_mattyrun.h`) for easier customization. You can add your customized
 *   dictionaries here.
 * - MATTYRUN_MFC_ESSENTIAL_KEYS: Compiled-in dictionary of keys that should be tested
 *   before any user dictionary.
 * 
 * This is a major rewrite of the original `hf_mattyrun` by Matías A. Ré Medina.
 * The original version is described [here](http://bit.ly/2c9nZXR) (in Spanish).
 */

// Pseudo-configuration block
static bool const MATTYRUN_PRINT_KEYS = false; // Print assembled key dictionary on startup.
static bool const MATTYRUN_NO_ECFILL = false;  // Do not load and emulate card.

// Key flags
// TODO: Do we want to add flags to mark keys to be tested only as key A / key B?
static uint64_t const MATTYRUN_MFC_KEY_BITS = 0x00FFFFFFFFFFFF;
static uint64_t const MATTYRUN_MFC_KEY_FLAG_UNUSED = 0x10000000000000;

// Set of priority keys to be used
static uint64_t const MATTYRUN_MFC_ESSENTIAL_KEYS[] = {
    0xFFFFFFFFFFFF,  // Default key
    0x000000000000,  // Blank key
    0xA0A1A2A3A4A5,  // MAD key
    0x5C8FF9990DA2,  // Mifare 1k EV1 (S50) hidden blocks, Signature data 16 A
    0x75CCB59C9BED,  // Mifare 1k EV1 (S50) hidden blocks, Signature data 17 A
    0xD01AFEEB890A,  // Mifare 1k EV1 (S50) hidden blocks, Signature data 16 B
    0x4B791BEA7BCC,  // Mifare 1k EV1 (S50) hidden blocks, Signature data 17 B
    0xD3F7D3F7D3F7,  // AN1305 MIFARE Classic as NFC Type MIFARE Classic Tag Public Key A
};

// Internal state
static uint8_t mattyrun_uid[10];
static uint32_t mattyrun_cuid;
static iso14a_card_select_t mattyrun_card;

// Discover ISO 14443A cards
static bool saMifareDiscover(void) {
    SpinDelay(500);
    iso14443a_setup(FPGA_HF_ISO14443A_READER_LISTEN);

    if (iso14443a_select_card(mattyrun_uid, &mattyrun_card, &mattyrun_cuid, true, 0, true) == 0) {
        FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
        SpinDelay(500);
        return false;
    }

    return true;
}

// Customized MifareChkKeys that operates on the already detected card in
// mattyrun_card and tests authentication with our dictionary
static int saMifareChkKeys(uint8_t const blockNo, uint8_t const keyType, bool const clearTrace,
                           uint16_t const keyCount, uint64_t const * const mfKeys, uint64_t * const key) {

    int retval = -1;

    struct Crypto1State mpcs = {0, 0};
    struct Crypto1State *pcs;
    pcs = &mpcs;

    uint8_t selectRetries = 16;
    uint8_t cascade_levels = 0;
    int authres = 0;

    if (clearTrace)
        clear_trace();

    int oldbg = g_dbglevel;
    g_dbglevel = DBG_NONE;

    set_tracing(false);

    for (uint16_t i = 0; i < keyCount; ++i) {

        uint64_t mfKey = mfKeys[i];
        if ((mfKey & MATTYRUN_MFC_KEY_FLAG_UNUSED) != 0) {
            // skip unused dictionary key slot
            continue;
        }
        mfKey &= MATTYRUN_MFC_KEY_BITS;

        if (mattyrun_card.uidlen == 0) {
            if (!saMifareDiscover()) {
                --i; // try same key once again
                --selectRetries;
                if (selectRetries > 0) {
                    continue;
                } else {
                    retval = -2;
                    break;
                }
            }
        } else {
            if (cascade_levels == 0) {
                switch (mattyrun_card.uidlen) {
                    case 4:  cascade_levels = 1; break;
                    case 7:  cascade_levels = 2; break;
                    case 10: cascade_levels = 3; break;
                    default: break;
                }
            }
            // No need for anticollision. Since we sucessfully selected the card before,
            // we can directly select the card again
            if (iso14443a_fast_select_card(mattyrun_uid, cascade_levels) == 0) {
                --i; // try same key once again
                --selectRetries;
                if (selectRetries > 0) {
                    continue;
                } else {
                    retval = -2;
                    break;
                }
            }
        }

        selectRetries = 16;

        authres = mifare_classic_auth(pcs, mattyrun_cuid, blockNo, keyType, mfKey, AUTH_FIRST);
        if (authres) {
            uint8_t dummy_answer = 0;
            ReaderTransmit(&dummy_answer, 1, NULL);
            // wait for the card to become ready again
            SpinDelayUs(AUTHENTICATION_TIMEOUT);
            if (authres == 1) {
                retval = -3;
                break;
            } else {
                continue;
            }
        }
        *key = mfKey;
        retval = i;
        break;
    }

    crypto1_deinit(pcs);

    set_tracing(false);
    g_dbglevel = oldbg;

    return retval;
}

void ModInfo(void) {
    DbpString("  HF MIFARE Classic chk/ecfill/sim - aka MattyRun");
}

void RunMod(void) {
    StandAloneMode();
    DbpString(">>  HF MIFARE Classic chk/ecfill/sim - aka MattyRun started  <<");

    // Comment this line below if you want to see debug messages.
    // usb_disable();

    // Allocate dictionary buffer
    uint64_t * const mfcKeys = (uint64_t *)BigBuf_malloc(
            sizeof(uint64_t) * (ARRAYLEN(MATTYRUN_MFC_ESSENTIAL_KEYS) +
                                ARRAYLEN(MATTYRUN_MFC_DEFAULT_KEYS) +
                                MIFARE_4K_MAXSECTOR * 2));
    uint16_t mfcKeyCount = 0;

    // Load essential keys to dictionary buffer
    for (uint16_t i = 0; i < ARRAYLEN(MATTYRUN_MFC_ESSENTIAL_KEYS); ++i) {
        uint64_t mfKey = MATTYRUN_MFC_ESSENTIAL_KEYS[i];
        for (uint16_t j = 0; j < mfcKeyCount; ++j) {
            if (mfKey == mfcKeys[j]) {
                // skip redundant dictionary key
                mfKey = MATTYRUN_MFC_KEY_FLAG_UNUSED;
                break;
            }
        }
        if ((mfKey & MATTYRUN_MFC_KEY_FLAG_UNUSED) == 0) {
            mfcKeys[mfcKeyCount] = mfKey;
            ++mfcKeyCount;
        }
    }

    // Load user keys from emulator memory to dictionary buffer
    for (uint8_t sectorNo = 0; sectorNo < MIFARE_4K_MAXSECTOR; ++sectorNo) {
        for (uint8_t keyType = 0; keyType < 2; ++keyType) {
            uint64_t mfKey = emlGetKey(sectorNo, keyType);
            for (uint16_t j = 0; j < mfcKeyCount; ++j) {
                if (mfKey == mfcKeys[j]) {
                    // skip redundant dictionary key
                    mfKey = MATTYRUN_MFC_KEY_FLAG_UNUSED;
                    break;
                }
            }
            if ((mfKey & MATTYRUN_MFC_KEY_FLAG_UNUSED) == 0) {
                mfcKeys[mfcKeyCount] = mfKey;
                ++mfcKeyCount;
            }
        }
    }

    // Load additional keys to dictionary buffer
    for (uint16_t i = 0; i < ARRAYLEN(MATTYRUN_MFC_DEFAULT_KEYS); ++i) {
        uint64_t mfKey = MATTYRUN_MFC_DEFAULT_KEYS[i];
        for (uint16_t j = 0; j < mfcKeyCount; ++j) {
            if (mfKey == mfcKeys[j]) {
                // skip redundant dictionary key
                mfKey = MATTYRUN_MFC_KEY_FLAG_UNUSED;
                break;
            }
        }
        if ((mfKey & MATTYRUN_MFC_KEY_FLAG_UNUSED) == 0) {
            mfcKeys[mfcKeyCount] = mfKey;
            ++mfcKeyCount;
        }
    }

    // Call FpgaDownloadAndGo(FPGA_BITSTREAM_HF) only after extracting keys from
    // emulator memory as it may destroy the contents of the emulator memory
    FpgaDownloadAndGo(FPGA_BITSTREAM_HF);

    // Pretty print keys to be checked
    if (MATTYRUN_PRINT_KEYS) {
        DbpString("[+] Printing mfc key dictionary");
        for (uint16_t i = 0; i < mfcKeyCount; ++i) {
            uint64_t mfKey = mfcKeys[i];
            if ((mfKey & MATTYRUN_MFC_KEY_FLAG_UNUSED) != 0) {
                // skip unused dictionary key slot
                continue;
            }
            Dbprintf("[-]     key[%5" PRIu16 "] = %012" PRIx64 "", i, mfKey);
        }
        DbpString("[+] --------------------------------------------------------");
    }

    uint8_t sectorsCnt = MIFARE_4K_MAXSECTOR;
    bool keyFound = false;
    bool allKeysFound = true;
    bool partialEmulation = false;
    bool validKey[2][MIFARE_4K_MAXSECTOR];
    uint8_t foundKey[2][MIFARE_4K_MAXSECTOR][6];

    enum {
        STATE_READ,
        STATE_ATTACK,
        STATE_LOAD,
        STATE_EMULATE,
    } state = STATE_READ;

    for (;;) {

        WDT_HIT();

        // Exit from MattyRun when usbcommand is received
        if (data_available()) break;

        // Exit from MattyRun on long-press of user button
        int button_pressed = BUTTON_HELD(280);
        if (button_pressed == BUTTON_HOLD) {
            WAIT_BUTTON_RELEASED();
            break;
        }

        if (state == STATE_READ) {
            // Wait for card.
            // If detected, try to authenticate with dictionary keys.

            LED_A_OFF();
            LED_B_OFF();
            LED_C_ON();
            LED_D_OFF();

            if (!saMifareDiscover()) {
                SpinErr(LED_D, 50, 2);
                continue;
            }

            switch (mattyrun_card.uidlen) {
                case 4:
                    Dbprintf("[=] Card detected: ATQA=%02x%02x, SAK=%02x, %dB UID=%02x%02x%02x%02x",
                             mattyrun_card.atqa[1], mattyrun_card.atqa[0], mattyrun_card.sak, mattyrun_card.uidlen,
                             mattyrun_card.uid[0], mattyrun_card.uid[1], mattyrun_card.uid[2], mattyrun_card.uid[3]);
                    break;
                case 7:
                    Dbprintf("[=] Card detected: ATQA=%02x%02x, SAK=%02x, %dB UID=%02x%02x%02x%02x%02x%02x%02x",
                             mattyrun_card.atqa[1], mattyrun_card.atqa[0], mattyrun_card.sak, mattyrun_card.uidlen,
                             mattyrun_card.uid[0], mattyrun_card.uid[1], mattyrun_card.uid[2], mattyrun_card.uid[3],
                             mattyrun_card.uid[4], mattyrun_card.uid[5], mattyrun_card.uid[6]);
                    break;
                default:
                    Dbprintf("[=] Card detected: ATQA=%02x%02x, SAK=%02x, %dB UID=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                             mattyrun_card.atqa[1], mattyrun_card.atqa[0], mattyrun_card.sak, mattyrun_card.uidlen,
                             mattyrun_card.uid[0], mattyrun_card.uid[1], mattyrun_card.uid[2], mattyrun_card.uid[3],
                             mattyrun_card.uid[4], mattyrun_card.uid[5], mattyrun_card.uid[6],
                             mattyrun_card.uid[7], mattyrun_card.uid[8], mattyrun_card.uid[9]);
                    break;
            }

            sectorsCnt = MIFARE_4K_MAXSECTOR;

            // Initialization of validKeys and foundKeys:
            // - validKey will store whether the sector has a valid A/B key.
            // - foundKey will store the found A/B key for each sector.
            for (uint8_t keyType = 0; keyType < 2; ++keyType) {
                for (uint8_t sectorNo = 0; sectorNo < sectorsCnt; ++sectorNo) {
                    validKey[keyType][sectorNo] = false;
                    memset(foundKey[keyType][sectorNo], 0xFF, 6);
                }
            }

            keyFound = false;
            allKeysFound = true;
            bool err = false;

            // Iterates through each sector, checking if there is a correct key
            for (uint8_t keyType = 0; keyType < 2 && !err; ++keyType) {
                for (uint8_t sec = 0; sec < sectorsCnt && !err; ++sec) {
                    uint64_t currentKey;
                    Dbprintf("[=] Testing sector %3" PRIu8 " (block %3" PRIu8 ") for key %c",
                             sec, FirstBlockOfSector(sec), (keyType == 0) ? 'A' : 'B');
                    int key = saMifareChkKeys(FirstBlockOfSector(sec), keyType, true,
                                              mfcKeyCount, &mfcKeys[0], &currentKey);
                    if (key == -2) {
                        DbpString("[" _RED_("!") "] " _RED_("Failed to select card!"));
                        SpinErr(LED_D, 50, 2);
                        err = true; // fall back into idle mode since we can't select card anymore
                        break;
                    } else if (key == -3) {
                        sectorsCnt = sec;
                        switch (sec) {
                            case MIFARE_MINI_MAXSECTOR:
                            case MIFARE_1K_MAXSECTOR:
                            case MIFARE_2K_MAXSECTOR:
                            case MIFARE_4K_MAXSECTOR:
                                break;
                            case (MIFARE_MINI_MAXSECTOR + 2):
                            case (MIFARE_1K_MAXSECTOR + 2):
                            case (MIFARE_2K_MAXSECTOR + 2):
                            case (MIFARE_4K_MAXSECTOR + 2):
                                break;
                            default:
                                Dbprintf("[" _RED_("!") "] " _RED_("Unexpected number of sectors (%" PRIu8 ")!"),
                                         sec);
                                SpinErr(LED_D, 250, 3);
                                allKeysFound = false;
                                break;
                        }
                        break;
                    } else if (key < 0) {
                        Dbprintf("[" _RED_("!") "] " _RED_("No key %c found for sector %" PRIu8 "!"),
                                 (keyType == 0) ? 'A' : 'B', sec);
                        SpinErr(LED_D, 50, 3);
                        LED_C_ON();
                        allKeysFound = false;
                        continue;
                    } else {
                        num_to_bytes(currentKey, 6, foundKey[keyType][sec]);
                        validKey[keyType][sec] = true;
                        keyFound = true;
                        Dbprintf("[=] Found valid key: %012" PRIx64 "", currentKey);
                    }
                }
            }

            FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);

            if (err) {
                SpinOff(500);
                continue;
            }

            if (allKeysFound) {
                DbpString("[" _GREEN_("+") "] " _GREEN_("All keys found"));
                state = STATE_LOAD;
                continue;
            } else if (keyFound) {
                DbpString("[" _RED_("!") "] " _RED_("Some keys could not be found!"));
                state = STATE_ATTACK;
                continue;
            } else {
                DbpString("[" _RED_("!") "] " _RED_("No keys found!"));
                DbpString("[" _RED_("!") "] " _RED_("There's nothing I can do without at least one valid key, sorry!"));
                SpinErr(LED_D, 250, 5);
                continue;
            }

        } else if (state == STATE_ATTACK) {
            // Do nested attack, set allKeysFound = true

            LED_A_OFF();
            LED_B_ON();
            LED_C_OFF();
            LED_D_OFF();

            // no room to run nested attack on device (iceman)
            DbpString("[" _RED_("!") "] " _RED_("There's currently no nested attack in MattyRun, sorry!"));
            // allKeysFound = true;

            state = STATE_LOAD;
            continue;

        } else if (state == STATE_LOAD) {
            // Transfer found keys to memory.
            // If enabled, load full card content into emulator memory.

            LED_A_OFF();
            LED_B_ON();
            LED_C_ON();
            LED_D_OFF();

            emlClearMem();

            uint8_t mblock[MIFARE_BLOCK_SIZE];
            for (uint8_t sectorNo = 0; sectorNo < sectorsCnt; ++sectorNo) {
                if (validKey[0][sectorNo] || validKey[1][sectorNo]) {
                    emlGetMem(mblock, FirstBlockOfSector(sectorNo) + NumBlocksPerSector(sectorNo) - 1, 1);
                    for (uint8_t keyType = 0; keyType < 2; ++keyType) {
                        if (validKey[keyType][sectorNo]) {
                            memcpy(mblock + keyType * 10, foundKey[keyType][sectorNo], 6);
                        }
                    }
                    emlSetMem_xt(mblock, FirstBlockOfSector(sectorNo) + NumBlocksPerSector(sectorNo) - 1, 1, MIFARE_BLOCK_SIZE);
                }
            }

            DbpString("[=] Found keys have been transferred to the emulator memory.");

            if (MATTYRUN_NO_ECFILL) {
                state = STATE_READ;
                continue;
            }

            int filled;
            partialEmulation = false;
            DbpString("[=] Filling emulator memory using key A");
            filled = MifareECardLoad(sectorsCnt, MF_KEY_A);
            if (filled != PM3_SUCCESS) {
                DbpString("[" _YELLOW_("-") "] " _YELLOW_("Only partially filled using key A, retry with key B!"));
                DbpString("[=] Filling emulator memory using key B");
                filled = MifareECardLoad(sectorsCnt, MF_KEY_B);
                if (filled != PM3_SUCCESS) {
                    DbpString("[" _YELLOW_("-") "] " _YELLOW_("Only partially filled using key B!"));
                }
            }
            if (filled != PM3_SUCCESS) {
                DbpString("[" _RED_("!") "] " _RED_("Emulator memory could not be completely filled due to errors!"));
                SpinErr(LED_D, 50, 8);
                partialEmulation = true;
            } else {
                DbpString("[" _GREEN_("+") "] " _GREEN_("Emulator memory filled completely."));
            }

            state = STATE_EMULATE;
            continue;

        } else if (state == STATE_EMULATE) {
            // Finally, emulate the cloned card.

            LED_A_ON();
            LED_B_ON();
            LED_C_ON();
            LED_D_OFF();

            DbpString("[=] Started emulation. Press button to abort at anytime.");
    
            if (partialEmulation) {
                LED_D_ON();
                DbpString("[=] Partial memory dump loaded. Trying best effort emulation approach.");
            }

            uint16_t simflags = 0;
            switch (mattyrun_card.uidlen) {
                case 4:  simflags |= FLAG_4B_UID_IN_DATA;  break;
                case 7:  simflags |= FLAG_7B_UID_IN_DATA;  break;
                case 10: simflags |= FLAG_10B_UID_IN_DATA; break;
                default: break;
            }
            uint16_t atqa = (uint16_t)bytes_to_num(mattyrun_card.atqa, 2);

            SpinDelay(1000);
            Mifare1ksim(simflags, 0, mattyrun_uid, atqa, mattyrun_card.sak);

            DbpString("[=] Emulation ended.");
            state = STATE_READ;
            continue;

        }
    }

    BigBuf_free_keep_EM();

    SpinErr((LED_A | LED_B | LED_C | LED_D), 250, 5);
    DbpString("[=] Standalone mode MattyRun ended.");
    DbpString("");
    DbpString("[" _YELLOW_("-") "] " _YELLOW_("Download card clone with `hf mf esave [--mini|--1k|--2k|--4k] -f dump_file`."));
    DbpString("");
    DbpString("[=] You can take shell back :) ...");
    LEDsoff();
}
