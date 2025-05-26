//-----------------------------------------------------------------------------
// Copyright (C) SecLabz, 2025
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
// Standalone mode for reading/storing and restoring ST25TB tags with tear-off for counters.
// Handles a collection of tags. Click swaps between Store and Restore modes.
// Requires WITH_FLASH enabled at compile time.
// Only tested on a Proxmark3 Easy with flash
//
// The initial mode is learning/storing with LED D.
// In this mode, the Proxmark3 is looking for an ST25TB tag, reads all its data,
// and stores the tag's contents to flash memory for later restoration.
//
// Clicking the button once will toggle to restore mode (LED C).
// In this mode, the Proxmark3 searches for an ST25TB tag and, if found, compares
// its UID with previously stored tags. If there's a match, it will restore the
// tag data from flash memory, including counter blocks using tear-off technique.
//
// The standalone supports a collection of up to 8 different ST25TB tags.
//
// Special handling is implemented for counter blocks 5 & 6. For these blocks,
// the tear-off technique is used to manipulate counters that normally can only
// be decremented, allowing restoration of previously stored counter values even
// if they're higher than the current value.
//
// Holding the button down for 1 second will exit the standalone mode.
//
// LEDs:
// LED D = Learn/Store mode (reading and storing tag data)
// LED C = Restore mode (writing stored data back to tags)
// LED A (blinking) = Operation successful
// LED B (blinking) = Operation failed
//
// Flash memory is required for this standalone mode to function properly.
//
//-----------------------------------------------------------------------------


//=============================================================================
// INCLUDES
//=============================================================================

// System includes
#include <string.h>     // memcpy, memset

// Proxmark3 includes
#include "standalone.h"
#include "proxmark3_arm.h"
#include "appmain.h"
#include "fpgaloader.h"
#include "iso14443b.h"  // ISO14443B operations
#include "util.h"
#include "spiffs.h"     // Flash memory filesystem access
#include "dbprint.h"
#include "ticks.h"
#include "BigBuf.h"
#include "protocols.h"
#include "crc16.h"      // compute_crc

//=============================================================================
// FLASH MEMORY REQUIREMENT CHECK
//=============================================================================

#ifndef WITH_FLASH
#error "This standalone mode requires WITH_FLASH to be defined. Please recompile with flash memory support."
#endif

//=============================================================================
// CONSTANTS & DEFINITIONS
//=============================================================================

// File and data structure constants
#define HF_ST25TB_MULTI_SR_FILE "hf_st25tb_tags.bin" // Store/Restore filename
#define ST25TB_BLOCK_COUNT 16                        // ST25TB512 or similar with 16 blocks
#define ST25TB_BLOCK_SIZE 4                          // 4 bytes per block
#define ST25TB_COUNTER_BLOCK_5 5                     // Counter block indices
#define ST25TB_COUNTER_BLOCK_6 6
#define ST25TB_DATA_SIZE (ST25TB_BLOCK_COUNT * ST25TB_BLOCK_SIZE)
#define MAX_SAVED_TAGS 8                            // Allow storing up to 8 tags

// Tear-off constants
#define TEAR_OFF_START_OFFSET_US 150
#define TEAR_OFF_ADJUSTMENT_US 25
#define PRE_READ_DELAY_US 0
#define TEAR_OFF_WRITE_RETRY_COUNT 30
#define TEAR_OFF_CONSOLIDATE_READ_COUNT 6
#define TEAR_OFF_CONSOLIDATE_WAIT_READ_COUNT 2
#define TEAR_OFF_CONSOLIDATE_WAIT_MS 2000

// Display/console colors
#define RESET "\033[0m"
#define BOLD "\033[01m"
#define RED "\033[31m"
#define BLUE "\033[34m"
#define GREEN "\033[32m"

// Bit manipulation macros
#define IS_ONE_BIT(value, index) ((value) & ((uint32_t)1 << (index)))
#define IS_ZERO_BIT(value, index) (!IS_ONE_BIT(value, index))

#define RF_SWTICH_OFF() FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF)

//=============================================================================
// TYPE DEFINITIONS
//=============================================================================

// Operation modes
typedef enum {
    MODE_LEARN = 0,     // Store/learn tag data
    MODE_RESTORE = 1    // Restore tag data
} standalone_mode_t;

// Operation states
typedef enum {
    STATE_BUSY = 0,     // Actively processing
    STATE_DONE = 1,     // Operation completed successfully
    STATE_ERROR = 2     // Operation failed
} standalone_state_t;

// Structure to hold tag data in RAM
typedef struct {
    uint64_t uid;
    uint32_t blocks[ST25TB_BLOCK_COUNT];
    uint32_t otp;
    bool data_valid;    // Flag to indicate if this slot holds valid data
} st25tb_data_t;

//=============================================================================
// GLOBAL VARIABLES
//=============================================================================

// Tag collection and state tracking
static st25tb_data_t g_stored_tags[MAX_SAVED_TAGS];
static uint8_t g_valid_tag_count = 0;                 // Number of valid entries
static standalone_mode_t g_current_mode = MODE_LEARN; // Current operation mode
static standalone_state_t current_state = STATE_BUSY; // Current operation state
static unsigned long g_prng_seed = 1;                 // Used for PRNG

//=============================================================================
// FUNCTION DECLARATIONS
//=============================================================================

// Core utility functions
static int dummy_rand(void);
uint64_t bytes_to_num_le(const uint8_t *src, size_t len);

// UI/LED interaction functions
static void update_leds_mode(standalone_mode_t mode);
static void indicate_success(void);
static void indicate_failure(void);

// Flash storage operations
static bool load_tags_from_flash(st25tb_data_t collection[MAX_SAVED_TAGS]);
static bool save_tags_to_flash(const st25tb_data_t collection[MAX_SAVED_TAGS]);
static int find_tag_by_uid(const uint64_t uid);
static int find_free_tag_slot(void);

// ISO14443B communication functions
static void iso14443b_setup_light(void);

// Tag read/write operations
static bool st25tb_tag_get_basic_info(iso14b_card_select_t *card_info);
static bool st25tb_tag_read(st25tb_data_t *tag_data_slot);
static bool st25tb_tag_restore(const st25tb_data_t *stored_data_slot);
static void st25tb_tag_print(st25tb_data_t *tag);

// Tear-off operations
static int st25tb_cmd_write_block(uint8_t block_address, uint8_t *block);
static bool st25tb_write_block_with_retry(uint8_t block_address, uint32_t target_value);
static int st25tb_tear_off_read_block(uint8_t block_address, uint32_t *block_value);
static void st25tb_tear_off_write_block(uint8_t block_address, uint32_t data, uint16_t tearoff_delay_us);
static int8_t st25tb_tear_off_retry_write_verify(uint8_t block_address, uint32_t target_value, uint32_t max_try_count, int sleep_time_ms, uint32_t *read_back_value);
static int8_t st25tb_tear_off_is_consolidated(const uint8_t block_address, uint32_t value, int repeat_read, int sleep_time_ms, uint32_t *read_value);
static int8_t st25tb_tear_off_consolidate_block(const uint8_t block_address, uint32_t current_value, uint32_t target_value, uint32_t *read_back_value);
static uint32_t st25tb_tear_off_next_value(uint32_t current_value, bool randomness);
static void st25tb_tear_off_adjust_timing(int *tear_off_us, uint32_t tear_off_adjustment_us);
static void st25tb_tear_off_log(int tear_off_us, char *color, uint32_t value);
static int8_t st25tb_tear_off_write_counter(uint8_t block_address, uint32_t target_value, uint32_t tear_off_adjustment_us, uint32_t safety_value);

// Main application functions
static void run_learn_function(void);
static void run_restore_function(void);
void ModInfo(void);
void RunMod(void);

//=============================================================================
// CORE UTILITY FUNCTIONS
//=============================================================================

/**
 * @brief Simple PRNG implementation
 * @return Random integer
 */
static int dummy_rand(void) {
    g_prng_seed = g_prng_seed * 1103515245 + 12345;
    return (unsigned int)(g_prng_seed / 65536) % 32768;
}

/**
 * @brief Convert bytes to number (little-endian)
 * @param src Source byte array
 * @param len Length of array
 * @return Converted 64-bit value
 */
uint64_t bytes_to_num_le(const uint8_t *src, size_t len) {
    uint64_t num = 0;
    size_t i;

    if (len > sizeof(uint64_t)) {
        len = sizeof(uint64_t);
    }

    // Iterate from LSB to MSB
    for (i = 0; i < len; ++i) {
        num |= ((uint64_t)src[i] << (i * 8));
    }

    return num;
}

//=============================================================================
// UI/LED INTERACTION FUNCTIONS
//=============================================================================

/**
 * @brief Update LEDs to indicate current mode and state
 * @param mode Current operation mode
 */
static void update_leds_mode(standalone_mode_t mode) {
    LEDsoff();
    if (mode == MODE_LEARN) {
        LED_D_ON();
    } else { // MODE_RESTORE
        LED_C_ON();
    }
}

/**
 * @brief Indicate successful operation with LED sequence
 */
static void indicate_success(void) {
    // Blink Green LED (A) 3 times quickly for success
    for (int i = 0; i < 3; ++i) {
        LED_A_ON();
        SpinDelay(150);
        LED_A_OFF();
        SpinDelay(150);
    }
}

/**
 * @brief Indicate failed operation with LED sequence
 */
static void indicate_failure(void) {
    // Blink Red LED (B) 3 times quickly for failure
    for (int i = 0; i < 3; ++i) {
        LED_B_ON();
        SpinDelay(150);
        LED_B_OFF();
        SpinDelay(150);
    }
}

//=============================================================================
// FLASH STORAGE OPERATIONS
//=============================================================================

/**
 * @brief Load tag collection from flash
 * @param collection Array to store loaded data
 * @return true if successful, false otherwise
 */
static bool load_tags_from_flash(st25tb_data_t collection[MAX_SAVED_TAGS]) {
    // Check if file exists
    if (!exists_in_spiffs(HF_ST25TB_MULTI_SR_FILE)) {
        return false; // File doesn't exist, nothing to load
    }

    // Verify file size
    uint32_t size = size_in_spiffs(HF_ST25TB_MULTI_SR_FILE);
    if (size != sizeof(g_stored_tags)) {
        Dbprintf(_RED_("Flash file size mismatch (expected %zu, got %u). Wiping old file."),
                 sizeof(g_stored_tags), size);
        // Remove corrupted file
        rdv40_spiffs_remove(HF_ST25TB_MULTI_SR_FILE, RDV40_SPIFFS_SAFETY_SAFE);
        return false;
    }

    // Read file contents
    int res = rdv40_spiffs_read(HF_ST25TB_MULTI_SR_FILE, (uint8_t *)collection,
                                size, RDV40_SPIFFS_SAFETY_SAFE);

    if (res != SPIFFS_OK) {
        Dbprintf(_RED_("Failed to read tag collection from flash (err %d)"), res);
        // Mark all as invalid if read failed
        for (int i = 0; i < MAX_SAVED_TAGS; i++)
            collection[i].data_valid = false;
        return false;
    }

    return true;
}

/**
 * @brief Save tag collection to flash
 * @param collection Array of tag data to save
 * @return true if successful, false otherwise
 */
static bool save_tags_to_flash(const st25tb_data_t collection[MAX_SAVED_TAGS]) {
    int res = rdv40_spiffs_write(HF_ST25TB_MULTI_SR_FILE, (uint8_t *)collection,
                                 sizeof(g_stored_tags), RDV40_SPIFFS_SAFETY_SAFE);
    return (res == SPIFFS_OK);
}

/**
 * @brief Find a tag in the collection by UID
 * @param uid UID to search for
 * @return Index of tag in collection, or -1 if not found
 */
static int find_tag_by_uid(const uint64_t uid) {
    for (int i = 0; i < MAX_SAVED_TAGS; i++) {
        if (g_stored_tags[i].data_valid && g_stored_tags[i].uid == uid) {
            return i;
        }
    }
    return -1; // Not found
}

/**
 * @brief Find next empty slot in the collection
 * @return Index of empty slot, or -1 if collection is full
 */
static int find_free_tag_slot(void) {
    for (int i = 0; i < MAX_SAVED_TAGS; i++) {
        if (!g_stored_tags[i].data_valid) {
            return i;
        }
    }
    return -1; // Collection is full
}

//=============================================================================
// ISO14443B COMMUNICATION FUNCTIONS
//=============================================================================

/**
 * @brief Stripped version of "iso14443b_setup" that avoids unnecessary LED
 * operations and uses shorter delays
 */
static void iso14443b_setup_light(void) {
    RF_SWTICH_OFF();

    FpgaDownloadAndGo(FPGA_BITSTREAM_HF);

    // Set up the synchronous serial port
    FpgaSetupSsc(FPGA_MAJOR_MODE_HF_READER);

    // Signal field is on with the appropriate LED
#ifdef RDV4
    FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_READER | FPGA_HF_READER_MODE_SEND_SHALLOW_MOD_RDV4);
#else
    FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_READER | FPGA_HF_READER_MODE_SEND_SHALLOW_MOD);
#endif

    SpinDelayUs(250);

    // Start the timer
    StartCountSspClk();
}

//=============================================================================
// TAG READ/WRITE OPERATIONS
//=============================================================================

/**
 * @brief Select a ST25TB tag and get basic info
 * @param card_info Pointer to store card info
 * @return true if successful, false otherwise
 */
static bool st25tb_tag_get_basic_info(iso14b_card_select_t *card_info) {
    iso14443b_setup_light();
    int res = iso14443b_select_srx_card(card_info);
    RF_SWTICH_OFF();
    return (res == PM3_SUCCESS);
}

/**
 * @brief Read all data from a ST25TB tag
 * @param tag_data_slot Pointer to store tag data
 * @return true if successful, false otherwise
 */
static bool st25tb_tag_read(st25tb_data_t *tag_data_slot) {
    iso14443b_setup_light();
    iso14b_card_select_t card_info;
    uint8_t block[ST25TB_BLOCK_SIZE];
    int res;
    bool success = true;

    // Select card
    res = iso14443b_select_srx_card(&card_info);
    if (res != PM3_SUCCESS) {
        RF_SWTICH_OFF();
        return false;
    }

    Dbprintf("Found ST tag. Reading %d blocks...", ST25TB_BLOCK_COUNT);
    tag_data_slot->uid = bytes_to_num_le(card_info.uid, sizeof(tag_data_slot->uid));

    // Read all data blocks
    for (uint8_t block_address = 0; block_address < ST25TB_BLOCK_COUNT; block_address++) {
        WDT_HIT();
        res = read_14b_srx_block(block_address, block);
        if (res != PM3_SUCCESS) {
            Dbprintf(_RED_("Failed to read block %d"), block_address);
            success = false;
            break;
        }

        // Store the read block data
        tag_data_slot->blocks[block_address] = bytes_to_num_le(block, ST25TB_BLOCK_SIZE);

        if (g_dbglevel >= DBG_DEBUG) {
            Dbprintf("Read Block %02d: %08X", block_address, tag_data_slot->blocks[block_address]);
        }
        SpinDelay(5); // Small delay between block reads
    }

    // Read OTP block
    res = read_14b_srx_block(255, block);
    if (res != PM3_SUCCESS) {
        Dbprintf(_RED_("Failed to read otp block"));
        success = false;
    } else {
        tag_data_slot->otp = bytes_to_num_le(block, ST25TB_BLOCK_SIZE);
    }

    RF_SWTICH_OFF();

    tag_data_slot->data_valid = success;
    return success;
}

/**
 * @brief Restore data to a ST25TB tag
 * @param stored_data_slot Pointer to stored tag data
 * @return true if successful, false otherwise
 */
static bool st25tb_tag_restore(const st25tb_data_t *stored_data_slot) {
    if (!stored_data_slot->data_valid) {
        DbpString(_RED_("Restore error: Slot data is invalid."));
        return false;
    }

    iso14443b_setup_light();
    iso14b_card_select_t card_info;
    int res;
    bool success = true;

    res = iso14443b_select_srx_card(&card_info);
    if (res != PM3_SUCCESS) {
        DbpString("Restore failed: No tag found or selection failed.");
        RF_SWTICH_OFF();
        return false;
    }

    uint64_t tag_uid = bytes_to_num_le(card_info.uid, sizeof(uint64_t));

    // Verify UID match before restoring
    if (tag_uid != stored_data_slot->uid) {
        Dbprintf("Restore failed: UID mismatch (Tag: %llX, Slot: %llX)", tag_uid, stored_data_slot->uid);
        RF_SWTICH_OFF();
        return false;
    }

    Dbprintf("Found ST tag, UID: %llX. Starting restore...", tag_uid);

    // Process all blocks
    for (uint8_t block_address = 0; block_address < ST25TB_BLOCK_COUNT; block_address++) {
        WDT_HIT();
        uint32_t stored_value = stored_data_slot->blocks[block_address];

        if (g_dbglevel >= DBG_DEBUG) {
            Dbprintf("Restoring Block %02d: %08X", block_address, stored_value);
        }

        // Special handling for counter blocks 5 and 6
        if (block_address == ST25TB_COUNTER_BLOCK_5 || block_address == ST25TB_COUNTER_BLOCK_6) {
            uint32_t current_value = 0;

            res = st25tb_tear_off_read_block(block_address, &current_value);
            if (res != PM3_SUCCESS) {
                Dbprintf(_RED_("Failed to read current counter value for block %d"), block_address);
                success = false;
                break;
            }

            if (g_dbglevel >= DBG_DEBUG) {
                Dbprintf("Counter Block %d: Stored=0x%08X, Current=0x%08X",
                         block_address, stored_value, current_value);
            }

            // Only use tear-off logic if stored value is greater
            if (stored_value > current_value) {
                // The st25tb_tear_off_write_counter function handles the tear-off logic
                if (st25tb_tear_off_write_counter(block_address, stored_value, TEAR_OFF_ADJUSTMENT_US, 0x1000) != 0) {
                    Dbprintf(_RED_("Tear-off write failed for counter block %d"), block_address);
                    success = false;
                    break;
                }
                Dbprintf("Used tear-off write for counter block %d", block_address);
            } else if (stored_value < current_value) {
                // Standard write for when stored value is less than current
                if (!st25tb_write_block_with_retry(block_address, stored_value)) {
                    Dbprintf(_RED_("Failed to write block %d"), block_address);
                    success = false;
                    break;
                }
            } else {
                Dbprintf("Counter block %d already has the target value (0x%08X). Skipping write.",
                         block_address, stored_value);
            }
        } else {
            // Standard write for non-counter blocks
            if (!st25tb_write_block_with_retry(block_address, stored_value)) {
                Dbprintf(_RED_("Failed to write block %d with value 0x%08X"), block_address, stored_value);
                success = false;
                break;
            }
        }
        SpinDelay(10); // Delay between writes
    }

    RF_SWTICH_OFF();
    return success;
}

/**
 * @brief Print tag data in formatted table
 * @param tag Pointer to tag data
 */
static void st25tb_tag_print(st25tb_data_t *tag) {
    uint8_t i;

    Dbprintf("UID: %016llX", tag->uid);

    Dbprintf("+---------------+----------+--------------------+");
    Dbprintf("| BLOCK ADDRESS |  VALUE   |    DESCRIPTION     |");
    Dbprintf("+---------------+----------+--------------------+");

    for (i = 0; i < 16; i++) {
        if (i == 2) {
            Dbprintf("|     %03d       | %08X |   Lockable EEPROM  |", i, tag->blocks[i]);
        } else if (i == 5) {
            Dbprintf("|     %03d       | %08X |     Count down     |", i, tag->blocks[i]);
        } else if (i == 6) {
            Dbprintf("|     %03d       | %08X |       counter      |", i, tag->blocks[i]);
        } else if (i == 11) {
            Dbprintf("|     %03d       | %08X |   Lockable EEPROM  |", i, tag->blocks[i]);
        } else {
            Dbprintf("|     %03d       | %08X |                    |", i, tag->blocks[i]);
        }
        if (i == 4 || i == 6 || i == 15) {
            Dbprintf("+---------------+----------+--------------------+");
        }
    }

    Dbprintf("|     %03d       | %08X |   System OTP bits  |", 255, tag->otp);
    Dbprintf("+---------------+----------+--------------------+");
}

//=============================================================================
// TEAR-OFF OPERATIONS
//=============================================================================

/**
 * @brief Read a block
 * @param block_address Block address to read
 * @param block_value Pointer to store read value
 * @return Result code (0 for success)
 */
static int st25tb_tear_off_read_block(uint8_t block_address, uint32_t *block_value) {
    int res;
    iso14b_card_select_t card;
    iso14443b_setup_light();

    res = iso14443b_select_srx_card(&card);
    if (res != PM3_SUCCESS) {
        goto out;
    }

    uint8_t block[ST25TB_BLOCK_SIZE];
    res = read_14b_srx_block(block_address, block);
    if (res == PM3_SUCCESS) {
        *block_value = bytes_to_num_le(block, ST25TB_BLOCK_SIZE);
    }

out:
    RF_SWTICH_OFF();
    return res;
}

/**
 * @brief Low-level block write function
 * @param block_address Block number to write
 * @param block Block data
 * @return Result code (0 for success)
 */
static int st25tb_cmd_write_block(uint8_t block_address, uint8_t *block) {
    uint8_t cmd[] = {ISO14443B_WRITE_BLK, block_address, block[0], block[1], block[2], block[3], 0x00, 0x00};
    AddCrc14B(cmd, 6);

    uint32_t start_time = 0;
    uint32_t eof_time = 0;
    CodeAndTransmit14443bAsReader(cmd, sizeof(cmd), &start_time, &eof_time, true);

    return PM3_SUCCESS;
}

/**
 * @brief Write a block with retry mechanism
 * @param block_address Block number to write
 * @param target_value Value to write
 * @return true if successful, false otherwise
 */
static bool st25tb_write_block_with_retry(uint8_t block_address, uint32_t target_value) {
    uint32_t read_back_value = 0;
    int max_retries = 5;

    if (st25tb_tear_off_retry_write_verify(block_address, target_value, max_retries, 0, &read_back_value) != 0) {
        return false;
    }

    return (read_back_value == target_value);
}

/**
 * @brief Write a block with tear-off capability
 * @param block_address Block number to write
 * @param data Data to write
 * @param tearoff_delay_us Tear-off delay in microseconds
 */
static void st25tb_tear_off_write_block(uint8_t block_address, uint32_t data, uint16_t tearoff_delay_us) {
    iso14443b_setup_light();

    uint8_t block[ST25TB_BLOCK_SIZE];
    block[0] = (data & 0xFF);
    block[1] = (data >> 8) & 0xFF;
    block[2] = (data >> 16) & 0xFF;
    block[3] = (data >> 24) & 0xFF;

    iso14b_card_select_t card;
    int res = iso14443b_select_srx_card(&card);
    if (res != PM3_SUCCESS) {
        goto out;
    }

    res = st25tb_cmd_write_block(block_address, block);

    // Tear off the communication at precise timing
    SpinDelayUsPrecision(tearoff_delay_us);
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);

out:
    RF_SWTICH_OFF();
}

/**
 * @brief Write a block with retry and verification
 * @param block_address Block address to write
 * @param target_value Value to write
 * @param max_try_count Maximum number of retries
 * @param sleep_time_ms Sleep time between retries in milliseconds
 * @param read_back_value Pointer to store read-back value
 * @return 0 for success, -1 for failure
 */
static int8_t st25tb_tear_off_retry_write_verify(uint8_t block_address, uint32_t target_value,
                                                 uint32_t max_try_count, int sleep_time_ms,
                                                 uint32_t *read_back_value) {
    int i = 0;
    *read_back_value = ~target_value; // Initialize to ensure the loop runs at least once

    while (*read_back_value != target_value && i < max_try_count) {
        st25tb_tear_off_write_block(block_address, target_value, 6000); // Long delay for reliability
        if (sleep_time_ms > 0) SpinDelayUsPrecision(sleep_time_ms * 1000);
        st25tb_tear_off_read_block(block_address, read_back_value);
        if (sleep_time_ms > 0) SpinDelayUsPrecision(sleep_time_ms * 1000);
        i++;
    }

    return (*read_back_value == target_value) ? 0 : -1;
}

/**
 * @brief Check if a block's value is consolidated (stable)
 * @param block_address Block address to check
 * @param value Expected value
 * @param repeat_read Number of reads to perform
 * @param sleep_time_ms Sleep time between reads in milliseconds
 * @param read_value Pointer to store read value
 * @return 0 if consolidated, -1 otherwise
 */
static int8_t st25tb_tear_off_is_consolidated(const uint8_t block_address, uint32_t value,
                                              int repeat_read, int sleep_time_ms,
                                              uint32_t *read_value) {
    int result;
    for (int i = 0; i < repeat_read; i++) {
        if (sleep_time_ms > 0) SpinDelayUsPrecision(sleep_time_ms * 1000);
        result = st25tb_tear_off_read_block(block_address, read_value);
        if (result != 0 || value != *read_value) {
            return -1; // Read error or value changed
        }
    }
    return 0; // Value remained stable
}

/**
 * @brief Consolidate a block to a stable state
 * @param block_address Block address to consolidate
 * @param current_value Current value
 * @param target_value Target value
 * @param read_back_value Pointer to store read-back value
 * @return 0 for success, -1 for failure
 */
static int8_t st25tb_tear_off_consolidate_block(const uint8_t block_address, uint32_t current_value,
                                                uint32_t target_value, uint32_t *read_back_value) {
    int8_t result;
    uint32_t consolidation_value;

    // Determine the value to write for consolidation based on target and current state
    if (target_value <= 0xFFFFFFFD && current_value >= (target_value + 2)) {
        consolidation_value = target_value + 2;
    } else {
        consolidation_value = current_value;
    }

    // Try writing value - 1
    result = st25tb_tear_off_retry_write_verify(block_address, consolidation_value - 1,
                                                TEAR_OFF_WRITE_RETRY_COUNT, 0, read_back_value);
    if (result != 0) {
        Dbprintf("Consolidation failed at step 1 (write 0x%08X)", consolidation_value - 1);
        return -1;
    }

    // If value is not FE or target is not FD, try writing value - 2
    if (*read_back_value != 0xFFFFFFFE || (*read_back_value == 0xFFFFFFFE && target_value == 0xFFFFFFFD)) {
        result = st25tb_tear_off_retry_write_verify(block_address, consolidation_value - 2,
                                                    TEAR_OFF_WRITE_RETRY_COUNT, 0, read_back_value);
        if (result != 0) {
            Dbprintf("Consolidation failed at step 2 (write 0x%08X)", consolidation_value - 2);
            return -1;
        }
    }

    // Final checks for stability of unstable high values (due to internal dual counters)
    if (result == 0 && target_value > 0xFFFFFFFD && *read_back_value > 0xFFFFFFFD) {
        result = st25tb_tear_off_is_consolidated(block_address, *read_back_value,
                                                 TEAR_OFF_CONSOLIDATE_READ_COUNT, 0, read_back_value);
        if (result == 0) {
            result = st25tb_tear_off_is_consolidated(block_address, *read_back_value,
                                                     TEAR_OFF_CONSOLIDATE_WAIT_READ_COUNT,
                                                     TEAR_OFF_CONSOLIDATE_WAIT_MS, read_back_value);
            if (result != 0) {
                Dbprintf("Consolidation failed stability check (long wait)");
                return -1;
            }
        } else {
            Dbprintf("Consolidation failed stability check (short wait)");
            return -1;
        }
    }

    return 0;
}

/**
 * @brief Calculate next value for counter decrement
 * @param current_value Current counter value
 * @param randomness Whether to use randomization
 * @return Next value to attempt
 */
static uint32_t st25tb_tear_off_next_value(uint32_t current_value, bool randomness) {
    uint32_t value = 0;
    int8_t index = 31;

    // Simple decrement for smaller values
    if (current_value < 0x0000FFFF) {
        return (current_value > 0) ? current_value - 1 : 0;
    }

    // Loop through each bit starting from the most significant bit (MSB)
    while (index >= 0) {
        // Find the most significant '1' bit
        if (value == 0 && IS_ONE_BIT(current_value, index)) {
            // Create a mask with '1's up to this position
            value = 0xFFFFFFFF >> (31 - index);
            index--; // Move to the next bit
        }

        // Once the first '1' is found, look for the first '0' after it
        if (value != 0 && IS_ZERO_BIT(current_value, index)) {
            index++; // Go back to the position of the '0'
            // Clear the bit at this '0' position in our mask
            value &= ~((uint32_t)1 << index);

            // Optional randomization: flip a random bit below the found '0'
            if (randomness && value < 0xF0000000 && index > 1) {
                value ^= ((uint32_t)1 << (dummy_rand() % index));
            }
            return value;
        }

        index--;
    }

    return (current_value > 0) ? current_value - 1 : 0;
}

/**
 * @brief Adjust timing for tear-off operations
 * @param tear_off_us Pointer to current tear-off timing
 * @param tear_off_adjustment_us Adjustment amount
 */
static void st25tb_tear_off_adjust_timing(int *tear_off_us, uint32_t tear_off_adjustment_us) {
    if (*tear_off_us > TEAR_OFF_START_OFFSET_US) {
        *tear_off_us -= tear_off_adjustment_us;
    }
}

/**
 * @brief Log tear-off operation details
 * @param tear_off_us Current tear-off timing
 * @param color Color code for output
 * @param value Value being processed
 */
static void st25tb_tear_off_log(int tear_off_us, char *color, uint32_t value) {
    char binaryRepresentation[33];
    for (int i = 31; i >= 0; i--) {
        binaryRepresentation[31 - i] = IS_ONE_BIT(value, i) ? '1' : '0';
    }
    binaryRepresentation[32] = '\0';
    Dbprintf("%s%08X%s : %s%s%s : %d us", color, value, RESET, color, binaryRepresentation, RESET, tear_off_us);
}

/**
 * @brief Main tear-off counter write function
 * @param block_address Block address to write
 * @param target_value Target value
 * @param tear_off_adjustment_us Adjustment for tear-off timing
 * @param safety_value Safety threshold to prevent going below
 * @return 0 for success, non-zero for failure
 */
static int8_t st25tb_tear_off_write_counter(uint8_t block_address, uint32_t target_value,
                                            uint32_t tear_off_adjustment_us, uint32_t safety_value) {
    int result;
    bool trigger = true;

    uint32_t read_value = 0;
    uint32_t current_value = 0;
    uint32_t last_consolidated_value = 0;
    uint32_t tear_off_value = 0;

    int tear_off_us = TEAR_OFF_START_OFFSET_US;
    if (tear_off_adjustment_us == 0) {
        tear_off_adjustment_us = TEAR_OFF_ADJUSTMENT_US;
    }

    // Initial read to get the current counter value
    result = st25tb_tear_off_read_block(block_address, &current_value);
    if (result != PM3_SUCCESS) {
        Dbprintf("Initial read failed for block %d", block_address);
        return -1; // Indicate failure
    }

    // Calculate the first value to attempt writing via tear-off
    tear_off_value = st25tb_tear_off_next_value(current_value, false);

    Dbprintf(" Target block: %d", block_address);
    Dbprintf("Current value: 0x%08X", current_value);
    Dbprintf(" Target value: 0x%08X", target_value);
    Dbprintf(" Safety value: 0x%08X", safety_value);
    Dbprintf("Adjustment us: %u", tear_off_adjustment_us);

    // Check if tear-off is even possible or needed
    if (tear_off_value == 0 && current_value != 0) {
        Dbprintf("Tear-off technique not possible from current value.");
        return -1;
    }
    if (current_value == target_value) {
        Dbprintf("Current value already matches target value.");
        return 0;
    }

    // Main tear-off loop
    for (;;) {
        // Safety check: ensure we don't go below the safety threshold
        if (tear_off_value < safety_value) {
            Dbprintf("Stopped. Safety threshold reached (next value 0x%08X < safety 0x%08X)",
                     tear_off_value, safety_value);
            return -1;
        }

        // Perform the tear-off write attempt
        st25tb_tear_off_write_block(block_address, tear_off_value, tear_off_us);

        // Read back the value after the attempt
        result = st25tb_tear_off_read_block(block_address, &read_value);
        if (result != 0) {
            continue; // Retry the loop if read fails (ex: tag is removed from the read for a short period)
        }

        // Analyze the result and decide next action
        if (read_value > current_value) {
            // Partial write succeeded (successful tear-off)
            if (read_value >= 0xFFFFFFFE ||
                    (read_value - 2) > target_value ||
                    read_value != last_consolidated_value ||
                    ((read_value & 0xF0000000) > (current_value & 0xF0000000))) { // Major bit flip

                result = st25tb_tear_off_consolidate_block(block_address, read_value,
                                                           target_value, &current_value);
                if (result == 0 && current_value == target_value) {
                    st25tb_tear_off_log(tear_off_us, GREEN, read_value);
                    Dbprintf("Target value 0x%08X reached successfully!", target_value);
                    return 0;
                }
                if (read_value != last_consolidated_value) {
                    st25tb_tear_off_adjust_timing(&tear_off_us, tear_off_adjustment_us);
                }
                last_consolidated_value = read_value;
                tear_off_value = st25tb_tear_off_next_value(current_value, false);
                trigger = true;
                st25tb_tear_off_log(tear_off_us, GREEN, read_value);
            }
        } else if (read_value == tear_off_value) {
            // Write succeeded completely (no tear-off effect)
            if (trigger) {
                tear_off_value = st25tb_tear_off_next_value(tear_off_value, true);
                trigger = false;
            } else {
                tear_off_value = st25tb_tear_off_next_value(read_value, false);
                trigger = true;
            }
            current_value = read_value;
            st25tb_tear_off_adjust_timing(&tear_off_us, tear_off_adjustment_us);
            st25tb_tear_off_log(tear_off_us, BLUE, read_value);
        } else if (read_value < tear_off_value) {
            // Partial write succeeded (successful tear-off) but lower value
            tear_off_value = st25tb_tear_off_next_value(read_value, false);
            st25tb_tear_off_adjust_timing(&tear_off_us, tear_off_adjustment_us);
            current_value = read_value;
            trigger = true;
            st25tb_tear_off_log(tear_off_us, RED, read_value);
        }

        // Increment tear-off timing for the next attempt
        tear_off_us++;

        // Check for user interruption
        WDT_HIT();
        if (BUTTON_PRESS()) {
            DbpString("Tear-off stopped by user.");
            return -1;
        }
    }

    return -1;
}

//=============================================================================
// MAIN APPLICATION FUNCTIONS
//=============================================================================

/**
 * @brief Learn/store function implementation
 */
static void run_learn_function(void) {
    st25tb_data_t temp_tag_data; // Temporary buffer to read into
    memset(&temp_tag_data, 0, sizeof(temp_tag_data));

    if (st25tb_tag_read(&temp_tag_data)) {
        st25tb_tag_print(&temp_tag_data);
        int slot_index = find_tag_by_uid(temp_tag_data.uid);

        if (slot_index != -1) {
            Dbprintf("Tag with UID %llX already in Slot %d. Overwriting...",
                     temp_tag_data.uid, slot_index);
        } else {
            slot_index = find_free_tag_slot();
            if (slot_index == -1) {
                DbpString("Collection full! Overwriting Slot 0.");
                slot_index = 0; // Overwrite oldest/first slot if full
            } else {
                // Only increment if we are adding to a new slot, not overwriting
                if (!g_stored_tags[slot_index].data_valid) {
                    g_valid_tag_count++;
                }
            }
        }

        // Store tag data in collection
        memcpy(&g_stored_tags[slot_index], &temp_tag_data, sizeof(st25tb_data_t));
        g_stored_tags[slot_index].data_valid = true;
        Dbprintf("Stored tag in Slot %d. (UID: %llX)", slot_index, temp_tag_data.uid);

        // Save collection to flash
        if (save_tags_to_flash(g_stored_tags)) {
            DbpString("Collection saved to flash.");
        } else {
            DbpString(_RED_("Failed to save collection to flash!"));
        }

        current_state = STATE_DONE; // Indicate success
    }
}

/**
 * @brief Restore function implementation
 */
static void run_restore_function(void) {
    iso14b_card_select_t current_tag_info; // To get UID of tag in field

    if (st25tb_tag_get_basic_info(&current_tag_info)) {
        // Tag found in field
        uint64_t tag_uid = bytes_to_num_le(current_tag_info.uid, sizeof(uint64_t));
        int slot = find_tag_by_uid(tag_uid);

        if (slot != -1) {
            Dbprintf("Found matching tag in Slot %d (UID: %llX). Restoring...", slot, tag_uid);

            current_state = STATE_BUSY; // Indicate busy during restore attempt
            update_leds_mode(g_current_mode);

            bool success = st25tb_tag_restore(&g_stored_tags[slot]);

            if (success) {
                DbpString(_GREEN_("Restore successful."));
                current_state = STATE_DONE;
            } else {
                DbpString(_RED_("Restore failed."));
                current_state = STATE_ERROR;
            }
        } else {
            // Tag found but not in collection, remain busy to scan again
            current_state = STATE_BUSY;
        }
    } else {
        // No tag found, remain busy to scan again
        current_state = STATE_BUSY;
    }
}

/**
 * @brief Display module information
 */
void ModInfo(void) {
    DbpString("  HF ST25TB Store/Restore");
    Dbprintf("  Data stored/restored from: %s", HF_ST25TB_MULTI_SR_FILE);
    Dbprintf("  Supports up to %d tag slots.", MAX_SAVED_TAGS);
}

/**
 * @brief Main module function
 */
void RunMod(void) {
    StandAloneMode();
    Dbprintf(_YELLOW_("HF ST25TB Store/Restore mode started"));
    iso14443b_setup();
    LED_D_OFF();
    FpgaDownloadAndGo(FPGA_BITSTREAM_HF); // Use HF bitstream for ISO14443B

    // Initialize collection
    for (int i = 0; i < MAX_SAVED_TAGS; i++) {
        g_stored_tags[i].data_valid = false;
    }
    g_valid_tag_count = 0;

    // Mount filesystem and load previous tags if available
    rdv40_spiffs_lazy_mount();
    if (load_tags_from_flash(g_stored_tags)) {
        DbpString("Loaded previous tag collection from flash.");
        // Count valid entries loaded
        for (int i = 0; i < MAX_SAVED_TAGS; i++) {
            if (g_stored_tags[i].data_valid)
                g_valid_tag_count++;
        }
        g_current_mode = MODE_RESTORE; // Default to restore if data exists
    } else {
        DbpString("No previous tag data found in flash or error loading.");
        g_current_mode = MODE_LEARN; // Default to store if no data
    }

    bool mode_display_update = true; // Force initial display
    current_state = STATE_BUSY;      // Reset state at the beginning

    // Main application loop
    for (;;) {
        WDT_HIT();

        // Exit condition: USB command received
        if (data_available()) {
            DbpString("USB data detected, exiting standalone mode.");
            break;
        }

        // --- Button Handling ---
        int button_status = BUTTON_HELD(1000); // Check for 1 second hold

        if (button_status == BUTTON_HOLD) {
            DbpString("Button held, exiting standalone mode.");
            break;
        } else if (button_status == BUTTON_SINGLE_CLICK) {
            // Toggle between modes
            g_current_mode = (g_current_mode == MODE_LEARN) ? MODE_RESTORE : MODE_LEARN;
            current_state = STATE_BUSY; // Reset state when changing mode
            mode_display_update = true;
            SpinDelay(100); // Debounce/allow user to see mode change
        }

        // --- Update Display (only if mode changed) ---
        if (mode_display_update) {
            if (g_current_mode == MODE_LEARN) {
                Dbprintf("Mode: " _YELLOW_("Learn") ". (Cnt: %d/%d)",
                         g_valid_tag_count, MAX_SAVED_TAGS);
            } else {
                Dbprintf("Mode: " _BLUE_("Restore") ". (Cnt: %d/%d)",
                         g_valid_tag_count, MAX_SAVED_TAGS);
            }
            mode_display_update = false;
        }
        update_leds_mode(g_current_mode);

        // Process according to current state
        if (current_state == STATE_BUSY) {
            // Run appropriate function based on mode
            if (g_current_mode == MODE_LEARN) {
                run_learn_function();
            } else { // MODE_RESTORE
                run_restore_function();
            }
        } else if (current_state == STATE_DONE) {
            indicate_success();
        } else {
            indicate_failure();
        }

        // Loop delay
        SpinDelay(100);
    }

    // Clean up before exiting
    LED_D_ON(); // Indicate potentially saving state on exit
    rdv40_spiffs_lazy_unmount();
    LED_D_OFF();

    switch_off(); // Turn off RF field
    LEDsoff();
    DbpString("Exiting " _YELLOW_("HF ST25TB Store/Restore") " mode.");
}
