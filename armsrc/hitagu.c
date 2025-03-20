//-----------------------------------------------------------------------------
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
// Low frequency HITAG µ (micro) functions

#include "hitagu.h"
#include "hitag_common.h"

#include "BigBuf.h"
#include "appmain.h"  // tearoff_hook()
#include "cmd.h"
#include "commonutil.h"
#include "crc16.h"
#include "dbprint.h"
#include "fpgaloader.h"
#include "hitag2/hitag2_crypto.h"
#include "lfadc.h"
#include "protocols.h"
#include "proxmark3_arm.h"
#include "string.h"
#include "ticks.h"
#include "util.h"

// Hitag µ specific definitions
#define HTU_SOF_BITS 4     // Start of frame bits is always 3 for Hitag µ (110) plus 1 bit error flag

MOD M = MC4K;  // Modulation type

// Structure to hold the state of the Hitag µ tag
static struct hitagU_tag tag = {
    .pstate = HT_READY,                    // Initial state is ready
    .max_page = HITAGU_MAX_PAGE_STANDARD,  // Default to standard version
    .icr = 0,                              // Default ICR value
};

// Macros for managing authentication state
#define IS_AUTHENTICATED() (tag.pstate == HT_AUTHENTICATE)
#define SET_AUTHENTICATED() (tag.pstate = HT_AUTHENTICATE)
#define RESET_AUTHENTICATION() (tag.pstate = HT_READY)

/*
 * Update the maximum page number based on the tag's ICR (IC Revision)
 */
static void update_tag_max_page_by_icr(void) {
    // Set max_page based on ICR value
    switch (tag.icr) {
        case HITAGU_ICR_STANDARD:
            tag.max_page = HITAGU_MAX_PAGE_STANDARD;
            DBG Dbprintf("Detected standard Hitag µ (ICR=0x%02X), max page: 0x%02X", tag.icr, tag.max_page);
            break;
        case HITAGU_ICR_ADVANCED:
            tag.max_page = HITAGU_MAX_PAGE_ADVANCED;
            DBG Dbprintf("Detected Hitag µ advanced (ICR=0x%02X), max page: 0x%02X", tag.icr, tag.max_page);
            break;
        case HITAGU_ICR_ADVANCED_PLUS:
            tag.max_page = HITAGU_MAX_PAGE_ADVANCED_PLUS;
            DBG Dbprintf("Detected Hitag µ advanced+ (ICR=0x%02X), max page: 0x%02X", tag.icr, tag.max_page);
            break;
        case HITAGU_ICR_8265:
            tag.max_page = HITAGU_MAX_PAGE_8265;
            DBG Dbprintf("Detected Hitag µ 8265 (ICR=0x%02X), max page: 0x%02X", tag.icr, tag.max_page);
            break;
        default:
            // Unknown ICR, use standard size as fallback
            tag.max_page = HITAGU_MAX_PAGE_STANDARD;
            DBG Dbprintf("Unknown Hitag µ ICR: 0x%02X, defaulting to max page: 0x%02X", tag.icr, tag.max_page);
            break;
    }
}

/*
 * Update the maximum page number based on the tag's memory configuration
 * This function checks both ICR and additional pattern-based detection
 */
static void update_tag_max_page(void) {
    // First try to determine max_page from ICR
    update_tag_max_page_by_icr();

    // Additional tag type detection can be added here
}

/*
 * Handles all commands from a reader for Hitag µ
 * Processes flags and commands, generates appropriate responses
 */
static void htu_handle_reader_command(uint8_t *rx, const size_t rxlen, uint8_t *tx, size_t *txlen) {
    // Initialize response
    *txlen = 0;

    if (rxlen < 5) {
        return;  // Command too short
    }

    // Extract flags (5 bits) and command (6 bits if present)
    uint8_t flags = (rx[0] >> 3) & 0x1F;
    uint8_t command = 0;

    if (rxlen >= 11) {
        // Extract 6-bit command if present
        command = ((rx[0] & 0x07) << 3) | ((rx[1] >> 5) & 0x07);
    }

    // Check flags
    bool inv_flag = (flags & HITAGU_FLAG_INV);
    bool crct_flag = (flags & HITAGU_FLAG_CRCT);

    // Handle based on flags and command
    if (inv_flag) {
        // Inventory mode - respond with UID (48 bits)
        *txlen = concatbits(tx, *txlen, tag.uid, 0, HITAGU_UID_SIZE * 8, true);
    } else if (command == HITAGU_CMD_LOGIN) {
        // Login command
        if (rxlen >= 43) {  // 5+6+32 bits = 43 bits minimum
            // Extract password - 32 bits after command
            uint32_t password = 0;
            for (int i = 0; i < 4; i++) {
                int startBit = 11 + i * 8;  // 5+6 bits of command + i*8
                uint8_t b = 0;

                for (int j = 0; j < 8; j++) {
                    int bitPos = startBit + j;
                    int pos = bitPos / 8;
                    int shift = 7 - (bitPos % 8);
                    b |= ((rx[pos] >> shift) & 0x01) << (7 - j);
                }
                password |= (b << (24 - i * 8));
            }

            // Check password
            if (password == ((tag.password[0] << 24) | (tag.password[1] << 16) | (tag.password[2] << 8) | tag.password[3])) {
                // Set authentication state
                SET_AUTHENTICATED();

                // Send success response
                uint8_t resp_byte = 0x01;  // Success code
                *txlen = concatbits(tx, *txlen, &resp_byte, 0, 8, true);
            } else {
                // Authentication failed
                RESET_AUTHENTICATION();

                // Send failure response
                uint8_t resp_byte = 0x00;  // Failure code
                *txlen = concatbits(tx, *txlen, &resp_byte, 0, 8, true);
            }
        }
    } else if (command == HITAGU_CMD_SELECT) {
        // Select command
        if (rxlen >= 59) {  // 5+6+48 bits = 59 bits minimum (48-bit UID)
            // Extract UID to select - next 48 bits
            uint8_t sel_uid[6] = {0};
            for (int i = 0; i < 6; i++) {
                int startBit = 11 + i * 8;  // 5+6 bits of command + i*8
                uint8_t b = 0;

                for (int j = 0; j < 8; j++) {
                    int bitPos = startBit + j;
                    int pos = bitPos / 8;
                    int shift = 7 - (bitPos % 8);
                    b |= ((rx[pos] >> shift) & 0x01) << (7 - j);
                }
                sel_uid[i] = b;
            }

            // Check if UID matches
            if (memcmp(sel_uid, tag.uid, 6) == 0) {
                // Selected - send response with select data
                uint8_t resp_data[4] = {0xCA, 0x24, 0x00, 0x00};  // Standard select response
                *txlen = concatbits(tx, *txlen, resp_data, 0, 32, true);
            } else {
                // UID mismatch - no response
                *txlen = 0;
            }
        }
    } else if (command == HITAGU_CMD_READ_MULTIPLE_BLOCK) {
        // Read command
        if (rxlen >= 19) {  // 5+6+8 bits = 19 bits minimum
            // Extract page address - 8 bits after command
            uint8_t page = 0;
            for (int i = 0; i < 8; i++) {
                int bitPos = 11 + i;  // 5+6 bits of command + i
                int pos = bitPos / 8;
                int shift = 7 - (bitPos % 8);
                page |= ((rx[pos] >> shift) & 0x01) << (7 - i);
            }

            // Extract number of blocks to read if ADR flag is set
            uint8_t read_len = 1;  // Default to 1 page
            if ((flags & HITAGU_FLAG_ADR) && rxlen >= 27) {
                for (int i = 0; i < 8; i++) {
                    int bitPos = 19 + i;
                    int pos = bitPos / 8;
                    int shift = 7 - (bitPos % 8);
                    if (pos < (rxlen + 7) / 8) {
                        read_len |= ((rx[pos] >> shift) & 0x01) << (7 - i);
                    }
                }
            }

            // Security check: does this page require authentication?
            bool needs_auth = false;
            // Check if page is password-protected (e.g., config or password page)
            if (page == HITAGU_PASSWORD_PADR) {
                needs_auth = true;
            }

            // Check authentication for protected pages
            if (needs_auth && !IS_AUTHENTICATED()) {
                // Not authenticated, cannot read protected pages
                DBG Dbprintf("Page %d requires authentication", page);

                // Mark as unauthorized access
                *txlen = 0;  // No response
            } else {
                // Map page address (some pages may be aliased)
                uint8_t real_page = page;
                if (page >= 64 && tag.max_page <= 64) {
                    real_page = page & 0x3F;  // Pages above 64 map to 0-63
                }

                // Read requested number of pages
                for (int i = 0; i < read_len && i < 16; i++) {  // Limit to 16 pages max
                    uint8_t curr_page = (real_page + i) % tag.max_page;

                    // Special pages
                    if (curr_page == HITAGU_CONFIG_PADR) {
                        // Config page
                        *txlen = concatbits(tx, *txlen, (uint8_t *)&tag.config, 0, 32, true);
                    } else if (curr_page == HITAGU_PASSWORD_PADR) {
                        // Password page - only return if authenticated
                        if (IS_AUTHENTICATED()) {
                            *txlen = concatbits(tx, *txlen, tag.password, 0, 32, true);
                        } else {
                            // Return zeros if not authenticated
                            uint8_t zeros[4] = {0};
                            *txlen = concatbits(tx, *txlen, zeros, 0, 32, true);
                        }
                    } else {
                        // Regular page
                        *txlen = concatbits(tx, *txlen, tag.data.pages[curr_page], 0, 32, true);
                    }
                }
            }
        }
    } else if (command == HITAGU_CMD_WRITE_SINGLE_BLOCK) {
        // Write command
        if (rxlen >= 51) {  // 5+6+8+32 bits = 51 bits minimum
            // Check if authenticated
            if (!IS_AUTHENTICATED()) {
                DBG Dbprintf("WRITE failed: not authenticated");
                *txlen = 0;  // No response
            } else {
                // Extract page address - 8 bits after command
                uint8_t page = 0;
                for (int i = 0; i < 8; i++) {
                    int bitPos = 11 + i;  // 5+6 bits of command + i
                    int pos = bitPos / 8;
                    int shift = 7 - (bitPos % 8);
                    page |= ((rx[pos] >> shift) & 0x01) << (7 - i);
                }

                // Extract data - 32 bits after page address
                uint8_t data[4] = {0};
                for (int i = 0; i < 4; i++) {
                    for (int j = 0; j < 8; j++) {
                        int bitPos = 19 + i * 8 + j;
                        int pos = bitPos / 8;
                        int shift = 7 - (bitPos % 8);
                        if (pos < (rxlen + 7) / 8) {
                            data[i] |= ((rx[pos] >> shift) & 0x01) << (7 - j);
                        }
                    }
                }

                // Map page address
                uint8_t real_page = page;
                if (page >= 64 && tag.max_page <= 64) {
                    real_page = page & 0x3F;  // Pages above 64 map to 0-63
                }

                // Special pages
                if (real_page == HITAGU_CONFIG_PADR) {
                    // Write config
                    memcpy(&tag.config, data, 4);
                    DBG Dbprintf("WRITE CONFIG: %02X %02X %02X %02X", data[0], data[1], data[2], data[3]);
                } else if (real_page == HITAGU_PASSWORD_PADR) {
                    // Write password
                    memcpy(tag.password, data, 4);
                    DBG Dbprintf("WRITE PASSWORD: %02X %02X %02X %02X", data[0], data[1], data[2], data[3]);
                } else if (real_page < tag.max_page) {
                    // Regular page
                    memcpy(tag.data.pages[real_page], data, 4);
                    DBG Dbprintf("WRITE PAGE %02X: %02X %02X %02X %02X", real_page, data[0], data[1], data[2], data[3]);
                }

                // Send success acknowledgment
                uint8_t ack = 0x01;  // Success acknowledgment
                *txlen = concatbits(tx, *txlen, &ack, 0, 8, true);
            }
        }
    } else if (command == HITAGU_CMD_SYSINFO) {
        // System info command
        // Prepare system info response with ICR field
        uint8_t info[8] = {0};

        // First byte: Error flag (0) + 7 reserved bits
        info[0] = 0x00;

        // Additional bytes: System Memory Block Data
        // MSN (Manufacturer Serial Number) - example values
        info[1] = 0x12;
        info[2] = 0x34;

        // MFC (Manufacturer Code) - example value
        info[3] = 0x04;  // NXP

        // ICR (IC Revision)
        info[4] = tag.icr;

        // Reserved bytes
        info[5] = 0x00;
        info[6] = 0x00;
        info[7] = 0x00;

        // Add the system info data to the response
        *txlen = concatbits(tx, *txlen, info, 0, 64, true);
    } else if (flags == HITAGU_CMD_STAY_QUIET) {
        // Quiet command - no response needed
        RESET_AUTHENTICATION();
        *txlen = 0;
    } else {
        // Unknown command
        DBG Dbprintf("Unknown command or flags: flags=%02X, cmd=%02X", flags, command);
        *txlen = 0;  // No response
    }

    // Add CRC if requested and there is response data
    if (crct_flag && *txlen > 0) {
        // Calculate CRC-16/XMODEM directly from tx
        uint16_t crc = Crc16(tx, *txlen, 0, CRC16_POLY_CCITT, false, true);

        // Append CRC-16 (16 bits)
        *txlen = concatbits(tx, *txlen, (uint8_t *)&crc, 0, 16, true);
    }
}

/*
 * Simulates a Hitag µ Tag with the given data
 */
void htu_simulate(bool tag_mem_supplied, int8_t threshold, const uint8_t *data, bool ledcontrol) {

    uint8_t rx[HITAG_FRAME_LEN] = {0};
    size_t rxlen = 0;
    uint8_t tx[HITAG_FRAME_LEN];
    size_t txlen = 0;

    // Free any allocated BigBuf memory
    BigBuf_free();
    BigBuf_Clear_ext(false);

    DbpString("Starting Hitag µ simulation");

    // Reset tag state
    memset(&tag, 0, sizeof(tag));
    tag.max_page = 64;  // Default maximum page
    RESET_AUTHENTICATION();

    // Read tag data into memory if supplied
    if (tag_mem_supplied) {
        DbpString("Loading Hitag µ memory...");
        // First 6 bytes are the UID (48 bits)
        memcpy(tag.uid, data, 6);
        // Rest is page data
        memcpy(tag.data.pages, data + 6, sizeof(tag.data.pages));
    }

    // Update max_page based on configuration
    update_tag_max_page();

    // Debug output of tag data
    DBG Dbprintf("UID: %02X%02X%02X%02X%02X%02X", tag.uid[0], tag.uid[1], tag.uid[2], tag.uid[3], tag.uid[4], tag.uid[5]);

    for (int i = 0; i <= tag.max_page; i++) {
        DBG Dbprintf("Page[%2d]: %02X %02X %02X %02X", i, tag.data.pages[i][0], tag.data.pages[i][1],
                     tag.data.pages[i][2], tag.data.pages[i][3]);
    }

    hitag_setup_fpga(0, threshold, ledcontrol);

    int overflow = 0;

    // Simulation main loop
    while ((BUTTON_PRESS() == false) && (data_available() == false)) {
        uint32_t start_time = 0;

        WDT_HIT();

        // Receive commands from the reader
        hitag_tag_receive_frame(rx, sizeof(rx), &rxlen, &start_time, ledcontrol, &overflow);

        // Check if frame was captured and store it
        if (rxlen > 0) {
            LogTraceBits(rx, rxlen, start_time, TIMESTAMP, true);

            // Disable timer 1 with external trigger to avoid triggers during our own modulation
            AT91C_BASE_TC1->TC_CCR = AT91C_TC_CLKDIS;

            // Prepare tag response (tx)
            memset(tx, 0x00, sizeof(tx));
            txlen = 0;

            // Process received reader command
            htu_handle_reader_command(rx, rxlen, tx, &txlen);

            // Wait for HITAG_T_WAIT_RESP carrier periods after the last reader bit,
            // not that since the clock counts since the rising edge, but T_Wait1 is
            // with respect to the falling edge, we need to wait actually (T_Wait1 - T_Low)
            // periods. The gap time T_Low varies (4..10). All timer values are in
            // terms of T0 units
            while (AT91C_BASE_TC0->TC_CV < T0 * (HITAG_T_WAIT_RESP - HITAG_T_LOW)) {
            };

            // Send and store the tag answer (if there is any)
            if (txlen > 0) {
                // Transmit the tag frame
                start_time = TIMESTAMP;
                hitag_tag_send_frame(tx, txlen, HTU_SOF_BITS, MC4K, ledcontrol);
                LogTraceBits(tx, txlen, start_time, TIMESTAMP, false);
            }

            // Enable and reset external trigger in timer for capturing future frames
            AT91C_BASE_TC1->TC_CCR = AT91C_TC_CLKEN | AT91C_TC_SWTRG;

            // Reset the received frame and response timing info
            memset(rx, 0x00, sizeof(rx));
        }

        // Reset the frame length
        rxlen = 0;
        // Save the timer overflow, will be 0 when frame was received
        overflow += (AT91C_BASE_TC1->TC_CV / T0);
        // Reset the timer to restart while-loop that receives frames
        AT91C_BASE_TC1->TC_CCR = AT91C_TC_SWTRG;
    }

    hitag_cleanup(ledcontrol);
    // Release allocated memory from BigBuf
    BigBuf_free();

    DbpString("Simulation stopped");
}

/*
 * Send command to reader and receive answer from tag
 */
static int htu_reader_send_receive(uint8_t *tx, size_t txlen, uint8_t *rx, size_t sizeofrx, size_t *rxlen,
                                   uint32_t t_wait, bool ledcontrol, uint8_t modulation, uint8_t sof_bits) {
    // Reset the received frame
    memset(rx, 0x00, sizeofrx);

    // Disable timer 1 with external trigger to avoid triggers during our own modulation
    AT91C_BASE_TC1->TC_CCR = AT91C_TC_CLKDIS;

    DBG Dbprintf("tx %d bits:", txlen);
    DBG Dbhexdump((txlen + 7) / 8, tx, false);

    // Wait until we can send the command
    while (AT91C_BASE_TC0->TC_CV < T0 * t_wait) {
    };

    // Set up tracing
    uint32_t start_time = TIMESTAMP;

    // Send the command - Hitag µ always requires SOF
    hitag_reader_send_frame(tx, txlen, ledcontrol, true);

    // if (enable_page_tearoff && tearoff_hook() == PM3_ETEAROFF) {
    //     return PM3_ETEAROFF;
    // }

    LogTraceBits(tx, txlen, start_time, TIMESTAMP, true);

    // Enable and reset external trigger in timer for capturing future frames
    AT91C_BASE_TC1->TC_CCR = AT91C_TC_CLKEN | AT91C_TC_SWTRG;

    // Capture response - SOF is automatically stripped by hitag_reader_receive_frame
    hitag_reader_receive_frame(rx, sizeofrx, rxlen, &start_time, ledcontrol, modulation, sof_bits);

    LogTraceBits(rx, *rxlen, start_time, TIMESTAMP, false);
    DBG Dbprintf("rx %d bits:", *rxlen);
    DBG Dbhexdump((*rxlen + 7) / 8, rx, false);

    // TODO: check Error flag

    return PM3_SUCCESS;
}

/*
 * Selects a tag using the READ UID, GET SYSTEM INFORMATION, and LOGIN commands
 */
static int htu_select_tag(const lf_hitag_data_t *payload, uint8_t *tx, size_t sizeoftx, uint8_t *rx, size_t sizeofrx,
                          int t_wait, bool ledcontrol) {
    // Initialize response
    size_t txlen = 0;
    size_t rxlen = 0;

    // Setup FPGA and initialize
    hitag_setup_fpga(FPGA_LF_EDGE_DETECT_READER_FIELD, 127, ledcontrol);

    // Prepare common flags and command variables
    uint8_t flags = HITAGU_FLAG_CRCT;  // Set appropriate flags for all commands
    uint8_t command;
    // uint8_t parameter;

    // 1. Send READ UID command
    command = HITAGU_CMD_READ_UID;
    txlen = concatbits(tx, txlen, &flags, 0, 5, true);
    txlen = concatbits(tx, txlen, &command, 0, 6, true);

    // Append CRC-16 (16 bits)
    uint16_t crc = Crc16(tx, txlen, 0, CRC16_POLY_CCITT, false, true);
    txlen = concatbits(tx, txlen, (uint8_t *)&crc, 0, 16, true);

    // lf cmdread -d 64 -z 96 -o 160 -e W2400 -e S224 -e E336 -s 4096 -c W0S00100010000

    // Send the READ UID command and receive the response
    htu_reader_send_receive(tx, txlen, rx, sizeofrx, &rxlen, t_wait, ledcontrol, MC4K, HTU_SOF_BITS);

    // Check if the response is valid
    if (rxlen < 1 + 48 + 16 || Crc16(rx, rxlen, 0, CRC16_POLY_CCITT, false, false) != 0) {
        DBG Dbprintf("Read UID command failed! %i", rxlen);
        return -2;  // Read UID failed
    }

    // Process the UID from the response
    concatbits(tag.uid, 0, rx, 1, 48, false);

    // 2. Send GET SYSTEM INFORMATION command
    command = HITAGU_CMD_SYSINFO;
    txlen = 0;  // Reset txlen for the new command
    txlen = concatbits(tx, txlen, &flags, 0, 5, true);
    txlen = concatbits(tx, txlen, &command, 0, 6, true);

    // Append CRC-16 (16 bits)
    crc = Crc16(tx, txlen, 0, CRC16_POLY_CCITT, false, true);
    txlen = concatbits(tx, txlen, (uint8_t *)&crc, 0, 16, true);

    // Send the GET SYSTEM INFORMATION command and receive the response
    htu_reader_send_receive(tx, txlen, rx, sizeofrx, &rxlen, HITAG_T_WAIT_SC, ledcontrol, MC4K, HTU_SOF_BITS);

    concatbits(&tag.icr, 0, rx, 9, 8, false);

    // Check if the response is valid
    if (rxlen < 1 + 16 + 16 || Crc16(rx, rxlen, 0, CRC16_POLY_CCITT, false, false) != 0) {
        // 8265 bug? sometile lost Data field first bit
        DBG Dbprintf("Get System Information command failed! %i", rxlen);
        return -3;  // Get System Information failed
    }

    // 3. Read config block
    command = HITAGU_CMD_READ_MULTIPLE_BLOCK;
    txlen = 0;  // Reset txlen for the new command
    txlen = concatbits(tx, txlen, &flags, 0, 5, true);
    txlen = concatbits(tx, txlen, &command, 0, 6, true);

    // Add block address
    txlen = concatbits(tx, txlen, (uint8_t *)&"\xFF", 0, 8, true);

    // Add number of blocks, 0 means 1 block
    txlen = concatbits(tx, txlen, (uint8_t *)&"\x00", 0, 8, true);

    // Append CRC-16 (16 bits)
    crc = Crc16(tx, txlen, 0, CRC16_POLY_CCITT, false, true);
    txlen = concatbits(tx, txlen, (uint8_t *)&crc, 0, 16, true);

    // Send read command and receive response
    htu_reader_send_receive(tx, txlen, rx, sizeofrx, &rxlen, HITAG_T_WAIT_SC, ledcontrol, MC4K, HTU_SOF_BITS);

    // Check if the response is valid
    if (rxlen < 1 + 32 + 16 || Crc16(rx, rxlen, 0, CRC16_POLY_CCITT, false, false) != 0) {
        DBG Dbprintf("Read config block command failed! %i", rxlen);
        return -3;  // Read config block failed
    }

    // Process the config block from the response
    concatbits(tag.config.asBytes, 0, rx, 1, 32, false);
    reverse_arraybytes(tag.config.asBytes, HITAGU_BLOCK_SIZE);

    // 4. Send LOGIN command if necessary
    if (payload && (payload->cmd == HTUF_82xx || payload->cmd == HTUF_PASSWORD)) {
        command = HITAGU_CMD_LOGIN;  // Set command for login
        txlen = 0;                   // Reset txlen for the new command
        txlen = concatbits(tx, txlen, &flags, 0, 5, true);
        txlen = concatbits(tx, txlen, &command, 0, 6, true);

        txlen = concatbits(tx, txlen, payload->pwd, 0, HITAG_PASSWORD_SIZE * 8, false);

        // Append CRC-16 (16 bits)
        crc = Crc16(tx, txlen, 0, CRC16_POLY_CCITT, false, true);
        txlen = concatbits(tx, txlen, (uint8_t *)&crc, 0, 16, true);

        // Send the LOGIN command and receive the response
        htu_reader_send_receive(tx, txlen, rx, sizeofrx, &rxlen, HITAG_T_WAIT_SC, ledcontrol, MC4K, HTU_SOF_BITS);

        // Check if login succeeded
        if (rxlen < 1 + 16 || Crc16(rx, rxlen, 0, CRC16_POLY_CCITT, false, false) != 0) {
            DBG Dbprintf("Login command failed! %i", rxlen);
            return -4;  // Login failed
        } else {
            DBG DbpString("Login successful");
        }

        // flags |= HITAGU_FLAG_ADR;
        // command = HITAGU_CMD_LOGIN;  // Set command for login
        // txlen = 0;                   // Reset txlen for the new command
        // txlen = concatbits(tx, txlen, &flags, 0, 5, true);
        // txlen = concatbits(tx, txlen, &command, 0, 6, true);

        // txlen = concatbits(tx, txlen, payload->uid, 0, HITAGU_UID_SIZE * 8, false);
        // txlen = concatbits(tx, txlen, payload->pwd, 0, HITAG_PASSWORD_SIZE * 8, false);

        // // Append CRC-16 (16 bits)
        // crc = Crc16(tx, txlen, 0, CRC16_POLY_CCITT, false, true);
        // txlen = concatbits(tx, txlen, (uint8_t *)&crc, 0, 16, true);

        // // Send the LOGIN command and receive the response
        // htu_reader_send_receive(tx, txlen, rx, sizeofrx, &rxlen, HITAG_T_WAIT_SC, ledcontrol, MC4K, HTU_SOF_BITS);

        // // Check if login succeeded
        // if (rxlen < 1 + 16 || Crc16(rx, rxlen, 0, CRC16_POLY_CCITT, false, false) != 0) {
        //     DBG Dbprintf("Login command failed! %i", rxlen);
        //     return -3;  // Login failed
        // } else {
        //     DbpString("Login successful");
        // }
    }

    // If all commands are successful, update the tag's state
    update_tag_max_page();  // Update max_page based on the new configuration

    return 0;  // Selection successful
}

/*
 * Reads the UID of a Hitag µ tag using the INVENTORY command
 */
int htu_read_uid(uint64_t *uid, bool ledcontrol, bool send_answer) {
    // Initialize response
    uint8_t rx[HITAG_FRAME_LEN] = {0x00};
    uint8_t tx[HITAG_FRAME_LEN] = {0x00};
    int status = PM3_SUCCESS;

    // Use htu_select_tag to select the card and retrieve UID
    int reason = htu_select_tag(NULL, tx, ARRAYLEN(tx), rx, ARRAYLEN(rx), HITAG_T_WAIT_FIRST, ledcontrol);
    if (reason != 0) {
        DBG DbpString("Error: htu_read_uid Failed to select tag");
        status = PM3_ERFTRANS;
        goto exit;
    }

    DBG Dbprintf("HitagU UID: %02X%02X%02X%02X%02X%02X", tag.uid[0], tag.uid[1], tag.uid[2], tag.uid[3], tag.uid[4], tag.uid[5]);

    if (uid) {
        *uid = MemBeToUint6byte(tag.uid);
    }

exit:
    hitag_cleanup(ledcontrol);

    if (send_answer) {
        // Send UID
        reply_reason(CMD_LF_HITAGU_UID, status, reason, tag.uid, sizeof(tag.uid));
    }

    // Reset authentication state
    RESET_AUTHENTICATION();

    return status;
}

/*
 * Reads a Hitag µ tag
 */
void htu_read(const lf_hitag_data_t *payload, bool ledcontrol) {
    size_t rxlen = 0;
    uint8_t rx[HITAG_FRAME_LEN] = {0x00};
    size_t txlen = 0;
    uint8_t tx[HITAG_FRAME_LEN] = {0x00};
    int status = PM3_SUCCESS;

    // DBG {
    //     DbpString("htu_read");
    //     Dbprintf("payload->page: %d", payload->page);
    //     Dbprintf("payload->page_count: %d", payload->page_count);
    //     Dbprintf("payload->cmd: %d", payload->cmd);
    //     Dbprintf("payload->uid: %02X%02X%02X%02X%02X%02X", payload->uid[0], payload->uid[1], payload->uid[2],
    //              payload->uid[3], payload->uid[4], payload->uid[5]);
    //     Dbprintf("payload->key: %02X%02X%02X%02X%02X%02X", payload->key[0], payload->key[1], payload->key[2],
    //              payload->key[3], payload->key[4], payload->key[5]);
    //     Dbprintf("payload->pwd: %02X%02X%02X%02X", payload->pwd[0], payload->pwd[1], payload->pwd[2], payload->pwd[3]);
    // }

    // Use htu_select_tag to select the card and retrieve UID
    int reason = htu_select_tag(payload, tx, ARRAYLEN(tx), rx, ARRAYLEN(rx), HITAG_T_WAIT_FIRST, ledcontrol);
    if (reason != 0) {
        DbpString("Error: htu_read Failed to select tag");
        status = PM3_ERFTRANS;
        goto exit;
    }

    lf_htu_read_response_t card = {
        .icr = tag.icr,
    };
    memcpy(card.uid, tag.uid, HITAGU_UID_SIZE);
    memcpy(card.config_page.asBytes, tag.config.asBytes, HITAGU_BLOCK_SIZE);

    uint8_t page_count_index = payload->page_count - 1;

    if (payload->page_count == 0) {
        page_count_index = tag.max_page - payload->page - 1;
    }

    // Step 2: Process the actual command
    // Add flags (5 bits)
    uint8_t flags = HITAGU_FLAG_CRCT;
    txlen = concatbits(tx, txlen, &flags, 0, 5, true);

    // Read command format: <flags> <command> [UID] <block address> <number of blocks> [CRC-16]

    // Add command (6 bits)
    uint8_t command = HITAGU_CMD_READ_MULTIPLE_BLOCK;
    txlen = concatbits(tx, txlen, &command, 0, 6, true);

    // The 8265 chip has known issues when reading multiple blocks:
    // - page_count = 1: Works correctly
    // - page_count >= 2: Data field is left shifted by 1 bit
    // - page_count = 2 or page+page_count exceeds valid page: Data field has an extra '1' bit
    // - page_count = 3,4: Data field last bit is always '1'
    // - page_count = 5: CRC is not appended
    // - page_count >= 6: May cause next command to have no response
    // Workaround: Read one block at a time
    if (payload->mode == 0 /**for debug */
            && (payload->cmd == HTUF_82xx || tag.icr == HITAGU_ICR_8265 || !memcmp(tag.uid, "\x00\x00\x00\x00\x00\x00", 6))) {

        uint8_t page_addr;
        for (int i = 0; i <= page_count_index; i++) {
            page_addr = payload->page + i;

            txlen = 5 + 6;  // restore txlen for the new command
            txlen = concatbits(tx, txlen, &page_addr, 0, 8, true);

            // Add number of blocks, 0 means 1 block
            txlen = concatbits(tx, txlen, (uint8_t *)&"\x00", 0, 8, true);

            // Append CRC-16 (16 bits)
            uint16_t crc = Crc16(tx, txlen, 0, CRC16_POLY_CCITT, false, true);
            txlen = concatbits(tx, txlen, (uint8_t *)&crc, 0, 16, true);

            // Send read command and receive response
            htu_reader_send_receive(tx, txlen, rx, ARRAYLEN(rx), &rxlen, HITAG_T_WAIT_SC, ledcontrol, MC4K, HTU_SOF_BITS);

            if (flags & HITAGU_FLAG_CRCT && Crc16(rx, rxlen, 0, CRC16_POLY_CCITT, false, false) != 0) {
                DBG Dbprintf("Error: response CRC invalid");
                card.pages_reason[i] = -6;
                continue;
            }

            // Check response
            if (rxlen < 1 + HITAGU_BLOCK_SIZE * 8 + (flags & HITAGU_FLAG_CRCT ? 16 : 0)) {
                DbpString("Error: invalid response received after read command");
                card.pages_reason[i] = -7;
            } else {
                DBG Dbprintf("Read successful, response: %d bits", rxlen);
                // todo: For certain pages, update our cached data
                card.pages_reason[i] = 1;
                concatbits(card.pages[i], 0, rx, 1, HITAGU_BLOCK_SIZE * 8, false);
            }
        }
    } else {
        txlen = concatbits(tx, txlen, &payload->page, 0, 8, true);

        // Add number of blocks, 0 means 1 block
        txlen = concatbits(tx, txlen, &page_count_index, 0, 8, true);

        // Append CRC-16 (16 bits)
        uint16_t crc = Crc16(tx, txlen, 0, CRC16_POLY_CCITT, false, true);
        txlen = concatbits(tx, txlen, (uint8_t *)&crc, 0, 16, true);

        // Send read command and receive response
        htu_reader_send_receive(tx, txlen, rx, ARRAYLEN(rx), &rxlen, HITAG_T_WAIT_SC, ledcontrol, MC4K, HTU_SOF_BITS);

        if (flags & HITAGU_FLAG_CRCT && Crc16(rx, rxlen, 0, CRC16_POLY_CCITT, false, false) != 0) {
            DBG Dbprintf("Error: response CRC invalid");
            status = PM3_ERFTRANS;
            goto exit;
        }

        // Check response
        if (rxlen < 1 + HITAGU_BLOCK_SIZE * 8 + (flags & HITAGU_FLAG_CRCT ? 16 : 0)) {
            DbpString("Error: invalid response received after read command");
            status = PM3_ERFTRANS;
        } else {
            DBG Dbprintf("Read successful, response: %d bits", rxlen);
            // todo: For certain pages, update our cached data
            concatbits((uint8_t *)card.pages, 0, rx, 1, rxlen - 1 - 16, false);
            for (int i = 0; i < (rxlen - 1 - 16) / (HITAGU_BLOCK_SIZE * 8); i++) {
                card.pages_reason[i] = 1;
            }
        }
    }

exit:
    hitag_cleanup(ledcontrol);
    // Send status to client
    reply_reason(CMD_LF_HITAGU_READ, status, reason, (uint8_t *)&card, sizeof(card));
}

/*
 * Writes a page to a Hitag µ tag
 */
void htu_write_page(const lf_hitag_data_t *payload, bool ledcontrol) {
    size_t rxlen = 0;
    uint8_t rx[HITAG_FRAME_LEN] = {0x00};
    size_t txlen = 0;
    uint8_t tx[HITAG_FRAME_LEN] = {0x00};
    int status = PM3_SUCCESS;

    // DBG {
    //     DbpString("htu_write_page");
    //     Dbprintf("payload->page: %d", payload->page);
    //     Dbprintf("payload->data: %02X%02X%02X%02X", payload->data[0], payload->data[1], payload->data[2], payload->data[3]);
    //     Dbprintf("payload->cmd: %d", payload->cmd);
    //     Dbprintf("payload->uid: %02X%02X%02X%02X%02X%02X", payload->uid[0], payload->uid[1], payload->uid[2], payload->uid[3], payload->uid[4], payload->uid[5]);
    //     Dbprintf("payload->key: %02X%02X%02X%02X%02X%02X", payload->key[0], payload->key[1], payload->key[2], payload->key[3], payload->key[4], payload->key[5]);
    //     Dbprintf("payload->pwd: %02X%02X%02X%02X", payload->pwd[0], payload->pwd[1], payload->pwd[2], payload->pwd[3]);
    //     Dbprintf("payload->mode: %d", payload->mode);
    // }

    int reason = htu_select_tag(payload, tx, ARRAYLEN(tx), rx, ARRAYLEN(rx), HITAG_T_WAIT_FIRST, ledcontrol);
    if (reason != 0) {
        status = PM3_ERFTRANS;
        goto exit;
    }

    // Step 2: Send write command
    uint8_t flags = HITAGU_FLAG_CRCT;

    // Add flags (5 bits) for write operation
    txlen = concatbits(tx, txlen, &flags, 0, 5, true);

    // Add write command (6 bits)
    uint8_t command = HITAGU_CMD_WRITE_SINGLE_BLOCK;
    txlen = concatbits(tx, txlen, &command, 0, 6, true);

    // Add page address (8 bits)
    txlen = concatbits(tx, txlen, &payload->page, 0, 8, true);

    // Add data to write (32 bits)
    txlen = concatbits(tx, txlen, payload->data, 0, 32, false);

    // Append CRC-16 (16 bits)
    uint16_t crc = Crc16(tx, txlen, 0, CRC16_POLY_CCITT, false, true);
    txlen = concatbits(tx, txlen, (uint8_t *)&crc, 0, 16, true);

    DBG Dbprintf("Writing to page 0x%02X", payload->page);

    // Send write command and receive response
    htu_reader_send_receive(tx, txlen, rx, ARRAYLEN(rx), &rxlen, HITAG_T_WAIT_SC, ledcontrol, MC4K, HTU_SOF_BITS);

    // Check response
    if (payload->cmd == HTUF_82xx && rxlen == 0) {
        // 8265 bug? no response on successful write command
        reason = 0;
        status = PM3_ENODATA;
    } else if (rxlen != 1 + 16) {
        DbpString("Error: htu_write_page No valid response received after write command");
        reason = -5;
        status = PM3_ERFTRANS;
    } else {
        DBG Dbprintf("Write successful, response: %d bits", rxlen);
    }

exit:
    hitag_cleanup(ledcontrol);
    reply_reason(CMD_LF_HITAGU_WRITE, status, reason, NULL, 0);
}
