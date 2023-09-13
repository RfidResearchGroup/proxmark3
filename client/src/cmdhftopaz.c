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
// High frequency Topaz (NFC Type 1) commands
//-----------------------------------------------------------------------------
#include "cmdhftopaz.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <inttypes.h>
#include "cliparser.h"
#include "cmdparser.h"    // command_t
#include "comms.h"
#include "cmdtrace.h"
#include "cmdhf14a.h"
#include "ui.h"
#include "crc16.h"
#include "protocols.h"
#include "nfc/ndef.h"
#include "fileutils.h"     // saveFile


#ifndef AddCrc14B
# define AddCrc14B(data, len) compute_crc(CRC_14443_B, (data), (len), (data)+(len), (data)+(len)+1)
#endif

static topaz_tag_t topaz_tag;

static void topaz_switch_on_field(void) {
    SendCommandMIX(CMD_HF_ISO14443A_READER, ISO14A_CONNECT | ISO14A_NO_SELECT | ISO14A_NO_DISCONNECT | ISO14A_TOPAZMODE | ISO14A_NO_RATS, 0, 0, NULL, 0);
}

static void topaz_switch_off_field(void) {
    SetISODEPState(ISODEP_INACTIVE);
    SendCommandMIX(CMD_HF_ISO14443A_READER, 0, 0, 0, NULL, 0);
}

// send a raw topaz command, returns the length of the response (0 in case of error)
static int topaz_send_cmd_raw(uint8_t *cmd, uint8_t len, uint8_t *response, uint16_t *response_len, bool verbose) {
    SendCommandMIX(CMD_HF_ISO14443A_READER, ISO14A_RAW | ISO14A_NO_DISCONNECT | ISO14A_TOPAZMODE | ISO14A_NO_RATS, len, 0, cmd, len);
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_ACK, &resp, 1500) == false) {
        if (verbose) PrintAndLogEx(WARNING, "timeout while waiting for reply.");
        return PM3_ETIMEOUT;
    }

    if (resp.oldarg[0] == *response_len) {
        *response_len = resp.oldarg[0];

        PrintAndLogEx(DEBUG, "%s", sprint_hex(resp.data.asBytes, *response_len));
        if (*response_len > 0) {
            memcpy(response, resp.data.asBytes, *response_len);
        }
    } else {
        if (verbose) PrintAndLogEx(WARNING, "Wrong response length (%d != %" PRIu64 ")", *response_len, resp.oldarg[0]);
        return PM3_ESOFT;
    }
    return PM3_SUCCESS;
}

// calculate CRC bytes and send topaz command, returns the length of the response (0 in case of error)
static int topaz_send_cmd(uint8_t *cmd, uint8_t len, uint8_t *response, uint16_t *response_len, bool verbose) {
    if (len > 1) {
        AddCrc14B(cmd, len - 2);
    }

    return topaz_send_cmd_raw(cmd, len, response, response_len, verbose);
}

// select a topaz tag. Send WUPA and RID.
static int topaz_select(uint8_t *atqa, uint8_t atqa_len, uint8_t *rid_response,  uint8_t rid_len, bool verbose) {
    // ToDo: implement anticollision

    uint16_t resp_len;
    uint8_t wupa_cmd[] = {TOPAZ_WUPA};
    uint8_t rid_cmd[] = {TOPAZ_RID, 0, 0, 0, 0, 0, 0, 0, 0};

    topaz_switch_on_field();

    resp_len = atqa_len;
    int status = topaz_send_cmd(wupa_cmd, sizeof(wupa_cmd), atqa, &resp_len, verbose);
    if (status == PM3_ETIMEOUT || status == PM3_ESOFT) {
        topaz_switch_off_field();
        return PM3_ESOFT; // WUPA failed
    }

    resp_len = rid_len;
    status = topaz_send_cmd(rid_cmd, sizeof(rid_cmd), rid_response, &resp_len, verbose);
    if (status == PM3_ETIMEOUT || status == PM3_ESOFT) {
        topaz_switch_off_field();
        return PM3_EWRONGANSWER; // RID failed
    }

    return PM3_SUCCESS;
}

// read all of the static memory of a selected Topaz tag.
static int topaz_rall(uint8_t *uid, uint8_t *response) {

    uint16_t resp_len = 124;
    uint8_t rall_cmd[] = {TOPAZ_RALL, 0, 0, 0, 0, 0, 0, 0, 0};
    memcpy(&rall_cmd[3], uid, 4);

    if (topaz_send_cmd(rall_cmd, sizeof(rall_cmd), response, &resp_len, true) == PM3_ETIMEOUT) {
        topaz_switch_off_field();
        return PM3_ESOFT; // RALL failed
    }

    return PM3_SUCCESS;
}

// read a block (8 Bytes) of a selected Topaz tag.
static int topaz_read_block(uint8_t blockno, uint8_t *block_data) {
    uint8_t atqa[2] = {0};
    uint8_t rid_response[8] = {0};
    int res = topaz_select(atqa, sizeof(atqa), rid_response, sizeof(rid_response), true);
    if (res != PM3_SUCCESS) {
        return res;
    }

    if (atqa[1] != 0x0c && atqa[0] != 0x00) {
        return res;
    }

    uint8_t *uid_echo = &rid_response[2];
    uint8_t rall_response[124] = {0};

    res = topaz_rall(uid_echo, rall_response);
    if (res == PM3_ESOFT) {
        return res;
    }

    uint8_t read8_cmd[] = {TOPAZ_READ8, blockno, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    memcpy(&read8_cmd[10], uid_echo, 4);

    uint16_t resp_len = 11;
    uint8_t response[11] = {0};

    if (topaz_send_cmd(read8_cmd, sizeof(read8_cmd), response, &resp_len, true) == PM3_ETIMEOUT) {
        topaz_switch_off_field();
        return PM3_ESOFT; // READ8 failed
    }
    memcpy(block_data, &response[1], 8);
    return PM3_SUCCESS;
}

// read a segment (16 blocks = 128 Bytes) of a selected Topaz tag. Works only for tags with dynamic memory.
static int topaz_read_segment(uint8_t segno, uint8_t *segment_data) {

    uint8_t atqa[2] = {0};
    uint8_t rid_response[8] = {0};
    int res = topaz_select(atqa, sizeof(atqa), rid_response, sizeof(rid_response), true);
    if (res != PM3_SUCCESS) {
        return res;
    }

    if (atqa[1] != 0x0c && atqa[0] != 0x00) {
        return res;
    }

    uint8_t *uid_echo = &rid_response[2];
    uint8_t rall_response[124] = {0};

    res = topaz_rall(uid_echo, rall_response);
    if (res == PM3_ESOFT) {
        return res;
    }

    uint16_t resp_len = 131;
    uint8_t rseg_cmd[] = {TOPAZ_RSEG, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    uint8_t rseg_response[131];

    rseg_cmd[1] = segno << 4;
    memcpy(&rseg_cmd[10], uid_echo, 4);

    if (topaz_send_cmd(rseg_cmd, sizeof(rseg_cmd), rseg_response, &resp_len, true) == PM3_ETIMEOUT) {
        topaz_switch_off_field();
        return PM3_ESOFT; // RSEG failed
    }
    memcpy(segment_data, &rseg_response[1], 128);
    return PM3_SUCCESS;
}

// write a block (8 Bytes) of a selected Topaz tag.
static int topaz_write_erase8_block(uint8_t blockno, uint8_t *block_data) {

    uint8_t atqa[2] = {0};
    uint8_t rid_response[8] = {0};
    int res = topaz_select(atqa, sizeof(atqa), rid_response, sizeof(rid_response), true);
    if (res != PM3_SUCCESS) {
        return res;
    }

    if (atqa[1] != 0x0c && atqa[0] != 0x00) {
        return res;
    }

    uint8_t *uid_echo = &rid_response[2];
    uint8_t rall_response[124] = {0};

    res = topaz_rall(uid_echo, rall_response);
    if (res == PM3_ESOFT) {
        return res;
    }

    uint8_t wr8_cmd[] = {TOPAZ_WRITE_E8, blockno, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    memcpy(wr8_cmd + 10, uid_echo, 4);
    memcpy(wr8_cmd + 2, block_data, 8);

    uint16_t resp_len = 11;
    uint8_t response[11] = {0};

    //

    if (topaz_send_cmd(wr8_cmd, sizeof(wr8_cmd), response, &resp_len, true) == PM3_ETIMEOUT) {
        topaz_switch_off_field();
        return PM3_ESOFT; // WriteErase 8bytes failed
    }

    if (resp_len != 11) {
        return PM3_EFAILED;
    }

    if (blockno != response[0]) {
        return PM3_EFAILED;
    }

    if (memcmp(block_data, response + 1, 8) == 0) {
        return PM3_SUCCESS;
    }
    return PM3_ESOFT;
}

// write a block (8 Bytes) of a selected Topaz tag.
static int topaz_write_nonerase8_block(uint8_t blockno, uint8_t *block_data) {

    uint8_t atqa[2] = {0};
    uint8_t rid_response[8] = {0};
    int res = topaz_select(atqa, sizeof(atqa), rid_response, sizeof(rid_response), true);
    if (res != PM3_SUCCESS) {
        return res;
    }

    if (atqa[1] != 0x0c && atqa[0] != 0x00) {
        return res;
    }

    uint8_t *uid_echo = &rid_response[2];
    uint8_t rall_response[124] = {0};

    res = topaz_rall(uid_echo, rall_response);
    if (res == PM3_ESOFT) {
        return res;
    }

    // ADD
    // 7 6 5 4 3 2 1 0
    //           b b b --- Byte  0 - 7
    //   B B B B --------- BLOCK
    // r ----------------- 0
    //

    uint8_t wr8_cmd[] = {TOPAZ_WRITE_NE8, blockno, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    memcpy(wr8_cmd + 10, uid_echo, 4);
    memcpy(wr8_cmd + 2, block_data, 8);

    uint16_t resp_len = 11;
    uint8_t response[11] = {0};

    //
    if (topaz_send_cmd(wr8_cmd, sizeof(wr8_cmd), response, &resp_len, true) == PM3_ETIMEOUT) {
        topaz_switch_off_field();
        return PM3_ESOFT;
    }

    if (resp_len != 11) {
        return PM3_EFAILED;
    }

    if (blockno != response[0]) {
        return PM3_EFAILED;
    }

    if (memcmp(block_data, response + 1, 8) == 0) {
        return PM3_SUCCESS;
    }
    return PM3_ESOFT;
}

// search for the lock area descriptor for the lockable area including byteno
static dynamic_lock_area_t *get_dynamic_lock_area(uint16_t byteno) {
    dynamic_lock_area_t *lock_area;
    lock_area = topaz_tag.dynamic_lock_areas;

    while (lock_area != NULL) {
        if (byteno < lock_area->first_locked_byte) {
            lock_area = lock_area->next;
        } else {
            return lock_area;
        }
    }
    return NULL;
}

// check if a memory byte is locked.
static bool topaz_byte_is_locked(uint16_t byteno) {
    uint8_t *lockbits;
    uint16_t locked_bytes_per_bit;
    dynamic_lock_area_t *lock_area;

    if (byteno < TOPAZ_STATIC_MEMORY) {
        lockbits = &topaz_tag.data_blocks[0x0e][0];
        locked_bytes_per_bit = 8;
    } else {
        lock_area = get_dynamic_lock_area(byteno);
        if (lock_area == NULL) {
            return false;
        } else {

            if ((lock_area->byte_offset - TOPAZ_STATIC_MEMORY) < 0) {
                return false;
            }

            lockbits = &topaz_tag.dynamic_memory[lock_area->byte_offset - TOPAZ_STATIC_MEMORY];
            locked_bytes_per_bit = lock_area->bytes_locked_per_bit;
            byteno = byteno - lock_area->first_locked_byte;
        }
    }

    uint16_t blockno = byteno / locked_bytes_per_bit;
    if (lockbits[blockno / 8] & (0x01 << (blockno % 8))) {
        return true;
    } else {
        return false;
    }
}

static int topaz_set_cc_dynamic(const uint8_t *data) {

    if (data[0] != 0xE1) {
        topaz_tag.size = TOPAZ_STATIC_MEMORY;
        PrintAndLogEx(WARNING, "No Type 1 NDEF capability container found");
        return PM3_ESOFT; // no NDEF message
    }

    // setting of dynamic memory and allocation of such memory.
    uint16_t memsize = (data[2] + 1) * 8;
    topaz_tag.size = memsize;
    topaz_tag.dynamic_memory = calloc(memsize - TOPAZ_STATIC_MEMORY, sizeof(uint8_t));
    if (topaz_tag.dynamic_memory == NULL) {
        return PM3_EMALLOC;
    }
    return PM3_SUCCESS;
}

// read and print the Capability Container
static int topaz_print_CC(uint8_t *data) {

    if (data[0] != 0xE1) {
        topaz_tag.size = TOPAZ_STATIC_MEMORY;
        PrintAndLogEx(WARNING, "No Type 1 NDEF capability container found");
        return PM3_ESOFT; // no NDEF message
    }


//NFC Forum Type 1,2,3,4
//
// 4 has 1.1 (11)

// b7, b6 major version
// b5, b4 minor version
// b3, b2 read
// 00 always, 01 rfu, 10 proprietary, 11 rfu
// b1, b0 write
// 00 always, 01 rfo, 10 proprietary, 11 never

// vs

// NFC Forum Type 2 docs,   where
// b7654 = major version
// b3219 = minor version

// CC write / read access
// (data[3] & 0xF0) ? "(RFU)" : "Read access granted without any security",
// (data[3] & 0x0F) == 0 ? "Write access granted without any security" : (data[3] & 0x0F) == 0x0F ? "No write access granted at all" : "(RFU)");
    uint8_t cc_major = (data[1] & 0xF0) >> 4;
    uint8_t cc_minor = (data[1] & 0x00);

    uint8_t cc_write = data[3] & 0x0F;
    uint8_t cc_read  = (data[3] & 0xF0) >> 4;

    const char *wStr;
    switch (cc_write) {
        case 0:
            wStr = "Write access granted without any security";
            break;
        case 0xF:
            wStr = "No write access";
            break;
        default:
            wStr = "RFU";
            break;
    }
    const char *rStr;
    switch (cc_read) {
        case 0:
            rStr = "Read access granted without any security";
            break;
        default:
            rStr = "RFU";
            break;
    }

    PrintAndLogEx(SUCCESS, "Capability Container: %s", sprint_hex(data, 4));
    PrintAndLogEx(SUCCESS, "  %02X: NDEF Magic Number", data[0]);

//    PrintAndLogEx(SUCCESS, "  %02X : version %d.%d supported by tag", data[1], (data[1] & 0xF0) >> 4, data[1] & 0x0F);
    PrintAndLogEx(SUCCESS, "  %02X: version %d.%d supported by tag", data[1], cc_major, cc_minor);
    PrintAndLogEx(SUCCESS, "       : %s / %s", rStr, wStr);

    PrintAndLogEx(SUCCESS, "  %02X: Physical Memory Size: %d bytes", data[2], (data[2] + 1) * 8);
    if (data[2] == 0x0E)
        PrintAndLogEx(SUCCESS, "  %02X: NDEF Memory Size: %d bytes", data[2], 120);
    else if (data[2] == 0x1F)
        PrintAndLogEx(SUCCESS, "  %02X: NDEF Memory Size: %d bytes", data[2], 256);
    else if (data[2] == 0xFF)
        PrintAndLogEx(SUCCESS, "  %02X: NDEF Memory Size: %d bytes", data[2], 2048);

    uint8_t msb3   = (data[3] & 0xE0) >> 5;
    uint8_t sf     = (data[3] & 0x10) >> 4;
    uint8_t lb     = (data[3] & 0x08) >> 3;
    uint8_t mlrule = (data[3] & 0x06) >> 1;
    uint8_t mbread = (data[3] & 0x01);

    PrintAndLogEx(SUCCESS, "  %02X: Additional feature information", data[3]);
    PrintAndLogEx(SUCCESS, "  ^^");
    PrintAndLogEx(SUCCESS, "  %s", sprint_bin(&data[3], 1));
    PrintAndLogEx(SUCCESS, "  xxx..... - %02X: RFU ( %s )", msb3, (msb3 == 0) ? _GREEN_("ok") : _RED_("fail"));
    PrintAndLogEx(SUCCESS, "  ...x.... - %02X: %s special frame", sf, (sf) ? "support" : "don\'t support");
    PrintAndLogEx(SUCCESS, "  ....x... - %02X: %s lock block", lb, (lb) ? "support" : "don\'t support");
    PrintAndLogEx(SUCCESS, "  .....xx. - %02X: RFU ( %s )", mlrule, (mlrule == 0) ? _GREEN_("ok") : _RED_("fail"));
    PrintAndLogEx(SUCCESS, "  .......x - %02X: IC %s multiple block reads", mbread, (mbread) ? "support" : "don\'t support");
    PrintAndLogEx(SUCCESS, "");

    return PM3_SUCCESS;
}

static void topaz_print_hdr(uint8_t blockno) {
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "  # | block " _GREEN_("0x%02X") "              | ascii", blockno);
    PrintAndLogEx(INFO, "----+-------------------------+---------");
}

// return type, length and value of a TLV, starting at memory position *TLV_ptr
static void get_TLV(uint8_t **TLV_ptr, uint8_t *TLV_type, uint16_t *TLV_length, uint8_t **TLV_value) {
    *TLV_length = 0;
    *TLV_value = NULL;

    *TLV_type = **TLV_ptr;
    *TLV_ptr += 1;
    switch (*TLV_type) {
        case 0x00:          // NULL TLV.
        case 0xFE:          // Terminator TLV.
            break;
        case 0x01:          // Lock Control TLV
        case 0x02:          // Reserved Memory TLV
        case 0x03:          // NDEF message TLV
        case 0xFD:          // proprietary TLV
            *TLV_length = **TLV_ptr;
            *TLV_ptr += 1;
            if (*TLV_length == 0xff) {
                *TLV_length = **TLV_ptr << 8;
                *TLV_ptr += 1;
                *TLV_length |= **TLV_ptr;
                *TLV_ptr += 1;
            }
            *TLV_value = *TLV_ptr;
            *TLV_ptr += *TLV_length;
            break;
        default:            // RFU
            break;
    }
}

// lock area TLVs contain no information on the start of the respective lockable area. Lockable areas
// do not include the lock bits and reserved memory. We therefore need to adjust the start of the
// respective lockable areas accordingly
static void adjust_lock_areas(uint16_t block_start, uint16_t block_size) {
    dynamic_lock_area_t *lock_area = topaz_tag.dynamic_lock_areas;
    while (lock_area != NULL) {
        if (lock_area->first_locked_byte <= block_start) {
            lock_area->first_locked_byte += block_size;
        }
        lock_area = lock_area->next;
    }
}

// read and print the lock area and reserved memory TLVs
static void topaz_print_control_TLVs(uint8_t *memory) {
    uint8_t *TLV_ptr = memory;
    uint8_t TLV_type = 0;
    uint16_t TLV_length;
    uint8_t *TLV_value;
    bool lock_TLV_present = false;
    bool reserved_memory_control_TLV_present = false;
    uint16_t next_lockable_byte = 0x0f * 8; // first byte after static memory area

    while (*TLV_ptr != 0x03 && *TLV_ptr != 0xFD && *TLV_ptr != 0xFE) {

        // all Lock Control TLVs shall be present before the NDEF message TLV, the proprietary TLV (and the Terminator TLV)
        get_TLV(&TLV_ptr, &TLV_type, &TLV_length, &TLV_value);

        if (TLV_type == 0x01) { // a Lock Control TLV
            uint8_t pages_addr = TLV_value[0] >> 4;
            uint8_t byte_offset = TLV_value[0] & 0x0f;
            uint16_t size_in_bits = TLV_value[1] ? TLV_value[1] : 256;
            uint16_t size_in_bytes = (size_in_bits + 7) / 8;
            uint16_t bytes_per_page = 1 << (TLV_value[2] & 0x0f);
            uint16_t bytes_locked_per_bit = 1 << (TLV_value[2] >> 4);
            uint16_t area_start = pages_addr * bytes_per_page + byte_offset;

            PrintAndLogEx(SUCCESS, "Lock Area of " _YELLOW_("%d") " bits at byte offset " _YELLOW_("0x%04x"), size_in_bits, area_start);
            PrintAndLogEx(SUCCESS, "Each lock bit locks " _YELLOW_("%d") " bytes", bytes_locked_per_bit);

            lock_TLV_present = true;
            dynamic_lock_area_t *old = topaz_tag.dynamic_lock_areas;
            dynamic_lock_area_t *new;

            if (old == NULL) {
                new = topaz_tag.dynamic_lock_areas = (dynamic_lock_area_t *) calloc(sizeof(dynamic_lock_area_t), sizeof(uint8_t));
            } else {
                while (old->next != NULL) {
                    old = old->next;
                }
                new = old->next = (dynamic_lock_area_t *) calloc(sizeof(dynamic_lock_area_t), sizeof(uint8_t));
            }
            new->next = NULL;

            if (area_start <= next_lockable_byte) {
                // lock areas are not lockable
                next_lockable_byte += size_in_bytes;
            }

            new->first_locked_byte = next_lockable_byte;
            new->byte_offset = area_start;
            new->size_in_bits = size_in_bits;
            new->bytes_locked_per_bit = bytes_locked_per_bit;
            next_lockable_byte += size_in_bits * bytes_locked_per_bit;
        }

        if (TLV_type == 0x02) { // a Reserved Memory Control TLV
            uint8_t pages_addr = TLV_value[0] >> 4;
            uint8_t byte_offset = TLV_value[0] & 0x0f;
            uint16_t size_in_bytes = TLV_value[1] ? TLV_value[1] : 256;
            uint8_t bytes_per_page = 1 << (TLV_value[2] & 0x0f);
            uint16_t area_start = pages_addr * bytes_per_page + byte_offset;

            PrintAndLogEx(SUCCESS, "Reserved Memory... " _GREEN_("%d") " bytes at byte offset " _YELLOW_("0x%02x"),
                          size_in_bytes,
                          area_start);

            reserved_memory_control_TLV_present = true;

            // reserved memory areas are not lockable
            adjust_lock_areas(area_start, size_in_bytes);
            if (area_start <= next_lockable_byte) {
                next_lockable_byte += size_in_bytes;
            }
        }
    }

    if (lock_TLV_present == false) {
        PrintAndLogEx(SUCCESS, "(No Lock Control TLV present)");
    }

    if (reserved_memory_control_TLV_present == false) {
        PrintAndLogEx(SUCCESS, "(No Reserved Memory Control TLV present)");
    }
}

// read all of the dynamic memory
static int topaz_read_dynamic_data(void) {
    // first read the remaining block of segment 0
    if (topaz_read_block(0x0F, &topaz_tag.dynamic_memory[0]) == PM3_ESOFT) {
        PrintAndLogEx(ERR, "Error while reading dynamic memory block " _YELLOW_("%02x") ". Aborting...", 0x0F);
        return PM3_ESOFT;
    }

    // read the remaining segments
    uint8_t max = topaz_tag.size / 128 - 1;
    for (uint8_t segment = 1; segment <= max; segment++) {
        if (topaz_read_segment(segment, &topaz_tag.dynamic_memory[(segment - 1) * 128 + 8]) == PM3_ESOFT) {
            PrintAndLogEx(ERR, "Error while reading dynamic memory block " _YELLOW_("%02x") ". Aborting...", segment);
            return PM3_ESOFT;
        }
    }
    return PM3_SUCCESS;
}

// read and print the dynamic memory
static void topaz_print_dynamic_data(void) {

    if (topaz_tag.size <= TOPAZ_STATIC_MEMORY) {
        return;
    }

    PrintAndLogEx(SUCCESS, "Dynamic Data blocks:");

    if (topaz_read_dynamic_data() == PM3_SUCCESS) {

        PrintAndLogEx(SUCCESS, "block# | Data                    |lck");
        PrintAndLogEx(SUCCESS, "-------+-------------------------+-------------");

        char line[80];
        for (uint16_t blockno = 0x0F; blockno < topaz_tag.size / 8; blockno++) {

            uint8_t *block_data = &topaz_tag.dynamic_memory[(blockno - 0x0F) * 8];
            char lockbits[9];
            for (uint16_t j = 0; j < 8; j++) {
                int offset = 3 * j;
                snprintf(line + offset, sizeof(line) - offset, "%02x ", block_data[j]);
                lockbits[j] = topaz_byte_is_locked(blockno * 8 + j) ? 'y' : 'n';
            }
            lockbits[8] = '\0';

            PrintAndLogEx(SUCCESS, "  0x%02x | %s|   %-3s", blockno, line, lockbits);
        }
    }
}

static void topaz_print_lifecycle_state(uint8_t *data) {
    // to be done
}

static void printTopazDumpContents(topaz_tag_t *dump) {

    // uses a global var for all
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(SUCCESS, "Static data blocks :");
    PrintAndLogEx(SUCCESS, "block#      | data                    |lck| info");
    PrintAndLogEx(SUCCESS, "------------+-------------------------+---+------------");

    const char *block_info;
    const char *topaz_ks[] = { "uid", "user", "rfu", "lock / otp" };

    for (uint8_t i = 0; i <= 0x0C; i++) {

        if (i == 0)
            block_info = topaz_ks[i];
        else
            block_info = topaz_ks[1];

        const char *lockstr = (topaz_byte_is_locked(i * 8)) ? _RED_("x") : " ";

        PrintAndLogEx(SUCCESS, " %3u / 0x%02x | %s| %s | %s",
                      i,
                      i,
                      sprint_hex(&dump->data_blocks[i][0], 8),
                      lockstr,
                      block_info
                     );
    }

    PrintAndLogEx(SUCCESS, " %3u / 0x%02x | %s|   | %s", 0x0D, 0x0D, sprint_hex(&dump->data_blocks[0x0D][0], 8), topaz_ks[2]);
    PrintAndLogEx(SUCCESS, " %3u / 0x%02x | %s|   | %s", 0x0E, 0x0E, sprint_hex(&dump->data_blocks[0x0E][0], 8), topaz_ks[3]);
    PrintAndLogEx(SUCCESS, "------------+-------------------------+---+------------");
    PrintAndLogEx(NORMAL, "");
}

static int CmdHFTopazReader(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf topaz reader",
                  "Read UID from Topaz tags",
                  "hf topaz reader\n"
                  "hf topaz reader -@     -> Continuous mode\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("v", "verbose", "verbose output"),
        arg_lit0("@", NULL, "optional - continuous reader mode"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool verbose = arg_get_lit(ctx, 1);
    bool cm = arg_get_lit(ctx, 2);
    CLIParserFree(ctx);

    if (cm) {
        PrintAndLogEx(INFO, "Press " _GREEN_("<Enter>") " to exit");
    }

    int res = readTopazUid(cm, verbose);

    topaz_switch_off_field();
    return res;
}

// read a Topaz tag and print some useful information
int CmdHFTopazInfo(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf topaz info",
                  "Get info from Topaz tags",
                  "hf topaz info\n"
                  "hf topaz info -f myfilename -> save raw NDEF to file\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("f", "file", "<fn>", "save raw NDEF to file"),
        arg_lit0("v", "verbose", "verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);
    bool verbose = arg_get_lit(ctx, 2);

    CLIParserFree(ctx);

    PrintAndLogEx(INFO, "--- " _CYAN_("Tag Information") " ---------------------------");

    int status = readTopazUid(false, verbose);
    if (status != PM3_SUCCESS) {
        return status;
    }

    PrintAndLogEx(SUCCESS, "MANUFACTURER: " _YELLOW_("%s"), getTagInfo(topaz_tag.uid[6]));

    // ToDo: CRC check
    PrintAndLogEx(SUCCESS, "  HR: " _GREEN_("%02X %02X"), topaz_tag.HR01[0], topaz_tag.HR01[1]);
    PrintAndLogEx(SUCCESS, "      ^^");

    PrintAndLogEx(SUCCESS, "      %s", sprint_bin(topaz_tag.HR01, 1));
    PrintAndLogEx(SUCCESS, "      ...x.... - %s / %s",
                  (topaz_tag.HR01[0] & 0xF0) == 0x10 ? _GREEN_("TOPAZ tag") : "",
                  (topaz_tag.HR01[0] & 0xF0) == 0x10 ? _GREEN_("Type 1 NDEF") : ""
                 );
    PrintAndLogEx(SUCCESS, "      .......x - %s memory map", ((topaz_tag.HR01[0] & 0x0F) == 0x01) ? "Static" : "Dynamic");
    PrintAndLogEx(SUCCESS, "");
    PrintAndLogEx(SUCCESS, " Lock bytes... %02X%02X",
                  topaz_tag.data_blocks[0x0e][0],
                  topaz_tag.data_blocks[0x0e][1]
                 );

    PrintAndLogEx(SUCCESS, " OTP.......... %s", sprint_hex(&topaz_tag.data_blocks[0x0e][2], 6));
    PrintAndLogEx(NORMAL, "");

    PrintAndLogEx(INFO, "--- " _CYAN_("NDEF configuration") " ---------------------------");
    status = topaz_print_CC(&topaz_tag.data_blocks[1][0]);
    if (status == PM3_ESOFT) {
        PrintAndLogEx(SUCCESS, "No NDEF message data present");
        topaz_switch_off_field();
        return PM3_SUCCESS;
    }

    PrintAndLogEx(NORMAL, "");
    topaz_print_control_TLVs(&topaz_tag.data_blocks[1][4]);

    PrintAndLogEx(NORMAL, "");
    topaz_switch_off_field();
    return PM3_SUCCESS;
}

static int CmdHFTopazSim(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf topaz sim",
                  "Simulate a Topaz tag",
                  "hf topaz sim   -> Not yet implemented");

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    PrintAndLogEx(INFO, "not yet implemented");
    return PM3_SUCCESS;
}

static int CmdHFTopazRaw(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf topaz raw",
                  "Send raw hex data to Topaz tags",
                  "hf topaz raw");

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    PrintAndLogEx(INFO, "not yet implemented. Use `hf 14 raw --topaz` meanwhile");
    return PM3_SUCCESS;
}

static int CmdHFTopazList(const char *Cmd) {
    return CmdTraceListAlias(Cmd, "hf topaz", "topaz -c");
}

static int CmdHFTopazSniff(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf topaz sniff",
                  "Sniff Topaz reader-tag communication",
                  "hf topaz sniff");

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);

    uint8_t param = 0;
    SendCommandNG(CMD_HF_ISO14443A_SNIFF, (uint8_t *)&param, sizeof(uint8_t));

    return PM3_SUCCESS;
}

static int CmdHFTopazDump(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf topaz dump",
                  "Dump TOPAZ tag to binary file\n"
                  "If no <name> given, UID will be used as filename",
                  "hf topaz dump\n");

    void *argtable[] = {
        arg_param_begin,
        arg_str0("f", "file", "<fn>", "filename of dump"),
        arg_lit0(NULL, "ns", "no save to file"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);
    bool nosave = arg_get_lit(ctx, 2);

    CLIParserFree(ctx);

    int status = readTopazUid(false, false);
    if (status != PM3_SUCCESS) {
        return status;
    }
    printTopazDumpContents(&topaz_tag);

    bool set_dynamic = false;
    if (topaz_set_cc_dynamic(&topaz_tag.data_blocks[1][0]) == PM3_SUCCESS) {
        set_dynamic = true;

        topaz_print_dynamic_data();

        topaz_print_lifecycle_state(&topaz_tag.data_blocks[1][0]);

        NDEFDecodeAndPrint(&topaz_tag.data_blocks[1][4],
                           (topaz_tag.HR01[0] == 1) ? (12 * 8) : 476
                           , true
                          );
    }

    topaz_switch_off_field();

    // Skip saving card data to file
    if (nosave) {
        PrintAndLogEx(INFO, "Called with no save option");
        if (set_dynamic) {
            free(topaz_tag.dynamic_memory);
        }
        return PM3_SUCCESS;
    }


    // user supplied filename?
    if (fnlen < 1) {
        PrintAndLogEx(INFO, "Using UID as filename");
        strcat(filename, "hf-topaz-");
        FillFileNameByUID(filename, topaz_tag.uid, "-dump", sizeof(topaz_tag.uid));
    }

    if (topaz_tag.size)
        pm3_save_dump(filename, (uint8_t *)&topaz_tag, sizeof(topaz_tag_t) + topaz_tag.size, jsfTopaz, TOPAZ_BLOCK_SIZE);
    else
        pm3_save_dump(filename, (uint8_t *)&topaz_tag, sizeof(topaz_tag_t), jsfTopaz, TOPAZ_BLOCK_SIZE);

    if (set_dynamic) {
        free(topaz_tag.dynamic_memory);
    }

    return PM3_SUCCESS;
}

static int CmdHFTopazView(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf topaz view",
                  "Print a Topaz tag dump file (bin/eml/json)",
                  "hf topaz view -f hf-topaz-04010203-dump.bin");

    void *argtable[] = {
        arg_param_begin,
        arg_str1("f", "file", "<fn>",  "filename of dump (bin/eml/json)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    int fnlen = 0;
    char filename[FILE_PATH_SIZE];
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);
    CLIParserFree(ctx);

    // read dump file
    topaz_tag_t *dump = NULL;
    size_t bytes_read = TOPAZ_MAX_SIZE;
    int res = pm3_load_dump(filename, (void **)&dump, &bytes_read, sizeof(topaz_tag_t) + TOPAZ_MAX_SIZE);
    if (res != PM3_SUCCESS) {
        return res;
    }
    if (bytes_read < sizeof(topaz_tag_t)) {
        free(dump);
        return PM3_EFAILED;
    }
    printTopazDumpContents(dump);

    if (topaz_set_cc_dynamic(&topaz_tag.data_blocks[1][0]) == PM3_SUCCESS) {

        topaz_print_dynamic_data();

        topaz_print_lifecycle_state(&topaz_tag.data_blocks[1][0]);

        NDEFDecodeAndPrint(&topaz_tag.data_blocks[1][4],
                           (topaz_tag.HR01[0] == 1) ? (12 * 8) : 476
                           , true
                          );

        PrintAndLogEx(INFO, "%s", sprint_hex(&topaz_tag.data_blocks[1][4], (12 * 8)));

        free(topaz_tag.dynamic_memory);
    }

    free(dump);
    return PM3_SUCCESS;
}

// Read single block
static int CmdHFTopazRdBl(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf topaz rdbl",
                  "Read Topaz block",
                  "hf topaz rdbl --blk 7\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_int1(NULL, "blk", "<dec>", "Block number"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    int blockno = arg_get_int_def(ctx, 1, -1);
    CLIParserFree(ctx);

    if (blockno < 0) {
        PrintAndLogEx(WARNING, "Wrong block number");
        return PM3_EINVARG;
    }

    // send read block
    uint8_t data[8] = {0};
    int res = topaz_read_block(blockno, data);
    if (res == PM3_SUCCESS) {

        topaz_print_hdr(blockno);

        PrintAndLogEx(INFO, " %2d | %s", blockno, sprint_hex_ascii(data, sizeof(data)));
        PrintAndLogEx(NORMAL, "");
    }

    topaz_switch_off_field();
    return res;
}

//  Write single block
static int CmdHFTopazWrBl(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf topaz wrbl",
                  "Write Topaz block with 8 hex bytes of data",
                  "hf topaz wrbl --blk 7 -d 1122334455667788\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_int1(NULL, "blk", "<dec>", "Block number"),
        arg_str1("d", "data", "<hex>", "Block data (8 hex bytes)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int blockno = arg_get_int_def(ctx, 1, -1);

    int dlen = 0;
    uint8_t data[8] = {0x00};
    CLIGetHexWithReturn(ctx, 2, data, &dlen);

    CLIParserFree(ctx);

    if (blockno < 0) {
        PrintAndLogEx(WARNING, "Wrong block number");
        return PM3_EINVARG;
    }

    if (dlen != 8) {
        PrintAndLogEx(WARNING, "Wrong data length. Expect 8, got %d", dlen);
        return PM3_EINVARG;
    }

    PrintAndLogEx(INFO, "Block: %0d (0x%02X) [ %s]", blockno, blockno, sprint_hex(data, dlen));

    int res;
    if (blockno != 13 && blockno != 14) {
        // send write/erase block
        res = topaz_write_erase8_block(blockno, data);
    } else {
        // send write/non erase block
        res = topaz_write_nonerase8_block(blockno, data);
    }

    if (res == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "Write ( " _GREEN_("ok") " )");
        PrintAndLogEx(HINT, "try `" _YELLOW_("hf topaz rdbl --blk %u") "` to verify", blockno);

    } else {
        PrintAndLogEx(WARNING, "Write ( " _RED_("fail") " )");
    }
    PrintAndLogEx(NORMAL, "");

    topaz_switch_off_field();
    return res;
}

static int CmdHelp(const char *Cmd);

static command_t CommandTable[] = {
    {"help",        CmdHelp,            AlwaysAvailable, "This help"},
    {"list",        CmdHFTopazList,     AlwaysAvailable, "List Topaz history"},
    {"-----------", CmdHelp,            IfPm3Iso14443a,  "------------------- " _CYAN_("operations") " ---------------------"},
    {"dump",        CmdHFTopazDump,     IfPm3Iso14443a,  "Dump TOPAZ family tag to file"},
    {"info",        CmdHFTopazInfo,     IfPm3Iso14443a,  "Tag information"},
    {"raw",         CmdHFTopazRaw,      IfPm3Iso14443a,  "Send raw hex data to tag"},
    {"rdbl",        CmdHFTopazRdBl,     IfPm3Iso14443a,  "Read block"},
    {"reader",      CmdHFTopazReader,   IfPm3Iso14443a,  "Act like a Topaz reader"},
    {"sim",         CmdHFTopazSim,      IfPm3Iso14443a,  "Simulate Topaz tag"},
    {"sniff",       CmdHFTopazSniff,    IfPm3Iso14443a,  "Sniff Topaz reader-tag communication"},
    {"view",        CmdHFTopazView,     AlwaysAvailable, "Display content from tag dump file"},
    {"wrbl",        CmdHFTopazWrBl,     IfPm3Iso14443a,  "Write block"},
    {"-----------", CmdHelp,            IfPm3Iso14443a,  "----------------------- " _CYAN_("ndef") " -----------------------"},
//    {"ndefformat",  CmdHFTopazNDEFFormat,      IfPm3Iso14443a,  "Format Topaz Tag as NFC Tag"},
//    {"ndefread",    CmdHFTopazNDEFRead,        IfPm3Iso14443a,  "Read and print NDEF records from card"},
//    {"ndefwrite",   CmdHFTopazNDEFWrite,       IfPm3Iso14443a,  "Write NDEF records to card"},

    {NULL, NULL, 0, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdHFTopaz(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

int readTopazUid(bool loop, bool verbose) {

    int res = PM3_SUCCESS;

    do {
        uint8_t atqa[2] = {0};
        uint8_t rid_response[8] = {0};
        uint8_t *uid_echo = &rid_response[2];
        uint8_t rall_response[124] = {0};

        int status = topaz_select(atqa, sizeof(atqa), rid_response, sizeof(rid_response), verbose);
        if (status == PM3_ESOFT) {
            if (verbose) PrintAndLogEx(ERR, "Error: couldn't receive ATQA");

            if (loop) {
                continue;
            }

            res = status;
            break;
        }

        if (atqa[1] != 0x0c && atqa[0] != 0x00) {
            if (verbose) PrintAndLogEx(ERR, "Tag doesn't support the Topaz protocol.");

            if (loop) {
                continue;
            }

            res = PM3_ESOFT;
            break;
        }

        if (status == PM3_EWRONGANSWER) {
            if (verbose) PrintAndLogEx(ERR, "Error: tag didn't answer to RID");

            if (loop) {
                continue;
            }
            res = status;
            break;
        }

        status = topaz_rall(uid_echo, rall_response);
        if (status == PM3_ESOFT) {
            PrintAndLogEx(ERR, "Error: tag didn't answer to RALL");

            if (loop) {
                continue;
            }

            res = status;
            break;
        }

        memcpy(topaz_tag.uid, rall_response + 2, 7);
        memcpy(topaz_tag.data_blocks, rall_response + 2, 0x0F * 8);

        // printing
        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(SUCCESS, " UID: " _GREEN_("%02X %02X %02X %02X %02X %02X %02X"),
                      topaz_tag.uid[6],
                      topaz_tag.uid[5],
                      topaz_tag.uid[4],
                      topaz_tag.uid[3],
                      topaz_tag.uid[2],
                      topaz_tag.uid[1],
                      topaz_tag.uid[0]);

        PrintAndLogEx(SUCCESS, "ATQA: " _GREEN_("%02X %02X"), atqa[1], atqa[0]);

        topaz_tag.HR01[0] = rid_response[0];
        topaz_tag.HR01[1] = rid_response[1];

    } while (loop && kbd_enter_pressed() == false);

    topaz_switch_off_field();
    return res;
}
