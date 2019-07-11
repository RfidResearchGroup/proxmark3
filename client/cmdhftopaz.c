//-----------------------------------------------------------------------------
// Copyright (C) 2015 Piwi
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency Topaz (NFC Type 1) commands
//-----------------------------------------------------------------------------
#include "cmdhftopaz.h"

#define TOPAZ_STATIC_MEMORY (0x0f * 8)  // 15 blocks with 8 Bytes each

// a struct to describe a memory area which contains lock bits and the corresponding lockable memory area
typedef struct dynamic_lock_area {
    struct dynamic_lock_area *next;
    uint16_t byte_offset;               // the address of the lock bits
    uint16_t size_in_bits;
    uint16_t first_locked_byte;         // the address of the lockable area
    uint16_t bytes_locked_per_bit;
} dynamic_lock_area_t;


static struct {
    uint8_t HR01[2];
    uint8_t uid[7];
    uint16_t size;
    uint8_t data_blocks[TOPAZ_STATIC_MEMORY / 8][8]; // this memory is always there
    uint8_t *dynamic_memory;                       // this memory can be there
    dynamic_lock_area_t *dynamic_lock_areas;       // lock area descriptors
} topaz_tag;

static void topaz_switch_on_field(void) {
    SendCommandMIX(CMD_READER_ISO_14443a, ISO14A_CONNECT | ISO14A_NO_SELECT | ISO14A_NO_DISCONNECT | ISO14A_TOPAZMODE | ISO14A_NO_RATS, 0, 0, NULL, 0);
}

static void topaz_switch_off_field(void) {
    SendCommandMIX(CMD_READER_ISO_14443a, 0, 0, 0, NULL, 0);
}

// send a raw topaz command, returns the length of the response (0 in case of error)
static int topaz_send_cmd_raw(uint8_t *cmd, uint8_t len, uint8_t *response) {
    SendCommandOLD(CMD_READER_ISO_14443a, ISO14A_RAW | ISO14A_NO_DISCONNECT | ISO14A_TOPAZMODE | ISO14A_NO_RATS, len, 0, cmd, len);

    PacketResponseNG resp;
    WaitForResponse(CMD_ACK, &resp);

    if (resp.oldarg[0] > 0) {
        memcpy(response, resp.data.asBytes, resp.oldarg[0]);
    }

    return resp.oldarg[0];
}


// calculate CRC bytes and send topaz command, returns the length of the response (0 in case of error)
static int topaz_send_cmd(uint8_t *cmd, uint8_t len, uint8_t *response) {
    if (len > 1) {
        uint8_t b1, b2;
        compute_crc(CRC_14443_B, cmd, len - 2, &b1, &b2);
        cmd[len - 2] = b1;
        cmd[len - 1] = b2;
    }

    return topaz_send_cmd_raw(cmd, len, response);
}


// select a topaz tag. Send WUPA and RID.
static int topaz_select(uint8_t *atqa, uint8_t *rid_response) {
    // ToDo: implement anticollision

    uint8_t wupa_cmd[] = {TOPAZ_WUPA};
    uint8_t rid_cmd[] = {TOPAZ_RID, 0, 0, 0, 0, 0, 0, 0, 0};

    topaz_switch_on_field();

    if (!topaz_send_cmd(wupa_cmd, sizeof(wupa_cmd), atqa)) {
        topaz_switch_off_field();
        return -1; // WUPA failed
    }

    if (!topaz_send_cmd(rid_cmd, sizeof(rid_cmd), rid_response)) {
        topaz_switch_off_field();
        return -2; // RID failed
    }

    return 0; // OK
}


// read all of the static memory of a selected Topaz tag.
static int topaz_rall(uint8_t *uid, uint8_t *response) {
    uint8_t rall_cmd[] = {TOPAZ_RALL, 0, 0, 0, 0, 0, 0, 0, 0};

    memcpy(&rall_cmd[3], uid, 4);
    if (!topaz_send_cmd(rall_cmd, sizeof(rall_cmd), response)) {
        topaz_switch_off_field();
        return -1; // RALL failed
    }

    return 0;
}


// read a block (8 Bytes) of a selected Topaz tag.
static int topaz_read_block(uint8_t *uid, uint8_t blockno, uint8_t *block_data) {
    uint8_t read8_cmd[] = {TOPAZ_READ8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    uint8_t read8_response[11];

    read8_cmd[1] = blockno;
    memcpy(&read8_cmd[10], uid, 4);
    if (!topaz_send_cmd(read8_cmd, sizeof(read8_cmd), read8_response)) {
        topaz_switch_off_field();
        return -1; // READ8 failed
    }
    memcpy(block_data, &read8_response[1], 8);
    return 0;
}

// read a segment (16 blocks = 128 Bytes) of a selected Topaz tag. Works only for tags with dynamic memory.
static int topaz_read_segment(uint8_t *uid, uint8_t segno, uint8_t *segment_data) {
    uint8_t rseg_cmd[] = {TOPAZ_RSEG, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    uint8_t rseg_response[131];

    rseg_cmd[1] = segno << 4;
    memcpy(&rseg_cmd[10], uid, 4);
    if (!topaz_send_cmd(rseg_cmd, sizeof(rseg_cmd), rseg_response)) {
        topaz_switch_off_field();
        return -1; // RSEG failed
    }
    memcpy(segment_data, &rseg_response[1], 128);
    return 0;
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


// read and print the Capability Container
static int topaz_print_CC(uint8_t *data) {
    if (data[0] != 0xe1) {
        topaz_tag.size = TOPAZ_STATIC_MEMORY;
        return -1; // no NDEF message
    }

    PrintAndLogEx(NORMAL, "Capability Container: %02x %02x %02x %02x", data[0], data[1], data[2], data[3]);
    PrintAndLogEx(NORMAL, "  %02x: NDEF Magic Number", data[0]);
    PrintAndLogEx(NORMAL, "  %02x: version %d.%d supported by tag", data[1], (data[1] & 0xF0) >> 4, data[1] & 0x0f);
    uint16_t memsize = (data[2] + 1) * 8;
    topaz_tag.size = memsize;
    topaz_tag.dynamic_memory = calloc(memsize - TOPAZ_STATIC_MEMORY, sizeof(uint8_t));
    PrintAndLogEx(NORMAL, "  %02x: Physical Memory Size of this tag: %d bytes", data[2], memsize);
    PrintAndLogEx(NORMAL, "  %02x: %s / %s", data[3],
                  (data[3] & 0xF0) ? "(RFU)" : "Read access granted without any security",
                  (data[3] & 0x0F) == 0 ? "Write access granted without any security" : (data[3] & 0x0F) == 0x0F ? "No write access granted at all" : "(RFU)");
    return 0;
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
            PrintAndLogEx(NORMAL, "Lock Area of %d bits at byte offset 0x%04x. Each Lock Bit locks %d bytes.",
                          size_in_bits,
                          area_start,
                          bytes_locked_per_bit);
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
            PrintAndLogEx(NORMAL, "Reserved Memory of %d bytes at byte offset 0x%02x.",
                          size_in_bytes,
                          area_start);
            reserved_memory_control_TLV_present = true;
            adjust_lock_areas(area_start, size_in_bytes);  // reserved memory areas are not lockable
            if (area_start <= next_lockable_byte) {
                next_lockable_byte += size_in_bytes;
            }
        }
    }

    if (!lock_TLV_present) {
        PrintAndLogEx(NORMAL, "(No Lock Control TLV present)");
    }

    if (!reserved_memory_control_TLV_present) {
        PrintAndLogEx(NORMAL, "(No Reserved Memory Control TLV present)");
    }
}

// read all of the dynamic memory
static int topaz_read_dynamic_data(void) {
    // first read the remaining block of segment 0
    if (topaz_read_block(topaz_tag.uid, 0x0f, &topaz_tag.dynamic_memory[0]) == -1) {
        PrintAndLogEx(WARNING, "Error while reading dynamic memory block %02x. Aborting...", 0x0f);
        return -1;
    }

    // read the remaining segments
    uint8_t max_segment = topaz_tag.size / 128 - 1;
    for (uint8_t segment = 1; segment <= max_segment; segment++) {
        if (topaz_read_segment(topaz_tag.uid, segment, &topaz_tag.dynamic_memory[(segment - 1) * 128 + 8]) == -1) {
            PrintAndLogEx(WARNING, "Error while reading dynamic memory block %02x. Aborting...", 0x0f);
            return -1;
        }
    }
    return 0;
}


// read and print the dynamic memory
static void topaz_print_dynamic_data(void) {
    if (topaz_tag.size > TOPAZ_STATIC_MEMORY) {
        PrintAndLogEx(NORMAL, "Dynamic Data blocks:");
        if (topaz_read_dynamic_data() == 0) {
            PrintAndLogEx(NORMAL, "block# | offset | Data                    | Locked(y/n)");
            char line[80];
            for (uint16_t blockno = 0x0f; blockno < topaz_tag.size / 8; blockno++) {
                uint8_t *block_data = &topaz_tag.dynamic_memory[(blockno - 0x0f) * 8];
                char lockbits[9];
                for (uint16_t j = 0; j < 8; j++) {
                    sprintf(&line[3 * j], "%02x ", block_data[j]);
                    lockbits[j] = topaz_byte_is_locked(blockno * 8 + j) ? 'y' : 'n';
                }
                lockbits[8] = '\0';
                PrintAndLogEx(NORMAL, "  0x%02x | 0x%04x | %s|   %-3s", blockno, blockno * 8, line, lockbits);
            }
        }
    }
}

static void topaz_print_lifecycle_state(uint8_t *data) {
    // to be done
}

static void topaz_print_NDEF(uint8_t *data) {
    // to be done.
}

// read a Topaz tag and print some useful information
static int CmdHFTopazReader(const char *Cmd) {
    int status;
    uint8_t atqa[2];
    uint8_t rid_response[8];
    uint8_t *uid_echo = &rid_response[2];
    uint8_t rall_response[124];
    bool verbose = true;

    char ctmp = param_getchar(Cmd, 0);
    if (ctmp == 'S' || ctmp == 's') verbose = false;

    status = topaz_select(atqa, rid_response);

    if (status == -1) {
        if (verbose) PrintAndLogEx(WARNING, "Error: couldn't receive ATQA");
        return -1;
    }

    PrintAndLogEx(NORMAL, "ATQA : %02x %02x", atqa[1], atqa[0]);
    if (atqa[1] != 0x0c && atqa[0] != 0x00) {
        PrintAndLogEx(NORMAL, "Tag doesn't support the Topaz protocol.");
        topaz_switch_off_field();
        return -1;
    }

    if (status == -2) {
        PrintAndLogEx(WARNING, "Error: tag didn't answer to RID");
        topaz_switch_off_field();
        return -1;
    }

    topaz_tag.HR01[0] = rid_response[0];
    topaz_tag.HR01[1] = rid_response[1];

    // ToDo: CRC check
    PrintAndLogEx(NORMAL, "HR0  : %02x (%sa Topaz tag (%scapable of carrying a NDEF message), %s memory map)", rid_response[0],
                  (rid_response[0] & 0xF0) == 0x10 ? "" : "not ",
                  (rid_response[0] & 0xF0) == 0x10 ? "" : "not ",
                  (rid_response[0] & 0x0F) == 0x01 ? "static" : "dynamic");
    PrintAndLogEx(NORMAL, "HR1  : %02x", rid_response[1]);

    status = topaz_rall(uid_echo, rall_response);

    if (status == -1) {
        PrintAndLogEx(WARNING, "Error: tag didn't answer to RALL");
        topaz_switch_off_field();
        return -1;
    }

    memcpy(topaz_tag.uid, rall_response + 2, 7);
    PrintAndLogEx(NORMAL, "UID  : %02x %02x %02x %02x %02x %02x %02x",
                  topaz_tag.uid[6],
                  topaz_tag.uid[5],
                  topaz_tag.uid[4],
                  topaz_tag.uid[3],
                  topaz_tag.uid[2],
                  topaz_tag.uid[1],
                  topaz_tag.uid[0]);

    PrintAndLogEx(NORMAL, "       UID[6] (Manufacturer Byte) = %02x, Manufacturer: %s",
                  topaz_tag.uid[6],
                  getTagInfo(topaz_tag.uid[6]));

    memcpy(topaz_tag.data_blocks, rall_response + 2, 0x0f * 8);
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Static Data blocks 00 to 0c:");
    PrintAndLogEx(NORMAL, "block# | offset | Data                    | Locked");
    char line[80];
    for (uint16_t i = 0; i <= 0x0c; i++) {
        char lockbits[9];
        for (uint16_t j = 0; j < 8; j++) {
            sprintf(&line[3 * j], "%02x ", topaz_tag.data_blocks[i][j] /*rall_response[2 + 8*i + j]*/);
            lockbits[j] = topaz_byte_is_locked(i * 8 + j) ? 'y' : 'n';
        }
        lockbits[8] = '\0';
        PrintAndLogEx(NORMAL, "  0x%02x | 0x%02x | %s|   %-3s", i, i * 8, line, lockbits);
    }

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Static Reserved block 0d:");
    for (uint16_t j = 0; j < 8; j++) {
        sprintf(&line[3 * j], "%02x ", topaz_tag.data_blocks[0x0d][j]);
    }
    PrintAndLogEx(NORMAL, "  0x%02x |  0x%02x  | %s|   %-3s", 0x0d, 0x0d * 8, line, "n/a");

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Static Lockbits and OTP Bytes:");
    for (uint16_t j = 0; j < 8; j++) {
        sprintf(&line[3 * j], "%02x ", topaz_tag.data_blocks[0x0e][j]);
    }
    PrintAndLogEx(NORMAL, "  0x%02x |  0x%02x  | %s|   %-3s", 0x0e, 0x0e * 8, line, "n/a");

    PrintAndLogEx(NORMAL, "");

    status = topaz_print_CC(&topaz_tag.data_blocks[1][0]);

    if (status == -1) {
        PrintAndLogEx(NORMAL, "No NDEF message data present");
        topaz_switch_off_field();
        return 0;
    }

    PrintAndLogEx(NORMAL, "");
    topaz_print_control_TLVs(&topaz_tag.data_blocks[1][4]);

    PrintAndLogEx(NORMAL, "");
    topaz_print_dynamic_data();

    topaz_print_lifecycle_state(&topaz_tag.data_blocks[1][0]);

    topaz_print_NDEF(&topaz_tag.data_blocks[1][0]);

    topaz_switch_off_field();
    return 0;
}

static int CmdHFTopazSim(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    PrintAndLogEx(NORMAL, "not yet implemented");
    return 0;
}

static int CmdHFTopazCmdRaw(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    PrintAndLogEx(NORMAL, "not yet implemented. Use hf 14 raw with option -T.");
    return 0;
}

static int CmdHFTopazList(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdTraceList("topaz");
    return 0;
}

static int CmdHelp(const char *Cmd);

static command_t CommandTable[] = {
    {"help",    CmdHelp,            AlwaysAvailable, "This help"},
    {"reader",  CmdHFTopazReader,   IfPm3Iso14443a,  "Act like a Topaz reader"},
    {"sim",     CmdHFTopazSim,      IfPm3Iso14443a,  "<UID> -- Simulate Topaz tag"},
    {"sniff",   CmdHF14ASniff,      IfPm3Iso14443a,  "Sniff Topaz reader-tag communication"},
    {"raw",     CmdHFTopazCmdRaw,   IfPm3Iso14443a,  "Send raw hex data to tag"},
    {"list",    CmdHFTopazList,     AlwaysAvailable,  "List Topaz history"},
    {NULL,      NULL,               0, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return 0;
}

int CmdHFTopaz(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

int readTopazUid(void) {
    return CmdHFTopazReader("s");
}
