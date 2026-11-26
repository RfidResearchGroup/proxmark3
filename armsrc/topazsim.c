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
// Topaz (NFC Forum Type 1 Tag) simulation, after the TPZ-201 (Topaz 96) and
// BCM20203T512 (Topaz 512) data sheets, and a real Topaz 512 where they say
// nothing. The tag memory is the emulator memory, block 0 first.
//-----------------------------------------------------------------------------
#include "topazsim.h"

#include "string.h"
#include "proxmark3_arm.h"
#include "cmd.h"
#include "appmain.h"
#include "BigBuf.h"
#include "dbprint.h"
#include "util.h"
#include "iso14443a.h"
#include "crc16.h"
#include "fpga_loader.h"
#include "fpga_apis.h"
#include "protocols.h"

#define TOPAZ_BLOCK_SIZE        8
#define TOPAZ_STATIC_SIZE       120     // blocks 0 - E: a Topaz 96, and what RALL returns
#define TOPAZ_DYNAMIC_SIZE      512     // blocks 0 - 3F: a Topaz 512
#define TOPAZ_SEGMENT_SIZE      128
#define TOPAZ_SEGMENTS          (TOPAZ_DYNAMIC_SIZE / TOPAZ_SEGMENT_SIZE)

#define TOPAZ_BLOCK_UID         0x00
#define TOPAZ_BLOCK_RESERVED    0x0D
#define TOPAZ_BLOCK_LOCK        0x0E    // LOCK-0 LOCK-1 for blocks 0 - F, then OTP bits
#define TOPAZ_BLOCK_LOCK_DYN    0x0F    // OTP bits, then LOCK-2 - LOCK-7 for blocks 10 - 3F

// a command is the 7 bit command code and 8 bit operand frames, CRC included
#define TOPAZ_CMD_FRAMES        9
#define TOPAZ_CMD8_FRAMES       16
// where the UID echo is in them
#define TOPAZ_CMD_UID           3
#define TOPAZ_CMD8_UID          10

// the writes answer once the EEPROM is programmed, n * 128 + 20 (or + 84)
// carrier periods after the command. The other commands take n = 9
#define TOPAZ_FDT_N_WRITE_E     554
#define TOPAZ_FDT_N_WRITE_NE    281

// modulation of an answer, 9 bytes for each byte and 3 more, see CodeIso14443aAsTagPar()
#define TOPAZ_MOD_SIZE(n)       ((9 * (n)) + 3)
// the longest answer coded per command: READ8, the block number, 8 bytes, the CRC
#define TOPAZ_DYN_LEN           (1 + TOPAZ_BLOCK_SIZE + 2)

typedef enum {
    TOPAZ_SIM_IDLE,     // powered, waits for REQA or WUPA
    TOPAZ_SIM_READY,    // takes the proprietary commands, a Topaz has no HALT
} topaz_sim_state_t;

// what the tag does once the last frame of a command is in
typedef enum {
    TOPAZ_DO_NOTHING,   // stay silent: wrong CRC or UID echo, no such block, a barred write
    TOPAZ_DO_ANSWER,    // send s_answer
    TOPAZ_DO_WRITE,     // write, then answer
} topaz_action_t;

static uint8_t *s_mem;
static uint16_t s_size;

// the answers that do not depend on the command, coded once
static tag_response_info_t s_atqa;
static tag_response_info_t s_rid;
static tag_response_info_t s_rall;
static tag_response_info_t s_rseg[TOPAZ_SEGMENTS];
// RSEG of a segment past the memory, a Topaz 512 reads it as zeros
static tag_response_info_t s_rseg_void;
// the answer to a READ or READ8, coded for each one
static tag_response_info_t s_dyn;

// worked out while the two CRC frames come: after the last one, 1172 or 1236
// carrier periods are too few to check the CRC and code the answer
static topaz_action_t s_action;
static tag_response_info_t *s_answer;
static uint8_t s_crc[2];

// frames a command takes, 0 for a code that is none
static uint8_t topaz_cmd_frames(uint8_t code) {
    switch (code) {
        case TOPAZ_RID:
        case TOPAZ_RALL:
        case TOPAZ_READ:
        case TOPAZ_WRITE_E:
        case TOPAZ_WRITE_NE:
            return TOPAZ_CMD_FRAMES;
        case TOPAZ_RSEG:
        case TOPAZ_READ8:
        case TOPAZ_WRITE_E8:
        case TOPAZ_WRITE_NE8:
            // the dynamic memory commands of a Topaz 512
            return (s_size == TOPAZ_DYNAMIC_SIZE) ? TOPAZ_CMD8_FRAMES : 0;
        default:
            return 0;
    }
}

// LOCK-0 and LOCK-1 hold the lock bits of blocks 0 - F, a Topaz 512 keeps the
// ones of blocks 10 - 3F in LOCK-2 - LOCK-7
static bool topaz_block_locked(uint8_t block) {
    if (block < 0x10) {
        return (s_mem[(TOPAZ_BLOCK_LOCK * TOPAZ_BLOCK_SIZE) + (block >> 3)] >> (block & 7)) & 1;
    }
    block -= 0x10;
    return (s_mem[(TOPAZ_BLOCK_LOCK_DYN * TOPAZ_BLOCK_SIZE) + 2 + (block >> 3)] >> (block & 7)) & 1;
}

// WRITE-E and WRITE-E8 never touch the UID, the reserved block, or the lock and
// OTP bits an erase would clear. Nor a locked block
static bool topaz_erase_write_barred(uint8_t block) {
    return (block == TOPAZ_BLOCK_UID) ||
           ((block >= TOPAZ_BLOCK_RESERVED) && (block <= TOPAZ_BLOCK_LOCK_DYN)) ||
           topaz_block_locked(block);
}

// WRITE-NE and WRITE-NE8 are how lock and OTP bits get set, so those blocks take them
static bool topaz_write_barred(uint8_t block) {
    if ((block == TOPAZ_BLOCK_LOCK) || (block == TOPAZ_BLOCK_LOCK_DYN)) {
        return false;
    }
    return (block == TOPAZ_BLOCK_UID) || (block == TOPAZ_BLOCK_RESERVED) || topaz_block_locked(block);
}

// CRC_B after the n bytes of an answer, then its modulation
static bool topaz_seal(tag_response_info_t *answer, uint16_t n) {
    AddCrc14B(answer->response, n);
    answer->response_n = n + 2;
    return prepare_tag_modulation(answer, TOPAZ_MOD_SIZE(answer->response_n));
}

static bool topaz_alloc_answer(tag_response_info_t *answer, uint16_t len) {
    answer->response = BigBuf_calloc(len);
    answer->response_n = len;
    answer->modulation = BigBuf_calloc(TOPAZ_MOD_SIZE(len));
    return (answer->response != NULL) && (answer->modulation != NULL);
}

// RALL: HR0 HR1, blocks 0 - E
static bool topaz_code_rall(void) {
    memcpy(s_rall.response + 2, s_mem, TOPAZ_STATIC_SIZE);
    return topaz_seal(&s_rall, 2 + TOPAZ_STATIC_SIZE);
}

// RSEG: ADDS, the 16 blocks of the segment
static bool topaz_code_rseg(uint8_t seg) {
    tag_response_info_t *answer = &s_rseg[seg];
    answer->response[0] = seg << 4;
    memcpy(answer->response + 1, s_mem + (seg * TOPAZ_SEGMENT_SIZE), TOPAZ_SEGMENT_SIZE);
    return topaz_seal(answer, 1 + TOPAZ_SEGMENT_SIZE);
}

// put len bytes at pos of an answer, and the new CRC after the data of the answer
static void topaz_patch(tag_response_info_t *answer, uint16_t pos, const uint8_t *data, uint8_t len) {
    for (uint8_t i = 0; i < len; i++) {
        set_tag_modulation_byte(answer, pos + i, data[i]);
    }
    uint16_t n = answer->response_n - 2;
    uint8_t crc[2];
    compute_crc(CRC_14443_B, answer->response, n, &crc[0], &crc[1]);
    set_tag_modulation_byte(answer, n, crc[0]);
    set_tag_modulation_byte(answer, n + 1, crc[1]);
}

// a write changed a block, put it in the answers that carry it. Coding RALL and
// RSEG again took longer than the n = 281 a WRITE-NE answers at
static void topaz_written(uint8_t block) {
    const uint8_t *data = s_mem + (block * TOPAZ_BLOCK_SIZE);
    if (block <= TOPAZ_BLOCK_LOCK) {
        // RALL: HR0 HR1, then blocks 0 - E
        topaz_patch(&s_rall, 2 + (block * TOPAZ_BLOCK_SIZE), data, TOPAZ_BLOCK_SIZE);
    }
    if (s_size == TOPAZ_DYNAMIC_SIZE) {
        // RSEG: ADDS, then the 16 blocks of the segment
        uint8_t seg = block / (TOPAZ_SEGMENT_SIZE / TOPAZ_BLOCK_SIZE);
        topaz_patch(&s_rseg[seg], 1 + ((block * TOPAZ_BLOCK_SIZE) % TOPAZ_SEGMENT_SIZE), data, TOPAZ_BLOCK_SIZE);
    }
}

static bool topaz_prepare_answers(const uint8_t *hr) {

    uint8_t atqa[] = { 0x00, 0x0C };
    if (topaz_alloc_answer(&s_atqa, sizeof(atqa)) == false) {
        return false;
    }
    memcpy(s_atqa.response, atqa, sizeof(atqa));
    if (prepare_tag_modulation(&s_atqa, TOPAZ_MOD_SIZE(s_atqa.response_n)) == false) {
        return false;
    }

    // RID: HR0 HR1, UID0 - UID3
    if (topaz_alloc_answer(&s_rid, 2 + 4 + 2) == false) {
        return false;
    }
    memcpy(s_rid.response, hr, 2);
    memcpy(s_rid.response + 2, s_mem, 4);
    if (topaz_seal(&s_rid, 2 + 4) == false) {
        return false;
    }

    if (topaz_alloc_answer(&s_rall, 2 + TOPAZ_STATIC_SIZE + 2) == false) {
        return false;
    }
    memcpy(s_rall.response, hr, 2);
    if (topaz_code_rall() == false) {
        return false;
    }

    if (s_size == TOPAZ_DYNAMIC_SIZE) {
        for (uint8_t seg = 0; seg < TOPAZ_SEGMENTS; seg++) {
            if (topaz_alloc_answer(&s_rseg[seg], 1 + TOPAZ_SEGMENT_SIZE + 2) == false) {
                return false;
            }
            if (topaz_code_rseg(seg) == false) {
                return false;
            }
        }
        // the echo goes in for each command, the 128 bytes stay zero
        if (topaz_alloc_answer(&s_rseg_void, 1 + TOPAZ_SEGMENT_SIZE + 2) == false) {
            return false;
        }
        if (topaz_seal(&s_rseg_void, 1 + TOPAZ_SEGMENT_SIZE) == false) {
            return false;
        }
    }

    return topaz_alloc_answer(&s_dyn, TOPAZ_DYN_LEN);
}

// all the operands of a command are in: what the tag will do with it, the
// answer coded already when it only reads. The CRC frames are checked as they come
static void topaz_prepare(const uint8_t *cmd, uint8_t len) {

    compute_crc(CRC_14443_B, cmd, len, &s_crc[0], &s_crc[1]);
    s_action = TOPAZ_DO_NOTHING;

    // a wrong UID echo ends the command too. RID has none, it is how a reader
    // learns the UID; its operands "shall be" zero, a real tag answers any
    uint8_t uid_echo = (len == (TOPAZ_CMD8_FRAMES - 2)) ? TOPAZ_CMD8_UID : TOPAZ_CMD_UID;
    if ((cmd[0] != TOPAZ_RID) && (memcmp(cmd + uid_echo, s_mem, 4) != 0)) {
        return;
    }

    switch (cmd[0]) {
        case TOPAZ_RID: {
            s_answer = &s_rid;
            s_action = TOPAZ_DO_ANSWER;
            break;
        }
        case TOPAZ_RALL: {
            s_answer = &s_rall;
            s_action = TOPAZ_DO_ANSWER;
            break;
        }
        case TOPAZ_READ: {
            // ADD is the offset in memory, block and byte. A Topaz 512 has a
            // block F and drops bit 7, in the echo too; a Topaz 96 has 0 - E
            uint8_t add = cmd[1];
            if (s_size == TOPAZ_DYNAMIC_SIZE) {
                add &= 0x7F;
            } else if ((add / TOPAZ_BLOCK_SIZE) > TOPAZ_BLOCK_LOCK) {
                break;
            }
            s_dyn.response[0] = add;
            s_dyn.response[1] = s_mem[add];
            if (topaz_seal(&s_dyn, 2)) {
                s_answer = &s_dyn;
                s_action = TOPAZ_DO_ANSWER;
            }
            break;
        }
        case TOPAZ_WRITE_E:
        case TOPAZ_WRITE_NE:
        case TOPAZ_WRITE_E8:
        case TOPAZ_WRITE_NE8: {
            // ADD is 0, the block 0 - E and the byte 0 - 7: its offset in memory;
            // ADD8 is the block 0 - 3F
            bool eight = (cmd[0] == TOPAZ_WRITE_E8) || (cmd[0] == TOPAZ_WRITE_NE8);
            uint8_t block = eight ? cmd[1] : (cmd[1] / TOPAZ_BLOCK_SIZE);
            if (block > (eight ? ((TOPAZ_DYNAMIC_SIZE / TOPAZ_BLOCK_SIZE) - 1) : TOPAZ_BLOCK_LOCK)) {
                break;
            }
            bool erase = (cmd[0] == TOPAZ_WRITE_E) || (cmd[0] == TOPAZ_WRITE_E8);
            bool barred = erase ? topaz_erase_write_barred(block) : topaz_write_barred(block);
            s_action = barred ? TOPAZ_DO_NOTHING : TOPAZ_DO_WRITE;
            break;
        }
        case TOPAZ_RSEG: {
            // ADDS has the segment in bits 7 - 4: a Topaz 512 echoes the whole
            // byte and reads the segments past its memory as zeros
            uint8_t seg = cmd[1] >> 4;
            tag_response_info_t *answer = (seg < TOPAZ_SEGMENTS) ? &s_rseg[seg] : &s_rseg_void;
            if (answer->response[0] != cmd[1]) {
                topaz_patch(answer, 0, &cmd[1], 1);
            }
            s_answer = answer;
            s_action = TOPAZ_DO_ANSWER;
            break;
        }
        case TOPAZ_READ8: {
            // ADD8 is the block: a Topaz 512 echoes it and reads the blocks past
            // its memory as zeros
            uint8_t block = cmd[1];
            s_dyn.response[0] = block;
            if (block < (TOPAZ_DYNAMIC_SIZE / TOPAZ_BLOCK_SIZE)) {
                memcpy(s_dyn.response + 1, s_mem + (block * TOPAZ_BLOCK_SIZE), TOPAZ_BLOCK_SIZE);
            } else {
                memset(s_dyn.response + 1, 0, TOPAZ_BLOCK_SIZE);
            }
            if (topaz_seal(&s_dyn, 1 + TOPAZ_BLOCK_SIZE)) {
                s_answer = &s_dyn;
                s_action = TOPAZ_DO_ANSWER;
            }
            break;
        }
        default: {
            break;
        }
    }
}

// the write of a valid command: the memory, the answers that carry it, then
// the answer, once the EEPROM of a real tag would be programmed
static void topaz_write(const uint8_t *cmd) {

    uint8_t resp[1 + TOPAZ_BLOCK_SIZE + 2] = {0};
    uint8_t len;
    uint8_t block;
    // no erase: bits can be set, not cleared
    bool erase = (cmd[0] == TOPAZ_WRITE_E) || (cmd[0] == TOPAZ_WRITE_E8);

    if ((cmd[0] == TOPAZ_WRITE_E) || (cmd[0] == TOPAZ_WRITE_NE)) {
        uint8_t add = cmd[1];
        block = add / TOPAZ_BLOCK_SIZE;
        s_mem[add] = erase ? cmd[2] : (s_mem[add] | cmd[2]);
        // the byte as it is in memory now
        resp[0] = add;
        resp[1] = s_mem[add];
        len = 2;
    } else {
        block = cmd[1];
        uint8_t *data = &s_mem[block * TOPAZ_BLOCK_SIZE];
        for (uint8_t i = 0; i < TOPAZ_BLOCK_SIZE; i++) {
            data[i] = erase ? cmd[2 + i] : (data[i] | cmd[2 + i]);
        }
        // the block as it is in memory now
        resp[0] = block;
        memcpy(resp + 1, data, TOPAZ_BLOCK_SIZE);
        len = 1 + TOPAZ_BLOCK_SIZE;
    }
    AddCrc14B(resp, len);

    topaz_written(block);
    EmSendCmdFdt(resp, len + 2, erase ? TOPAZ_FDT_N_WRITE_E : TOPAZ_FDT_N_WRITE_NE);
}

void SimulateTopazTag(const topaz_sim_t *params) {

    s_size = params->size;
    if ((s_size != TOPAZ_STATIC_SIZE) && (s_size != TOPAZ_DYNAMIC_SIZE)) {
        Dbprintf("Topaz sim, %u bytes of memory. A Topaz has 120 or 512", s_size);
        reply_ng(CMD_HF_TOPAZ_SIMULATE, PM3_EINVARG, NULL, 0);
        return;
    }

    // keep_EM: a bitstream download frees and clears BigBuf, the tag memory with it
    FpgaDownloadAndGo_keep_EM(FPGA_BITSTREAM_HF);
    BigBuf_free_keep_EM();

    // the answers come out of the BigBuf the trace is in: clear it first
    clear_trace();

    s_mem = BigBuf_get_EM_addr();
    if (s_mem == NULL) {
        reply_ng(CMD_HF_TOPAZ_SIMULATE, PM3_EMALLOC, NULL, 0);
        return;
    }

    if (topaz_prepare_answers(params->hr) == false) {
        Dbprintf("Topaz sim, not enough memory for the answers");
        BigBuf_free_keep_EM();
        reply_ng(CMD_HF_TOPAZ_SIMULATE, PM3_EMALLOC, NULL, 0);
        return;
    }

    // the CRC table is built now, not while a reader waits for an answer
    init_table(CRC_14443_B);

    iso14443a_setup(FPGA_HF_ISO14443A_TAGSIM_LISTEN);

    uint8_t rx[MAX_FRAME_SIZE] = {0};
    uint8_t rx_par[MAX_PARITY_SIZE] = {0};

    // the frames of the command coming in, one byte each
    uint8_t cmd[TOPAZ_CMD8_FRAMES] = {0};
    uint8_t cmd_len = 0;
    uint8_t cmd_frames = 0;     // frames the command takes, 0 when none is coming in

    topaz_sim_state_t state = TOPAZ_SIM_IDLE;
    const tUart14a *uart = GetUart14a();
    bool field_on = true;
    uint32_t idle_counter = 0;
    uint32_t cmdcount = 0;
    int retval = PM3_SUCCESS;

    set_tracing(true);
    LED_A_ON();

    for (;;) {

        WDT_HIT();

        // with no field EmGetCmd() returns before its host stop check
        if ((field_on == false) || (idle_counter >= 1000)) {
            idle_counter = 0;
            if (data_available()) {
                retval = PM3_EOPABORTED;
                break;
            }
        } else {
            idle_counter++;
        }

        if (BUTTON_PRESS()) {
            retval = PM3_EOPABORTED;
            break;
        }

        uint16_t len = 0;
        int res = EmGetCmd(rx, sizeof(rx), &len, rx_par);
        if (res == 2) {
            // the reader took its field away, the tag lost power
            if (field_on) {
                field_on = false;
                state = TOPAZ_SIM_IDLE;
                cmd_frames = 0;
                LED_A_OFF();
            }
            continue;
        }
        if (res == 1) {
            retval = PM3_EOPABORTED;
            break;
        }

        if (field_on == false) {
            field_on = true;
            LED_A_ON();
        }

        if (len == 0) {
            continue;
        }

        // a 7 bit short frame, or 8 bits without parity, see MillerDecoding()
        bool short_frame = (len == 1) && (uart->bitCount == 7);
        bool operand_frame = (len == 1) && (uart->bitCount == -1);

        if (short_frame && ((rx[0] == TOPAZ_REQA) || (rx[0] == TOPAZ_WUPA))) {
            cmd_frames = 0;
            state = TOPAZ_SIM_READY;
            EmSendPrecompiledCmd(&s_atqa);
            continue;
        }

        if (short_frame && (state == TOPAZ_SIM_READY) && topaz_cmd_frames(rx[0])) {
            // a new command, whatever was coming in before
            cmd[0] = rx[0];
            cmd_len = 1;
            cmd_frames = topaz_cmd_frames(rx[0]);
        } else if (operand_frame && cmd_frames) {
            cmd[cmd_len++] = rx[0];
            if (cmd_len == (cmd_frames - 2)) {
                topaz_prepare(cmd, cmd_len);
            } else if (cmd_len > (cmd_frames - 2)) {
                // a wrong CRC ends the command, the tag waits in READY for the next one
                if (rx[0] != s_crc[cmd_len - (cmd_frames - 1)]) {
                    s_action = TOPAZ_DO_NOTHING;
                }
                if (cmd_len == cmd_frames) {
                    cmd_frames = 0;
                    cmdcount++;
                    // an answer traces the last frame along with it
                    if (s_action == TOPAZ_DO_ANSWER) {
                        EmSendPrecompiledCmd(s_answer);
                        continue;
                    }
                    if (s_action == TOPAZ_DO_WRITE) {
                        topaz_write(cmd);
                        continue;
                    }
                }
            }
        } else {
            // HLTA, ANTICOLL and the like, the tag ignores them
            cmd_frames = 0;
        }

        iso14a_sim_trace_rx(rx);
    }

    switch_off();
    set_tracing(false);
    BigBuf_free_keep_EM();

    if (g_dbglevel >= DBG_EXTENDED) {
        Dbprintf("-[ commands received %u ]-", cmdcount);
    }

    reply_ng(CMD_HF_TOPAZ_SIMULATE, retval, NULL, 0);
}
