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
// HID Config Card (JCOP / GlobalPlatform SCP02) simulation helpers.
// Called from iso14443a.c; isolated here to keep HID-specific logic separate.
//-----------------------------------------------------------------------------
#ifndef SECC_H__
#define SECC_H__

#include "common.h"
#include "mifare.h"   // tag_response_info_t

// ---------------------------------------------------------------------------
// Shared payload structs (used by both ARM and client via CMD_HF_HIDCONFIG_SIM)
// ---------------------------------------------------------------------------

// Sized so the full hid_sim_payload_t (including default_resp[]) stays within
// PM3_CMD_DATA_SIZE (512). Adding/removing fields here requires re-checking
// sizeof(hid_sim_payload_t) against the NG transport limit.
#define HID_APDU_MAX_ENTRIES 7
#define HID_APDU_MAX_CMD     20   // max APDU command bytes to prefix-match
#define HID_APDU_MAX_RESP    32   // max response bytes (without PCB/CID/CRC)
#define HID_APDU_MASK_LEN    3    // ceil(HID_APDU_MAX_CMD / 8): bitmask for wildcard bytes

// One custom APDU override entry: if the incoming APDU matches the pattern,
// respond with resp[0..resp_len-1] (raw APDU payload).
// apdu_mask bit i=1: byte i must match apdu[i] exactly.
// apdu_mask bit i=0: wildcard — apdu[i] selects type:
//   0x00 = match any single byte  ("**" in JSON)
//   0x01 = length-prefix skip: read length byte N, skip N+1 bytes total ("##" in JSON)
typedef struct {
    uint8_t apdu[HID_APDU_MAX_CMD];
    uint8_t apdu_len;
    uint8_t apdu_mask[HID_APDU_MASK_LEN];
    uint8_t resp[HID_APDU_MAX_RESP];
    uint8_t resp_len;
} PACKED hid_apdu_entry_t;

// Full simulation payload sent from client to ARM via CMD_HF_HIDCONFIG_SIM.
// ATQA is stored big-endian: atqa[0] = high byte (used as rATQA[0] in SimulateIso14443aInit).
typedef struct {
    uint8_t  tagtype;
    uint16_t flags;
    uint8_t  uid[10];
    uint8_t  exitAfter;
    uint8_t  atqa[2];          // ATQA override (big-endian: [0]=high, [1]=low)
    uint8_t  sak;              // SAK override
    uint8_t  scp02_key[16];    // SCP02 master key (from JSON "SCP02Key")
    uint8_t  kdd[10];          // 10-byte Key Diversification Data returned in INITIALIZE UPDATE.
    // All-zero = legacy "no diversification" mode (scp02_key used directly).
    // Any non-zero value enables VISA-2 diversification of scp02_key per
    // SCP02 type (0x01=ENC, 0x02=MAC) on every handshake.
    uint8_t  kvn;              // Key Version Number emitted in INIT UPDATE response (JSON "KVN", default 0x01).
    uint8_t  ats[20];          // ATS bytes without CRC (from JSON "ATS")
    uint8_t  ats_len;          // actual number of valid bytes in ats[]
    uint8_t  default_resp[HID_APDU_MAX_RESP]; // fallback reply for unmatched APDUs (from JSON "DefaultResponse")
    uint8_t  default_resp_len; // 0 = none configured (handler will skip the fallback)
    uint8_t  apdu_count;
    hid_apdu_entry_t apdu_table[HID_APDU_MAX_ENTRIES];
} PACKED hid_sim_payload_t;

// ---------------------------------------------------------------------------
// Sniff payload (sent from client to ARM via CMD_HF_HIDCONFIG_SNIFF).
// When apdu_len == 0 the default A0 D4 00 00 00 pattern is used.
// When resp_len == 0 the default 00 00 90 00 response is used.
// ---------------------------------------------------------------------------

#define HID_JAM_MAX_APDU  32
#define HID_JAM_MAX_RESP  32

typedef struct {
    uint8_t param;                      // sniff flags: 0x01=card-triggered, 0x02=reader-triggered, 0x04=jam
    uint8_t apdu[HID_JAM_MAX_APDU];    // APDU to jam (raw bytes after PCB/CID stripped)
    uint8_t apdu_len;                   // 0 = use default (A0 D4 00 00 00)
    uint8_t resp[HID_JAM_MAX_RESP];    // jam response payload (raw APDU, without PCB/CID/CRC)
    uint8_t resp_len;                   // 0 = use default (00 00 90 00)
} PACKED hid_sniff_payload_t;

// Load a custom APDU response table into static storage (call before sim loop).
void hid_config_card_set_apdu_table(const hid_apdu_entry_t *table, uint8_t count);

// Run a complete HID Config Card simulation using payload received from the client.
void SimulateHIDConfigCard(const hid_sim_payload_t *payload);

// Sniff ISO 14443-A with optional jamming (param bit 0x04).
// When apdu_len > 0 the supplied APDU pattern overrides the default A0 D4 00 00 00.
// When resp_len > 0 the supplied response overrides the default 00 00 90 00.
void SniffHIDConfigCard(const hid_sniff_payload_t *payload);

// Handle an I-block received during HID Config Card (tagType=16) simulation.
// Fills dynamic_response_info with the appropriate response payload (without CRC).
// Returns true if a response was prepared, false if the command was not handled.
bool hid_config_card_handle_iblock(const uint8_t *cmd, int len, tag_response_info_t *response_info);

// CID-aware ISO 14443-4 APDU exchange for HID Config Card reader interaction.
// Sends I-blocks with PCB=0x0A (CID present, CID=0) as negotiated in RATS.
// Strips PCB+CID from received responses. API mirrors iso14_apdu().
int hid_config_card_iso14_apdu(uint8_t *cmd, uint16_t cmd_len, bool send_chaining, void *data, uint16_t data_len, uint8_t *res);

// Handle a sniff-mode jam: inspect cmd and, if it matches A0 D4 00 00 00,
// transmit the jam response and restore sniffer FPGA mode + re-arm DMA.
// dma_buf: pointer to the DMA ring buffer start (passed to FpgaSetupSscDma).
// Returns true if the frame was jammed; caller must then reset its data pointer
// back to the DMA buffer start and continue the sniff loop.
bool hid_config_card_jam(const uint8_t *cmd, int len, uint8_t *dma_buf);

#endif // SECC_H__
