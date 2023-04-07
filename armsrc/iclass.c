//-----------------------------------------------------------------------------
// Copyright (C) Gerhard de Koning Gans - May 2008
// Contribution made during a security research at Radboud University Nijmegen
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
// Routines to support iClass.
//-----------------------------------------------------------------------------
#include "iclass.h"

#include "proxmark3_arm.h"
#include "cmd.h"
// Needed for CRC in emulation mode;
// same construction as in ISO 14443;
// different initial value (CRC_ICLASS)
#include "crc16.h"
#include "optimized_cipher.h"

#include "appmain.h"
#include "BigBuf.h"
#include "fpgaloader.h"
#include "string.h"
#include "util.h"
#include "dbprint.h"
#include "protocols.h"
#include "ticks.h"
#include "iso15693.h"
#include "iclass_cmd.h"              /* iclass_card_select_t struct */

static uint8_t get_pagemap(const picopass_hdr_t *hdr) {
    return (hdr->conf.fuses & (FUSE_CRYPT0 | FUSE_CRYPT1)) >> 3;
}

// The length of a received command will in most cases be no more than 18 bytes.
// we expect max 34 (32+2) bytes as tag answer (response to READ4)
#ifndef ICLASS_BUFFER_SIZE
#define ICLASS_BUFFER_SIZE     34 + 2
#endif

#ifndef ICLASS_16KS_SIZE
#define ICLASS_16KS_SIZE       0x100 * 8
#endif

// iCLASS has a slightly different timing compared to ISO15693. According to the picopass data sheet the tag response is expected 330us after
// the reader command. This is measured from end of reader EOF to first modulation of the tag's SOF which starts with a 56,64us unmodulated period.
// 330us = 140 ssp_clk cycles @ 423,75kHz when simulating.
// 56,64us = 24 ssp_clk_cycles
#define DELAY_ICLASS_VCD_TO_VICC_SIM     (140 - 26) // (140 - 24)

// times in ssp_clk_cycles @ 3,3625MHz when acting as reader
#define DELAY_ICLASS_VICC_TO_VCD_READER  DELAY_ISO15693_VICC_TO_VCD_READER

// times in samples @ 212kHz when acting as reader
#define ICLASS_READER_TIMEOUT_ACTALL     330 // 1558us, nominal 330us + 7slots*160us = 1450us
#define ICLASS_READER_TIMEOUT_UPDATE    3390 // 16000us, nominal 4-15ms
#define ICLASS_READER_TIMEOUT_OTHERS      80 // 380us, nominal 330us

#define AddCrc(data, len) compute_crc(CRC_ICLASS, (data), (len), (data)+(len), (data)+(len)+1)


/*
* CARD TO READER
* in ISO15693-2 mode -  Manchester
* in ISO 14443b - BPSK coding
*
* Timings:
*  ISO 15693-2
*           Tout = 330 µs, Tprog 1 = 4 to 15 ms, Tslot = 330 µs + (number of slots x 160 µs)
*  ISO 14443a
*           Tout = 100 µs, Tprog = 4 to 15 ms, Tslot = 100 µs+ (number of slots x 80 µs)
*  ISO 14443b
            Tout = 76 µs, Tprog = 4 to 15 ms, Tslot = 119 µs+ (number of slots x 150 µs)
*
*
*  So for current implementation in ISO15693, its 330 µs from end of reader, to start of card.
*/

//=============================================================================
// a `sniffer' for iClass communication
// Both sides of communication!
//=============================================================================
void SniffIClass(uint8_t jam_search_len, uint8_t *jam_search_string) {
    SniffIso15693(jam_search_len, jam_search_string, true);
}

static void rotateCSN(const uint8_t *original_csn, uint8_t *rotated_csn) {
    for (uint8_t i = 0; i < 8; i++) {
        rotated_csn[i] = (original_csn[i] >> 3) | (original_csn[(i + 1) % 8] << 5);
    }
}

// Encode SOF only
static void CodeIClassTagSOF(void) {
    tosend_reset();
    tosend_t *ts = get_tosend();
    ts->buf[++ts->max] = 0x1D;
    ts->max++;
}

/*
 * SOF comprises 3 parts;
 * * An unmodulated time of 56.64 us
 * * 24 pulses of 423.75 kHz (fc/32)
 * * A logic 1, which starts with an unmodulated time of 18.88us
 *   followed by 8 pulses of 423.75kHz (fc/32)
 *
 *
 * EOF comprises 3 parts:
 * - A logic 0 (which starts with 8 pulses of fc/32 followed by an unmodulated
 *   time of 18.88us.
 * - 24 pulses of fc/32
 * - An unmodulated time of 56.64 us
 *
 *
 * A logic 0 starts with 8 pulses of fc/32
 * followed by an unmodulated time of 256/fc (~18,88us).
 *
 * A logic 0 starts with unmodulated time of 256/fc (~18,88us) followed by
 * 8 pulses of fc/32 (also 18.88us)
 *
 * The mode FPGA_HF_SIMULATOR_MODULATE_424K_8BIT which we use to simulate tag,
 * works like this.
 * - A 1-bit input to the FPGA becomes 8 pulses on 423.5kHz (fc/32) (18.88us).
 * - A 0-bit input to the FPGA becomes an unmodulated time of 18.88us
 *
 * In this mode
 * SOF can be written as 00011101 = 0x1D
 * EOF can be written as 10111000 = 0xb8
 * logic 1 be written as 01 = 0x1
 * logic 0 be written as 10 = 0x2
 *
 *
 */

/**
 * @brief SimulateIClass simulates an iClass card.
 * @param arg0 type of simulation
 *          - 0 uses the first 8 bytes in usb data as CSN
 *          - 2 "dismantling iclass"-attack. This mode iterates through all CSN's specified
 *          in the usb data. This mode collects MAC from the reader, in order to do an offline
 *          attack on the keys. For more info, see "dismantling iclass" and proxclone.com.
 *          - Other : Uses the default CSN (031fec8af7ff12e0)
 * @param arg1 - number of CSN's contained in datain (applicable for mode 2 only)
 * @param arg2
 * @param datain
 */
// turn off afterwards
void SimulateIClass(uint32_t arg0, uint32_t arg1, uint32_t arg2, uint8_t *datain) {
    iclass_simulate(arg0, arg1, arg2, datain, NULL, NULL);
}

void iclass_simulate(uint8_t sim_type, uint8_t num_csns, bool send_reply, uint8_t *datain, uint8_t *dataout, uint16_t *dataoutlen) {

    LEDsoff();

    Iso15693InitTag();

    clear_trace();

    // only logg if we are called from the client.
    set_tracing(send_reply);

    //Use the emulator memory for SIM
    uint8_t *emulator = BigBuf_get_EM_addr();
    uint8_t mac_responses[PM3_CMD_DATA_SIZE] = { 0 };

    if (sim_type == ICLASS_SIM_MODE_CSN) {
        // Use the CSN from commandline
        memcpy(emulator, datain, 8);
        do_iclass_simulation(ICLASS_SIM_MODE_CSN, NULL);

    } else if (sim_type == ICLASS_SIM_MODE_CSN_DEFAULT) {
        //Default CSN
        uint8_t csn[] = { 0x03, 0x1f, 0xec, 0x8a, 0xf7, 0xff, 0x12, 0xe0 };
        // Use the CSN from commandline
        memcpy(emulator, csn, 8);
        do_iclass_simulation(ICLASS_SIM_MODE_CSN, NULL);

    } else if (sim_type == ICLASS_SIM_MODE_READER_ATTACK) {

        Dbprintf("going into attack mode, %d CSNS sent", num_csns);
        // In this mode, a number of csns are within datain. We'll simulate each one, one at a time
        // in order to collect MAC's from the reader. This can later be used in an offlne-attack
        // in order to obtain the keys, as in the "dismantling iclass"-paper.
#define EPURSE_MAC_SIZE 16
        int i = 0;
        for (; i < num_csns && i * EPURSE_MAC_SIZE + 8 < PM3_CMD_DATA_SIZE; i++) {

            memcpy(emulator, datain + (i * 8), 8);

            if (do_iclass_simulation(ICLASS_SIM_MODE_EXIT_AFTER_MAC, mac_responses + i * EPURSE_MAC_SIZE)) {

                if (dataoutlen)
                    *dataoutlen = i * EPURSE_MAC_SIZE;

                // Button pressed
                if (send_reply)
                    reply_old(CMD_ACK, CMD_HF_ICLASS_SIMULATE, i, 0, mac_responses, i * EPURSE_MAC_SIZE);
                goto out;
            }
        }
        if (dataoutlen)
            *dataoutlen = i * EPURSE_MAC_SIZE;

        if (send_reply)
            reply_old(CMD_ACK, CMD_HF_ICLASS_SIMULATE, i, 0, mac_responses, i * EPURSE_MAC_SIZE);

    } else if (sim_type == ICLASS_SIM_MODE_FULL) {

        //This is 'full sim' mode, where we use the emulator storage for data.
        //ie:  BigBuf_get_EM_addr should be previously filled with data from the "eload" command
        picopass_hdr_t *hdr = (picopass_hdr_t *)BigBuf_get_EM_addr();
        uint8_t pagemap = get_pagemap(hdr);
        if (pagemap == PICOPASS_NON_SECURE_PAGEMODE) {
            do_iclass_simulation_nonsec();
        } else {
            do_iclass_simulation(ICLASS_SIM_MODE_FULL, NULL);
        }

    } else if (sim_type == ICLASS_SIM_MODE_CONFIG_CARD) {

        // config card
        do_iclass_simulation(ICLASS_SIM_MODE_FULL, NULL);
        // swap bin

    } else if (sim_type == ICLASS_SIM_MODE_READER_ATTACK_KEYROLL) {

        // This is the KEYROLL version of sim 2.
        // the collected data (mac_response) is doubled out since we are trying to collect both keys in the keyroll process.
        // Keyroll iceman  9 csns * 8 * 2 = 144
        // keyroll CARL55  15csns * 8 * 2 = 15 * 8 * 2 = 240
        Dbprintf("going into attack keyroll mode, %d CSNS sent", num_csns);
        // In this mode, a number of csns are within datain. We'll simulate each one, one at a time
        // in order to collect MAC's from the reader. This can later be used in an offlne-attack
        // in order to obtain the keys, as in the "dismantling iclass"-paper.

        // keyroll mode,   reader swaps between old key and new key alternatively when fail a authentication.
        // attack below is same as SIM 2, but we run the CSN twice to collected the mac for both keys.
        int i = 0;
        // The usb data is 512 bytes, fitting 65 8-byte CSNs in there.  iceman fork uses 9 CSNS
        for (; i < num_csns && i * EPURSE_MAC_SIZE + 8 < PM3_CMD_DATA_SIZE; i++) {

            memcpy(emulator, datain + (i * 8), 8);

            // keyroll 1
            if (do_iclass_simulation(ICLASS_SIM_MODE_EXIT_AFTER_MAC, mac_responses + i * EPURSE_MAC_SIZE)) {

                if (dataoutlen)
                    *dataoutlen = i * EPURSE_MAC_SIZE * 2;

                if (send_reply)
                    reply_old(CMD_ACK, CMD_HF_ICLASS_SIMULATE, i * 2, 0, mac_responses, i * EPURSE_MAC_SIZE * 2);

                // Button pressed
                goto out;
            }

            // keyroll 2
            if (do_iclass_simulation(ICLASS_SIM_MODE_EXIT_AFTER_MAC, mac_responses + (i + num_csns) * EPURSE_MAC_SIZE)) {

                if (dataoutlen)
                    *dataoutlen = i * EPURSE_MAC_SIZE * 2;

                if (send_reply)
                    reply_old(CMD_ACK, CMD_HF_ICLASS_SIMULATE, i * 2, 0, mac_responses, i * EPURSE_MAC_SIZE * 2);

                // Button pressed
                goto out;
            }
        }

        if (dataoutlen)
            *dataoutlen = i * EPURSE_MAC_SIZE * 2;

        // double the amount of collected data.
        if (send_reply)
            reply_old(CMD_ACK, CMD_HF_ICLASS_SIMULATE, i * 2, 0, mac_responses, i * EPURSE_MAC_SIZE * 2);

    } else {
        // We may want a mode here where we hardcode the csns to use (from proxclone).
        // That will speed things up a little, but not required just yet.
        DbpString("the mode is not implemented, reserved for future use");
    }

out:
    if (dataout && dataoutlen)
        memcpy(dataout, mac_responses, *dataoutlen);

    switch_off();
    BigBuf_free_keep_EM();
}

/**
 * Simulation assumes a SECURE PAGE simulation with authentication and application areas.
 *
 *
 * @brief Does the actual simulation
 * @param csn - csn to use
 * @param breakAfterMacReceived if true, returns after reader MAC has been received.
 */
int do_iclass_simulation(int simulationMode, uint8_t *reader_mac_buf) {

    // free eventually allocated BigBuf memory
    BigBuf_free_keep_EM();

    uint16_t page_size = 32 * 8;
    uint8_t current_page = 0;

    // maintain cipher states for both credit and debit key for each page
    State_t cipher_state_KD[8];
    State_t cipher_state_KC[8];
    State_t *cipher_state = &cipher_state_KD[0];

    uint8_t *emulator = BigBuf_get_EM_addr();
    uint8_t *csn = emulator;

    // CSN followed by two CRC bytes
    uint8_t anticoll_data[10] = { 0 };
    uint8_t csn_data[10] = { 0 };
    memcpy(csn_data, csn, sizeof(csn_data));

    // Construct anticollision-CSN
    rotateCSN(csn_data, anticoll_data);

    // Compute CRC on both CSNs
    AddCrc(anticoll_data, 8);
    AddCrc(csn_data, 8);

    uint8_t diversified_kd[8] = { 0 };
    uint8_t diversified_kc[8] = { 0 };
    uint8_t *diversified_key = diversified_kd;

    // configuration block
    uint8_t conf_block[10] = {0x12, 0xFF, 0xFF, 0xFF, 0x7F, 0x1F, 0xFF, 0x3C, 0x00, 0x00};

    // e-Purse
    uint8_t card_challenge_data[8] = { 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

    // AIA
    uint8_t aia_data[10] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00};

    if (simulationMode == ICLASS_SIM_MODE_FULL) {

        memcpy(conf_block, emulator + (8 * 1), 8);            // blk 1
        memcpy(card_challenge_data, emulator + (8 * 2), 8); // e-purse, blk 2
        memcpy(diversified_kd, emulator + (8 * 3), 8);      // Kd, blk 3
        memcpy(diversified_kc, emulator + (8 * 4), 8);      // Kc, blk 4

        // (iceman) this only works for 2KS / 16KS tags.
        // Use application data from block 5
        memcpy(aia_data, emulator + (8 * 5), 8);
    }

    AddCrc(conf_block, 8);
    AddCrc(aia_data, 8);

    // set epurse of sim2,4 attack
    if (reader_mac_buf != NULL) {
        memcpy(reader_mac_buf, card_challenge_data, 8);
    }

    if ((conf_block[5] & 0x80) == 0x80) {
        page_size = 256 * 8;
    }

    // From PicoPass DS:
    // When the page is in personalization mode this bit is equal to 1.
    // Once the application issuer has personalized and coded its dedicated areas, this bit must be set to 0:
    // the page is then "in application mode".
    bool personalization_mode = conf_block[7] & 0x80;

    uint8_t block_wr_lock = conf_block[3];

    // chip memory may be divided in 8 pages
    uint8_t max_page = ((conf_block[4] & 0x10) == 0x10) ? 0 : 7;

    // pre-calculate the cipher states, feeding it the CC
    cipher_state_KD[0] = opt_doTagMAC_1(card_challenge_data, diversified_kd);
    cipher_state_KC[0] = opt_doTagMAC_1(card_challenge_data, diversified_kc);

    if (simulationMode == ICLASS_SIM_MODE_FULL) {

        for (int i = 1; i < max_page; i++) {

            uint8_t *epurse = emulator + (i * page_size) + (8 * 2);
            uint8_t *kd = emulator + (i * page_size) + (8 * 3);
            uint8_t *kc = emulator + (i * page_size) + (8 * 4);

            cipher_state_KD[i] = opt_doTagMAC_1(epurse, kd);
            cipher_state_KC[i] = opt_doTagMAC_1(epurse, kc);
        }
    }

    // Anti-collision process:
    // Reader 0a
    // Tag    0f
    // Reader 0c
    // Tag    anticoll. CSN
    // Reader 81 anticoll. CSN
    // Tag    CSN

    uint8_t *modulated_response = NULL;
    int modulated_response_size;
    uint8_t *trace_data = NULL;
    int trace_data_size;

    // Respond SOF -- takes 1 bytes
    uint8_t *resp_sof = BigBuf_malloc(1);
    int resp_sof_len;

    // Anticollision CSN (rotated CSN)
    // 22: Takes 2 bytes for SOF/EOF and 10 * 2 = 20 bytes (2 bytes/byte)
    uint8_t *resp_anticoll = BigBuf_malloc(22);
    int resp_anticoll_len;

    // CSN (block 0)
    // 22: Takes 2 bytes for SOF/EOF and 10 * 2 = 20 bytes (2 bytes/byte)
    uint8_t *resp_csn = BigBuf_malloc(22);
    int resp_csn_len;

    // configuration (blk 1) PICOPASS 2ks
    uint8_t *resp_conf = BigBuf_malloc(22);
    int resp_conf_len;

    // e-Purse (blk 2)
    // 18: Takes 2 bytes for SOF/EOF and 8 * 2 = 16 bytes (2 bytes/bit)
    uint8_t *resp_cc = BigBuf_malloc(18);
    int resp_cc_len;

    // Kd, Kc (blocks 3 and 4). Cannot be read. Always respond with 0xff bytes only
    uint8_t *resp_ff = BigBuf_malloc(22);
    int resp_ff_len;
    uint8_t ff_data[10] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00};
    AddCrc(ff_data, 8);

    // Application Issuer Area  (blk 5)
    uint8_t *resp_aia = BigBuf_malloc(22);
    int resp_aia_len;

    // receive command
    uint8_t *receivedCmd = BigBuf_malloc(MAX_FRAME_SIZE);

    // Prepare card messages
    tosend_t *ts = get_tosend();

    // First card answer: SOF
    CodeIClassTagSOF();
    memcpy(resp_sof, ts->buf, ts->max);
    resp_sof_len = ts->max;

    // Anticollision CSN
    CodeIso15693AsTag(anticoll_data, sizeof(anticoll_data));
    memcpy(resp_anticoll, ts->buf, ts->max);
    resp_anticoll_len = ts->max;

    // CSN (block 0)
    CodeIso15693AsTag(csn_data, sizeof(csn_data));
    memcpy(resp_csn, ts->buf, ts->max);
    resp_csn_len = ts->max;

    // Configuration (block 1)
    CodeIso15693AsTag(conf_block, sizeof(conf_block));
    memcpy(resp_conf, ts->buf, ts->max);
    resp_conf_len = ts->max;

    // e-Purse (block 2)
    CodeIso15693AsTag(card_challenge_data, sizeof(card_challenge_data));
    memcpy(resp_cc, ts->buf, ts->max);
    resp_cc_len = ts->max;

    // Kd, Kc (blocks 3 and 4)
    CodeIso15693AsTag(ff_data, sizeof(ff_data));
    memcpy(resp_ff, ts->buf, ts->max);
    resp_ff_len = ts->max;

    // Application Issuer Area (block 5)
    CodeIso15693AsTag(aia_data, sizeof(aia_data));
    memcpy(resp_aia, ts->buf, ts->max);
    resp_aia_len = ts->max;

    //This is used for responding to READ-block commands or other data which is dynamically generated
    //First the 'trace'-data, not encoded for FPGA
    uint8_t *data_generic_trace = BigBuf_malloc(34); // 32 bytes data + 2byte CRC is max tag answer

    //Then storage for the modulated data
    //Each bit is doubled when modulated for FPGA, and we also have SOF and EOF (2 bytes)
    uint8_t *data_response = BigBuf_malloc((34 * 2) + 3);

    enum { IDLE, ACTIVATED, SELECTED, HALTED } chip_state = IDLE;

    bool button_pressed = false;
    uint8_t cmd, options, block;
    int len, kc_attempt = 0;
    bool exit_loop = false;
    bool using_kc = false;

    while (exit_loop == false) {
        WDT_HIT();

        // Now look at the reader command and provide appropriate responses
        // default is no response:
        modulated_response = NULL;
        modulated_response_size = 0;
        trace_data = NULL;
        trace_data_size = 0;

        uint32_t reader_eof_time = 0;
        len = GetIso15693CommandFromReader(receivedCmd, MAX_FRAME_SIZE, &reader_eof_time);
        if (len < 0) {
            button_pressed = true;
            exit_loop = true;
            continue;
        }

        // extra response data
        cmd = receivedCmd[0] & 0xF;
        options = (receivedCmd[0] >> 4) & 0xFF;
        block = receivedCmd[1];

        if (cmd == ICLASS_CMD_ACTALL && len == 1) {   // 0x0A
            // Reader in anti collision phase
            modulated_response = resp_sof;
            modulated_response_size = resp_sof_len;
            chip_state = ACTIVATED;
            goto send;

        } else if (cmd == ICLASS_CMD_READ_OR_IDENTIFY && len == 1) { // 0x0C
            // Reader asks for anti collision CSN
            if (chip_state == SELECTED || chip_state == ACTIVATED) {
                modulated_response = resp_anticoll;
                modulated_response_size = resp_anticoll_len;
                trace_data = anticoll_data;
                trace_data_size = sizeof(anticoll_data);
            }
            goto send;

        } else if (cmd == ICLASS_CMD_SELECT && len == 9) {
            // Reader selects anticollision CSN.
            // Tag sends the corresponding real CSN
            if (chip_state == ACTIVATED || chip_state == SELECTED) {
                if (!memcmp(receivedCmd + 1, anticoll_data, 8)) {
                    modulated_response = resp_csn;
                    modulated_response_size = resp_csn_len;
                    trace_data = csn_data;
                    trace_data_size = sizeof(csn_data);
                    chip_state = SELECTED;
                } else {
                    chip_state = IDLE;
                }
            } else if (chip_state == HALTED || chip_state == IDLE) {
                // RESELECT with CSN
                if (!memcmp(receivedCmd + 1, csn_data, 8)) {
                    modulated_response = resp_csn;
                    modulated_response_size = resp_csn_len;
                    trace_data = csn_data;
                    trace_data_size = sizeof(csn_data);
                    chip_state = SELECTED;
                }
            }
            goto send;


        } else if (cmd == ICLASS_CMD_READ_OR_IDENTIFY && len == 4) { // 0x0C

            if (chip_state != SELECTED) {
                goto send;
            }
            if (simulationMode == ICLASS_SIM_MODE_EXIT_AFTER_MAC) {
                // provide defaults for blocks 0 ... 5

                // block0,1,2,5 is always readable.
                switch (block) {
                    case 0: { // csn (0c 00)
                        modulated_response = resp_csn;
                        modulated_response_size = resp_csn_len;
                        trace_data = csn_data;
                        trace_data_size = sizeof(csn_data);
                        goto send;
                    }
                    case 1: { // configuration (0c 01)
                        modulated_response = resp_conf;
                        modulated_response_size = resp_conf_len;
                        trace_data = conf_block;
                        trace_data_size = sizeof(conf_block);
                        goto send;
                    }
                    case 2: {// e-purse (0c 02)
                        modulated_response = resp_cc;
                        modulated_response_size = resp_cc_len;
                        trace_data = card_challenge_data;
                        trace_data_size = sizeof(card_challenge_data);
                        // set epurse of sim2,4 attack
                        if (reader_mac_buf != NULL) {
                            memcpy(reader_mac_buf, card_challenge_data, 8);
                        }
                        goto send;
                    }
                    case 3:
                    case 4: { // Kd, Kc, always respond with 0xff bytes
                        modulated_response = resp_ff;
                        modulated_response_size = resp_ff_len;
                        trace_data = ff_data;
                        trace_data_size = sizeof(ff_data);
                        goto send;
                    }
                    case 5: { // Application Issuer Area (0c 05)
                        modulated_response = resp_aia;
                        modulated_response_size = resp_aia_len;
                        trace_data = aia_data;
                        trace_data_size = sizeof(aia_data);
                        goto send;
                    }
                } // switch
            } else if (simulationMode == ICLASS_SIM_MODE_FULL) {
                if (block == 3 || block == 4) { // Kd, Kc, always respond with 0xff bytes
                    modulated_response = resp_ff;
                    modulated_response_size = resp_ff_len;
                    trace_data = ff_data;
                    trace_data_size = sizeof(ff_data);
                } else { // use data from emulator memory
                    memcpy(data_generic_trace, emulator + (current_page * page_size) + (block * 8), 8);
                    AddCrc(data_generic_trace, 8);
                    trace_data = data_generic_trace;
                    trace_data_size = 10;
                    CodeIso15693AsTag(trace_data, trace_data_size);
                    memcpy(data_response, ts->buf, ts->max);
                    modulated_response = data_response;
                    modulated_response_size = ts->max;
                }
                goto send;
            }

        } else if (cmd == ICLASS_CMD_READCHECK && block == 0x02 && len == 2) {  // 0x88
            // Read e-purse KD (88 02)  KC  (18 02)
            if (chip_state != SELECTED) {
                goto send;
            }

            // debit key
            if (receivedCmd[0] == 0x88) {
                cipher_state = &cipher_state_KD[current_page];
                diversified_key = diversified_kd;
                using_kc = false;
            } else {
                cipher_state = &cipher_state_KC[current_page];
                diversified_key = diversified_kc;
                using_kc = true;
            }

            modulated_response = resp_cc;
            modulated_response_size = resp_cc_len;
            trace_data = card_challenge_data;
            trace_data_size = sizeof(card_challenge_data);
            goto send;

        } else if (cmd == ICLASS_CMD_CHECK && len == 9) { // 0x05

            // Reader random and reader MAC!!!
            if (chip_state != SELECTED) {
                goto send;
            }

            if (simulationMode == ICLASS_SIM_MODE_FULL) {
                // NR, from reader, is in receivedCmd +1
                opt_doTagMAC_2(*cipher_state, receivedCmd + 1, data_generic_trace, diversified_key);

                /*
                uint8_t _mac[4] = {0};
                opt_doReaderMAC_2(*cipher_state, receivedCmd + 1, _mac,  diversified_key);

                if (_mac[0] != receivedCmd[5] || _mac[1] != receivedCmd[6] || _mac[2] != receivedCmd[7] || _mac[3] != receivedCmd[8]) {
                    Dbprintf("reader auth " _RED_("failed"));
                    Dbprintf("hf iclass lookup --csn %02x%02x%02x%02x%02x%02x%02x%02x --epurse %02x%02x%02x%02x%02x%02x%02x%02x --macs %02x%02x%02x%02x%02x%02x%02x%02x f iclass_default_keys.dic",
                             csn_data[0], csn_data[1], csn_data[2], csn_data[3], csn_data[4], csn_data[5], csn_data[6], csn_data[7],
                             card_challenge_data[0], card_challenge_data[1], card_challenge_data[2], card_challenge_data[3],
                             card_challenge_data[4], card_challenge_data[5], card_challenge_data[6], card_challenge_data[7],
                             receivedCmd[1], receivedCmd[2], receivedCmd[3], receivedCmd[4],
                             receivedCmd[5], receivedCmd[6], receivedCmd[7], receivedCmd[8]
                            );

                    goto send;
                }
                */

                trace_data = data_generic_trace;
                trace_data_size = 4;
                CodeIso15693AsTag(trace_data, trace_data_size);
                memcpy(data_response, ts->buf, ts->max);
                modulated_response = data_response;
                modulated_response_size = ts->max;

                if (using_kc)
                    kc_attempt++;

            } else {
                // Not fullsim, we don't respond
                chip_state = HALTED;

                if (simulationMode == ICLASS_SIM_MODE_EXIT_AFTER_MAC) {

                    if (g_dbglevel ==  DBG_EXTENDED) {
                        Dbprintf("CSN: %02x %02x %02x %02x %02x %02x %02x %02x", csn[0], csn[1], csn[2], csn[3], csn[4], csn[5], csn[6], csn[7]);
                        Dbprintf("RDR:  (len=%02d): %02x %02x %02x %02x %02x %02x %02x %02x %02x", len,
                                 receivedCmd[0], receivedCmd[1], receivedCmd[2],
                                 receivedCmd[3], receivedCmd[4], receivedCmd[5],
                                 receivedCmd[6], receivedCmd[7], receivedCmd[8]);
                    } else {
                        Dbprintf("CSN: %02x .... %02x OK", csn[0], csn[7]);
                    }
                    if (reader_mac_buf != NULL) {
                        // save NR and MAC for sim 2,4
                        memcpy(reader_mac_buf + 8, receivedCmd + 1, 8);
                    }
                    exit_loop = true;
                }
            }
            goto send;

        } else if (cmd == ICLASS_CMD_HALT && options == 0 && len == 1) {

            if (chip_state != SELECTED) {
                goto send;
            }
            // Reader ends the session
            modulated_response = resp_sof;
            modulated_response_size = resp_sof_len;
            chip_state = HALTED;
            goto send;

        } else if (simulationMode == ICLASS_SIM_MODE_FULL && cmd == ICLASS_CMD_READ4 && len == 4) {  // 0x06

            if (chip_state != SELECTED) {
                goto send;
            }
            //Read block
            memcpy(data_generic_trace, emulator + (current_page * page_size) + (block * 8), 32);
            AddCrc(data_generic_trace, 32);
            trace_data = data_generic_trace;
            trace_data_size = 34;
            CodeIso15693AsTag(trace_data, trace_data_size);
            memcpy(data_response, ts->buf, ts->max);
            modulated_response = data_response;
            modulated_response_size = ts->max;
            goto send;

        } else if (cmd == ICLASS_CMD_UPDATE  && (len == 12 || len == 14)) {

            // We're expected to respond with the data+crc, exactly what's already in the receivedCmd
            // receivedCmd is now UPDATE 1b | ADDRESS 1b | DATA 8b | Signature 4b or CRC 2b
            if (chip_state != SELECTED) {
                goto send;
            }
            // is chip in ReadOnly (RO)
            if ((block_wr_lock & 0x80) == 0) goto send;

            if (block == 12 && (block_wr_lock & 0x40) == 0) goto send;
            if (block == 11 && (block_wr_lock & 0x20) == 0) goto send;
            if (block == 10 && (block_wr_lock & 0x10) == 0) goto send;
            if (block ==  9 && (block_wr_lock & 0x08) == 0) goto send;
            if (block ==  8 && (block_wr_lock & 0x04) == 0) goto send;
            if (block ==  7 && (block_wr_lock & 0x02) == 0) goto send;
            if (block ==  6 && (block_wr_lock & 0x01) == 0) goto send;

            if (block == 2) { // update e-purse
                memcpy(card_challenge_data, receivedCmd + 2, 8);
                CodeIso15693AsTag(card_challenge_data, sizeof(card_challenge_data));
                memcpy(resp_cc, ts->buf, ts->max);
                resp_cc_len = ts->max;
                cipher_state_KD[current_page] = opt_doTagMAC_1(card_challenge_data, diversified_kd);
                cipher_state_KC[current_page] = opt_doTagMAC_1(card_challenge_data, diversified_kc);
                if (simulationMode == ICLASS_SIM_MODE_FULL) {
                    memcpy(emulator + (current_page * page_size) + (8 * 2), card_challenge_data, 8);
                }
            } else if (block == 3) { // update Kd
                for (int i = 0; i < 8; i++) {
                    if (personalization_mode) {
                        diversified_kd[i] = receivedCmd[2 + i];
                    } else {
                        diversified_kd[i] ^= receivedCmd[2 + i];
                    }
                }
                cipher_state_KD[current_page] = opt_doTagMAC_1(card_challenge_data, diversified_kd);
                if (simulationMode == ICLASS_SIM_MODE_FULL) {
                    memcpy(emulator + (current_page * page_size) + (8 * 3), diversified_kd, 8);
                }
            } else if (block == 4) { // update Kc
                for (int i = 0; i < 8; i++) {
                    if (personalization_mode) {
                        diversified_kc[i] = receivedCmd[2 + i];
                    } else {
                        diversified_kc[i] ^= receivedCmd[2 + i];
                    }
                }
                cipher_state_KC[current_page] = opt_doTagMAC_1(card_challenge_data, diversified_kc);
                if (simulationMode == ICLASS_SIM_MODE_FULL) {
                    memcpy(emulator + (current_page * page_size) + (8 * 4), diversified_kc, 8);
                }
            } else if (simulationMode == ICLASS_SIM_MODE_FULL) {
                // update emulator memory
                memcpy(emulator + (current_page * page_size) + (8 * block), receivedCmd + 2, 8);
            }

            memcpy(data_generic_trace, receivedCmd + 2, 8);
            AddCrc(data_generic_trace, 8);
            trace_data = data_generic_trace;
            trace_data_size = 10;
            CodeIso15693AsTag(trace_data, trace_data_size);
            memcpy(data_response, ts->buf, ts->max);
            modulated_response = data_response;
            modulated_response_size = ts->max;
            goto send;

        } else if (cmd == ICLASS_CMD_PAGESEL && len == 4) {  // 0x84
            // Pagesel,
            //  - enables to select a page in the selected chip memory and return its configuration block
            // Chips with a single page will not answer to this command
            // Otherwise, we should answer 8bytes (conf block 1) + 2bytes CRC
            if (chip_state != SELECTED) {
                goto send;
            }

            if (simulationMode == ICLASS_SIM_MODE_FULL && max_page > 0) {

                // if on 2k,  always ignore 3msb,  & 0x1F)
                uint8_t page = receivedCmd[1] & 0x1F;
                if (page > max_page) {
                    goto send;
                }

                current_page = page;

                memcpy(data_generic_trace, emulator + (current_page * page_size) + (8 * 1), 8);
                memcpy(diversified_kd, emulator + (current_page * page_size) + (8 * 3), 8);
                memcpy(diversified_kc, emulator + (current_page * page_size) + (8 * 4), 8);

                cipher_state = &cipher_state_KD[current_page];

                personalization_mode = data_generic_trace[7] & 0x80;
                block_wr_lock = data_generic_trace[3];

                AddCrc(data_generic_trace, 8);

                trace_data = data_generic_trace;
                trace_data_size = 10;

                CodeIso15693AsTag(trace_data, trace_data_size);
                memcpy(data_response, ts->buf, ts->max);
                modulated_response = data_response;
                modulated_response_size = ts->max;
            }
            goto send;

        } else if (cmd == ICLASS_CMD_DETECT) { // 0x0F
            // not supported yet, ignore
//        } else if (cmd == 0x26 && len == 5) {
            // standard ISO15693 INVENTORY command. Ignore.
        } else {
            // Never seen this command before
            if (g_dbglevel >= DBG_EXTENDED)
                print_result("Unhandled command received ", receivedCmd, len);
        }

send:
        /**
        A legit tag has about 330us delay between reader EOT and tag SOF.
        **/
        if (modulated_response_size > 0) {
            uint32_t response_time = reader_eof_time + DELAY_ICLASS_VCD_TO_VICC_SIM;
            TransmitTo15693Reader(modulated_response, modulated_response_size, &response_time, 0, false);
            LogTrace_ISO15693(trace_data, trace_data_size, response_time * 32, (response_time * 32) + (modulated_response_size * 32 * 64), NULL, false);
        }

        if (chip_state == HALTED) {
            uint32_t wait_time = GetCountSspClk() + ICLASS_READER_TIMEOUT_ACTALL;
            while (GetCountSspClk() < wait_time) {};
        }

        // CC attack
        // wait to trigger the reader bug, then wait 1000ms
        if (kc_attempt > 3) {
            uint32_t wait_time = GetCountSspClk() + (16000 * 100);
            while (GetCountSspClk() < wait_time) {};
            kc_attempt = 0;
            exit_loop = true;
        }
    }

    LEDsoff();

    if (button_pressed)
        DbpString("button pressed");

    return button_pressed;
}

int do_iclass_simulation_nonsec(void) {
    // free eventually allocated BigBuf memory
    BigBuf_free_keep_EM();

    uint16_t page_size = 32 * 8;
    uint8_t current_page = 0;

    uint8_t *emulator = BigBuf_get_EM_addr();
    uint8_t *csn = emulator;

    // CSN followed by two CRC bytes
    uint8_t anticoll_data[10] = { 0 };
    uint8_t csn_data[10] = { 0 };
    memcpy(csn_data, csn, sizeof(csn_data));

    // Construct anticollision-CSN
    rotateCSN(csn_data, anticoll_data);

    // Compute CRC on both CSNs
    AddCrc(anticoll_data, 8);
    AddCrc(csn_data, 8);

    // configuration block
    uint8_t conf_block[10] = {0x12, 0xFF, 0xFF, 0xFF, 0x7F, 0x1F, 0xFF, 0x3C, 0x00, 0x00};

    // AIA
    uint8_t aia_data[10] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00};

    memcpy(conf_block, emulator + (8 * 1), 8);
    memcpy(aia_data, emulator + (8 * 2), 8);

    AddCrc(conf_block, 8);
    AddCrc(aia_data, 8);

    if ((conf_block[5] & 0x80) == 0x80) {
        page_size = 256 * 8;
    }

    // chip memory may be divided in 8 pages
    uint8_t max_page = ((conf_block[4] & 0x10) == 0x10) ? 0 : 7;

    // Anti-collision process:
    // Reader 0a
    // Tag    0f
    // Reader 0c
    // Tag    anticoll. CSN
    // Reader 81 anticoll. CSN
    // Tag    CSN

    uint8_t *modulated_response = NULL;
    int modulated_response_size = 0;
    uint8_t *trace_data = NULL;
    int trace_data_size = 0;

    // Respond SOF -- takes 1 bytes
    uint8_t *resp_sof = BigBuf_malloc(2);
    int resp_sof_len;

    // Anticollision CSN (rotated CSN)
    // 22: Takes 2 bytes for SOF/EOF and 10 * 2 = 20 bytes (2 bytes/byte)
    uint8_t *resp_anticoll = BigBuf_malloc(28);
    int resp_anticoll_len;

    // CSN
    // 22: Takes 2 bytes for SOF/EOF and 10 * 2 = 20 bytes (2 bytes/byte)
    uint8_t *resp_csn = BigBuf_malloc(28);
    int resp_csn_len;

    // configuration (blk 1) PICOPASS 2ks
    uint8_t *resp_conf = BigBuf_malloc(28);
    int resp_conf_len;

    // Application Issuer Area  (blk 5)
    uint8_t *resp_aia = BigBuf_malloc(28);
    int resp_aia_len;

    // receive command
    uint8_t *receivedCmd = BigBuf_malloc(MAX_FRAME_SIZE);

    // Prepare card messages
    tosend_t *ts = get_tosend();
    ts->max = 0;

    // First card answer: SOF
    CodeIClassTagSOF();
    memcpy(resp_sof, ts->buf, ts->max);
    resp_sof_len = ts->max;

    // Anticollision CSN
    CodeIso15693AsTag(anticoll_data, sizeof(anticoll_data));
    memcpy(resp_anticoll, ts->buf, ts->max);
    resp_anticoll_len = ts->max;

    // CSN (block 0)
    CodeIso15693AsTag(csn_data, sizeof(csn_data));
    memcpy(resp_csn, ts->buf, ts->max);
    resp_csn_len = ts->max;

    // Configuration (block 1)
    CodeIso15693AsTag(conf_block, sizeof(conf_block));
    memcpy(resp_conf, ts->buf, ts->max);
    resp_conf_len = ts->max;

    // Application Issuer Area (block 2)
    CodeIso15693AsTag(aia_data, sizeof(aia_data));
    memcpy(resp_aia, ts->buf, ts->max);
    resp_aia_len = ts->max;

    //This is used for responding to READ-block commands or other data which is dynamically generated
    //First the 'trace'-data, not encoded for FPGA
    uint8_t *data_generic_trace = BigBuf_malloc(32 + 2); // 32 bytes data + 2byte CRC is max tag answer

    //Then storage for the modulated data
    //Each bit is doubled when modulated for FPGA, and we also have SOF and EOF (2 bytes)
    uint8_t *data_response = BigBuf_malloc((32 + 2) * 2 + 2);

    enum { IDLE, ACTIVATED, SELECTED, HALTED } chip_state = IDLE;

    bool button_pressed = false;
    uint8_t cmd, options, block;
    int len;

    bool exit_loop = false;
    while (exit_loop == false) {
        WDT_HIT();

        uint32_t reader_eof_time = 0;
        len = GetIso15693CommandFromReader(receivedCmd, MAX_FRAME_SIZE, &reader_eof_time);
        if (len < 0) {
            button_pressed = true;
            exit_loop = true;
            continue;
        }

        // Now look at the reader command and provide appropriate responses
        // default is no response:
        modulated_response = NULL;
        modulated_response_size = 0;
        trace_data = NULL;
        trace_data_size = 0;

        // extra response data
        cmd = receivedCmd[0] & 0xF;
        options = (receivedCmd[0] >> 4) & 0xFF;
        block = receivedCmd[1];

        if (cmd == ICLASS_CMD_ACTALL && len == 1) {   // 0x0A
            // Reader in anti collision phase
            if (chip_state != HALTED) {
                modulated_response = resp_sof;
                modulated_response_size = resp_sof_len;
                chip_state = ACTIVATED;
            }
            goto send;

        } else if (cmd == ICLASS_CMD_READ_OR_IDENTIFY && len == 1) { // 0x0C
            // Reader asks for anti collision CSN
            if (chip_state == SELECTED || chip_state == ACTIVATED) {
                modulated_response = resp_anticoll;
                modulated_response_size = resp_anticoll_len;
                trace_data = anticoll_data;
                trace_data_size = sizeof(anticoll_data);
            }
            goto send;

        } else if (cmd == ICLASS_CMD_SELECT && len == 9) {
            // Reader selects anticollision CSN.
            // Tag sends the corresponding real CSN
            if (chip_state == ACTIVATED || chip_state == SELECTED) {
                if (!memcmp(receivedCmd + 1, anticoll_data, 8)) {
                    modulated_response = resp_csn;
                    modulated_response_size = resp_csn_len;
                    trace_data = csn_data;
                    trace_data_size = sizeof(csn_data);
                    chip_state = SELECTED;
                } else {
                    chip_state = IDLE;
                }
            } else if (chip_state == HALTED) {
                // RESELECT with CSN
                if (!memcmp(receivedCmd + 1, csn_data, 8)) {
                    modulated_response = resp_csn;
                    modulated_response_size = resp_csn_len;
                    trace_data = csn_data;
                    trace_data_size = sizeof(csn_data);
                    chip_state = SELECTED;
                }
            }
            goto send;


        } else if (cmd == ICLASS_CMD_READ_OR_IDENTIFY && len == 4) { // 0x0C

            if (chip_state != SELECTED) {
                goto send;
            }

            switch (block) {
                case 0: { // csn (0c 00)
                    modulated_response = resp_csn;
                    modulated_response_size = resp_csn_len;
                    trace_data = csn_data;
                    trace_data_size = sizeof(csn_data);
                    goto send;
                }
                case 1: { // configuration (0c 01)
                    modulated_response = resp_conf;
                    modulated_response_size = resp_conf_len;
                    trace_data = conf_block;
                    trace_data_size = sizeof(conf_block);
                    goto send;
                }
                case 2: { // Application Issuer Area (0c 02)
                    modulated_response = resp_aia;
                    modulated_response_size = resp_aia_len;
                    trace_data = aia_data;
                    trace_data_size = sizeof(aia_data);
                    goto send;
                }
                default : {
                    memcpy(data_generic_trace, emulator + (block << 3), 8);
                    AddCrc(data_generic_trace, 8);
                    trace_data = data_generic_trace;
                    trace_data_size = 10;
                    CodeIso15693AsTag(trace_data, trace_data_size);
                    memcpy(data_response, ts->buf, ts->max);
                    modulated_response = data_response;
                    modulated_response_size = ts->max;
                    goto send;
                }
            } // swith

        } else if (cmd == ICLASS_CMD_READCHECK) {                 // 0x88
            goto send;

        } else if (cmd == ICLASS_CMD_CHECK && len == 9) {         // 0x05
            goto send;

        } else if (cmd == ICLASS_CMD_HALT && options == 0 && len == 1) {

            if (chip_state != SELECTED) {
                goto send;
            }
            // Reader ends the session
            modulated_response = resp_sof;
            modulated_response_size = resp_sof_len;
            chip_state = HALTED;
            goto send;

        } else if (cmd == ICLASS_CMD_READ4 && len == 4) {         // 0x06

            if (chip_state != SELECTED) {
                goto send;
            }
            //Read block
            memcpy(data_generic_trace, emulator + (current_page * page_size) + (block * 8), 8 * 4);
            AddCrc(data_generic_trace, 8 * 4);
            trace_data = data_generic_trace;
            trace_data_size = 34;
            CodeIso15693AsTag(trace_data, trace_data_size);
            memcpy(data_response, ts->buf, ts->max);
            modulated_response = data_response;
            modulated_response_size = ts->max;
            goto send;

        } else if (cmd == ICLASS_CMD_UPDATE  && (len == 12 || len == 14)) {

            // We're expected to respond with the data+crc, exactly what's already in the receivedCmd
            // receivedCmd is now UPDATE 1b | ADDRESS 1b | DATA 8b | Signature 4b or CRC 2b
            if (chip_state != SELECTED) {
                goto send;
            }

            // update emulator memory
            memcpy(emulator + (current_page * page_size) + (8 * block), receivedCmd + 2, 8);

            memcpy(data_generic_trace, receivedCmd + 2, 8);
            AddCrc(data_generic_trace, 8);
            trace_data = data_generic_trace;
            trace_data_size = 10;
            CodeIso15693AsTag(trace_data, trace_data_size);
            memcpy(data_response, ts->buf, ts->max);
            modulated_response = data_response;
            modulated_response_size = ts->max;
            goto send;

        } else if (cmd == ICLASS_CMD_PAGESEL && len == 4) {  // 0x84
            // Pagesel,
            //  - enables to select a page in the selected chip memory and return its configuration block
            // Chips with a single page will not answer to this command
            // Otherwise, we should answer 8bytes (conf block 1) + 2bytes CRC
            if (chip_state != SELECTED) {
                goto send;
            }

            if (max_page > 0) {

                current_page = receivedCmd[1];

                memcpy(data_generic_trace, emulator + (current_page * page_size) + (8 * 1), 8);
                AddCrc(data_generic_trace, 8);
                trace_data = data_generic_trace;
                trace_data_size = 10;

                CodeIso15693AsTag(trace_data, trace_data_size);
                memcpy(data_response, ts->buf, ts->max);
                modulated_response = data_response;
                modulated_response_size = ts->max;
            }
            goto send;

//            } else if(cmd == ICLASS_CMD_DETECT) {  // 0x0F
//        } else if (cmd == 0x26 && len == 5) {
            // standard ISO15693 INVENTORY command. Ignore.
        } else {
            // Never seen this command before
            if (g_dbglevel >= DBG_EXTENDED)
                print_result("Unhandled command received ", receivedCmd, len);
        }

send:
        /**
        A legit tag has about 330us delay between reader EOT and tag SOF.
        **/
        if (modulated_response_size > 0) {
            uint32_t response_time = reader_eof_time + DELAY_ICLASS_VCD_TO_VICC_SIM;
            TransmitTo15693Reader(modulated_response, modulated_response_size, &response_time, 0, false);
            LogTrace_ISO15693(trace_data, trace_data_size, response_time * 32, (response_time * 32) + (modulated_response_size * 32 * 64), NULL, false);
        }
    }

    LEDsoff();

    if (button_pressed)
        DbpString("button pressed");

    return button_pressed;

}

// THE READER CODE
static void iclass_send_as_reader(uint8_t *frame, int len, uint32_t *start_time, uint32_t *end_time, bool shallow_mod) {
    CodeIso15693AsReader(frame, len);
    tosend_t *ts = get_tosend();
    TransmitTo15693Tag(ts->buf, ts->max, start_time, shallow_mod);
    *end_time = *start_time + (32 * ((8 * ts->max) - 4)); // subtract the 4 padding bits after EOF
    LogTrace_ISO15693(frame, len, (*start_time * 4), (*end_time * 4), NULL, true);
}

static bool iclass_send_cmd_with_retries(uint8_t *cmd, size_t cmdsize, uint8_t *resp, size_t max_resp_size,
                                         uint8_t expected_size, uint8_t tries, uint32_t *start_time,
                                         uint16_t timeout, uint32_t *eof_time, bool shallow_mod) {

    uint16_t resp_len = 0;
    while (tries-- > 0) {

        iclass_send_as_reader(cmd, cmdsize, start_time, eof_time, shallow_mod);

        if (resp == NULL) {
            return true;
        }

        int res = GetIso15693AnswerFromTag(resp, max_resp_size, timeout, eof_time, false, true, &resp_len);
        if (res == PM3_SUCCESS && expected_size == resp_len) {
            return true;
        }
    }
    return false;
}

/**
 * @brief Talks to an iclass tag, sends the commands to get CSN and CC.
 * @param card_data where the CSN, CONFIG, CC are stored for return
 *        8 bytes csn + 8 bytes config + 8 bytes CC
 * @return false = fail
 *         true = Got all.
 */
static bool select_iclass_tag_ex(picopass_hdr_t *hdr, bool use_credit_key, uint32_t *eof_time, uint8_t *status, bool shallow_mod) {

    static uint8_t act_all[] = { ICLASS_CMD_ACTALL };
    static uint8_t identify[] = { ICLASS_CMD_READ_OR_IDENTIFY, 0x00, 0x73, 0x33 };
    static uint8_t read_conf[] = { ICLASS_CMD_READ_OR_IDENTIFY, 0x01, 0xfa, 0x22 };
    uint8_t select[] = { 0x80 | ICLASS_CMD_SELECT, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    uint8_t read_aia[] = { ICLASS_CMD_READ_OR_IDENTIFY, 0x05, 0xde, 0x64};
    uint8_t read_check_cc[] = { 0x80 | ICLASS_CMD_READCHECK, 0x02 };
    uint8_t resp[ICLASS_BUFFER_SIZE] = {0};

    // Bit 4: K.If this bit equals to one, the READCHECK will use the Credit Key (Kc); if equals to zero, Debit Key (Kd) will be used
    // bit 7: parity.
    if (use_credit_key)
        read_check_cc[0] = 0x10 | ICLASS_CMD_READCHECK;

    // wakeup
    uint32_t start_time = GetCountSspClk();
    iclass_send_as_reader(act_all, 1, &start_time, eof_time, shallow_mod);
    int res;
    uint16_t resp_len = 0;
    res = GetIso15693AnswerFromTag(resp, sizeof(resp), ICLASS_READER_TIMEOUT_ACTALL, eof_time, false, true, &resp_len);
    if (res != PM3_SUCCESS)
        return false;

    // send Identify
    start_time = *eof_time + DELAY_ICLASS_VICC_TO_VCD_READER;
    iclass_send_as_reader(identify, 1, &start_time, eof_time, shallow_mod);

    // expect a 10-byte response here, 8 byte anticollision-CSN and 2 byte CRC
    res = GetIso15693AnswerFromTag(resp, sizeof(resp), ICLASS_READER_TIMEOUT_OTHERS, eof_time, false, true, &resp_len);
    if (res != PM3_SUCCESS || resp_len != 10)
        return false;

    // copy the Anti-collision CSN to our select-packet
    memcpy(&select[1], resp, 8);

    // select the card
    start_time = *eof_time + DELAY_ICLASS_VICC_TO_VCD_READER;
    iclass_send_as_reader(select, sizeof(select), &start_time, eof_time, shallow_mod);

    // expect a 10-byte response here, 8 byte CSN and 2 byte CRC
    res = GetIso15693AnswerFromTag(resp, sizeof(resp), ICLASS_READER_TIMEOUT_OTHERS, eof_time, false, true, &resp_len);
    if (res != PM3_SUCCESS || resp_len != 10)
        return false;

    // save CSN
    memcpy(hdr->csn, resp, sizeof(hdr->csn));

    // card selected, now read config (block1) (only 8 bytes no CRC)
    start_time = *eof_time + DELAY_ICLASS_VICC_TO_VCD_READER;
    iclass_send_as_reader(read_conf, sizeof(read_conf), &start_time, eof_time, shallow_mod);

    // expect a 8-byte response here
    res = GetIso15693AnswerFromTag(resp, sizeof(resp), ICLASS_READER_TIMEOUT_OTHERS, eof_time, false, true, &resp_len);
    if (res != PM3_SUCCESS || resp_len != 10)
        return false;

    // save CONF
    memcpy((uint8_t *)&hdr->conf, resp, sizeof(hdr->conf));

    if (status)
        *status |= (FLAG_ICLASS_CSN | FLAG_ICLASS_CONF);

    uint8_t pagemap = get_pagemap(hdr);
    if (pagemap != PICOPASS_NON_SECURE_PAGEMODE) {

        // read App Issuer Area block 5
        start_time = *eof_time + DELAY_ICLASS_VICC_TO_VCD_READER;
        iclass_send_as_reader(read_aia, sizeof(read_aia), &start_time, eof_time, shallow_mod);

        // expect a 10-byte response here
        res = GetIso15693AnswerFromTag(resp, sizeof(resp), ICLASS_READER_TIMEOUT_OTHERS, eof_time, false, true, &resp_len);
        if (res != PM3_SUCCESS || resp_len != 10)
            return false;

        if (status) {
            *status |= FLAG_ICLASS_AIA;
            memcpy(hdr->app_issuer_area, resp, sizeof(hdr->app_issuer_area));
        }

        // card selected, now read e-purse (cc) (block2) (only 8 bytes no CRC)
        start_time = *eof_time + DELAY_ICLASS_VICC_TO_VCD_READER;
        iclass_send_as_reader(read_check_cc, sizeof(read_check_cc), &start_time, eof_time, shallow_mod);

        // expect a 8-byte response here
        res = GetIso15693AnswerFromTag(resp, sizeof(resp), ICLASS_READER_TIMEOUT_OTHERS, eof_time, false, true, &resp_len);
        if (res != PM3_SUCCESS || resp_len != 8)
            return false;

        memcpy(hdr->epurse, resp, sizeof(hdr->epurse));

        if (status)
            *status |= FLAG_ICLASS_CC;

    }  else {

        // on NON_SECURE_PAGEMODE cards, AIA is on block2..

        // read App Issuer Area block 2
        read_aia[1] = 0x02;
        read_aia[2] = 0x61;
        read_aia[3] = 0x10;

        start_time = *eof_time + DELAY_ICLASS_VICC_TO_VCD_READER;
        iclass_send_as_reader(read_aia, sizeof(read_aia), &start_time, eof_time, shallow_mod);

        // expect a 10-byte response here
        res = GetIso15693AnswerFromTag(resp, sizeof(resp), ICLASS_READER_TIMEOUT_OTHERS, eof_time, false, true, &resp_len);
        if (res != PM3_SUCCESS || resp_len != 10)
            return false;

        if (status) {
            *status |= FLAG_ICLASS_AIA;
            memcpy(hdr->epurse, resp, sizeof(hdr->epurse));
        }
    }

    return true;
}

bool select_iclass_tag(picopass_hdr_t *hdr, bool use_credit_key, uint32_t *eof_time, bool shallow_mod) {
    uint8_t result = 0;
    return select_iclass_tag_ex(hdr, use_credit_key, eof_time, &result, shallow_mod);
}

// Reader iClass Anticollission
// turn off afterwards
void ReaderIClass(uint8_t flags) {

    // flag to use credit key
    bool use_credit_key = ((flags & FLAG_ICLASS_READER_CREDITKEY) == FLAG_ICLASS_READER_CREDITKEY);
    bool shallow_mod = (flags & FLAG_ICLASS_READER_SHALLOW_MOD);

    if ((flags & FLAG_ICLASS_READER_INIT) == FLAG_ICLASS_READER_INIT) {
        Iso15693InitReader();
    }

    if ((flags & FLAG_ICLASS_READER_CLEARTRACE) == FLAG_ICLASS_READER_CLEARTRACE) {
        clear_trace();
    }


    uint8_t res = 0;
    uint32_t eof_time = 0;
    picopass_hdr_t hdr = {0};

    if (select_iclass_tag_ex(&hdr, use_credit_key, &eof_time, &res, shallow_mod) == false) {
        reply_ng(CMD_HF_ICLASS_READER, PM3_ERFTRANS, NULL, 0);
        goto out;
    }

    // Page mapping for secure mode
    // 0 : CSN
    // 1 : Configuration
    // 2 : e-purse
    // 3 : kd / debit / aa2 (write-only)
    // 4 : kc / credit / aa1 (write-only)
    // 5 : AIA, Application issuer area
    //
    // Page mapping for non secure mode
    // 0 : CSN
    // 1 : Configuration
    // 2 : AIA, Application issuer area

    // Return to client, e 6 * 8 bytes of data.
    // with 0xFF:s in block 3 and 4.

    iclass_card_select_resp_t payload = {
        .status = res
    };
    memcpy(&payload.header.hdr, &hdr, sizeof(picopass_hdr_t));

    reply_ng(CMD_HF_ICLASS_READER, PM3_SUCCESS, (uint8_t *)&payload, sizeof(iclass_card_select_resp_t));

out:
    switch_off();
}

bool authenticate_iclass_tag(iclass_auth_req_t *payload, picopass_hdr_t *hdr, uint32_t *start_time, uint32_t *eof_time, uint8_t *mac_out) {

    uint8_t cmd_check[9] = { ICLASS_CMD_CHECK };
    uint8_t mac[4] = {0};
    uint8_t resp_auth[4] = {0};
    uint8_t ccnr[12] = {0};

    uint8_t *pmac = mac;
    if (mac_out)
        pmac = mac_out;

    memcpy(ccnr, hdr->epurse, sizeof(hdr->epurse));

    if (payload->use_replay) {

        memcpy(pmac, payload->key + 4, 4);
        memcpy(cmd_check + 1, payload->key, 8);

    } else {

        uint8_t div_key[8] = {0};
        if (payload->use_raw)
            memcpy(div_key, payload->key, 8);
        else
            iclass_calc_div_key(hdr->csn, payload->key, div_key, payload->use_elite);

        if (payload->use_credit_key)
            memcpy(hdr->key_c, div_key, sizeof(hdr->key_c));
        else
            memcpy(hdr->key_d, div_key, sizeof(hdr->key_d));

        opt_doReaderMAC(ccnr, div_key, pmac);

        // copy MAC to check command (readersignature)
        cmd_check[5] = pmac[0];
        cmd_check[6] = pmac[1];
        cmd_check[7] = pmac[2];
        cmd_check[8] = pmac[3];
    }
    return iclass_send_cmd_with_retries(cmd_check, sizeof(cmd_check), resp_auth, sizeof(resp_auth), 4, 2, start_time, ICLASS_READER_TIMEOUT_OTHERS, eof_time, payload->shallow_mod);
}


/* this function works on the following assumptions.
* - one select first, to get CSN / CC (e-purse)
* - calculate before diversified keys and precalc mac based on CSN/KEY.
* - data in contains of diversified keys, mac
* - key loop only test one type of authtication key. Ie two calls needed
*   to cover debit and credit key. (AA1/AA2)
*/
void iClass_Authentication_fast(iclass_chk_t *p) {
    // sanitation
    if (p == NULL) {
        reply_ng(CMD_HF_ICLASS_CHKKEYS, PM3_ESOFT, NULL, 0);
        return;
    }

    bool shallow_mod = p->shallow_mod;

    uint8_t check[9] = { ICLASS_CMD_CHECK };
    uint8_t resp[ICLASS_BUFFER_SIZE] = {0};
    uint8_t readcheck_cc[] = { 0x80 | ICLASS_CMD_READCHECK, 0x02 };

    if (p->use_credit_key)
        readcheck_cc[0] = 0x10 | ICLASS_CMD_READCHECK;

    // select card / e-purse
    picopass_hdr_t hdr = {0};
    iclass_premac_t *keys = p->items;

    LED_A_ON();

    // fresh start
    switch_off();
    SpinDelay(20);
    Iso15693InitReader();

    bool isOK = false;

    uint32_t start_time = 0, eof_time = 0;
    if (select_iclass_tag(&hdr, p->use_credit_key, &eof_time, shallow_mod) == false)
        goto out;

    start_time = eof_time + DELAY_ICLASS_VICC_TO_VCD_READER;

    // since select_iclass_tag call sends s readcheck,  we start with sending first response.
    uint16_t checked = 0;

    // Keychunk loop
    uint8_t i = 0;
    for (i = 0; i < p->count; i++) {

        // Allow button press / usb cmd to interrupt device
        if (checked == 1000) {
            if (BUTTON_PRESS() || data_available()) goto out;
            checked = 0;
        }
        ++checked;

        WDT_HIT();
        LED_B_ON();

        // copy MAC to check command (readersignature)
        check[5] = keys[i].mac[0];
        check[6] = keys[i].mac[1];
        check[7] = keys[i].mac[2];
        check[8] = keys[i].mac[3];

        // expect 4bytes, 3 retries times..
        isOK = iclass_send_cmd_with_retries(check, sizeof(check), resp, sizeof(resp), 4, 2, &start_time, ICLASS_READER_TIMEOUT_OTHERS, &eof_time, shallow_mod);
        if (isOK)
            goto out;

        start_time = eof_time + DELAY_ICLASS_VICC_TO_VCD_READER;
        // Auth Sequence MUST begin with reading e-purse. (block2)
        // Card selected, now read e-purse (cc) (block2) (only 8 bytes no CRC)
        iclass_send_as_reader(readcheck_cc, sizeof(readcheck_cc), &start_time, &eof_time, shallow_mod);
        LED_B_OFF();
    }

out:
    // send keyindex.
    reply_ng(CMD_HF_ICLASS_CHKKEYS, (isOK) ? PM3_SUCCESS : PM3_ESOFT, (uint8_t *)&i, sizeof(i));
    switch_off();
}

// Tries to read block.
// retries 3times.
// reply 8 bytes block
bool iclass_read_block(uint16_t blockno, uint8_t *data, uint32_t *start_time, uint32_t *eof_time, bool shallow_mod) {
    uint8_t resp[10];
    uint8_t c[] = {ICLASS_CMD_READ_OR_IDENTIFY, blockno, 0x00, 0x00};
    AddCrc(c + 1, 1);
    bool isOK = iclass_send_cmd_with_retries(c, sizeof(c), resp, sizeof(resp), 10, 2, start_time, ICLASS_READER_TIMEOUT_OTHERS, eof_time, shallow_mod);
    if (isOK)
        memcpy(data, resp, 8);
    return isOK;
}

// turn off afterwards
// send in authentication needed data,  if to use auth.
// reply 8 bytes block if send_reply  (for client)
void iClass_ReadBlock(uint8_t *msg) {

    iclass_auth_req_t *payload = (iclass_auth_req_t *)msg;
    bool shallow_mod = payload->shallow_mod;

    iclass_readblock_resp_t response = { .isOK = true };
    memset(response.data, 0, sizeof(response.data));

    uint8_t cmd_read[] = {ICLASS_CMD_READ_OR_IDENTIFY, payload->blockno, 0x00, 0x00};
    AddCrc(cmd_read + 1, 1);

    Iso15693InitReader();

    // select tag.
    uint32_t eof_time = 0;
    picopass_hdr_t hdr = {0};
    bool res = select_iclass_tag(&hdr, payload->use_credit_key, &eof_time, shallow_mod);
    if (res == false) {
        if (payload->send_reply) {
            response.isOK = res;
            reply_ng(CMD_HF_ICLASS_READBL, PM3_ETIMEOUT, (uint8_t *)&response, sizeof(response));
        }
        goto out;
    }

    uint32_t start_time = eof_time + DELAY_ICLASS_VICC_TO_VCD_READER;

    // authenticate
    if (payload->do_auth) {

        res = authenticate_iclass_tag(payload, &hdr, &start_time, &eof_time, NULL);
        if (res == false) {
            if (payload->send_reply) {
                response.isOK = res;
                reply_ng(CMD_HF_ICLASS_READBL, PM3_ETIMEOUT, (uint8_t *)&response, sizeof(response));
            }
            goto out;
        }
    }

    start_time = eof_time + DELAY_ICLASS_VICC_TO_VCD_READER;

    // read data
    uint8_t resp[10];
    res = iclass_send_cmd_with_retries(cmd_read, sizeof(cmd_read), resp, sizeof(resp), 10, 3, &start_time, ICLASS_READER_TIMEOUT_OTHERS, &eof_time, shallow_mod);
    if (res) {
        memcpy(response.data, resp, sizeof(response.data));
        if (payload->send_reply) {
            reply_ng(CMD_HF_ICLASS_READBL, PM3_SUCCESS, (uint8_t *)&response, sizeof(response));
        }
    } else {
        if (payload->send_reply) {
            response.isOK = res;
            reply_ng(CMD_HF_ICLASS_READBL, PM3_ETIMEOUT, (uint8_t *)&response, sizeof(response));
        }
    }

out:
    switch_off();
}

// Dump command seems to dump a block related portion of card memory.
// I suppose it will need to do an authentatication to AA1,  read its blocks by calling this.
// then authenticate AA2, and read those blocks by calling this.
// By the looks at it only 2K cards is supported,  or first page dumps on larger cards.
// turn off afterwards
void iClass_Dump(uint8_t *msg) {

    BigBuf_free();

    iclass_dump_req_t *cmd = (iclass_dump_req_t *)msg;
    iclass_auth_req_t *req = &cmd->req;
    bool shallow_mod = req->shallow_mod;

    uint8_t *dataout = BigBuf_malloc(ICLASS_16KS_SIZE);
    if (dataout == NULL) {
        DbpString("fail to allocate memory");
        if (req->send_reply) {
            reply_ng(CMD_HF_ICLASS_DUMP, PM3_EMALLOC, NULL, 0);
        }
        switch_off();
        return;
    }
    memset(dataout, 0xFF, ICLASS_16KS_SIZE);

    Iso15693InitReader();

    // select tag.
    uint32_t eof_time = 0;
    picopass_hdr_t hdr = {0};
    memset(&hdr, 0xff, sizeof(picopass_hdr_t));

    bool res = select_iclass_tag(&hdr, req->use_credit_key, &eof_time, shallow_mod);
    if (res == false) {
        if (req->send_reply) {
            reply_ng(CMD_HF_ICLASS_DUMP, PM3_ETIMEOUT, NULL, 0);
        }
        switch_off();
        return;
    }

    uint32_t start_time = eof_time + DELAY_ICLASS_VICC_TO_VCD_READER;

    // authenticate
    if (req->do_auth) {
        res = authenticate_iclass_tag(req, &hdr, &start_time, &eof_time, NULL);
        if (res == false) {
            if (req->send_reply) {
                reply_ng(CMD_HF_ICLASS_DUMP, PM3_ETIMEOUT, NULL, 0);
            }
            switch_off();
            return;
        }
    }

    start_time = eof_time + DELAY_ICLASS_VICC_TO_VCD_READER;

    bool dumpsuccess = true;

    // main read loop
    uint16_t i;
    for (i = cmd->start_block; i <= cmd->end_block; i++) {

        uint8_t resp[10];
        uint8_t c[] = {ICLASS_CMD_READ_OR_IDENTIFY, i, 0x00, 0x00};
        AddCrc(c + 1, 1);

        res = iclass_send_cmd_with_retries(c, sizeof(c), resp, sizeof(resp), 10, 3, &start_time, ICLASS_READER_TIMEOUT_OTHERS, &eof_time, shallow_mod);
        if (res) {
            memcpy(dataout + (8 * i), resp, 8);
        } else {
            Dbprintf("failed to read block %u ( 0x%02x)", i, i);
            dumpsuccess = false;
        }
    }

    switch_off();

    // copy diversified key back.
    if (req->do_auth) {
        if (req->use_credit_key)
            memcpy(dataout + (8 * 4), hdr.key_c, 8);
        else
            memcpy(dataout + (8 * 3), hdr.key_d, 8);
    }

    if (req->send_reply) {
        struct p {
            bool isOK;
            uint16_t block_cnt;
            uint32_t bb_offset;
        } PACKED response;

        response.isOK = dumpsuccess;
        response.block_cnt = i;
        response.bb_offset = dataout - BigBuf_get_addr();
        reply_ng(CMD_HF_ICLASS_DUMP, PM3_SUCCESS, (uint8_t *)&response, sizeof(response));
    }

    BigBuf_free();
}

static bool iclass_writeblock_ext(uint8_t blockno, uint8_t *data, uint8_t *mac, bool use_mac, bool shallow_mod) {

    // write command: cmd, 1 blockno, 8 data, 4 mac
    uint8_t write[14] = { 0x80 | ICLASS_CMD_UPDATE, blockno };
    uint8_t write_len = 14;
    memcpy(write + 2, data, 8);

    if (use_mac) {
        memcpy(write + 10, mac, 4);
    } else {
        AddCrc(write + 1, 9);
        write_len -= 2;
    }

    uint8_t resp[10] = {0};
    uint32_t eof_time = 0, start_time = 0;
    bool isOK = iclass_send_cmd_with_retries(write, write_len, resp, sizeof(resp), 10, 3, &start_time, ICLASS_READER_TIMEOUT_UPDATE, &eof_time, shallow_mod);
    if (isOK == false) {
        return false;
    }

    uint8_t all_ff[8] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    if (blockno == 2) {
        // check response. e-purse update swaps first and second half
        if (memcmp(data + 4, resp, 4) || memcmp(data, resp + 4, 4)) {
            return false;
        }
    } else if (blockno == 3 || blockno == 4) {
        // check response. Key updates always return 0xffffffffffffffff
        if (memcmp(all_ff, resp, 8)) {
            return false;
        }
    } else {
        // check response. All other updates return unchanged data
        if (memcmp(data, resp, 8)) {
            return false;
        }
    }

    return true;
}

// turn off afterwards
void iClass_WriteBlock(uint8_t *msg) {

    LED_A_ON();

    iclass_writeblock_req_t *payload = (iclass_writeblock_req_t *)msg;
    bool shallow_mod = payload->req.shallow_mod;

    uint8_t write[14] = { 0x80 | ICLASS_CMD_UPDATE, payload->req.blockno };
    uint8_t write_len = 14;

    Iso15693InitReader();

    // select tag.
    uint32_t eof_time = 0;
    picopass_hdr_t hdr = {0};
    uint8_t res = select_iclass_tag(&hdr, payload->req.use_credit_key, &eof_time, shallow_mod);
    if (res == false) {
        goto out;
    }

    uint32_t start_time = eof_time + DELAY_ICLASS_VICC_TO_VCD_READER;

    uint8_t mac[4] = {0};

    // authenticate
    if (payload->req.do_auth) {

        res = authenticate_iclass_tag(&payload->req, &hdr, &start_time, &eof_time, mac);
        if (res == false) {
            goto out;
        }
    }

    // new block data
    memcpy(write + 2, payload->data, 8);

    uint8_t pagemap = get_pagemap(&hdr);
    if (pagemap == PICOPASS_NON_SECURE_PAGEMODE) {
        // Unsecured tags uses CRC16,  but don't include the UPDATE operation code
        // byte0 = update op
        // byte1 = block no
        // byte2..9 = new block data
        AddCrc(write + 1, 9);
        write_len -= 2;
    } else {

        if (payload->req.use_replay) {
            memcpy(write + 10, payload->mac, sizeof(payload->mac));
        } else {
            // Secure tags uses MAC
            uint8_t wb[9];
            wb[0] = payload->req.blockno;
            memcpy(wb + 1, payload->data, 8);

            if (payload->req.use_credit_key)
                doMAC_N(wb, sizeof(wb), hdr.key_c, mac);
            else
                doMAC_N(wb, sizeof(wb), hdr.key_d, mac);

            memcpy(write + 10, mac, sizeof(mac));
        }
    }

    start_time = eof_time + DELAY_ICLASS_VICC_TO_VCD_READER;

    uint8_t resp[10] = {0};

    uint8_t tries = 3;
    while (tries-- > 0) {

        iclass_send_as_reader(write, write_len, &start_time, &eof_time, shallow_mod);

        if (tearoff_hook() == PM3_ETEAROFF) { // tearoff occurred
            res = false;
            switch_off();
            if (payload->req.send_reply)
                reply_ng(CMD_HF_ICLASS_WRITEBL, PM3_ETEAROFF, (uint8_t *)&res, sizeof(uint8_t));
            return;
        } else {

            uint16_t resp_len = 0;
            int res2 = GetIso15693AnswerFromTag(resp, sizeof(resp), ICLASS_READER_TIMEOUT_UPDATE, &eof_time, false, true, &resp_len);
            if (res2 == PM3_SUCCESS && resp_len == 10) {
                res = true;
                break;
            }
        }
    }

    if (tries == 0) {
        res = false;
        goto out;
    }

    // verify write
    uint8_t all_ff[8] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    if (payload->req.blockno == 2) {
        // check response. e-purse update swaps first and second half
        if (memcmp(payload->data + 4, resp, 4) || memcmp(payload->data, resp + 4, 4)) {
            res = false;
            goto out;
        }
    } else if (payload->req.blockno == 3 || payload->req.blockno == 4) {
        // check response. Key updates always return 0xffffffffffffffff
        if (memcmp(all_ff, resp, 8)) {
            res = false;
            goto out;
        }
    } else {
        // check response. All other updates return unchanged data
        if (memcmp(payload->data, resp, 8)) {
            res = false;
            goto out;
        }
    }

out:
    switch_off();

    if (payload->req.send_reply)
        reply_ng(CMD_HF_ICLASS_WRITEBL, PM3_SUCCESS, (uint8_t *)&res, sizeof(uint8_t));
}

void iClass_Restore(iclass_restore_req_t *msg) {

    // sanitation
    if (msg == NULL) {
        reply_ng(CMD_HF_ICLASS_RESTORE, PM3_ESOFT, NULL, 0);
        return;
    }

    if (msg->item_cnt == 0) {
        if (msg->req.send_reply) {
            reply_ng(CMD_HF_ICLASS_RESTORE, PM3_ESOFT, NULL, 0);
        }
        return;
    }

    bool shallow_mod = msg->req.shallow_mod;

    LED_A_ON();
    Iso15693InitReader();

    uint16_t written = 0;
    uint32_t eof_time = 0;
    picopass_hdr_t hdr = {0};

    // select
    bool res = select_iclass_tag(&hdr, msg->req.use_credit_key, &eof_time, shallow_mod);
    if (res == false) {
        goto out;
    }

    // authenticate
    uint8_t mac[4] = {0};
    uint32_t start_time = eof_time + DELAY_ICLASS_VICC_TO_VCD_READER;

    // authenticate
    if (msg->req.do_auth) {
        res = authenticate_iclass_tag(&msg->req, &hdr, &start_time, &eof_time, mac);
        if (res == false) {
            goto out;
        }
    }

    // main loop
    bool use_mac;
    for (uint8_t i = 0; i < msg->item_cnt; i++) {

        iclass_restore_item_t item = msg->blocks[i];

        uint8_t pagemap = get_pagemap(&hdr);
        if (pagemap == PICOPASS_NON_SECURE_PAGEMODE) {
            // Unsecured tags uses CRC16
            use_mac = false;
        } else {
            // Secure tags uses MAC
            use_mac = true;
            uint8_t wb[9] = {0};
            wb[0] = item.blockno;
            memcpy(wb + 1, item.data, 8);

            if (msg->req.use_credit_key)
                doMAC_N(wb, sizeof(wb), hdr.key_c, mac);
            else
                doMAC_N(wb, sizeof(wb), hdr.key_d, mac);
        }

        // data + mac
        if (iclass_writeblock_ext(item.blockno, item.data, mac, use_mac, shallow_mod)) {
            Dbprintf("Write block [%3d/0x%02X] " _GREEN_("successful"), item.blockno, item.blockno);
            written++;
        } else {
            Dbprintf("Write block [%3d/0x%02X] " _RED_("failed"), item.blockno, item.blockno);
        }
    }

out:

    switch_off();
    if (msg->req.send_reply) {
        int isOK = (written == msg->item_cnt) ? PM3_SUCCESS : PM3_ESOFT;
        reply_ng(CMD_HF_ICLASS_RESTORE, isOK, NULL, 0);
    }
}
