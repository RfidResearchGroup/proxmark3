//-----------------------------------------------------------------------------
// Copyright (C) Christian Herrmann, 2020
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
// main code for hf_iceclass by Iceman
//-----------------------------------------------------------------------------
//
// Created for the live streamed talk 'DEFCON 28 Wireless Village-Omikron and Iceman - Ghosting the PACS-man: New Tools and Techniques'
// https://www.youtube.com/watch?v=ghiHXK4GEzE
//
//

#include "standalone.h" // standalone definitions
#include "proxmark3_arm.h"
#include "appmain.h"
#include "BigBuf.h"
#include "fpgaloader.h"
#include "util.h"
#include "ticks.h"
#include "dbprint.h"
#include "spiffs.h"
#include "iclass.h"
#include "iso15693.h"
#include "optimized_cipher.h"
#include "pm3_cmd.h"
#include "protocols.h"


#define ICE_STATE_NONE        0
#define ICE_STATE_FULLSIM     1
#define ICE_STATE_ATTACK      2
#define ICE_STATE_READER      3
#define ICE_STATE_CONFIGCARD  4
#define ICE_STATE_DUMP_SIM    5
#define ICE_STATE_READ_SIM    6

#define HF_ICLASS_NUM_MODES 7

// ====================================================
// Select which standalone function to be active.
// 5 possibilities.  Uncomment the one you wanna use.

#define ICE_USE               ICE_STATE_FULLSIM
//#define ICE_USE               ICE_STATE_ATTACK
//#define ICE_USE               ICE_STATE_READER
//#define ICE_USE               ICE_STATE_CONFIGCARD
//#define ICE_USE               ICE_STATE_DUMP_SIM
//#define ICE_USE               ICE_STATE_READ_SIM

// ====================================================


#define NUM_CSNS                    9
#define MAC_RESPONSES_SIZE          (16 * NUM_CSNS)
#define HF_ICLASS_FULLSIM_ORIG_BIN  "iceclass-orig.bin"
#define HF_ICALSSS_READSIM_TEMP_BIN "iceclass-temp.bin"
#define HF_ICALSSS_READSIM_TEMP_MOD_BIN  "iceclass-temp-mod.bin"
#define HF_ICLASS_FULLSIM_MOD       "iceclass-modified"
#define HF_ICLASS_FULLSIM_MOD_BIN   HF_ICLASS_FULLSIM_MOD".bin"
#define HF_ICLASS_FULLSIM_MOD_EML   HF_ICLASS_FULLSIM_MOD".eml"
#define HF_ICLASS_ATTACK_BIN        "iclass_mac_attack"

#define HF_ICLASS_CC_A              "iceclass_cc_a.bin"
#define HF_ICLASS_CC_B              "iceclass_cc_b.bin"
char *cc_files[] = { HF_ICLASS_CC_A, HF_ICLASS_CC_B };



// times in ssp_clk_cycles @ 3,3625MHz when acting as reader
#ifndef DELAY_ICLASS_VICC_TO_VCD_READER
#define DELAY_ICLASS_VICC_TO_VCD_READER  DELAY_ISO15693_VICC_TO_VCD_READER
#endif

#ifndef ICLASS_16KS_SIZE
#define ICLASS_16KS_SIZE       0x100 * 8
#endif

// iclass card descriptors
char *card_types[] = {
    "PicoPass 16K / 16",                       // 000
    "PicoPass 32K with current book 16K / 16", // 001
    "Unknown Card Type!",                      // 010
    "Unknown Card Type!",                      // 011
    "PicoPass 2K",                             // 100
    "Unknown Card Type!",                      // 101
    "PicoPass 16K / 2",                        // 110
    "PicoPass 32K with current book 16K / 2",  // 111
};

uint8_t card_app2_limit[] = {
    0xff,
    0xff,
    0xff,
    0xff,
    0x1f,
    0xff,
    0xff,
    0xff,
};

static uint8_t aa2_key[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
static uint8_t legacy_aa1_key[] = {0xAE, 0xA6, 0x84, 0xA6, 0xDA, 0xB2, 0x32, 0x78};

static bool have_aa2(void) {
    return memcmp(aa2_key, "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", 8);
}

static uint8_t get_pagemap(const picopass_hdr_t *hdr) {
    return (hdr->conf.fuses & (FUSE_CRYPT0 | FUSE_CRYPT1)) >> 3;
}

static uint8_t csns[8 * NUM_CSNS] = {
    0x01, 0x0A, 0x0F, 0xFF, 0xF7, 0xFF, 0x12, 0xE0,
    0x0C, 0x06, 0x0C, 0xFE, 0xF7, 0xFF, 0x12, 0xE0,
    0x10, 0x97, 0x83, 0x7B, 0xF7, 0xFF, 0x12, 0xE0,
    0x13, 0x97, 0x82, 0x7A, 0xF7, 0xFF, 0x12, 0xE0,
    0x07, 0x0E, 0x0D, 0xF9, 0xF7, 0xFF, 0x12, 0xE0,
    0x14, 0x96, 0x84, 0x76, 0xF7, 0xFF, 0x12, 0xE0,
    0x17, 0x96, 0x85, 0x71, 0xF7, 0xFF, 0x12, 0xE0,
    0xCE, 0xC5, 0x0F, 0x77, 0xF7, 0xFF, 0x12, 0xE0,
    0xD2, 0x5A, 0x82, 0xF8, 0xF7, 0xFF, 0x12, 0xE0
};

static void download_instructions(uint8_t t) {
    DbpString("");
    switch (t) {
        case ICE_STATE_FULLSIM: {
            DbpString("The emulator memory was saved to SPIFFS");
            DbpString("1. " _YELLOW_("mem spiffs dump -s " HF_ICLASS_FULLSIM_MOD_BIN " -d " HF_ICLASS_FULLSIM_MOD" -e"));
            DbpString("2. " _YELLOW_("hf iclass view -f " HF_ICLASS_FULLSIM_MOD_BIN));
            break;
        }
        case ICE_STATE_ATTACK: {
            DbpString("The collected data was saved to SPIFFS. The file names below may differ");
            DbpString("1. " _YELLOW_("mem spiffs tree"));
            DbpString("2. " _YELLOW_("mem spiffs dump -s " HF_ICLASS_ATTACK_BIN " -d " HF_ICLASS_ATTACK_BIN));
            DbpString("3. " _YELLOW_("hf iclass loclass -f " HF_ICLASS_ATTACK_BIN));
            break;
        }
        case ICE_STATE_READER: {
            DbpString("The found tags was saved to SPIFFS");
            DbpString("1. " _YELLOW_("mem spiffs tree"));
            DbpString("2. " _YELLOW_("mem spiffs dump -h"));
            break;
        }
        case ICE_STATE_DUMP_SIM: {
            DbpString("The found tag will be dumped to " HF_ICALSSS_READSIM_TEMP_BIN);
            DbpString("1. " _YELLOW_("mem spiffs tree"));
            DbpString("2. " _YELLOW_("mem spiffs dump -h"));
            break;
        }
    }
}

// Save to flash if file doesn't exist.
// Write over file if size of flash file is less than new datalen
static void save_to_flash(uint8_t *data, uint16_t datalen, char *filename) {

    rdv40_spiffs_lazy_mount();

    char fn[SPIFFS_OBJ_NAME_LEN];
    memset(fn, 0, sizeof(fn));

    if (filename == NULL) {
        sprintf(fn, "iclass-%02X%02X%02X%02X%02X%02X%02X%02X.bin",
                data[0], data[1], data[2], data[3],
                data[4], data[5], data[6], data[7]
               );
    } else {
        int fnlen = MIN(strlen(filename), SPIFFS_OBJ_NAME_LEN - 1);
        // if the given name len longer than buffer allows, cut it down to size
        memcpy(fn, filename, fnlen);
    }

    int res;
    if (exists_in_spiffs(fn) == false) {
        res = rdv40_spiffs_write(fn, data, datalen, RDV40_SPIFFS_SAFETY_SAFE);
        if (res == SPIFFS_OK) {
            Dbprintf("saved to " _GREEN_("%s"), fn);
        }
    } else {

        // if already exist,  see if saved file is smaller..
        uint32_t fsize = 0;
        res = rdv40_spiffs_stat(fn, &fsize, RDV40_SPIFFS_SAFETY_SAFE);
        if (res == SPIFFS_OK) {

            if (fsize < datalen) {
                res = rdv40_spiffs_write(fn, data, datalen, RDV40_SPIFFS_SAFETY_SAFE);
                if (res == SPIFFS_OK) {
                    Dbprintf("wrote over " _GREEN_("%s"), fn);
                }
            }
        }
    }

    rdv40_spiffs_lazy_unmount();
}

static int fullsim_mode(void) {

    rdv40_spiffs_lazy_mount();

    SpinOff(0);
    uint8_t *emul = BigBuf_get_EM_addr();
    uint32_t fsize = size_in_spiffs(HF_ICLASS_FULLSIM_ORIG_BIN);
    int res = rdv40_spiffs_read_as_filetype(HF_ICLASS_FULLSIM_ORIG_BIN, emul, fsize, RDV40_SPIFFS_SAFETY_SAFE);
    rdv40_spiffs_lazy_unmount();
    if (res == SPIFFS_OK) {
        Dbprintf("loaded " _GREEN_(HF_ICLASS_FULLSIM_ORIG_BIN) " (%u bytes)", fsize);
    }

    iclass_simulate(ICLASS_SIM_MODE_FULL, 0, false, NULL, NULL, NULL);

    LED_B_ON();
    rdv40_spiffs_lazy_mount();
    res = rdv40_spiffs_write(HF_ICLASS_FULLSIM_MOD_BIN, emul, fsize, RDV40_SPIFFS_SAFETY_SAFE);
    rdv40_spiffs_lazy_unmount();
    LED_B_OFF();
    if (res == SPIFFS_OK) {
        Dbprintf("wrote emulator memory to " _GREEN_(HF_ICLASS_FULLSIM_MOD_BIN));
    } else {
        Dbprintf(_RED_("error") " writing "HF_ICLASS_FULLSIM_MOD_BIN" to flash ( %d )", res);
    }

    DbpString("-=[ exiting " _CYAN_("`full simulation`") " mode ]=-");
    return PM3_SUCCESS;
}

static int reader_attack_mode(void) {

    BigBuf_free();
    uint16_t mac_response_len = 0;
    uint8_t *mac_responses = BigBuf_malloc(MAC_RESPONSES_SIZE);

    iclass_simulate(ICLASS_SIM_MODE_READER_ATTACK, NUM_CSNS, false, csns, mac_responses, &mac_response_len);

    if (mac_response_len > 0) {

        bool success = (mac_response_len == MAC_RESPONSES_SIZE);
        uint8_t num_mac = (mac_response_len >> 4);
        Dbprintf("%u out of %d MAC obtained ( %s )", num_mac, NUM_CSNS, (success) ? _GREEN_("ok") : _RED_("fail"));

        size_t dumplen = NUM_CSNS * 24;

        uint8_t *dump = BigBuf_malloc(dumplen);
        if (dump == false) {
            Dbprintf("failed to allocate memory");
            return PM3_EMALLOC;
        }

        // need zeroes for the EPURSE
        memset(dump, 0, dumplen);

        for (uint8_t i = 0 ; i < NUM_CSNS ; i++) {
            //copy CSN
            memcpy(dump + (i * 24), csns + (i * 8), 8);
            //copy epurse
            memcpy(dump + (i * 24) + 8, mac_responses + (i * 16), 8);
            // NR_MAC (eight bytes from the response)  ( 8b csn + 8b epurse == 16)
            memcpy(dump + (i * 24) + 16, mac_responses + (i * 16) + 8, 8);
        }

        LED_B_ON();
        rdv40_spiffs_lazy_mount();

        char fn[32];
        uint16_t p_namelen = strlen(HF_ICLASS_ATTACK_BIN);
        uint16_t num = 1;
        sprintf(fn, "%.*s%s", p_namelen, HF_ICLASS_ATTACK_BIN, ".bin");

        while (exists_in_spiffs(fn)) {
            sprintf(fn, "%.*s-%u%s", p_namelen, HF_ICLASS_ATTACK_BIN, num, ".bin");
            num++;
        }
        int res = rdv40_spiffs_write(fn, dump, dumplen, RDV40_SPIFFS_SAFETY_SAFE);
        rdv40_spiffs_lazy_unmount();
        LED_B_OFF();
        if (res == SPIFFS_OK) {
            Dbprintf("saved to " _GREEN_("%s"), fn);
        } else {
            Dbprintf(_RED_("error") " writing %s to flash ( %d )", fn, res);
        }
    }
    BigBuf_free();
    DbpString("-=[ exiting " _CYAN_("`reader attack`") " mode ]=-");
    return PM3_SUCCESS;
}

static int reader_dump_mode(void) {

    DbpString("this mode has no tracelog");
    if (have_aa2())
        DbpString("dumping of " _YELLOW_("AA2 enabled"));

    for (;;) {

        BigBuf_free();

        uint8_t *card_data = BigBuf_malloc(ICLASS_16KS_SIZE);
        memset(card_data, 0xFF, ICLASS_16KS_SIZE);

        if (BUTTON_PRESS()) {
            DbpString("button pressed");
            break;
        }

        // setup authenticate AA1
        iclass_auth_req_t auth = {
            .use_raw = false,
            .use_elite = false,
            .use_credit_key = false,
            .do_auth = true,
            .send_reply = false,
            .shallow_mod = false,
        };
        memcpy(auth.key, legacy_aa1_key, sizeof(auth.key));

        Iso15693InitReader();
        set_tracing(false);


        picopass_hdr_t *hdr = (picopass_hdr_t *)card_data;

        // select tag.
        uint32_t eof_time = 0;
        bool res = select_iclass_tag(hdr, auth.use_credit_key, &eof_time, false);
        if (res == false) {
            switch_off();
            continue;
        }

        // sanity check of CSN.
        if (hdr->csn[7] != 0xE0 && hdr->csn[6] != 0x12) {
            switch_off();
            continue;
        }

        uint32_t start_time = eof_time + DELAY_ICLASS_VICC_TO_VCD_READER;

        // get 3 config bits
        uint8_t type = (hdr->conf.chip_config & 0x10) >> 2;
        type |= (hdr->conf.mem_config & 0x80) >> 6;
        type |= (hdr->conf.mem_config & 0x20) >> 5;

        Dbprintf(_GREEN_("%s") ", dumping...", card_types[type]);

        uint8_t pagemap = get_pagemap(hdr);
        uint8_t app1_limit, app2_limit, start_block;

        // tags configured for NON SECURE PAGE,  acts different
        if (pagemap == PICOPASS_NON_SECURE_PAGEMODE) {
            app1_limit = card_app2_limit[type];
            app2_limit = 0;
            start_block = 3;
        } else {

            app1_limit = hdr->conf.app_limit;
            app2_limit = card_app2_limit[type];
            start_block = 5;

            res = authenticate_iclass_tag(&auth, hdr, &start_time, &eof_time, NULL);
            if (res == false) {
                switch_off();
                Dbprintf(_RED_("failed AA1 auth") ", skipping ");
                continue;
            }

            start_time = eof_time + DELAY_ICLASS_VICC_TO_VCD_READER;
        }

        uint16_t dumped = 0;

        // main read loop
        for (uint16_t i = start_block; i <= app1_limit; i++) {
            if (iclass_read_block(i, card_data + (8 * i), &start_time, &eof_time, false)) {
                dumped++;
            }
        }

        if (pagemap != PICOPASS_NON_SECURE_PAGEMODE && have_aa2()) {

            // authenticate AA2
            auth.use_raw = false;
            auth.use_credit_key = true;
            memcpy(auth.key, aa2_key, sizeof(auth.key));

            res = select_iclass_tag(hdr, auth.use_credit_key, &eof_time, false);
            if (res) {

                // sanity check of CSN.
                if (hdr->csn[7] != 0xE0 && hdr->csn[6] != 0x12) {
                    switch_off();
                    continue;
                }

                res = authenticate_iclass_tag(&auth, hdr, &start_time, &eof_time, NULL);
                if (res) {
                    start_time = eof_time + DELAY_ICLASS_VICC_TO_VCD_READER;

                    for (uint16_t i = app1_limit + 1; i <= app2_limit; i++) {
                        if (iclass_read_block(i, card_data + (8 * i), &start_time, &eof_time, false)) {
                            dumped++;
                        }
                    }
                } else {
                    DbpString(_RED_("failed AA2 auth"));
                }
            } else {
                DbpString(_RED_("failed selecting AA2"));

                // sanity check of CSN.
                if (hdr->csn[7] != 0xE0 && hdr->csn[6] != 0x12) {
                    switch_off();
                    continue;
                }
            }
        }
        switch_off();
        save_to_flash(card_data, (start_block + dumped) * 8, NULL);
        Dbprintf("%u bytes saved", (start_block + dumped) * 8);
    }
    DbpString("-=[ exiting " _CYAN_("`read & dump`") " mode ]=-");
    return PM3_SUCCESS;
}

static int dump_sim_mode(void) {

    DbpString("this mode has no tracelog");
    if (have_aa2())
        DbpString("dumping of " _YELLOW_("AA2 enabled"));

    for (;;) {

        BigBuf_free();

        uint8_t *card_data = BigBuf_malloc(ICLASS_16KS_SIZE);
        memset(card_data, 0xFF, ICLASS_16KS_SIZE);

        if (BUTTON_PRESS()) {
            DbpString("button pressed");
            break;
        }

        // setup authenticate AA1
        iclass_auth_req_t auth = {
            .use_raw = false,
            .use_elite = false,
            .use_credit_key = false,
            .do_auth = true,
            .send_reply = false,
            .shallow_mod = false,
        };
        memcpy(auth.key, legacy_aa1_key, sizeof(auth.key));

        Iso15693InitReader();
        set_tracing(false);


        picopass_hdr_t *hdr = (picopass_hdr_t *)card_data;

        // select tag.
        uint32_t eof_time = 0;
        bool res = select_iclass_tag(hdr, auth.use_credit_key, &eof_time, false);
        if (res == false) {
            switch_off();
            continue;
        }

        // sanity check of CSN.
        if (hdr->csn[7] != 0xE0 && hdr->csn[6] != 0x12) {
            switch_off();
            continue;
        }

        uint32_t start_time = eof_time + DELAY_ICLASS_VICC_TO_VCD_READER;

        // get 3 config bits
        uint8_t type = (hdr->conf.chip_config & 0x10) >> 2;
        type |= (hdr->conf.mem_config & 0x80) >> 6;
        type |= (hdr->conf.mem_config & 0x20) >> 5;

        Dbprintf(_GREEN_("%s") ", dumping...", card_types[type]);

        uint8_t pagemap = get_pagemap(hdr);
        uint8_t app1_limit, app2_limit, start_block;

        // tags configured for NON SECURE PAGE,  acts different
        if (pagemap == PICOPASS_NON_SECURE_PAGEMODE) {
            app1_limit = card_app2_limit[type];
            app2_limit = 0;
            start_block = 3;
        } else {

            app1_limit = hdr->conf.app_limit;
            app2_limit = card_app2_limit[type];
            start_block = 5;

            res = authenticate_iclass_tag(&auth, hdr, &start_time, &eof_time, NULL);
            if (res == false) {
                switch_off();
                Dbprintf(_RED_("failed AA1 auth") ", skipping ");
                continue;
            }

            start_time = eof_time + DELAY_ICLASS_VICC_TO_VCD_READER;
        }

        uint16_t dumped = 0;

        // main read loop
        for (uint16_t i = start_block; i <= app1_limit; i++) {
            if (iclass_read_block(i, card_data + (8 * i), &start_time, &eof_time, false)) {
                dumped++;
            }
        }

        if (pagemap != PICOPASS_NON_SECURE_PAGEMODE && have_aa2()) {

            // authenticate AA2
            auth.use_raw = false;
            auth.use_credit_key = true;
            memcpy(auth.key, aa2_key, sizeof(auth.key));

            res = select_iclass_tag(hdr, auth.use_credit_key, &eof_time, false);
            if (res) {

                // sanity check of CSN.
                if (hdr->csn[7] != 0xE0 && hdr->csn[6] != 0x12) {
                    switch_off();
                    continue;
                }

                res = authenticate_iclass_tag(&auth, hdr, &start_time, &eof_time, NULL);
                if (res) {
                    start_time = eof_time + DELAY_ICLASS_VICC_TO_VCD_READER;

                    for (uint16_t i = app1_limit + 1; i <= app2_limit; i++) {
                        if (iclass_read_block(i, card_data + (8 * i), &start_time, &eof_time, false)) {
                            dumped++;
                        }
                    }
                } else {
                    DbpString(_RED_("failed AA2 auth"));
                }
            } else {
                DbpString(_RED_("failed selecting AA2"));

                // sanity check of CSN.
                if (hdr->csn[7] != 0xE0 && hdr->csn[6] != 0x12) {
                    switch_off();
                    continue;
                }
            }
        }
        switch_off();
        char *temp_file = HF_ICALSSS_READSIM_TEMP_BIN;
        save_to_flash(card_data, (start_block + dumped) * 8, temp_file);
        Dbprintf("%u bytes saved", (start_block + dumped) * 8);

        if (((start_block + dumped) * 8) > 0) {
            break; //switch to sim mode
        }
    }

    rdv40_spiffs_lazy_mount();

    SpinOff(0);
    uint8_t *emul = BigBuf_get_EM_addr();
    uint32_t fsize = size_in_spiffs(HF_ICALSSS_READSIM_TEMP_BIN);
    int res = rdv40_spiffs_read_as_filetype(HF_ICALSSS_READSIM_TEMP_BIN, emul, fsize, RDV40_SPIFFS_SAFETY_SAFE);
    rdv40_spiffs_lazy_unmount();
    if (res == SPIFFS_OK) {
        Dbprintf("loaded " _GREEN_(HF_ICALSSS_READSIM_TEMP_BIN) " (%u bytes)", fsize);
    }

    Dbprintf("simming " _GREEN_(HF_ICALSSS_READSIM_TEMP_BIN));
    iclass_simulate(ICLASS_SIM_MODE_FULL, 0, false, NULL, NULL, NULL);

    LED_B_ON();
    rdv40_spiffs_lazy_mount();
    res = rdv40_spiffs_write(HF_ICALSSS_READSIM_TEMP_BIN, emul, fsize, RDV40_SPIFFS_SAFETY_SAFE);
    rdv40_spiffs_lazy_unmount();
    LED_B_OFF();
    if (res == SPIFFS_OK) {
        Dbprintf("wrote emulator memory to " _GREEN_(HF_ICALSSS_READSIM_TEMP_MOD_BIN));
    } else {
        Dbprintf(_RED_("error") " writing "HF_ICALSSS_READSIM_TEMP_MOD_BIN" to flash ( %d )", res);
    }

    DbpString("-=[ exiting " _CYAN_("`dump & sim`") " mode ]=-");
    return PM3_SUCCESS;
}

static int config_sim_mode(void) {

    uint8_t *emul = BigBuf_get_EM_addr();

    for (uint8_t i = 0; i < 2; i++) {
        SpinOff(0);
        rdv40_spiffs_lazy_mount();
        uint32_t fsize = size_in_spiffs(cc_files[i]);
        int res = rdv40_spiffs_read_as_filetype(cc_files[i], emul, fsize, RDV40_SPIFFS_SAFETY_SAFE);
        rdv40_spiffs_lazy_unmount();

        if (res == SPIFFS_OK) {
            Dbprintf("loaded " _GREEN_("%s") " (%u bytes) to emulator memory", cc_files[i], fsize);
            iclass_simulate(ICLASS_SIM_MODE_FULL, 0, false, NULL, NULL, NULL);
        }
    }

    DbpString("-=[ exiting " _CYAN_("`glitch & config`") " mode ]=-");
    return PM3_SUCCESS;
}

void ModInfo(void) {
    DbpString("  HF iCLASS mode -  aka iceCLASS (iceman)");
}

void RunMod(void) {

    uint8_t mode = ICE_USE;
    uint8_t *bb = BigBuf_get_EM_addr();
    if (bb[0] > 0 && bb[0] < HF_ICLASS_NUM_MODES) {
        mode = bb[0];
    }

    FpgaDownloadAndGo(FPGA_BITSTREAM_HF_15);
    BigBuf_Clear_ext(false);

    StandAloneMode();
    Dbprintf(_YELLOW_("HF iCLASS mode a.k.a iceCLASS started"));


    for (;;) {

        WDT_HIT();

        if (mode == ICE_STATE_NONE) break;
        if (data_available()) break;

        int res;
        switch (mode) {

            case ICE_STATE_FULLSIM: {
                DbpString("-=[ enter " _CYAN_("`full simulation`") " mode ]=-");

                // Look for iCLASS dump file
                rdv40_spiffs_lazy_mount();
                if (exists_in_spiffs(HF_ICLASS_FULLSIM_ORIG_BIN) == false) {
                    Dbprintf(_RED_("error") " " _YELLOW_(HF_ICLASS_FULLSIM_ORIG_BIN) " file missing");
                    mode = ICE_STATE_NONE;
                }
                rdv40_spiffs_lazy_unmount();

                if (mode == ICE_STATE_FULLSIM) {
                    res = fullsim_mode();
                    if (res == PM3_SUCCESS) {
                        download_instructions(mode);
                    }
                }
                // the button press to exit sim, is captured in main loop here
                mode = ICE_STATE_NONE;
                break;
            }
            case ICE_STATE_ATTACK: {
                DbpString("-=[ enter " _CYAN_("`reader attack`") " mode ]=-");
                res = reader_attack_mode();
                if (res == PM3_SUCCESS)
                    download_instructions(mode);

                mode = ICE_STATE_NONE;
                break;
            }
            case ICE_STATE_READER: {
                DbpString("-=[ enter " _CYAN_("`read & dump`") " mode, continuous scanning ]=-");
                res = reader_dump_mode();
                if (res == PM3_SUCCESS)
                    download_instructions(mode);

                mode = ICE_STATE_NONE;
                break;
            }
            case ICE_STATE_CONFIGCARD: {
                DbpString("-=[ enter " _CYAN_("`glitch & config`") " mode ]=-");

                // Look for config cards
                rdv40_spiffs_lazy_mount();
                for (uint8_t i = 0; i < 2; i++) {
                    if (exists_in_spiffs(cc_files[i]) == false) {
                        Dbprintf(_RED_("error") ", " _YELLOW_("%s") " file missing", cc_files[i]);
                        mode = ICE_STATE_NONE;
                    }
                }
                rdv40_spiffs_lazy_unmount();

                if (mode == ICE_STATE_CONFIGCARD)
                    config_sim_mode();

                mode = ICE_STATE_NONE;
                break;
            }
            case ICE_STATE_DUMP_SIM: {
                DbpString("-=[ enter " _CYAN_("`dump & sim`") " mode, read 1 card and sim it ]=-");
                res = dump_sim_mode();
                if (res == PM3_SUCCESS) {
                    download_instructions(mode);
                }

                mode = ICE_STATE_NONE;
                break;
            }
            case ICE_STATE_READ_SIM: {
                DbpString("-=[ enter " _CYAN_("`read & sim`") " mode, read cards, then sim after button press ]=-");
                DbpString("Entering reader dump mode");
                reader_dump_mode();
                SpinDelay(1200); // debounce button press
                DbpString("Entering fullsim mode");
                fullsim_mode();
                DbpString("Exiting fullsim mode");
                LEDsoff();
            }
        }
    }

    switch_off();
    Dbprintf("-=[ exit ]=-");
}
