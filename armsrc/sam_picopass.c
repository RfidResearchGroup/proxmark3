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
// Routines to support Picopass <-> SAM communication
//-----------------------------------------------------------------------------
#include "sam_picopass.h"
#include "iclass.h"
#include "crc16.h"
#include "proxmark3_arm.h"
#include "BigBuf.h"
#include "cmd.h"
#include "commonutil.h"
#include "ticks.h"
#include "dbprint.h"
#include "i2c.h"
#include "iso15693.h"
#include "protocols.h"
#include "optimized_cipher.h"
#include "fpgaloader.h"

static int sam_rxtx(const uint8_t *data, uint16_t n, uint8_t *resp, uint16_t *resplen) {

    StartTicks();

    bool res = I2C_BufferWrite(data, n, I2C_DEVICE_CMD_SEND_T0, I2C_DEVICE_ADDRESS_MAIN);
    if (res == false) {
        DbpString("failed to send to SIM CARD");
        goto out;
    }

    *resplen = ISO7816_MAX_FRAME;

    res = sc_rx_bytes(resp, resplen, SIM_WAIT_DELAY);
    if (res == false) {
        DbpString("failed to receive from SIM CARD");
        goto out;
    }

    if (*resplen < 2) {
        DbpString("received too few bytes from SIM CARD");
        res = false;
        goto out;
    }

    uint16_t more_len = 0;

    if (resp[*resplen - 2] == 0x61 || resp[*resplen - 2] == 0x9F) {
        more_len = resp[*resplen - 1];
    } else {
        // we done, return
        goto out;
    }

    // Don't discard data we already received except the SW code.
    // If we only received 1 byte, this is the echo of INS, we discard it.
    *resplen -= 2;
    if (*resplen == 1) {
        *resplen = 0;
    }

    uint8_t cmd_getresp[] = {0x00, ISO7816_GET_RESPONSE, 0x00, 0x00, more_len};

    res = I2C_BufferWrite(cmd_getresp, sizeof(cmd_getresp), I2C_DEVICE_CMD_SEND_T0, I2C_DEVICE_ADDRESS_MAIN);
    if (res == false) {
        DbpString("failed to send to SIM CARD 2");
        goto out;
    }

    more_len = 255 - *resplen;

    res = sc_rx_bytes(resp + *resplen, &more_len, SIM_WAIT_DELAY);
    if (res == false) {
        DbpString("failed to receive from SIM CARD 2");
        goto out;
    }

    *resplen += more_len;

out:
    StopTicks();
    return res;
}

// using HID SAM to authenticate w PICOPASS
int sam_picopass_get_pacs(void) {

    static uint8_t act_all[] = { ICLASS_CMD_ACTALL };
    static uint8_t identify[] = { ICLASS_CMD_READ_OR_IDENTIFY, 0x00, 0x73, 0x33 };
    static uint8_t read_conf[] = { ICLASS_CMD_READ_OR_IDENTIFY, 0x01, 0xfa, 0x22 };
    uint8_t select[] = { 0x80 | ICLASS_CMD_SELECT, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    uint8_t read_aia[] = { ICLASS_CMD_READ_OR_IDENTIFY, 0x05, 0xde, 0x64};
    uint8_t read_check_cc[] = { 0x80 | ICLASS_CMD_READCHECK, 0x02 };

    picopass_hdr_t hdr = {0};
    // Bit 4: K.If this bit equals to one, the READCHECK will use the Credit Key (Kc); if equals to zero, Debit Key (Kd) will be used
    // bit 7: parity.
    // if (use_credit_key)
    //     read_check_cc[0] = 0x10 | ICLASS_CMD_READCHECK;

    BigBuf_free_keep_EM();

    clear_trace();

    I2C_Reset_EnterMainProgram();
    StopTicks();

    uint8_t *resp = BigBuf_calloc(ISO7816_MAX_FRAME);

    bool shallow_mod = false;
    uint16_t resp_len = 0;
    int res;
    uint32_t eof_time = 0;

    // wakeup
    Iso15693InitReader();

    uint32_t start_time = GetCountSspClk();
    iclass_send_as_reader(act_all, 1, &start_time, &eof_time, shallow_mod);

    res = GetIso15693AnswerFromTag(resp, ISO7816_MAX_FRAME, ICLASS_READER_TIMEOUT_ACTALL, &eof_time, false, true, &resp_len);
    if (res != PM3_SUCCESS) {
        res = PM3_ECARDEXCHANGE;
        goto out;
    }

    // send Identify
    start_time = eof_time + DELAY_ICLASS_VICC_TO_VCD_READER;
    iclass_send_as_reader(identify, 1, &start_time, &eof_time, shallow_mod);

    // expect a 10-byte response here, 8 byte anticollision-CSN and 2 byte CRC
    res = GetIso15693AnswerFromTag(resp, ISO7816_MAX_FRAME, ICLASS_READER_TIMEOUT_OTHERS, &eof_time, false, true, &resp_len);
    if (res != PM3_SUCCESS || resp_len != 10) {
        res = PM3_ECARDEXCHANGE;
        goto out;
    }

    // copy the Anti-collision CSN to our select-packet
    memcpy(&select[1], resp, 8);

    // select the card
    start_time = eof_time + DELAY_ICLASS_VICC_TO_VCD_READER;
    iclass_send_as_reader(select, sizeof(select), &start_time, &eof_time, shallow_mod);

    // expect a 10-byte response here, 8 byte CSN and 2 byte CRC
    res = GetIso15693AnswerFromTag(resp, ISO7816_MAX_FRAME, ICLASS_READER_TIMEOUT_OTHERS, &eof_time, false, true, &resp_len);
    if (res != PM3_SUCCESS || resp_len != 10) {
        res = PM3_ECARDEXCHANGE;
        goto out;
    }

    // store CSN
    memcpy(hdr.csn, resp, sizeof(hdr.csn));

    // card selected, now read config (block1) (only 8 bytes no CRC)
    start_time = eof_time + DELAY_ICLASS_VICC_TO_VCD_READER;
    iclass_send_as_reader(read_conf, sizeof(read_conf), &start_time, &eof_time, shallow_mod);

    // expect a 8-byte response here
    res = GetIso15693AnswerFromTag(resp, ISO7816_MAX_FRAME, ICLASS_READER_TIMEOUT_OTHERS, &eof_time, false, true, &resp_len);
    if (res != PM3_SUCCESS || resp_len != 10) {
        res = PM3_ECARDEXCHANGE;
        goto out;
    }

    // store CONFIG
    memcpy((uint8_t *)&hdr.conf, resp, sizeof(hdr.conf));

    uint8_t pagemap = get_pagemap(&hdr);
    if (pagemap == PICOPASS_NON_SECURE_PAGEMODE) {
        res = PM3_EWRONGANSWER;
        goto out;
    }

    // read App Issuer Area block 5
    start_time = eof_time + DELAY_ICLASS_VICC_TO_VCD_READER;
    iclass_send_as_reader(read_aia, sizeof(read_aia), &start_time, &eof_time, shallow_mod);

    // expect a 10-byte response here
    res = GetIso15693AnswerFromTag(resp, ISO7816_MAX_FRAME, ICLASS_READER_TIMEOUT_OTHERS, &eof_time, false, true, &resp_len);
    if (res != PM3_SUCCESS || resp_len != 10) {
        res = PM3_ECARDEXCHANGE;
        goto out;
    }

    // store AIA
    memcpy(hdr.app_issuer_area, resp, sizeof(hdr.app_issuer_area));

    // card selected, now read e-purse (cc) (block2) (only 8 bytes no CRC)
    start_time = eof_time + DELAY_ICLASS_VICC_TO_VCD_READER;
    iclass_send_as_reader(read_check_cc, sizeof(read_check_cc), &start_time, &eof_time, shallow_mod);

    // expect a 8-byte response here
    res = GetIso15693AnswerFromTag(resp, ISO7816_MAX_FRAME, ICLASS_READER_TIMEOUT_OTHERS, &eof_time, false, true, &resp_len);
    if (res != PM3_SUCCESS || resp_len != 8) {
        res = PM3_ECARDEXCHANGE;
        goto out;
    }

    // store EPURSE
    memcpy(hdr.epurse, resp, sizeof(hdr.epurse));

    // -----------------------------------------------------------------------------
    // SAM comms
    // -----------------------------------------------------------------------------
    size_t sam_len = 0;
    uint8_t *sam_apdu = BigBuf_calloc(ISO7816_MAX_FRAME);

    // -----------------------------------------------------------------------------
    // first
    // a0 da 02 63 1a 44 0a 44 00 00 00 a0 12 ad 10 a0 0e 80 02 00 04 81 08 9b fc a4 00 fb ff 12 e0
    hexstr_to_byte_array("a0da02631a440a44000000a012ad10a00e800200048108", sam_apdu, &sam_len);
    memcpy(sam_apdu + sam_len, hdr.csn, sizeof(hdr.csn));
    sam_len += sizeof(hdr.csn);

    if (sam_rxtx(sam_apdu, sam_len, resp, &resp_len) == false) {
        res = PM3_ECARDEXCHANGE;
        goto out;
    }
    print_dbg("-- 1", resp, resp_len);

    // -----------------------------------------------------------------------------
    // second
    // a0 da 02 63 0d 44 0a 44 00 00 00 a0 05 a1 03 80 01 04
    hexstr_to_byte_array("a0da02630d440a44000000a005a103800104", sam_apdu, &sam_len);
    if (sam_rxtx(sam_apdu, sam_len, resp, &resp_len) == false) {
        res = PM3_ECARDEXCHANGE;
        goto out;
    }
    print_dbg("-- 2", resp, resp_len);

    // TAG response
    // --  0c 05 de64 // read block 5
    // Tag|c00a140a000000a110a10e8004 0c05de64 8102 0004 820201f4

    // -----------------------------------------------------------------------------
    // third   AIA block 5
    // a0da02631c140a00000000bd14a012a010800a ffffff0006fffffff88e 81020000
    //  picopass  legacy is fixed.  wants AIA and crc. ff ff ff ff ff ff ff ff ea f5
    //  picpoasss SE                                   ff ff ff 00 06 ff ff ff f8 8e
    hexstr_to_byte_array("a0da02631c140a00000000bd14a012a010800affffff0006fffffff88e81020000", sam_apdu, &sam_len);
    memcpy(sam_apdu + 19, hdr.app_issuer_area, sizeof(hdr.app_issuer_area));
    AddCrc(sam_apdu + 19, 8);

    if (sam_rxtx(sam_apdu, sam_len, resp, &resp_len) == false) {
        res = PM3_ECARDEXCHANGE;
        goto out;
    }
    print_dbg("-- 3", resp, resp_len);

    // 88 02 --  readcheck  (block2 epurse, start of auth)
    // Tag|c00a140a000000a10ea10c8002 8802 8102 0004 820201f4 9000
    //    61 16 f5 0a140a000000a10ea10c 8002 8802 8102 0004 820201f4 9000

    // -----------------------------------------------------------------------------
    // forth  EPURSE
    // a0da02631a140a00000000bd12a010a00e8008 ffffffffedffffff 81020000
    hexstr_to_byte_array("a0da02631a140a00000000bd12a010a00e8008ffffffffedffffff81020000", sam_apdu, &sam_len);
    memcpy(sam_apdu + 19, hdr.epurse, sizeof(hdr.epurse));

    if (sam_rxtx(sam_apdu, sam_len, resp, &resp_len) == false) {
        res = PM3_ECARDEXCHANGE;
        goto out;
    }
    print_dbg("-- 4", resp, resp_len);

    uint8_t nr_mac[9] = {0};
    memcpy(nr_mac, resp + 11, sizeof(nr_mac));
    // resp here hold the whole   NR/MAC
    // 05 9bcd475e965ee20e // CHECK (w key)
    print_dbg("NR/MAC", nr_mac, sizeof(nr_mac));

    // c00a140a000000a115a1138009 059bcd475e965ee20e 8102 0004 820201f4 9000

    // pre calc ourself?
    // uint8_t cc_nr[] = {0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0};
    uint8_t div_key[8] = {0};
    static uint8_t legacy_aa1_key[] = {0xAE, 0xA6, 0x84, 0xA6, 0xDA, 0xB2, 0x32, 0x78};
    iclass_calc_div_key(hdr.csn, legacy_aa1_key, div_key, false);

    uint8_t mac[4] = {0};
    if (g_dbglevel == DBG_DEBUG) {
        uint8_t wb[16] = {0};
        memcpy(wb, hdr.epurse, sizeof(hdr.epurse));
        memcpy(wb + sizeof(hdr.epurse), nr_mac + 1, 4);
        print_dbg("cc_nr...", wb, sizeof(wb));
        doMAC_N(wb, sizeof(wb), div_key, mac);
        print_dbg("Calc MAC...", mac, sizeof(mac));
    }

    // start ssp clock again...
    StartCountSspClk();

    // NOW we auth against tag
    uint8_t cmd_check[9] = { ICLASS_CMD_CHECK };
    memcpy(cmd_check + 1, nr_mac + 1, 8);

    start_time = GetCountSspClk();
    iclass_send_as_reader(cmd_check, sizeof(cmd_check), &start_time, &eof_time, shallow_mod);

    // expect a 10-byte response here
    res = GetIso15693AnswerFromTag(resp, ISO7816_MAX_FRAME, ICLASS_READER_TIMEOUT_OTHERS, &eof_time, false, true, &resp_len);
    if (res != PM3_SUCCESS || resp_len != 4) {
        res = PM3_ECARDEXCHANGE;
        goto out;
    }
    // store MAC
    memcpy(mac, resp, sizeof(mac));
    print_dbg("Got MAC", mac, sizeof(mac));

    // -----------------------------------------------------------------------------
    // fifth  send received MAC
    // A0DA026316140A00000000BD0EA00CA00A8004 311E32E9 81020000
    hexstr_to_byte_array("A0DA026316140A00000000BD0EA00CA00A8004311E32E981020000", sam_apdu, &sam_len);
    memcpy(sam_apdu + 19, mac, sizeof(mac));

    if (sam_rxtx(sam_apdu, sam_len, resp, &resp_len) == false) {
        res = PM3_ECARDEXCHANGE;
        goto out;
    }
    print_dbg("-- 5", resp, resp_len);

    uint8_t tmp_p1[4] = {0};
    uint8_t tmp_p2[4] = {0};

    // c161c10000a11aa118800e8702 ffffffff88ffffff 0a914eb981020004820236b09000

    memcpy(tmp_p1, resp + 13, sizeof(tmp_p1));
    memcpy(tmp_p2, resp + 13 + 4, sizeof(tmp_p2));
    // -----------------------------------------------------------------------------
    // sixth  send fake epurse update
    // A0DA02631C140A00000000BD14A012A010800A 88FFFFFFFFFFFFFF9DE1 81020000
    hexstr_to_byte_array("A0DA02631C140A00000000BD14A012A010800A88FFFFFFFFFFFFFF9DE181020000", sam_apdu, &sam_len);

    memcpy(sam_apdu + 19, tmp_p2, sizeof(tmp_p1));
    memcpy(sam_apdu + 19 + 4, tmp_p1, sizeof(tmp_p1));
    AddCrc(sam_apdu + 19, 8);

    if (sam_rxtx(sam_apdu, sam_len, resp, &resp_len) == false) {
        res = PM3_ECARDEXCHANGE;
        goto out;
    }
    print_dbg("-- 6", resp, resp_len);
    // c1 61 c1 00 00 a1 10 a1 0e 80 04 0c 06 45 56 81 02 00 04 82 02 01 f4 90 00

    // read block 6
    StartCountSspClk();
    start_time = GetCountSspClk();
    iclass_send_as_reader(resp + 11, 4, &start_time, &eof_time, shallow_mod);

    // expect a 10-byte response here
    res = GetIso15693AnswerFromTag(resp, ISO7816_MAX_FRAME, ICLASS_READER_TIMEOUT_OTHERS, &eof_time, false, true, &resp_len);
    if (res != PM3_SUCCESS || resp_len != 10) {
        res = PM3_ECARDEXCHANGE;
        goto out;
    }
    print_dbg("Block 6 from Picopass", resp, resp_len);

    // -----------------------------------------------------------------------------
    // eight  send block 6 config to SAM
    // A0DA02631C140A00000000BD14A012A010800A 030303030003E0174323 81020000
    hexstr_to_byte_array("A0DA02631C140A00000000BD14A012A010800A030303030003E017432381020000", sam_apdu, &sam_len);
    memcpy(sam_apdu + 19, resp, resp_len);

    if (sam_rxtx(sam_apdu, sam_len, resp, &resp_len) == false) {
        res = PM3_ECARDEXCHANGE;
        goto out;
    }
    print_dbg("-- 7", resp, resp_len);

    // c161c10000a110a10e8004 0606455681020004820201f49000

    // read the credential blocks
    StartCountSspClk();
    start_time = GetCountSspClk();
    iclass_send_as_reader(resp + 11, 4, &start_time, &eof_time, shallow_mod);

    // expect a 10-byte response here
    res = GetIso15693AnswerFromTag(resp, ISO7816_MAX_FRAME, ICLASS_READER_TIMEOUT_OTHERS, &eof_time, false, true, &resp_len);
    if (res != PM3_SUCCESS) {
        res = PM3_ECARDEXCHANGE;
        goto out;
    }
    print_dbg("Block 6-9 from Picopass", resp, resp_len);

    // -----------------------------------------------------------------------------
    // nine  send credential blocks to SAM
    // A0DA026334140A00000000BD2CA02AA0288022 030303030003E017769CB4A198E0DEC82AD4C8211F9968712BE7393CF8E71D7E804C 81020000
    hexstr_to_byte_array("A0DA026334140A00000000BD2CA02AA0288022030303030003E017769CB4A198E0DEC82AD4C8211F9968712BE7393CF8E71D7E804C81020000", sam_apdu, &sam_len);
    memcpy(sam_apdu + 19, resp, resp_len);

    if (sam_rxtx(sam_apdu, sam_len, resp, &resp_len) == false) {
        res = PM3_ECARDEXCHANGE;
        goto out;
    }
    print_dbg("-- 8", resp, resp_len);


    // -----------------------------------------------------------------------------
    // TEN  ask for PACS data
    // A0DA02630C440A00000000BD04A0028200
    hexstr_to_byte_array("A0DA02630C440A00000000BD04A0028200", sam_apdu, &sam_len);
    memcpy(sam_apdu + 19, resp, resp_len);

    if (sam_rxtx(sam_apdu, sam_len, resp, &resp_len) == false) {
        res = PM3_ECARDEXCHANGE;
        goto out;
    }

    print_dbg("-- 9  response", resp, resp_len);
    if (memcmp(resp, "\xc1\x64\x00\x00\x00\xbd\x17\x8a\x15", 9) == 0) {
        res = PM3_ENOPACS;
        goto out;
    }

    // c164000000bd098a07 030506951f9a00 9000
    uint8_t *pacs = BigBuf_calloc(resp[8]);
    memcpy(pacs, resp + 9, resp[8]);

    print_dbg("-- 10  PACS data", pacs, resp[8]);

    reply_ng(CMD_HF_SAM_PICOPASS, PM3_SUCCESS, pacs, resp[8]);
    res = PM3_SUCCESS;
    goto off;

out:
    reply_ng(CMD_HF_SAM_PICOPASS, res, NULL, 0);

off:
    switch_off();
    BigBuf_free();
    return res;
}

// HID SAM <-> MFC
// HID SAM <-> SEOS
