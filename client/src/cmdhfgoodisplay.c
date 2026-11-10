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
// Goodisplay NFC e-paper commands
//-----------------------------------------------------------------------------
// Protocol from the Flipper Zero NFC Eink app (GPLv3) by RebornedBrain
// https://github.com/RebornedBrain/nfc_eink
// Tags use a Fudan FM1280, ISO14443-4 with proprietary CLA F0 APDUs.

#include "cmdhfgoodisplay.h"

#include <stdio.h>
#include <string.h>
#include "comms.h"
#include "cmdparser.h"
#include "cmdhf14a.h"
#include "ui.h"
#include "util.h"
#include "fileutils.h"
#include "util_posix.h"     // msleep
#include "commonutil.h"     // ARRAYLEN, Uint2byteToMemBe
#include "cliparser.h"
#include "imgutils.h"

#define GD_BLOCK_SIZE       250 // image bytes per F0 D2 APDU
#define GD_CHAIN_SIZE       248 // image bytes in the first frame of a chain
#define GD_CHANNEL_BW       0x20
#define GD_UPDATE_POLLS     20
#define GD_UPDATE_POLL_MS   150

typedef struct {
    const char *desc;
    uint8_t size_code;
    uint16_t width;   // source pixels, bytes per row = width / 8
    uint16_t height;  // gate lines, one row each
} gd_model_t;

// panel native portrait orientation
static const gd_model_t gd_models[] = {
    {"GDEY0154D67 1.54 inch", 0x12, 200, 200},
    {"GDEY0213B74 2.13 inch", 0x00, 122, 250},
    {"GDEY029T94  2.9  inch", 0x01, 128, 296},
    {"GDEY037T03  3.7  inch", 0x51, 240, 416},
};

// F0 DB 00 00 config, SSD16xx init sequence captured from the NFC-D1 app
static const uint8_t gd_config[] = {
    0xf0, 0xdb, 0x00, 0x00, 0x67, 0xa0, 0x06, 0x00, 0x20, 0x00, 0x80, 0x01, 0x28, 0xa4, 0x01, 0x0c,
    0xa5, 0x02, 0x00, 0x0a, 0xa4, 0x01, 0x08, 0xa5, 0x02, 0x00, 0x0a, 0xa4, 0x01, 0x0c, 0xa5, 0x02,
    0x00, 0x0a, 0xa4, 0x01, 0x02, 0xa1, 0x01, 0x12, 0xa4, 0x01, 0x02, 0xa1, 0x04, 0x01, 0x27, 0x01,
    0x01, 0xa1, 0x02, 0x11, 0x01, 0xa1, 0x03, 0x44, 0x00, 0x0f, 0xa1, 0x05, 0x45, 0x27, 0x01, 0x00,
    0x00, 0xa1, 0x02, 0x3c, 0x05, 0xa1, 0x03, 0x21, 0x00, 0x80, 0xa1, 0x02, 0x18, 0x80, 0xa1, 0x02,
    0x4e, 0x00, 0xa1, 0x03, 0x4f, 0x27, 0x01, 0xa3, 0x01, 0x24, 0xa2, 0x02, 0x22, 0xf7, 0xa2, 0x01,
    0x20, 0xa4, 0x01, 0x02, 0xa2, 0x02, 0x10, 0x01, 0xa5, 0x02, 0x00, 0x0a
};

// offsets of the A0 size record inside gd_config
#define GD_CFG_SIZE_CODE    7
#define GD_CFG_CHANNEL      8
#define GD_CFG_SOURCES      9
#define GD_CFG_GATES        11

// next ISO14443-4 block number, mirrors the firmware's
static uint8_t gd_blocknum = 0;

static int CmdHelp(const char *Cmd);

static int gd_select(void) {
    iso14a_card_select_t card;
    int res = SelectCard14443A_4(false, false, &card);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "No ISO14443-4 tag found");
        return res;
    }
    gd_blocknum = 0;
    return PM3_SUCCESS;
}

// raw single byte PCB frame (S-block / R-block), any reply accepted
static int gd_send_pcb(uint8_t pcb) {
    clearCommandBuffer();
    SendIso14aReader(ISO14A_RAW | ISO14A_APPEND_CRC | ISO14A_NO_DISCONNECT, &pcb, 1);
    uint16_t len = 0;
    if (WaitForIso14aReply(NULL, 1000, &len, NULL) == false || len == 0) {
        return PM3_ECARDEXCHANGE;
    }
    return PM3_SUCCESS;
}

// S(DESELECT), field off for 100 ms, reselect
static int gd_reset(void) {
    int res = gd_send_pcb(0xC2);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(DEBUG, "DESELECT failed");
        return res;
    }
    DropField();
    msleep(100);
    return gd_select();
}

// R(NAK) presence check
static int gd_presence_check(void) {
    return gd_send_pcb(0xB2 | gd_blocknum);
}

// one I-block, rx gets the reply without PCB and CRC
static int gd_exchange(const uint8_t *tx, uint16_t txlen, bool chaining, uint8_t *rx, uint16_t rxmax, uint16_t *rxlen, uint8_t *pcb) {
    uint32_t flags = ISO14A_APDU | ISO14A_NO_DISCONNECT;
    if (chaining) {
        flags |= ISO14A_SEND_CHAINING;
    }

    clearCommandBuffer();
    SendIso14aReader(flags, tx, txlen);

    PacketResponseNG resp;
    uint16_t len = 0;
    uint8_t res = 0;
    if (WaitForIso14aReply(&resp, 5000, &len, &res) == false) {
        PrintAndLogEx(DEBUG, "APDU reply timeout");
        return PM3_ETIMEOUT;
    }

    // len counts the CRC
    if (len < 2 || len - 2 > rxmax) {
        PrintAndLogEx(DEBUG, "APDU bad reply length %u", len);
        return PM3_EAPDU_FAIL;
    }

    // I-block or R(ACK) with the current block number toggles it
    if ((((res & 0xC0) == 0x00) || ((res & 0xD0) == 0x80)) && ((res & 0x01) == gd_blocknum)) {
        gd_blocknum ^= 1;
    }

    *rxlen = len - 2;
    memcpy(rx, resp.data.asBytes, *rxlen);
    if (pcb) {
        *pcb = res;
    }
    return PM3_SUCCESS;
}

static bool gd_reply_is(const uint8_t *rx, uint16_t rxlen, const uint8_t *exp, uint16_t explen) {
    return (rxlen == explen) && (memcmp(rx, exp, explen) == 0);
}

// APDU expecting exactly `exp` back
static int gd_apdu(const uint8_t *tx, uint16_t txlen, const uint8_t *exp, uint16_t explen) {
    uint8_t rx[32] = {0};
    uint16_t rxlen = 0;
    int res = gd_exchange(tx, txlen, false, rx, sizeof(rx), &rxlen, NULL);
    if (res != PM3_SUCCESS) {
        return res;
    }
    if (gd_reply_is(rx, rxlen, exp, explen) == false) {
        PrintAndLogEx(DEBUG, "APDU %s", sprint_hex(tx, MIN(txlen, 8)));
        PrintAndLogEx(DEBUG, "unexpected reply %s", sprint_hex(rx, rxlen));
        return PM3_EAPDU_FAIL;
    }
    return PM3_SUCCESS;
}

static const uint8_t SW_OK[] = {0x90, 0x00};

// NFC Forum Type 4 probe the app does before writing
static int gd_probe(void) {
    const uint8_t sel_app[] = {0x00, 0xA4, 0x04, 0x00, 0x07, 0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01, 0x00};
    const uint8_t sel_cc[] = {0x00, 0xA4, 0x00, 0x0C, 0x02, 0xE1, 0x03};
    const uint8_t read_cc[] = {0x00, 0xB0, 0x00, 0x00, 0x0F};
    const uint8_t sel_ndef[] = {0x00, 0xA4, 0x00, 0x0C, 0x02, 0xE1, 0x04};
    const uint8_t read_ndef[] = {0x00, 0xB0, 0x00, 0x00, 0x02};
    const uint8_t ndef_empty[] = {0x00, 0x00, 0x90, 0x00};

    int res = gd_apdu(sel_app, sizeof(sel_app), SW_OK, sizeof(SW_OK));
    if (res != PM3_SUCCESS) {
        return res;
    }

    res = gd_apdu(sel_cc, sizeof(sel_cc), SW_OK, sizeof(SW_OK));
    if (res != PM3_SUCCESS) {
        return res;
    }

    // CCLEN must be 0x000F
    uint8_t rx[32] = {0};
    uint16_t rxlen = 0;
    res = gd_exchange(read_cc, sizeof(read_cc), false, rx, sizeof(rx), &rxlen, NULL);
    if (res != PM3_SUCCESS) {
        return res;
    }
    if (rxlen < 2 || rx[0] != 0x00 || rx[1] != 0x0F) {
        PrintAndLogEx(DEBUG, "unexpected CC %s", sprint_hex(rx, rxlen));
        return PM3_EAPDU_FAIL;
    }

    res = gd_apdu(sel_ndef, sizeof(sel_ndef), SW_OK, sizeof(SW_OK));
    if (res != PM3_SUCCESS) {
        return res;
    }
    return gd_apdu(read_ndef, sizeof(read_ndef), ndef_empty, sizeof(ndef_empty));
}

static int gd_send_config(const gd_model_t *model) {
    const uint8_t cfg_start[] = {0xF0, 0xDB, 0x02, 0x00, 0x00};
    int res = gd_apdu(cfg_start, sizeof(cfg_start), SW_OK, sizeof(SW_OK));
    if (res != PM3_SUCCESS) {
        return res;
    }

    uint8_t cfg[sizeof(gd_config)];
    memcpy(cfg, gd_config, sizeof(cfg));
    cfg[GD_CFG_SIZE_CODE] = model->size_code;
    cfg[GD_CFG_CHANNEL] = GD_CHANNEL_BW;
    Uint2byteToMemBe(cfg + GD_CFG_SOURCES, model->width);
    Uint2byteToMemBe(cfg + GD_CFG_GATES, model->height);
    res = gd_apdu(cfg, sizeof(cfg), SW_OK, sizeof(SW_OK));
    if (res != PM3_SUCCESS) {
        return res;
    }

    const uint8_t cfg_end[] = {0xF0, 0xDA, 0x00, 0x00, 0x03, 0xF0, model->size_code, GD_CHANNEL_BW};
    res = gd_apdu(cfg_end, sizeof(cfg_end), SW_OK, sizeof(SW_OK));
    if (res != PM3_SUCCESS) {
        return res;
    }

    return gd_presence_check();
}

// F0 D2 <block BE> FA <250 bytes>, sent as a two frame chain
static int gd_send_block(uint16_t blocknr, const uint8_t *data) {
    uint8_t frame[5 + GD_CHAIN_SIZE] = {0xF0, 0xD2, 0x00, 0x00, GD_BLOCK_SIZE};
    Uint2byteToMemBe(frame + 2, blocknr);
    memcpy(frame + 5, data, GD_CHAIN_SIZE);

    uint8_t rx[32] = {0};
    uint16_t rxlen = 0;
    uint8_t pcb = 0;
    int res = gd_exchange(frame, sizeof(frame), true, rx, sizeof(rx), &rxlen, &pcb);
    if (res != PM3_SUCCESS) {
        return res;
    }

    // expect R(ACK)
    if ((pcb & 0xF2) != 0xA2) {
        PrintAndLogEx(DEBUG, "block %u, chaining not acknowledged, PCB %02X", blocknr, pcb);
        return PM3_EAPDU_FAIL;
    }

    return gd_exchange(data + GD_CHAIN_SIZE, GD_BLOCK_SIZE - GD_CHAIN_SIZE, false, rx, sizeof(rx), &rxlen, NULL);
}

static int gd_write_image(const gd_model_t *model, const uint8_t *plane) {

    uint32_t plane_len = ((model->width + 7) / 8) * model->height;
    uint16_t blocks = (plane_len + GD_BLOCK_SIZE - 1) / GD_BLOCK_SIZE;

    // last block padded with white
    uint8_t *data = malloc(blocks * GD_BLOCK_SIZE);
    if (data == NULL) {
        return PM3_EMALLOC;
    }
    memset(data, 0xFF, blocks * GD_BLOCK_SIZE);
    memcpy(data, plane, plane_len);

    // select, deselect / reselect twice around the probe, as the app does
    int res = gd_select();
    if (res != PM3_SUCCESS) {
        goto out;
    }

    res = gd_reset();
    if (res != PM3_SUCCESS) {
        goto out;
    }

    res = gd_probe();
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, "Card doesn't look like a Goodisplay tag");
        goto out;
    }

    for (uint8_t i = 0; i < 2; i++) {
        res = gd_reset();
        if (res != PM3_SUCCESS) {
            goto out;
        }
    }

    PrintAndLogEx(DEBUG, "Sending config");
    res = gd_send_config(model);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, "Config rejected");
        goto out;
    }

    for (uint16_t i = 0; i < blocks; i++) {
        res = gd_send_block(i, data + (i * GD_BLOCK_SIZE));
        if (res != PM3_SUCCESS) {
            PROMPT_CLEARLINE;
            PrintAndLogEx(WARNING, "Transmission failed at block %u, please try again.", i);
            goto out;
        }
        PrintAndLogEx(INPLACE, "Progress: %d %%", (i + 1) * 100 / blocks);
    }
    PROMPT_CLEARLINE;

    // tag answers with WTX while refreshing, handled by the device
    PrintAndLogEx(INFO, "E-paper Reflashing, Waiting");
    const uint8_t apply[] = {0xF0, 0xD4, 0x05, 0x80, 0x00};
    res = gd_apdu(apply, sizeof(apply), SW_OK, sizeof(SW_OK));
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, "Update failed, please try again.");
        goto out;
    }

    // keep the tag powered until the panel is done
    for (uint8_t i = 0; i < GD_UPDATE_POLLS; i++) {
        res = gd_presence_check();
        if (res != PM3_SUCCESS) {
            PrintAndLogEx(WARNING, "Tag lost during refresh");
            goto out;
        }
        msleep(GD_UPDATE_POLL_MS);
    }

    PrintAndLogEx(SUCCESS, "E-paper Update OK");

out:
    DropField();
    free(data);
    return res;
}

static int CmdHFGoodisplayLoad(const char *Cmd) {

    char desc[600] = {0};
    for (uint8_t i = 0; i < ARRAYLEN(gd_models); i++) {
        snprintf(desc + strlen(desc),
                 sizeof(desc) - strlen(desc),
                 "hf goodisplay load -f myfile -m %u -> %s ( %u, %u )\n",
                 i,
                 gd_models[i].desc,
                 gd_models[i].width,
                 gd_models[i].height
                );
    }

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf goodisplay load",
                  "Load image file to Goodisplay NFC ePaper (NFC-D1 tags).\n"
                  "Image is cropped to the panel's native portrait size, black/white only.",
                  desc
                 );

    char modeldesc[40];
    snprintf(modeldesc, sizeof(modeldesc), "model number [0 - %d] of your tag", (int)ARRAYLEN(gd_models) - 1);

    void *argtable[] = {
        arg_param_begin,
        arg_int1("m", NULL, "<nr>", modeldesc),
        arg_str1("f", "file", "<fn>", "specify image to upload to tag"),
        arg_str0("s", "save", "<fn>", "save paletized version in file"),
        arg_param_end
    };

    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int model_nr = arg_get_int_def(ctx, 1, -1);

    int infilelen, outfilelen;
    char infile[FILE_PATH_SIZE];
    char outfile[FILE_PATH_SIZE];
    CLIParamStrToBuf(arg_get_str(ctx, 2), (uint8_t *)infile, FILE_PATH_SIZE, &infilelen);
    CLIParamStrToBuf(arg_get_str(ctx, 3), (uint8_t *)outfile, FILE_PATH_SIZE, &outfilelen);
    CLIParserFree(ctx);

    if (infilelen < 1) {
        PrintAndLogEx(WARNING, "Missing input file");
        return PM3_EINVARG;
    }
    if (model_nr < 0 || model_nr >= (int)ARRAYLEN(gd_models)) {
        PrintAndLogEx(WARNING, "Unknown model");
        return PM3_EINVARG;
    }
    if (!g_session.pm3_present && !outfilelen) {
        PrintAndLogEx(WARNING, "Offline - can only perform image conversion");
        return PM3_ENOTTY;
    }

    const gd_model_t *model = &gd_models[model_nr];

    int pal[2];
    pal[0] = gdTrueColorAlpha(0xFF, 0xFF, 0xFF, 0); // White
    pal[1] = gdTrueColorAlpha(0x00, 0x00, 0x00, 0); // Black

    gdImagePtr pal_img = NULL;
    int res = img_load_dithered(infile, model->width, model->height, pal, ARRAYLEN(pal), &pal_img);
    if (res != PM3_SUCCESS) {
        return res;
    }

    if (outfilelen) {
        res = img_save(pal_img, outfile);
        gdImageDestroy(pal_img);
        return res;
    }

    uint8_t *plane = img_to_bitplane(pal_img, 1);
    gdImageDestroy(pal_img);
    if (plane == NULL) {
        PrintAndLogEx(WARNING, "Could not convert image to bit plane");
        return PM3_EMALLOC;
    }

    res = gd_write_image(model, plane);
    free(plane);
    return res;
}

static command_t CommandTable[] = {
    {"help",        CmdHelp,              AlwaysAvailable, "This help"},
    {"load",        CmdHFGoodisplayLoad,  AlwaysAvailable, "Load image file to Goodisplay NFC ePaper"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdHFGoodisplay(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}
