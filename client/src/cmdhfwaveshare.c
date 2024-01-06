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
// Waveshare commands
//-----------------------------------------------------------------------------
// from ST25R3911B-NFC-Demo source code by Waveshare team

#include "cmdhfwaveshare.h"

#include <stdio.h>
#include <ctype.h>
#include "comms.h"
#include "cmdparser.h"
#include "ui.h"
#include "util.h"
#include "fileutils.h"
#include "util_posix.h"     // msleep
#include "cliparser.h"
#include "imgutils.h"

#define EPD_1IN54B     0
#define EPD_1IN54C     1
#define EPD_1IN54V2    2
#define EPD_1IN54BCV2  3
#define EPD_2IN13V2    4
#define EPD_2IN13BC    5
#define EPD_2IN13D     6
#define EPD_2IN9       7
#define EPD_2IN9BC     8
#define EPD_2IN9D      9
#define EPD_4IN2      10
#define EPD_4IN2BC    11
#define EPD_7IN5      12
#define EPD_7IN5BC    13
#define EPD_7IN5V2    14
#define EPD_7IN5BCV2  15
#define EPD_2IN7      16
#define EPD_7IN5HD    17

typedef struct model_s {
    const char *desc;
    uint8_t len; // The data sent in one time shall not be greater than 128-3
    uint16_t width;
    uint16_t height;
} model_t;

typedef enum {
    M2in13 = 0,
    M2in9,
    M4in2,
    M7in5,
    M2in7,
    M2in13B,
    M1in54B,
    M7in5HD,
    MEND
} model_enum_t;

static model_t models[] = {
    {"2.13 inch e-paper",               16, 122, 250}, // tested
    {"2.9  inch e-paper",               16, 296, 128},
    {"4.2  inch e-paper",              100, 400, 300}, // tested
    {"7.5  inch e-paper",              120, 800, 480},
    {"2.7  inch e-paper",              121, 176, 276}, // tested
    {"2.13 inch e-paper B (with red)", 106, 104, 212}, // tested
    {"1.54 inch e-paper B (with red)", 100, 200, 200}, // tested
    {"7.5  inch e-paper HD",           120, 880, 528},
};

static int CmdHelp(const char *Cmd);

static uint8_t * map8to1(gdImagePtr img, int color) {
    // Calculate width rounding up
    uint16_t width8 = (gdImageSX(img) + 7) / 8;

    uint8_t * colormap8 = malloc(width8 * gdImageSY(img));
    if (!colormap8) {
        return NULL;
    }

    uint8_t data = 0;
    uint8_t count = 0;
    for (uint16_t Y = 0; Y < gdImageSY(img); Y++) {
        for (uint16_t X = 0; X < gdImageSX(img); X++) {
            if (gdImageGetPixel(img, X, Y) == color) {
                data |= 1;
            }
            count += 1;
            if ((count >= 8) || (X == gdImageSX(img) - 1)) {
                colormap8[X / 8 + Y * width8] = (~data) & 0xFF;
                count = 0;
                data = 0;
            }
            data = (data << 1) & 0xFF;
        }
    }

    return colormap8;
}

static void read_black(uint32_t i, uint8_t *l, uint8_t model_nr, const uint8_t *black) {
    for (uint8_t j = 0; j < models[model_nr].len; j++) {
        l[3 + j] = black[i * models[model_nr].len + j];
    }
}
static void read_red(uint32_t i, uint8_t *l, uint8_t model_nr, const uint8_t *red) {
    // spurious warning with GCC10 (-Wstringop-overflow) when j is uint8_t, even if all len are < 128
    for (uint16_t j = 0; j < models[model_nr].len; j++) {
        if (model_nr == M1in54B) {
            //1.54B needs to flip the red picture data, other screens do not need to flip data
            l[3 + j] = ~red[i * models[model_nr].len + j];
        } else {
            l[3 + j] = red[i * models[model_nr].len + j];
        }
    }
}

static int transceive_blocking(uint8_t *txBuf, uint16_t txBufLen, uint8_t *rxBuf, uint16_t rxBufLen, uint16_t *actLen, bool retransmit) {
    uint8_t fail_num = 0;
    if (rxBufLen < 2) {
        return PM3_EINVARG;
    }

    while (1) {
        PacketResponseNG resp;
        SendCommandMIX(CMD_HF_ISO14443A_READER, ISO14A_RAW | ISO14A_APPEND_CRC | ISO14A_NO_DISCONNECT, txBufLen, 0, txBuf, txBufLen);
        rxBuf[0] = 1;
        if (WaitForResponseTimeout(CMD_ACK, &resp, 2000)) {
            if (resp.oldarg[0] > rxBufLen) {
                PrintAndLogEx(WARNING, "Received %"PRIu64 " bytes, rxBuf too small (%u)", resp.oldarg[0], rxBufLen);
                memcpy(rxBuf, resp.data.asBytes, rxBufLen);
                *actLen = rxBufLen;
                return PM3_ESOFT;
            }
            memcpy(rxBuf, resp.data.asBytes, resp.oldarg[0]);
            *actLen = resp.oldarg[0];
        }

        if ((retransmit) && (rxBuf[0] != 0 || rxBuf[1] != 0)) {
            fail_num++;
            if (fail_num > 10) {
                PROMPT_CLEARLINE;
                PrintAndLogEx(WARNING, "Transmission failed, please try again.");
                DropField();
                return PM3_ESOFT;
            }
        } else {
            break;
        }
    }
    return PM3_SUCCESS;
}

// 1.54B Keychain
// 1.54B does not share the common base and requires specific handling
static int start_drawing_1in54B(uint8_t model_nr, uint8_t *black, uint8_t *red) {
    int ret;
    uint8_t step_5[128] = {0xcd, 0x05, 100};
    uint8_t step_4[2] = {0xcd, 0x04};
    uint8_t step_6[2] = {0xcd, 0x06};
    uint8_t rx[20] = {0};
    uint16_t actrxlen[20], i, progress;

    if (model_nr == M1in54B) {
        step_5[2] = 100;
    }
    PrintAndLogEx(DEBUG, "1.54_Step9: e-paper config2 (black)");
    if (model_nr == M1in54B) {      //1.54inch B Keychain
        for (i = 0; i < 50; i++) {
            read_black(i, step_5, model_nr, black);
            ret = transceive_blocking(step_5, 103, rx, 20, actrxlen, true); // cd 05
            if (ret != PM3_SUCCESS) {
                return ret;
            }
            progress = i * 100 / 100;
            PrintAndLogEx(INPLACE, "Progress: %d %%", progress);
        }
    }
    PROMPT_CLEARLINE;
    PrintAndLogEx(DEBUG, "1.54_Step6: e-paper power on");
    ret = transceive_blocking(step_4, 2, rx, 20, actrxlen, true);          //cd 04
    if (ret != PM3_SUCCESS) {
        return ret;
    }

    PrintAndLogEx(DEBUG, "1.54_Step7: e-paper config2 (red)");
    if (model_nr == M1in54B) {       //1.54inch B Keychain
        for (i = 0; i < 50; i++) {
            read_red(i, step_5, model_nr, red);
            ret = transceive_blocking(step_5, 103, rx, 20, actrxlen, true); // cd 05
            if (ret != PM3_SUCCESS) {
                return ret;
            }
            progress = i * 100 / 100 + 50;
            PrintAndLogEx(INPLACE, "Progress: %d %%", progress);
        }
    }
    PROMPT_CLEARLINE;
    // Send update instructions
    PrintAndLogEx(DEBUG, "1.54_Step8: EDP load to main");
    ret = transceive_blocking(step_6, 2, rx, 20, actrxlen, true);          //cd 06
    if (ret != PM3_SUCCESS) {
        return ret;
    }

    PrintAndLogEx(DEBUG, "1.54_Step9");
    return PM3_SUCCESS;
}

static int start_drawing(uint8_t model_nr, uint8_t *black, uint8_t *red) {
    uint8_t step0[2] = {0xcd, 0x0d};
    uint8_t step1[3] = {0xcd, 0x00, 10};  // select e-paper type and reset e-paper
    //  4 :2.13inch e-Paper
    //  7 :2.9inch e-Paper
    // 10 :4.2inch e-Paper
    // 14 :7.5inch e-Paper
    uint8_t step2[2] = {0xcd, 0x01};      // e-paper normal mode  type：
    uint8_t step3[2] = {0xcd, 0x02};      // e-paper config1
    uint8_t step4[2] = {0xcd, 0x03};      // e-paper power on
    uint8_t step5[2] = {0xcd, 0x05};      // e-paper config2
    uint8_t step6[2] = {0xcd, 0x06};      // EDP load to main
    uint8_t step7[2] = {0xcd, 0x07};      // Data preparation

    uint8_t step8[123] = {0xcd, 0x08, 0x64};  // Data start command
    // 2.13inch(0x10:Send 16 data at a time)
    // 2.9inch(0x10:Send 16 data at a time)
    // 4.2inch(0x64:Send 100 data at a time)
    // 7.5inch(0x78:Send 120 data at a time)
    uint8_t step9[2] = {0xcd, 0x18};      // e-paper power on
    uint8_t step10[2] = {0xcd, 0x09};     // Refresh e-paper
    uint8_t step11[2] = {0xcd, 0x0a};     // wait for ready
    uint8_t step12[2] = {0xcd, 0x04};     // e-paper power off command
    uint8_t step13[124] = {0xcd, 0x19, 121};
// uint8_t step13[2]={0xcd,0x0b};     // Judge whether the power supply is turned off successfully
// uint8_t step14[2]={0xcd,0x0c};     // The end of the transmission
    uint8_t rx[20];
    uint16_t actrxlen[20];

    clearCommandBuffer();
    SendCommandMIX(CMD_HF_ISO14443A_READER, ISO14A_CONNECT | ISO14A_NO_DISCONNECT, 0, 0, NULL, 0);
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_ACK, &resp, 2500) == false) {
        PrintAndLogEx(ERR, "No tag found");
        DropField();
        return PM3_ETIMEOUT;
    }

    iso14a_card_select_t card;
    memcpy(&card, (iso14a_card_select_t *)resp.data.asBytes, sizeof(iso14a_card_select_t));

    uint64_t select_status = resp.oldarg[0];

    if (select_status == 0) {
        PrintAndLogEx(ERR, "Tag select error");
        DropField();
        return PM3_ERFTRANS;
    } else if (select_status == 3) {
        PrintAndLogEx(WARNING, "Card doesn't support standard iso14443-3 anticollision, doesn't look like Waveshare tag");
        DropField();
        return PM3_ESOFT;
    }

    if ((card.uidlen != 7) || ((memcmp(card.uid, "FSTN10m", 7) != 0) && (memcmp(card.uid, "FSTN11m", 7) != 0) && (memcmp(card.uid, "WSDZ10m", 7) != 0))) {
        PrintAndLogEx(WARNING, "Card doesn't look like Waveshare tag");
        DropField();
        return PM3_ESOFT;
    }
    if (((model_nr != M1in54B) && ((memcmp(card.uid, "FSTN10m", 7) == 0) || (memcmp(card.uid, "FSTN11m", 7) == 0)))) {
        PrintAndLogEx(WARNING, "Card is a Waveshare tag 1.54\", not %s", models[model_nr].desc);
        DropField();
        return PM3_ESOFT;
    }
    if (((model_nr == M1in54B) && (memcmp(card.uid, "FSTN10m", 7) != 0) && (memcmp(card.uid, "FSTN11m", 7) != 0))) {
        PrintAndLogEx(WARNING, "Card is not a Waveshare tag 1.54\", check your model number");
        DropField();
        return PM3_ESOFT;
    }
    PrintAndLogEx(DEBUG, "model_nr = %d", model_nr);

    PrintAndLogEx(DEBUG, "Step0");
    int ret = transceive_blocking(step0, 2, rx, 20, actrxlen, true);  //cd 0d
    if (ret != PM3_SUCCESS) {
        return ret;
    }

    PrintAndLogEx(DEBUG, "Step1: e-paper config");
    // step1[2] screen model
    // step8[2] nr of bytes sent at once
    // step13[2] nr of bytes sent for the second time
    // generally, step8 sends a black image, step13 sends a red image
    if (model_nr == M2in13) {        // 2.13inch
        step1[2] = EPD_2IN13V2;
        step8[2] = 16;
        step13[2] = 0;
    } else if (model_nr == M2in9) {  // 2.9inch
        step1[2] = EPD_2IN9;
        step8[2] = 16;
        step13[2] = 0;
    } else if (model_nr == M4in2) {  // 4.2inch
        step1[2] = EPD_4IN2;
        step8[2] = 100;
        step13[2] = 0;
    } else if (model_nr == M7in5) {  // 7.5inch
        step1[2] = EPD_7IN5V2;
        step8[2] = 120;
        step13[2] = 0;
    } else if (model_nr == M2in7) {  // 2.7inch
        step1[2] = EPD_2IN7;
        step8[2] = 121;
        // Send blank data for the first time, and send other data to 0xff without processing the bottom layer
        step13[2] = 121;
        // Sending the second data is the real image data. If the previous 0xff is not sent, the last output image is abnormally black
    } else if (model_nr == M2in13B) {  // 2.13inch B
        step1[2] = EPD_2IN13BC;
        step8[2] = 106;
        step13[2] = 106;
    } else if (model_nr == M7in5HD) {
        step1[2] = EPD_7IN5HD;
        step8[2] = 120;
        step13[2] = 0;
    }

    if (model_nr == M1in54B) {
        ret = transceive_blocking(step1, 2, rx, 20, actrxlen, true);  // cd 00
    } else {
        ret = transceive_blocking(step1, 3, rx, 20, actrxlen, true);
    }
    if (ret != PM3_SUCCESS) {
        return ret;
    }

    msleep(100);
    PrintAndLogEx(DEBUG, "Step2: e-paper normal mode type");
    ret = transceive_blocking(step2, 2, rx, 20, actrxlen, true);  // cd 01
    if (ret != PM3_SUCCESS) {
        return ret;
    }

    msleep(100);
    PrintAndLogEx(DEBUG, "Step3: e-paper config1");
    ret = transceive_blocking(step3, 2, rx, 20, actrxlen, true); // cd 02
    if (ret != PM3_SUCCESS) {
        return ret;
    }

    msleep(200);
    PrintAndLogEx(DEBUG, "Step4: e-paper power on");
    ret = transceive_blocking(step4, 2, rx, 20, actrxlen, true); // cd 03
    if (ret != PM3_SUCCESS) {
        return ret;
    }

    if (model_nr == M1in54B) {
        // 1.54B Keychain handler
        PrintAndLogEx(DEBUG, "Start_Drawing_1in54B");
        ret = start_drawing_1in54B(model_nr, black, red);
        if (ret != PM3_SUCCESS) {
            return ret;
        }
        // 1.54B Data transfer is complete and wait for refresh
    } else {
        uint8_t progress;
        PrintAndLogEx(DEBUG, "Step5: e-paper config2");
        ret = transceive_blocking(step5, 2, rx, 20, actrxlen, true); // cd 05
        if (ret != PM3_SUCCESS) {
            return ret;
        }
        msleep(100);
        PrintAndLogEx(DEBUG, "Step6: EDP load to main") ;
        ret = transceive_blocking(step6, 2, rx, 20, actrxlen, true); // cd 06
        if (ret != PM3_SUCCESS) {
            return ret;
        }
        msleep(100);
        PrintAndLogEx(DEBUG, "Step7: Data preparation");
        ret = transceive_blocking(step7, 2, rx, 20, actrxlen, true); // cd 07
        if (ret != PM3_SUCCESS) {
            return ret;
        }
        PrintAndLogEx(DEBUG, "Step8: Start data transfer");
        if (model_nr == M2in13) {      // 2.13inch
            for (uint16_t i = 0; i < 250; i++) {
                read_black(i, step8, model_nr, black);
                ret = transceive_blocking(step8, 19, rx, 20, actrxlen, true); // cd 08
                if (ret != PM3_SUCCESS) {
                    return ret;
                }
                progress = i * 100 / 250;
                PrintAndLogEx(INPLACE, "Progress: %d %%", progress);
            }
        } else if (model_nr == M2in9) {
            for (uint16_t i = 0; i < 296; i++) {
                read_black(i, step8, model_nr, black);
                ret = transceive_blocking(step8, 19, rx, 20, actrxlen, true); // cd 08
                if (ret != PM3_SUCCESS) {
                    return ret;
                }
                progress = i * 100 / 296;
                PrintAndLogEx(INPLACE, "Progress: %d %%", progress);
            }
        } else if (model_nr == M4in2) {    //4.2inch
            for (uint16_t i = 0; i < 150; i++) {
                read_black(i, step8, model_nr, black);
                ret = transceive_blocking(step8, 103, rx, 20, actrxlen, true); // cd 08
                if (ret != PM3_SUCCESS) {
                    return ret;
                }
                progress = i * 100 / 150;
                PrintAndLogEx(INPLACE, "Progress: %d %%", progress);
            }
        } else if (model_nr == M7in5) {  //7.5inch
            for (uint16_t i = 0; i < 400; i++) {
                read_black(i, step8, model_nr, black);
                ret = transceive_blocking(step8, 123, rx, 20, actrxlen, true); // cd 08
                if (ret != PM3_SUCCESS) {
                    return ret;
                }
                progress = i * 100 / 400;
                PrintAndLogEx(INPLACE, "Progress: %d %%", progress);
                msleep(6);
            }
        } else if (model_nr == M2in13B) {  //2.13inch B
            for (uint16_t i = 0; i < 26; i++) {
                read_black(i, step8, model_nr, black);
                ret = transceive_blocking(step8, 109, rx, 20, actrxlen, false); // cd 08
                if (ret != PM3_SUCCESS) {
                    return ret;
                }
                progress = i * 50 / 26;
                PrintAndLogEx(INPLACE, "Progress: %d %%", progress);
            }
        } else if (model_nr == M7in5HD) {  //7.5HD

            for (uint16_t i = 0; i < 484; i++) {
                read_black(i, step8, model_nr, black);
                //memset(&step8[3], 0xf0, 120);
                ret = transceive_blocking(step8, 123, rx, 20, actrxlen, true); // cd 08
                if (ret != PM3_SUCCESS) {
                    return ret;
                }
                progress = i * 100 / 484;
                PrintAndLogEx(INPLACE, "Progress: %d %%", progress);
            }
            memset(&step8[3], 0xff, 120);
            ret = transceive_blocking(step8, 110 + 3, rx, 20, actrxlen, true); // cd 08
            if (ret != PM3_SUCCESS) {
                return ret;
            }
        } else if (model_nr == M2in7) {   //2.7inch
            for (uint16_t i = 0; i < 48; i++) {
                //read_black(i,step8, model_nr, black);
                memset(&step8[3], 0xFF, sizeof(step8) - 3);
                ret = transceive_blocking(step8, 124, rx, 20, actrxlen, true); // cd 08
                if (ret != PM3_SUCCESS) {
                    return ret;
                }
                progress = i * 50 / 48;
                PrintAndLogEx(INPLACE, "Progress: %d %%", progress);
            }
        }
        PROMPT_CLEARLINE;
        PrintAndLogEx(DEBUG, "Step9: e-paper power on");
        if (model_nr == M2in13 || model_nr == M2in9 || model_nr == M4in2 || model_nr == M7in5 || model_nr == M7in5HD) {
            ret = transceive_blocking(step9, 2, rx, 20, actrxlen, true); //cd 18
            // The black-and-white screen sending backplane is also shielded, with no effect. Except 2.7
            if (ret != PM3_SUCCESS) {
                return ret;
            }
        } else if (model_nr == M2in13B ||  model_nr == M2in7) {
            ret = transceive_blocking(step9, 2, rx, 20, actrxlen, true); //cd 18
            if (ret != PM3_SUCCESS) {
                return ret;
            }
            PrintAndLogEx(DEBUG, "Step9b");
            if (model_nr == M2in7) {
                for (uint16_t i = 0; i < 48; i++) {
                    read_black(i, step13, model_nr, black);
                    ret = transceive_blocking(step13, 124, rx, 20, actrxlen, true); //CD 19
                    if (ret != PM3_SUCCESS) {
                        return ret;
                    }
                    progress = i * 50 / 48 + 50;
                    PrintAndLogEx(INPLACE, "Progress: %d %%", progress);
                }
            } else if (model_nr == M2in13B) {
                for (uint16_t i = 0; i < 26; i++) {
                    read_red(i, step13, model_nr, red);
                    //memset(&step13[3], 0xfE, 106);
                    ret = transceive_blocking(step13, 109, rx, 20, actrxlen, false);
                    if (ret != PM3_SUCCESS) {
                        return ret;
                    }
                    progress = i * 50 / 26 + 50;
                    PrintAndLogEx(INPLACE, "Progress: %d %%", progress);
                }
            }
            PROMPT_CLEARLINE;
        }
        PrintAndLogEx(DEBUG, "Step10: Refresh e-paper");
        ret = transceive_blocking(step10, 2, rx, 20, actrxlen, true); //cd 09 refresh command
        if (ret != PM3_SUCCESS) {
            return ret;
        }
        msleep(200);
    }
    PrintAndLogEx(DEBUG, "Step11: Wait tag to be ready");
    PrintAndLogEx(INPLACE, "E-paper Reflashing, Waiting");
    if (model_nr == M2in13B || model_nr == M1in54B) { // Black, white and red screen refresh time is longer, wait first
        msleep(9000);
    } else if (model_nr == M7in5HD) {
        msleep(1000);
    }

    uint8_t fail_num = 0;
    while (1) {
        if (model_nr == M1in54B) {
            // send 0xcd 0x08 with 1.54B
            ret = transceive_blocking(step8, 2, rx, 20, actrxlen, false);           //cd 08
        } else {
            ret = transceive_blocking(step11, 2, rx, 20, actrxlen, false);          //cd 0a
        }
        if (ret != PM3_SUCCESS) {
            return ret;
        }
        if (rx[0] == 0xff && rx[1] == 0) {
            PrintAndLogEx(NORMAL, "");
            PrintAndLogEx(SUCCESS, "E-paper Reflash OK");
            msleep(200);
            break;
        } else {
            if (fail_num > 50) {
                PrintAndLogEx(WARNING, "Update failed, please try again.");
                DropField();
                return PM3_ESOFT;
            } else {
                fail_num++;
                PrintAndLogEx(INPLACE, "E-paper Reflashing, Waiting");
                msleep(400);
            }
        }
    }
    PrintAndLogEx(DEBUG, "Step12: e-paper power off command");
    ret = transceive_blocking(step12, 2, rx, 20, actrxlen, true);          //cd 04
    if (ret != PM3_SUCCESS) {
        return ret;
    }
    msleep(200);
    PrintAndLogEx(SUCCESS, "E-paper Update OK");
    msleep(200);
    DropField();
    return PM3_SUCCESS;
}

static int CmdHF14AWSLoad(const char *Cmd) {

    char desc[800] = {0};
    for (uint8_t i = 0; i < MEND; i++) {
        snprintf(desc + strlen(desc),
                 sizeof(desc) - strlen(desc),
                 "hf waveshare loadbmp -f myfile -m %2u -> %s ( %u, %u )\n",
                 i,
                 models[i].desc,
                 models[i].width,
                 models[i].height
                );
    }

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf waveshare loadbmp",
                  "Load BMP file to Waveshare NFC ePaper.",
                  desc
                 );

    char modeldesc[40];
    snprintf(modeldesc, sizeof(modeldesc), "model number [0 - %d] of your tag", MEND - 1);

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

    //Validations
    if (infilelen < 1) {
        PrintAndLogEx(WARNING, "Missing input file");
        return PM3_EINVARG;
    }
    if (model_nr == -1) {
        PrintAndLogEx(WARNING, "Missing model");
        return PM3_EINVARG;
    }
    if (model_nr >= MEND) {
        PrintAndLogEx(WARNING, "Unknown model");
        return PM3_EINVARG;
    }

    bool model_has_red = model_nr == M1in54B || model_nr == M2in13B;

    gdImagePtr rgb_img = gdImageCreateFromFile(infile);
    if (!rgb_img) {
        PrintAndLogEx(WARNING, "Could not load image from " _YELLOW_("%s"), infile);
        return PM3_EFILE;
    }

    if (
        gdImageSX(rgb_img) != models[model_nr].width ||
        gdImageSY(rgb_img) != models[model_nr].height
    ) {
        PrintAndLogEx(WARNING, "Image size does not match panel size");
        gdImageDestroy(rgb_img);
        return PM3_EFILE;
    }

    int pal_len = 2;
    int pal[3];
    pal[0] = gdTrueColorAlpha(0xFF, 0xFF, 0xFF, 0); // White
    pal[1] = gdTrueColorAlpha(0x00, 0x00, 0x00, 0); // Black
    if (model_has_red) {
        pal_len = 3;
        pal[2] = gdTrueColorAlpha(0xFF, 0x00, 0x00, 0); // Red
    }

    gdImagePtr pal_img = img_palettize(rgb_img, pal, pal_len);
    gdImageDestroy(rgb_img);

    if (!pal_img) {
        PrintAndLogEx(WARNING, "Could not convert image");
        return PM3_EMALLOC;
    }

    if (outfilelen && !gdImageFile(pal_img, outfile)) {
        PrintAndLogEx(WARNING, "Could not save converted image");
    }

    uint8_t * black_plane = map8to1(pal_img, 1);
    if (!black_plane) {
        PrintAndLogEx(WARNING, "Could not convert image to bit plane");
        gdImageDestroy(pal_img);
        return PM3_EMALLOC;
    }

    uint8_t * red_plane = NULL;
    if (model_has_red) {
        red_plane = map8to1(pal_img, 2);
        if (!red_plane) {
            PrintAndLogEx(WARNING, "Could not convert image to bit plane");
            free(black_plane);
            gdImageDestroy(pal_img);
            return PM3_EMALLOC;
        }
    }

    gdImageDestroy(pal_img);
    int res = start_drawing(model_nr, black_plane, red_plane);

    free(black_plane);
    if (red_plane) {
        free(red_plane);
    }

    return res;
}

static command_t CommandTable[] = {
    {"help",        CmdHelp,              AlwaysAvailable, "This help"},
    {"load",        CmdHF14AWSLoad,       IfPm3Iso14443a,  "Load image file to Waveshare NFC ePaper"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdHFWaveshare(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}
