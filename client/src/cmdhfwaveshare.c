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

// Currently the largest pixel 880*528 only needs 58.08K bytes
#define WSMAPSIZE 60000

#pragma pack(1) /* Mandatory to remove any padding */
typedef struct {
    uint8_t  B;
    uint8_t  M;
    uint32_t fsize;
    uint16_t res1;
    uint16_t res2;
    uint32_t offset;
    uint32_t Bit_Pixel;
    uint32_t BMP_Width;
    uint32_t BMP_Height;
    uint16_t planes;
    uint16_t bpp;
    uint32_t ctype;
    uint32_t dsize;
    uint32_t hppm;
    uint32_t vppm;
    uint32_t colorsused;
    uint32_t colorreq;
    uint32_t Color_1;  //Color palette
    uint32_t Color_2;
} PACKED BMP_HEADER;

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
    {"2.13 inch e-paper",    16},
    {"2.9 inch e-paper",     16},
    {"4.2 inch e-paper",    100},
    {"7.5 inch e-paper",    120},
    {"2.7 inch e-paper",    121},
    {"2.13 inch e-paper B", 106},
    {"1.54 inch e-paper B", 100},
    {"7.5 inch e-paper HD", 120},
};

static int CmdHelp(const char *Cmd);

static int usage_hf_waveshare_loadbmp(void) {
    PrintAndLogEx(NORMAL, "Load BMP file to Waveshare NFC ePaper.");
    PrintAndLogEx(NORMAL, "Usage:  hf waveshare loadbmp [h] f <filename[.bmp]> m <model_nr>");
    PrintAndLogEx(NORMAL, "  Options :");
    PrintAndLogEx(NORMAL, "  f <fn>  : " _YELLOW_("filename[.bmp]") " to upload to tag");
    PrintAndLogEx(NORMAL, "  m <nr>  : " _YELLOW_("model number") " of your tag");
    for (uint8_t i=0; i< MEND; i++) {
        PrintAndLogEx(NORMAL, "  m %2i    : %s", i, models[i].desc);
    }
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, _YELLOW_("       hf waveshare loadbmp m 0 f myfile"));
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}

static int picture_bit_depth(const uint8_t *bmp, const size_t bmpsize) {
    if (bmpsize < sizeof(BMP_HEADER))
        return PM3_ESOFT;
    BMP_HEADER *pbmpheader = (BMP_HEADER *)bmp;
    PrintAndLogEx(DEBUG, "colorsused = %d", pbmpheader->colorsused);
    PrintAndLogEx(DEBUG, "pbmpheader->bpp = %d", pbmpheader->bpp);
    return pbmpheader->bpp;
}


static int read_bmp_bitmap(const uint8_t *bmp, const size_t bmpsize, uint8_t **black) {
    BMP_HEADER *pbmpheader = (BMP_HEADER *)bmp;
    // check file is bitmap
    if (pbmpheader->bpp != 1) {
        return PM3_ESOFT;
    }
    if (pbmpheader->B == 'M' || pbmpheader->M == 'B') { //0x4d42
        PrintAndLogEx(WARNING, "The file is not a BMP!");
        return PM3_ESOFT;
    }
    PrintAndLogEx(DEBUG, "file size =  %d", pbmpheader->fsize);
    PrintAndLogEx(DEBUG, "file offset =  %d", pbmpheader->offset);
    if (pbmpheader->fsize > bmpsize) {
        PrintAndLogEx(WARNING, "The file is truncated!");
        return PM3_ESOFT;
    }
    uint8_t color_flag = pbmpheader->Color_1;
    // Get BMP file data pointer
    uint32_t offset = pbmpheader->offset;

    uint16_t X, Y;
    uint16_t Image_Width_Byte = (pbmpheader->BMP_Width % 8 == 0) ? (pbmpheader->BMP_Width / 8) : (pbmpheader->BMP_Width / 8 + 1);
    uint16_t Bmp_Width_Byte = (Image_Width_Byte % 4 == 0) ? Image_Width_Byte : ((Image_Width_Byte / 4 + 1) * 4);

    *black = calloc(WSMAPSIZE, sizeof(uint8_t));
    if (*black == NULL) {
        return PM3_EMALLOC;
    }
    // Write data into RAM
    for (Y = 0; Y < pbmpheader->BMP_Height; Y++) { // columns
        for (X = 0; X < Bmp_Width_Byte; X++) { // lines
            if ((X < Image_Width_Byte) && ((X + (pbmpheader->BMP_Height - Y - 1) * Image_Width_Byte) < WSMAPSIZE)) {
                (*black)[X + (pbmpheader->BMP_Height - Y - 1) * Image_Width_Byte] = color_flag ? bmp[offset] : ~bmp[offset];
                offset++;
            }
        }
    }
    return PM3_SUCCESS;
}

static int read_bmp_rgb(const uint8_t *bmp, const size_t bmpsize, uint8_t **black, uint8_t **red) {
    BMP_HEADER *pbmpheader = (BMP_HEADER *)bmp;
    // check file is full color
    if (pbmpheader->bpp != 24) {
        return PM3_ESOFT;
    }
    if (pbmpheader->B == 'M' || pbmpheader->M == 'B') { //0x4d42
        PrintAndLogEx(WARNING, "The file is not a BMP!");
        return PM3_ESOFT;
    }
    PrintAndLogEx(DEBUG, "file size =  %d", pbmpheader->fsize);
    PrintAndLogEx(DEBUG, "file offset =  %d", pbmpheader->offset);
    if (pbmpheader->fsize > bmpsize) {
        PrintAndLogEx(WARNING, "The file is truncated!");
        return PM3_ESOFT;
    }
    // Get BMP file data pointer
    uint32_t offset = pbmpheader->offset;

    uint16_t X, Y;
    uint16_t Image_Width_Byte = (pbmpheader->BMP_Width % 8 == 0) ? (pbmpheader->BMP_Width / 8) : (pbmpheader->BMP_Width / 8 + 1);

    *black = calloc(WSMAPSIZE, sizeof(uint8_t));
    if (*black == NULL) {
        return PM3_EMALLOC;
    }
    *red = calloc(WSMAPSIZE, sizeof(uint8_t));
    if (*red == NULL) {
        free(*black);
        return PM3_EMALLOC;
    }

    uint8_t R = 0, G = 0, B = 0;
    uint8_t Black_data = 0;
    uint8_t Red_data = 0;
    uint8_t count = 0;
    // Write data into RAM
    for (Y = 0; Y < pbmpheader->BMP_Height; Y++) { // columns
        for (X = 0; X < pbmpheader->BMP_Width; X++) { // lines
            B = bmp[offset++];
            G = bmp[offset++];
            G = bmp[offset++];
            if (R < 30 && G < 30 && B < 30) {
                Black_data = Black_data | (1);
            } else if (R > 190 && G < 90 && B < 90) {
                Red_data = Red_data | (1);
            }
            count++;
            if (count >= 8) {
                (*black)[X / 8 + (pbmpheader->BMP_Height - Y - 1) * Image_Width_Byte] = ~Black_data;
                (*red)[X / 8 + (pbmpheader->BMP_Height - Y - 1) * Image_Width_Byte] = ~Red_data;
                count = 0;
                Black_data = 0;
                Red_data = 0;
            }
            Black_data = Black_data << 1;
            Red_data = Red_data << 1;
        }
    }
    return PM3_SUCCESS;
}

static void read_black(uint32_t i, uint8_t *l, uint8_t model_nr, uint8_t *black) {
    for (uint8_t j = 0; j < models[model_nr].len; j++) {
        l[3 + j] = black[i * models[model_nr].len + j];
    }
}
static void read_red(uint32_t i, uint8_t *l, uint8_t model_nr, uint8_t *red) {
    for (uint8_t j = 0; j < models[model_nr].len; j++) {
        if (model_nr == M1in54B) {
            //1.54B needs to flip the red picture data, other screens do not need to flip data
            l[3 + j] = ~red[i * models[model_nr].len + j];
        } else {
            l[3 + j] = red[i * models[model_nr].len + j];
        }
    }
}

static void transceive_blocking( uint8_t* txBuf, uint16_t txBufLen, uint8_t* rxBuf, uint16_t rxBufLen, uint16_t* actLen, uint32_t fwt ){
    *actLen = 2;
    (void) fwt;
    PacketResponseNG resp;
    SendCommandMIX(CMD_HF_ISO14443A_READER, ISO14A_RAW | ISO14A_APPEND_CRC | ISO14A_NO_DISCONNECT, txBufLen, 0, txBuf, txBufLen);
    WaitForResponse(CMD_ACK, &resp);
    if (resp.oldarg[0] > rxBufLen) {
        PrintAndLogEx(WARNING, "Received % bytes, rxBuf too small (%)", resp.oldarg[0], rxBufLen);
        memcpy(rxBuf, resp.data.asBytes, rxBufLen);
        *actLen = rxBufLen;
        return;
    }
    memcpy(rxBuf, resp.data.asBytes, resp.oldarg[0]);
    *actLen = resp.oldarg[0];
}

// 1.54B Keychain
// 1.54B does not share the common base and requires specific handling
static int start_drawing_1in54B(uint8_t model_nr, uint8_t *black, uint8_t *red, uint8_t fail_num) {
    uint8_t step = 5;
    uint8_t step_5[128] = {0xcd, 0x05, 100};
    uint8_t step_4[2] = {0xcd, 0x04};
    uint8_t step_6[2] = {0xcd, 0x06};
    uint8_t rx[20] = {0};
    uint16_t actrxlen[20], i = 0, progress = 0;

    if (model_nr == M1in54B) {
        step_5[2] = 100;
    }
    while (1) {
        if (step == 5) {
            PrintAndLogEx(INFO, "1.54_Step9: e-paper config2 (black)");
            if (model_nr == M1in54B) {      //1.54inch B Keychain
                for (i = 0; i < 50; i++) {
                    rx[0] = 1;
                    rx[1] = 1;
                    read_black(i, step_5, model_nr, black);
                    transceive_blocking(step_5, 103, rx, 20, actrxlen, 2157 + 2048); // cd 05
                    progress = i * 100 / 100;
                    PrintAndLogEx(INPLACE, "Progress: %d %%", progress);
                }
            }
            PROMPT_CLEARLINE;
            step = 6;
        } else if (step == 6) {
            PrintAndLogEx(INFO, "1.54_Step6: e-paper power on");
            transceive_blocking(step_4, 2, rx, 20, actrxlen, 2157 + 2048);          //cd 04
            step = 7;
            if (rx[0] == 0 && rx[1] == 0) {
                step = 7;
            } else {
                fail_num++;
                if (fail_num > 10) {
                    PrintAndLogEx(WARNING, "Update failed, please press any key to exit and try again.");
                    step = 14;
                    fail_num = 0;
                    msleep(200);
                }
            }
        } else if (step == 7) {
            PrintAndLogEx(INFO, "1.54_Step7: e-paper config2 (red)");
            if (model_nr == M1in54B) {       //1.54inch B Keychain
                for (i = 0; i < 50; i++) {
                    rx[0] = 1;
                    rx[1] = 1;
                    read_red(i, step_5, model_nr, red);
                    transceive_blocking(step_5, 103, rx, 20, actrxlen, 2157 + 2048); // cd 05
                    progress = i * 100 / 100 + 50;
                    PrintAndLogEx(INPLACE, "Progress: %d %%", progress);
                }
            }
            PROMPT_CLEARLINE;
            step = 8;
            rx[0] = 1;
            rx[1] = 1;
        } else if (step == 8) {
            // Send update instructions
            PrintAndLogEx(INFO, "1.54_Step8: EDP load to main");
            transceive_blocking(step_6, 2, rx, 20, actrxlen, 2157 + 2048);          //cd 06
            if (rx[0] == 0 && rx[1] == 0) {
                rx[0] = 1;
                rx[1] = 1;
                step = 9;
            } else {
                fail_num++;
                if (fail_num > 10) {
                    PrintAndLogEx(WARNING, "Update failed, please press any key to exit and try again.");
                    step = 14;
                    fail_num = 0;
                    msleep(200);
                }
            }
        } else if (step == 9) {
            PrintAndLogEx(INFO, "1.54_Step9");
            return PM3_SUCCESS;
        } else if (step == 14) {
            return PM3_ESOFT;
        }
    }
}

static int start_drawing(uint8_t model_nr, uint8_t *black, uint8_t *red) {
    uint8_t fail_num = 0;
    uint8_t      step = 0, progress = 0;
    uint8_t      step0[2] = {0xcd, 0x0d};
    uint8_t      step1[3] = {0xcd, 0x00, 10};    //select e-paper type and reset e-paper        4:2.13inch e-Paper   7:2.9inch e-Paper  10:4.2inch e-Paper  14:7.5inch e-Paper
    uint8_t      step2[2] = {0xcd, 0x01};      //e-paper normal mode  type：
    uint8_t      step3[2] = {0xcd, 0x02};      //e-paper config1
    uint8_t      step4[2] = {0xcd, 0x03};      //e-paper power on
    uint8_t      step5[2] = {0xcd, 0x05};      //e-paper config2
    uint8_t      step6[2] = {0xcd, 0x06};      //EDP load to main
    uint8_t      step7[2] = {0xcd, 0x07};      //Data preparation
    uint8_t      step8[123] = {0xcd, 0x08, 0x64};  //Data start command   2.13inch(0x10:Send 16 data at a time)    2.9inch(0x10:Send 16 data at a time)     4.2inch(0x64:Send 100 data at a time)  7.5inch(0x78:Send 120 data at a time)
    uint8_t      step9[2] = {0xcd, 0x18};     //e-paper power on
    uint8_t      step10[2] = {0xcd, 0x09};     //Refresh e-paper
    uint8_t      step11[2] = {0xcd, 0x0a};     //wait for ready
    uint8_t      step12[2] = {0xcd, 0x04};     //e-paper power off command
    uint8_t      step13[124] = {0xcd, 0x19, 121};
// uint8_t      step13[2]={0xcd,0x0b};     //Judge whether the power supply is turned off successfully
// uint8_t      step14[2]={0xcd,0x0c};     //The end of the transmission
    uint8_t      rx[20];
    uint16_t     actrxlen[20], i = 0;



    clearCommandBuffer();
    SendCommandMIX(CMD_HF_ISO14443A_READER, ISO14A_CONNECT | ISO14A_NO_DISCONNECT, 0, 0, NULL, 0);
    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_ACK, &resp, 2500)) {
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

    if ((card.uidlen != 7) || (memcmp(card.uid, "WSDZ10m", 7) != 0)) {
        PrintAndLogEx(WARNING, "Card doesn't look like Waveshare tag");
        DropField();
        return PM3_ESOFT;
    }

    PrintAndLogEx(DEBUG, "model_nr = %d", model_nr);
    while (1) {
        if (step == 0) {
            PrintAndLogEx(INFO, "Step0");
            transceive_blocking(step0, 2, rx, 20, actrxlen, 2157 + 2048);  //cd 0d
            if (rx[0] == 0 && rx[1] == 0) {
                rx[0] = 1;
                rx[1] = 1;
                step = 1;
            } else {
                fail_num++;
                if (fail_num > 10) {
                    PrintAndLogEx(WARNING, "Update failed, please try again.");
                    DropField();
                    return PM3_ESOFT;
                }
            }
        } else if (step == 1) {
            PrintAndLogEx(INFO, "Step1: e-paper config");
            //step1[2] screen model
            //step8[2] nr of bytes sent at once
            //step13[2] nr of bytes sent for the second time
            // generally, step8 sends a black image, step13 sends a red image
            if (model_nr == M2in13) {        //2.13inch
                step1[2] = EPD_2IN13V2;
                step8[2] = 16;
                step13[2] = 0;
            } else if (model_nr == M2in9) {  //2.9inch
                step1[2] = EPD_2IN9;
                step8[2] = 16;
                step13[2] = 0;
            } else if (model_nr == M4in2) {  //4.2inch
                step1[2] = EPD_4IN2;
                step8[2] = 100;
                step13[2] = 0;
            } else if (model_nr == M7in5) {  //7.5inch
                step1[2] = EPD_7IN5V2;
                step8[2] = 120;
                step13[2] = 0;
            } else if (model_nr == M2in7) {  //2.7inch
                step1[2] = EPD_2IN7;
                step8[2] = 121;
                // Send blank data for the first time, and send other data to 0xff without processing the bottom layer
                step13[2] = 121;
                //Sending the second data is the real image data. If the previous 0xff is not sent, the last output image is abnormally black
            } else if (model_nr == M2in13B) {  //2.13inch B
                step1[2] = EPD_2IN13BC;
                step8[2] = 106;
                step13[2] = 106;
            } else if (model_nr == M7in5HD) {
                step1[2] = EPD_7IN5HD;
                step8[2] = 120;
                step13[2] = 0;
            }

            if (model_nr == M1in54B) {
                transceive_blocking(step1, 2, rx, 20, actrxlen, 2157 + 2048);  //cd 00
            } else {
                transceive_blocking(step1, 3, rx, 20, actrxlen, 2157 + 2048);
            }
            if (rx[0] == 0 && rx[1] == 0) {
                rx[0] = 1;
                rx[1] = 1;
                step = 2;
                fail_num = 0;
                msleep(100);
            } else {
                fail_num++;
                if (fail_num > 10) {
                    PrintAndLogEx(WARNING, "Update failed, please try again.");
                    DropField();
                    return PM3_ESOFT;
                }
            }
            msleep(10);
        } else if (step == 2) {
            PrintAndLogEx(INFO, "Step2: e-paper normal mode type");
            transceive_blocking(step2, 2, rx, 20, actrxlen, 2157 + 2048);   //cd 01
            if (rx[0] == 0 && rx[1] == 0) {
                rx[0] = 1;
                rx[1] = 1;
                step = 3;
                fail_num = 0;
                msleep(100);
            } else {
                fail_num++;
                if (fail_num > 50) {
                    PrintAndLogEx(WARNING, "Update failed, please try again.");
                    DropField();
                    return PM3_ESOFT;
                }
            }
            msleep(100);
        } else if (step == 3) {
            PrintAndLogEx(INFO, "Step3: e-paper config1");
            transceive_blocking(step3, 2, rx, 20, actrxlen, 2157 + 2048); //cd 02
            if (rx[0] == 0 && rx[1] == 0) {
                rx[0] = 1;
                rx[1] = 1;
                step = 4;
                fail_num = 0;
            } else {
                fail_num++;
                if (fail_num > 10) {
                    PrintAndLogEx(WARNING, "Update failed, please try again.");
                    DropField();
                    return PM3_ESOFT;
                }
            }
            msleep(200);
        } else if (step == 4) {
            PrintAndLogEx(INFO, "Step4: e-paper power on");
            transceive_blocking(step4, 2, rx, 20, actrxlen, 2157 + 2048); //cd 03
            if (model_nr == M1in54B) {
                // 1.54B Keychain handler
                PrintAndLogEx(DEBUG, "Start_Drawing_1in54B");
                char t = start_drawing_1in54B(model_nr, black, red, fail_num);
                if (t == 0) {
                    step = 11;
                    //1.54B Data transfer is complete and wait for refresh
                } else if (t == 1) {
                    step = 14;
                    //1.54B Data transmission error
                }
                // 1.54B Keychain handler end
            }
            if (rx[0] == 0 && rx[1] == 0) {
                    fail_num = 0;
                    step = 5;
            } else {
                fail_num++;
                if (fail_num > 10) {
                    PrintAndLogEx(WARNING, "Update failed, please try again.");
                    DropField();
                    return PM3_ESOFT;
                }
            }
        } else if (step == 5) {
            PrintAndLogEx(INFO, "Step5: e-paper config2");
            transceive_blocking(step5, 2, rx, 20, actrxlen, 2157 + 2048);   //cd 05
            if (rx[0] == 0 && rx[1] == 0) {
                rx[0] = 1;
                rx[1] = 1;
                step = 6;
                fail_num = 0;
                msleep(100);
            } else {
                fail_num++;
                if (fail_num > 30) {
                    PrintAndLogEx(WARNING, "Update failed, please try again.");
                    DropField();
                    return PM3_ESOFT;
                }
            }
            msleep(10);
        } else if (step == 6) {
            PrintAndLogEx(INFO, "Step6: EDP load to main") ;
            transceive_blocking(step6, 2, rx, 20, actrxlen, 2157 + 2048); //cd 06
            if (rx[0] == 0 && rx[1] == 0) {
                rx[0] = 1;
                rx[1] = 1;
                step = 7;
                fail_num = 0;
                msleep(100);
            } else {
                fail_num++;
                if (fail_num > 10) {
                    PrintAndLogEx(WARNING, "Update failed, please try again.");
                    DropField();
                    return PM3_ESOFT;
                }
            }
        } else if (step == 7) {
            PrintAndLogEx(INFO, "Step7: Data preparation");
            transceive_blocking(step7, 2, rx, 20, actrxlen, 2157 + 2048); //cd 07
            if (rx[0] == 0 && rx[1] == 0) {
                rx[0] = 1;
                rx[1] = 1;
                step = 8;
                fail_num = 0;
            } else {
                fail_num++;
                if (fail_num > 10) {
                    PrintAndLogEx(WARNING, "Update failed, please try again.");
                    DropField();
                    return PM3_ESOFT;
                }
            }
        } else if (step == 8) { //cd 08
            PrintAndLogEx(INFO, "Step8: Start data transfer");
            if (model_nr == M2in13) {      //2.13inch
                for (i = 0; i < 250; i++) {
                    rx[0] = 1;
                    rx[1] = 1;
                    read_black(i, step8, model_nr, black);
                    transceive_blocking(step8, 19, rx, 20, actrxlen, 2157 + 2048);
                    progress = i * 100 / 250;
                    PrintAndLogEx(INPLACE, "Progress: %d %%", progress);
                }
            } else if (model_nr == M2in9) {
                for (i = 0; i < 296; i++) {
                    rx[0] = 1;
                    rx[1] = 1;
                    read_black(i, step8, model_nr, black);
                    transceive_blocking(step8, 19, rx, 20, actrxlen, 2157 + 2048);
                    progress = i * 100 / 296;
                    PrintAndLogEx(INPLACE, "Progress: %d %%", progress);
                }
            } else if (model_nr == M4in2) {    //4.2inch
                for (i = 0; i < 150; i++) {
                    rx[0] = 1;
                    rx[1] = 1;
                    read_black(i, step8, model_nr, black);
                    transceive_blocking(step8, 103, rx, 20, actrxlen, 2157 + 2048);
                    progress = i * 100 / 150;
                    PrintAndLogEx(INPLACE, "Progress: %d %%", progress);
                }
            } else if (model_nr == M7in5) {  //7.5inch
                for (i = 0; i < 400; i++) {
                    rx[0] = 1;
                    rx[1] = 1;
                    read_black(i, step8, model_nr, black);
                    transceive_blocking(step8, 123, rx, 20, actrxlen, 2157 + 2048);
                    progress = i * 100 / 400;
                    PrintAndLogEx(INPLACE, "Progress: %d %%", progress);
                    msleep(6);
                }
            } else if (model_nr == M2in13B) {  //2.13inch B
                for (i = 0; i < 26; i++) {
                    rx[0] = 1;
                    rx[1] = 1;
                    read_black(i, step8, model_nr, black);
                    transceive_blocking(step8, 109, rx, 20, actrxlen, 2157 + 2048);
                    progress = i * 50 / 26;
                    PrintAndLogEx(INPLACE, "Progress: %d %%", progress);
                }
            } else if (model_nr == M7in5HD) {  //7.5HD

                for (i = 0; i < 484; i++) {
                    rx[0] = 1;
                    rx[1] = 1;
                    read_black(i, step8, model_nr, black);
                    //memset(&step8[3], 0xf0, 120);
                    transceive_blocking(step8, 123, rx, 20, actrxlen, 2157 + 2048);
                    progress = i * 100 / 484;
                    PrintAndLogEx(INPLACE, "Progress: %d %%", progress);
                }
                memset(&step8[3], 0xff, 120);
                transceive_blocking(step8, 110 + 3, rx, 20, actrxlen, 2157 + 2048);


            } else if (model_nr == M2in7) {   //2.7inch
                for (i = 0; i < 48; i++) {
                    rx[0] = 1;
                    rx[1] = 1;
                    //read_black(i,step8, model_nr, black);
                    memset(&step8[3], 0xFF, sizeof(step8)-3);
                    transceive_blocking(step8, 124, rx, 20, actrxlen, 2157 + 2048);
                    progress = i * 50 / 48;
                    PrintAndLogEx(INPLACE, "Progress: %d %%", progress);
                }
            }
            PROMPT_CLEARLINE;
            step = 9;
        } else if (step == 9) {
            PrintAndLogEx(INFO, "Step9: e-paper power on");
            if (model_nr == M2in13 || model_nr == M2in9 || model_nr == M4in2 || model_nr == M7in5 || model_nr == M7in5HD) {
                transceive_blocking(step9, 2, rx, 20, actrxlen, 2157 + 2048); //cd 18
                // The black-and-white screen sending backplane is also shielded, with no effect. Except 2.7
                if (rx[0] != 0 || rx[1] != 0) {
                    fail_num++;
                    if (fail_num > 10) {
                        PrintAndLogEx(WARNING, "Update failed, please try again.");
                        DropField();
                        return PM3_ESOFT;
                    }
                } else
                    fail_num = 0;

                rx[0] = 1;
                rx[1] = 1;
                step = 10;
            } else if (model_nr == M2in13B ||  model_nr == M2in7) {
                transceive_blocking(step9, 2, rx, 20, actrxlen, 2157 + 2048); //cd 18
                //rx[0]=1;rx[1]=1;
                step = 19;
            }
        } else if (step == 10) {
            PrintAndLogEx(INFO, "Step10: Refresh e-paper");
            transceive_blocking(step10, 2, rx, 20, actrxlen, 2157 + 2048); //cd 09 refresh command
            if (rx[0] != 0 || rx[1] != 0) {
                fail_num++;
                if (fail_num > 10) {
                    PrintAndLogEx(WARNING, "Update failed, please try again.");
                    DropField();
                    return PM3_ESOFT;
                }
            } else
                fail_num = 0;
            rx[0] = 1;
            rx[1] = 1;
            step = 11;
            msleep(200);
        } else if (step == 11) {
            PrintAndLogEx(INFO, "Step11: Wait tag to be ready");
            if (model_nr == M2in13B || model_nr == M1in54B) { // Black, white and red screen refresh time is longer, wait first
                msleep(9000);
            } else if (model_nr == M7in5HD) {
                msleep(1000);
            }
            while (1) {
                rx[0] = 1;
                rx[1] = 1;
                if (model_nr == M1in54B) {
                    // send 0xcd 0x08 with 1.54B
                    transceive_blocking(step8, 2, rx, 20, actrxlen, 2157 + 2048);
                } else {
                    transceive_blocking(step11, 2, rx, 20, actrxlen, 2157 + 2048);          //cd 0a
                }
                if (rx[0] == 0xff && rx[1] == 0) {
                    PrintAndLogEx(NORMAL, "");
                    PrintAndLogEx(SUCCESS, "E-paper Reflash OK");
                    fail_num = 0;
                    step = 12;
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
                        msleep(100);
                    }
                }
            }

        } else if (step == 12) {
            PrintAndLogEx(INFO, "Step12: e-paper power off command");
            transceive_blocking(step12, 2, rx, 20, actrxlen, 2157 + 2048);          //cd 04
            rx[0] = 1;
            rx[1] = 1;
            step = 13;
            msleep(200);
        } else if (step == 13) {
            PrintAndLogEx(SUCCESS, "E-paper Update OK");
            rx[0] = 1;
            rx[1] = 1;
            msleep(200);
            DropField();
            return PM3_SUCCESS;
        } else if (step == 19) {
            PrintAndLogEx(INFO, "Step9b");
            if (model_nr == M2in7) {
                for (i = 0; i < 48; i++) {
                    rx[0] = 1;
                    rx[1] = 1;
                    read_black(i, step13, model_nr, black);
                    transceive_blocking(step13, 124, rx, 20, actrxlen, 2157 + 2048); //CD 19
                    progress = i * 50 / 48 + 50;
                    PrintAndLogEx(INPLACE, "Progress: %d %%", progress);
                }
            } else if (model_nr == M2in13B) {
                for (i = 0; i < 26; i++) {
                    rx[0] = 1;
                    rx[1] = 1;
                    read_red(i, step13, model_nr, red);
                    //memset(&step13[3], 0xfE, 106);
                    transceive_blocking(step13, 109, rx, 20, actrxlen, 2157 + 2048);
                    progress = i * 50 / 26 + 50;
                    PrintAndLogEx(INPLACE, "Progress: %d %%", progress);
                }
            }
            PROMPT_CLEARLINE;
            rx[0] = 1;
            rx[1] = 1;
            step = 10;
        }
    }
}


static int CmdHF14AWSLoadBmp(const char *Cmd) {

    char filename[FILE_PATH_SIZE] = {0};
    uint8_t cmdp = 0;
    bool errors = false;
    size_t filenamelen = 0;
    uint8_t model_nr = 0xff;

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_hf_waveshare_loadbmp();
            case 'f':
                filenamelen = param_getstr(Cmd, cmdp + 1, filename, FILE_PATH_SIZE);
                if (filenamelen > FILE_PATH_SIZE - 5)
                    filenamelen = FILE_PATH_SIZE - 5;
                cmdp += 2;
                break;
            case 'm':
                model_nr = param_get8(Cmd, cmdp + 1);
                cmdp += 2;
                break;
            default:
                PrintAndLogEx(WARNING, "Unknown parameter: " _RED_("'%c'"), param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }

    //Validations
    if (filenamelen < 1) {
        PrintAndLogEx(WARNING, "Missing filename");
        errors = true;
    }
    if (model_nr == 0xff) {
        PrintAndLogEx(WARNING, "Missing model");
        errors = true;
    } else if (model_nr >= MEND) {
        PrintAndLogEx(WARNING, "Unknown model");
        errors = true;
    }
    if (errors || cmdp == 0) return usage_hf_waveshare_loadbmp();

    uint8_t *bmp = NULL;
    uint8_t *black = NULL;
    uint8_t *red = NULL;
    size_t bytes_read = 0;
    if (loadFile_safe(filename, ".bmp", (void **)&bmp, &bytes_read) != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, "Could not find file " _YELLOW_("%s"), filename);
        return PM3_EIO;
    }

    int depth = picture_bit_depth(bmp, bytes_read);
    if (depth == PM3_ESOFT) {
        PrintAndLogEx(ERR, "Error, BMP file is too small");
        free(bmp);
        return PM3_ESOFT;
    } else if (depth == 1) {
        PrintAndLogEx(DEBUG, "BMP file is a bitmap");
        if (read_bmp_bitmap(bmp, bytes_read, &black) != PM3_SUCCESS) {
            free(bmp);
            return PM3_ESOFT;
        }
    } else if (depth == 24) {
        PrintAndLogEx(DEBUG, "BMP file is a RGB");
        if (read_bmp_rgb(bmp, bytes_read, &black, &red) != PM3_SUCCESS) {
            free(bmp);
            return PM3_ESOFT;
        }
    } else if (depth == 32) {
        PrintAndLogEx(ERR, "Error, BMP color depth %i not supported. Remove alpha channel.", depth);
        free(bmp);
        return PM3_ESOFT;
    } else {
        PrintAndLogEx(ERR, "Error, BMP color depth %i not supported", depth);
        free(bmp);
        return PM3_ESOFT;
    }
    free(bmp);

    start_drawing(model_nr, black, red);
    free(black);
    if (red != NULL) {
        free(red);
    }
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",        CmdHelp,              AlwaysAvailable, "This help"},
    {"loadbmp",     CmdHF14AWSLoadBmp,    IfPm3Iso14443a,  "Load BMP file to Waveshare NFC ePaper"},
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
