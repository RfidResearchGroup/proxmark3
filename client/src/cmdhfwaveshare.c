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

// Currently the largest pixel 880*528 only needs 58.08K bytes
#define WSMAPSIZE 60000

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
} PACKED bmp_header_t;

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

static int picture_bit_depth(const uint8_t *bmp, const size_t bmpsize, const uint8_t model_nr) {
    if (bmpsize < sizeof(bmp_header_t)) {
        return PM3_ESOFT;
    }

    bmp_header_t *pbmpheader = (bmp_header_t *)bmp;
    PrintAndLogEx(DEBUG, "colorsused = %d", pbmpheader->colorsused);
    PrintAndLogEx(DEBUG, "pbmpheader->bpp = %d", pbmpheader->bpp);
    if ((pbmpheader->BMP_Width != models[model_nr].width) || (pbmpheader->BMP_Height != models[model_nr].height)) {
        PrintAndLogEx(WARNING, "Invalid BMP size, expected %ix%i, got %ix%i", models[model_nr].width, models[model_nr].height, pbmpheader->BMP_Width, pbmpheader->BMP_Height);
    }
    return pbmpheader->bpp;
}

static int read_bmp_bitmap(const uint8_t *bmp, const size_t bmpsize, uint8_t model_nr, uint8_t **black, uint8_t **red) {
    bmp_header_t *pbmpheader = (bmp_header_t *)bmp;
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
    uint16_t width = pbmpheader->BMP_Width;
    uint16_t height = pbmpheader->BMP_Height;
    if ((width + 8) * height > WSMAPSIZE * 8) {
        PrintAndLogEx(WARNING, "The file is too large, aborting!");
        return PM3_ESOFT;
    }

    uint16_t X, Y;
    uint16_t Image_Width_Byte = (width % 8 == 0) ? (width / 8) : (width / 8 + 1);
    uint16_t Bmp_Width_Byte = (Image_Width_Byte % 4 == 0) ? Image_Width_Byte : ((Image_Width_Byte / 4 + 1) * 4);

    *black = calloc(WSMAPSIZE, sizeof(uint8_t));
    if (*black == NULL) {
        return PM3_EMALLOC;
    }
    // Write data into RAM
    for (Y = 0; Y < height; Y++) { // columns
        for (X = 0; X < Bmp_Width_Byte; X++) { // lines
            if ((X < Image_Width_Byte) && ((X + (height - Y - 1) * Image_Width_Byte) < WSMAPSIZE)) {
                (*black)[X + (height - Y - 1) * Image_Width_Byte] = color_flag ? bmp[offset] : ~bmp[offset];
            }
            offset++;
        }
    }
    if ((model_nr == M1in54B) || (model_nr == M2in13B)) {
        // for BW+Red screens:
        *red = calloc(WSMAPSIZE, sizeof(uint8_t));
        if (*red == NULL) {
            free(*black);
            return PM3_EMALLOC;
        }
    }
    return PM3_SUCCESS;
}

static void rgb_to_gray(const int16_t *chanR, const int16_t *chanG, const int16_t *chanB,
                        uint16_t width, uint16_t height, int16_t *chanGrey) {
    for (uint16_t Y = 0; Y < height; Y++) {
        for (uint16_t X = 0; X < width; X++) {
            // greyscale conversion
            float Clinear = 0.2126 * chanR[X + Y * width] + 0.7152 * chanG[X + Y * width] + 0.0722 * chanB[X + Y * width];
            // Csrgb = 12.92 Clinear when Clinear <= 0.0031308
            // Csrgb = 1.055 Clinear1/2.4 - 0.055 when Clinear > 0.0031308
            chanGrey[X + Y * width] = Clinear;
        }
    }
}

// Floyd-Steinberg dithering
static void dither_chan_inplace(int16_t *chan, uint16_t width, uint16_t height) {
    for (uint16_t Y = 0; Y < height; Y++) {
        for (uint16_t X = 0; X < width; X++) {
            int16_t oldp = chan[X + Y * width];
            int16_t newp = oldp > 127 ? 255 : 0;
            chan[X + Y * width] = newp;
            int16_t err = oldp - newp;
            const float m[] = {7, 3, 5, 1};
            if (X < width - 1) {
                chan[X + 1 +  Y      * width] = chan[X + 1 +  Y      * width] + m[0] / 16 * err;
            }
            if (Y < height - 1) {
                chan[X - 1 + (Y + 1) * width] = chan[X - 1 + (Y + 1) * width] + m[1] / 16 * err;
                chan[X     + (Y + 1) * width] = chan[X     + (Y + 1) * width] + m[2] / 16 * err;
            }
            if ((X < width - 1) && (Y < height - 1)) {
                chan[X + 1 + (Y + 1) * width] = chan[X + 1 + (Y + 1) * width] + m[3] / 16 * err;
            }
        }
    }
}

static uint32_t color_compare(int16_t r1, int16_t g1, int16_t b1, int16_t r2, int16_t g2, int16_t b2) {
    // Compute (square of) distance from oldR/G/B to this color
    int16_t inR = r1 - r2;
    int16_t inG = g1 - g2;
    int16_t inB = b1 - b2;
    // use RGB-to-grey weighting
    float dist =  0.2126 * inR * inR + 0.7152 * inG * inG + 0.0722 * inB * inB;
    return dist;
}

static void nearest_color(int16_t oldR, int16_t oldG, int16_t oldB, const uint8_t *palette,
                          uint16_t palettelen, uint8_t *newR, uint8_t *newG, uint8_t *newB) {
    uint32_t bestdist = 0x7FFFFFFF;
    for (uint16_t i = 0; i < palettelen; i++) {
        uint8_t R = palette[i * 3 + 0];
        uint8_t G = palette[i * 3 + 1];
        uint8_t B = palette[i * 3 + 2];
        uint32_t dist = color_compare(oldR, oldG, oldB, R, G, B);
        if (dist < bestdist) {
            bestdist = dist;
            *newR = R;
            *newG = G;
            *newB = B;
        }
    }
}

static void dither_rgb_inplace(int16_t *chanR, int16_t *chanG, int16_t *chanB, uint16_t width, uint16_t height, uint8_t *palette, uint16_t palettelen) {
    for (uint16_t Y = 0; Y < height; Y++) {
        for (uint16_t X = 0; X < width; X++) {
            // scan odd lines in the opposite direction
            uint16_t XX = X;
            if (Y % 2) {
                XX = width - X - 1;
            }
            int16_t oldR = chanR[XX + Y * width];
            int16_t oldG = chanG[XX + Y * width];
            int16_t oldB = chanB[XX + Y * width];
            uint8_t newR = 0, newG = 0, newB = 0;
            nearest_color(oldR, oldG, oldB, palette, palettelen, &newR, &newG, &newB);
            chanR[XX + Y * width] = newR;
            chanG[XX + Y * width] = newG;
            chanB[XX + Y * width] = newB;
            int16_t errR = oldR - newR;
            int16_t errG = oldG - newG;
            int16_t errB = oldB - newB;
            const float m[] = {7, 3, 5, 1};
            if (Y % 2) {
                if (XX > 0) {
                    chanR[XX - 1 +  Y      * width] = (chanR[XX - 1 +  Y      * width] + m[0] / 16 * errR);
                    chanG[XX - 1 +  Y      * width] = (chanG[XX - 1 +  Y      * width] + m[0] / 16 * errG);
                    chanB[XX - 1 +  Y      * width] = (chanB[XX - 1 +  Y      * width] + m[0] / 16 * errB);
                }
                if (Y < height - 1) {
                    chanR[XX - 1 + (Y + 1) * width] = (chanR[XX - 1 + (Y + 1) * width] + m[3] / 16 * errR);
                    chanG[XX - 1 + (Y + 1) * width] = (chanG[XX - 1 + (Y + 1) * width] + m[3] / 16 * errG);
                    chanB[XX - 1 + (Y + 1) * width] = (chanB[XX - 1 + (Y + 1) * width] + m[3] / 16 * errB);
                    chanR[XX     + (Y + 1) * width] = (chanR[XX     + (Y + 1) * width] + m[2] / 16 * errR);
                    chanG[XX     + (Y + 1) * width] = (chanG[XX     + (Y + 1) * width] + m[2] / 16 * errG);
                    chanB[XX     + (Y + 1) * width] = (chanB[XX     + (Y + 1) * width] + m[2] / 16 * errB);
                }
                if ((XX < width - 1) && (Y < height - 1)) {
                    chanR[XX + 1 + (Y + 1) * width] = (chanR[XX + 1 + (Y + 1) * width] + m[1] / 16 * errR);
                    chanG[XX + 1 + (Y + 1) * width] = (chanG[XX + 1 + (Y + 1) * width] + m[1] / 16 * errG);
                    chanB[XX + 1 + (Y + 1) * width] = (chanB[XX + 1 + (Y + 1) * width] + m[1] / 16 * errB);
                }
            } else {
                if (XX < width - 1) {
                    chanR[XX + 1 +  Y      * width] = (chanR[XX + 1 +  Y      * width] + m[0] / 16 * errR);
                    chanG[XX + 1 +  Y      * width] = (chanG[XX + 1 +  Y      * width] + m[0] / 16 * errG);
                    chanB[XX + 1 +  Y      * width] = (chanB[XX + 1 +  Y      * width] + m[0] / 16 * errB);
                }
                if (Y < height - 1) {
                    chanR[XX - 1 + (Y + 1) * width] = (chanR[XX - 1 + (Y + 1) * width] + m[1] / 16 * errR);
                    chanG[XX - 1 + (Y + 1) * width] = (chanG[XX - 1 + (Y + 1) * width] + m[1] / 16 * errG);
                    chanB[XX - 1 + (Y + 1) * width] = (chanB[XX - 1 + (Y + 1) * width] + m[1] / 16 * errB);
                    chanR[XX     + (Y + 1) * width] = (chanR[XX     + (Y + 1) * width] + m[2] / 16 * errR);
                    chanG[XX     + (Y + 1) * width] = (chanG[XX     + (Y + 1) * width] + m[2] / 16 * errG);
                    chanB[XX     + (Y + 1) * width] = (chanB[XX     + (Y + 1) * width] + m[2] / 16 * errB);
                }
                if ((XX < width - 1) && (Y < height - 1)) {
                    chanR[XX + 1 + (Y + 1) * width] = (chanR[XX + 1 + (Y + 1) * width] + m[3] / 16 * errR);
                    chanG[XX + 1 + (Y + 1) * width] = (chanG[XX + 1 + (Y + 1) * width] + m[3] / 16 * errG);
                    chanB[XX + 1 + (Y + 1) * width] = (chanB[XX + 1 + (Y + 1) * width] + m[3] / 16 * errB);
                }
            }
        }
    }
}

static void rgb_to_gray_red_inplace(int16_t *chanR, int16_t *chanG, int16_t *chanB, uint16_t width, uint16_t height) {
    for (uint16_t Y = 0; Y < height; Y++) {
        for (uint16_t X = 0; X < width; X++) {
            float Clinear = 0.2126 * chanR[X + Y * width] + 0.7152 * chanG[X + Y * width] + 0.0722 * chanB[X + Y * width];
            if ((chanR[X + Y * width] < chanG[X + Y * width] && chanR[X + Y * width] < chanB[X + Y * width])) {
                chanR[X + Y * width] = Clinear;
                chanG[X + Y * width] = Clinear;
                chanB[X + Y * width] = Clinear;
            }
        }
    }
}

static void threshold_chan(const int16_t *colorchan, uint16_t width, uint16_t height, uint8_t threshold, uint8_t *colormap) {
    for (uint16_t Y = 0; Y < height; Y++) {
        for (uint16_t X = 0; X < width; X++) {
            colormap[X + Y * width] = colorchan[X + Y * width] < threshold;
        }
    }
}

static void threshold_rgb_black_red(const int16_t *chanR, const int16_t *chanG, const int16_t *chanB,
                                    uint16_t width, uint16_t height, uint8_t threshold_black,
                                    uint8_t threshold_red, uint8_t *blackmap, uint8_t *redmap) {
    for (uint16_t Y = 0; Y < height; Y++) {
        for (uint16_t X = 0; X < width; X++) {
            if ((chanR[X + Y * width] < threshold_black) && (chanG[X + Y * width] < threshold_black) && (chanB[X + Y * width] < threshold_black)) {
                blackmap[X + Y * width] = 1;
                redmap[X + Y * width] = 0;
            } else if ((chanR[X + Y * width] > threshold_red) && (chanG[X + Y * width] < threshold_black) && (chanB[X + Y * width] < threshold_black)) {
                blackmap[X + Y * width] = 0;
                redmap[X + Y * width] = 1;
            } else {
                blackmap[X + Y * width] = 0;
                redmap[X + Y * width] = 0;
            }
        }
    }
}

static void map8to1(const uint8_t *colormap, uint16_t width, uint16_t height, uint8_t *colormap8) {
    uint16_t width8;
    if (width % 8 == 0) {
        width8 = width / 8;
    } else {
        width8 = width / 8 + 1;
    }
    uint8_t data = 0;
    uint8_t count = 0;
    for (uint16_t Y = 0; Y < height; Y++) {
        for (uint16_t X = 0; X < width; X++) {
            data = data | colormap[X + Y * width];
            count += 1;
            if ((count >= 8) || (X == width - 1)) {
                colormap8[X / 8 + Y * width8] = (~data) & 0xFF;
                count = 0;
                data = 0;
            }
            data = (data << 1) & 0xFF;
        }
    }
}

static int read_bmp_rgb(uint8_t *bmp, const size_t bmpsize, uint8_t model_nr, uint8_t **black, uint8_t **red, char *filename, bool save_conversions) {
    bmp_header_t *pbmpheader = (bmp_header_t *)bmp;
    // check file is full color
    if ((pbmpheader->bpp != 24) && (pbmpheader->bpp != 32)) {
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
    uint16_t width = pbmpheader->BMP_Width;
    uint16_t height = pbmpheader->BMP_Height;
    if ((width + 8) * height > WSMAPSIZE * 8) {
        PrintAndLogEx(WARNING, "The file is too large, aborting!");
        return PM3_ESOFT;
    }

    int16_t *chanR = calloc(((size_t)width) * height, sizeof(int16_t));
    if (chanR == NULL) {
        return PM3_EMALLOC;
    }

    int16_t *chanG = calloc(((size_t)width) * height, sizeof(int16_t));
    if (chanG == NULL) {
        free(chanR);
        return PM3_EMALLOC;
    }

    int16_t *chanB = calloc(((size_t)width) * height, sizeof(int16_t));
    if (chanB == NULL) {
        free(chanR);
        free(chanG);
        return PM3_EMALLOC;
    }

    // Extracting BMP chans
    for (uint16_t Y = 0; Y < height; Y++) {
        for (uint16_t X = 0; X < width; X++) {
            chanB[X + (height - Y - 1) * width] = bmp[offset++];
            chanG[X + (height - Y - 1) * width] = bmp[offset++];
            chanR[X + (height - Y - 1) * width] = bmp[offset++];
            if (pbmpheader->bpp == 32) // Skip Alpha chan
                offset++;
        }
        // Skip line padding
        offset += width % 4;
    }

    if ((model_nr == M1in54B) || (model_nr == M2in13B)) {
        // for BW+Red screens:
        uint8_t *mapBlack = calloc(((size_t)width) * height, sizeof(uint8_t));
        if (mapBlack == NULL) {
            free(chanR);
            free(chanG);
            free(chanB);
            return PM3_EMALLOC;
        }
        uint8_t *mapRed = calloc(((size_t)width) * height, sizeof(uint8_t));
        if (mapRed == NULL) {
            free(chanR);
            free(chanG);
            free(chanB);
            free(mapBlack);
            return PM3_EMALLOC;
        }
        rgb_to_gray_red_inplace(chanR, chanG, chanB, width, height);

        uint8_t palette[] = {0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00}; // black, white, red
        dither_rgb_inplace(chanR, chanG, chanB, width, height, palette, sizeof(palette) / 3);

        threshold_rgb_black_red(chanR, chanG, chanB, width, height, 128, 128, mapBlack, mapRed);
        if (save_conversions) {
            // fill BMP chans
            offset = pbmpheader->offset;
            for (uint16_t Y = 0; Y < height; Y++) {
                for (uint16_t X = 0; X < width; X++) {
                    bmp[offset++] = chanB[X + (height - Y - 1) * width] & 0xFF;
                    bmp[offset++] = chanG[X + (height - Y - 1) * width] & 0xFF;
                    bmp[offset++] = chanR[X + (height - Y - 1) * width] & 0xFF;
                    if (pbmpheader->bpp == 32) // Fill Alpha chan
                        bmp[offset++] = 0xFF;
                }
                // Skip line padding
                offset += width % 4;
            }
            PrintAndLogEx(INFO, "Saving red+black dithered version...");
            if (saveFile(filename, ".bmp", bmp, offset) != PM3_SUCCESS) {
                PrintAndLogEx(WARNING, "Could not save file " _YELLOW_("%s"), filename);
                free(chanR);
                free(chanG);
                free(chanB);
                free(mapBlack);
                free(mapRed);
                return PM3_EIO;
            }
        }
        free(chanR);
        free(chanG);
        free(chanB);
        *black = calloc(WSMAPSIZE, sizeof(uint8_t));
        if (*black == NULL) {
            free(mapBlack);
            free(mapRed);
            return PM3_EMALLOC;
        }
        map8to1(mapBlack, width, height, *black);
        free(mapBlack);
        *red = calloc(WSMAPSIZE, sizeof(uint8_t));
        if (*red == NULL) {
            free(mapRed);
            free(*black);
            return PM3_EMALLOC;
        }
        map8to1(mapRed, width, height, *red);
        free(mapRed);
    } else {
        // for BW-only screens:
        int16_t *chanGrey = calloc(((size_t)width) * height, sizeof(int16_t));
        if (chanGrey == NULL) {
            free(chanR);
            free(chanG);
            free(chanB);
            return PM3_EMALLOC;
        }
        rgb_to_gray(chanR, chanG, chanB, width, height, chanGrey);
        dither_chan_inplace(chanGrey, width, height);

        uint8_t *mapBlack = calloc(((size_t)width) * height, sizeof(uint8_t));
        if (mapBlack == NULL) {
            free(chanR);
            free(chanG);
            free(chanB);
            free(chanGrey);
            return PM3_EMALLOC;
        }
        threshold_chan(chanGrey, width, height, 128, mapBlack);

        if (save_conversions) {
            // fill BMP chans
            offset = pbmpheader->offset;
            for (uint16_t Y = 0; Y < height; Y++) {
                for (uint16_t X = 0; X < width; X++) {
                    bmp[offset++] = chanGrey[X + (height - Y - 1) * width] & 0xFF;
                    bmp[offset++] = chanGrey[X + (height - Y - 1) * width] & 0xFF;
                    bmp[offset++] = chanGrey[X + (height - Y - 1) * width] & 0xFF;
                    if (pbmpheader->bpp == 32) // Fill Alpha chan
                        bmp[offset++] = 0xFF;
                }
                // Skip line padding
                offset += width % 4;
            }
            PrintAndLogEx(INFO, "Saving black dithered version...");
            if (saveFile(filename, ".bmp", bmp, offset) != PM3_SUCCESS) {
                PrintAndLogEx(WARNING, "Could not save file " _YELLOW_("%s"), filename);
                free(chanGrey);
                free(chanR);
                free(chanG);
                free(chanB);
                free(mapBlack);
                return PM3_EIO;
            }
        }
        free(chanGrey);
        free(chanR);
        free(chanG);
        free(chanB);
        *black = calloc(WSMAPSIZE, sizeof(uint8_t));
        if (*black == NULL) {
            free(mapBlack);
            return PM3_EMALLOC;
        }
        map8to1(mapBlack, width, height, *black);
        free(mapBlack);
    }
    return PM3_SUCCESS;
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

static int CmdHF14AWSLoadBmp(const char *Cmd) {

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
        arg_lit0("s", "save", "save dithered version in filename-[n].bmp, only for RGB BMP"),
        arg_str1("f", "file", "<fn>", "specify filename[.bmp] to upload to tag"),
        arg_param_end
    };

    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int model_nr = arg_get_int_def(ctx, 1, -1);
    bool save_conversions = arg_get_lit(ctx, 2);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 3), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);
    CLIParserFree(ctx);

    //Validations
    if (fnlen < 1) {
        PrintAndLogEx(WARNING, "Missing filename");
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

    uint8_t *bmp = NULL;
    uint8_t *black = NULL;
    uint8_t *red = NULL;
    size_t bytes_read = 0;
    if (loadFile_safe(filename, ".bmp", (void **)&bmp, &bytes_read) != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, "Could not find file " _YELLOW_("%s"), filename);
        return PM3_EFILE;
    }
    if (bmp == NULL) {
        return PM3_EMALLOC;
    }
    if (bytes_read < sizeof(bmp_header_t)) {
        free(bmp);
        return PM3_ESOFT;
    }

    int depth = picture_bit_depth(bmp, bytes_read, model_nr);
    if (depth == PM3_ESOFT) {
        PrintAndLogEx(ERR, "Error, BMP file is too small");
        free(bmp);
        return PM3_ESOFT;
    } else if (depth == 1) {
        PrintAndLogEx(DEBUG, "BMP file is a bitmap");
        if (read_bmp_bitmap(bmp, bytes_read, model_nr, &black, &red) != PM3_SUCCESS) {
            free(bmp);
            return PM3_ESOFT;
        }
    } else if (depth == 24) {
        PrintAndLogEx(DEBUG, "BMP file is a RGB");
        if (read_bmp_rgb(bmp, bytes_read, model_nr, &black, &red, filename, save_conversions) != PM3_SUCCESS) {
            free(bmp);
            return PM3_ESOFT;
        }
    } else if (depth == 32) {
        PrintAndLogEx(DEBUG, "BMP file is a RGBA, we will ignore the Alpha channel");
        if (read_bmp_rgb(bmp, bytes_read, model_nr, &black, &red, filename, save_conversions) != PM3_SUCCESS) {
            free(bmp);
            return PM3_ESOFT;
        }
    } else {
        PrintAndLogEx(ERR, "Error, BMP color depth %i not supported. Must be 1 (BW), 24 (RGB) or 32 (RGBA)", depth);
        free(bmp);
        return PM3_ESOFT;
    }
    free(bmp);

    start_drawing(model_nr, black, red);
    free(black);
    if ((model_nr == M1in54B) || (model_nr == M2in13B)) {
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
