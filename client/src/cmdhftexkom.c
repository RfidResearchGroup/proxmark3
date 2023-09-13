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
// High frequency proximity cards from TEXCOM commands
//-----------------------------------------------------------------------------

#include "cmdhftexkom.h"

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "cliparser.h"
#include "cmdparser.h"    // command_t
#include "comms.h"
#include "ui.h"
#include "cmdhf14a.h"
#include "cmddata.h"
#include "graph.h"

#define TEXKOM_NOISE_THRESHOLD (10)

static inline uint32_t GetGraphBuffer(uint32_t indx) {
    if (g_GraphBuffer[indx] < -128)
        return 0;
    else
        return g_GraphBuffer[indx] + 128;
}

static uint32_t TexkomAVGField(void) {
    if (g_GraphTraceLen == 0)
        return 0;

    uint64_t vsum = 0;
    for (uint32_t i = 0; i < g_GraphTraceLen; i++)
        vsum += GetGraphBuffer(i);

    return vsum / g_GraphTraceLen;
}

static uint32_t TexkomSearchStart(uint32_t indx, uint32_t threshold) {
    // one bit length = 27, minimal noise = 60
    uint32_t lownoisectr = 0;
    for (uint32_t i = indx; i < g_GraphTraceLen; i++) {
        if (lownoisectr > 60) {
            if (GetGraphBuffer(i) > threshold)
                return i;
        } else {
            if (GetGraphBuffer(i) > threshold)
                lownoisectr = 0;
            else
                lownoisectr++;
        }
    }

    return 0;
}

static uint32_t TexkomSearchLength(uint32_t indx, uint32_t threshold) {
    // one bit length = 27, minimal noise = 60
    uint32_t lownoisectr = 0;
    uint32_t datalen = 0;
    for (uint32_t i = indx; i < g_GraphTraceLen; i++) {
        if (lownoisectr > 60) {
            break;
        } else {
            if (GetGraphBuffer(i) > threshold) {
                lownoisectr = 0;
                datalen = i - indx + 27;
            } else {
                lownoisectr++;
            }
        }
    }

    return datalen;
}

static uint32_t TexkomSearchMax(uint32_t indx, uint32_t len) {
    uint32_t res = 0;

    for (uint32_t i = 0; i < len; i++) {
        if (i + indx > g_GraphTraceLen)
            break;

        if (GetGraphBuffer(indx + i) > res)
            res = GetGraphBuffer(indx + i);
    }

    return res;
}

static bool TexkomCorrelate(uint32_t indx, uint32_t threshold) {
    if (indx < 2 || indx + 2 > g_GraphTraceLen)
        return false;

    uint32_t g1 = GetGraphBuffer(indx - 2);
    uint32_t g2 = GetGraphBuffer(indx - 1);
    uint32_t g3 = GetGraphBuffer(indx);
    uint32_t g4 = GetGraphBuffer(indx + 1);
    uint32_t g5 = GetGraphBuffer(indx + 2);

    return (
               (g3 > threshold) &&
               (g3 >= g2) && (g3 >= g1) && (g3 > g4) && (g3 > g5)
           );
}

static bool TexkomCalculateMaxMin(const uint32_t *data, uint32_t len, uint32_t *dmax, uint32_t *dmin) {
    *dmax = 0;
    *dmin = 0xffffffff;
    for (size_t i = 0; i < len; i++) {
        if (data[i] > *dmax)
            *dmax = data[i];
        if (data[i] < *dmin)
            *dmin = data[i];
    }

    return (*dmax != 0) && (*dmin != 0xffffffff) && (*dmax > *dmin);
}

static bool TexkomCalculateBitLengths(uint32_t *data, uint32_t len, uint32_t *hi, uint32_t *low, uint32_t *lmax, uint32_t *lmin) {
    *hi = 0;
    *low = 0;

    uint32_t dmax = 0;
    uint32_t dmin = 0xffffffff;
    if (!TexkomCalculateMaxMin(data, len, &dmax, &dmin))
        return false;

    uint32_t dmiddle = (dmax + dmin) / 2;
    uint32_t sumhi = 0;
    uint32_t lenhi = 0;
    uint32_t sumlow = 0;
    uint32_t lenlow = 0;
    for (size_t i = 0; i < len; i++) {
        if (data[i] > dmiddle) {
            sumhi += data[i];
            lenhi++;
        } else {
            sumlow += data[i];
            lenlow++;
        }
    }

    if (lenhi)
        *hi = sumhi / lenhi;

    if (lenlow)
        *low = sumlow / lenlow;

    if (lmax != NULL)
        *lmax = dmax;
    if (lmin != NULL)
        *lmin = dmin;

    return (*hi != 0) && (*low != 0) && (*hi > *low);
}

static inline bool TexcomCalculateBit(uint32_t data, uint32_t bitlen, uint32_t threshold) {
    return
        (data < (bitlen + threshold)) &&
        (data > (bitlen - threshold));
}

// code from https://github.com/li0ard/crclib/blob/main/index.js
static uint8_t TexcomTK13CRC(const uint8_t *data) {
    uint8_t crc = 0;
    uint8_t indx = 0;
    while (indx < 4) {
        crc = crc ^ data[indx++];

        for (uint8_t i = 0; i < 8; i++)
            if (crc & 0x80) {
                crc = 0x31 ^ (crc << 1);
            } else
                crc <<= 1;
    };

    return crc;
}

static uint8_t MMBITCRC(const uint8_t *data) {
    return
        (((data[0] & 0x0f) ^ ((data[0] >> 4) & 0x0f) ^
          (data[1] & 0x0f) ^ ((data[1] >> 4) & 0x0f) ^
          (data[2] & 0x0f) ^ ((data[2] >> 4) & 0x0f)
         ) ^ 0x0f
        ) & 0x0f;
}

static unsigned char dallas_crc8(const unsigned char *data, const unsigned int size) {
    unsigned char crc = 0;
    for (unsigned int i = 0; i < size; ++i) {
        unsigned char inbyte = data[i];
        for (unsigned char j = 0; j < 8; ++j) {
            unsigned char mix = (crc ^ inbyte) & 0x01;
            crc >>= 1;
            if (mix) crc ^= 0x8C;
            inbyte >>= 1;
        }
    }
    return crc;
}

// code from https://github.com/li0ard/crclib/blob/main/index.js
static uint8_t TexcomTK17CRC(uint8_t *data) {
    uint8_t ddata[8] = {0x00, 0x00, 0x00, data[0], data[1], data[2], data[3], 0x00};

    return dallas_crc8(ddata, 7);
}

static bool TexcomTK13Decode(uint32_t *implengths, uint32_t implengthslen, char *bitstring, char *cbitstring, bool verbose) {
    bitstring[0] = 0;
    cbitstring[0] = 0;
    if (implengthslen == 0)
        return false;

    uint32_t hilength = 0;
    uint32_t lowlength = 0;
    if (!TexkomCalculateBitLengths(implengths, implengthslen, &hilength, &lowlength, NULL, NULL))
        return false;

    uint32_t threshold = (hilength - lowlength) / 3 + 1;
    //PrintAndLogEx(WARNING, "--- hi: %d, low: %d, threshold: %d", hilength, lowlength, threshold);

    bool biterror = false;
    for (uint32_t i = 0; i < implengthslen; i++) {
        if (TexcomCalculateBit(implengths[i], hilength, threshold))
            strcat(bitstring, "1");
        else if (TexcomCalculateBit(implengths[i], lowlength, threshold))
            strcat(bitstring, "0");
        else {
            //PrintAndLogEx(INFO, "ERROR string [%zu]: %s, bit: %d, blen: %d", strlen(bitstring), bitstring, i, implengths[i]);

            biterror = true;
            break;
        }
    }

    if (biterror || strlen(bitstring) == 0)
        return false;

    if (verbose)
        PrintAndLogEx(INFO, "raw bit string [%3zu]... %s", strlen(bitstring), bitstring);

    // add trailing impulse (some tags just ignore it)
    if (strlen(bitstring) % 2 != 0) {
        if (bitstring[strlen(bitstring) - 1] == '1')
            strcat(bitstring, "0");
        else
            strcat(bitstring, "1");
    }

    for (uint32_t i = 0; i < strlen(bitstring); i = i + 2) {
        if (bitstring[i] == bitstring[i + 1]) {
            cbitstring[0] = 0;
            if (verbose)
                PrintAndLogEx(WARNING, "Raw bit string have error at offset %d.", i);
            break;
        }
        if (bitstring[i] == '1')
            strcat(cbitstring, "1");
        else
            strcat(cbitstring, "0");
    }

    if (strlen(cbitstring) == 0)
        return false;

    if (verbose)
        PrintAndLogEx(INFO, "bit string [%3zu].... %s", strlen(cbitstring), cbitstring);

    return ((strlen(cbitstring) == 64) && (strncmp(cbitstring, "1111111111111111", 16) == 0));
}

// general decode of the very bad signal. maybe here will be some of tk-13 old badges
static bool TexcomTK15Decode(uint32_t *implengths, uint32_t implengthslen, char *bitstring, char *cbitstring, bool verbose) {
    bitstring[0] = 0;
    cbitstring[0] = 0;
    if (implengthslen == 0)
        return false;

    bool biterror = false;
    for (uint32_t i = 0; i < implengthslen / 2; i++) {
        if (implengths[i * 2] == implengths[i * 2 + 1]) {
            biterror = true;
            break;
        } else if (implengths[i * 2] > implengths[i * 2 + 1]) {
            strcat(bitstring, "10");
            strcat(cbitstring, "1");
        } else {
            strcat(bitstring, "01");
            strcat(cbitstring, "0");
        }
    }

    if (implengthslen > 2 && implengthslen % 2 != 0) {
        int lastimplen = implengths[implengthslen - 1];
        bool prevbit = (implengths[implengthslen - 3] > implengths[implengthslen - 2]);
        bool thesamebit = (abs(lastimplen - (int)implengths[implengthslen - 3]) < abs(lastimplen - (int)implengths[implengthslen - 2]));

        if (prevbit ^ (!thesamebit)) {
            strcat(bitstring, "10");
            strcat(cbitstring, "1");
        } else {
            strcat(bitstring, "01");
            strcat(cbitstring, "0");
        }
    }

    if (biterror || strlen(bitstring) == 0 || strlen(cbitstring) == 0)
        return false;

    if (verbose) {
        PrintAndLogEx(INFO, "raw bit string [%3zu]... %s", strlen(bitstring), bitstring);
        PrintAndLogEx(INFO, "bit string [%3zu]....... %s", strlen(cbitstring), cbitstring);
    }

    return ((strlen(cbitstring) == 64) && (strncmp(cbitstring, "1111111111111111", 16) == 0));
}

static inline int TexcomTK17Get2Bits(uint32_t len1, uint32_t len2) {
    uint32_t xlen = (len2 * 100) / (len1 + len2);
    if (xlen < 10 || xlen > 90)
        return TK17WrongBit;
    if (xlen < 30)
        return TK17Bit00;
    if (xlen < 50)
        return TK17Bit10;
    if (xlen < 70)
        return TK17Bit01;
    return TK17Bit11;
}

static bool TexcomTK17Decode(uint32_t *implengths, uint32_t implengthslen, char *bitstring, char *cbitstring, bool verbose) {
    bitstring[0] = 0;
    cbitstring[0] = 0;
    if (implengthslen == 0)
        return false;

    for (uint32_t i = 0; i < implengthslen; i = i + 2) {
        int dbit = TexcomTK17Get2Bits(implengths[i], implengths[i + 1]);
        if (dbit == TK17WrongBit)
            return false;

        switch (dbit) {
            case TK17Bit00:
                strcat(bitstring, "00");
                break;
            case TK17Bit01:
                strcat(bitstring, "01");
                break;
            case TK17Bit10:
                strcat(bitstring, "10");
                break;
            case TK17Bit11:
                strcat(bitstring, "11");
                break;
            default:
                return false;
        }
    }

    if (verbose)
        PrintAndLogEx(INFO, "TK17 raw bit string [%zu]: %s", strlen(bitstring), bitstring);

    for (uint32_t i = 0; i < 8; i++) {
        memcpy(&cbitstring[i * 8 + 0], &bitstring[i * 8 + 6], 2);
        memcpy(&cbitstring[i * 8 + 2], &bitstring[i * 8 + 4], 2);
        memcpy(&cbitstring[i * 8 + 4], &bitstring[i * 8 + 2], 2);
        memcpy(&cbitstring[i * 8 + 6], &bitstring[i * 8 + 0], 2);
    }

    if (verbose)
        PrintAndLogEx(INFO, "TK17 bit string [%zu]: %s", strlen(cbitstring), cbitstring);

    return (strlen(bitstring) == 64) && (strncmp(cbitstring, "1111111111111111", 16) == 0);
}

static bool TexcomGeneralDecode(uint32_t *implengths, uint32_t implengthslen, char *bitstring, bool verbose) {
    uint32_t hilength = 0;
    uint32_t lowlength = 0;
    if (!TexkomCalculateBitLengths(implengths, implengthslen, &hilength, &lowlength, NULL, NULL))
        return false;

    uint32_t threshold = (hilength - lowlength) / 3 + 1;

    bitstring[0] = 0;
    bool biterror = false;
    for (uint32_t i = 0; i < implengthslen; i++) {
        if (TexcomCalculateBit(implengths[i], hilength, threshold))
            strcat(bitstring, "1");
        else if (TexcomCalculateBit(implengths[i], lowlength, threshold))
            strcat(bitstring, "0");
        else {
            if (verbose) {
                PrintAndLogEx(INFO, "ERROR string [%zu]: %s, bit: %d, blen: %d", strlen(bitstring), bitstring, i, implengths[i]);

                PrintAndLogEx(INFO, "Length array:");
                for (uint32_t j = 0; j < implengthslen; j++) {
                    PrintAndLogEx(NORMAL, "%u, " NOLF, implengths[j]);
                }
                PrintAndLogEx(NORMAL, "");
            }

            biterror = true;
            break;
        }
    }
    if (verbose)
        PrintAndLogEx(INFO, "General raw bit string [%zu]... %s", strlen(bitstring), bitstring);

    return (!biterror && strlen(bitstring) > 0);
}

static void TexcomReverseCode(const uint8_t *code, int length, uint8_t *reverse_code) {
    for (int i = 0; i < length; i++) {
        reverse_code[i] = code[(length - 1) - i];
    }
};

static int texkom_get_type(texkom_card_select_t *card, bool verbose) {

    if (card == NULL) {
        return PM3_EINVARG;
    }

    // get samples from tag.

    uint32_t samplesCount = 30000;
    clearCommandBuffer();
    SendCommandNG(CMD_HF_ACQ_RAW_ADC, (uint8_t *)&samplesCount, sizeof(uint32_t));
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_HF_ACQ_RAW_ADC, &resp, 2500) == false) {
        if (verbose) {
            PrintAndLogEx(WARNING, "command execution time out");
        }
        return PM3_ETIMEOUT;
    }

    uint32_t size = (resp.data.asDwords[0]);
    if (size > 0) {
        if (getSamples(samplesCount, false) != PM3_SUCCESS) {
            if (verbose)
                PrintAndLogEx(ERR, "Get samples error");

            return PM3_EFAILED;
        };
    }

    // decode samples to 8 bytes
    char bitstring[256] = {0};
    char cbitstring[128] = {0};
    char genbitstring[256] = {0};
    int found = TexkomModError;
    uint32_t sindx = 0;

    while (sindx < samplesCount - 5) {

        sindx = TexkomSearchStart(sindx, TEXKOM_NOISE_THRESHOLD);
        if (sindx == 0 || sindx > samplesCount - 5) {
            if (TexkomAVGField() > 30 && verbose) {
                PrintAndLogEx(WARNING, "Too noisy environment. Try to move the tag from the antenna a bit.");
            }
            break;
        }

        uint32_t slen = TexkomSearchLength(sindx, TEXKOM_NOISE_THRESHOLD);
        if (slen == 0) {
            continue;
        }

        uint32_t maxlvl = TexkomSearchMax(sindx, 1760);
        if (maxlvl < TEXKOM_NOISE_THRESHOLD) {
            sindx += 1700;
            continue;
        }

        uint32_t noiselvl = maxlvl / 5;
        if (noiselvl < TEXKOM_NOISE_THRESHOLD) {
            noiselvl = TEXKOM_NOISE_THRESHOLD;
        }

        uint32_t implengths[256] = {};
        uint32_t implengthslen = 0;
        uint32_t impulseindx = 0;
        uint32_t impulsecnt = 0;
        for (uint32_t i = 0; i < slen; i++) {
            if (TexkomCorrelate(sindx + i, noiselvl)) {
                impulsecnt++;

                if (impulseindx != 0) {
                    if (implengthslen < 256) {
                        implengths[implengthslen++] = sindx + i - impulseindx;
                    }
                }
                impulseindx = sindx + i;
            }
        }

        // check if it TK-17 modulation
        // 65 impulses and 64 intervals (1 interval = 2 bits, interval length encoding) that represents 128 bit of card code
        if (impulsecnt == 65) {
            if (TexcomTK17Decode(implengths, implengthslen, bitstring, cbitstring, verbose)) {
                found = TexkomModTK17;
                break;
            }
        }

        // check if it TK-13 or TK-15 modulation
        // it have 127 or 128 impulses and 128 double-intervals that represents 128 bit of card code
        if (impulsecnt == 127 || impulsecnt == 128) {
            if (TexcomTK13Decode(implengths, implengthslen, bitstring, cbitstring, verbose)) {
                found = TexkomModTK13;
                break;
            } else if (TexcomTK15Decode(implengths, implengthslen, bitstring, cbitstring, verbose)) {
                found = TexkomModTK15;
                break;
            }
        }

        // general decoding. it thought that there is 2 types of intervals "long" (1) and "short" (0)
        // and tries to decode sequence. shows only raw data
        if (verbose)
            TexcomGeneralDecode(implengths, implengthslen, genbitstring, verbose);
    }

    if (found != TexkomModError) {

        for (uint32_t i = 0; i < strlen(cbitstring); i++) {
            card->tcode[i / 8] = (card->tcode[i / 8] << 1) | ((cbitstring[i] == '1') ? 1 : 0);
        }

        TexcomReverseCode(card->tcode, sizeof(card->tcode), card->rtcode);
        return PM3_SUCCESS;
    }
    return PM3_ESOFT;
}

int read_texkom_uid(bool loop, bool verbose) {

    do {
        texkom_card_select_t card;

        int res = texkom_get_type(&card, verbose);

        if (loop) {
            if (res != PM3_SUCCESS) {
                continue;
            }
        } else {
            switch (res) {
                case PM3_EFAILED:
                case PM3_EINVARG:
                    return res;
                case PM3_ETIMEOUT:
                    if (verbose) {
                        PrintAndLogEx(WARNING, "command execution time out");
                    }
                    return res;
                case PM3_ESOFT:
                    if (verbose) {
                        PrintAndLogEx(WARNING, "texkom card select failed");
                    }
                    return PM3_ESOFT;
                default:
                    break;
            }
        }

        // decoding code
        if (card.tcode[0] == 0xff && card.tcode[1] == 0xff) {

            if (loop == false) {
                PrintAndLogEx(NORMAL, "");
            }

            bool crc = (TexcomTK13CRC(&card.tcode[3]) == card.tcode[7]);
            bool printed = false;

            if (card.tcode[2] == 0x63) {
                PrintAndLogEx(INFO, "TYPE..... " _YELLOW_("TK13"));
                PrintAndLogEx(INFO, "UID...... " _GREEN_("%s"), sprint_hex(&card.tcode[3], 4));
                if (verbose) {
                    PrintAndLogEx(INFO, "CRC...... %s", (crc) ?  _GREEN_("ok") : _RED_("fail"));
                }
                printed = true;
            } else if (card.tcode[2] == 0xCA) {
                PrintAndLogEx(INFO, "TYPE..... " _YELLOW_("TK17"));
                PrintAndLogEx(INFO, "UID...... " _GREEN_("%s"), sprint_hex(&card.tcode[3], 4));
                if (verbose) {
                    PrintAndLogEx(INFO, "CRC...... %s", (crc) ?  _GREEN_("ok") : _RED_("fail"));
                }
                printed = true;
            } else if (card.tcode[2] == 0xFF && card.tcode[3] == 0xFF) {
                PrintAndLogEx(INFO, "TYPE..... " _YELLOW_("MMBIT"));
                PrintAndLogEx(INFO, "UID...... " _GREEN_("%s"), sprint_hex(&card.tcode[4], 3));
                if (verbose) {
                    crc = (MMBITCRC(&card.tcode[4]) == card.tcode[7] >> 4);
                    PrintAndLogEx(INFO, "CRC...... %s", (crc) ?  _GREEN_("ok") : _RED_("fail"));
                }
                printed = true;
            }

            if (verbose) {
                PrintAndLogEx(INFO, "Raw....... " _YELLOW_("%s"), sprint_hex(card.tcode, 8));
                PrintAndLogEx(INFO, "Raw rev... " _YELLOW_("%s"), sprint_hex(card.rtcode, 8));
            }
            if (printed && loop) {
                PrintAndLogEx(NORMAL, "");
            }
        }

    } while (loop && kbd_enter_pressed() == false);

    return PM3_SUCCESS;
}

static int CmdHFTexkomReader(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf texkom reader",
                  "Read a texkom tag",
                  "hf texkom reader\n"
                  "hf texkom reader -@   -> continuous reader mode"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("1", NULL, "Use data from Graphbuffer"),
        arg_lit0("v",  "verbose",  "Verbose scan and output"),
        arg_lit0("@", NULL, "optional - continuous reader mode"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool gbuffer = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);
    bool cm = arg_get_lit(ctx, 3);

    CLIParserFree(ctx);

    if (cm) {
        PrintAndLogEx(INFO, "Press " _GREEN_("<Enter>") " to exit");
        return read_texkom_uid(cm, verbose);
    }

    uint32_t samplesCount = 30000;
    if (gbuffer) {
        samplesCount = g_GraphTraceLen;
    } else {
        clearCommandBuffer();
        SendCommandNG(CMD_HF_ACQ_RAW_ADC, (uint8_t *)&samplesCount, sizeof(uint32_t));

        PacketResponseNG resp;
        if (!WaitForResponseTimeout(CMD_HF_ACQ_RAW_ADC, &resp, 2500)) {
            PrintAndLogEx(WARNING, "command execution time out");
            return PM3_ETIMEOUT;
        }

        uint32_t size = (resp.data.asDwords[0]);
        if (size > 0) {
            if (getSamples(samplesCount, false) != PM3_SUCCESS) {
                PrintAndLogEx(ERR, "Get samples error");
                return PM3_EFAILED;
            };
        }
    }

    char bitstring[256] = {0};
    char cbitstring[128] = {0};
    char genbitstring[256] = {0};
    int codefound = TexkomModError;
    uint32_t sindx = 0;
    while (sindx < samplesCount - 5) {
        sindx = TexkomSearchStart(sindx, TEXKOM_NOISE_THRESHOLD);
        if (sindx == 0 || sindx > samplesCount - 5) {
            if (TexkomAVGField() > 30)
                PrintAndLogEx(WARNING, "Too noisy environment. Try to move the tag from the antenna a bit.");
            break;
        }

        uint32_t slen = TexkomSearchLength(sindx, TEXKOM_NOISE_THRESHOLD);
        if (slen == 0)
            continue;

        uint32_t maxlvl = TexkomSearchMax(sindx, 1760);
        if (maxlvl < TEXKOM_NOISE_THRESHOLD) {
            sindx += 1700;
            continue;
        }

        uint32_t noiselvl = maxlvl / 5;
        if (noiselvl < TEXKOM_NOISE_THRESHOLD)
            noiselvl = TEXKOM_NOISE_THRESHOLD;

        //PrintAndLogEx(WARNING, "--- indx: %d, len: %d, max: %d, noise: %d", sindx, slen, maxlvl, noiselvl);

        uint32_t implengths[256] = {};
        uint32_t implengthslen = 0;
        uint32_t impulseindx = 0;
        uint32_t impulsecnt = 0;
        for (uint32_t i = 0; i < slen; i++) {
            if (TexkomCorrelate(sindx + i, noiselvl)) {
                impulsecnt++;

                if (impulseindx != 0) {
                    if (implengthslen < 256)
                        implengths[implengthslen++] = sindx + i - impulseindx;
                }
                impulseindx = sindx + i;
            }
        }
        //PrintAndLogEx(WARNING, "--- impulses: %d, lenarray: %d, [%d,%d]", impulsecnt, implengthslen, implengths[0], implengths[1]);

        // check if it TK-17 modulation
        // 65 impulses and 64 intervals (1 interval = 2 bits, interval length encoding) that represents 128 bit of card code
        if (impulsecnt == 65) {
            if (TexcomTK17Decode(implengths, implengthslen, bitstring, cbitstring, verbose)) {
                codefound = TexkomModTK17;
                break;
            }
        }

        // check if it TK-13 modulation
        // it have 127 or 128 impulses and 128 double-intervals that represents 128 bit of card code
        if (impulsecnt == 127 || impulsecnt == 128) {
            if (TexcomTK13Decode(implengths, implengthslen, bitstring, cbitstring, verbose)) {
                codefound = TexkomModTK13;
                break;
            } else if (TexcomTK15Decode(implengths, implengthslen, bitstring, cbitstring, verbose)) {
                codefound = TexkomModTK15;
                break;
            }
        }

        // general decoding. it thought that there is 2 types of intervals "long" (1) and "short" (0)
        // and tries to decode sequence. shows only raw data
        if (verbose)
            TexcomGeneralDecode(implengths, implengthslen, genbitstring, verbose);
    }

    if (codefound != TexkomModError) {
        uint8_t tcode[8] = {0};
        for (uint32_t i = 0; i < strlen(cbitstring); i++) {
            tcode[i / 8] = (tcode[i / 8] << 1) | ((cbitstring[i] == '1') ? 1 : 0);
        }

        uint8_t rtcode[8] = {0};
        TexcomReverseCode(tcode, 8, rtcode);

        if (verbose) {
            PrintAndLogEx(INFO, "Hex code............ %s", sprint_hex(tcode, 8));
            PrintAndLogEx(INFO, "Hex code rev........ %s", sprint_hex(rtcode, 8));
        }

        if (tcode[0] == 0xff && tcode[1] == 0xff) {
            // decoding code

            if (verbose == false) {
                PrintAndLogEx(SUCCESS, "Texkom.............. %s", sprint_hex(tcode, 8));
                PrintAndLogEx(SUCCESS, "Texkom duplicator... %s", sprint_hex(rtcode, 8));
            }

            if (codefound == TexkomModTK13)
                PrintAndLogEx(SUCCESS, "Modulation.......... " _YELLOW_("TK13"));
            else if (codefound == TexkomModTK15)
                PrintAndLogEx(SUCCESS, "Modulation.......... " _YELLOW_("TK15"));
            else if (codefound == TexkomModTK17)
                PrintAndLogEx(SUCCESS, "Modulation.......... " _YELLOW_("TK17"));
            else
                PrintAndLogEx(INFO, "Modulation.......... " _YELLOW_("unknown"));

            if (tcode[2] == 0x63) {
                // TK13 and TK15. differs only by timings. TK15 has impulse 0 and 1 lengths very close to each other.
                if (codefound == TexkomModTK13)
                    PrintAndLogEx(SUCCESS, "Type................ " _YELLOW_("TK13"));
                else if (codefound == TexkomModTK15)
                    PrintAndLogEx(SUCCESS, "Type................ " _YELLOW_("TK15"));
                else
                    PrintAndLogEx(WARNING, "Type................ " _RED_("fail"));

                PrintAndLogEx(SUCCESS, "UID................. " _YELLOW_("%s"), sprint_hex(&tcode[3], 4));
                PrintAndLogEx(INFO, "CRC................ " NOLF);
                if (TexcomTK13CRC(&tcode[3]) == tcode[7])
                    PrintAndLogEx(NORMAL, "( " _GREEN_("ok") " )");
                else
                    PrintAndLogEx(NORMAL, "( " _RED_("fail") " )");

            } else if (tcode[2] == 0xFF && tcode[3] == 0xFF) {
                // MMBIT
                if (codefound != TexkomModTK13 && codefound != TexkomModTK15) {
                    PrintAndLogEx(WARNING, "Mod type............ " _RED_("fail"));
                }
                PrintAndLogEx(SUCCESS, "Type................ " _YELLOW_("MMBIT"));
                PrintAndLogEx(SUCCESS, "UID................. " _YELLOW_("%s"), sprint_hex(&tcode[4], 3));
                PrintAndLogEx(INFO, "CRC................ " NOLF);
                if (MMBITCRC(&tcode[4]) == tcode[7] >> 4)
                    PrintAndLogEx(NORMAL, "( " _GREEN_("ok") " )");
                else
                    PrintAndLogEx(NORMAL, "( " _RED_("fail") " )");


            } else if (tcode[2] == 0xCA) {
                // TK17
                if (codefound != TexkomModTK17) {
                    PrintAndLogEx(WARNING, "Mod type............ " _RED_("fail"));
                }
                PrintAndLogEx(SUCCESS, "Type............... " _YELLOW_("TK17"));
                PrintAndLogEx(SUCCESS, "UID................ " _YELLOW_("%s"), sprint_hex(&tcode[3], 4));
                PrintAndLogEx(INFO, "CRC................ " NOLF);
                if (TexcomTK17CRC(&tcode[3]) == tcode[7])
                    PrintAndLogEx(NORMAL, "( " _GREEN_("ok") " )");
                else
                    PrintAndLogEx(NORMAL, "( " _RED_("fail") " )");

            } else {
                PrintAndLogEx(INFO, "Type............... unknown");
                PrintAndLogEx(INFO, "UID................ %s (maybe)", sprint_hex(&tcode[3], 4));
            }
        } else {
            PrintAndLogEx(ERR, "Code have no preamble FFFF... %s", sprint_hex(tcode, 8));
        }
    } else {
        if (strlen(genbitstring) > 0)
            PrintAndLogEx(INFO, "General decoding bitstring... %s", genbitstring);
        if (strlen(bitstring) > 0)
            PrintAndLogEx(INFO, "last raw bit string [%zu].... %s", strlen(bitstring), bitstring);
        if (strlen(cbitstring) > 0)
            PrintAndLogEx(INFO, "last bit string [%zu]........ %s", strlen(cbitstring), cbitstring);

        PrintAndLogEx(ERR, "Texkom card is not found");
    }

    return PM3_SUCCESS;
}

static int CmdHFTexkomSim(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf texkom sim",
                  "Simulate a texkom tag",
                  "hf texkom sim \n"
                  "hf texkom sim --raw FFFF638C7DC45553 -> simulate TK13 tag with id 8C7DC455\n"
                  "hf texkom sim --tk17 --raw FFFFCA17F31EC512 -> simulate TK17 tag with id 17F31EC5\n"
                  "hf texkom sim --id 8C7DC455 -> simulate TK13 tag with id 8C7DC455\n"
                  "hf texkom sim --id 8C7DC455 --tk17 -> simulate TK17 tag with id 17F31EC5");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("v",  "verbose",  "Verbose work"),
        arg_lit0("t",  "tk17",     "Use TK-17 modulation (TK-13 by default)"),
        arg_str0(NULL, "raw",      "<hex 8 bytes>", "Raw data for texkom card, 8 bytes. Manual modulation select."),
        arg_str0(NULL, "id",       "<hex 4 bytes>", "Raw data for texkom card, 8 bytes. Manual modulation select."),
        arg_int0(NULL, "timeout",  "<dec, ms>", "Simulation timeout in the ms. If not specified or 0 - infinite. Command can be skipped by pressing the button"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    // <texkom data 8bytes><modulation type 1b><timeout ms 4b>
    struct p {
        uint8_t data[8];
        uint8_t modulation;
        uint32_t timeout;
    } PACKED payload = {};

    bool verbose = arg_get_lit(ctx, 1);
    payload.modulation = 0; // tk-13
    if (arg_get_lit(ctx, 2))
        payload.modulation = 1; //tk-17

    uint8_t rawdata[250] = {0};
    int rawdatalen = 0;
    CLIGetHexWithReturn(ctx, 3, rawdata, &rawdatalen);

    uint8_t iddata[250] = {0};
    int iddatalen = 0;
    CLIGetHexWithReturn(ctx, 4, iddata, &iddatalen);

    payload.timeout = arg_get_int_def(ctx, 5, 0);

    CLIParserFree(ctx);

    if (rawdatalen == 0 && iddatalen == 0) {
        PrintAndLogEx(ERR, "<raw data> or <id> must be specified to simulate");
        return PM3_EINVARG;
    }

    if (iddatalen > 0 && iddatalen != 4) {
        PrintAndLogEx(ERR, "<id> must be 4 bytes long instead of: %d", iddatalen);
        return PM3_EINVARG;
    }

    if (iddatalen == 4) {
        rawdata[0] = 0xff;
        rawdata[1] = 0xff;
        rawdata[2] = (payload.modulation == 0) ? 0x63 : 0xCA;
        memcpy(&rawdata[3], iddata, 4);
        rawdata[7] = (payload.modulation == 0) ? TexcomTK13CRC(iddata) : TexcomTK17CRC(iddata);
        rawdatalen = 8;
    }

    if (rawdatalen > 0 && rawdatalen != 8) {
        PrintAndLogEx(ERR, "<raw data> must be 8 bytes long instead of: %d", rawdatalen);
        return PM3_EINVARG;
    }

    memcpy(payload.data, rawdata, 8);

    clearCommandBuffer();
    SendCommandNG(CMD_HF_TEXKOM_SIMULATE, (uint8_t *)&payload, sizeof(payload));

    if (payload.timeout > 0 && payload.timeout < 2800) {
        PrintAndLogEx(INFO, "simulate command started");
        PacketResponseNG resp;
        if (WaitForResponseTimeout(CMD_HF_TEXKOM_SIMULATE, &resp, 3000) == false) {
            if (verbose) {
                PrintAndLogEx(WARNING, "(hf texkom simulate) command execution time out");
            }
            return PM3_ETIMEOUT;
        }
        PrintAndLogEx(INFO, "simulate command execution done");
    } else {
        PrintAndLogEx(INFO, "simulate command started...");
    }

    return PM3_SUCCESS;
}

static int CmdHelp(const char *Cmd);

static command_t CommandTable[] = {
    {"help",    CmdHelp,            AlwaysAvailable,  "This help"},
    {"reader",  CmdHFTexkomReader,  IfPm3Iso14443a,   "Act like a Texkom reader"},
    {"sim",     CmdHFTexkomSim,     IfPm3Iso14443a,   "Simulate a Texkom tag"},
    //{"write",   CmdHFTexkomWrite,   IfPm3Iso14443a,   "Write a Texkom tag"},
    {NULL,      NULL,               0, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdHFTexkom(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}
