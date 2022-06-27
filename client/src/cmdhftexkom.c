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

inline uint32_t GetGraphBuffer(uint32_t indx) {
    if (g_GraphBuffer[indx] < -128)
        return 0;
    else
        return g_GraphBuffer[indx] + 128;
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

static bool TexkomCalculateMaxMin(uint32_t* data, uint32_t len, uint32_t* dmax, uint32_t* dmin) {
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

static bool TexkomCalculateBitLengths(uint32_t* data, uint32_t len, uint32_t* hi, uint32_t* low, uint32_t* lmax, uint32_t* lmin) {
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
PrintAndLogEx(WARNING, "--- min: %d, middle: %d, max: %d", dmin, dmiddle, dmax);

    *hi = sumhi / lenhi;
    *low = sumlow / lenlow;

    if (lmax != NULL)
        *lmax = dmax;
    if (lmin != NULL)
        *lmin = dmin;

    return (*hi != 0) && (*low != 0) && (*hi > *low);
}

inline bool TexcomCalculateBit(uint32_t data, uint32_t bitlen, uint32_t threshold) {
    return 
        (data < (bitlen + threshold)) && 
        (data > (bitlen - threshold));
}

// code from https://github.com/li0ard/crclib/blob/main/index.js
static uint8_t TexcomTK13CRC(uint8_t* data) {
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

static unsigned char dallas_crc8(const unsigned char * data, const unsigned int size)
{
    unsigned char crc = 0;
    for ( unsigned int i = 0; i < size; ++i )
    {
        unsigned char inbyte = data[i];
        for ( unsigned char j = 0; j < 8; ++j )
        {
            unsigned char mix = (crc ^ inbyte) & 0x01;
            crc >>= 1;
            if ( mix ) crc ^= 0x8C;
            inbyte >>= 1;
        }
    }
    return crc;
}

// code from https://github.com/li0ard/crclib/blob/main/index.js
static uint8_t TexcomTK17CRC(uint8_t* data) {
    uint8_t ddata[8] = {0x00, 0x00, 0x00, data[0], data[1], data[2], data[3], 0x00};

/*
	dallas (arrby) {
		var arrby2 = [];
		if (arrby.length < 8) {
			return "FF";
		}
		var n = 0;
		var n2 = 7;
		while (n < 7){
			arrby2[n] = arrby[n2];
			++n;
			--n2;
		}
		var n3 = 0;
		var n4 = 0;
		do {
			var n5 = 255 & arrby2[n3];
			var n6 = n4;
			for (var n7 = 0; n7 < 8; n7 = Number(n7 + 1)) {
				var n8 = 1 & (255 & (n6 ^ n5));
				n6 = 255 & n6 >> 1;
				n5 = 255 & n5 >> 1;
				if (n8 != 1) continue;
				n6 ^= 140;
			}
			if ((n3 = Number(n3 + 1)) >= 7) {
				return n6.toString(16).toUpperCase();
			}
			n4 = n6;
		} while (true);
	}
	tk17(arrby) {
		if(arrby.length < 8) {
			return "FF"
		}
		return this.dallas( [0x00, arrby[1], arrby[2], arrby[3], arrby[4], 0x00, 0x00, 0x00] )
	}
*/

    return dallas_crc8(ddata, 8);
}


static int CmdHFTexkomReader(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf texkom reader",
                  "Read a texkom tag",
                  "hf texkom reader");

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool verbose = true;

    CLIParserFree(ctx);

    uint32_t samplesCount = 30000;
    clearCommandBuffer();
    SendCommandNG(CMD_HF_ACQ_RAW_ADC, (uint8_t *)&samplesCount, sizeof(uint32_t));

    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_HF_ACQ_RAW_ADC, &resp, 2500)) {
        PrintAndLogEx(WARNING, "(hf texkom reader) command execution time out");
        return PM3_ETIMEOUT;
    }

    uint32_t size = (resp.data.asDwords[0]);
    if (size > 0) {
        if (getSamples(samplesCount, true) != PM3_SUCCESS) {
            PrintAndLogEx(ERR, "Get samples error");
            return PM3_EFAILED;
        };
    }

    char bitstring[256] = {0};
    char cbitstring[128] = {0};
    bool codefound = false;
    uint32_t sindx = 0;
    while (sindx < samplesCount - 5) {
        sindx = TexkomSearchStart(sindx, TEXKOM_NOISE_THRESHOLD);
        if (sindx == 0 || sindx > samplesCount - 5)
            break;

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

        PrintAndLogEx(WARNING, "--- indx: %d, len: %d, max: %d, noise: %d", sindx, slen, maxlvl, noiselvl);
      
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
        PrintAndLogEx(WARNING, "--- impulses: %d, lenarray: %d, [%d,%d]", impulsecnt, implengthslen, implengths[0], implengths[1]);

        uint32_t hilength = 0;
        uint32_t lowlength = 0;
        uint32_t lenmax = 0;
        uint32_t lenmin = 0;
        if (!TexkomCalculateBitLengths(implengths, implengthslen, &hilength, &lowlength, &lenmax, &lenmin))
            continue;

        uint32_t threshold = (hilength - lowlength) / 3 + 1;
        PrintAndLogEx(WARNING, "--- hi: %d, low: %d, threshold: %d", hilength, lowlength, threshold);

        bitstring[0] = 0;
        bool biterror = false;
        for (uint32_t i = 0; i < implengthslen; i++) {
            if (TexcomCalculateBit(implengths[i], hilength, MAX(threshold, lenmax - hilength)))
                strcat(bitstring, "1");
            else if (TexcomCalculateBit(implengths[i], lowlength, threshold))
                strcat(bitstring, "0");
            else {
                biterror = true;
                break;
            }
        }

        if (biterror || strlen(bitstring) == 0)
            continue;

        if (verbose)
            PrintAndLogEx(INFO, "raw bit string [%d]: %s", strlen(bitstring), bitstring);

        // add trailing impulse (some tags just ignore it)
        if (strlen(bitstring) % 2 != 0) {
            if (bitstring[strlen(bitstring) - 1] == '1')            
                strcat(bitstring, "0");
            else
                strcat(bitstring, "1");
        }
        PrintAndLogEx(INFO, "bs [%d]: %s", strlen(bitstring), bitstring);

        cbitstring[0] = 0;
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
            continue;

        if (verbose)
            PrintAndLogEx(INFO, "bit string [%d]: %s", strlen(cbitstring), cbitstring);

        if (strlen(cbitstring) != 64)
            continue;

        uint8_t tcode[8] = {0};
        for (uint32_t i = 0; i < strlen(cbitstring); i++) {
            tcode[i / 8] = (tcode[i / 8] << 1) | ((cbitstring[i] == '1') ? 1 : 0);
        }

        if (verbose)
            PrintAndLogEx(INFO, "Hex code: %s", sprint_hex(tcode, 8));

        if (tcode[0] != 0xff || tcode[1] != 0xff)
            continue;

        // decoding code

        if (!verbose)
            PrintAndLogEx(INFO, "Texkom: %s", sprint_hex(tcode, 8));

        if (tcode[2] == 0x63) {
            // TK13
            PrintAndLogEx(INFO, "type: TK13");
            PrintAndLogEx(INFO, "uid : %s", sprint_hex(&tcode[3], 4));

            if (TexcomTK13CRC(&tcode[3]) == tcode[7])
                PrintAndLogEx(INFO, "crc : OK");
            else
                PrintAndLogEx(WARNING, "crc : WRONG");

        } else if (tcode[2] == 0xca) {
            // TK17
            PrintAndLogEx(INFO, "type: TK17");
            PrintAndLogEx(INFO, "uid : %s", sprint_hex(&tcode[3], 4));

            if (TexcomTK17CRC(&tcode[3]) == tcode[7])
                PrintAndLogEx(INFO, "crc : OK");
            else
                PrintAndLogEx(WARNING, "crc : WRONG");

        } else {
            PrintAndLogEx(INFO, "type: unknown");
            PrintAndLogEx(INFO, "uid : %s (maybe)", sprint_hex(&tcode[3], 4));
        }

        
        codefound = true;
        break;
    }

    if (!codefound) {
        if (strlen(bitstring) > 0)
            PrintAndLogEx(INFO, "last raw bit string [%d]: %s", strlen(bitstring), bitstring);
        if (strlen(cbitstring) > 0)
            PrintAndLogEx(INFO, "last bit string [%d]: %s", strlen(cbitstring), cbitstring);

        PrintAndLogEx(ERR, "Texkom card is not found");
    }

    return PM3_SUCCESS;
}


static int CmdHelp(const char *Cmd);

static command_t CommandTable[] = {
    {"help",    CmdHelp,            AlwaysAvailable,  "This help"},
    {"reader",  CmdHFTexkomReader,  IfPm3Iso14443a,   "Act like a Texkom reader"},
    //{"sim",     CmdHFTexkomSim,     IfPm3Iso14443a,   "Simulate a Texkom tag"},
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
