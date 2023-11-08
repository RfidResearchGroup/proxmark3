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
// Low frequency T55xx commands
//-----------------------------------------------------------------------------

#ifndef CMDLFT55XX_H__
#define CMDLFT55XX_H__

#include "common.h"

#define T55x7_CONFIGURATION_BLOCK       0x00
#define T55x7_PWD_BLOCK                 0x07
#define T55x7_TRACE_BLOCK1              0x01
#define T55x7_TRACE_BLOCK2              0x02
#define T55x7_PAGE0                     0x00
#define T55x7_PAGE1                     0x01
#define T55x7_PWD                       0x00000010
#define REGULAR_READ_MODE_BLOCK         0xFF
#define T55x7_BLOCK_COUNT               12

// config blocks
#define T55X7_DEFAULT_CONFIG_BLOCK      0x000880E8  // ASK, compat mode, data rate 32, manchester, STT, 7 data blocks
#define T55X7_RAW_CONFIG_BLOCK          0x000880E0  // ASK, compat mode, data rate 32, manchester, 7 data blocks
#define T55X7_EM_UNIQUE_CONFIG_BLOCK    0x00148040  // ASK, EM4x02/unique - compat mode, manchester, data rate 64, 2 data blocks
#define T55X7_EM_PAXTON_CONFIG_BLOCK    0x00148040  // ASK, EM4x02/paxton - compat mode, manchester, data rate 64, 2 data blocks
#define T55X7_VISA2000_CONFIG_BLOCK     0x00148068  // ASK, data rate 64, 3 data blocks, STT
#define T55X7_VIKING_CONFIG_BLOCK       0x00088040  // ASK, compat mode, data rate 32, Manchester, 2 data blocks
#define T55X7_NORALSY_CONFIG_BLOCK      0x00088C6A  // ASK, compat mode,   (NORALSY - KCP3000), data rate 32, 3 data blocks
#define T55X7_PRESCO_CONFIG_BLOCK       0x00088088  // ASK, data rate 32, Manchester, 4 data blocks, STT
#define T55X7_SECURAKEY_CONFIG_BLOCK    0x000C8060  // ASK, Manchester, data rate 40, 3 data blocks
#define T55X7_UNK_CONFIG_BLOCK          0x000880FA  // ASK, Manchester, data rate 32, 7 data blocks STT, Inverse ...

// FDXB requires data inversion and BiPhase 57 is simply BiPhase 50 inverted, so we can either do it using the modulation scheme or the inversion flag
// we've done both below to prove that it works either way, and the modulation value for BiPhase 50 in the Atmel data sheet of binary "10001" (17) is a typo,
// and it should actually be "10000" (16)
// #define T55X7_FDXB_CONFIG_BLOCK        0x903F8080  // BiPhase, fdx-b - xtended mode, BiPhase ('57), data rate 32, 4 data blocks
#define T55X7_FDXB_CONFIG_BLOCK         0x903F0082  // BiPhase, fdx-b - xtended mode, BiPhase ('50), invert data, data rate 32, 4 data blocks
#define T55X7_FDXB_2_CONFIG_BLOCK       0x00098080  //

#define T55X7_HID_26_CONFIG_BLOCK       0x00107060  // FSK2a, hid 26 bit - compat mode, data rate 50, 3 data blocks
#define T55X7_PARADOX_CONFIG_BLOCK      0x00107060  // FSK2a, hid 26 bit - compat mode, data rate 50, 3 data blocks
#define T55X7_AWID_CONFIG_BLOCK         0x00107060  // FSK2a, hid 26 bit - compat mode, data rate 50, 3 data blocks
#define T55X7_PYRAMID_CONFIG_BLOCK      0x00107080  // FSK2a, Pyramid 26 bit - compat mode, data rate 50, 4 data blocks
#define T55X7_IOPROX_CONFIG_BLOCK       0x00147040  // FSK2a, data rate 64, 2 data blocks

#define T55X7_INDALA_64_CONFIG_BLOCK    0x00081040  // PSK1, indala 64 bit - compat mode, psk carrier FC * 2, data rate 32, maxblock 2
#define T55X7_INDALA_224_CONFIG_BLOCK   0x000810E0  // PSK1, indala 224 bit - compat mode, psk carrier FC * 2, data rate 32, maxblock 7
#define T55X7_MOTOROLA_CONFIG_BLOCK     0x00081040  // PSK1, data rate 32, 2 data blocks
#define T55X7_NEXWATCH_CONFIG_BLOCK     0x00081060  // PSK1 data rate 16, psk carrier FC * 2, 3 data blocks
#define T55X7_KERI_CONFIG_BLOCK         0x603E1040  // PSK1, 2 data blocks
#define T55X7_IDTECK_CONFIG_BLOCK       0x00081040  // PSK1, data rate 32, 2 data blocks

#define T55X7_JABLOTRON_CONFIG_BLOCK    0x00158040  // Biphase, data rate 64, 2 data blocks
#define T55X7_GUARDPROXII_CONFIG_BLOCK  0x00150060  // Biphase, data rate 64, Direct modulation, 3 data blocks
#define T55X7_NEDAP_64_CONFIG_BLOCK     0x907f0042  // BiPhase, data rate 64, 2 data blocks
#define T55X7_NEDAP_128_CONFIG_BLOCK    0x907f0082  // BiPhase, data rate 64, 4 data blocks

#define T55X7_PAC_CONFIG_BLOCK          0x00080080  // NRZ, data rate 32, 4 data blocks
#define T55X7_VERICHIP_CONFIG_BLOCK     0x000C0080  // NRZ, data rate 40, 4 data blocks

#define T55X7_bin 0b0010

// Q5 / Termic / T5555
#define T5555_DEFAULT_CONFIG_BLOCK      0x6001F004  // ASK, data rate 64, manchester, 2 data blocks?

typedef enum {
    T55x7_RAW = 0x00,
    T55x7_DEFAULT = 0x00,
    T5555_DEFAULT = 0x01,
    EM_UNIQUE  = 0x0,
    FDBX = 0x02,
    HID_26 = 0x03,
    INDALA_64 = 0x04,
    INDALA_224 = 0x05,
    GUARDPROXXII = 0x06,
    VIKING = 0x07,
    NORALSYS = 0x08,
    IOPROX = 0x09,
    NEDAP_64 = 0x0A,
    NEDAP_128 = 0x0B,
} t55xx_tag;

typedef struct {
    uint32_t bl1;
    uint32_t bl2;
    uint32_t acl;
    uint32_t mfc;
    uint32_t cid;
    uint32_t year;
    uint32_t quarter;
    uint32_t icr;
    uint32_t lotid;
    uint32_t wafer;
    uint32_t dw;
} t55x7_tracedata_t;

typedef struct {
    uint32_t bl1;
    uint32_t bl2;
    uint32_t icr;
    char lotidc;
    uint32_t lotid;
    uint32_t wafer;
    uint32_t dw;
} t5555_tracedata_t;

typedef enum {
    DEMOD_NRZ  = 0x00,
    DEMOD_PSK1 = 0x01,
    DEMOD_PSK2 = 0x02,
    DEMOD_PSK3 = 0x03,
    DEMOD_FSK1 = 0x04,
    DEMOD_FSK2 = 0x05,
    DEMOD_FSK1a = 0x06,
    DEMOD_FSK2a = 0x07,
    DEMOD_FSK   = 0xF0, //generic FSK (auto detect FCs)
    DEMOD_ASK  = 0x08,
    DEMOD_BI   = 0x10,
    DEMOD_BIa  = 0x18,
} t55xx_modulation;

typedef struct {
    t55xx_modulation modulation;
    bool inverted;
    uint8_t offset;
    uint32_t block0;
    enum {
        NOTSET     = 0x00,
        AUTODETECT = 0x01,
        USERSET    = 0x02,
        TAGREAD    = 0x03,
    } block0Status;
    enum {
        RF_8 = 0x00,
        RF_16 = 0x01,
        RF_32 = 0x02,
        RF_40 = 0x03,
        RF_50 = 0x04,
        RF_64 = 0x05,
        RF_100 = 0x06,
        RF_128 = 0x07,
    } bitrate;
    bool Q5;
    bool ST;
    bool usepwd;
    uint32_t pwd;
    enum {
        refFixedBit = 0x00,
        refLongLeading = 0x01,
        refLeading0 = 0x02,
        ref1of4 = 0x03,
    } downlink_mode;
} t55xx_conf_block_t;

typedef struct {
    uint32_t blockdata;
    bool valid;
}  t55xx_memory_item_t;

t55xx_conf_block_t Get_t55xx_Config(void);
void Set_t55xx_Config(t55xx_conf_block_t conf);

int CmdLFT55XX(const char *Cmd);

void SetConfigWithBlock0(uint32_t block0);
void SetConfigWithBlock0Ex(uint32_t block0, uint8_t offset, bool Q5);

char *GetPskCfStr(uint32_t id, bool q5);
char *GetBitRateStr(uint32_t id, bool xmode);
char *GetSaferStr(uint32_t id);
char *GetQ5ModulationStr(uint32_t id);
char *GetModulationStr(uint32_t id, bool xmode);
char *GetModelStrFromCID(uint32_t cid);
char *GetConfigBlock0Source(uint8_t id);
char *GetSelectedModulationStr(uint8_t id);
char *GetDownlinkModeStr(uint8_t downlink_mode);
void printT5xxHeader(uint8_t page);
void printT55xxBlock(uint8_t blockNum, bool page1);
int  printConfiguration(t55xx_conf_block_t b);

bool t55xxAcquireAndCompareBlock0(bool usepwd, uint32_t password, uint32_t known_block0, bool verbose);
bool t55xxAcquireAndDetect(bool usepwd, uint32_t password, uint32_t known_block0, bool verbose);
bool t55xxVerifyWrite(uint8_t block, bool page1, bool usepwd, uint8_t override, uint32_t password, uint8_t downlink_mode, uint32_t data);
int T55xxReadBlock(uint8_t block, bool page1, bool usepwd, uint8_t override, uint32_t password, uint8_t downlink_mode);
int T55xxReadBlockEx(uint8_t block, bool page1, bool usepwd, uint8_t override, uint32_t password, uint8_t downlink_mode, bool verbose);

int t55xxWrite(uint8_t block, bool page1, bool usepwd, bool testMode, uint32_t password, uint8_t downlink_mode, uint32_t data);

bool GetT55xxBlockData(uint32_t *blockdata);
bool DecodeT55xxBlock(void);
bool t55xxTryDetectModulation(uint8_t downlink_mode, bool print_config);
//bool t55xxTryDetectModulationEx(uint8_t downlink_mode, bool print_config, uint32_t wanted_conf);
bool t55xxTryDetectModulationEx(uint8_t downlink_mode, bool print_config, uint32_t wanted_conf, uint64_t pwd);
bool testKnownConfigBlock(uint32_t block0);

bool tryDetectP1(bool getData);
bool test(uint8_t mode, uint8_t *offset, int *fndBitRate, uint8_t clk, bool *Q5);
int  CmdT55xxSpecial(const char *Cmd);
bool AcquireData(uint8_t page, uint8_t block, bool pwdmode, uint32_t password, uint8_t downlink_mode);
uint8_t t55xx_try_one_password(uint32_t password, uint8_t downlink_mode, bool try_all_dl_modes);

void printT55x7Trace(t55x7_tracedata_t data, uint8_t repeat);
void printT5555Trace(t5555_tracedata_t data, uint8_t repeat);

int clone_t55xx_tag(uint32_t *blockdata, uint8_t numblocks);
#endif
