//-----------------------------------------------------------------------------
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency T55xx commands
//-----------------------------------------------------------------------------

#ifndef CMDLFT55XX_H__
#define CMDLFT55XX_H__

#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <time.h>
#include <ctype.h>
#include "proxmark3.h"
#include "ui.h"
#include "graph.h"
#include "comms.h"
#include "cmdparser.h"
#include "cmddata.h"
#include "cmdlf.h"
#include "util.h"
#include "lfdemod.h"
#include "cmdhf14a.h"   // for getTagInfo
#include "loclass/fileutils.h"  // loadDictionary


#define T55x7_CONFIGURATION_BLOCK 0x00
#define T55x7_TRACE_BLOCK1 0x01
#define T55x7_TRACE_BLOCK2 0x02
#define T55x7_PAGE0 0x00
#define T55x7_PAGE1 0x01
#define T55x7_PWD 0x00000010
#define REGULAR_READ_MODE_BLOCK 0xFF

// config blocks
#define T55X7_DEFAULT_CONFIG_BLOCK      0x000880E8  // ASK, compat mode, data rate 32, manchester, STT, 7 data blocks
#define T55X7_RAW_CONFIG_BLOCK          0x000880E0  // ASK, compat mode, data rate 32, manchester, 7 data blocks
#define T55X7_EM_UNIQUE_CONFIG_BLOCK    0x00148040  // ASK, emulate em4x02/unique - compat mode, manchester, data rate 64, 2 data blocks
#define T55X7_EM_PAXTON_CONFIG_BLOCK    0x00148040  // ASK, emulate em4x02/paxton - compat mode, manchester, data rate 64, 2 data blocks
// FDXB requires data inversion and BiPhase 57 is simply BiPhase 50 inverted, so we can either do it using the modulation scheme or the inversion flag
// we've done both below to prove that it works either way, and the modulation value for BiPhase 50 in the Atmel data sheet of binary "10001" (17) is a typo,
// and it should actually be "10000" (16)
// #define T55X7_FDXB_CONFIG_BLOCK        0x903F8080  // emulate fdx-b - xtended mode, BiPhase ('57), data rate 32, 4 data blocks
#define T55X7_FDXB_CONFIG_BLOCK         0x903F0082  // emulate fdx-b - xtended mode, BiPhase ('50), invert data, data rate 32, 4 data blocks
#define T55X7_HID_26_CONFIG_BLOCK       0x00107060  // hid 26 bit - compat mode, FSK2a, data rate 50, 3 data blocks
#define T55X7_PYRAMID_CONFIG_BLOCK      0x00107080  // Pyramid 26 bit - compat mode, FSK2a, data rate 50, 4 data blocks
#define T55X7_INDALA_64_CONFIG_BLOCK    0x00081040  // emulate indala 64 bit - compat mode, PSK1, psk carrier FC * 2, data rate 32, maxblock 2
#define T55X7_INDALA_224_CONFIG_BLOCK   0x000810E0  // emulate indala 224 bit - compat mode, PSK1, psk carrier FC * 2, data rate 32, maxblock 7
#define T55X7_GUARDPROXII_CONFIG_BLOCK  0x00150060  // bitrate 64pcb, Direct modulation, Biphase, 3 data blocks
#define T55X7_VIKING_CONFIG_BLOCK       0x00088040  // ASK, compat mode, data rate 32, Manchester, 2 data blocks
#define T55X7_NORALYS_CONFIG_BLOCK      0x00088C6A  // ASK, compat mode,   (NORALYS - KCP3000)
#define T55X7_IOPROX_CONFIG_BLOCK       0x00147040  // ioprox - FSK2a, data rate 64, 2 data blocks
#define T55X7_PRESCO_CONFIG_BLOCK       0x00088088  // ASK, data rate 32, Manchester, 5 data blocks, STT
#define T55X7_NEDAP_64_CONFIG_BLOCK     0x907f0042  // BiPhase,  data rate 64, 3 data blocks
#define T55X7_NEDAP_128_CONFIG_BLOCK    0x907f0082  // BiPhase,  data rate 64, 5 data blocks

#define T55X7_bin 0b0010

#define T5555_DEFAULT_CONFIG_BLOCK      0x6001F004  // data rate 64 , ask, manchester, 2 data blocks?
enum {
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

typedef struct {
    enum {
        DEMOD_NRZ  = 0x00,
        DEMOD_PSK1 = 0x01,
        DEMOD_PSK2 = 0x02,
        DEMOD_PSK3 = 0x03,
        DEMOD_FSK1  = 0x04,
        DEMOD_FSK1a = 0x05,
        DEMOD_FSK2  = 0x06,
        DEMOD_FSK2a = 0x07,
        DEMOD_FSK   = 0xF0, //generic FSK (auto detect FCs)
        DEMOD_ASK  = 0x08,
        DEMOD_BI   = 0x10,
        DEMOD_BIa  = 0x18,
    }  modulation;
    bool inverted;
    uint8_t offset;
    uint32_t block0;
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
} t55xx_conf_block_t;

t55xx_conf_block_t Get_t55xx_Config(void);
void Set_t55xx_Config(t55xx_conf_block_t conf);

extern int CmdLFT55XX(const char *Cmd);
extern int CmdT55xxChk(const char *Cmd);
extern int CmdT55xxBruteForce(const char *Cmd);
extern int CmdT55xxSetConfig(const char *Cmd);
extern int CmdT55xxReadBlock(const char *Cmd);
extern int CmdT55xxWriteBlock(const char *Cmd);
extern int CmdT55xxReadTrace(const char *Cmd);
extern int CmdT55xxInfo(const char *Cmd);
extern int CmdT55xxDetect(const char *Cmd);
extern int CmdResetRead(const char *Cmd);
extern int CmdT55xxWipe(const char *Cmd);

char *GetPskCfStr(uint32_t id, bool q5);
char *GetBitRateStr(uint32_t id, bool xmode);
char *GetSaferStr(uint32_t id);
char *GetQ5ModulationStr(uint32_t id);
char *GetModulationStr(uint32_t id, bool xmode);
char *GetModelStrFromCID(uint32_t cid);
char *GetSelectedModulationStr(uint8_t id);
uint32_t PackBits(uint8_t start, uint8_t len, uint8_t *bitstream);
void printT5xxHeader(uint8_t page);
void printT55xxBlock(const char *demodStr);
int printConfiguration(t55xx_conf_block_t b);

bool DecodeT55xxBlock(void);
bool tryDetectModulation(void);
bool testKnownConfigBlock(uint32_t block0);
extern bool tryDetectP1(bool getData);
bool test(uint8_t mode, uint8_t *offset, int *fndBitRate, uint8_t clk, bool *Q5);
int special(const char *Cmd);
bool AquireData(uint8_t page, uint8_t block, bool pwdmode, uint32_t password);

int tryOnePassword(uint32_t password);

void printT55x7Trace(t55x7_tracedata_t data, uint8_t repeat);
void printT5555Trace(t5555_tracedata_t data, uint8_t repeat);

#endif
