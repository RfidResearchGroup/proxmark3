#ifndef CMDHFMFU_H__
#define CMDHFMFU_H__

#include <stdint.h>
#include <stdio.h>
#include "mbedtls/des.h"
#include "cmdhfmf.h"
#include "cmdhf14a.h"
#include "mifare.h"
#include "util.h"
#include "protocols.h"
#include "comms.h"
#include "loclass/fileutils.h"


// Old Ultralight/NTAG dump file format
// It is used only for converting
#define OLD_MFU_DUMP_PREFIX_LENGTH 48

typedef struct {
    uint8_t version[8];
    uint8_t tbo[2];
    uint8_t tearing[3];
    uint8_t pack[2];
    uint8_t tbo1[1];
    uint8_t signature[32];
    //uint8_t counter[3];
    uint8_t data[1024];
} old_mfu_dump_t;


uint32_t GetHF14AMfU_Type(void);
int ul_print_type(uint32_t tagtype, uint8_t spaces);

void printMFUdump(mfu_dump_t *card);
void printMFUdumpEx(mfu_dump_t *card, uint16_t pages, uint8_t startpage);

int CmdHFMFUltra(const char *Cmd);

uint32_t ul_ev1_pwdgenA(uint8_t *uid);
uint32_t ul_ev1_pwdgenA(uint8_t *uid);
uint32_t ul_ev1_pwdgenC(uint8_t *uid);
uint32_t ul_ev1_pwdgenD(uint8_t *uid);

uint16_t ul_ev1_packgenA(uint8_t *uid);
uint16_t ul_ev1_packgenB(uint8_t *uid);
uint16_t ul_ev1_packgenC(uint8_t *uid);
uint16_t ul_ev1_packgenD(uint8_t *uid);
uint16_t ul_ev1_packgen_VCNEW(uint8_t *uid, uint32_t pwd);

uint32_t ul_ev1_otpgenA(uint8_t *uid);

typedef enum TAGTYPE_UL {
    UNKNOWN          = 0x000000,
    UL               = 0x1,
    UL_C             = 0x2,
    UL_EV1_48        = 0x4,
    UL_EV1_128       = 0x8,
    NTAG             = 0x10,
    NTAG_203         = 0x20,
    NTAG_210         = 0x40,
    NTAG_212         = 0x80,
    NTAG_213         = 0x100,
    NTAG_215         = 0x200,
    NTAG_216         = 0x400,
    MY_D             = 0x800,
    MY_D_NFC         = 0x1000,
    MY_D_MOVE        = 0x2000,
    MY_D_MOVE_NFC    = 0x4000,
    MY_D_MOVE_LEAN   = 0x8000,
    NTAG_I2C_1K      = 0x10000,
    NTAG_I2C_2K      = 0x20000,
    NTAG_I2C_1K_PLUS = 0x40000,
    NTAG_I2C_2K_PLUS = 0x80000,
    FUDAN_UL         = 0x100000,
    MAGIC            = 0x200000,
    NTAG_213_F       = 0x400000,
    NTAG_216_F       = 0x800000,
    UL_EV1           = 0x1000000,
    UL_NANO_40       = 0x2000000,
    UL_MAGIC         = UL | MAGIC,
    UL_C_MAGIC       = UL_C | MAGIC,
    UL_ERROR         = 0xFFFFFF,
} TagTypeUL_t;

#endif
