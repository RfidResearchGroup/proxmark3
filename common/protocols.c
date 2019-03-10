#include "protocols.h"

// ATA55xx shared presets & routines
uint32_t GetT55xxClockBit(uint32_t clock) {
    switch (clock) {
        case 128:
            return T55x7_BITRATE_RF_128;
        case 100:
            return T55x7_BITRATE_RF_100;
        case  64:
            return T55x7_BITRATE_RF_64;
        case  50:
            return T55x7_BITRATE_RF_50;
        case  40:
            return T55x7_BITRATE_RF_40;
        case  32:
            return T55x7_BITRATE_RF_32;
        case  16:
            return T55x7_BITRATE_RF_16;
        case   8:
            return T55x7_BITRATE_RF_8;
        default :
            return 0;
    }
}

#ifndef ON_DEVICE
#include "ui.h"
#define PrintAndLogDevice(level, format, args...)  PrintAndLogEx(level, format , ## args)

uint8_t isset(uint8_t val, uint8_t mask) {
    return (val & mask);
}

uint8_t notset(uint8_t val, uint8_t mask) {
    return !(val & mask);
}

void fuse_config(const picopass_hdr *hdr) {
    uint8_t fuses = hdr->conf.fuses;

    if (isset(fuses, FUSE_FPERS))
        PrintAndLogDevice(SUCCESS, "\tMode: Personalization [Programmable]");
    else
        PrintAndLogDevice(NORMAL, "\tMode: Application [Locked]");

    if (isset(fuses, FUSE_CODING1)) {
        PrintAndLogDevice(NORMAL, "\tCoding: RFU");
    } else {
        if (isset(fuses, FUSE_CODING0))
            PrintAndLogDevice(NORMAL, "\tCoding: ISO 14443-2 B/ISO 15693");
        else
            PrintAndLogDevice(NORMAL, "\tCoding: ISO 14443B only");
    }
    // 1 1
    if (isset(fuses, FUSE_CRYPT1) && isset(fuses, FUSE_CRYPT0)) PrintAndLogDevice(SUCCESS, "\tCrypt: Secured page, keys not locked");
    // 1 0
    if (isset(fuses, FUSE_CRYPT1) && notset(fuses, FUSE_CRYPT0)) PrintAndLogDevice(NORMAL, "\tCrypt: Secured page, keys locked");
    // 0 1
    if (notset(fuses, FUSE_CRYPT1) && isset(fuses, FUSE_CRYPT0)) PrintAndLogDevice(SUCCESS, "\tCrypt: Non secured page");
    // 0 0
    if (notset(fuses, FUSE_CRYPT1) && notset(fuses, FUSE_CRYPT0)) PrintAndLogDevice(NORMAL, "\tCrypt: No auth possible. Read only if RA is enabled");

    if (isset(fuses, FUSE_RA))
        PrintAndLogDevice(NORMAL, "\tRA: Read access enabled");
    else
        PrintAndLogDevice(WARNING, "\tRA: Read access not enabled");
}

void getMemConfig(uint8_t mem_cfg, uint8_t chip_cfg, uint8_t *max_blk, uint8_t *app_areas, uint8_t *kb) {
    // mem-bit 5, mem-bit 7, chip-bit 4: defines chip type
    uint8_t k16 = isset(mem_cfg, 0x80);
    //uint8_t k2 = isset(mem_cfg, 0x08);
    uint8_t book = isset(mem_cfg, 0x20);

    if (isset(chip_cfg, 0x10) && !k16 && !book) {
        *kb = 2;
        *app_areas = 2;
        *max_blk = 31;
    } else if (isset(chip_cfg, 0x10) && k16 && !book) {
        *kb = 16;
        *app_areas = 2;
        *max_blk = 255; //16kb
    } else if (notset(chip_cfg, 0x10) && !k16 && !book) {
        *kb = 16;
        *app_areas = 16;
        *max_blk = 255; //16kb
    } else if (isset(chip_cfg, 0x10) && k16 && book) {
        *kb = 32;
        *app_areas = 3;
        *max_blk = 255; //16kb
    } else if (notset(chip_cfg, 0x10) && !k16 && book) {
        *kb = 32;
        *app_areas = 17;
        *max_blk = 255; //16kb
    } else {
        *kb = 32;
        *app_areas = 2;
        *max_blk = 255;
    }
}

void mem_app_config(const picopass_hdr *hdr) {
    uint8_t mem = hdr->conf.mem_config;
    uint8_t chip = hdr->conf.chip_config;
    uint8_t applimit = hdr->conf.app_limit;
    uint8_t kb = 2;
    uint8_t app_areas = 2;
    uint8_t max_blk = 31;

    getMemConfig(mem, chip, &max_blk, &app_areas, &kb);

    if (applimit < 6) applimit = 26;
    if (kb == 2 && (applimit > 0x1f)) applimit = 26;

    PrintAndLogDevice(NORMAL, " Mem: %u KBits/%u App Areas (%u * 8 bytes) [%02X]", kb, app_areas, max_blk, mem);
    PrintAndLogDevice(NORMAL, "\tAA1: blocks 06-%02X", applimit);
    PrintAndLogDevice(NORMAL, "\tAA2: blocks %02X-%02X", applimit + 1, max_blk);
    PrintAndLogDevice(NORMAL, "\tOTP: 0x%02X%02X", hdr->conf.otp[1],  hdr->conf.otp[0]);
    PrintAndLogDevice(NORMAL, "\nKeyAccess:");

    uint8_t book = isset(mem, 0x20);
    if (book) {
        PrintAndLogDevice(NORMAL, "\tRead A - Kd");
        PrintAndLogDevice(NORMAL, "\tRead B - Kc");
        PrintAndLogDevice(NORMAL, "\tWrite A - Kd");
        PrintAndLogDevice(NORMAL, "\tWrite B - Kc");
        PrintAndLogDevice(NORMAL, "\tDebit  - Kd or Kc");
        PrintAndLogDevice(NORMAL, "\tCredit - Kc");
    } else {
        PrintAndLogDevice(NORMAL, "\tRead A - Kd or Kc");
        PrintAndLogDevice(NORMAL, "\tRead B - Kd or Kc");
        PrintAndLogDevice(NORMAL, "\tWrite A - Kc");
        PrintAndLogDevice(NORMAL, "\tWrite B - Kc");
        PrintAndLogDevice(NORMAL, "\tDebit  - Kd or Kc");
        PrintAndLogDevice(NORMAL, "\tCredit - Kc");
    }
}
void print_picopass_info(const picopass_hdr *hdr) {
    fuse_config(hdr);
    mem_app_config(hdr);
}
void printIclassDumpInfo(uint8_t *iclass_dump) {
    print_picopass_info((picopass_hdr *) iclass_dump);
}

#else
#define PrintAndLogDevice(level, format, ...) { }
#endif
//ON_DEVICE
