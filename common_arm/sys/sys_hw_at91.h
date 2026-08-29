#ifndef SYS_HW_AT91_H
#define SYS_HW_AT91_H

#include "common.h"
#include "at91sam7s512.h"
#include "proxmark3_arm.h"

void mck_from_pll_to_slck(void);

void mck_from_slck_to_pll(void);

STATIC_FORCE_INLINE main_chip_type_t GetChipType(void) {
    return MAIN_CHIP_TYPE_AT91;
}

STATIC_FORCE_INLINE uint32_t GetChipId(void) {
    return *(AT91C_DBGU_CIDR);
}

STATIC_FORCE_INLINE uint8_t *GetChipUniqueId(uint8_t *size) {
    // !!! UNSUPPORTED !!!
    if (size) {
        *size = 0;
    }
    return NULL;
}

STATIC_FORCE_INLINE void ResetChip(void) {
    AT91C_BASE_RSTC->RSTC_RCR = RST_CONTROL_KEY | AT91C_RSTC_PROCRST;
}

STATIC_FORCE_INLINE uint32_t GetChipFlashSize(void) {
    uint8_t nvpsiz = (GetChipId() & 0xF00) >> 8;
    if (nvpsiz == 0) {
        return 0;
    }
    if (nvpsiz == 1) {
        return 8 * 1024;
    }
    if (nvpsiz == 2) {
        return 16 * 1024;
    }
    if (nvpsiz == 3) {
        return 32 * 1024;
    }
    if (nvpsiz == 5) {
        return 64 * 1024;
    }
    if (nvpsiz == 7) {
        return 128 * 1024;
    }
    if (nvpsiz == 9) {
        return 256 * 1024;
    }
    if (nvpsiz == 10) {
        return 512 * 1024;
    }
    if (nvpsiz == 12) {
        return 1024 * 1024;
    }
    // for 'reserved' values, guess 2MB
    return 2048 * 1024;
}

STATIC_FORCE_INLINE bool CheckRSTWithSRAMRetention(void) {
    if ((AT91C_BASE_RSTC->RSTC_RSR & AT91C_RSTC_RSTTYP) == AT91C_RSTC_RSTTYP_WATCHDOG ||
            (AT91C_BASE_RSTC->RSTC_RSR & AT91C_RSTC_RSTTYP) == AT91C_RSTC_RSTTYP_SOFTWARE ||
            (AT91C_BASE_RSTC->RSTC_RSR & AT91C_RSTC_RSTTYP) == AT91C_RSTC_RSTTYP_USER) {
        return true;
    }
    /* Otherwise, initialize it from scratch */
    return false;
}

#endif //SYS_HW_AT91_H
