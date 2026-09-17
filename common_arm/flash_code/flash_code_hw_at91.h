//
// Created by dxl on 2026/5/25.
//

#ifndef FLASH_CODE_HW_AT91_H
#define FLASH_CODE_HW_AT91_H

#include "flash_code_apis.h"
#include "proxmark3_arm.h"
#include "at91sam7s512.h"
#include "sys_apis.h"


STATIC_FORCE_INLINE uint16_t FlashCodeGetEWMinUnit(void) {
    // The page size of the chip used by pm3 is only 256 bytes.
    // No 128/64 byte page size.
    // If a pm3 device really uses such a small capacity chip, remember to add this compatibility support.
    return AT91C_IFLASH_PAGE_SIZE;
}

STATIC_FORCE_INLINE void FlashCodeInit(void) {
    // Set the first 256KB memory flashspeed
    AT91C_BASE_EFC0->EFC_FMR = AT91C_MC_FWS_1FWS | MC_FLASH_MODE_MASTER_CLK_IN_MHZ(48);
    // 9 = 256, 10+ is 512KB
    uint8_t id = (GetChipId() & 0xF00) >> 8;
    if (id > 9) {
        // Set the second 256KB memory flashspeed, if it exists
        AT91C_BASE_EFC1->EFC_FMR = AT91C_MC_FWS_1FWS | MC_FLASH_MODE_MASTER_CLK_IN_MHZ(48);
    }
}

#endif //FLASH_CODE_HW_AT91_H
