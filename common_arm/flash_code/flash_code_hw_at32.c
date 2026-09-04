//
// Created by dxl on 2026/5/26.
//
#include "at32f435_437_flash.h"
#include "at32f435_437_misc.h"
#include "flash_code_apis.h"


// The configuration is 512K. If the code execution speed is desired,
// please define the functions as a code segment executed by RAM.
// 512K_SRAM -> Flash memory zero wait delay area 128K bytes
// 448K_SRAM -> Flash memory zero wait delay area 192K bytes
// 384K_SRAM -> Flash memory zero wait delay area 256K bytes
// 320K_SRAM -> Flash memory zero wait delay area 320K bytes
// 256K_SRAM -> Flash memory zero wait delay area 384K bytes
// 192K_SRAM -> Flash memory zero wait delay area 448K bytes
// 128K_SRAM -> Flash memory zero wait delay area 512K bytes
#define AT32_EXTEND_SRAM FLASH_EOPB0_SRAM_512K


void Extend_SRAM(void) {
#ifdef AS_BOOTROM // !!! Warning: this function only works in bootrom. Otherwise, it may cause crash/infinite restart.
    // check if ram has been set to expectant size, if not, change eopb0
    if (((USD->eopb0) & 0x07) != AT32_EXTEND_SRAM) {
        // unlock flash first
        flash_unlock();
        // erase user system data bytes
        flash_user_system_data_erase();
        // change sram size. Theoretically, we need to judge whether it can be set to this size according to the flash size,
        // but PM5 is only 1M, so we will not judge it temporarily.
        flash_eopb0_config(AT32_EXTEND_SRAM);
        // system reset
        nvic_system_reset();
    }
#endif
}

bool FlashCodeEWriteMinUnit(uint32_t flash_address, const uint32_t *data, uint32_t *flash_start, uint32_t *status) {
    const uint32_t min_ew_unit = FlashCodeGetEWMinUnit();
    const uint32_t min_ew_unit_u32 = min_ew_unit / sizeof(uint32_t);
    UNUSED(flash_start);

    flash_unlock();

    // Wait for operation to be completed
    *status = flash_operation_wait_for(ERASE_TIMEOUT);
    if ((*status == FLASH_PROGRAM_ERROR) || (*status == FLASH_EPP_ERROR)) {
        flash_flag_clear(FLASH_PRGMERR_FLAG | FLASH_EPPERR_FLAG);
    } else if (*status == FLASH_OPERATE_TIMEOUT) {
        return false;
    }

    // Erase and write using the starting address of the sector.
    flash_address = (flash_address / min_ew_unit) * min_ew_unit;

    // Erase
    *status = flash_sector_erase(flash_address);
    if (*status != FLASH_OPERATE_DONE) {
        return false;
    }

    // Write
    for (uint32_t i = 0; i < min_ew_unit_u32; i++) {
        uint32_t w_addr = flash_address + i * sizeof(uint32_t);
        *status = flash_word_program(w_addr, data[i]);
        if (*status != FLASH_OPERATE_DONE) {
            return false;
        }
    }

    flash_lock();
    return true;
}
