//
// Created by dxl on 2026/5/25.
//

#ifndef FLASH_CODE_APIS_H
#define FLASH_CODE_APIS_H

#include "common.h"


/**
 * Write code flash minimum unit. The implementation of this function is very specific to different platforms.
 * The minimum flash rewriting unit varies from platform to platform,
 * so the data length must strictly comply with the length returned by FlashCodeGetEWMinUnit.
 *
 * @param flash_address The flash address to write to. Must be aligned to 4 bytes.
 * @param data The data to write. u32 only.
 * @param flash_start The flash start address of firmware code.
 * @param status The pointer to store the platform specific status code of flash erase/write.
 * @return Whether the operation is successful. If it fails, you can refer to the status.
 */
bool FlashCodeEWriteMinUnit(uint32_t flash_address, const uint32_t *data, uint32_t *flash_start, uint32_t *status);

/**
 * Minimum unit for Flash erase/write.
 * @return Minimum number of bytes per erase/write.
 */
STATIC_FORCE_INLINE uint16_t FlashCodeGetEWMinUnit(void);

/**
 * Initialize the FLASH that stores firmware/code.
 * Configure the clock speed of FLASH, for example.
 */
STATIC_FORCE_INLINE void FlashCodeInit(void);

#ifdef PM5
#include "flash_code_hw_at32.h"
#else
#include "flash_code_hw_at91.h"
#endif

#endif //FLASH_CODE_APIS_H
