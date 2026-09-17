//
// Created by dxl on 2026/5/25.
//

#ifndef FLASH_CODE_HW_AT32_H
#define FLASH_CODE_HW_AT32_H

#include "common.h"
#include "sys_apis.h"
#include "at32f435_437_flash.h"


/**
 * Config the sram extend for MORE ram size.
 * Note: sacrifice non-0 wait FLASH area. And this configuration function must be called
 * before accessing a larger memory area, otherwise HW FAULT may result.
 */
void Extend_SRAM(void);

// It is not allowed to hard code 4096 or 2048, but should be determined according to the current chip capacity.
STATIC_FORCE_INLINE uint16_t FlashCodeGetEWMinUnit(void) {
    // 4032K:
    // The flash memory capacity of slice 1 is 2048K bytes, including 32 blocks, each block has 16 sectors, and each sector size is 4K bytes;
    // The flash memory capacity of slice 2 is 1984K bytes, including 31 blocks. Each block has 16 sectors, and the size of each sector is 4K bytes.
    // The user system data area is 4K bytes in total.
    // 1024K:
    // The main memory is divided into chip 1 and chip 2 flash memory. Each flash memory has a capacity of 512K bytes and contains 8 blocks,
    // each block contains 32 sectors, and the size of each sector is 2K bytes.
    // The user system data area is 512 bytes in total.
    // 256K:
    // The 256K byte main memory has only one flash memory, which contains 4 blocks.
    // Each block contains 32 sectors, and each sector is 2K bytes in size.
    // The user system data area is 512 bytes in total.
    if (GetChipFlashSize() > 1024 * 1024) {
        return 4096;
    }
    return 2048;
}

/**
 * Improve the performance of flash
 * See: https://www.arterytek.com/download/APNOTE/AN0092_AT32F435_437_Performance_Improve_V2.0.1_EN.pdf
 */
STATIC_FORCE_INLINE void FlashCodeInit(void) {
    /*
    Note: If you want to improve the performance of the non-zero wait flash area,
          you need to pay attention to the following specification limits.
    +--------+--------------------------+--------------------------------+---------------------+-------+-------+------+
    | Symbol | Parameter                | Condition                      | Sub-Condition       | Min   | Max   | Unit |
    +--------+--------------------------+--------------------------------+---------------------+-------+-------+------+
    |        |                          | NZW_BST acceleration off       | LDO Voltage 1.3 V   | 0     | 288   |      |
    |        |                          |                                | LDO Voltage 1.2 V   | 0     | 240   |      |
    | f_HCLK | Internal AHB clock freq  |                                | LDO Voltage 1.1 V   | 0     | 144   | MHz  |
    |        |                          |--------------------------------+---------------------+-------+-------+      |
    |        |                          | NZW_BST acceleration on        | LDO Voltage 1.3 V   | 0     | 192   |      |
    |        |                          |                                | LDO Voltage 1.2 V   | 0     | 160   |      |
    |        |                          |                                | LDO Voltage 1.1 V   | 0     | 108   |      |
    +--------+--------------------------+--------------------------------+---------------------+-------+-------+------+
    */

    // Improve the performance of continuous flash reading, Note: increased power consumption.
    flash_continue_read_enable(TRUE); // FLASH->contr_bit.fcontr_en = TRUE;
}

#endif //FLASH_CODE_HW_AT32_H
