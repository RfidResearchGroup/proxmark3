//
// Created by dxl on 2026/2/7.
//

#ifndef FLASHMEM_HW_AT91_H
#define FLASHMEM_HW_AT91_H

#include "flashmem.h"
#include "proxmark3_arm.h"

/* here: use NCPS2 @ PA10: */
#define SPI_CSR_NUM      2
#define SPI_PCS(npcs)       ((~(1 << (npcs)) & 0xF) << 16)
/// Calculates the value of the CSR SCBR field given the baudrate and MCK.
#define SPI_SCBR(baudrate, masterClock) ((uint32_t) ((masterClock) / (baudrate)) << 8)
/// Calculates the value of the CSR DLYBS field given the desired delay (in ns)
#define SPI_DLYBS(delay, masterClock) ((uint32_t) ((((masterClock) / 1000000) * (delay)) / 1000) << 16)
/// Calculates the value of the CSR DLYBCT field given the desired delay (in ns)
#define SPI_DLYBCT(delay, masterClock) ((uint32_t) ((((masterClock) / 1000000) * (delay)) / 32000) << 24)

// com speed
#define FLASH_MINFAST   24000000
#define FLASH_BAUD      (MCK / 2)
#define FLASH_FASTBAUD  MCK
#define FLASH_MINBAUD   FLASH_FASTBAUD

#define FASTFLASH (Flash_GetSpiBaudrate() > FLASH_MINFAST)

#endif // FLASHMEM_HW_AT91_H
