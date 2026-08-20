//
// Created by dxl on 2026/5/27.
//
#include "flash_code_apis.h"


RAMFUNC
bool FlashCodeEWriteMinUnit(uint32_t flash_address, const uint32_t *data, uint32_t *flash_start, uint32_t *status) {
    *status = 0x00;
    // The default is AT91C_BASE_EFC0. If the current write address exceeds AT91C_BASE_EFC0,
    // it will automatically switch to AT91C_BASE_EFC1.
    AT91PS_EFC efc_bank = AT91C_BASE_EFC0;
    // If bank1 is currently being writing, we need to calculate the offset to get the starting position of bank1 in flash.
    int offset = 0;
    // Calculate how many pages have been written in total.
    uint32_t page_n = (flash_address - (uint32_t) flash_start) / AT91C_IFLASH_PAGE_SIZE;
    if (page_n >= AT91C_IFLASH_NB_OF_PAGES / 2) {
        // When writing to bank2, we need to recalculate the page from 0 to 1023.
        page_n -= AT91C_IFLASH_NB_OF_PAGES / 2;
        // Switch to AT91C_BASE_EFC1
        efc_bank = AT91C_BASE_EFC1;
        // We need to offset the writes or it will not fill the correct bank write buffer.
        // offset = 65535, 65535 * 4(u32) = 262,140, for write bank1 not bank0.
        offset = (AT91C_IFLASH_NB_OF_PAGES / 2) * AT91C_IFLASH_PAGE_SIZE / sizeof(uint32_t);
    }
    // The Flash of the SAM7S512/256/128 contains a 256-byte write buffer, accessible through a 32-bit interface.
    // The Flash of the SAM7S64/321/32/161/16 contains a 128-byte write buffer, accessible through a 32-bit interface.
    // The writing is not directly written to the flash, but committed to the latch buffer,
    // and then to write the EFC register triggers the erase and write.
    // In addition, the write operation only considers the address of the lower eight bits,
    // so actually only needs to write data to flash_start,
    // and the chip will automatically copy the data to the latch buffer and increase count.
    for (int i = 0; i < FlashCodeGetEWMinUnit() / sizeof(uint32_t); i++) {
        flash_start[offset + i] = data[i];
    }
    efc_bank->EFC_FCR = MC_FLASH_COMMAND_KEY |
                        MC_FLASH_COMMAND_PAGEN(page_n) |
                        AT91C_MC_FCMD_START_PROG;
    // Wait until flashing of page finishes
    uint32_t sr;
    while (!((sr = efc_bank->EFC_FSR) & AT91C_MC_FRDY));
    if (sr & (AT91C_MC_LOCKE | AT91C_MC_PROGE)) {
        *status = sr;
        return false;
    }
    return true;
}
