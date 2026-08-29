#include "flashmem.h"
#include "pmflash.h"
#include "string.h"
#include "ticks_apis.h"

#ifndef AS_BOOTROM
#include "dbprint.h"
#endif // AS_BOOTROM

// default is 0, first set when FlashInit() call.
static uint32_t flashmem_spibaudrate = 0;

#ifndef AS_BOOTROM

// flash ids, first set when FlashInit() call.
static spi_flash_t spi_flash_data = {0};
// The capacity information calculated after the flash information is detected.
// This variable is referenced in many places, so it cannot be modified with static.
uint8_t spi_flash_pages64k = 4;

// Get spi baudrate
uint32_t Flash_GetSpiBaudrate(void) {
    return flashmem_spibaudrate;
}

// Set spi baudrate, not updated immediately.
// The new baud rate will take effect the next time the FlashSetup function is executed.
// And depending on the platform, the baud rate that is finally set may not be your expected value.
// Maybe some platforms can only communicate at certain fixed baud rates.
void Flash_SetSpiBaudrate(uint32_t baudrate) {
    flashmem_spibaudrate = baudrate;
    Dbprintf("Spi Baudrate : %dMHz", flashmem_spibaudrate / 1000000);
}

// WARNING -- if callers are using a file system (such as SPIFFS),
//            they should inform the file system of this change
//            e.g., rdv40_spiffs_check()
bool Flash_WipeMemoryPage(uint8_t page) {
    if (!FlashInit()) {
        if (g_dbglevel > DBG_DEBUG) Dbprintf("Flash_WriteData init fail");
        return false;
    }

    // Each block is 64Kb. One block erase takes 1s ( 1000ms )
    Flash_WriteEnable();
    Flash_Erase64k(page);
    Flash_CheckBusy(BUSY_TIMEOUT);

    FlashStop();

    return true;
}

// Wipes flash memory completely, fills with 0xFF
bool Flash_WipeMemory(void) {
    if (!FlashInit()) {
        if (g_dbglevel > DBG_DEBUG) Dbprintf("Flash_WriteData init fail");
        return false;
    }

    // Each block is 64Kb.  Four blocks
    // one block erase takes 1s ( 1000ms )
    for (uint8_t i = 0; i < spi_flash_pages64k; i++) {
        Flash_WriteEnable();
        Flash_Erase64k(i);
        Flash_CheckBusy(BUSY_TIMEOUT);
    }

    FlashStop();
    return true;
}

// ReadData with spi initialization
uint16_t Flash_ReadData(uint32_t address, uint8_t *out, uint16_t len) {

    if (!FlashInit()) return 0;

    // check busy only
    if (Flash_CheckBusy(BUSY_TIMEOUT)) return 0;

    // function reused, length check inside.
    len = Flash_ReadDataCont(address, out, len);

    FlashStop();
    return len;
}

// Write data can only program one page. A page has 256 bytes.
// if len > 256, it might wrap around and overwrite pos 0.
uint16_t Flash_WriteData(uint32_t address, uint8_t *in, uint16_t len) {

    if (!FlashInit()) {
        if (g_dbglevel > DBG_DEBUG) Dbprintf("Flash_WriteData init fail");
        return 0;
    }

    Flash_CheckBusy(BUSY_TIMEOUT);
    Flash_WriteEnable();

    // function reused, len and addr check inside.
    len = Flash_WriteDataCont(address, in, len);

    FlashStop();
    return len;
}

// assumes valid start 256 based 00 address
// Start writing flash from the specified location.
// Write FLASH_MEM_BLOCK_SIZE bytes at most each time. If the writing is nearly complete, write it as bytes_remaining bytes.
uint16_t Flash_Write(uint32_t address, uint8_t *in, uint16_t len) {

    bool isok;
    uint16_t res, bytes_sent = 0, bytes_remaining = len;
    uint8_t buf[FLASH_MEM_BLOCK_SIZE];
    while (bytes_remaining > 0) {

        Flash_CheckBusy(BUSY_TIMEOUT);
        Flash_WriteEnable();

        uint32_t bytes_in_packet = MIN(FLASH_MEM_BLOCK_SIZE, bytes_remaining);

        memcpy(buf, in + bytes_sent, bytes_in_packet);

        res = Flash_WriteDataCont(address + bytes_sent, buf, bytes_in_packet);

        bytes_remaining -= bytes_in_packet;
        bytes_sent += bytes_in_packet;

        isok = (res == bytes_in_packet);

        if (!isok)
            goto out;
    }

out:
    FlashStop();
    return len;
}

void Flashmem_print_status(void) {
    DbpString(_CYAN_("Flash memory"));
    Dbprintf("  Baudrate................ " _GREEN_("%d MHz"), flashmem_spibaudrate / 1000000);

    if (FlashInit() == false) {
        DbpString("  Init.................... " _RED_("failed"));
        return;
    }
    DbpString("  Init.................... " _GREEN_("ok"));

    if (spi_flash_data.device_id > 0) {
        Dbprintf("  Mfr ID / Dev ID......... " _YELLOW_("%02X / %02X"),
                 spi_flash_data.manufacturer_id,
                 spi_flash_data.device_id
                );
    }

    if (spi_flash_data.jedec_id > 0) {
        Dbprintf("  JEDEC Mfr ID / Dev ID... " _YELLOW_("%02X / %04X"),
                 spi_flash_data.manufacturer_id,
                 spi_flash_data.jedec_id
                );
    }

    Dbprintf("  Memory size............. " _YELLOW_("%d Kb") " ( %d pages * 64k )", spi_flash_pages64k * 64, spi_flash_pages64k);

    uint8_t uid[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    Flash_UniqueID(uid);
    Dbprintf("  Unique ID (be).......... " _YELLOW_("0x%02X%02X%02X%02X%02X%02X%02X%02X"),
             uid[0], uid[1], uid[2], uid[3],
             uid[4], uid[5], uid[6], uid[7]
            );
    if (g_dbglevel > DBG_DEBUG) {
        Dbprintf("  Unique ID (le).......... " _YELLOW_("0x%02X%02X%02X%02X%02X%02X%02X%02X"),
                 uid[7], uid[6], uid[5], uid[4],
                 uid[3], uid[2], uid[1], uid[0]
                );
    }
    FlashStop();
}

spi_flash_t *flash_get_info(void) {
    return &spi_flash_data;
}

bool FlashDetect(void) {

    flash_device_type_t flash_data = {0};
    bool ret = false;
    // read using 0x9F (JEDEC)
    if (Flash_ReadID(&flash_data, true)) {
        spi_flash_data.manufacturer_id = flash_data.manufacturer_id;
        spi_flash_data.jedec_id = (flash_data.device_id << 8) +  flash_data.device_id2;
        ret = true;
    } else {
        if (g_dbglevel > DBG_DEBUG) Dbprintf("Flash_ReadID failed reading JEDEC (0x9F)");
    }

    // read using 0x90 (Manufacturer / Device ID)
    if (Flash_ReadID(&flash_data, false)) {
        if (spi_flash_data.manufacturer_id == 0) {
            spi_flash_data.manufacturer_id = flash_data.manufacturer_id;
        }
        spi_flash_data.device_id = flash_data.device_id;
        ret = true;
    } else {
        if (g_dbglevel > DBG_DEBUG) Dbprintf("Flash_ReadID failed reading Mfr/Dev (0x90)");
    }

    // Check JEDEC data is valid, compare the reported device types and then calculate the number of pages
    // It is covering the most (known) cases of devices but probably there are vendors with different data
    // They will be handled when there is such cases
    if (ret) {
        if (spi_flash_data.jedec_id > 0 && spi_flash_data.jedec_id < 0xFFFF) {
            if (((spi_flash_data.device_id + 1) & 0x0F) == (spi_flash_data.jedec_id & 0x000F)) {
                spi_flash_pages64k = 1 << (spi_flash_data.jedec_id & 0x000F);
            }
        }
    }

    spi_flash_data.pages64k = spi_flash_pages64k;
    return ret;
}

#endif // #ifndef AS_BOOTROM

// initialize
bool FlashInit(void) {
    // set default baud rate from platform specific
    if (!flashmem_spibaudrate) { // only set if current value == 0
        flashmem_spibaudrate = Flash_DefaultBaudrate();
    }

    // Prioritize call the StartTicks, as the subsequent initialization process may rely on the counter
    // to determine if there is a communication timeout.
    StartTicks();

    // If it is a QSPI communication interface, an attempt will be made to enable 4-wire communication at this stage.
    // If the enable fails, it indicates that the chip does not support QSPI or has poor soldering.
    // Tip: Some platform related steps only need to be executed once during initialization, which will be done in this function.
    if (!FlashSetup(flashmem_spibaudrate)) {
        StopTicks();
        return false;
    }

    if (Flash_CheckBusy(BUSY_TIMEOUT)) {
        StopTicks();
        return false;
    }

#ifndef AS_BOOTROM
    if (spi_flash_data.manufacturer_id == 0) {
        if (FlashDetect() == false) {
            return false;
        }
    }
#endif // #ifndef AS_BOOTROM

    return true;
}

// check flash write/erase working.
bool Flash_CheckBusy(uint32_t timeout) {
    WaitUS(WINBOND_WRITE_DELAY);
    StartCountUS();
    uint32_t _time = GetCountUS();
    uint8_t status;

    do {
        // Read status register failed!
        if (!Flash_ReadStat1(&status)) {
            // The chip may not be working properly, so it is meaningless to determine whether it is busy.
            // We will return false first. If we consider returning true in the future, please modify it.
            return false;
        }
        // Flash is busy for wipe/write
        if (!(status & BUSY)) {
            return false;
        }
    } while ((GetCountUS() - _time) < timeout);

    if (timeout <= (GetCountUS() - _time)) {
        return true;
    }

    return false;
}
