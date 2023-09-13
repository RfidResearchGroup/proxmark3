//-----------------------------------------------------------------------------
// Borrowed initially from Arduino SPIFlash Library v.2.5.0
// Copyright (C) 2015 by Prajwal Bhattaram.
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------
#include "flashmem.h"
#include "pmflash.h"

#include "proxmark3_arm.h"
#include "ticks.h"

#ifndef AS_BOOTROM
#include "dbprint.h"
#endif // AS_BOOTROM

#include "string.h"
#include "usb_cdc.h"

/* here: use NCPS2 @ PA10: */
#define SPI_CSR_NUM      2
#define SPI_PCS(npcs)       ((~(1 << (npcs)) & 0xF) << 16)
/// Calculates the value of the CSR SCBR field given the baudrate and MCK.
#define SPI_SCBR(baudrate, masterClock) ((uint32_t) ((masterClock) / (baudrate)) << 8)
/// Calculates the value of the CSR DLYBS field given the desired delay (in ns)
#define SPI_DLYBS(delay, masterClock) ((uint32_t) ((((masterClock) / 1000000) * (delay)) / 1000) << 16)
/// Calculates the value of the CSR DLYBCT field given the desired delay (in ns)
#define SPI_DLYBCT(delay, masterClock) ((uint32_t) ((((masterClock) / 1000000) * (delay)) / 32000) << 24)

static uint32_t FLASHMEM_SPIBAUDRATE = FLASH_BAUD;
#define FASTFLASH (FLASHMEM_SPIBAUDRATE > FLASH_MINFAST)

#ifndef AS_BOOTROM

void FlashmemSetSpiBaudrate(uint32_t baudrate) {
    FLASHMEM_SPIBAUDRATE = baudrate;
    Dbprintf("Spi Baudrate : %dMHz", FLASHMEM_SPIBAUDRATE / 1000000);
}

// read ID out
bool Flash_ReadID_90(flash_device_type_90_t *result) {

    if (Flash_CheckBusy(BUSY_TIMEOUT)) return false;

    // Manufacture ID / device ID
    FlashSendByte(ID);
    FlashSendByte(0x00);
    FlashSendByte(0x00);
    FlashSendByte(0x00);

    result->manufacturer_id = FlashSendByte(0xFF);
    result->device_id       = FlashSendLastByte(0xFF);

    return true;
}

uint16_t Flash_ReadData(uint32_t address, uint8_t *out, uint16_t len) {

    if (!FlashInit()) return 0;

    // length should never be zero
    if (!len || Flash_CheckBusy(BUSY_TIMEOUT)) return 0;

    uint8_t cmd = (FASTFLASH) ? FASTREAD : READDATA;

    FlashSendByte(cmd);
    Flash_TransferAdresse(address);

    if (FASTFLASH) {
        FlashSendByte(DUMMYBYTE);
    }

    uint16_t i = 0;
    for (; i < (len - 1); i++)
        out[i] = FlashSendByte(0xFF);

    out[i] = FlashSendLastByte(0xFF);
    FlashStop();
    return len;
}

void Flash_TransferAdresse(uint32_t address) {
    FlashSendByte((address >> 16) & 0xFF);
    FlashSendByte((address >> 8) & 0xFF);
    FlashSendByte((address >> 0) & 0xFF);
}

/* This ensures we can ReadData without having to cycle through initialization every time */
uint16_t Flash_ReadDataCont(uint32_t address, uint8_t *out, uint16_t len) {

    // length should never be zero
    if (!len) return 0;

    uint8_t cmd = (FASTFLASH) ? FASTREAD : READDATA;

    FlashSendByte(cmd);
    Flash_TransferAdresse(address);

    if (FASTFLASH) {
        FlashSendByte(DUMMYBYTE);
    }

    uint16_t i = 0;
    for (; i < (len - 1); i++)
        out[i] = FlashSendByte(0xFF);

    out[i] = FlashSendLastByte(0xFF);
    return len;
}

////////////////////////////////////////
// Write data can only program one page. A page has 256 bytes.
// if len > 256, it might wrap around and overwrite pos 0.
uint16_t Flash_WriteData(uint32_t address, uint8_t *in, uint16_t len) {

    // length should never be zero
    if (!len)
        return 0;

    // Max 256 bytes write
    if (((address & 0xFF) + len) > 256) {
        Dbprintf("Flash_WriteData 256 fail [ 0x%02x ] [ %u ]", (address & 0xFF) + len, len);
        return 0;
    }

    // out-of-range
    if (((address >> 16) & 0xFF) > MAX_BLOCKS) {
        Dbprintf("Flash_WriteData,  block out-of-range");
        return 0;
    }

    if (!FlashInit()) {
        if (g_dbglevel > 3) Dbprintf("Flash_WriteData init fail");
        return 0;
    }

    Flash_CheckBusy(BUSY_TIMEOUT);

    Flash_WriteEnable();

    FlashSendByte(PAGEPROG);
    FlashSendByte((address >> 16) & 0xFF);
    FlashSendByte((address >> 8) & 0xFF);
    FlashSendByte((address >> 0) & 0xFF);

    uint16_t i = 0;
    for (; i < (len - 1); i++)
        FlashSendByte(in[i]);

    FlashSendLastByte(in[i]);

    FlashStop();
    return len;
}

// length should never be zero
// Max 256 bytes write
// out-of-range
uint16_t Flash_WriteDataCont(uint32_t address, uint8_t *in, uint16_t len) {

    if (!len)
        return 0;

    if (((address & 0xFF) + len) > 256) {
        Dbprintf("Flash_WriteDataCont 256 fail [ 0x%02x ] [ %u ]", (address & 0xFF) + len, len);
        return 0;
    }

    if (((address >> 16) & 0xFF) > MAX_BLOCKS) {
        Dbprintf("Flash_WriteDataCont,  block out-of-range");
        return 0;
    }

    FlashSendByte(PAGEPROG);
    FlashSendByte((address >> 16) & 0xFF);
    FlashSendByte((address >> 8) & 0xFF);
    FlashSendByte((address >> 0) & 0xFF);

    uint16_t i = 0;
    for (; i < (len - 1); i++)
        FlashSendByte(in[i]);

    FlashSendLastByte(in[i]);
    return len;
}

// assumes valid start 256 based 00 address
//
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

// WARNING -- if callers are using a file system (such as SPIFFS),
//            they should inform the file system of this change
//            e.g., rdv40_spiffs_check()
bool Flash_WipeMemoryPage(uint8_t page) {
    if (!FlashInit()) {
        if (g_dbglevel > 3) Dbprintf("Flash_WriteData init fail");
        return false;
    }
    Flash_ReadStat1();

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
        if (g_dbglevel > 3) Dbprintf("Flash_WriteData init fail");
        return false;
    }
    Flash_ReadStat1();

    // Each block is 64Kb.  Four blocks
    // one block erase takes 1s ( 1000ms )
    Flash_WriteEnable();
    Flash_Erase64k(0);
    Flash_CheckBusy(BUSY_TIMEOUT);
    Flash_WriteEnable();
    Flash_Erase64k(1);
    Flash_CheckBusy(BUSY_TIMEOUT);
    Flash_WriteEnable();
    Flash_Erase64k(2);
    Flash_CheckBusy(BUSY_TIMEOUT);
    Flash_WriteEnable();
    Flash_Erase64k(3);
    Flash_CheckBusy(BUSY_TIMEOUT);

    FlashStop();
    return true;
}

// enable the flash write
void Flash_WriteEnable(void) {
    FlashSendLastByte(WRITEENABLE);
    if (g_dbglevel > 3) Dbprintf("Flash Write enabled");
}

// erase 4K at one time
// execution time: 0.8ms / 800us
bool Flash_Erase4k(uint8_t block, uint8_t sector) {

    if (block > MAX_BLOCKS  || sector > MAX_SECTORS) return false;

    FlashSendByte(SECTORERASE);
    FlashSendByte(block);
    FlashSendByte(sector << 4);
    FlashSendLastByte(00);
    return true;
}

/*
// erase 32K at one time
// execution time: 0,3s / 300ms
bool Flash_Erase32k(uint32_t address) {
    if (address & (32*1024 - 1)) {
        if ( g_dbglevel > 1 ) Dbprintf("Flash_Erase32k : Address is not align at 4096");
        return false;
    }
    FlashSendByte(BLOCK32ERASE);
    FlashSendByte((address >> 16) & 0xFF);
    FlashSendByte((address >> 8) & 0xFF);
    FlashSendLastByte((address >> 0) & 0xFF);
    return true;
}
*/

// erase 64k at one time
// since a block is 64kb,  and there is four blocks.
// we only need block number,  as MSB
// execution time: 1s  / 1000ms
// 0x00 00 00  -- 0x 00 FF FF  == block 0
// 0x01 00 00  -- 0x 01 FF FF  == block 1
// 0x02 00 00  -- 0x 02 FF FF  == block 2
// 0x03 00 00  -- 0x 03 FF FF  == block 3
bool Flash_Erase64k(uint8_t block) {

    if (block > MAX_BLOCKS) return false;

    FlashSendByte(BLOCK64ERASE);
    FlashSendByte(block);
    FlashSendByte(0x00);
    FlashSendLastByte(0x00);
    return true;
}

/*
// Erase chip
void Flash_EraseChip(void) {
    FlashSendLastByte(CHIPERASE);
}
*/

void Flashmem_print_status(void) {
    DbpString(_CYAN_("Flash memory"));
    Dbprintf("  Baudrate................ " _GREEN_("%d MHz"), FLASHMEM_SPIBAUDRATE / 1000000);

    if (!FlashInit()) {
        DbpString("  Init.................... " _RED_("FAILED"));
        return;
    }
    DbpString("  Init.................... " _GREEN_("OK"));

    // NOTE: It would likely be more useful to use JDEC ID command 9F,
    //       as it provides a third byte indicative of capacity.
    flash_device_type_90_t device_type = {0};
    if (!Flash_ReadID_90(&device_type)) {
        DbpString("  Device ID............... " _RED_(" -->  Not Found  <--"));
    } else {
        if (device_type.manufacturer_id == WINBOND_MANID) {
            switch (device_type.device_id) {
                case WINBOND_2MB_DEVID:
                    DbpString("  Memory size............. " _YELLOW_("2 mbits / 256 kb"));
                    break;
                case WINBOND_1MB_DEVID:
                    DbpString("  Memory size..... ....... " _YELLOW_("1 mbits / 128 kb"));
                    break;
                case WINBOND_512KB_DEVID:
                    DbpString("  Memory size............. " _YELLOW_("512 kbits / 64 kb"));
                    break;
                default:
                    break;
            }
        } else {
            Dbprintf("  Device ID............... " _YELLOW_("%02X / %02X (unknown)"),
                     device_type.manufacturer_id,
                     device_type.device_id
                    );
        }
    }

    uint8_t uid[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    Flash_UniqueID(uid);
    Dbprintf("  Unique ID (be).......... " _YELLOW_("0x%02X%02X%02X%02X%02X%02X%02X%02X"),
             uid[0], uid[1], uid[2], uid[3],
             uid[4], uid[5], uid[6], uid[7]
            );
    if (g_dbglevel > 3) {
        Dbprintf("  Unique ID (le).......... " _YELLOW_("0x%02X%02X%02X%02X%02X%02X%02X%02X"),
                 uid[7], uid[6], uid[5], uid[4],
                 uid[3], uid[2], uid[1], uid[0]
                );
    }
    FlashStop();
}

void Flashmem_print_info(void) {

    if (!FlashInit()) return;

    DbpString(_CYAN_("Flash memory dictionary loaded"));

    // load dictionary offsets.
    uint8_t keysum[2];
    uint16_t num;

    Flash_CheckBusy(BUSY_TIMEOUT);
    uint16_t isok = Flash_ReadDataCont(DEFAULT_MF_KEYS_OFFSET, keysum, 2);
    if (isok == 2) {
        num = ((keysum[1] << 8) | keysum[0]);
        if (num != 0xFFFF && num != 0x0)
            Dbprintf("  Mifare.................. "_YELLOW_("%u")" / "_GREEN_("%u")" keys", num, DEFAULT_MF_KEYS_MAX);
    }

    Flash_CheckBusy(BUSY_TIMEOUT);
    isok = Flash_ReadDataCont(DEFAULT_T55XX_KEYS_OFFSET, keysum, 2);
    if (isok == 2) {
        num = ((keysum[1] << 8) | keysum[0]);
        if (num != 0xFFFF && num != 0x0)
            Dbprintf("  T55x7................... "_YELLOW_("%u")" / "_GREEN_("%u")" keys", num, DEFAULT_T55XX_KEYS_MAX);
    }

    Flash_CheckBusy(BUSY_TIMEOUT);
    isok = Flash_ReadDataCont(DEFAULT_ICLASS_KEYS_OFFSET, keysum, 2);
    if (isok == 2) {
        num = ((keysum[1] << 8) | keysum[0]);
        if (num != 0xFFFF && num != 0x0)
            Dbprintf("  iClass.................. "_YELLOW_("%u")" / "_GREEN_("%u")" keys", num, DEFAULT_ICLASS_KEYS_MAX);
    }

    FlashStop();
}

#endif // #ifndef AS_BOOTROM


// initialize
bool FlashInit(void) {
    FlashSetup(FLASHMEM_SPIBAUDRATE);

    StartTicks();

    if (Flash_CheckBusy(BUSY_TIMEOUT)) {
        StopTicks();
        return false;
    }

    return true;
}

// read unique id for chip.
void Flash_UniqueID(uint8_t *uid) {

    if (Flash_CheckBusy(BUSY_TIMEOUT)) return;

    // reading unique serial number
    FlashSendByte(UNIQUE_ID);
    FlashSendByte(0xFF);
    FlashSendByte(0xFF);
    FlashSendByte(0xFF);
    FlashSendByte(0xFF);

    uid[7] = FlashSendByte(0xFF);
    uid[6] = FlashSendByte(0xFF);
    uid[5] = FlashSendByte(0xFF);
    uid[4] = FlashSendByte(0xFF);
    uid[3] = FlashSendByte(0xFF);
    uid[2] = FlashSendByte(0xFF);
    uid[1] = FlashSendByte(0xFF);
    uid[0] = FlashSendLastByte(0xFF);
}

void FlashStop(void) {
    //Bof
    //* Reset all the Chip Select register
    AT91C_BASE_SPI->SPI_CSR[0] = 0;
    AT91C_BASE_SPI->SPI_CSR[1] = 0;
    AT91C_BASE_SPI->SPI_CSR[2] = 0;
    AT91C_BASE_SPI->SPI_CSR[3] = 0;

    // Reset the SPI mode
    AT91C_BASE_SPI->SPI_MR = 0;

    // Disable all interrupts
    AT91C_BASE_SPI->SPI_IDR = 0xFFFFFFFF;

    // SPI disable
    AT91C_BASE_SPI->SPI_CR = AT91C_SPI_SPIDIS;

#ifndef AS_BOOTROM
    if (g_dbglevel > 3) Dbprintf("FlashStop");
#endif // AS_BOOTROM

    StopTicks();
}

void FlashSetup(uint32_t baudrate) {
    //WDT_DISABLE
    AT91C_BASE_WDTC->WDTC_WDMR = AT91C_WDTC_WDDIS;

    // PA10 -> SPI_NCS2 chip select (FLASHMEM)
    // PA11 -> SPI_NCS0 chip select (FPGA)
    // PA12 -> SPI_MISO Master-In Slave-Out
    // PA13 -> SPI_MOSI Master-Out Slave-In
    // PA14 -> SPI_SPCK Serial Clock

    // Disable PIO control of the following pins, allows use by the SPI peripheral
    AT91C_BASE_PIOA->PIO_PDR |= (GPIO_NCS0 | GPIO_MISO | GPIO_MOSI | GPIO_SPCK | GPIO_NCS2);

    // Pull-up Enable
    AT91C_BASE_PIOA->PIO_PPUER |= (GPIO_NCS0 | GPIO_MISO | GPIO_MOSI | GPIO_SPCK | GPIO_NCS2);

    // Peripheral A
    AT91C_BASE_PIOA->PIO_ASR |= (GPIO_NCS0 | GPIO_MISO | GPIO_MOSI | GPIO_SPCK);

    // Peripheral B
    AT91C_BASE_PIOA->PIO_BSR |= GPIO_NCS2;

    //enable the SPI Peripheral clock
    AT91C_BASE_PMC->PMC_PCER = (1 << AT91C_ID_SPI);


    //reset spi needs double SWRST, see atmel's errata on this case
    AT91C_BASE_SPI->SPI_CR = AT91C_SPI_SWRST;
    AT91C_BASE_SPI->SPI_CR = AT91C_SPI_SWRST;

    // Enable SPI
    AT91C_BASE_SPI->SPI_CR = AT91C_SPI_SPIEN;

    // NPCS2 Mode 0
    AT91C_BASE_SPI->SPI_MR =
        (0 << 24)            | // Delay between chip selects = DYLBCS/MCK BUT:
        // If DLYBCS is less than or equal to six, six MCK periods
        // will be inserted by default.
        SPI_PCS(SPI_CSR_NUM) | // Peripheral Chip Select (selects SPI_NCS2 or PA10)
        (0 << 7)            |  // Disable LLB (1=MOSI2MISO test mode)
        (1 << 4)            |  // Disable ModeFault Protection
        (0 << 3)            |  // makes spi operate at MCK (1 is MCK/2)
        (0 << 2)            |  // Chip selects connected directly to peripheral
        AT91C_SPI_PS_FIXED   | // Fixed Peripheral Select
        AT91C_SPI_MSTR;        // Master Mode

    uint8_t csaat = 1;
    uint32_t dlybct = 0;
    uint8_t ncpha = 1;
    uint8_t cpol = 0;
    if (baudrate > FLASH_MINFAST) {
        baudrate = FLASH_FASTBAUD;
        //csaat = 0;
        dlybct = 1500;
        ncpha = 0;
        cpol = 0;
    }

    AT91C_BASE_SPI->SPI_CSR[2] =
        SPI_DLYBCT(dlybct, MCK) | // Delay between Consecutive Transfers (32 MCK periods)
        SPI_DLYBS(0, MCK)      | // Delay Beforce SPCK CLock
        SPI_SCBR(baudrate, MCK) | // SPI Baudrate Selection
        AT91C_SPI_BITS_8      | // Bits per Transfer (8 bits)
        //AT91C_SPI_CSAAT       | // Chip Select inactive after transfer
        // 40.4.6.2 SPI: Bad tx_ready Behavior when CSAAT = 1 and SCBR = 1
        // If the SPI is programmed with CSAAT = 1, SCBR(baudrate) = 1 and two transfers are performed consecutively on
        // the same slave with an IDLE state between them, the tx_ready signal does not rise after the second data has been
        // transferred in the shifter. This can imply for example, that the second data is sent twice.
        // COLIN :: For now we STILL use CSAAT=1 to avoid having to (de)assert  NPCS manually via PIO lines and we deal with delay
        (csaat << 3)         |
        /* Spi modes:
            Mode CPOL CPHA NCPHA
            0    0    0    1       clock normally low    read on rising edge
            1    0    1    0       clock normally low    read on falling edge
            2    1    0    1       clock normally high   read on falling edge
            3    1    1    0       clock normally high   read on rising edge
            However, page 512 of the AT91SAM7Sx datasheet say "Note that in SPI
            master mode the ATSAM7S512/256/128/64/321/32 does not sample the data
            (MISO) on the opposite edge where data clocks out (MOSI) but the same
            edge is used as shown in Figure 36-3 and Figure 36-4."  Figure 36-3
            shows that CPOL=NCPHA=0 or CPOL=NCPHA=1 samples on the rising edge and
            that the data changes sometime after the rising edge (about 2 ns).  To
            be consistent with normal SPI operation, it is probably safe to say
            that the data changes on the falling edge and should be sampled on the
            rising edge.  Therefore, it appears that NCPHA should be treated the
            same as CPHA.  Thus:
            Mode CPOL CPHA NCPHA
            0    0    0    0       clock normally low    read on rising edge
            1    0    1    1       clock normally low    read on falling edge
            2    1    0    0       clock normally high   read on falling edge
            3    1    1    1       clock normally high   read on rising edge
            Update: for 24MHz, writing is more stable with ncpha=1, else bitflips occur.
        */
        (ncpha << 1)             |  // Clock Phase data captured on leading edge, changes on following edge
        (cpol << 0);               // Clock Polarity inactive state is logic 0

    // read first, empty buffer
    if (AT91C_BASE_SPI->SPI_RDR == 0) {};
}

bool Flash_CheckBusy(uint32_t timeout) {
    WaitUS(WINBOND_WRITE_DELAY);
    StartCountUS();
    uint32_t _time = GetCountUS();

    do {
        if (!(Flash_ReadStat1() & BUSY)) {
            return false;
        }
    } while ((GetCountUS() - _time) < timeout);

    if (timeout <= (GetCountUS() - _time)) {
        return true;
    }

    return false;
}

// read state register 1
uint8_t Flash_ReadStat1(void) {
    FlashSendByte(READSTAT1);
    return FlashSendLastByte(0xFF);
}

// send one byte over SPI
uint16_t FlashSendByte(uint32_t data) {

    // wait until SPI is ready for transfer
    //if you are checking for incoming data returned then the TXEMPTY flag is redundant
    //while ((AT91C_BASE_SPI->SPI_SR & AT91C_SPI_TXEMPTY) == 0) {};

    // send the data
    AT91C_BASE_SPI->SPI_TDR = data;

    //while ((AT91C_BASE_SPI->SPI_SR & AT91C_SPI_TDRE) == 0){};

    // wait receive transfer is complete
    while ((AT91C_BASE_SPI->SPI_SR & AT91C_SPI_RDRF) == 0) {};

    // reading incoming data
    return ((AT91C_BASE_SPI->SPI_RDR) & 0xFFFF);
}

// send last byte over SPI
uint16_t FlashSendLastByte(uint32_t data) {
    return FlashSendByte(data | AT91C_SPI_LASTXFER);
}
