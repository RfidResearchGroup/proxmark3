//-----------------------------------------------------------------------------
// Borrowed initially from Arduino SPIFlash Library v.2.5.0
// Copyright (C) 2015 by Prajwal Bhattaram.
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
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~//
//                      Common Instructions                           //
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~//
#ifndef FLASHMEM_H_
#define FLASHMEM_H_

#include "common.h"
#include "pmflash.h"

//    Used Command
#define ID              0x90
#define MANID           0x90
#define JEDECID         0x9F

#define READSTAT1       0x05
#define READSTAT2       0x35
#define WRITESTAT       0x01

#define WRITEDISABLE    0x04
#define WRITEENABLE     0x06

#define READDATA        0x03
#define FASTREAD        0x0B
#define FASTREAD_QO     0x6B // Fast Read Quad Output, qspi, some platform unsupported(at91, haha).
#define PAGEPROG        0x02

#define SECTORERASE     0x20
#define BLOCK32ERASE    0x52
#define BLOCK64ERASE    0xD8
#define CHIPERASE       0xC7

#define UNIQUE_ID       0x4B

//    Not used or not support command
#define RELEASE         0xAB
#define POWERDOWN       0xB9
#define SUSPEND         0x75
#define RESUME          0x7A

// Flash busy timeout: 20ms is the strict minimum when writing 256kb
#define BUSY_TIMEOUT    200000L

#define PAGESIZE        0x100
#define WINBOND_WRITE_DELAY 0x02

#define BUSY            0x01
#define WRTEN           0x02
#define SUS             0x40

#define DUMMYBYTE       0xEE
#define NULLBYTE        0x00
#define NULLINT         0x0000
#define NO_CONTINUE     0x00
#define PASS            0x01
#define FAIL            0x00

// List of blocks
#define MAX_BLOCKS      4
#define MAX_SECTORS     16

//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~//

// The default values returned by different platforms are different.
// This function is implemented by the platform.
uint32_t Flash_DefaultBaudrate(void);

bool FlashInit(void);
bool FlashSetup(uint32_t baudrate);
void FlashStop(void);

bool Flash_UniqueID(uint8_t *uid);
bool Flash_CheckBusy(uint32_t timeout);
bool Flash_ReadStat1(uint8_t *status);
bool Flash_ReadStat2(uint8_t *status);

#ifndef AS_BOOTROM

uint32_t Flash_GetSpiBaudrate(void);
void Flash_SetSpiBaudrate(uint32_t baudrate);
bool Flash_WriteEnable(void);
bool Flash_WipeMemoryPage(uint8_t page);
bool Flash_WipeMemory(void);
bool Flash_Erase4k(uint8_t block, uint8_t sector);
//bool Flash_Erase32k(uint32_t address);
bool Flash_Erase64k(uint8_t block);

// defs see: https://chromium.googlesource.com/chromiumos/third_party/flashrom/+/798d2adc9527f724bc5096a646cf99efdbb6b59e/flashchips.h
typedef struct {
    uint8_t manufacturer_id;
    uint8_t device_id;
    uint8_t device_id2;
} flash_device_type_t; // extra device_id used for the JEDEC ID read via cmd 9F
bool Flash_ReadID(flash_device_type_t *result, bool read_jedec);

uint16_t Flash_ReadData(uint32_t address, uint8_t *out, uint16_t len);
uint16_t Flash_ReadDataCont(uint32_t address, uint8_t *out, uint16_t len);
uint16_t Flash_Write(uint32_t address, uint8_t *in, uint16_t len);
uint16_t Flash_WriteData(uint32_t address, uint8_t *in, uint16_t len);
uint16_t Flash_WriteDataCont(uint32_t address, uint8_t *in, uint16_t len);
void Flashmem_print_status(void);

spi_flash_t *flash_get_info(void);

extern uint8_t spi_flash_pages64k;

bool FlashDetect(void);

#endif // #ifndef AS_BOOTROM

#endif // FLASHMEM_H_
