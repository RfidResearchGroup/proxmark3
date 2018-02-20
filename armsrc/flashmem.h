/* Arduino SPIFlash Library v.2.5.0
 * Copyright (C) 2015 by Prajwal Bhattaram
 * Modified by Prajwal Bhattaram - 13/11/2016
 *
 * This file is part of the Arduino SPIFlash Library. This library is for
 * Winbond NOR flash memory modules. In its current form it enables reading
 * and writing individual data variables, structs and arrays from and to various locations;
 * reading and writing pages; continuous read functions; sector, block and chip erase;
 * suspending and resuming programming/erase and powering down for low power operation.
 *
 * This Library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This Library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License v3.0
 * along with the Arduino SPIFlash Library.  If not, see
 * <http://www.gnu.org/licenses/>.
 */
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~//
//						Common Instructions 						  //
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~//
#ifndef __FLASHMEM_H
#define __FLASHMEM_H

#include "proxmark3.h"
#include "apps.h"

#define	MANID			0x90
#define PAGEPROG		0x02
#define READDATA		0x03
#define FASTREAD		0x0B
#define WRITEDISABLE	0x04
#define READSTAT1		0x05
#define READSTAT2		0x35
#define WRITESTAT		0x01
#define WRITEENABLE		0x06
#define SECTORERASE		0x20
#define BLOCK32ERASE	0x52
#define CHIPERASE		0xC7
#define SUSPEND			0x75
#define ID				0x90
#define RESUME			0x7A
#define JEDECID			0x9F
#define RELEASE			0xAB
#define POWERDOWN		0xB9
#define BLOCK64ERASE	0xD8
#define ENABLE_RESET	0x66
#define RESET			0x99

#define UNIQUE_ID		0x4B
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~//
//					Chip specific instructions 						  //
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~//

//~~~~~~~~~~~~~~~~~~~~~~~~~ Winbond ~~~~~~~~~~~~~~~~~~~~~~~~~//
#define WINBOND_MANID	0xEF
#define WINBOND_DEVID	0x11
#define PAGESIZE	 	0x100

//~~~~~~~~~~~~~~~~~~~~~~~~ Microchip ~~~~~~~~~~~~~~~~~~~~~~~~//
#define MICROCHIP_MANID	0xBF
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~//
//							Definitions 							  //
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~//

#define BUSY          0x01
#define SPI_CLK       104000000       //Hex equivalent of 104MHz
#define WRTEN         0x02
#define SUS           0x40
#define DUMMYBYTE     0xEE
#define NULLBYTE      0x00
#define NULLINT       0x0000
#define NO_CONTINUE   0x00
#define PASS          0x01
#define FAIL          0x00
#define arrayLen(x)   (sizeof(x) / sizeof(*x))
#define lengthOf(x)   (sizeof(x))/sizeof(byte)
#define maxAddress    capacity

//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~//
//     					   List of Error codes						  //
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~//
#define SUCCESS      0x00
#define CALLBEGIN    0x01
#define UNKNOWNCHIP  0x02
#define UNKNOWNCAP   0x03
#define CHIPBUSY     0x04
#define OUTOFBOUNDS  0x05
#define CANTENWRITE  0x06
#define PREVWRITTEN  0x07
#define LOWRAM       0x08
#define NOSUSPEND    0x09
#define UNKNOWNERROR 0xFF

//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~//
extern void Dbprintf(const char *fmt, ...);

void FlashSetup(void);
void FlashStop(void);
bool Flash_NOTBUSY(void);
uint8_t Flash_ReadStat1(void);
uint8_t Flash_ReadStat2(void);
uint16_t FlashSend(uint16_t data);
bool FlashInit();
void EXFLASH_TEST(void);

 #endif