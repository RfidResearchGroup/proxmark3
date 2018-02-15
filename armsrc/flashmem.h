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

#define	MANID        0x90
#define PAGEPROG     0x02
#define READDATA     0x03
#define FASTREAD     0x0B
#define WRITEDISABLE 0x04
#define READSTAT1    0x05
#define READSTAT2    0x35
#define WRITESTAT    0x01
#define WRITEENABLE  0x06
#define SECTORERASE  0x20
#define BLOCK32ERASE 0x52
#define CHIPERASE    0xC7
#define SUSPEND      0x75
#define ID           0x90
#define RESUME       0x7A
#define JEDECID      0x9F
#define RELEASE      0xAB
#define POWERDOWN    0xB9
#define BLOCK64ERASE 0xD8
#define ENABLE_RESET 0x66
#define RESET        0x99

//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~//
//					Chip specific instructions 						  //
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~//

//~~~~~~~~~~~~~~~~~~~~~~~~~ Winbond ~~~~~~~~~~~~~~~~~~~~~~~~~//
#define WINBOND_MANID	 0xEF
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
//                    Arduino Due DMA definitions                     //
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~//
// Use SAM3X DMAC if nonzero
#define USE_SAM3X_DMAC 1
// Use extra Bus Matrix arbitration fix if nonzero
#define USE_SAM3X_BUS_MATRIX_FIX 0
// Time in ms for DMA receive timeout
#define SAM3X_DMA_TIMEOUT 100
// chip select register number
#define SPI_CHIP_SEL 3
// DMAC receive channel
#define SPI_DMAC_RX_CH  1
// DMAC transmit channel
#define SPI_DMAC_TX_CH  0
// DMAC Channel HW Interface Number for SPI TX.
#define SPI_TX_IDX  1
// DMAC Channel HW Interface Number for SPI RX.
#define SPI_RX_IDX  2
// Set DUE SPI clock div (any integer from 2 - 255)
#define DUE_SPI_CLK 2
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

 uint8_t 	EXFLASH_spi_write_read(uint8_t wData);
 uint8_t 	EXFLASH_readStat1(void) ;
 uint8_t 	EXFLASH_readStat2(void) ;
 bool    	EXFLASH_NOTBUSY(void);
 void    	EXFLASH_Write_Enable(void) ;
 uint8_t    EXFLASH_Read(uint8_t *address, uint16_t len);
 uint8_t    EXFLASH_Program(uint8_t address[], uint8_t *array, uint8_t len) ;

 uint8_t 	EXFLASH_ReadID(void) ;
 bool    	EXFLASH_Erase(void) ;
 bool    	EXFLASH_Reset(void);
 void    	EXFLASH_Init(void);
 void    	EXFLASH_TEST(void);

 #endif