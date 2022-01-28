//-----------------------------------------------------------------------------
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
// Hardware and interface definitions
//-----------------------------------------------------------------------------

#ifndef __PROXMARK3_H
#define __PROXMARK3_H

#include "common.h"

// Might as well have the hardware-specific defines everywhere.
#include "at91sam7s512.h"
#include "config_gpio.h"
#include "pm3_cmd.h"

// Check bootrom.c for actual clock settings
#define MAINCK                                  16000000
#define MCK                                     (3 * MAINCK)

#define WDT_HIT()                               AT91C_BASE_WDTC->WDTC_WDCR = 0xa5000001

#define PWM_CH_MODE_PRESCALER(x)                ((x) << 0)
#define PWM_CHANNEL(x)                          (1 << (x))

#define ADC_CHAN_LF                             4
#if defined RDV4 || defined ICOPYX
#define ADC_CHAN_HF                             7
#else
#define ADC_CHAN_HF                             5
#endif
#define ADC_MODE_PRESCALE(x)                    ((x) << 8)
#define ADC_MODE_STARTUP_TIME(x)                ((x) << 16)
#define ADC_MODE_SAMPLE_HOLD_TIME(x)            ((x) << 24)
#define ADC_CHANNEL(x)                          (1 << (x))
#define ADC_END_OF_CONVERSION(x)                (1 << (x))

#define SSC_CLOCK_MODE_START(x)                 ((x) << 8)
#define SSC_FRAME_MODE_WORDS_PER_TRANSFER(x)    ((x) << 8)
#define SSC_CLOCK_MODE_SELECT(x)                ((x) << 0)
#define SSC_FRAME_MODE_BITS_IN_WORD(x)          (((x)-1) << 0)

#define MC_FLASH_COMMAND_KEY                    ((0x5A) << 24)
#define MC_FLASH_MODE_FLASH_WAIT_STATES(x)      ((x) << 8)
#define MC_FLASH_MODE_MASTER_CLK_IN_MHZ(x)      (((x)+((x)/2)) << 16)
#define MC_FLASH_COMMAND_PAGEN(x)               ((x) << 8)

#define RST_CONTROL_KEY                         (0xA5U << 24)

#define PMC_MAIN_OSC_STARTUP_DELAY(x)           ((x) << 8)
#define PMC_PLL_DIVISOR(x)                      (x)
#define PMC_PLL_MULTIPLIER(x)                   (((x)-1) << 16)
#define PMC_PLL_COUNT_BEFORE_LOCK(x)            (((x) & 0x3F) << 8)        // 6bit register 0011 1111
#define PMC_PLL_FREQUENCY_RANGE(x)              (((x) & 0x3) << 14)        // 2bit register
#define PMC_PLL_USB_DIVISOR(x)                  ((x) << 28)

#define UDP_INTERRUPT_ENDPOINT(x)               (1 << (x))
#define UDP_CSR_BYTES_RECEIVED(x)               (((x) >> 16) & 0x7ff)
//**************************************************************



#define LOW(x)      AT91C_BASE_PIOA->PIO_CODR |= (x)
#define HIGH(x)     AT91C_BASE_PIOA->PIO_SODR |= (x)

#define GETBIT(x)   (AT91C_BASE_PIOA->PIO_ODSR & (x)) ? 1:0
#define SETBIT(x, y) (y) ? (HIGH(x)):(LOW(x))
#define INVBIT(x)   SETBIT((x), !(GETBIT(x)))

// Setup for SPI current modes
#define SPI_FPGA_MODE   0
#define SPI_LCD_MODE    1
#define SPI_MEM_MODE    2

#ifndef COTAG_BITS
#define COTAG_BITS 264
#endif

#define LED_A_ON()        HIGH(GPIO_LED_A)
#define LED_A_OFF()       LOW(GPIO_LED_A)
#define LED_A_INV()       INVBIT(GPIO_LED_A)
#define LED_B_ON()        HIGH(GPIO_LED_B)
#define LED_B_OFF()       LOW(GPIO_LED_B)
#define LED_B_INV()       INVBIT(GPIO_LED_B)
#define LED_C_ON()        HIGH(GPIO_LED_C)
#define LED_C_OFF()       LOW(GPIO_LED_C)
#define LED_C_INV()       INVBIT(GPIO_LED_C)
#define LED_D_ON()        HIGH(GPIO_LED_D)
#define LED_D_OFF()       LOW(GPIO_LED_D)
#define LED_D_INV()       INVBIT(GPIO_LED_D)


// SPI
#define SCK_LOW           LOW(GPIO_SPCK)
#define SCK_HIGH          HIGH(GPIO_SPCK)
#define MOSI_HIGH         HIGH(GPIO_MOSI)
#define MOSI_LOW          LOW(GPIO_MOSI)
#define MISO_VALUE        (AT91C_BASE_PIOA->PIO_PDSR & GPIO_MISO)

// fpga
#define NCS_0_LOW         LOW(GPIO_NCS0)
#define NCS_0_HIGH        HIGH(GPIO_NCS0)

// flash mem PA1
#define NCS_1_LOW         LOW(GPIO_NCS2)
#define NCS_1_HIGH        HIGH(GPIO_NCS2)

#define RELAY_ON()        HIGH(GPIO_RELAY)
#define RELAY_OFF()       LOW(GPIO_RELAY)

#define BUTTON_PRESS()         !((AT91C_BASE_PIOA->PIO_PDSR & GPIO_BUTTON) == GPIO_BUTTON)
#define WAIT_BUTTON_RELEASED() { while ( BUTTON_PRESS() )  { WDT_HIT(); }; }

//NVDD goes LOW when USB is attached.
#define USB_ATTACHED()    !((AT91C_BASE_PIOA->PIO_PDSR & GPIO_NVDD_ON) == GPIO_NVDD_ON)

// VERSION_INFORMATION is now in common.h

#define COMMON_AREA_MAGIC 0x43334d50 // "PM3C"
#define COMMON_AREA_COMMAND_NONE 0
#define COMMON_AREA_COMMAND_ENTER_FLASH_MODE 1
typedef struct {
    int magic; /* Magic sequence, to distinguish against random uninitialized memory */
    char version; /* Must be 1 */
    char command;
    struct {
        unsigned int bootrom_present: 1; /* Set when a bootrom that is capable of parsing the common area is present */
        unsigned int osimage_present: 1; /* Set when a osimage that is capable of parsing the common area is present */
        unsigned int button_pressed: 1;
    } PACKED flags;
    int arg1, arg2;
} PACKED common_area_t;

#endif
