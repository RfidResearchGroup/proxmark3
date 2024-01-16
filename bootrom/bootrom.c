//-----------------------------------------------------------------------------
// Copyright (C) Jonathan Westhues, Mar 2006
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
// Main code for the bootloader
//-----------------------------------------------------------------------------

#include "clocks.h"
#include "usb_cdc.h"

#ifdef WITH_FLASH
#include "flashmem.h"
#endif

#include "proxmark3_arm.h"
#define DEBUG 0

common_area_t g_common_area __attribute__((section(".commonarea")));
uint32_t start_addr, end_addr;
bool bootrom_unlocked;
extern uint32_t _bootrom_start[], _bootrom_end[], _flash_start[], _flash_end[], _osimage_entry[];

static int reply_old(uint64_t cmd, uint64_t arg0, uint64_t arg1, uint64_t arg2, void *data, size_t len) {
    PacketResponseOLD txcmd;

    for (size_t i = 0; i < sizeof(PacketResponseOLD); i++)
        ((uint8_t *)&txcmd)[i] = 0x00;

    // Compose the outgoing command frame
    txcmd.cmd = cmd;
    txcmd.arg[0] = arg0;
    txcmd.arg[1] = arg1;
    txcmd.arg[2] = arg2;

    // Add the (optional) content to the frame, with a maximum size of PM3_CMD_DATA_SIZE
    if (data && len) {
        len = MIN(len, PM3_CMD_DATA_SIZE);
        for (size_t i = 0; i < len; i++) {
            txcmd.d.asBytes[i] = ((uint8_t *)data)[i];
        }
    }

    // Send frame and make sure all bytes are transmitted
    return usb_write((uint8_t *)&txcmd, sizeof(PacketResponseOLD));
}

#if DEBUG
static void DbpString(char *str) {
    uint8_t len = 0;
    while (str[len] != 0x00)
        len++;

    reply_old(CMD_DEBUG_PRINT_STRING, len, 0, 0, (uint8_t *)str, len);
}
#endif

static void ConfigClocks(void) {
    // we are using a 16 MHz crystal as the basis for everything
    // slow clock runs at 32kHz typical regardless of crystal

    // enable system clock and USB clock
    AT91C_BASE_PMC->PMC_SCER |= AT91C_PMC_PCK | AT91C_PMC_UDP;

    // enable the clock to the following peripherals
    AT91C_BASE_PMC->PMC_PCER =
        (1 << AT91C_ID_PIOA)   |
        (1 << AT91C_ID_ADC)    |
        (1 << AT91C_ID_SPI)    |
        (1 << AT91C_ID_SSC)    |
        (1 << AT91C_ID_PWMC)   |
        (1 << AT91C_ID_UDP);

    mck_from_slck_to_pll();
}

static void Fatal(void) {
    for (;;) {};
}

static void UsbPacketReceived(uint8_t *packet) {
    bool ack = true;
    PacketCommandOLD *c = (PacketCommandOLD *)packet;

    //if ( len != sizeof(PacketCommandOLD`)) Fatal();

    uint32_t arg0 = (uint32_t)c->arg[0];

    switch (c->cmd) {
        case CMD_DEVICE_INFO: {
            ack = false;
            arg0 = DEVICE_INFO_FLAG_BOOTROM_PRESENT |
                   DEVICE_INFO_FLAG_CURRENT_MODE_BOOTROM |
                   DEVICE_INFO_FLAG_UNDERSTANDS_START_FLASH |
                   DEVICE_INFO_FLAG_UNDERSTANDS_CHIP_INFO |
                   DEVICE_INFO_FLAG_UNDERSTANDS_VERSION;
            if (g_common_area.flags.osimage_present)
                arg0 |= DEVICE_INFO_FLAG_OSIMAGE_PRESENT;

            reply_old(CMD_DEVICE_INFO, arg0, 1, 2, 0, 0);
        }
        break;

        case CMD_CHIP_INFO: {
            ack = false;
            arg0 = *(AT91C_DBGU_CIDR);
            reply_old(CMD_CHIP_INFO, arg0, 0, 0, 0, 0);
        }
        break;

        case CMD_BL_VERSION: {
            ack = false;
            arg0 = BL_VERSION_1_0_0;
            reply_old(CMD_BL_VERSION, arg0, 0, 0, 0, 0);
        }
        break;

        case CMD_FINISH_WRITE: {
#if defined ICOPYX
            if (c->arg[1] == 0xff && c->arg[2] == 0x1fd) {
#endif
                for (int j = 0; j < 2; j++) {
                    uint32_t flash_address = arg0 + (0x100 * j);
                    AT91PS_EFC efc_bank = AT91C_BASE_EFC0;
                    int offset = 0;
                    uint32_t page_n = (flash_address - (uint32_t)_flash_start) / AT91C_IFLASH_PAGE_SIZE;
                    if (page_n >= AT91C_IFLASH_NB_OF_PAGES / 2) {
                        page_n -= AT91C_IFLASH_NB_OF_PAGES / 2;
                        efc_bank = AT91C_BASE_EFC1;
                        // We need to offset the writes or it will not fill the correct bank write buffer.
                        offset = (AT91C_IFLASH_NB_OF_PAGES / 2) * AT91C_IFLASH_PAGE_SIZE / sizeof(uint32_t);
                    }
                    for (int i = 0 + (64 * j); i < 64 + (64 * j); i++) {
                        _flash_start[offset + i] = c->d.asDwords[i];
                    }

                    /* Check that the address that we are supposed to write to is within our allowed region */
                    if (((flash_address + AT91C_IFLASH_PAGE_SIZE - 1) >= end_addr) || (flash_address < start_addr)) {
                        /* Disallow write */
                        ack = false;
                        reply_old(CMD_NACK, 0, 0, 0, 0, 0);
                    } else {

                        efc_bank->EFC_FCR = MC_FLASH_COMMAND_KEY |
                                            MC_FLASH_COMMAND_PAGEN(page_n) |
                                            AT91C_MC_FCMD_START_PROG;
                    }

                    // Wait until flashing of page finishes
                    uint32_t sr;
                    while (!((sr = efc_bank->EFC_FSR) & AT91C_MC_FRDY));
                    if (sr & (AT91C_MC_LOCKE | AT91C_MC_PROGE)) {
                        ack = false;
                        reply_old(CMD_NACK, sr, 0, 0, 0, 0);
                    }
                }
#if defined ICOPYX
            }
#endif
        }
        break;

        case CMD_HARDWARE_RESET: {
            usb_disable();
            AT91C_BASE_RSTC->RSTC_RCR = RST_CONTROL_KEY | AT91C_RSTC_PROCRST;
        }
        break;

        case CMD_START_FLASH: {
            if (c->arg[2] == START_FLASH_MAGIC)
                bootrom_unlocked = true;
            else
                bootrom_unlocked = false;

            uint32_t cmd_start = c->arg[0];
            uint32_t cmd_end = c->arg[1];

            /* Only allow command if the bootrom is unlocked, or the parameters are outside of the protected
            * bootrom area. In any case they must be within the flash area.
            */
            if ((bootrom_unlocked || ((cmd_start >= (uint32_t)_bootrom_end) || (cmd_end < (uint32_t)_bootrom_start))) &&
                    (cmd_start >= (uint32_t)_flash_start) &&
                    (cmd_end <= (uint32_t)_flash_end)) {
                start_addr = cmd_start;
                end_addr = cmd_end;
            } else {
                start_addr = end_addr = 0;
                ack = false;
                reply_old(CMD_NACK, 0, 0, 0, 0, 0);
            }
        }
        break;

        default: {
            Fatal();
        }
        break;
    }

    if (ack)
        reply_old(CMD_ACK, arg0, 0, 0, 0, 0);
}

static void flash_mode(void) {
    start_addr = 0;
    end_addr = 0;
    bootrom_unlocked = false;
    uint8_t rx[sizeof(PacketCommandOLD)];
    g_common_area.command = COMMON_AREA_COMMAND_NONE;
    if (!g_common_area.flags.button_pressed && BUTTON_PRESS()) {
        g_common_area.flags.button_pressed = 1;
    }

#ifdef WITH_FLASH
    if (FlashInit()) { // checks for existence of flash also ... OK because bootrom was built for devices with flash
        uint64_t flash_uniqueID = 0;
        Flash_UniqueID((uint8_t *)&flash_uniqueID);
        FlashStop();
        usb_update_serial(flash_uniqueID);
    }
#endif

    usb_enable();

    // wait for reset to be complete?
    for (volatile size_t i = 0; i < 0x100000; i++) {};

    for (;;) {
        WDT_HIT();

        // Check if there is a usb packet available
        if (usb_poll_validate_length()) {
            if (usb_read(rx, sizeof(rx))) {
                UsbPacketReceived(rx);
            }
        }

        if (g_common_area.flags.button_pressed && BUTTON_PRESS() == false) {
            g_common_area.flags.button_pressed = 0;
        }
        if (!g_common_area.flags.button_pressed && BUTTON_PRESS()) {
            /* Perform a reset to leave flash mode */
            g_common_area.flags.button_pressed = 1;
            usb_disable();
            LED_B_ON();
            AT91C_BASE_RSTC->RSTC_RCR = RST_CONTROL_KEY | AT91C_RSTC_PROCRST;
            for (;;) {};
        }
    }
}

void BootROM(void);
void BootROM(void) {
    //------------
    // First set up all the I/O pins; GPIOs configured directly, other ones
    // just need to be assigned to the appropriate peripheral.

    // Kill all the pullups, especially the one on USB D+; leave them for
    // the unused pins, though.
    AT91C_BASE_PIOA->PIO_PPUDR =
        GPIO_USB_PU         |
        GPIO_LED_A          |
        GPIO_LED_B          |
        GPIO_LED_C          |
        GPIO_LED_D          |
        GPIO_FPGA_DIN       |
        GPIO_FPGA_DOUT      |
        GPIO_FPGA_CCLK      |
        GPIO_FPGA_NINIT     |
        GPIO_FPGA_NPROGRAM  |
        GPIO_FPGA_DONE      |
        GPIO_MUXSEL_HIPKD   |
        GPIO_MUXSEL_HIRAW   |
        GPIO_MUXSEL_LOPKD   |
        GPIO_MUXSEL_LORAW   |
        GPIO_RELAY          |
        GPIO_NVDD_ON;
    // (and add GPIO_FPGA_ON)
    // These pins are outputs
    AT91C_BASE_PIOA->PIO_OER =
        GPIO_LED_A          |
        GPIO_LED_B          |
        GPIO_LED_C          |
        GPIO_LED_D          |
        GPIO_RELAY          |
        GPIO_NVDD_ON;
    // PIO controls the following pins
    AT91C_BASE_PIOA->PIO_PER =
        GPIO_USB_PU         |
        GPIO_LED_A          |
        GPIO_LED_B          |
        GPIO_LED_C          |
        GPIO_LED_D;

    // USB_D_PLUS_PULLUP_OFF();
    usb_disable();
    LED_D_OFF();
    LED_C_ON();
    LED_B_OFF();
    LED_A_OFF();

    // Set the first 256KB memory flashspeed
    AT91C_BASE_EFC0->EFC_FMR = AT91C_MC_FWS_1FWS | MC_FLASH_MODE_MASTER_CLK_IN_MHZ(48);

    // 9 = 256, 10+ is 512KB
    uint8_t id = (*(AT91C_DBGU_CIDR) & 0xF00) >> 8;
    if (id > 9)
        AT91C_BASE_EFC1->EFC_FMR = AT91C_MC_FWS_1FWS | MC_FLASH_MODE_MASTER_CLK_IN_MHZ(48);

    // Initialize all system clocks
    ConfigClocks();

    LED_A_ON();

    int g_common_area_present = 0;
    switch (AT91C_BASE_RSTC->RSTC_RSR & AT91C_RSTC_RSTTYP) {
        case AT91C_RSTC_RSTTYP_WATCHDOG:
        case AT91C_RSTC_RSTTYP_SOFTWARE:
        case AT91C_RSTC_RSTTYP_USER:
            /* In these cases the g_common_area in RAM should be ok, retain it if it's there */
            if (g_common_area.magic == COMMON_AREA_MAGIC && g_common_area.version == 1)
                g_common_area_present = 1;
            break;
        default: /* Otherwise, initialize it from scratch */
            break;
    }

    if (!g_common_area_present) {
        /* Common area not ok, initialize it */
        size_t i;
        /* Makeshift memset, no need to drag util.c into this */
        for (i = 0; i < sizeof(g_common_area); i++)
            ((char *)&g_common_area)[i] = 0;

        g_common_area.magic = COMMON_AREA_MAGIC;
        g_common_area.version = 1;
    }
    g_common_area.flags.bootrom_present = 1;

    if ((g_common_area.command == COMMON_AREA_COMMAND_ENTER_FLASH_MODE) ||
            (!g_common_area.flags.button_pressed && BUTTON_PRESS()) ||
            (*_osimage_entry == 0xffffffffU)) {
        flash_mode();
    } else {
        // clear button status, even if button still pressed
        g_common_area.flags.button_pressed = 0;
        // jump to Flash address of the osimage entry point (LSBit set for thumb mode)
        __asm("bx %0\n" : : "r"(((uint32_t)_osimage_entry) | 0x1));
    }
}
