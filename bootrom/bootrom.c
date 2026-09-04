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

#include "commonutil.h"
#include "flash_code_apis.h"
#include "usb_cdc_apis.h"
#include "gpio_apis.h"
#include "sys_apis.h"
#include "ticks_apis.h"
#include "proxmark3_arm.h"

#ifdef WITH_FLASH
#include "flashmem.h"
#endif

#define DEBUG 0
// At present, in the case of at32 with a flash size of 4m byte, a sector is 4096 bytes.
// If there is a larger size sector in the future, remember to modify it here.
#define FLASH_MIN_UNIT_DATA_SIZE 4096

typedef struct {
    uint32_t count;
    uint32_t data[FLASH_MIN_UNIT_DATA_SIZE / sizeof(uint32_t)];
} flash_min_unit_data_t;

// An information segment memory shared between bootrom and osimage.
common_area_t g_common_area __attribute__((section(".commonarea")));
// The start address & end address of flash for writing.
uint32_t start_addr, end_addr;
// Is bootrom unlocked? if true, the bootrom can be overwritten.
bool bootrom_unlocked;
// Buffer the firmware block data from USB, and write it to FLASH once when the minimum write unit is reached.
flash_min_unit_data_t flash_min_unit_data;

// Define in link script(ld)
extern uint32_t _bootrom_start[], _bootrom_end[], _flash_start[], _flash_end[], __bss_start__[], __bss_end__[];
extern uint32_t _osimage_entry[], _stack_start[], _stack_end[];

// Send an old frame response packet.
static int reply_old(uint64_t cmd, uint64_t arg0, uint64_t arg1, uint64_t arg2, void *data, size_t len) {
    PacketResponseOLD txcmd;

    for (size_t i = 0; i < sizeof(PacketResponseOLD); i++)
        ((uint8_t *)&txcmd)[i] = 0x00;

    // Compose the outgoing command frame
    txcmd.cmd = cmd;
    txcmd.arg[0] = arg0;
    txcmd.arg[1] = arg1;
    txcmd.arg[2] = arg2;

    // Add the (optional) content to the frame, with a maximum size of PM3_CMD_DATA_SIZE_OLD
    if (data && len) {
        len = MIN(len, PM3_CMD_DATA_SIZE_OLD);
        for (size_t i = 0; i < len; i++) {
            txcmd.d.asBytes[i] = ((uint8_t *)data)[i];
        }
    }

    // Send frame and make sure all bytes are transmitted
    return usb_write((uint8_t *)&txcmd, sizeof(PacketResponseOLD));
}

// Check the table to see if the magic is valid.
// TODO DXL Reuse functions similar to CheckValidInformationMagic?
static bool is_valid_magic(int magic) {
    int magics[] = { VERSION_INFORMATION_MAGIC_PM3V, VERSION_INFORMATION_MAGIC_PM5V };
    for (int i = 0; i < ARRAYLEN(magics); i++) {
        if (magics[i] == magic) {
            return true;
        }
    }
    return false;
}

#if DEBUG
static void DbpString(char *str) {
    uint8_t len = 0;
    while (str[len] != 0x00) {
        len++;
    }
    reply_old(CMD_DEBUG_PRINT_STRING, len, 0, 0, (uint8_t *)str, len);
}
#endif

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
            arg0 = 0;
            arg0 = DEVICE_INFO_FLAG_BOOTROM_PRESENT |
                   DEVICE_INFO_FLAG_CURRENT_MODE_BOOTROM |
                   DEVICE_INFO_FLAG_UNDERSTANDS_START_FLASH |
                   DEVICE_INFO_FLAG_UNDERSTANDS_CHIP_INFO |
                   DEVICE_INFO_FLAG_UNDERSTANDS_VERSION |
                   DEVICE_INFO_FLAG_UNDERSTANDS_READ_MEM |
                   DEVICE_INFO_FLAG_UNDERSTANDS_CHIP_TYPE;

            if (g_common_area.flags.osimage_present) {
                arg0 |= DEVICE_INFO_FLAG_OSIMAGE_PRESENT;
            }

            reply_old(CMD_DEVICE_INFO, arg0, 1, 2, 0, 0);
        }
        break;

        case CMD_CHIP_INFO: {
            ack = false;
            arg0 = GetChipId();
            reply_old(CMD_CHIP_INFO, arg0, 0, 0, 0, 0);
        }
        break;

        case CMD_CHIP_TYPE: {
            ack = false;
            arg0 = GetChipType();
            reply_old(CMD_CHIP_TYPE, arg0, 0, 0, 0, 0);
        }
        break;

        case CMD_BL_VERSION: {
            ack = false;
            arg0 = BL_VERSION_1_0_0;
            reply_old(CMD_BL_VERSION, arg0, 0, 0, 0, 0);
        }
        break;

        case CMD_READ_MEM_DOWNLOAD: {
            ack = false;
            LED_B_ON();

            size_t offset = (size_t) c->arg[0];
            size_t count = (size_t) c->arg[1];
            uint32_t flags = (uint32_t) c->arg[2];

            bool isok = true;
            uint8_t *base = NULL;

            bool raw_address_mode = ((flags & READ_MEM_DOWNLOAD_FLAG_RAW) == READ_MEM_DOWNLOAD_FLAG_RAW);
            if (raw_address_mode == false) {

                base = (uint8_t *) _flash_start;

                size_t flash_size = GetChipFlashSize();

                // Boundary check the offset.
                if (offset > flash_size) {
                    isok = false;
                }

                // Clip the length if it goes past the end of the flash memory.
                count = MIN(count, flash_size - offset);

            } else {
                // Allow reading from any memory address and length in special 'raw' mode.
                base = NULL;
                // Boundary check against end of addressable space.
                if (offset > 0) {
                    count = MIN(count, -offset);
                }
            }

            if (isok) {
                for (size_t pos = 0; pos < count; pos += PM3_CMD_DATA_SIZE_OLD) {
                    size_t len = MIN((count - pos), PM3_CMD_DATA_SIZE_OLD);
                    isok = (0 == reply_old(CMD_READ_MEM_DOWNLOADED, pos, len, 0, &base[offset + pos], len));
                    if (!isok) {
                        break;
                    }
                }
            }

            if (isok) {
                reply_old(CMD_ACK, 1, 0, 0, 0, 0);
            } else {
                reply_old(CMD_NACK, 0, 0, 0, 0, 0);
            }

            LED_B_OFF();
            break;
        }

        case CMD_FINISH_WRITE: {

            // For this COMMAND Note
            // ---
            // 20260604: In older versions, the response arg1 was 0x00; in newer versions, it will be changed to PM3_E* error codes.
            // These codes are used to transmit specific error information to the client in cases such as out-of-bounds access;
            // they are unrelated to the FLASH error status.
            // ---

#if defined ICOPYX // ICopyX needs special parameters to unlock boot write.
            if (c->arg[1] != 0xff || c->arg[2] != 0x1fd) {
                // arg[1] must be 0xff, arg[2] must be 0x1fd
                // The reason why icopyx locks the boot is that the device cannot be used
                // due to the possibility of incorrect firmware flash. Because fpga and other hardware features are different.
                // If there is a better way to prevent the firmware from entering an inoperable state, this check is theoretically unnecessary.
                break;
            }
#endif
            // If a valid magic is passed in, we need to check if the magic is the same as the current firmware.
            if (is_valid_magic((int)c->arg[1]) && g_version_information.magic != c->arg[1]) {
                ack = false;
                reply_old(CMD_NACK, 0, PM3_EINVARG, 0, 0, 0);
                break;
            }
            // Get current flash min erase/write unit of platform in bytes(not u32).
            const uint16_t flash_ew_unit = FlashCodeGetEWMinUnit();
            const uint16_t flash_ew_unit_u32 = flash_ew_unit / sizeof(uint32_t); // count of min erase/write unit(u32)
            // The fixed data payload is 512 bytes, which is 128 u32.
            const uint16_t usb_payload_u32_len = sizeof(c->d) / sizeof(uint32_t);
            // Copy data from usb to flash_min_unit_data buffer. A single usb payload may hold more
            // than one erase/write unit (e.g. AT91 pages of 256 bytes), so always copy it in and flush
            // the whole units below instead of assuming the payload is no larger than one unit.
            bool copy_overflow = false;
            for (int i = 0; i < usb_payload_u32_len; i++) {
                // Check data buffer is no overflow.
                if (flash_min_unit_data.count >= ARRAYLEN(flash_min_unit_data.data)) {
                    copy_overflow = true;
                    break;
                }
                flash_min_unit_data.data[flash_min_unit_data.count++] = c->d.asDwords[i];
            }
            if (copy_overflow) {
                ack = false;
                flash_min_unit_data.count = 0;
                reply_old(CMD_NACK, 0, PM3_EOVFLOW, 0, 0, 0);
                break;
            }
            // How many min unit are stored in the data buffer?
            const uint16_t flash_unit_num_u32 = flash_min_unit_data.count / flash_ew_unit_u32;
            for (int idx_unit = 0; idx_unit < flash_unit_num_u32; idx_unit++) {
                // Calculate the write start address of the new flash unit.
                uint32_t flash_address = arg0 + idx_unit * flash_ew_unit;
                // Check that the address that we are supposed to write to is within our allowed region
                if (((flash_address + flash_ew_unit - 1) >= end_addr) || (flash_address < start_addr)) {
                    ack = false; // Disallow write
                    reply_old(CMD_NACK, 0, PM3_EOUTOFBOUND, 0, 0, 0);
                    break;
                }
                uint32_t *flash_min_unit_addr = &flash_min_unit_data.data[idx_unit * flash_ew_unit_u32];
                // Call the cross-platform flash api to write firmware to flash.
                uint32_t status = 0x00;
                bool isok = FlashCodeEWriteMinUnit(flash_address, flash_min_unit_addr, _flash_start, &status);
                if (!isok) {
                    ack = false;
                    reply_old(CMD_NACK, status, 0, 0, 0, 0);
                    break;
                }
            }
            if (ack) {
                // After flushing whole units, keep the remaining partial unit for the next transfer.
                flash_min_unit_data.count %= flash_ew_unit_u32;
            } else {
                flash_min_unit_data.count = 0; // Discard buffered data after a failed write.
            }
        }
        break;

        case CMD_HARDWARE_RESET: {
            usb_disable();
            ResetChip();
        }
        break;

        case CMD_START_FLASH: {
            if (c->arg[2] == START_FLASH_MAGIC)
                bootrom_unlocked = true;
            else
                bootrom_unlocked = false;

            uint32_t cmd_start = c->arg[0]; // code flash start address
            uint32_t cmd_end = c->arg[1];   // code flash end address

            /*
             * Only allow command if the bootrom is unlocked, or the parameters are outside of the protected
             * bootrom area. In any case they must be within the flash area.
             */
            if ((bootrom_unlocked || ((cmd_start >= (uint32_t)_bootrom_end) || (cmd_end < (uint32_t)_bootrom_start))) &&
                    (cmd_start >= (uint32_t)_flash_start) &&
                    (cmd_end <= (uint32_t)_flash_end)) {
                start_addr = cmd_start;
                end_addr = cmd_end;
            } else {
                start_addr = end_addr = 0;
                flash_min_unit_data.count = 0;
                // In this command, flasher.c does not care what arg0 is;
                // it considers the process to have failed as long as a NACK response is received.
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

    if (ack) {
        reply_old(CMD_ACK, arg0, 0, 0, 0, 0);
    }
}

static void flash_mode(void) {
    start_addr = 0;
    end_addr = 0;
    bootrom_unlocked = false;
    flash_min_unit_data.count = 0;
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
    SpinDelayUs(300 * 1000); // Wait for 300ms

    for (;;) {
        WDT_HIT();

        // Check if there is a usb packet available
        if (usb_poll_validate_length()) {
            if (usb_read(rx, sizeof(rx))) {
                UsbPacketReceived(rx);
            }
        }

        bool button_state = BUTTON_PRESS();
        SpinDelayUs(10000); // ~10ms, prevent jitter
        if (button_state != BUTTON_PRESS()) {
            // in jitter state, ignore
            continue;
        }
        if (g_common_area.flags.button_pressed && button_state == false) {
            g_common_area.flags.button_pressed = 0;
        }
        if (!g_common_area.flags.button_pressed && button_state) {
            /* Perform a reset to leave flash mode */
            g_common_area.flags.button_pressed = 1;
            usb_disable();
            LED_B_ON();
            ResetChip();
            for (;;) {};
        }
    }
}

// On PM5 the button is also the power button, so a press at power up is not by
// itself a request for the bootloader and has to be qualified by a hold.
#ifdef PM5
#define BOOTROM_BUTTON_HOLD_MS  3000
#else
#define BOOTROM_BUTTON_HOLD_MS  0
#endif

static bool check_goto_flash_mode(void) {
    int common_area_present = 0;
    // Check if RESET is SRAM retention? if not, the content of g_common_area in RAM is not reliable, must to init.
    if (CheckRSTWithSRAMRetention()) {
        // In these cases the g_common_area in RAM should be ok, retain it if it's there
        if (g_common_area.magic == COMMON_AREA_MAGIC && g_common_area.version == 1) {
            common_area_present = 1;
        }
    }

    if (!common_area_present) {
        /* Common area not ok, initialize it */
        size_t i;
        /* Makeshift memset, no need to drag util.c into this */
        for (i = 0; i < sizeof(g_common_area); i++) {
            ((char *)&g_common_area)[i] = 0;
        }

        g_common_area.magic = COMMON_AREA_MAGIC;
        g_common_area.version = 1;
    }
    g_common_area.flags.bootrom_present = 1;

    // Handle the event of button startup separately.
    bool to_flash_mode = false;
    if (g_common_area.flags.button_pressed == 0 && BUTTON_PRESS()) {

        to_flash_mode = true;
        
        if (BOOTROM_BUTTON_HOLD_MS > 0) {
            for (int16_t ms = 0; ms < BOOTROM_BUTTON_HOLD_MS; ms++) {
                if (BUTTON_PRESS() == false) {
                    to_flash_mode = false; // released too early, this was not a bootloader request
                    break;
                }
                SpinDelayUs(1000); // 1ms
            }
        }
    }

    // Checked whatever the button did
    if (to_flash_mode == false) {
        if ((g_common_area.command == COMMON_AREA_COMMAND_ENTER_FLASH_MODE) || (*_osimage_entry == 0xffffffffU)) {
            to_flash_mode = true;
        }
    }

    return to_flash_mode;
}

void BootROM(void);
void BootROM(void) {
    // __BKPT(0); // For debug

    /* Set up (that is: clear) BSS. */
    uint32_t *bss_dst = __bss_start__;
    while (bss_dst < __bss_end__) *bss_dst++ = 0;

    //------------
    // First set up all the I/O pins; GPIOs configured directly, other ones
    // just need to be assigned to the appropriate peripheral.
    gpio_sysboot_setup();

    // Turn off all leds
    LED_A_OFF();
    LED_B_OFF();
    LED_C_OFF();
    LED_D_OFF();

    // USB_D_PLUS_PULLUP_OFF();
    usb_disable();

    // Initialize the FLASH area for firmware/code.
    FlashCodeInit();

    // Initialize all system clocks
    ConfigSystemClocks();

    // Light C before the decision
    LED_C_ON();

    // Check whether to enter the FLASH mode.
    const bool to_flash_mode = check_goto_flash_mode();

    LED_A_ON();

    // Keep running in BOOT or jump to App image?
    if (to_flash_mode) {
        flash_mode();
    } else {
        // clear button status, even if button still pressed
        g_common_area.flags.button_pressed = 0;
        // jump to OS image
        JumpToAnyImage((uint32_t)_stack_end, (uint32_t)_osimage_entry);
    }
}
