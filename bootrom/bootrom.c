//-----------------------------------------------------------------------------
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Main code for the bootloader
//-----------------------------------------------------------------------------

#include <proxmark3.h>
#include "usb_cdc.h"

struct common_area common_area __attribute__((section(".commonarea")));
unsigned int start_addr, end_addr, bootrom_unlocked;
extern char _bootrom_start, _bootrom_end, _flash_start, _flash_end;
extern uint32_t _osimage_entry;

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

    int result = PM3_EUNDEF;
    // Send frame and make sure all bytes are transmitted

    result = usb_write((uint8_t *)&txcmd, sizeof(PacketResponseOLD));

    return result;
}

void DbpString(char *str) {
    uint8_t len = 0;
    while (str[len] != 0x00)
        len++;

    reply_old(CMD_DEBUG_PRINT_STRING, len, 0, 0, (uint8_t *)str, len);
}

static void ConfigClocks(void) {
    // we are using a 16 MHz crystal as the basis for everything
    // slow clock runs at 32Khz typical regardless of crystal

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

    // worst case scenario, with MAINCK = 16Mhz xtal, startup delay is 1.4ms
    // if SLCK slow clock runs at its worst case (max) frequency of 42khz
    // max startup delay = (1.4ms*42k)/8 = 7.356 so round up to 8

    // enable main oscillator and set startup delay
    AT91C_BASE_PMC->PMC_MOR =
        AT91C_CKGR_MOSCEN |
        PMC_MAIN_OSC_STARTUP_DELAY(8);

    // wait for main oscillator to stabilize
    while (!(AT91C_BASE_PMC->PMC_SR & AT91C_PMC_MOSCS)) {};

    // PLL output clock frequency in range  80 - 160 MHz needs CKGR_PLL = 00
    // PLL output clock frequency in range 150 - 180 MHz needs CKGR_PLL = 10
    // PLL output is MAINCK * multiplier / divisor = 16Mhz * 12 / 2 = 96Mhz
    AT91C_BASE_PMC->PMC_PLLR =
        PMC_PLL_DIVISOR(2) |
        //PMC_PLL_COUNT_BEFORE_LOCK(0x10) |
        PMC_PLL_COUNT_BEFORE_LOCK(0x3F) |
        PMC_PLL_FREQUENCY_RANGE(0) |
        PMC_PLL_MULTIPLIER(12) |
        PMC_PLL_USB_DIVISOR(1);

    // wait for PLL to lock
    while (!(AT91C_BASE_PMC->PMC_SR & AT91C_PMC_LOCK)) {};

    // we want a master clock (MCK) to be PLL clock / 2 = 96Mhz / 2 = 48Mhz
    // datasheet recommends that this register is programmed in two operations
    // when changing to PLL, program the prescaler first then the source
    AT91C_BASE_PMC->PMC_MCKR = AT91C_PMC_PRES_CLK_2;

    // wait for main clock ready signal
    while (!(AT91C_BASE_PMC->PMC_SR & AT91C_PMC_MCKRDY)) {};

    // set the source to PLL
    AT91C_BASE_PMC->PMC_MCKR = AT91C_PMC_PRES_CLK_2 | AT91C_PMC_CSS_PLL_CLK;

    // wait for main clock ready signal
    while (!(AT91C_BASE_PMC->PMC_SR & AT91C_PMC_MCKRDY)) {};
}

static void Fatal(void) {
    for (;;) {};
}

void UsbPacketReceived(uint8_t *packet, int len) {
    int i, dont_ack = 0;
    PacketCommandOLD *c = (PacketCommandOLD *)packet;

    //if ( len != sizeof(PacketCommandOLD`)) Fatal();

    uint32_t arg0 = (uint32_t)c->arg[0];

    switch (c->cmd) {
        case CMD_DEVICE_INFO: {
            dont_ack = 1;
            arg0 = DEVICE_INFO_FLAG_BOOTROM_PRESENT | DEVICE_INFO_FLAG_CURRENT_MODE_BOOTROM |
                   DEVICE_INFO_FLAG_UNDERSTANDS_START_FLASH;
            if (common_area.flags.osimage_present)
                arg0 |= DEVICE_INFO_FLAG_OSIMAGE_PRESENT;

            reply_old(CMD_DEVICE_INFO, arg0, 1, 2, 0, 0);
        }
        break;

        case CMD_SETUP_WRITE: {
            /* The temporary write buffer of the embedded flash controller is mapped to the
            * whole memory region, only the last 8 bits are decoded.
            */
            volatile uint32_t *p = (volatile uint32_t *)&_flash_start;
            for (i = 0; i < 12; i++)
                p[i + arg0] = c->d.asDwords[i];
        }
        break;

        case CMD_FINISH_WRITE: {
            uint32_t *flash_mem = (uint32_t *)(&_flash_start);
            for (int j = 0; j < 2; j++) {
                for (i = 0 + (64 * j); i < 64 + (64 * j); i++) {
                    flash_mem[i] = c->d.asDwords[i];
                }

                uint32_t flash_address = arg0 + (0x100 * j);

                /* Check that the address that we are supposed to write to is within our allowed region */
                if (((flash_address + AT91C_IFLASH_PAGE_SIZE - 1) >= end_addr) || (flash_address < start_addr)) {
                    /* Disallow write */
                    dont_ack = 1;
                    reply_old(CMD_NACK, 0, 0, 0, 0, 0);
                } else {
                    uint32_t page_n = (flash_address - ((uint32_t)flash_mem)) / AT91C_IFLASH_PAGE_SIZE;
                    /* Translate address to flash page and do flash, update here for the 512k part */
                    AT91C_BASE_EFC0->EFC_FCR = MC_FLASH_COMMAND_KEY |
                                               MC_FLASH_COMMAND_PAGEN(page_n) |
                                               AT91C_MC_FCMD_START_PROG;
                }

                // Wait until flashing of page finishes
                uint32_t sr;
                while (!((sr = AT91C_BASE_EFC0->EFC_FSR) & AT91C_MC_FRDY));
                if (sr & (AT91C_MC_LOCKE | AT91C_MC_PROGE)) {
                    dont_ack = 1;
                    reply_old(CMD_NACK, sr, 0, 0, 0, 0);
                }
            }
        }
        break;

        case CMD_HARDWARE_RESET: {
            usb_disable();
            AT91C_BASE_RSTC->RSTC_RCR = RST_CONTROL_KEY | AT91C_RSTC_PROCRST;
        }
        break;

        case CMD_START_FLASH: {
            if (c->arg[2] == START_FLASH_MAGIC)
                bootrom_unlocked = 1;
            else
                bootrom_unlocked = 0;

            int prot_start = (int)&_bootrom_start;
            int prot_end = (int)&_bootrom_end;
            int allow_start = (int)&_flash_start;
            int allow_end = (int)&_flash_end;
            int cmd_start = c->arg[0];
            int cmd_end = c->arg[1];

            /* Only allow command if the bootrom is unlocked, or the parameters are outside of the protected
            * bootrom area. In any case they must be within the flash area.
            */
            if ((bootrom_unlocked || ((cmd_start >= prot_end) || (cmd_end < prot_start))) &&
                    (cmd_start >= allow_start) &&
                    (cmd_end <= allow_end)) {
                start_addr = cmd_start;
                end_addr = cmd_end;
            } else {
                start_addr = end_addr = 0;
                dont_ack = 1;
                reply_old(CMD_NACK, 0, 0, 0, 0, 0);
            }
        }
        break;

        default: {
            Fatal();
        }
        break;
    }

    if (!dont_ack)
        reply_old(CMD_ACK, arg0, 0, 0, 0, 0);
}

static void flash_mode(void) {
    start_addr = 0;
    end_addr = 0;
    bootrom_unlocked = 0;
    uint8_t rx[sizeof(PacketCommandOLD)];
    common_area.command = COMMON_AREA_COMMAND_NONE;
    if (!common_area.flags.button_pressed && BUTTON_PRESS())
        common_area.flags.button_pressed = 1;

    usb_enable();

    // wait for reset to be complete?
    for (volatile size_t i = 0; i < 0x100000; i++) {};

    for (;;) {
        WDT_HIT();

        // Check if there is a usb packet available
        if (usb_poll_validate_length()) {
            if (usb_read(rx, sizeof(rx))) {
                UsbPacketReceived(rx, sizeof(rx));
            }
        }

        if (common_area.flags.button_pressed && !BUTTON_PRESS()) {
            common_area.flags.button_pressed = 0;
        }
        if (!common_area.flags.button_pressed && BUTTON_PRESS()) {
            /* Perform a reset to leave flash mode */
            common_area.flags.button_pressed = 1;
            usb_disable();
            LED_B_ON();
            AT91C_BASE_RSTC->RSTC_RCR = RST_CONTROL_KEY | AT91C_RSTC_PROCRST;
            for (;;) {};
        }
    }
}

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

    // Set the first 256kb memory flashspeed
    AT91C_BASE_EFC0->EFC_FMR = AT91C_MC_FWS_1FWS | MC_FLASH_MODE_MASTER_CLK_IN_MHZ(48);

    // 9 = 256, 10+ is 512kb
    uint8_t id = (*(AT91C_DBGU_CIDR) & 0xF00) >> 8;
    if (id > 9)
        AT91C_BASE_EFC1->EFC_FMR = AT91C_MC_FWS_1FWS | MC_FLASH_MODE_MASTER_CLK_IN_MHZ(48);

    // Initialize all system clocks
    ConfigClocks();

    LED_A_ON();

    int common_area_present = 0;
    switch (AT91C_BASE_RSTC->RSTC_RSR & AT91C_RSTC_RSTTYP) {
        case AT91C_RSTC_RSTTYP_WATCHDOG:
        case AT91C_RSTC_RSTTYP_SOFTWARE:
        case AT91C_RSTC_RSTTYP_USER:
            /* In these cases the common_area in RAM should be ok, retain it if it's there */
            if (common_area.magic == COMMON_AREA_MAGIC && common_area.version == 1)
                common_area_present = 1;
            break;
        default: /* Otherwise, initialize it from scratch */
            break;
    }

    if (!common_area_present) {
        /* Common area not ok, initialize it */
        int i;
        /* Makeshift memset, no need to drag util.c into this */
        for (i = 0; i < sizeof(common_area); i++)
            ((char *)&common_area)[i] = 0;

        common_area.magic = COMMON_AREA_MAGIC;
        common_area.version = 1;
    }
    common_area.flags.bootrom_present = 1;

    if ((common_area.command == COMMON_AREA_COMMAND_ENTER_FLASH_MODE) ||
            (!common_area.flags.button_pressed && BUTTON_PRESS()) ||
            (_osimage_entry == 0xffffffffU)) {
        flash_mode();
    } else {
        // clear button status, even if button still pressed
        common_area.flags.button_pressed = 0;
        // jump to Flash address of the osimage entry point (LSBit set for thumb mode)
        __asm("bx %0\n" : : "r"(((int)&_osimage_entry) | 0x1));
    }
}
