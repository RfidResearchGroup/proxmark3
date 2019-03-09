//-----------------------------------------------------------------------------
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// GPIO pin mapping for the Proxmark3
//-----------------------------------------------------------------------------

#ifndef __CONFIG_GPIO_H
#define __CONFIG_GPIO_H

#define GPIO_LED_A          AT91C_PIO_PA0
#define GPIO_PA1            AT91C_PIO_PA1
#define GPIO_LED_D          AT91C_PIO_PA2
#define GPIO_NVDD_ON        AT91C_PIO_PA3
#define GPIO_FPGA_NINIT     AT91C_PIO_PA4
#define GPIO_PA5            AT91C_PIO_PA5
#define GPIO_PCK0           AT91C_PA6_PCK0
#define GPIO_LRST           AT91C_PIO_PA7
#define GPIO_LED_B          AT91C_PIO_PA8
#define GPIO_LED_C          AT91C_PIO_PA9

// defines for flash mem,  or rdv40 ?
// flashmem hooked on PA10
//#define GPIO_NCS2            AT91C_PIO_PA1
#define GPIO_NCS2           AT91C_PA10_NPCS2
#define GPIO_NCS0           AT91C_PA11_NPCS0

#define GPIO_MISO           AT91C_PA12_MISO
#define GPIO_MOSI           AT91C_PA13_MOSI
#define GPIO_SPCK           AT91C_PA14_SPCK
#define GPIO_SSC_FRAME      AT91C_PA15_TF
#define GPIO_SSC_CLK        AT91C_PA16_TK
#define GPIO_SSC_DOUT       AT91C_PA17_TD
#define GPIO_SSC_DIN        AT91C_PA18_RD
#define GPIO_MUXSEL_HIPKD   AT91C_PIO_PA19
#define GPIO_MUXSEL_LOPKD   AT91C_PIO_PA20

// RDV40 has no HIRAW/LORAW,  its used for FPC
#define GPIO_MUXSEL_HIRAW   AT91C_PIO_PA21
#define GPIO_MUXSEL_LORAW   AT91C_PIO_PA22

#define GPIO_BUTTON         AT91C_PIO_PA23
#define GPIO_USB_PU         AT91C_PIO_PA24
#define GPIO_RELAY          AT91C_PIO_PA25
#define GPIO_FPGA_ON        AT91C_PIO_PA26
#define GPIO_FPGA_DONE      AT91C_PIO_PA27
#define GPIO_FPGA_NPROGRAM  AT91C_PIO_PA28
#define GPIO_FPGA_CCLK      AT91C_PIO_PA29
#define GPIO_FPGA_DIN       AT91C_PIO_PA30
#define GPIO_FPGA_DOUT      AT91C_PIO_PA31

#endif
