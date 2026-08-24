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
// GPIO pin mapping for the Proxmark5
//-----------------------------------------------------------------------------

#ifndef CONFIG_GPIO_PROXMARK5_H_
#define CONFIG_GPIO_PROXMARK5_H_

#include "at32f435_437_crm.h"
#include "at32f435_437_gpio.h"

// leds
#define AT32_GPIO_LED_CLK                   CRM_GPIOC_PERIPH_CLOCK
#define AT32_GPIO_LED                       GPIOC
#define AT32_GPIO_LEDA_PIN                  GPIO_PINS_3
#define AT32_GPIO_LEDB_PIN                  GPIO_PINS_15
#define AT32_GPIO_LEDC_PIN                  GPIO_PINS_14
#define AT32_GPIO_LEDD_PIN                  GPIO_PINS_13
// button
#define AT32_GPIO_BTN_CLK                   CRM_GPIOB_PERIPH_CLOCK
#define AT32_GPIO_BTN                       GPIOB
#define AT32_GPIO_BTN_PIN                   GPIO_PINS_12
// qspi flash
#define AT32_GPIO_PERIPH_QSPI_FLASH_CLK     CRM_GPIOB_PERIPH_CLOCK,CRM_GPIOC_PERIPH_CLOCK,CRM_GPIOH_PERIPH_CLOCK
#define AT32_GPIO_QSPI_FLASH_IO0            GPIOB // <--
#define AT32_GPIO_QSPI_FLASH_IO0_SOURCE     GPIO_PINS_SOURCE11
#define AT32_GPIO_QSPI_FLASH_IO0_MUX        GPIO_MUX_10
#define AT32_GPIO_QSPI_FLASH_IO0_PIN        GPIO_PINS_11 // PB11_QSPI1_IO0
#define AT32_GPIO_QSPI_FLASH_IO1            GPIOH // <--
#define AT32_GPIO_QSPI_FLASH_IO1_SOURCE     GPIO_PINS_SOURCE3
#define AT32_GPIO_QSPI_FLASH_IO1_MUX        GPIO_MUX_10
#define AT32_GPIO_QSPI_FLASH_IO1_PIN        GPIO_PINS_3 // PH3_QSPI1_IO1
#define AT32_GPIO_QSPI_FLASH_IO2            GPIOC // <--
#define AT32_GPIO_QSPI_FLASH_IO2_SOURCE     GPIO_PINS_SOURCE4
#define AT32_GPIO_QSPI_FLASH_IO2_MUX        GPIO_MUX_10
#define AT32_GPIO_QSPI_FLASH_IO2_PIN        GPIO_PINS_4 // PC4_QSPI1_IO2
#define AT32_GPIO_QSPI_FLASH_IO3            GPIOC // <--
#define AT32_GPIO_QSPI_FLASH_IO3_SOURCE     GPIO_PINS_SOURCE5
#define AT32_GPIO_QSPI_FLASH_IO3_MUX        GPIO_MUX_10
#define AT32_GPIO_QSPI_FLASH_IO3_PIN        GPIO_PINS_5 // PC5_QSPI1_IO3
#define AT32_GPIO_QSPI_FLASH_SCK            GPIOB // <--
#define AT32_GPIO_QSPI_FLASH_SCK_SOURCE     GPIO_PINS_SOURCE1
#define AT32_GPIO_QSPI_FLASH_SCK_MUX        GPIO_MUX_9
#define AT32_GPIO_QSPI_FLASH_SCK_PIN        GPIO_PINS_1 // PB1_QSPI1_SCK
#define AT32_GPIO_QSPI_FLASH_CS             GPIOB // <--
#define AT32_GPIO_QSPI_FLASH_CS_SOURCE      GPIO_PINS_SOURCE10
#define AT32_GPIO_QSPI_FLASH_CS_MUX         GPIO_MUX_9
#define AT32_GPIO_QSPI_FLASH_CS_PIN         GPIO_PINS_10 // PB10_QSPI1_CS
// fpga 24m clock
#define AT32_GPIO_PERIPH_FPGA_24M_CLK       CRM_GPIOA_PERIPH_CLOCK
#define AT32_GPIO_FPGA_24M_CLK              GPIOA
#define AT32_GPIO_FPGA_24M_CLK_PIN          GPIO_PINS_8
// fpga switch
#define AT32_GPIO_FPGA_SWITCH_CLK           CRM_GPIOB_PERIPH_CLOCK
#define AT32_GPIO_FPGA_SWITCH               GPIOB
#define AT32_GPIO_FPGA_SWITCH_PIN           GPIO_PINS_5
// fpga ssc(spi ti_mode)
#define AT32_GPIO_PERIPH_SSC_CLK            CRM_GPIOB_PERIPH_CLOCK
#define AT32_GPIO_SSC_DIN                   GPIOB // <--
#define AT32_GPIO_SSC_DIN_SOURCE            GPIO_PINS_SOURCE9
#define AT32_GPIO_SSC_DIN_MUX               GPIO_MUX_6
#define AT32_GPIO_SSC_DIN_PIN               GPIO_PINS_9 // PB9_SPI4_MOSI
#define AT32_GPIO_SSC_DOUT                  GPIOB // <--
#define AT32_GPIO_SSC_DOUT_SOURCE           GPIO_PINS_SOURCE8
#define AT32_GPIO_SSC_DOUT_MUX              GPIO_MUX_6
#define AT32_GPIO_SSC_DOUT_PIN              GPIO_PINS_8 // PB8_SPI4_MISO
#define AT32_GPIO_SSC_CLK                   GPIOB // <--
#define AT32_GPIO_SSC_CLK_SOURCE            GPIO_PINS_SOURCE7
#define AT32_GPIO_SSC_CLK_MUX               GPIO_MUX_6
#define AT32_GPIO_SSC_CLK_PIN               GPIO_PINS_7 // PB7_SPI4_SCK
#define AT32_GPIO_SSC_FRAME                 GPIOB // <--
#define AT32_GPIO_SSC_FRAME_SOURCE          GPIO_PINS_SOURCE6
#define AT32_GPIO_SSC_FRAME_MUX             GPIO_MUX_6
#define AT32_GPIO_SSC_FRAME_PIN             GPIO_PINS_6 // PB6_SPI4_CS
// fpga ssc clk counter
#define CRM_GPIO_PERIPH_COUNT_SSP_CLK       CRM_GPIOB_PERIPH_CLOCK
#define CRM_GPIO_COUNT_SSP_CLK              GPIOB
#define CRM_GPIO_COUNT_SSP_CLK_SOURCE       GPIO_PINS_SOURCE3
#define CRM_GPIO_COUNT_SSP_CLK_MUX          GPIO_MUX_1
#define CRM_GPIO_COUNT_SSP_CLK_PIN          GPIO_PINS_3
// fpga ssc frame input capture (LF tag modulation edges), PB4 = TMR3_CH1
#define CRM_GPIO_PERIPH_INPUT_CAPTURE       CRM_GPIOB_PERIPH_CLOCK
#define CRM_GPIO_INPUT_CAPTURE              GPIOB
#define CRM_GPIO_INPUT_CAPTURE_SOURCE       GPIO_PINS_SOURCE4
#define CRM_GPIO_INPUT_CAPTURE_MUX          GPIO_MUX_2
#define CRM_GPIO_INPUT_CAPTURE_PIN          GPIO_PINS_4
// fpga spi(for cmd)
#define AT32_GPIO_PERIPH_SPI_CLK            CRM_GPIOC_PERIPH_CLOCK,CRM_GPIOA_PERIPH_CLOCK
#define AT32_GPIO_SPI_CS                    GPIOA // <--
#define AT32_GPIO_SPI_CS_PIN                GPIO_PINS_15
#define AT32_GPIO_SPI_SCK                   GPIOC // <--
#define AT32_GPIO_SPI_SCK_SOURCE            GPIO_PINS_SOURCE10
#define AT32_GPIO_SPI_SCK_MUX               GPIO_MUX_6
#define AT32_GPIO_SPI_SCK_PIN               GPIO_PINS_10
#define AT32_GPIO_SPI_MISO                  GPIOC // <--
#define AT32_GPIO_SPI_MISO_SOURCE           GPIO_PINS_SOURCE11
#define AT32_GPIO_SPI_MISO_MUX              GPIO_MUX_6
#define AT32_GPIO_SPI_MISO_PIN              GPIO_PINS_11
#define AT32_GPIO_SPI_MOSI                  GPIOC // <--
#define AT32_GPIO_SPI_MOSI_SOURCE           GPIO_PINS_SOURCE12
#define AT32_GPIO_SPI_MOSI_MUX              GPIO_MUX_6
#define AT32_GPIO_SPI_MOSI_PIN              GPIO_PINS_12
// fpga JTAG
#define AT32_GPIO_PERIPH_FPGA_JTAG_CLK      CRM_GPIOA_PERIPH_CLOCK,CRM_GPIOC_PERIPH_CLOCK,CRM_GPIOD_PERIPH_CLOCK
#define AT32_GPIO_FPGA_JTAG_TCK             GPIOC // <--
#define AT32_GPIO_FPGA_JTAG_TCK_PIN         GPIO_PINS_10 // PC10_SPI3_SCK -> TCK
#define AT32_GPIO_FPGA_JTAG_TMS             GPIOA // <--
#define AT32_GPIO_FPGA_JTAG_TMS_PIN         GPIO_PINS_15 // PA15_SPI3_CS -> TMS
#define AT32_GPIO_FPGA_JTAG_TDO             GPIOC // <--
#define AT32_GPIO_FPGA_JTAG_TDO_PIN         GPIO_PINS_11 // PC11_SPI3_MISO -> TDO
#define AT32_GPIO_FPGA_JTAG_TDI             GPIOC // <--
#define AT32_GPIO_FPGA_JTAG_TDI_PIN         GPIO_PINS_12 // PC12_SPI3_MOSI -> TDI
#define AT32_GPIO_FPGA_JTAG_SEL             GPIOD // <--
#define AT32_GPIO_FPGA_JTAG_SEL_PIN         GPIO_PINS_2 // PD2 -> FPGA_JTAGSEL

// adc rssi
#define AT32_GPIO_ADC_RSSI_CLK              CRM_GPIOC_PERIPH_CLOCK
#define AT32_GPIO_ADC_RSSI                  GPIOC
#define AT32_GPIO_ADC_RSSI_LF_PIN           GPIO_PINS_0
#define AT32_GPIO_ADC_RSSI_HF_PIN           GPIO_PINS_1
// arm power lock
#define AT32_GPIO_ARM_POWER_LOCK_CLK        CRM_GPIOB_PERIPH_CLOCK
#define AT32_GPIO_ARM_POWER_LOCK            GPIOB
#define AT32_GPIO_ARM_POWER_LOCK_PIN        GPIO_PINS_0
// i2c software
#define AT32_GPIO_I2C_SW_CLK                CRM_GPIOC_PERIPH_CLOCK
#define AT32_GPIO_I2C_SW                    GPIOC
#define AT32_GPIO_I2C_SCL_PIN               GPIO_PINS_6
#define AT32_GPIO_I2C_SDA_PIN               GPIO_PINS_7
// spi in inter-usb for switch master/slave
#define AT32_GPIO_INTER_USB_SPI_ROLE_CLK    CRM_GPIOB_PERIPH_CLOCK
#define AT32_GPIO_INTER_USB_SPI_ROLE        GPIOB
#define AT32_GPIO_INTER_USB_SPI_ROLE_PIN    GPIO_PINS_2
// vusb
#define AT32_GPIO_VUSB_CLK                  CRM_GPIOC_PERIPH_CLOCK
#define AT32_GPIO_VUSB                      GPIOC
#define AT32_GPIO_VUSB_PIN                  GPIO_PINS_2

#endif // CONFIG_GPIO_PROXMARK5_H_
