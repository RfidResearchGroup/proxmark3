#ifndef _GPIO_HW_AT91_H
#define _GPIO_HW_AT91_H

#include "common.h"
#include "config_gpio.h"

#define LOW(x)      AT91C_BASE_PIOA->PIO_CODR |= (x)
#define HIGH(x)     AT91C_BASE_PIOA->PIO_SODR |= (x)

#define GETBIT(x)   (AT91C_BASE_PIOA->PIO_ODSR & (x)) ? 1:0
#define SETBIT(x, y) (y) ? (HIGH(x)):(LOW(x))
#define INVBIT(x)   SETBIT((x), !(GETBIT(x)))

STATIC_FORCE_INLINE void Gpio_ARM_Power_ON_High(void) {
    // Unsupported!
    // If AT91 devices support power self-locking in the future, please implement this function.
    // And Gpio_ARM_Power_ON_Low() functions.
}

STATIC_FORCE_INLINE void Gpio_ARM_Power_ON_Low(void) {
    // Unsupported!
}

STATIC_FORCE_INLINE bool Gpio_Button_Read(void) {
    return (AT91C_BASE_PIOA->PIO_PDSR & GPIO_BUTTON) == GPIO_BUTTON;
}

STATIC_FORCE_INLINE void Gpio_LED_A_High(void) {
    HIGH(GPIO_LED_A);
}

STATIC_FORCE_INLINE void Gpio_LED_B_High(void) {
    HIGH(GPIO_LED_B);
}

STATIC_FORCE_INLINE void Gpio_LED_C_High(void) {
    HIGH(GPIO_LED_C);
}

STATIC_FORCE_INLINE void Gpio_LED_D_High(void) {
    HIGH(GPIO_LED_D);
}

STATIC_FORCE_INLINE void Gpio_LED_A_Low(void) {
    LOW(GPIO_LED_A);
}

STATIC_FORCE_INLINE void Gpio_LED_B_Low(void) {
    LOW(GPIO_LED_B);
}

STATIC_FORCE_INLINE void Gpio_LED_C_Low(void) {
    LOW(GPIO_LED_C);
}

STATIC_FORCE_INLINE void Gpio_LED_D_Low(void) {
    LOW(GPIO_LED_D);
}

STATIC_FORCE_INLINE void Gpio_LED_A_Inv(void) {
    INVBIT(GPIO_LED_A);
}

STATIC_FORCE_INLINE void Gpio_LED_B_Inv(void) {
    INVBIT(GPIO_LED_B);
}

STATIC_FORCE_INLINE void Gpio_LED_C_Inv(void) {
    INVBIT(GPIO_LED_C);
}

STATIC_FORCE_INLINE void Gpio_LED_D_Inv(void) {
    INVBIT(GPIO_LED_D);
}

STATIC_FORCE_INLINE void Gpio_FPGA_ON_High(void) {
    HIGH(GPIO_FPGA_ON);
}

STATIC_FORCE_INLINE void Gpio_FPGA_ON_Low(void) {
    LOW(GPIO_FPGA_ON);
}

STATIC_FORCE_INLINE void Gpio_SSC_DOUT_High(void) {
    HIGH(GPIO_SSC_DOUT);
}

STATIC_FORCE_INLINE void Gpio_SSC_DOUT_Low(void) {
    LOW(GPIO_SSC_DOUT);
}

STATIC_FORCE_INLINE bool Gpio_SSC_DIN_Read(void) {
    return (AT91C_BASE_PIOA->PIO_PDSR & GPIO_SSC_DIN) == GPIO_SSC_DIN;
}

STATIC_FORCE_INLINE bool Gpio_SSC_FRAME_Read(void) {
    return (AT91C_BASE_PIOA->PIO_PDSR & GPIO_SSC_FRAME) == GPIO_SSC_FRAME;
}

STATIC_FORCE_INLINE bool Gpio_SSC_CLK_Read(void) {
    return (AT91C_BASE_PIOA->PIO_PDSR & GPIO_SSC_CLK) == GPIO_SSC_CLK;
}

STATIC_FORCE_INLINE void Gpio_FPGA_DIN_High(void) {
    HIGH(GPIO_FPGA_DIN);
}

STATIC_FORCE_INLINE void Gpio_FPGA_DIN_Low(void) {
    LOW(GPIO_FPGA_DIN);
}

STATIC_FORCE_INLINE void Gpio_FPGA_CCLK_High(void) {
    HIGH(GPIO_FPGA_CCLK);
}

STATIC_FORCE_INLINE void Gpio_FPGA_CCLK_Low(void) {
    LOW(GPIO_FPGA_CCLK);
}

STATIC_FORCE_INLINE void Gpio_FPGA_NPROGRAM_High(void) {
    HIGH(GPIO_FPGA_NPROGRAM);
}

STATIC_FORCE_INLINE void Gpio_FPGA_NPROGRAM_Low(void) {
    LOW(GPIO_FPGA_NPROGRAM);
}

STATIC_FORCE_INLINE bool Gpio_FPGA_NINIT_Read(void) {
    return (AT91C_BASE_PIOA->PIO_PDSR & GPIO_FPGA_NINIT) == GPIO_FPGA_NINIT;
}

STATIC_FORCE_INLINE bool Gpio_FPGA_DONE_Read(void) {
    return (AT91C_BASE_PIOA->PIO_PDSR & GPIO_FPGA_DONE) == GPIO_FPGA_DONE;
}

STATIC_FORCE_INLINE void Gpio_FPGA_SWITCH_High(void) {
#ifdef GPIO_FPGA_SWITCH
    HIGH(GPIO_FPGA_SWITCH);
#endif
}

STATIC_FORCE_INLINE void Gpio_FPGA_SWITCH_Low(void) {
#ifdef GPIO_FPGA_SWITCH
    LOW(GPIO_FPGA_SWITCH);
#endif
}

STATIC_FORCE_INLINE void Gpio_FPGA_XC3_M1_High(void) {
    HIGH(GPIO_SPCK);
}

STATIC_FORCE_INLINE void Gpio_FPGA_XC3_M1_Low(void) {
    LOW(GPIO_SPCK);
}

STATIC_FORCE_INLINE void Gpio_FPGA_XC3_M2_High(void) {
    HIGH(GPIO_MOSI);
}

STATIC_FORCE_INLINE void Gpio_FPGA_XC3_M2_Low(void) {
    LOW(GPIO_MOSI);
}

STATIC_FORCE_INLINE void Gpio_MUXSEL_HIPKD_High(void) {
    HIGH(GPIO_MUXSEL_HIPKD);
}

STATIC_FORCE_INLINE void Gpio_MUXSEL_HIPKD_Low(void) {
    LOW(GPIO_MUXSEL_HIPKD);
}

STATIC_FORCE_INLINE void Gpio_MUXSEL_LOPKD_High(void) {
    HIGH(GPIO_MUXSEL_LOPKD);
}

STATIC_FORCE_INLINE void Gpio_MUXSEL_LOPKD_Low(void) {
    LOW(GPIO_MUXSEL_LOPKD);
}

STATIC_FORCE_INLINE void Gpio_MUXSEL_HIRAW_High(void) {
    HIGH(GPIO_MUXSEL_HIRAW);
}

STATIC_FORCE_INLINE void Gpio_MUXSEL_HIRAW_Low(void) {
    LOW(GPIO_MUXSEL_HIRAW);
}

STATIC_FORCE_INLINE void Gpio_MUXSEL_LORAW_High(void) {
    HIGH(GPIO_MUXSEL_LORAW);
}

STATIC_FORCE_INLINE void Gpio_MUXSEL_LORAW_Low(void) {
    LOW(GPIO_MUXSEL_LORAW);
}

STATIC_FORCE_INLINE void Gpio_I2C_SCL_High(void) {
    HIGH(GPIO_I2C_SCL);
}

STATIC_FORCE_INLINE void Gpio_I2C_SCL_Low(void) {
    LOW(GPIO_I2C_SCL);
}

STATIC_FORCE_INLINE void Gpio_I2C_SDA_High(void) {
    HIGH(GPIO_I2C_SDA);
}

STATIC_FORCE_INLINE void Gpio_I2C_SDA_Low(void) {
    LOW(GPIO_I2C_SDA);
}

STATIC_FORCE_INLINE void Gpio_I2C_RST_High(void) {
    HIGH(GPIO_I2C_RST);
}

STATIC_FORCE_INLINE void Gpio_I2C_RST_Low(void) {
    LOW(GPIO_I2C_RST);
}

STATIC_FORCE_INLINE bool Gpio_I2C_SCL_Read(void) {
    return (AT91C_BASE_PIOA->PIO_PDSR & GPIO_I2C_SCL) == GPIO_I2C_SCL;
}

STATIC_FORCE_INLINE bool Gpio_I2C_SDA_Read(void) {
    return (AT91C_BASE_PIOA->PIO_PDSR & GPIO_I2C_SDA) == GPIO_I2C_SDA;
}

STATIC_FORCE_INLINE void Gpio_Inter_USB_SPI_Role_High(void) {
    // Unsupported
}

STATIC_FORCE_INLINE void Gpio_Inter_USB_SPI_Role_Low(void) {
    // Unsupported
}

STATIC_FORCE_INLINE bool Gpio_VUSB_Read(void) {
    // Unsupported
    return false;
}

STATIC_FORCE_INLINE void Gpio_Relay_High(void) {
    HIGH(GPIO_RELAY);
}

STATIC_FORCE_INLINE void Gpio_Relay_Low(void) {
    LOW(GPIO_RELAY);
}

STATIC_FORCE_INLINE bool Gpio_NVDD_Read(void) {
    return ((AT91C_BASE_PIOA->PIO_PDSR & GPIO_NVDD_ON) == GPIO_NVDD_ON);
}

#endif
