#ifndef GPIO_HW_AT32_H_
#define GPIO_HW_AT32_H_

#include "common.h"
#include "config_gpio.h"


/**
 * For at32 gpio peripheral clk enable by array
 */
#define AT32_GPIO_PERIPH_CLKS_ENABLE(...)                              \
    do {                                                               \
        const crm_periph_clock_type args[] = { __VA_ARGS__ };          \
        for (size_t i = 0; i < sizeof(args) / sizeof(args[0]); ++i) {  \
            crm_periph_clock_enable(args[i], TRUE);                    \
        }                                                              \
    } while(0)


// Get gpio input status
STATIC_FORCE_INLINE uint8_t GpioInputStatus(const gpio_type *gpio_x, uint16_t pins) {
    return pins == (pins & gpio_x->idt);
}

// Get gpio output status
STATIC_FORCE_INLINE uint8_t GpioOutputStatus(gpio_type *gpio_x, uint16_t pins) {
    return pins == (pins & gpio_x->odt);
}

// Output inversion
STATIC_FORCE_INLINE void GpioOutputInv(gpio_type *gpio_x, uint16_t pins) {
    if (GpioOutputStatus(gpio_x, pins)) {
        gpio_x->clr = pins;
    } else {
        gpio_x->scr = pins;
    }
}

STATIC_FORCE_INLINE void Gpio_ARM_Power_ON_High(void) {
    AT32_GPIO_ARM_POWER_LOCK->scr = AT32_GPIO_ARM_POWER_LOCK_PIN;
}

STATIC_FORCE_INLINE void Gpio_ARM_Power_ON_Low(void) {
    AT32_GPIO_ARM_POWER_LOCK->clr = AT32_GPIO_ARM_POWER_LOCK_PIN;
}

STATIC_FORCE_INLINE bool Gpio_Button_Read(void) {
    return GpioInputStatus(AT32_GPIO_BTN, AT32_GPIO_BTN_PIN);
}

STATIC_FORCE_INLINE void Gpio_LED_A_High(void) {
    AT32_GPIO_LED->scr = AT32_GPIO_LEDA_PIN;
}

STATIC_FORCE_INLINE void Gpio_LED_B_High(void) {
    AT32_GPIO_LED->scr = AT32_GPIO_LEDB_PIN;
}

STATIC_FORCE_INLINE void Gpio_LED_C_High(void) {
    AT32_GPIO_LED->scr = AT32_GPIO_LEDC_PIN;
}

STATIC_FORCE_INLINE void Gpio_LED_D_High(void) {
    AT32_GPIO_LED->scr = AT32_GPIO_LEDD_PIN;
}

STATIC_FORCE_INLINE void Gpio_LED_A_Low(void) {
    AT32_GPIO_LED->clr = AT32_GPIO_LEDA_PIN;
}

STATIC_FORCE_INLINE void Gpio_LED_B_Low(void) {
    AT32_GPIO_LED->clr = AT32_GPIO_LEDB_PIN;
}

STATIC_FORCE_INLINE void Gpio_LED_C_Low(void) {
    AT32_GPIO_LED->clr = AT32_GPIO_LEDC_PIN;
}

STATIC_FORCE_INLINE void Gpio_LED_D_Low(void) {
    AT32_GPIO_LED->clr = AT32_GPIO_LEDD_PIN;
}

STATIC_FORCE_INLINE void Gpio_LED_A_Inv(void) {
    GpioOutputInv(AT32_GPIO_LED, AT32_GPIO_LEDA_PIN);
}

STATIC_FORCE_INLINE void Gpio_LED_B_Inv(void) {
    GpioOutputInv(AT32_GPIO_LED, AT32_GPIO_LEDB_PIN);
}

STATIC_FORCE_INLINE void Gpio_LED_C_Inv(void) {
    GpioOutputInv(AT32_GPIO_LED, AT32_GPIO_LEDC_PIN);
}

STATIC_FORCE_INLINE void Gpio_LED_D_Inv(void) {
    GpioOutputInv(AT32_GPIO_LED, AT32_GPIO_LEDD_PIN);
}

STATIC_FORCE_INLINE void Gpio_FPGA_ON_High(void) {
    // Unsupported
}

STATIC_FORCE_INLINE void Gpio_FPGA_ON_Low(void) {
    // Unsupported
}

STATIC_FORCE_INLINE void Gpio_SSC_DOUT_High(void) {
    AT32_GPIO_SSC_DOUT->scr = AT32_GPIO_SSC_DOUT_PIN;
}

STATIC_FORCE_INLINE void Gpio_SSC_DOUT_Low(void) {
    AT32_GPIO_SSC_DOUT->clr = AT32_GPIO_SSC_DOUT_PIN;
}

STATIC_FORCE_INLINE bool Gpio_SSC_DIN_Read(void) {
    return GpioInputStatus(AT32_GPIO_SSC_DIN, AT32_GPIO_SSC_DIN_PIN);
}

STATIC_FORCE_INLINE bool Gpio_SSC_FRAME_Read(void) {
    return GpioInputStatus(AT32_GPIO_SSC_FRAME, AT32_GPIO_SSC_FRAME_PIN);
}

STATIC_FORCE_INLINE bool Gpio_SSC_CLK_Read(void) {
    return GpioInputStatus(AT32_GPIO_SSC_CLK, AT32_GPIO_SSC_CLK_PIN);
}

STATIC_FORCE_INLINE void Gpio_FPGA_DIN_High(void) {
    // Unsupported
}

STATIC_FORCE_INLINE void Gpio_FPGA_DIN_Low(void) {
    // Unsupported
}

STATIC_FORCE_INLINE void Gpio_FPGA_CCLK_High(void) {
    // Unsupported
}

STATIC_FORCE_INLINE void Gpio_FPGA_CCLK_Low(void) {
    // Unsupported
}

STATIC_FORCE_INLINE void Gpio_FPGA_NPROGRAM_High(void) {
    // Unsupported
}

STATIC_FORCE_INLINE void Gpio_FPGA_NPROGRAM_Low(void) {
    // Unsupported
}

STATIC_FORCE_INLINE bool Gpio_FPGA_NINIT_Read(void) {
    return false; // Unsupported
}

STATIC_FORCE_INLINE bool Gpio_FPGA_DONE_Read(void) {
    return false; // Unsupported
}

STATIC_FORCE_INLINE void Gpio_FPGA_SWITCH_High(void) {
    AT32_GPIO_FPGA_SWITCH->scr = AT32_GPIO_FPGA_SWITCH_PIN;
}

STATIC_FORCE_INLINE void Gpio_FPGA_SWITCH_Low(void) {
    AT32_GPIO_FPGA_SWITCH->clr = AT32_GPIO_FPGA_SWITCH_PIN;
}

STATIC_FORCE_INLINE void Gpio_FPGA_XC3_M1_High(void) {
    // Unsupported
}

STATIC_FORCE_INLINE void Gpio_FPGA_XC3_M1_Low(void) {
    // Unsupported
}

STATIC_FORCE_INLINE void Gpio_FPGA_XC3_M2_High(void) {
    // Unsupported
}

STATIC_FORCE_INLINE void Gpio_FPGA_XC3_M2_Low(void) {
    // Unsupported
}

STATIC_FORCE_INLINE void Gpio_MUXSEL_HIPKD_High(void) {
    // Unsupported
}

STATIC_FORCE_INLINE void Gpio_MUXSEL_HIPKD_Low(void) {
    // Unsupported
}

STATIC_FORCE_INLINE void Gpio_MUXSEL_LOPKD_High(void) {
    // Unsupported
}

STATIC_FORCE_INLINE void Gpio_MUXSEL_LOPKD_Low(void) {
    // Unsupported
}

STATIC_FORCE_INLINE void Gpio_MUXSEL_HIRAW_High(void) {
    // Unsupported
}

STATIC_FORCE_INLINE void Gpio_MUXSEL_HIRAW_Low(void) {
    // Unsupported
}

STATIC_FORCE_INLINE void Gpio_MUXSEL_LORAW_High(void) {
    // Unsupported
}

STATIC_FORCE_INLINE void Gpio_MUXSEL_LORAW_Low(void) {
    // Unsupported
}

STATIC_FORCE_INLINE void Gpio_I2C_SCL_High(void) {
    AT32_GPIO_I2C_SW->scr = AT32_GPIO_I2C_SCL_PIN;
}

STATIC_FORCE_INLINE void Gpio_I2C_SCL_Low(void) {
    AT32_GPIO_I2C_SW->clr = AT32_GPIO_I2C_SCL_PIN;
}

STATIC_FORCE_INLINE void Gpio_I2C_SDA_High(void) {
    AT32_GPIO_I2C_SW->scr = AT32_GPIO_I2C_SDA_PIN;
}

STATIC_FORCE_INLINE void Gpio_I2C_SDA_Low(void) {
    AT32_GPIO_I2C_SW->clr = AT32_GPIO_I2C_SDA_PIN;
}

STATIC_FORCE_INLINE void Gpio_I2C_RST_High(void) {
    // TODO DXL 待实现
}

STATIC_FORCE_INLINE void Gpio_I2C_RST_Low(void) {
    // TODO DXL 待实现
}

STATIC_FORCE_INLINE bool Gpio_I2C_SCL_Read(void) {
    return GpioInputStatus(AT32_GPIO_I2C_SW, AT32_GPIO_I2C_SCL_PIN);
}

STATIC_FORCE_INLINE bool Gpio_I2C_SDA_Read(void) {
    return GpioInputStatus(AT32_GPIO_I2C_SW, AT32_GPIO_I2C_SDA_PIN);
}

STATIC_FORCE_INLINE void Gpio_Inter_USB_SPI_Role_High(void) {
    AT32_GPIO_INTER_USB_SPI_ROLE->scr = AT32_GPIO_INTER_USB_SPI_ROLE_PIN;
}

STATIC_FORCE_INLINE void Gpio_Inter_USB_SPI_Role_Low(void) {
    AT32_GPIO_INTER_USB_SPI_ROLE->clr = AT32_GPIO_INTER_USB_SPI_ROLE_PIN;
}

STATIC_FORCE_INLINE bool Gpio_VUSB_Read(void) {
    return GpioInputStatus(AT32_GPIO_VUSB, AT32_GPIO_VUSB_PIN);
}

STATIC_FORCE_INLINE void Gpio_Relay_High(void) {
    // Unsupported
}

STATIC_FORCE_INLINE void Gpio_Relay_Low(void) {
    // Unsupported
}

STATIC_FORCE_INLINE bool Gpio_NVDD_Read(void) {
    return false; // Unsupported
}

#endif // GPIO_HW_AT32_H_
