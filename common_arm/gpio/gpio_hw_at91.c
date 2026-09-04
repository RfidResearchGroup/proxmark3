#include "gpio_apis.h"
#include "at91sam7s512.h"
#include "config_gpio.h"

void gpio_button_setup(void) {
    AT91C_BASE_PIOA->PIO_PER = GPIO_BUTTON;
    AT91C_BASE_PIOA->PIO_ODR = GPIO_BUTTON;
}

void gpio_leds_setup(void) {
    AT91C_BASE_PIOA->PIO_PER = AT91C_BASE_PIOA->PIO_OER = // Chained assignment
                                   GPIO_LED_A   |
                                   GPIO_LED_B   |
                                   GPIO_LED_C   |
                                   GPIO_LED_D;
}

void gpio_arm_power_on_setup(void) {
    // Currently, there are no devices with AT91 as the core that support power control.
}

void gpio_inter_usb_spi_role_setup(void) {
    // Unsupported
}

void gpio_sw_i2c_rst_setup(void) {
    // Configure reset pin, close up pull, push-pull output, default high
    AT91C_BASE_PIOA->PIO_PPUDR = GPIO_I2C_RST;
    AT91C_BASE_PIOA->PIO_MDDR = GPIO_I2C_RST;

    // Configure I2C pin, open up, open leakage
    AT91C_BASE_PIOA->PIO_PPUER |= (GPIO_I2C_SCL | GPIO_I2C_SDA);
    AT91C_BASE_PIOA->PIO_MDER |= (GPIO_I2C_SCL | GPIO_I2C_SDA);

    // default three lines all pull up
    AT91C_BASE_PIOA->PIO_SODR |= (GPIO_I2C_SCL | GPIO_I2C_SDA | GPIO_I2C_RST);

    AT91C_BASE_PIOA->PIO_OER |= (GPIO_I2C_SCL | GPIO_I2C_SDA | GPIO_I2C_RST);
    AT91C_BASE_PIOA->PIO_PER |= (GPIO_I2C_SCL | GPIO_I2C_SDA | GPIO_I2C_RST);
}

void gpio_fpga_switch_setup(void) {
#ifdef GPIO_FPGA_SWITCH
    AT91C_BASE_PIOA->PIO_PER = GPIO_FPGA_SWITCH;
    AT91C_BASE_PIOA->PIO_OER = GPIO_FPGA_SWITCH;
#endif
}

void gpio_adc_mux_setup(void) {
    AT91C_BASE_PIOA->PIO_PER = AT91C_BASE_PIOA->PIO_OER = // Chained assignment
                                   GPIO_MUXSEL_HIPKD |
#ifndef WITH_FPC_USART // FPC USART uses HIRAW/LOWRAW pins, so they are excluded here.
                                   GPIO_MUXSEL_LORAW |
                                   GPIO_MUXSEL_HIRAW |
#endif
                                   GPIO_MUXSEL_LOPKD;
}

void gpio_fpga_download_setup(void) {

    /**
     * ICopyx(XC3S100E) reuse M1 & M2(M2,M3) pin for spi communication.
     * When M2 & M3 is high before enter configuration, The mode 'Slave Serial (M[2:0] = 110)' selected.
     * It is also to reuse the download code of xc2s30.
     * Therefore, after the configuration mode is selected, these two PINs will free, so they can be reused as SPI communication ports.
     * See docs at Table 44: Spartan-3E Configuration Mode Options and Pin Settings
     */

    // PIO controls the following pins for 'Slave Serial', need disable peripheral functions.
    AT91C_BASE_PIOA->PIO_PER =
        GPIO_FPGA_NINIT |
        GPIO_FPGA_DONE |
#if defined XC3
        // ICopyX(3S100E) M2 & M3 PIO ENA
        GPIO_SPCK |
        GPIO_MOSI |
#endif
        GPIO_FPGA_NPROGRAM |
        GPIO_FPGA_CCLK |
        GPIO_FPGA_DIN;

    // These pins are inputs
    AT91C_BASE_PIOA->PIO_ODR = GPIO_FPGA_NINIT | GPIO_FPGA_DONE;
    AT91C_BASE_PIOA->PIO_PPUER = GPIO_FPGA_NINIT | GPIO_FPGA_DONE; // Enable pull-ups

    // These pins are outputs
    AT91C_BASE_PIOA->PIO_OER =
        GPIO_FPGA_NPROGRAM |
        GPIO_FPGA_CCLK     |
#if defined XC3
        // ICopyX(3S100E) M2 & M3 OUTPUT ENA
        GPIO_SPCK |
        GPIO_MOSI |
#endif
        GPIO_FPGA_DIN;
}

void gpio_fpga_on_setup(void) {
    AT91C_BASE_PIOA->PIO_OER = GPIO_FPGA_ON;
    AT91C_BASE_PIOA->PIO_PER = GPIO_FPGA_ON;
}

void gpio_fpga_mod_feedback_setup(void) {
    AT91C_BASE_PIOA->PIO_PER = GPIO_SSC_DOUT | GPIO_SSC_CLK;
    AT91C_BASE_PIOA->PIO_OER = GPIO_SSC_DOUT;
    AT91C_BASE_PIOA->PIO_ODR = GPIO_SSC_CLK;
}

void gpio_fpga_mod_only_setup(void) {
    AT91C_BASE_PIOA->PIO_PER = GPIO_SSC_DOUT;
    AT91C_BASE_PIOA->PIO_OER = GPIO_SSC_DOUT;
}

void gpio_sysboot_setup(void) {
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

    gpio_button_setup();
}

void gpio_vusb_setup(void) {
    // Unsupported!
}
