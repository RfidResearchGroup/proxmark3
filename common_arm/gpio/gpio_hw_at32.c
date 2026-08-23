#include "gpio_apis.h"
#include "at32f435_437_gpio.h"
#include "at32f435_437_crm.h"
#include "proxmark3_arm.h"

// Simplify Enable GPIO Clock
#define GPIO_CLK_EN(clk) crm_periph_clock_enable(clk, TRUE)

// common output init
static void gpio_output_init(gpio_init_type *gpio_init_struct, gpio_type *gpio_x, uint32_t pins) {
    gpio_init_struct->gpio_mode = GPIO_MODE_OUTPUT;
    gpio_init_struct->gpio_pins = pins;
    gpio_init_struct->gpio_pull = GPIO_PULL_NONE;
    gpio_init(gpio_x, gpio_init_struct);
}

void gpio_button_setup(void) {
    gpio_init_type gpio_init_struct;
    gpio_default_para_init(&gpio_init_struct);
    GPIO_CLK_EN(AT32_GPIO_BTN_CLK);
    gpio_init_struct.gpio_mode = GPIO_MODE_INPUT;
    gpio_init_struct.gpio_pins = AT32_GPIO_BTN_PIN;
    gpio_init_struct.gpio_pull = GPIO_PULL_DOWN;
    gpio_init(AT32_GPIO_BTN, &gpio_init_struct);
}

void gpio_leds_setup(void) {
    gpio_init_type gpio_init_struct;
    gpio_default_para_init(&gpio_init_struct);
    gpio_init_struct.gpio_out_type = GPIO_OUTPUT_OPEN_DRAIN;

    GPIO_CLK_EN(AT32_GPIO_LED_CLK);
    // Off all leds before setup(Avoid flickering)
    LED_A_OFF();
    LED_B_OFF();
    LED_C_OFF();
    LED_D_OFF();

    gpio_output_init(
        &gpio_init_struct,
        AT32_GPIO_LED,
        AT32_GPIO_LEDA_PIN | AT32_GPIO_LEDB_PIN | AT32_GPIO_LEDC_PIN | AT32_GPIO_LEDD_PIN);
}

/**
 * After power up, it is necessary to initialize and lock this IO (pull up) as soon as possible,
 * otherwise the power will automatically shut down after a certain period of time.
 * Note:
 *  1. After power up, the button function will return to normal.
 *  2. The buttons of the old models are directly connected to ARM and do not have power control function.
 */
void gpio_arm_power_on_setup(void) {
    gpio_init_type gpio_init_struct;
    gpio_default_para_init(&gpio_init_struct);
    GPIO_CLK_EN(AT32_GPIO_ARM_POWER_LOCK_CLK);
    Gpio_ARM_Power_ON_High(); // Self-lock power control, keep ARM power on.
    gpio_output_init(&gpio_init_struct, AT32_GPIO_ARM_POWER_LOCK, AT32_GPIO_ARM_POWER_LOCK_PIN);
}

/**
 * For spi switch master/slave in 'inter-usb', High is Master, Low is slave
 * Only PM5 supported(inter-usb ext spi functions)
 */
void gpio_inter_usb_spi_role_setup(void) {
    gpio_init_type gpio_init_struct;
    gpio_default_para_init(&gpio_init_struct);

    GPIO_CLK_EN(AT32_GPIO_INTER_USB_SPI_ROLE_CLK);
    gpio_output_init(&gpio_init_struct, AT32_GPIO_INTER_USB_SPI_ROLE, AT32_GPIO_INTER_USB_SPI_ROLE_PIN);
}

void gpio_sw_i2c_rst_setup(void) {
    gpio_init_type gpio_init_struct;
    gpio_default_para_init(&gpio_init_struct);

    // Software implemented I2C needs to be set to open drain output
    gpio_init_struct.gpio_out_type = GPIO_OUTPUT_OPEN_DRAIN;

    crm_periph_clock_enable(AT32_GPIO_I2C_SW_CLK, TRUE);
    gpio_output_init(&gpio_init_struct, AT32_GPIO_I2C_SW, AT32_GPIO_I2C_SCL_PIN | AT32_GPIO_I2C_SDA_PIN);
}

void gpio_fpga_switch_setup(void) {
    gpio_init_type gpio_init_struct;
    gpio_default_para_init(&gpio_init_struct);
    GPIO_CLK_EN(AT32_GPIO_FPGA_SWITCH_CLK);
    gpio_output_init(&gpio_init_struct, AT32_GPIO_FPGA_SWITCH, AT32_GPIO_FPGA_SWITCH_PIN);
}

void gpio_adc_mux_setup(void) {
    // The fpgaswitch linkage switches adcmux. The HF firmware is hipkd, otherwise it is lopkd
    // So, we can reuse setup functions of 'fpga_switch'
    gpio_fpga_switch_setup();
}

void gpio_fpga_download_setup(void) {
    gpio_init_type gpio_init_struct;

    // TODO DXL: Move IO & CLK definition to 'config_gpio_proxmark5.h'

    GPIO_CLK_EN(CRM_GPIOA_PERIPH_CLOCK);
    GPIO_CLK_EN(CRM_GPIOC_PERIPH_CLOCK);
    GPIO_CLK_EN(CRM_GPIOD_PERIPH_CLOCK);

    gpio_default_para_init(&gpio_init_struct);
    gpio_init_struct.gpio_mode = GPIO_MODE_OUTPUT;

    gpio_init_struct.gpio_pins = GPIO_PINS_4;
    gpio_init(GPIOB, &gpio_init_struct);

    gpio_init_struct.gpio_pins = GPIO_PINS_10; // PC10_SPI3_SCK -> TCK
    gpio_init_struct.gpio_pull = GPIO_PULL_DOWN;
    gpio_init(GPIOC, &gpio_init_struct);

    gpio_init_struct.gpio_pins = GPIO_PINS_15; // PA15_SPI3_CS -> TMS
    gpio_init_struct.gpio_pull = GPIO_PULL_UP;
    gpio_init(GPIOA, &gpio_init_struct);

    gpio_init_struct.gpio_pins = GPIO_PINS_12; // PC12_SPI3_MOSI -> TDI
    gpio_init_struct.gpio_pull = GPIO_PULL_UP;
    gpio_init(GPIOC, &gpio_init_struct);

    gpio_init_struct.gpio_pins = GPIO_PINS_2; // PD2 -> FPGA_JTAGSEL
    gpio_init_struct.gpio_pull = GPIO_PULL_UP;
    gpio_init(GPIOD, &gpio_init_struct);

    gpio_init_struct.gpio_mode = GPIO_MODE_INPUT;
    gpio_init_struct.gpio_pull = GPIO_PULL_NONE;
    gpio_init_struct.gpio_pins = GPIO_PINS_11; // PC11_SPI3_MISO -> TDO
    gpio_init(GPIOC, &gpio_init_struct);
}

void gpio_fpga_on_setup(void) {
    // Unsupported
}

void gpio_fpga_mod_feedback_setup(void) {
    gpio_init_type gpio_init_struct;
    gpio_default_para_init(&gpio_init_struct);
    GPIO_CLK_EN(AT32_GPIO_PERIPH_SSC_CLK);
    gpio_output_init(&gpio_init_struct, AT32_GPIO_SSC_DOUT, AT32_GPIO_SSC_DOUT_PIN);
    gpio_init_struct.gpio_mode = GPIO_MODE_INPUT;
    gpio_init_struct.gpio_pull = GPIO_PULL_NONE;
    gpio_init_struct.gpio_pins = AT32_GPIO_SSC_CLK_PIN;
    gpio_init(AT32_GPIO_SSC_CLK, &gpio_init_struct);
}

void gpio_fpga_mod_only_setup(void) {
    gpio_init_type gpio_init_struct;
    gpio_default_para_init(&gpio_init_struct);
    // ssc_out == miso, arm -> fpga
    GPIO_CLK_EN(AT32_GPIO_PERIPH_SSC_CLK);
    gpio_output_init(&gpio_init_struct, AT32_GPIO_SSC_DOUT, AT32_GPIO_SSC_DOUT_PIN);
}

void gpio_sysboot_setup(void) {
    // To keep power on for ARM, This is a power supply locking pin.
    // Once released, the whole system will be powered off.
    gpio_arm_power_on_setup();
    // 4 x leds(red)
    gpio_leds_setup();
    // Button for POWER_CONTROL / User interaction
    gpio_button_setup();
}

void gpio_vusb_setup(void) {
    gpio_init_type gpio_init_struct;
    gpio_default_para_init(&gpio_init_struct);
    GPIO_CLK_EN(AT32_GPIO_VUSB_CLK);
    gpio_init_struct.gpio_mode = GPIO_MODE_INPUT;
    gpio_init_struct.gpio_pins = AT32_GPIO_VUSB_PIN;
    gpio_init_struct.gpio_pull = GPIO_PULL_NONE;
    gpio_init(AT32_GPIO_VUSB, &gpio_init_struct);
}
