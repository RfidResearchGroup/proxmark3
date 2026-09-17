#ifndef GPIO_APIS_H_
#define GPIO_APIS_H_

#include "common.h"


/*
 * Relying on forced inlining to achieve the same effect as macro definitions,
 * while retaining function specific type and scope checks and limitations.
 * ---
 * Most importantly, due to compatibility with multiple platforms,
 * if macro definitions are used, macro functions will not be clearly displayed to developers.
 * ---
 * To ensure proper function inlining, we need to ensure that the code is concise enough
 * and does not have recursive/looping logic.
 * ---
 * If the function does not require very fast execution speed or the logic of the function is very complex,
 * do not inline it, but declare it as a common function and define it in the C source file.
 * ---
 * Notice:
 *  Remember, the reason for using inline functions instead of macro functions is have to isolate platform differences as much as possible in this header file,
 *  only considering exposing interfaces that are supported by all platforms,
 *  rather than mixing all underlying operations, which can make maintenance very difficult.
 * ---
 * In fact, the main purpose is to standardize interface declarations and preserving code prompts.
 * ---
 * Note that this module only implement IO operations,
 * IO initialization/operations related to peripheral/multiplexing are implemented in modules related to peripheral operations.
 */

// TODO DXL 待实现具体调用初始化的位置的思考。（测试阶段暂时直接在start.c调用）
//  可能需要在boot里调用：gpio_button_setup 和 gpio_leds_setup 和 gpio_arm_power_on_setup

void gpio_sysboot_setup(void);
void gpio_button_setup(void);
void gpio_leds_setup(void);
void gpio_arm_power_on_setup(void);
void gpio_inter_usb_spi_role_setup(void);
void gpio_sw_i2c_rst_setup(void);
void gpio_adc_mux_setup(void);
void gpio_fpga_switch_setup(void);
void gpio_fpga_download_setup(void);
void gpio_fpga_on_setup(void);
void gpio_fpga_mod_feedback_setup(void);
void gpio_fpga_mod_only_setup(void);
void gpio_vusb_setup(void);

// -- Deprecated

// Control the relay of antenna? Used on very old models.
__attribute__((deprecated)) void gpio_relay_setup(void);
// The original pm3 has this pin. If it is low, it means that the vdd reaches 5v (USB power supply)
__attribute__((deprecated)) void gpio_nvdd_setup(void);

// -- Deprecated

// ------------------------------------------ INLINE FUNCTIONS ------------------------------------------

STATIC_FORCE_INLINE void Gpio_ARM_Power_ON_High(void);
STATIC_FORCE_INLINE void Gpio_ARM_Power_ON_Low(void);

STATIC_FORCE_INLINE bool Gpio_Button_Read(void);

STATIC_FORCE_INLINE void Gpio_LED_A_High(void);
STATIC_FORCE_INLINE void Gpio_LED_A_Low(void);
STATIC_FORCE_INLINE void Gpio_LED_A_Inv(void);
STATIC_FORCE_INLINE void Gpio_LED_B_High(void);
STATIC_FORCE_INLINE void Gpio_LED_B_Low(void);
STATIC_FORCE_INLINE void Gpio_LED_B_Inv(void);
STATIC_FORCE_INLINE void Gpio_LED_C_High(void);
STATIC_FORCE_INLINE void Gpio_LED_C_Low(void);
STATIC_FORCE_INLINE void Gpio_LED_C_Inv(void);
STATIC_FORCE_INLINE void Gpio_LED_D_High(void);
STATIC_FORCE_INLINE void Gpio_LED_D_Low(void);
STATIC_FORCE_INLINE void Gpio_LED_D_Inv(void);

STATIC_FORCE_INLINE void Gpio_SSC_DOUT_High(void);
STATIC_FORCE_INLINE void Gpio_SSC_DOUT_Low(void);
STATIC_FORCE_INLINE bool Gpio_SSC_DIN_Read(void);
STATIC_FORCE_INLINE bool Gpio_SSC_FRAME_Read(void);
STATIC_FORCE_INLINE bool Gpio_SSC_CLK_Read(void);

STATIC_FORCE_INLINE void Gpio_FPGA_ON_High(void);
STATIC_FORCE_INLINE void Gpio_FPGA_ON_Low(void);
STATIC_FORCE_INLINE void Gpio_FPGA_DIN_High(void);
STATIC_FORCE_INLINE void Gpio_FPGA_DIN_Low(void);
STATIC_FORCE_INLINE void Gpio_FPGA_CCLK_High(void);
STATIC_FORCE_INLINE void Gpio_FPGA_CCLK_Low(void);
STATIC_FORCE_INLINE void Gpio_FPGA_NPROGRAM_High(void);
STATIC_FORCE_INLINE void Gpio_FPGA_NPROGRAM_Low(void);
STATIC_FORCE_INLINE bool Gpio_FPGA_NINIT_Read(void);
STATIC_FORCE_INLINE bool Gpio_FPGA_DONE_Read(void);

STATIC_FORCE_INLINE void Gpio_FPGA_SWITCH_High(void);
STATIC_FORCE_INLINE void Gpio_FPGA_SWITCH_Low(void);

STATIC_FORCE_INLINE void Gpio_FPGA_XC3_M1_High(void);
STATIC_FORCE_INLINE void Gpio_FPGA_XC3_M1_Low(void);
STATIC_FORCE_INLINE void Gpio_FPGA_XC3_M2_High(void);
STATIC_FORCE_INLINE void Gpio_FPGA_XC3_M2_Low(void);

STATIC_FORCE_INLINE void Gpio_MUXSEL_HIPKD_High(void);
STATIC_FORCE_INLINE void Gpio_MUXSEL_HIPKD_Low(void);
STATIC_FORCE_INLINE void Gpio_MUXSEL_LOPKD_High(void);
STATIC_FORCE_INLINE void Gpio_MUXSEL_LOPKD_Low(void);
STATIC_FORCE_INLINE void Gpio_MUXSEL_HIRAW_High(void);
STATIC_FORCE_INLINE void Gpio_MUXSEL_HIRAW_Low(void);
STATIC_FORCE_INLINE void Gpio_MUXSEL_LORAW_High(void);
STATIC_FORCE_INLINE void Gpio_MUXSEL_LORAW_Low(void);

STATIC_FORCE_INLINE void Gpio_I2C_SCL_High(void);
STATIC_FORCE_INLINE void Gpio_I2C_SDA_High(void);
STATIC_FORCE_INLINE void Gpio_I2C_RST_High(void);
STATIC_FORCE_INLINE void Gpio_I2C_SCL_Low(void);
STATIC_FORCE_INLINE void Gpio_I2C_SDA_Low(void);
STATIC_FORCE_INLINE void Gpio_I2C_RST_Low(void);
STATIC_FORCE_INLINE bool Gpio_I2C_SCL_Read(void);
STATIC_FORCE_INLINE bool Gpio_I2C_SDA_Read(void);

STATIC_FORCE_INLINE void Gpio_Inter_USB_SPI_Role_High(void);
STATIC_FORCE_INLINE void Gpio_Inter_USB_SPI_Role_Low(void);

STATIC_FORCE_INLINE bool Gpio_VUSB_Read(void);

// -- Deprecated

STATIC_FORCE_INLINE void Gpio_Relay_High(void);
STATIC_FORCE_INLINE void Gpio_Relay_Low(void);
STATIC_FORCE_INLINE bool Gpio_NVDD_Read(void);

// -- Deprecated

#ifdef PM5
#include "gpio_hw_at32.h"
#else
#include "gpio_hw_at91.h"
#endif

// ------------------------------------------ INLINE FUNCTIONS ------------------------------------------

#endif // GPIO_APIS_H_
