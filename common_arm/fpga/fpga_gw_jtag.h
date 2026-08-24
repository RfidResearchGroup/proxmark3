/*
* GOWIN fpga JTAG software implement
 *
 * @Author DXL
 * MIT license
 */
#ifndef GOWIN_JTAG_H_
#define GOWIN_JTAG_H_

#include <stdint.h>
#include <stdbool.h>

#include "gpio_apis.h"  // GpioInputStatus (via gpio_hw_at32.h under PM5) + GPIOA/GPIOC/GPIOD/GPIO_PINS_*
#include "ticks_apis.h" // SpinDelay
#include "dbprint.h"    // Dbprintf

// 是否将调试打印信息编译进当前模块中
#define DEBUG_GW_JTAG   1

// 毫秒延迟，不要求太高精度
#define delay_ms_gowin(ms)    SpinDelay(ms)

// TCK 电平设置（PC10）
#define set_tck_high()  (AT32_GPIO_FPGA_JTAG_TCK->scr = AT32_GPIO_FPGA_JTAG_TCK_PIN)
#define set_tck_low()   (AT32_GPIO_FPGA_JTAG_TCK->clr = AT32_GPIO_FPGA_JTAG_TCK_PIN)

// TMS 电平设置（PA15）
#define set_tms_high()  (AT32_GPIO_FPGA_JTAG_TMS->scr = AT32_GPIO_FPGA_JTAG_TMS_PIN)
#define set_tms_low()   (AT32_GPIO_FPGA_JTAG_TMS->clr = AT32_GPIO_FPGA_JTAG_TMS_PIN)

// TDI 电平设置（PC12）
#define set_tdi_high()  (AT32_GPIO_FPGA_JTAG_TDI->scr = AT32_GPIO_FPGA_JTAG_TDI_PIN)
#define set_tdi_low()   (AT32_GPIO_FPGA_JTAG_TDI->clr = AT32_GPIO_FPGA_JTAG_TDI_PIN)

// 获取 TDO 电平状态，true 为高，false 为低（PC11）
#define get_tdo()       GpioInputStatus(AT32_GPIO_FPGA_JTAG_TDO, AT32_GPIO_FPGA_JTAG_TDO_PIN)

// JTAGSEL 引脚电平设置（PD2），若 JTAG 脚复用为普通 IO，则烧录前需拉低 JTAGSEL_N
#define set_jtagsel_high()  (AT32_GPIO_FPGA_JTAG_SEL->scr = AT32_GPIO_FPGA_JTAG_SEL_PIN)
#define set_jtagsel_low()   (AT32_GPIO_FPGA_JTAG_SEL->clr = AT32_GPIO_FPGA_JTAG_SEL_PIN)

// 调试打印，受 DEBUG_GW_JTAG 编译开关控制，不再支持运行时开关
#if DEBUG_GW_JTAG
#define dbg_printf(...) Dbprintf(__VA_ARGS__)
#else
#define dbg_printf(...) ((void)0)
#endif

// 产生一个时钟周期的 tck 波形（先低后高），半周期约 250ns，即约 2MHz
#define tck_pulse() \
    do { \
        SysTick->LOAD = GW_JTAG_TCK_HALF_PERIOD_TICKS; \
        SysTick->CTRL = SysTick_CTRL_ENABLE_Msk; \
        set_tck_low(); \
        SysTick->VAL = GW_JTAG_TCK_HALF_PERIOD_TICKS; \
        while ((SysTick->CTRL & SysTick_CTRL_COUNTFLAG_Msk) == 0) {} \
        set_tck_high(); \
        SysTick->VAL = GW_JTAG_TCK_HALF_PERIOD_TICKS; \
        while ((SysTick->CTRL & SysTick_CTRL_COUNTFLAG_Msk) == 0) {} \
    } while (0)

// tck 输出 2mhz 的时钟，持续指定的 us 时长，仅适用于 us > 0 的场景（单脉冲请使用 tck_pulse()）。
// 实测 2.01mhz 左右，理论上可以稳定使用，误差在 ±200khz 内都可接受。
// 注意：一般只会更慢不会更快，最终量产使用前仍需用示波器测量实际输出频率。
#define GW_JTAG_TCK_HALF_PERIOD_TICKS   6 // 250ns @ 36MHz（AHB/8）

#define tck_2m(us) \
    do { \
        uint32_t _cycles = (uint32_t)(us) * 2; /* each us has 2 half-cycles at 2MHz */ \
        SysTick->LOAD = GW_JTAG_TCK_HALF_PERIOD_TICKS; \
        SysTick->CTRL = SysTick_CTRL_ENABLE_Msk; \
        while (_cycles) { \
            set_tck_low(); \
            (void)SysTick->CTRL; /* Clear COUNTFLAG by reading it */ \
            SysTick->VAL = GW_JTAG_TCK_HALF_PERIOD_TICKS; \
            while ((SysTick->CTRL & SysTick_CTRL_COUNTFLAG_Msk) == 0) {} \
            set_tck_high(); \
            (void)SysTick->CTRL; /* Clear COUNTFLAG by reading it */ \
            SysTick->VAL = GW_JTAG_TCK_HALF_PERIOD_TICKS; \
            _cycles--; \
            while ((SysTick->CTRL & SysTick_CTRL_COUNTFLAG_Msk) == 0) {} \
        } \
    } while (0)

typedef enum {
    GOWIN_JTAG_OK = 0U,
    GOWIN_JTAG_ERROR_INVALID_IDCODE,
    GOWIN_JTAG_ERROR_NULL_POINTER,
    GOWIN_JTAG_ERROR_OUT_OF_RANGE,
    GOWIN_JTAG_ERROR_POR_STATUS,
    GOWIN_JTAG_ERROR_VLD_STATUS,
    GOWIN_JTAG_ERROR_ERASE_FAIL,
    GOWIN_JTAG_ERROR_ENABLE_CFG,
} gowin_jtag_status_t;

typedef enum {
    GW_DEVICE_UNKNOWN = 0,
    GW_DEVICE_GW1N_1,
    GW_DEVICE_GW1N_1S,
    GW_DEVICE_GW1NZ_1,
    GW_DEVICE_GW1N_R_Z_2_2B_2C,
    GW_DEVICE_GW1N_1P5_1P5B_1P5C,
    GW_DEVICE_GW1N_R_4,
    GW_DEVICE_GW1N_R_4B,
    GW_DEVICE_GW1N_R_4D,
    GW_DEVICE_GW1NS_4,
    GW_DEVICE_GW1NS_ER_4C,
    GW_DEVICE_GW1N_R_9,
    GW_DEVICE_GW1N_R_9C,
    GW_DEVICE_GW2A_R_18_18C,
    GW_DEVICE_GW2A_55_55C,
} gowin_device_t;

typedef enum {
    GW_FLASH_TYPE_UNKNOWN = 0U, // 未知工艺？
    GW_FLASH_TYPE_TSMC,         // T 工艺
    GW_FLASH_TYPE_HL,           // H 工艺
    GW_FLASH_TYPE_SMIC,         // SMIC 工艺有 ID_GW1NS_2 和 ID_GW1NS_2C，但是我们暂时不打算对接
    GW_FLASH_TYPE_SPI_FLASH,    // 核封了一颗SPI-FLASH或者是只支持外部FLASH
} gowin_flash_type_t;

/**
 * @brief Gowin FPGA Device Status Register (32-bit)
 *
 * Reference:
 *   - 表7-12: GW1N(R)-(1/4B/4C/4D)/GW1NRF-4B 系列
 *   - 表7-13: GW1N(R)-(1P5/2/6/9/9C)/GW1NS-4(4C)/GW1NSR-4(4C)/GW1NSE-4C/GW1NSER-4C/GW1NZ-(1/2) 系列
 *
 * Note:
 *   - Bit 编号从 LSB (bit 0) 到 MSB (bit 31)
 *   - 某些位在不同系列中含义一致，部分位仅在特定系列存在（见注释）
 */
typedef union {
    uint32_t raw;
    struct {
        /* Bit 0 */
        uint32_t crc_error            : 1;  ///< CRC Error Flag (1=发生错误, 0=正常). 所有系列通用.
        /* Bit 1 */
        uint32_t bad_command_error    : 1;  ///< Bad Command Error Flag (1=发生错误). 所有系列通用.
        /* Bit 2 */
        uint32_t id_verify_failed     : 1;  ///< ID Verify Failed Error Flag (1=ID校验失败). 所有系列通用.
        /* Bit 3 */
        uint32_t timeout_error        : 1;  ///< Timeout Error Flag (1=超时错误). 所有系列通用.
        /* Bit 4 */
        uint32_t reserved_4           : 1;  ///< 保留位，固定为0.
        /* Bit 5 */
        uint32_t memory_erase         : 1;  ///< Memory Erase 标志. 所有系列通用.
        /* Bit 6 */
        uint32_t preamble             : 1;  ///< Preamble 标志. 所有系列通用.
        /* Bit 7 */
        uint32_t edit_mode            : 1;  ///< Edit Mode 标志. 所有系列通用.
        /* Bit 8 */
        uint32_t program_spi_directly : 1;  ///< Program SPI Directly 标志. 所有系列通用.
        /* Bit 9 */
        uint32_t autoboot_state       : 1;  ///< AutoBoot State.
                                            ///< - 表7-13: 存在此字段（用于支持AutoBoot的型号）
                                            ///< - 表7-12: 此位为0（即不支持AutoBoot的型号如GW1N-1/4B等）
        /* Bit 10 */
        uint32_t non_jtag_active      : 1;  ///< Non-JTAG Active 标志（例如MSPI/SSPI配置中激活）. 所有系列通用.
        /* Bit 11 */
        uint32_t bypass_state         : 1;  ///< Bypass State 标志. 所有系列通用.
        /* Bit 12 */
        uint32_t vld            : 1;  ///< Gowin VLD (1=正常, 0=异常). 内置Flash相关参数.
                                            ///< 适用于所有带内置Flash的型号（如GW1NS、GW1NZ等）.
        /* Bit 13 */
        uint32_t done_final           : 1;  ///< Done Final (1=配置成功完成, 0=失败). 所有系列通用.
        /* Bit 14 */
        uint32_t security_final       : 1;  ///< Security Final (1=已设置安全位, 0=未设置). 所有系列通用.
        /* Bit 15 */
        uint32_t ready                : 1;  ///< Ready (1=正常, 0=异常). 所有系列通用.
        /* Bit 16 */
        uint32_t por                  : 1;  ///< POR (Power-On Reset) 状态 (1=正常, 0=异常). 所有系列通用.
        /* Bit 17 */
        uint32_t flash_lock           : 1;  ///< Flash Lock 标志：
                                            ///< - 1 = Flash锁定（禁止回读，但允许擦除）
                                            ///< - 仅存在于表7-13所列型号（即带内置Flash的系列，如GW1NS/GW1NZ/GW1NSE等）
                                            ///< - 表7-12型号（如GW1N-1/4B）此位为0（无Flash Lock功能）
        /* Bits 18–31 */
        uint32_t reserved_18_31       : 14; ///< 保留位，固定为0（两表均明确说明）.
    } bits;
} gowin_status_reg_t;

/**
 * Information required during the configuration process
 */
typedef struct {
    uint8_t x_page_buf[256];    // Buffer for incomplete data of x-page
    uint32_t tx_pos;            // Current position of data to be sent, in bytes
    uint32_t tx_total;          // Total size of the data to be sent, in bytes
    bool is_cfg_sram;           // true: config sram, false: config flash
    gowin_jtag_status_t status; // Status of the current configuration process, used to track errors of platform
} gowin_config_ctx_t;

gowin_jtag_status_t gowin_jtag_init(void);
void gowin_jtag_deinit(void);

gowin_device_t gowin_jtag_get_device_type(void);
const char *gowin_jtag_get_device_name(void);
gowin_flash_type_t gowin_get_flash_type(void);
uint32_t gowin_jtag_get_idcode(void);

void gowin_jtag_reset(void);
uint32_t gowin_jtag_read_status(void);
uint32_t gowin_jtag_read_usercode(void);
void gowin_jtag_reprogram(void);
gowin_jtag_status_t gowin_jtag_read_status_reg(gowin_status_reg_t *reg_out);

gowin_jtag_status_t gowin_jtag_sram_erase(void);
gowin_jtag_status_t gowin_jtag_sram_config_start(uint32_t *tx_bits_pos);
gowin_jtag_status_t gowin_jtag_sram_config_write(
    uint8_t *data,
    uint32_t data_length,
    uint32_t *tx_bytes_pos,
    uint32_t tx_bytes_total);
gowin_jtag_status_t gowin_jtag_sram_config_finish(void);

gowin_jtag_status_t gowin_jtag_flash_erase(void);
gowin_jtag_status_t gowin_jtag_flash_config_start(
    uint8_t *xbuf_256,
    uint32_t *tx_bits_pos,
    bool bg_update);
gowin_jtag_status_t gowin_jtag_flash_config_write(
    uint8_t *data,
    uint32_t data_length,
    uint32_t *tx_bytes_pos,
    uint32_t tx_bytes_total);
gowin_jtag_status_t gowin_jtag_flash_config_finish(void);

void gowin_jtag_start_config(gowin_config_ctx_t *cctx);
void gowin_jtag_config_write(uint8_t *data, uint32_t data_length, gowin_config_ctx_t *cctx);
void gowin_jtag_stop_config(gowin_config_ctx_t *cctx);

#endif // GOWIN_JTAG_H_
