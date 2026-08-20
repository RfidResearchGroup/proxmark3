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

// 是否将调试打印信息编译进当前模块中
#define DEBUG_GW_JTAG   1

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

typedef struct {
    /**
     * 设置TCK电平状态，true为高，false为低。
     */
    void (*set_tck)(bool level);
    /**
     * 设置TMS电平状态，true为高，false为低。
     */
    void (*set_tms)(bool level);
    /**
     * 设置TDI电平状态，true为高，false为低。
     */
    void (*set_tdi)(bool level);
    /**
     * 获取TDO电平状态，true为高，false为低。
     */
    bool (*get_tdo)(void);
    /**
     * 微秒延迟，不要求太高精度,在 tck_pulse 未实现时，此延时接口作为一个后备方案提供大概500kHZ的TCK时钟输出
     */
    void (*delay_us)(int us);
    /**
     * 毫秒延迟，不要求太高精度
     */
    void (*delay_ms)(int ms);
    /**
     * 产生 2mhz 的tck时钟，持续指定的us时长，如果传入参数为0，则只产生一个时钟周期的tck波形
     * 也就是拉低tck持续半周期 250ns，然后拉高tck持续半周期 250ns
     * 注意：实际精度不能低于 1.8mhz 和高于 2.2mhz,也就是正负200K的精度都在可接受范围内
     */
    void (*tck_2m)(uint32_t us);
    /**
     * 可选的实现，如果不实现，则不会输出任何调试信息，并且你可选将当前模块的所有打印信息编译进模块中
     * 如果你是在资源紧张的平台，则可以通过 DEBUG_GW_JTAG 去除当前模块的所有调试信息
     */
    void (*dbg_printf)(const char *fmt, ...);
    /**
     * 可选的实现，如果复用了JTAG脚为普通IO，则需要在烧录之前，拉低 JTAGSEL_N 引脚
     */
    void (*set_jtagsel)(bool level);
} gowin_jtag_ops_t;

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
    gowin_jtag_ops_t *jtag_ops; // Pointer to the JTAG operations structure, used for functions during configuration
    gowin_jtag_status_t status; // Status of the current configuration process, used to track errors of platform
} gowin_config_ctx_t;

gowin_jtag_status_t gowin_jtag_init(gowin_jtag_ops_t *ops);
void gowin_jtag_deinit(gowin_jtag_ops_t *jtag_ops);

gowin_device_t gowin_jtag_get_device_type(void);
const char *gowin_jtag_get_device_name(void);
gowin_flash_type_t gowin_get_flash_type(void);
uint32_t gowin_jtag_get_idcode(void);

void gowin_jtag_reset(gowin_jtag_ops_t *jtag_ops);
uint32_t gowin_jtag_read_status(gowin_jtag_ops_t *jtag_ops);
uint32_t gowin_jtag_read_usercode(gowin_jtag_ops_t *jtag_ops);
void gowin_jtag_reprogram(gowin_jtag_ops_t *jtag_ops);
gowin_jtag_status_t gowin_jtag_read_status_reg(gowin_status_reg_t *reg_out, gowin_jtag_ops_t *jtag_ops);

gowin_jtag_status_t gowin_jtag_sram_erase(gowin_jtag_ops_t *jtag_ops);
gowin_jtag_status_t gowin_jtag_sram_config_start(uint32_t *tx_bits_pos, gowin_jtag_ops_t *jtag_ops);
gowin_jtag_status_t gowin_jtag_sram_config_write(
    uint8_t *data,
    uint32_t data_length,
    uint32_t *tx_bytes_pos,
    uint32_t tx_bytes_total,
    gowin_jtag_ops_t *jtag_ops);
gowin_jtag_status_t gowin_jtag_sram_config_finish(gowin_jtag_ops_t *jtag_ops);

gowin_jtag_status_t gowin_jtag_flash_erase(gowin_jtag_ops_t *jtag_ops);
gowin_jtag_status_t gowin_jtag_flash_config_start(
    uint8_t *xbuf_256,
    uint32_t *tx_bits_pos,
    bool bg_update,
    gowin_jtag_ops_t *jtag_ops);
gowin_jtag_status_t gowin_jtag_flash_config_write(
    uint8_t *data,
    uint32_t data_length,
    uint32_t *tx_bytes_pos,
    uint32_t tx_bytes_total,
    gowin_jtag_ops_t *jtag_ops);
gowin_jtag_status_t gowin_jtag_flash_config_finish(gowin_jtag_ops_t *jtag_ops);

void gowin_jtag_start_config(gowin_config_ctx_t *cctx);
void gowin_jtag_config_write(uint8_t *data, uint32_t data_length, gowin_config_ctx_t *cctx);
void gowin_jtag_stop_config(gowin_config_ctx_t *cctx);

#endif // GOWIN_JTAG_H_
