/*
 * GOWIN FPGA JTAG software implementation
 *
 * @Author DXL
 * MIT license
 */
#ifndef GOWIN_JTAG_H_
#define GOWIN_JTAG_H_

#include <stdint.h>
#include <stdbool.h>

#include "gpio_apis.h"  // GpioInputStatus (provided via gpio_hw_at32.h under PM5) + GPIOA/GPIOC/GPIOD/GPIO_PINS_*
#include "ticks_apis.h" // SpinDelay
#include "dbprint.h"    // Dbprintf

// Whether to compile debug print information into this module
#define DEBUG_GW_JTAG   1

// Millisecond delay, not requiring high precision
#define delay_ms_gowin(ms)    SpinDelay(ms)

// TCK level setting (PC10)
#define set_tck_high()  (AT32_GPIO_FPGA_JTAG_TCK->scr = AT32_GPIO_FPGA_JTAG_TCK_PIN)
#define set_tck_low()   (AT32_GPIO_FPGA_JTAG_TCK->clr = AT32_GPIO_FPGA_JTAG_TCK_PIN)

// TMS level setting (PA15)
#define set_tms_high()  (AT32_GPIO_FPGA_JTAG_TMS->scr = AT32_GPIO_FPGA_JTAG_TMS_PIN)
#define set_tms_low()   (AT32_GPIO_FPGA_JTAG_TMS->clr = AT32_GPIO_FPGA_JTAG_TMS_PIN)

// TDI level setting (PC12)
#define set_tdi_high()  (AT32_GPIO_FPGA_JTAG_TDI->scr = AT32_GPIO_FPGA_JTAG_TDI_PIN)
#define set_tdi_low()   (AT32_GPIO_FPGA_JTAG_TDI->clr = AT32_GPIO_FPGA_JTAG_TDI_PIN)

// Read the TDO level; true = high, false = low (PC11)
#define get_tdo()       GpioInputStatus(AT32_GPIO_FPGA_JTAG_TDO, AT32_GPIO_FPGA_JTAG_TDO_PIN)

// JTAGSEL pin level setting (PD2); if the JTAG pins are muxed as normal IO, JTAGSEL_N must be pulled low before programming
#define set_jtagsel_high()  (AT32_GPIO_FPGA_JTAG_SEL->scr = AT32_GPIO_FPGA_JTAG_SEL_PIN)
#define set_jtagsel_low()   (AT32_GPIO_FPGA_JTAG_SEL->clr = AT32_GPIO_FPGA_JTAG_SEL_PIN)

// Debug print, controlled by the DEBUG_GW_JTAG compile switch; runtime toggling is no longer supported
#if DEBUG_GW_JTAG
#define dbg_printf(...) Dbprintf(__VA_ARGS__)
#else
#define dbg_printf(...) ((void)0)
#endif

// Generate one tck waveform cycle (low then high), half period ~250ns, i.e. ~2MHz
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

// tck outputs a 2MHz clock for the specified us duration; only for us > 0 (use tck_pulse() for a single pulse).
// Measured around 2.01MHz; theoretically stable, with an error within ±200kHz acceptable.
// Note: it is generally slower, not faster; measure the actual output frequency with an oscilloscope before production use.
#define GW_JTAG_TCK_HALF_PERIOD_TICKS   6 // 250ns @ 36MHz (AHB/8)

#define tck_2m(us) \
    do { \
        uint32_t _cycles = (uint32_t)(us) * 2; /* at 2MHz each us has 2 half-cycles */ \
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
    GW_FLASH_TYPE_UNKNOWN = 0U, // Unknown process?
    GW_FLASH_TYPE_TSMC,         // T process
    GW_FLASH_TYPE_HL,           // H process
    GW_FLASH_TYPE_SMIC,         // SMIC process has ID_GW1NS_2 and ID_GW1NS_2C, but we don't plan to support them for now
    GW_FLASH_TYPE_SPI_FLASH,    // Has an internal SPI-FLASH or only supports an external FLASH
} gowin_flash_type_t;

/**
 * @brief Gowin FPGA Device Status Register (32-bit)
 *
 * Reference:
 *   - Table 7-12: GW1N(R)-(1/4B/4C/4D)/GW1NRF-4B series
 *   - Table 7-13: GW1N(R)-(1P5/2/6/9/9C)/GW1NS-4(4C)/GW1NSR-4(4C)/GW1NSE-4C/GW1NSER-4C/GW1NZ-(1/2) series
 *
 * Note:
 *   - Bits are numbered from LSB (bit 0) to MSB (bit 31)
 *   - Some bits have the same meaning across series, while others only exist in specific series (see comments)
 */
typedef union {
    uint32_t raw;
    struct {
        /* Bit 0 */
        uint32_t crc_error            : 1;  ///< CRC Error Flag (1=error, 0=normal). Common to all series.
        /* Bit 1 */
        uint32_t bad_command_error    : 1;  ///< Bad Command Error Flag (1=error). Common to all series.
        /* Bit 2 */
        uint32_t id_verify_failed     : 1;  ///< ID Verify Failed Error Flag (1=ID verification failed). Common to all series.
        /* Bit 3 */
        uint32_t timeout_error        : 1;  ///< Timeout Error Flag (1=timeout error). Common to all series.
        /* Bit 4 */
        uint32_t reserved_4           : 1;  ///< Reserved, always 0.
        /* Bit 5 */
        uint32_t memory_erase         : 1;  ///< Memory Erase flag. Common to all series.
        /* Bit 6 */
        uint32_t preamble             : 1;  ///< Preamble flag. Common to all series.
        /* Bit 7 */
        uint32_t edit_mode            : 1;  ///< Edit Mode flag. Common to all series.
        /* Bit 8 */
        uint32_t program_spi_directly : 1;  ///< Program SPI Directly flag. Common to all series.
        /* Bit 9 */
        uint32_t autoboot_state       : 1;  ///< AutoBoot State.
        ///< - Table 7-13: this field exists (for models supporting AutoBoot)
        ///< - Table 7-12: this bit is 0 (models that don't support AutoBoot, e.g. GW1N-1/4B)
        /* Bit 10 */
        uint32_t non_jtag_active      : 1;  ///< Non-JTAG Active flag (e.g. active during MSPI/SSPI configuration). Common to all series.
        /* Bit 11 */
        uint32_t bypass_state         : 1;  ///< Bypass State flag. Common to all series.
        /* Bit 12 */
        uint32_t vld                  : 1;  ///< Gowin VLD (1=normal, 0=abnormal). Internal Flash related parameter.
        ///< Applies to all models with internal Flash (e.g. GW1NS, GW1NZ).
        /* Bit 13 */
        uint32_t done_final           : 1;  ///< Done Final (1=configuration completed successfully, 0=failed). Common to all series.
        /* Bit 14 */
        uint32_t security_final       : 1;  ///< Security Final (1=security bit set, 0=not set). Common to all series.
        /* Bit 15 */
        uint32_t ready                : 1;  ///< Ready (1=normal, 0=abnormal). Common to all series.
        /* Bit 16 */
        uint32_t por                  : 1;  ///< POR (Power-On Reset) status (1=normal, 0=abnormal). Common to all series.
        /* Bit 17 */
        uint32_t flash_lock           : 1;  ///< Flash Lock flag:
        ///< - 1 = Flash locked (read-back disabled, but erase allowed)
        ///< - Only present in the models listed in Table 7-13 (i.e. series with internal Flash, e.g. GW1NS/GW1NZ/GW1NSE)
        ///< - On Table 7-12 models (e.g. GW1N-1/4B) this bit is 0 (no Flash Lock function)
        /* Bits 18–31 */
        uint32_t reserved_18_31       : 14; ///< Reserved, always 0 (both tables state this explicitly).
    } bits;
} gowin_status_reg_t;

/**
 * Information required during the configuration process
 */
typedef struct {
    uint8_t x_page_buf[256];    // Buffer for incomplete x-page data
    uint32_t tx_pos;            // Current position of the data to be sent, in bytes
    uint32_t tx_total;          // Total size of the data to be sent, in bytes
    bool is_cfg_sram;           // true: configure SRAM, false: configure Flash
    gowin_jtag_status_t status; // Status of the current configuration process, used to track platform errors
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
