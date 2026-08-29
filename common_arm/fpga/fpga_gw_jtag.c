/*
 * GOWIN FPGA JTAG software implementation
 *
 * @Author DXL
 * MIT license
 */

#include <string.h>
#include "commonutil.h"
#include "fpga_gw_jtag.h"

#define INST_BYPASS             0xFF
#define INST_IDCODE             0x11
#define INST_STATUS             0x41
#define INST_USERCODE           0x13
#define INST_CONFIG_ENABLE      0x15
#define INST_CONFIG_DISABLE     0x3A
#define INST_NOOP               0x02
#define INST_SRAM_ERASE         0x05
#define INST_SRAM_ERASE_DONE    0x09
#define INST_EFLASH_ERASE       0x75
#define INST_EF_PROGRAM         0x71
#define INST_EF_READ            0x73
#define INST_REPROGRAM          0x3C
#define INST_TRANSFER_CFG       0x17
#define INST_ADDR_INIT          0x12
#define INST_SRAM_READ          0x03


typedef struct {
    uint16_t sram_erase_ms; // Time to wait after sending EraseSram (0x05) and Noop (0x02) for the erase to complete
    uint16_t y_page_w_wait_us; // Delay required after writing one y-page
    uint16_t x_page_w_wait_us; // Delay required after writing one x-page
} gowin_timing_t;

typedef struct {
    uint32_t idcode;
    gowin_device_t device;
    const char *name;
    gowin_flash_type_t flash_type;
    bool reprogram; // On some devices, if the 4 JTAG pins or JTAGSEL_N are muxed as GPIO, a reprogram command must be sent once before reconfiguration.
    gowin_timing_t timing;
} device_map_t;

static gowin_device_t detected_device = GW_DEVICE_UNKNOWN;
static uint32_t cached_idcode = 0;
static bool m_flash_bg_update = false;
static uint8_t *m_flash_xpage_buf = NULL;
static uint16_t m_flash_xpage_pos = 0;

static const device_map_t device_map[] = {
    {
        0x0900281B, GW_DEVICE_GW1N_1, "GW1N-1", GW_FLASH_TYPE_HL, true,
        {1, 0, 2400}
    },
    {
        0x0900381B, GW_DEVICE_GW1N_1S, "GW1N-1S", GW_FLASH_TYPE_HL, true,
        {1, 0, 2400}
    },
    {
        0x0100681B, GW_DEVICE_GW1NZ_1, "GW1NZ-1", GW_FLASH_TYPE_TSMC, true,
        {1, 0, 6}
    },
    {
        0x0120681B, GW_DEVICE_GW1N_R_Z_2_2B_2C, "GW1N(R/Z)-2/2B/2C/1P5/1P5B/1P5C", GW_FLASH_TYPE_TSMC, false,
        {2, 16, 6}
    },
    // The above merges GW1N-2 and GW1N-1P5 series into a single mapping {0x0120681B, GW_DEVICE_GW1N_1P5_1P5B_1P5C, "GW1N-1P5/1P5B/1P5C", {2, 120, 0, 32}},
    {
        0x0100381B, GW_DEVICE_GW1N_R_4, "GW1N(R)-4", GW_FLASH_TYPE_TSMC, true,
        {2, 16, 6}
    },
    {
        0x1100381B, GW_DEVICE_GW1N_R_4B, "GW1N(R)-4B/4D", GW_FLASH_TYPE_TSMC, true,
        {2, 16, 6}
    },
    // The above merges GW1NR-4B and GW1NR-4D series into a single mapping {0x1100381B, GW_DEVICE_GW1N_R_4D, "GW1N(R)-4D", {2, 120, 0, 32}},
    {
        0x0100881B, GW_DEVICE_GW1NS_4, "GW1NS-4", GW_FLASH_TYPE_TSMC, false,
        {2, 16, 6}
    },
    {
        0x0100981B, GW_DEVICE_GW1NS_ER_4C, "GW1NS(ER)-4C", GW_FLASH_TYPE_TSMC, false,
        {2, 16, 6}
    },
    {
        0x1100581B, GW_DEVICE_GW1N_R_9, "GW1N(R)-9", GW_FLASH_TYPE_TSMC, true,
        {4, 16, 6}
    },
    {
        0x1100481B, GW_DEVICE_GW1N_R_9C, "GW1N(R)-9C", GW_FLASH_TYPE_TSMC, true,
        {4, 16, 6}
    },

    // Per the manual: GW2ANR-18/GW2AN-55 have an internal SPI-Flash, programmed the same way as GW2A-18/GW2A-55.
    //  That is, the GW2A series uses an SPI flash: the JTAG interface must be bridged to MSPI, then SPI commands operate the
    //  on-chip SPI-FLASH (or an external FLASH). The rough flow is JTAG -> 0x16 command -> MSPI -> 0x06 (write enable) -> 0xC7 (erase)...
    //  In short, aside from the JTAG used before bridging to MSPI, everything else is SPI-FLASH operation, so erase does not
    //  require a clock of a specific rate like the internal FLASH does.
    // {0x0000081B, GW_DEVICE_GW2A_R_18_18C, "GW2A(R)-18/18C", {6, 120, 0, 32}},
    // {0x0000281B, GW_DEVICE_GW2A_55_55C, "GW2A-55/55C", {10, 120, 0, 32}},

    // We don't plan to support these two old models for now: they appear to be discontinued and marked "old" by the vendor,
    //  with their manual info removed, making sample testing difficult.
    // Note: the internal FLASH process of these two chips is SMIC; the vendor has STM32 example code that wraps their internal FLASH programming.
    //  This series requires a 30-35us delay after each Y page write.
    // #define ID_GW1NS_2 0x0300081B
    // #define ID_GW1NS_2C 0x0300181B
};

// Look up the device info mapping table by ID; return NULL if no matching device is found
static const device_map_t *get_device_map_by_idcode(void) {
    for (size_t i = 0; i < ARRAYLEN(device_map); i++) {
        if (device_map[i].idcode == cached_idcode) {
            return &device_map[i];
        }
    }
    return NULL;
}

// Set the TAP state machine and generate one clock; the clock rate depends on the tck_pulse() function
static RAMFUNC void jtag_tap_clock(bool tms) {
    if (tms) {
        set_tms_high();
    } else {
        set_tms_low();
    }
    tck_pulse();
}

// Move from Run-Test/Idle to Shift-IR (standard IEEE 1149.1 path)
static void jtag_goto_shift_ir(void) {
    jtag_tap_clock(1); // -> Select-DR-Scan
    jtag_tap_clock(1); // -> Select-IR-Scan
    jtag_tap_clock(0); // -> Capture-IR
    jtag_tap_clock(0); // -> Shift-IR
}

static void jtag_shift_ir_safe(uint8_t inst) {
    jtag_goto_shift_ir();
    for (int i = 0; i < 8; i++) {
        if ((inst >> i) & 1) {
            set_tdi_high();
        } else {
            set_tdi_low();
        }
        jtag_tap_clock(i == 7); // -> enter Exit1-IR on the last bit
    }
    // Exit1-IR -> Update-IR -> Run-Test/Idle
    jtag_tap_clock(1); // -> Update-IR
    jtag_tap_clock(0); // -> Run-Test/Idle
    // Per the Gowin spec: hold at least 3 TCK cycles in Run-Test/Idle after loading the IR
    for (int i = 0; i < 3; i++) {
        tck_pulse();
    }
}

// Move from Run-Test/Idle to Shift-DR (standard IEEE 1149.1 path)
static void jtag_goto_shift_dr(void) {
    jtag_tap_clock(1); // -> Select-DR
    jtag_tap_clock(0); // -> Capture-DR
    jtag_tap_clock(0); // -> Shift-DR
}

// Only for data sent LSB-first
static void jtag_shift_dr_safe(const uint8_t *tx, uint8_t *rx, uint32_t bits) {
    // From Run-Test/Idle -> Select-DR-Scan -> Capture-DR -> Shift-DR
    jtag_goto_shift_dr();

    uint8_t byte = 0;
    for (uint32_t i = 0; i < bits; i++) {
        int byte_idx = i / 8;
        int bit_idx = i % 8;
        bool tdi = tx ? ((tx[byte_idx] >> bit_idx) & 1) : false;
        if (tdi) {
            set_tdi_high();
        } else {
            set_tdi_low();
        }
        jtag_tap_clock(i == bits - 1); // -> enter Exit1-DR on the last bit

        if (rx) {
            bool tdo = get_tdo();
            byte |= (tdo << bit_idx);
            if (bit_idx == 7 || i == bits - 1) {
                rx[byte_idx] = byte;
                byte = 0;
            }
        }
    }

    // Exit1-DR -> Update-DR -> Run-Test/Idle
    jtag_tap_clock(1); // -> Update-DR
    jtag_tap_clock(0); // -> Run-Test/Idle
}

#define jtag_shift_dr_fast() \
    do { \
        set_tdi_low(); \
        set_tms_high(); \
        tck_pulse(); /* -> Select-DR */ \
        set_tms_low(); \
        tck_pulse(); /* -> Capture-DR */ \
        tck_pulse(); /* -> Shift-DR */ \
        for (uint8_t _i = 0; _i < 31; _i++) { \
            tck_pulse(); \
        } \
        set_tms_high(); \
        tck_pulse(); /* 32 */ \
        /* Exit1-DR -> Update-DR -> Run-Test/Idle */ \
        tck_pulse(); /* -> Update-DR */ \
        set_tms_low(); \
        tck_pulse(); /* -> Run-Test/Idle */ \
    } while (0)

#if DEBUG_GW_JTAG
static void print_gowin_status(gowin_status_reg_t *status) {
    dbg_printf("Gowin Status Register (raw = 0x%08X):", status->raw);
    /*
    jtag_ops->dbg_print("  crc_error            : %u  // CRC Error Flag",            status->bits.crc_error);
    jtag_ops->dbg_print("  bad_command_error    : %u  // Bad Command Error Flag",    status->bits.bad_command_error);
    jtag_ops->dbg_print("  id_verify_failed     : %u  // ID Verify Failed Error Flag", status->bits.id_verify_failed);
    jtag_ops->dbg_print("  timeout_error        : %u  // Timeout Error Flag",        status->bits.timeout_error);
    jtag_ops->dbg_print("  reserved_4           : %u  // Reserved (should be 0)",   status->bits.reserved_4);
    jtag_ops->dbg_print("  memory_erase         : %u  // Memory Erase Flag",         status->bits.memory_erase);
    jtag_ops->dbg_print("  preamble             : %u  // Preamble Flag",             status->bits.preamble);

    */

    dbg_printf("  edit_mode            : %u  // Edit Mode Flag", status->bits.edit_mode);

    /*

    jtag_ops->dbg_print("  program_spi_directly : %u  // Program SPI Directly Flag", status->bits.program_spi_directly);
    jtag_ops->dbg_print("  autoboot_state       : %u  // AutoBoot State",           status->bits.autoboot_state);
    jtag_ops->dbg_print("  non_jtag_active      : %u  // Non-JTAG Active Flag",      status->bits.non_jtag_active);
    jtag_ops->dbg_print("  bypass_state         : %u  // Bypass State Flag",         status->bits.bypass_state);
    jtag_ops->dbg_print("  vld                  : %u  // VLD (1=normal)",            status->bits.vld);

    */

    dbg_printf("  done_final           : %u  // Done Final (1=success)", status->bits.done_final);
    dbg_printf("  security_final       : %u  // Security Final (1=secured)", status->bits.security_final);
    dbg_printf("  ready                : %u  // Ready (1=normal)", status->bits.ready);
    dbg_printf("  por                  : %u  // POR (1=normal)", status->bits.por);
    /*
    jtag_ops->dbg_print("  flash_lock           : %u  // Flash Lock (1=locked)",     status->bits.flash_lock);
    jtag_ops->dbg_print("  reserved_18_31       : %u  // Reserved bits [31:18] (should be 0)", status->bits.reserved_18_31);
    */
}
#endif

static uint32_t gowin_jtag_read_idcode_u32(void) {
    uint8_t buf[4] = {0};
    jtag_shift_ir_safe(INST_IDCODE);
    jtag_shift_dr_safe(NULL, buf, 32);
    return (buf[3] << 24) | (buf[2] << 16) | (buf[1] << 8) | buf[0];
}

/**
 * Initialize the JTAG interface
 *
 * @return GOWIN_JTAG_OK on success
 */
gowin_jtag_status_t gowin_jtag_init(void) {
    // Before starting JTAG operations, pull JTAGSEL low to release the FPGA's JTAG pin mux
    set_jtagsel_low();
    // Reset the TAP state machine so communication with the device starts from Run-Test/Idle
    gowin_jtag_reset();
    // Read the IDCODE and cache it in a global
    cached_idcode = gowin_jtag_read_idcode_u32();
    const device_map_t *dm = get_device_map_by_idcode();
    detected_device = dm ? dm->device : GW_DEVICE_UNKNOWN;
    return detected_device == GW_DEVICE_UNKNOWN ? GOWIN_JTAG_ERROR_INVALID_IDCODE : GOWIN_JTAG_OK;
}

void gowin_jtag_deinit(void) {
    // Pull JTAGSEL high to restore the JTAG pins to GPIO
    set_jtagsel_high();
}

gowin_device_t gowin_jtag_get_device_type(void) {
    return detected_device;
}

const char *gowin_jtag_get_device_name(void) {
    const device_map_t *dm = get_device_map_by_idcode();
    return dm ? dm->name : "Unknown";
}

gowin_flash_type_t gowin_get_flash_type(void) {
    const device_map_t *dm = get_device_map_by_idcode();
    return dm ? dm->flash_type : GW_FLASH_TYPE_UNKNOWN;
}

uint32_t gowin_jtag_get_idcode(void) {
    return cached_idcode;
}

void gowin_jtag_reset(void) {
    set_tms_high();
    for (int i = 0; i < 6; i++) {
        tck_pulse(); // Replaces the original set_tck toggle
    }
    // Enter Run-Test/Idle explicitly
    jtag_tap_clock(0);
}

static uint32_t gowin_jtag_read_status_u32(void) {
    jtag_shift_ir_safe(INST_STATUS);
    uint8_t buf[4] = {0};
    jtag_shift_dr_safe(NULL, buf, 32);
    return (buf[3] << 24) | (buf[2] << 16) | (buf[1] << 8) | buf[0];
}

uint32_t gowin_jtag_read_status(void) {
    return gowin_jtag_read_status_u32();
}

uint32_t gowin_jtag_read_usercode(void) {
    jtag_shift_ir_safe(INST_USERCODE);
    uint8_t buf[4] = {0};
    jtag_shift_dr_safe(NULL, buf, 32);
    return (buf[3] << 24) | (buf[2] << 16) | (buf[1] << 8) | buf[0];
}

void gowin_jtag_reprogram(void) {
    jtag_shift_ir_safe(INST_REPROGRAM);
    jtag_shift_ir_safe(INST_NOOP);
    delay_ms_gowin(200);
}

gowin_jtag_status_t gowin_jtag_read_status_reg(gowin_status_reg_t *reg_out) {
    if (reg_out) {
        reg_out->raw = gowin_jtag_read_status_u32();
    }
#if DEBUG_GW_JTAG
    print_gowin_status(reg_out);
#endif
    return GOWIN_JTAG_OK;
}

static gowin_jtag_status_t gowin_jtag_cfg_enable(bool enable) {
    gowin_jtag_status_t status;
    gowin_status_reg_t status_reg;

    // Send command
    if (enable) {
        jtag_shift_ir_safe(INST_CONFIG_ENABLE);
    } else {
        jtag_shift_ir_safe(INST_CONFIG_DISABLE);
        jtag_shift_ir_safe(INST_NOOP);
    }

    // Check status and wait for Edit mode to be entered
    uint32_t retry = 100000; // timeout
    while (retry--) {
        status = gowin_jtag_read_status_reg(&status_reg);
        if (status != GOWIN_JTAG_OK) {
            return status;
        }
        if (enable && status_reg.bits.edit_mode) {
            return GOWIN_JTAG_OK;
        }
        if (!enable && !status_reg.bits.edit_mode) {
            return GOWIN_JTAG_OK;
        }
    }

    return GOWIN_JTAG_ERROR_ENABLE_CFG;
}

gowin_jtag_status_t gowin_jtag_sram_config_start(uint32_t *tx_bits_pos) {
    if (detected_device == GW_DEVICE_UNKNOWN) return GOWIN_JTAG_ERROR_INVALID_IDCODE;
    // TAP reset — very important; brings the FPGA TAP state machine back to Run-Test-Idle
    gowin_jtag_reset();
    // In any case, always erase SRAM first when starting SRAM configuration
    gowin_jtag_status_t status = gowin_jtag_sram_erase();
    if (status != GOWIN_JTAG_OK) {
        return status;
    }
    jtag_shift_ir_safe(INST_CONFIG_ENABLE); // Send ConfigEnable command 0x15
    jtag_shift_ir_safe(INST_ADDR_INIT); // Send Address Initialize command 0x12
    jtag_shift_ir_safe(INST_TRANSFER_CFG); // Send Transfer Configuration Data command 0x17
    jtag_goto_shift_dr(); // Move the state machine to Shift-DR (data register)

    // Send the Bitstream Data MSB-first bit by bit, transmit the entire bitstream file contents, then return to Run-Test-Idle
    // Note: this runs over the config interface, which allows splitting the operation into multiple steps, sending the file a bit at a time until all of it is sent
    *tx_bits_pos = 0; // Reset the bitstream position being transferred here

    return GOWIN_JTAG_OK;
}

gowin_jtag_status_t gowin_jtag_sram_config_write(uint8_t *data, uint32_t data_length, uint32_t *tx_bytes_pos,
                                                 uint32_t tx_bytes_total) {
    if (!data) return GOWIN_JTAG_ERROR_NULL_POINTER;
    if (detected_device == GW_DEVICE_UNKNOWN) return GOWIN_JTAG_ERROR_INVALID_IDCODE;

    // Send the Bitstream Data MSB-first bit by bit, transmit the entire bitstream file contents, then return to Run-Test-Idle
    for (uint32_t i = 0; i < data_length; i++) {
        // Send a byte
        for (uint8_t j = 0; j < 8; j++) {
            // Send bit by bit
            if ((data[i] >> (7 - j)) & 0x01) {
                set_tdi_high();
            } else {
                set_tdi_low();
            }
            if (j == 7) {
                // Increment tx_bytes_pos after one byte is transferred
                (*tx_bytes_pos)++;
                // -> enter Exit1-DR on the last bit of the last byte
                jtag_tap_clock(*tx_bytes_pos == tx_bytes_total);
            } else {
                jtag_tap_clock(0); // One clock, do not enter Exit1-DR
            }
        }
    }

    return GOWIN_JTAG_OK;
}

gowin_jtag_status_t gowin_jtag_sram_config_finish(void) {
    jtag_shift_ir_safe(INST_CONFIG_DISABLE);
    jtag_shift_ir_safe(INST_NOOP);

    // Wait 60ms after the SRAM write for the status code to refresh
    delay_ms_gowin(60);

    // Remember to reset the state machine so the FPGA returns to Run-Test/Idle, otherwise the new firmware won't start
    gowin_jtag_reset();

    return GOWIN_JTAG_OK;
}

gowin_jtag_status_t gowin_jtag_sram_erase(void) {
    const device_map_t *dm = get_device_map_by_idcode();

    if (!dm) return GOWIN_JTAG_ERROR_NULL_POINTER;

    jtag_shift_ir_safe(INST_CONFIG_ENABLE);
    jtag_shift_ir_safe(INST_SRAM_ERASE);
    jtag_shift_ir_safe(INST_NOOP);

    tck_2m(dm->timing.sram_erase_ms * 1000);
    // delay_ms(dm->timing.sram_erase_ms);

    jtag_shift_ir_safe(INST_SRAM_ERASE_DONE);
    jtag_shift_ir_safe(INST_NOOP);
    jtag_shift_ir_safe(INST_CONFIG_DISABLE);
    jtag_shift_ir_safe(INST_NOOP);

    return GOWIN_JTAG_OK;
}

// Read status and check POR & VLD
static gowin_jtag_status_t gowin_check_status_gw1n(gowin_status_reg_t *reg_out) {
    gowin_jtag_read_status_reg(reg_out);
    if (!reg_out->bits.vld) {
        return GOWIN_JTAG_ERROR_VLD_STATUS;
    }
    if (!reg_out->bits.por) {
        return GOWIN_JTAG_ERROR_POR_STATUS;
    }
    return GOWIN_JTAG_OK;
}

// Read out and check whether the erase succeeded; this function is only for the GW1N series
static gowin_jtag_status_t gowin_check_erase_gw1n(gowin_status_reg_t *reg_out) {
    gowin_jtag_read_status_reg(reg_out);
    // Do not check the Security Final bit
    if (reg_out->bits.vld && reg_out->bits.por && reg_out->bits.ready && reg_out->bits.done_final) {
        return GOWIN_JTAG_ERROR_ERASE_FAIL;
    }
    return GOWIN_JTAG_OK;
}

gowin_jtag_status_t gowin_jtag_flash_erase(void) {
    gowin_status_reg_t status_reg;

    if (detected_device == GW_DEVICE_UNKNOWN) return GOWIN_JTAG_ERROR_INVALID_IDCODE;

    const device_map_t *dm = get_device_map_by_idcode();
    if (dm == NULL) {
        return GOWIN_JTAG_ERROR_INVALID_IDCODE;
    }

    // Read the status value to confirm everything is OK
    gowin_jtag_status_t api_status = gowin_check_status_gw1n(&status_reg);
    if (api_status != GOWIN_JTAG_OK) {
        return api_status;
    }

    // if (dbg_printf) dbg_printf("m_flash_bg_update = %d", m_flash_bg_update);

    // If not doing background programming, check the done_final bit: if it is high, clear SRAM; otherwise no need
    //  Because in background programming we must keep the FPGA firmware in SRAM running; the update only touches FLASH and does not overwrite SRAM, so service is not interrupted
    if (m_flash_bg_update == false && status_reg.bits.done_final) {
        // Erase SRAM
        api_status = gowin_jtag_sram_erase();
        if (api_status != GOWIN_JTAG_OK) {
            return api_status;
        }
        // Verify the SRAM erase result
        api_status = gowin_check_erase_gw1n(&status_reg);
        if (api_status != GOWIN_JTAG_OK) {
            return api_status;
        }
        dbg_printf("erase the SRAM is finish, next step erase the FLASH");
    }

    // The erase procedure differs depending on the FLASH process
    api_status = gowin_jtag_cfg_enable(true);
    if (api_status != GOWIN_JTAG_OK) {
        return api_status;
    }

    jtag_shift_ir_safe(INST_EFLASH_ERASE); // Send the embedded FLASH erase command 0x75

    if (dm->flash_type == GW_FLASH_TYPE_HL) {
        for (int i = 0; i < 65; i++) {
            // The H process requires repeating this step 65 times, per the manual
            // Move the state machine to Shift-DR (data register) and generate 32 clocks (TDI held low)
            jtag_shift_dr_fast();
        }
        tck_2m(95 * 1000); // The H process requires 95ms of continuous clocks in Run-Test-Idle afterwards
        dbg_printf("erase for GW_FLASH_TYPE_HL");
    }
    if (dm->flash_type == GW_FLASH_TYPE_TSMC) {
        jtag_shift_dr_fast(); // The T process only requires one 32-bit output transfer clock
        tck_2m(150 * 1000); // The T process requires 120-150ms of continuous clocks in Run-Test-Idle afterwards
        dbg_printf("erase for GW_FLASH_TYPE_TSMC");
    }

    api_status = gowin_jtag_cfg_enable(false);
    if (api_status != GOWIN_JTAG_OK) {
        return api_status;
    }

    // In the official code, the H process delays 500ms after sending 0x02 before continuing, and the T process delays 200ms
    if (dm->flash_type == GW_FLASH_TYPE_HL) {
        delay_ms_gowin(500);
        if (m_flash_bg_update == false) {
            // If background programming is enabled, no status-code exception check is needed, since the firmware is still running normally
            api_status = gowin_check_erase_gw1n(&status_reg);
            if (api_status != GOWIN_JTAG_OK) {
                // Erase failed, report the error directly
                return api_status;
            }
        }
    }
    if (dm->flash_type == GW_FLASH_TYPE_TSMC) {
        delay_ms_gowin(200);
        if (m_flash_bg_update == false) {
            // If background programming is enabled, reconfiguration must not be triggered, otherwise the erased FLASH data would be loaded into SRAM and overwrite the running firmware
            gowin_jtag_reprogram();
            // Read the firmware reconfiguration result; it should have stopped running (not done/ready state) in theory
            api_status = gowin_check_erase_gw1n(&status_reg);
            if (api_status != GOWIN_JTAG_OK) {
                // Erase failed, report the error directly
                return api_status;
            }
        }
    }

    return GOWIN_JTAG_OK;
}

gowin_jtag_status_t gowin_jtag_flash_config_start(uint8_t *xbuf_256, uint32_t *tx_bits_pos,
                                                  bool bg_update) {
    if (detected_device == GW_DEVICE_UNKNOWN) return GOWIN_JTAG_ERROR_INVALID_IDCODE;

    *tx_bits_pos = 0; // Reset the bitstream position being transferred here
    m_flash_bg_update = bg_update; // Cache the background-update flag
    m_flash_xpage_buf = xbuf_256; // A 256-byte buffer provided externally; all incoming firmware data is buffered by full x-pages in this buffer
    m_flash_xpage_pos = 0; // Reset the x-page buffer position, i.e. zero out the valid byte count of the current x-page buffer

    // TAP reset — very important; brings the FPGA TAP state machine back to Run-Test-Idle
    gowin_jtag_reset();
    // In any case, always erase FLASH first when starting FLASH configuration
    gowin_jtag_status_t status = gowin_jtag_flash_erase();
    if (status != GOWIN_JTAG_OK) {
        return status;
    }

    return GOWIN_JTAG_OK;
}

static void gowin_jtag_flash_config_xpage(const uint8_t data[256], uint32_t page_index) {
    const device_map_t *dm = get_device_map_by_idcode();

    jtag_shift_ir_safe(INST_CONFIG_ENABLE); // Send the config-enable command 0x15
    jtag_shift_ir_safe(INST_EF_PROGRAM); // Send the write-internal-FLASH command 0x71

    // Per the manual, wait 16us when the page address being programmed is greater than 0
    if (page_index > 0) {
        tck_2m(16);
    }

    // The address is 32 bits total, with the lower 6 bits reserved. For example, when the address is b'00010011 (0x13), the
    // written address is b'00000000000000000000010011000000. The address is written LSB-first, and the last bit exits Shift-DR.
    uint32_t addr = (page_index << 6) & 0xFFFFFFC0;
    uint8_t addr_bytes[4] = {addr >> 0, addr >> 8, addr >> 16, addr >> 24};
    jtag_shift_dr_safe(addr_bytes, NULL, 32);
    // After the address transfer, also keep the TCK clock running and wait for a while
    tck_2m(16);

    // Start programming the Y-PAGEs: fixed 64 of them, 256 data bytes total, i.e. one X-PAGE
    for (int y = 0; y < 64; y++) {
        const uint8_t *ypage = &data[y * 4];
        // Take the high 4 bytes from Configuration Data; data written in Shift-DR must start from the LSB.
        uint8_t tx[4] = {ypage[3], ypage[2], ypage[1], ypage[0]};
        jtag_shift_dr_safe(tx, NULL, 32);
        // After each Y-page write: GW1N(Z)-2/4/6/9 series require 13-15us of Run-Test, GW1N-2(C) requires 30-35us, other series need none
        if (dm->timing.y_page_w_wait_us) {
            tck_2m(dm->timing.y_page_w_wait_us);
        }
    }

    // The whole X-PAGE programming is done. Per the manual:
    //  GW1N-1(S) needs 2400us of clocks, GW1N(Z)-2/4/6/9 needs 6us, other series need no extra clocks.
    tck_2m(dm->timing.x_page_w_wait_us);
}

// Replace the head of the data source with the specified reserved data. Per the official FAE, it is safe to replace it;
//  the header has reserved bytes for certain configurations.
//  type == 1: replace with the Autoboot-pattern
//  type == 0: replace with the Readable-pattern
static void gowin_pattern_replace(uint8_t *data, const uint8_t type) {
    // H-process devices: Readable-pattern 0x07,0x07,0x30,0x40
    // T-process devices: Readable-pattern 0xF7,0xF7,0x3F,0x4F
    // Both processes currently share the same Autoboot-pattern 0x47,0x57,0x31,0x4E
    if (type == 1) {
        data[0] = 0x47;
        data[1] = 0x57;
        data[2] = 0x31;
        data[3] = 0x4E;
        return;
    }
    if (type == 0) {
        const device_map_t *dm = get_device_map_by_idcode();
        if (dm == NULL) return;
        if (dm->flash_type == GW_FLASH_TYPE_TSMC) {
            data[0] = 0xF7;
            data[1] = 0xF7;
            data[2] = 0x3F;
            data[3] = 0x4F;
        }
        if (dm->flash_type == GW_FLASH_TYPE_HL) {
            data[0] = 0x07;
            data[1] = 0x07;
            data[2] = 0x30;
            data[3] = 0x40;
        }
    }
}

gowin_jtag_status_t gowin_jtag_flash_config_write(uint8_t *data, uint32_t data_length, uint32_t *tx_bytes_pos,
                                                  uint32_t tx_bytes_total) {
    if (!data) return GOWIN_JTAG_ERROR_NULL_POINTER;
    if (detected_device == GW_DEVICE_UNKNOWN) return GOWIN_JTAG_ERROR_INVALID_IDCODE;
    if (m_flash_xpage_buf == NULL) return GOWIN_JTAG_ERROR_NULL_POINTER;
    if (*tx_bytes_pos + data_length + m_flash_xpage_pos > tx_bytes_total) return GOWIN_JTAG_ERROR_OUT_OF_RANGE;

    // When xbuf already holds buffered data, we must first accumulate a full x-page before writing the data in xbuf
    if (data_length < 256 || m_flash_xpage_pos > 0) {
        // Ensure the new data plus old data won't overflow; if it would, copy only part into xbuf to fill one page first
        uint16_t copy_length = data_length;
        if (m_flash_xpage_pos + data_length > 256) {
            copy_length = 256 - m_flash_xpage_pos; // Compute the copyable length that won't overflow xbuf
        }
        memcpy(m_flash_xpage_buf + m_flash_xpage_pos, data, copy_length);
        data += copy_length; // We've copied part of the data into xbuf; advance the pointer to the remaining input data and subtract this part from the input length
        data_length -= copy_length;
        m_flash_xpage_pos += copy_length; // After copying, record the current x-page content length
        // If this isn't the last packet and there isn't enough data to fill xbuf, cache it and wait until a full x-page (256 bytes) is accumulated
        if (m_flash_xpage_pos != 256) {
            if (*tx_bytes_pos + data_length + m_flash_xpage_pos < tx_bytes_total) {
                return GOWIN_JTAG_OK; // Return directly here, since there isn't enough to fill xbuf and this isn't the last packet; still need to wait
            }
            // This is the last packet; if it's under 256 bytes, pad the remainder with 0x00 and send it as a full page
            memset(m_flash_xpage_buf + m_flash_xpage_pos, 0x00, 256 - m_flash_xpage_pos);
            // m_flash_xpage_pos = 256; // don't assign 256 here, to correctly count the bytes in xbuf — otherwise the padding data would also be counted into tx_bytes_pos
        }
    }

    // Compute the page position corresponding to the number of bytes already transferred
    uint32_t page_index = *tx_bytes_pos / 256;
    // Handle the Readable-pattern / Autoboot-pattern. We don't support Verify for now, so we don't need to consider the Readable-pattern
    if (page_index == 0) {
        gowin_pattern_replace(m_flash_xpage_pos == 0 ? data : m_flash_xpage_buf, 1);
    }

    // Now start writing X-PAGEs. We have two buffers: the 256-byte xbuf staging area and the external data source.
    // Send the xbuf staging area first (if it contains data).
    if (m_flash_xpage_pos > 0) {
        gowin_jtag_flash_config_xpage(m_flash_xpage_buf, page_index);
        *tx_bytes_pos += m_flash_xpage_pos; // After one x-page is sent, add it to the total transferred byte count; note that only the actually valid bytes are added here
        page_index++;
        m_flash_xpage_pos = 0; // After sending, reset the xbuf byte count to zero
    }
    // After xbuf is sent, check the external data source for whole x-pages and send them if any
    for (uint32_t p = 0; p < data_length / 256; p++) {
        gowin_jtag_flash_config_xpage(&data[p * 256], page_index);
        *tx_bytes_pos += 256; // Same as described above
        page_index++;
    }
    // If there is leftover data, it hasn't been sent and must wait for a full x-page. Compute the remainder and copy it into xbuf, waiting for the next packet
    uint8_t remain_bytes = data_length % 256; // Using u8 is safe here, since there can't be 256 bytes remaining — it would have been divided evenly
    if (remain_bytes > 0) {
        memset(&m_flash_xpage_buf[remain_bytes], 0x00, 256 - remain_bytes); // Zero out the invalid trailing data
        memcpy(m_flash_xpage_buf, &data[data_length - remain_bytes], remain_bytes); // Copy the data to the start of the buffer
        m_flash_xpage_pos += remain_bytes; // Record the remaining byte count for this transfer
        // If this is the last packet, send it directly without buffering
        if (*tx_bytes_pos + remain_bytes >= tx_bytes_total) {
            gowin_jtag_flash_config_xpage(m_flash_xpage_buf, page_index);
            m_flash_xpage_pos = 0;
            *tx_bytes_pos += remain_bytes;
        }
    }

    return GOWIN_JTAG_OK;
}

gowin_jtag_status_t gowin_jtag_flash_config_finish(void) {
    if (detected_device == GW_DEVICE_UNKNOWN) return GOWIN_JTAG_ERROR_INVALID_IDCODE;

    jtag_shift_ir_safe(INST_CONFIG_DISABLE); // Send the config-disable command 0x3A
    gowin_jtag_reprogram(); // Tested: after FLASH programming, executing reprogram is enough to start the program; no need to reset the JTAG port

    return GOWIN_JTAG_OK;
}

void gowin_jtag_start_config(gowin_config_ctx_t *cctx) {
    // Perform JTAG init and read the ID
    cctx->status = gowin_jtag_init();
    if (cctx->status == GOWIN_JTAG_OK) {
        uint32_t idcode = gowin_jtag_get_idcode();
        const char *name = gowin_jtag_get_device_name();
        dbg_printf("gowin_jtag OK: idcode = 0x%04lX, name = %s", idcode, name);
        // Read and print the detailed status register
        gowin_status_reg_t status_reg;
        gowin_jtag_read_status_reg(&status_reg);
    } else {
        dbg_printf("gowin_jtag NOT OK");
        return;
    }

    // Initialize and start the configuration
    if (cctx->is_cfg_sram) {
        dbg_printf("Erase sram started");
        cctx->status = gowin_jtag_sram_config_start(&cctx->tx_pos);
        if (cctx->status != GOWIN_JTAG_OK) {
            dbg_printf("Failed to start sram config: %d", cctx->status);
            return;
        }
        dbg_printf("Erase sram done");
    } else {
        dbg_printf("Erase flash started");
        // For now only do non-background update (it will halt FPGA execution)
        cctx->status = gowin_jtag_flash_config_start(cctx->x_page_buf, &cctx->tx_pos, false);
        if (cctx->status != GOWIN_JTAG_OK) {
            dbg_printf("Failed to start flash config: %d", cctx->status);
            return;
        }
        dbg_printf("Erase flash done");
    }

    // Print a message to indicate the startup is complete
    dbg_printf("gowin_jtag %s config started: %d", cctx->is_cfg_sram ? "sram" : "flash", cctx->status);
}

void gowin_jtag_config_write(uint8_t *data, uint32_t data_length, gowin_config_ctx_t *cctx) {
    // Selectively call the corresponding logic based on the current configuration type
    if (cctx->is_cfg_sram) {
        cctx->status = gowin_jtag_sram_config_write(data, data_length, &cctx->tx_pos, cctx->tx_total);
    } else {
        cctx->status = gowin_jtag_flash_config_write(data, data_length, &cctx->tx_pos, cctx->tx_total);
    }
}

void gowin_jtag_stop_config(gowin_config_ctx_t *cctx) {
    // Choose a different finalization based on the current programming mode
    if (cctx->is_cfg_sram) {
        cctx->status = gowin_jtag_sram_config_finish();
    } else {
        cctx->status = gowin_jtag_flash_config_finish();
    }
    gowin_jtag_deinit(); // Deinitialize the Gowin JTAG library, exit some states and release some resources
}
