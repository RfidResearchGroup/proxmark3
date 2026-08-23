/*
 * GOWIN fpga JTAG software implement
 *
 * @Author DXL
 * GPL license
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
    uint16_t sram_erase_ms; // 在发送 EraseSram（0x05）指令、Noop（0x02）之后，要给足够的时间等待其擦除完毕
    uint16_t y_page_w_wait_us; // 写一个y-page完成后需要延迟的时间长度
    uint16_t x_page_w_wait_us; // 写一个x-page完成后需要延迟的时间长度
} gowin_timing_t;

typedef struct {
    uint32_t idcode;
    gowin_device_t device;
    const char *name;
    gowin_flash_type_t flash_type;
    bool reprogram; // 在部分器件中，如果 JTAG 的 4 个管脚或 JTAGSEL_N 复用为 GPIO，此时若需重新配置，需要先发送一次 reprogram 指令。
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
    // 以上将 GW1N-2 和 GW1N-1P5 系列合并映射 {0x0120681B, GW_DEVICE_GW1N_1P5_1P5B_1P5C, "GW1N-1P5/1P5B/1P5C", {2, 120, 0, 32}},
    {
        0x0100381B, GW_DEVICE_GW1N_R_4, "GW1N(R)-4", GW_FLASH_TYPE_TSMC, true,
        {2, 16, 6}
    },
    {
        0x1100381B, GW_DEVICE_GW1N_R_4B, "GW1N(R)-4B/4D", GW_FLASH_TYPE_TSMC, true,
        {2, 16, 6}
    },
    // 以上将 GW1NR-4B 和 GW1NR-4D 系列合并映射 {0x1100381B, GW_DEVICE_GW1N_R_4D, "GW1N(R)-4D", {2, 120, 0, 32}},
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

    // 根据手册描述： GW2ANR-18/GW2AN-55 内部封了一颗 SPI-Flash，编程方式与 GW2A-18、GW2A-55 相同
    //  也就是说，GW2A 系列是 spi-flash，需要让JTAG接口转接到MSPI的情况下，用SPI指令去操作最终的片上SPI—FLASH或者外部FLASH
    //  大概流程就是JATG -> 0x16指令 -> MSPI -> 0x06（写使能） -> 0xC7（擦除）...
    //  由此总结就是，除了转接到MSPI之前需要用到JTAG，其他时候都是和 SPI-FLASH 有关的操作了，因此擦除不需要像内部FLASH一样必须提供一个指定速率的时钟
    // {0x0000081B, GW_DEVICE_GW2A_R_18_18C, "GW2A(R)-18/18C", {6, 120, 0, 32}},
    // {0x0000281B, GW_DEVICE_GW2A_55_55C, "GW2A-55/55C", {10, 120, 0, 32}},

    // 暂时不考虑这两个旧的型号的适配，这俩芯片官方貌似已经停产了，官方已经把芯片标记为old然后手册也删除了相关的信息，弄样品测试也麻烦。
    // 注：这俩芯片的内部FLASH工艺是SMIC，官方有STM32的例程和代码有封装了此芯片的内部FLASH烧录
    //  此系列要求的 Y page 写入之后的延迟时长是 30-35us
    // #define ID_GW1NS_2 0x0300081B
    // #define ID_GW1NS_2C 0x0300181B
};

// 根据ID索引到具体的设备信息映射表上，如果没有发现对应的设备存在，则返回NULL
static const device_map_t *get_device_map_by_idcode(void) {
    for (size_t i = 0; i < ARRAYLEN(device_map); i++) {
        if (device_map[i].idcode == cached_idcode) {
            return &device_map[i];
        }
    }
    return NULL;
}

// 设置tap状态机并且产生一次驱动时钟，驱动时钟的速度取决于 tck_pulse() 函数
static RAMFUNC void jtag_tap_clock(bool tms) {
    if (tms) {
        set_tms_high();
    } else {
        set_tms_low();
    }
    tck_pulse();
}

// 从 Run-Test/Idle 进入 Shift-IR（标准 IEEE 1149.1 路径）
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
        jtag_tap_clock(i == 7); // -> Exit1-IR if is last bit
    }
    // Exit1-IR -> Update-IR -> Run-Test/Idle
    jtag_tap_clock(1); // -> Update-IR
    jtag_tap_clock(0); // -> Run-Test/Idle
    // Per Gowin spec: ≥3 TCK cycles in Run-Test/Idle after IR load
    for (int i = 0; i < 3; i++) {
        tck_pulse();
    }
}

// 从 Run-Test/Idle 进入 Shift-DR（标准 IEEE 1149.1 路径）
static void jtag_goto_shift_dr(void) {
    jtag_tap_clock(1); // -> Select-DR
    jtag_tap_clock(0); // -> Capture-DR
    jtag_tap_clock(0); // -> Shift-DR
}

// 仅用于从LSB开始发送的数据
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
        jtag_tap_clock(i == bits - 1); // -> Exit1-DR if is last bit

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
 * 初始化 jtag 接口
 *
 * @return 初始化成功时，返回 GOWIN_JTAG_OK
 */
gowin_jtag_status_t gowin_jtag_init(void) {
    // 启动JTAG操作之前，拉低 JTAGSEL 引脚，确保取消FPGA的JTAG复用
    set_jtagsel_low();
    // 重置TAP状态机，确保和设备从 Run-Test/Idle 位置开始通信
    gowin_jtag_reset();
    // 读取IDCODE，并且缓存到全局域
    cached_idcode = gowin_jtag_read_idcode_u32();
    const device_map_t *dm = get_device_map_by_idcode();
    detected_device = dm ? dm->device : GW_DEVICE_UNKNOWN;
    return detected_device == GW_DEVICE_UNKNOWN ? GOWIN_JTAG_ERROR_INVALID_IDCODE : GOWIN_JTAG_OK;
}

void gowin_jtag_deinit(void) {
    // 拉高JTAGSEL脚，恢复JTAG脚复用为GPIO
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
        tck_pulse(); // 替代原来的 set_tck toggle
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
    delay_ms(200);
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

    // send command
    if (enable) {
        jtag_shift_ir_safe(INST_CONFIG_ENABLE);
    } else {
        jtag_shift_ir_safe(INST_CONFIG_DISABLE);
        jtag_shift_ir_safe(INST_NOOP);
    }

    // check status and waiting for edit mode enter.
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
    // TAP 复位，非常重要，让FPGA的TAP的状态机回到 Run-Test-Idle 状态
    gowin_jtag_reset();
    // 无论如何，总是在启动配置SRAM的时候，首先擦除SRAM
    gowin_jtag_status_t status = gowin_jtag_sram_erase();
    if (status != GOWIN_JTAG_OK) {
        return status;
    }
    jtag_shift_ir_safe(INST_CONFIG_ENABLE); // 发送 ConfigEnable 指令 0x15
    jtag_shift_ir_safe(INST_ADDR_INIT); // 发送 Address Initialize 指令 0x12
    jtag_shift_ir_safe(INST_TRANSFER_CFG); // 发送 Transfer Configuration Data 指令 0x17
    jtag_goto_shift_dr(); // 移动状态到 Shift-DR（数据寄存器）

    // 将 Bitstream Data 从最高位开始（MSB），逐位发送，发送全部数据流文件内容，并回到 Run-Test-Idle状态
    // 注：在配置接口中进行此操作，对于配置接口来说，此操作可以分多步执行，一点点发送文件知道全部发送完毕
    *tx_bits_pos = 0; // 在此处进行传输的比特流位置的重置

    return GOWIN_JTAG_OK;
}

gowin_jtag_status_t gowin_jtag_sram_config_write(uint8_t *data, uint32_t data_length, uint32_t *tx_bytes_pos,
                                                 uint32_t tx_bytes_total) {
    if (!data) return GOWIN_JTAG_ERROR_NULL_POINTER;
    if (detected_device == GW_DEVICE_UNKNOWN) return GOWIN_JTAG_ERROR_INVALID_IDCODE;

    // 将 Bitstream Data 从最高位开始（MSB），逐位发送，发送全部数据流文件内容，并回到 Run-Test-Idle状态
    for (uint32_t i = 0; i < data_length; i++) {
        // Send byte
        for (uint8_t j = 0; j < 8; j++) {
            // Send bits
            if ((data[i] >> (7 - j)) & 0x01) {
                set_tdi_high();
            } else {
                set_tdi_low();
            }
            if (j == 7) {
                // Increment tx_bytes_pos if one byte transfer finish.
                (*tx_bytes_pos)++;
                // -> Exit1-DR if is last bit and is last byte
                jtag_tap_clock(*tx_bytes_pos == tx_bytes_total);
            } else {
                jtag_tap_clock(0); // One clock, no Exit1-DR
            }
        }
    }

    return GOWIN_JTAG_OK;
}

gowin_jtag_status_t gowin_jtag_sram_config_finish(void) {
    jtag_shift_ir_safe(INST_CONFIG_DISABLE);
    jtag_shift_ir_safe(INST_NOOP);

    // SRAM 写完后等待 60ms, 以待 status code 刷新
    delay_ms(60);

    // 记得，一定要重置状态机，让fpga回到 Run-Test/Idle 的状态，不然新固件不启动
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

// readout status and check POR & VLD
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

// 读出并且检查是否擦除成功，此函数仅用于gw1n系列
static gowin_jtag_status_t gowin_check_erase_gw1n(gowin_status_reg_t *reg_out) {
    gowin_jtag_read_status_reg(reg_out);
    // 不检查 Security Final 位
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

    GPIOA->scr = GPIO_PINS_2; // TODO DXL

    // 读一下状态值，确认当前没问题
    gowin_jtag_status_t api_status = gowin_check_status_gw1n(&status_reg);
    if (api_status != GOWIN_JTAG_OK) {
        return api_status;
    }

    // if (dbg_printf) dbg_printf("m_flash_bg_update = %d", m_flash_bg_update);

    // 如果不是背景烧录的话，就得关注 done_final 位，如果 done_final位是高的，就得清除SRAM，否则不需要清除
    //  因为在背景烧录的情况下，我们仍需要保留SRAM中的FPGA固件，使其正常运行，更新操作只会操作FLASH，不会导致SRAM被覆盖，因此不会中断服务
    if (m_flash_bg_update == false && status_reg.bits.done_final) {
        // Do sram erase
        api_status = gowin_jtag_sram_erase();
        if (api_status != GOWIN_JTAG_OK) {
            return api_status;
        }
        // Verify for erase sram result
        api_status = gowin_check_erase_gw1n(&status_reg);
        if (api_status != GOWIN_JTAG_OK) {
            return api_status;
        }
        dbg_printf("erase the SRAM is finish, next step erase the FLASH");
    }

    // 擦除过程，FLASH工艺不同，所进行的操作也不同
    api_status = gowin_jtag_cfg_enable(true);
    if (api_status != GOWIN_JTAG_OK) {
        return api_status;
    }

    jtag_shift_ir_safe(INST_EFLASH_ERASE); // 发送内嵌FLASH的擦除指令 0x75

    GPIOA->clr = GPIO_PINS_2; // TODO DXL

    if (dm->flash_type == GW_FLASH_TYPE_HL) {
        for (int i = 0; i < 65; i++) {
            // H工艺要求重复此步骤65次，这是手册要求的
            // 移动状态到 Shift-DR（数据寄存器），并且产生32个时钟（TDI保持低电平）
            jtag_shift_dr_fast();
        }
        tck_2m(95 * 1000); // H 工艺要求后续在 Run-Test-Idle 状态下持续产生时钟95ms
        dbg_printf("erase for GW_FLASH_TYPE_HL");
    }
    if (dm->flash_type == GW_FLASH_TYPE_TSMC) {
        jtag_shift_dr_fast(); // T 工艺只要求产生一次32bit的输出传输时钟
        tck_2m(150 * 1000); // T 工艺要求后续在 Run-Test-Idle 状态下持续产生时钟 120-150 ms
        dbg_printf("erase for GW_FLASH_TYPE_TSMC");
    }

    GPIOA->scr = GPIO_PINS_2; // TODO DXL

    api_status = gowin_jtag_cfg_enable(false);
    if (api_status != GOWIN_JTAG_OK) {
        return api_status;
    }

    // 官方的代码里，H工艺在发送了 0x02 之后延迟了 500ms才继续干活，T工艺则是200ms
    if (dm->flash_type == GW_FLASH_TYPE_HL) {
        delay_ms(500);
        if (m_flash_bg_update == false) {
            // 如果背景烧录使能，则不需要检查任何状态码相关的异常，因为这个时候固件是在正常运行的
            api_status = gowin_check_erase_gw1n(&status_reg);
            if (api_status != GOWIN_JTAG_OK) {
                // 擦除失败了，直接报错
                return api_status;
            }
        }
    }
    if (dm->flash_type == GW_FLASH_TYPE_TSMC) {
        delay_ms(200);
        if (m_flash_bg_update == false) {
            // 如果背景烧录使能，则不可以触发重新配置，否则会导致被清空的FLASH的数据加载到SRAM覆盖正在运行的固件
            gowin_jtag_reprogram();
            // 读取固件重新配置的结果，理论上应当是要停止运行的，非done和ready状态
            api_status = gowin_check_erase_gw1n(&status_reg);
            if (api_status != GOWIN_JTAG_OK) {
                // 擦除失败了，直接报错
                return api_status;
            }
        }
    }

    return GOWIN_JTAG_OK;
}

gowin_jtag_status_t gowin_jtag_flash_config_start(uint8_t *xbuf_256, uint32_t *tx_bits_pos,
                                                  bool bg_update) {
    if (detected_device == GW_DEVICE_UNKNOWN) return GOWIN_JTAG_ERROR_INVALID_IDCODE;

    *tx_bits_pos = 0; // 在此处进行传输的比特流位置的重置
    m_flash_bg_update = bg_update; // 缓存背景升级的操作标志
    m_flash_xpage_buf = xbuf_256; // 由外部提供一个256byte的缓冲区，所有传过来的固件数据都依靠此buf进行整xpage的缓存
    m_flash_xpage_pos = 0; // 重置xpage的缓存位置，也就是将当前xpage的buf的有效字节数量归零

    // TAP 复位，非常重要，让FPGA的TAP的状态机回到 Run-Test-Idle 状态
    gowin_jtag_reset();
    // 无论如何，总是在启动配置FLASH的时候，首先擦除FLASH
    gowin_jtag_status_t status = gowin_jtag_flash_erase();
    if (status != GOWIN_JTAG_OK) {
        return status;
    }

    return GOWIN_JTAG_OK;
}

static void gowin_jtag_flash_config_xpage(const uint8_t data[256], uint32_t page_index) {
    const device_map_t *dm = get_device_map_by_idcode();

    jtag_shift_ir_safe(INST_CONFIG_ENABLE); // 发送配置使能指令 0x15
    jtag_shift_ir_safe(INST_EF_PROGRAM); // 发送写内部FLASH指令 0x71

    // 根据手册描述，在编程的页面地址大于0时，需要等待16us
    if (page_index > 0) {
        tck_2m(16);
    }

    // 地址数据格式共 32bits，其中低 6 位保留，例如地址为 b’00010011(0x13)时，写入的地
    // 址为 b’ 00000000000000000000010011000000，该地址数据遵循 LSB 方式写入，最后一个 bit 跳出 Shift-DR。
    uint32_t addr = (page_index << 6) & 0xFFFFFFC0;
    uint8_t addr_bytes[4] = {addr >> 0, addr >> 8, addr >> 16, addr >> 24};
    jtag_shift_dr_safe(addr_bytes, NULL, 32);
    // 在地址传输完毕之后，也需要保持TCK时钟并且等待一段时间
    tck_2m(16);

    // 开始编程Y-PAGE，固定64个，总数据字节长度为 256 也就是一个 X-PAGE 的大小
    for (int y = 0; y < 64; y++) {
        const uint8_t *ypage = &data[y * 4];
        // 数据从 Configuration Data 取高位 4Bytes，在 Shift-DR 写数据时要从最低位开始写入（LSB）。
        uint8_t tx[4] = {ypage[3], ypage[2], ypage[1], ypage[0]};
        jtag_shift_dr_safe(tx, NULL, 32);
        // 每次写完一个 Y-page, GW1N(Z)-2/4/6/9 系列要求 Run-Test 13-15μs，GW1N-2(C)系列要求 Run-Test 30-35μs，其他系列器件不需要
        if (dm->timing.y_page_w_wait_us) {
            tck_2m(dm->timing.y_page_w_wait_us);
        }
    }

    // 整个 X-PAGE 编程完成了，按照手册描述：
    //  GW1N-1(S)器件需要执行 2400μs 时长的时钟，GW1N(Z)-2/4/6/9 系列器件需要执行 6μs 时长的时钟，其他系列器件不需要额外时钟。
    tck_2m(dm->timing.x_page_w_wait_us);
}

// 给数据源的头部替换为指定的保留数据，根据官方FAE的描述，可以放心替换，头部有预留字节是给某些配置用的
//  type 为 1 时，替换为 Autoboot-pattern
//  type 为 0 时，替换为 Readable-pattern
static void gowin_pattern_replace(uint8_t *data, const uint8_t type) {
    // H 工艺器件：Readable-pattern 0x07,0x07,0x30,0x40
    // T 工艺器件：Readable-pattern 0xF7,0xF7,0x3F,0x4F
    // 目前两个工艺的器件的 Autoboot-pattern 都是一样的 0x47,0x57,0x31,0x4E
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

    // 在xbuf里面已经有缓存的数据的情况下，我们需要先确认本次攒够了一个xpage的大小，才去开工写入xbuf里面的数据
    if (data_length < 256 || m_flash_xpage_pos > 0) {
        // 确保新到来的数据加上旧的数据的长度不会溢出，如果溢出的话，那我们就只取一部分写入到xbuf里，让xbuf先满一个page
        uint16_t copy_length = data_length;
        if (m_flash_xpage_pos + data_length > 256) {
            copy_length = 256 - m_flash_xpage_pos; // 计算不会溢出xbuf的可复制数据的长度
        }
        memcpy(m_flash_xpage_buf + m_flash_xpage_pos, data, copy_length);
        data += copy_length; // 此时我们复制了一部分数据到xbuf里头，外部传进来的剩下的数据的指针要往前移，传入长度也要减去这部分
        data_length -= copy_length;
        m_flash_xpage_pos += copy_length; // 复制之后，记录当前xpage的内容长度
        // 如果当前不是最后一包并且数据不够一个xbuf大小，那就得先把数据缓存下来，等足够一个xpage（256字节）了再去传
        if (m_flash_xpage_pos != 256) {
            if (*tx_bytes_pos + data_length + m_flash_xpage_pos < tx_bytes_total) {
                return GOWIN_JTAG_OK; // 此处直接返回，因为不够一个xbuf大小并且不是最后一包数据，仍需等待传输
            }
            // 已经是最后一包了，不够256的话那我们就默认用 0x00 补齐剩下的数据，当作足额给发过去
            memset(m_flash_xpage_buf + m_flash_xpage_pos, 0x00, 256 - m_flash_xpage_pos);
            // m_flash_xpage_pos = 256; 为了正确统计xbuf里面的自己数量，此处不要赋值为 256，否则padding的数据也会被计算进去 tx_bytes_pos 里
        }
    }

    // 计算当前已传输的字节数量对应到的page位置
    uint32_t page_index = *tx_bytes_pos / 256;
    // 处理 Readable-pattern / Autoboot-pattern，我们暂时不加入对 Verify 的支持，自然也就不需要考虑 Readable-pattern
    if (page_index == 0) {
        gowin_pattern_replace(m_flash_xpage_pos == 0 ? data : m_flash_xpage_buf, 1);
    }

    // 完事儿了开始写X-PAGE，我们有两个BUF，一个是256大小的xbuf暂存区，一个是外部传入的数据源，
    // 我们优先把xbuf暂存区给发出去（如果里面有数据的话）
    if (m_flash_xpage_pos > 0) {
        gowin_jtag_flash_config_xpage(m_flash_xpage_buf, page_index);
        *tx_bytes_pos += m_flash_xpage_pos; // 一个x-page传完了就记到总传输的字节数量里，记住，我们此处要加实际有效的字节数量
        page_index++;
        m_flash_xpage_pos = 0; // 传完了记得归零xbuf的字节计数
    }
    // xbuf传完了以后，还得继续看看外部数据源里有没有完整的x-page的数据，如果有的话，就继续传
    for (uint32_t p = 0; p < data_length / 256; p++) {
        gowin_jtag_flash_config_xpage(&data[p * 256], page_index);
        *tx_bytes_pos += 256; // 同上描述
        page_index++;
    }
    // 如果有剩余数据，那剩余的数据一定是没发出去的，需要等到有完整的一包x-page才能发，所以我们计算余数，将其拷贝到xbuf里面暂存等待下一包
    uint8_t remain_bytes = data_length % 256; // 用u8是安全的，因为不可能有256个字节剩余，直接整除了
    if (remain_bytes > 0) {
        memset(&m_flash_xpage_buf[remain_bytes], 0x00, 256 - remain_bytes); // 把后面的无效数据归零
        memcpy(m_flash_xpage_buf, &data[data_length - remain_bytes], remain_bytes); // 复制数据到缓冲区的开头
        m_flash_xpage_pos += remain_bytes; // 记录本次传输剩余的字节数
        // 如果是最后一包了的话，那就直接传过去，不要再缓存了
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

    jtag_shift_ir_safe(INST_CONFIG_DISABLE); // 发送配置禁用指令 0x3A
    gowin_jtag_reprogram(); // 经测试，flash的烧录只要执行 reprogram 就可以让程序开始执行，不需要重置JTAG端口

    return GOWIN_JTAG_OK;
}

void gowin_jtag_start_config(gowin_config_ctx_t *cctx) {
    // 发起jtag初始化和读取ID
    cctx->status = gowin_jtag_init();
    if (cctx->status == GOWIN_JTAG_OK) {
        uint32_t idcode = gowin_jtag_get_idcode();
        const char* name = gowin_jtag_get_device_name();
        dbg_printf("gowin_jtag OK: idcode = 0x%04lX, name = %s", idcode, name);
        // 读取和打印详细的状态表
        gowin_status_reg_t status_reg;
        gowin_jtag_read_status_reg(&status_reg);
    } else {
        dbg_printf("gowin_jtag NOT OK");
        return;
    }

    // 初始化启动配置
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
        // 暂时只进行非背景升级（会终止FPGA的执行）
        cctx->status = gowin_jtag_flash_config_start(cctx->x_page_buf, &cctx->tx_pos, false);
        if (cctx->status != GOWIN_JTAG_OK) {
            dbg_printf("Failed to start flash config: %d", cctx->status);
            return;
        }
        dbg_printf("Erase flash done");
    }

    // 打印个消息告知一下启动完成了
    dbg_printf("gowin_jtag %s config started: %d", cctx->is_cfg_sram ? "sram" : "flash" , cctx->status);
}

void gowin_jtag_config_write(uint8_t *data, uint32_t data_length, gowin_config_ctx_t *cctx) {
    // 根据当前的配置类型，选择性调用对应的逻辑
    if (cctx->is_cfg_sram) {
        cctx->status = gowin_jtag_sram_config_write(data, data_length, &cctx->tx_pos, cctx->tx_total);
    } else {
        cctx->status = gowin_jtag_flash_config_write(data, data_length, &cctx->tx_pos, cctx->tx_total);
    }
}

void gowin_jtag_stop_config(gowin_config_ctx_t *cctx) {
    // 根据当前烧录模式的不同选择不同的收尾
    if (cctx->is_cfg_sram) {
        cctx->status = gowin_jtag_sram_config_finish();
    } else {
        cctx->status = gowin_jtag_flash_config_finish();
    }
    gowin_jtag_deinit(); // 反初始化gowinjtag库，退出某些状态并且释放某些资源
}
