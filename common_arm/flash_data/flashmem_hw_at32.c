#include <stdbool.h>
#include "ticks_apis.h"
#include "gpio_hw_at32.h"
#include "flashmem.h"
#include "flashmem_hw_at32.h"

#ifndef AS_BOOTROM
#include "dbprint.h"
#endif // AS_BOOTROM

static qspi_cmd_type w25q_cmd_config;

// Initialization of gpio related to qspi
static void qspi_gpio_config(void) {
    gpio_init_type gpio_init_struct;

    /* enable the gpio clock */
    AT32_GPIO_PERIPH_CLKS_ENABLE(AT32_GPIO_PERIPH_QSPI_FLASH_CLK);

    /* set default parameter */
    gpio_default_para_init(&gpio_init_struct);
    gpio_init_struct.gpio_drive_strength = GPIO_DRIVE_STRENGTH_STRONGER;
    gpio_init_struct.gpio_out_type = GPIO_OUTPUT_PUSH_PULL;
    gpio_init_struct.gpio_mode = GPIO_MODE_MUX;
    gpio_init_struct.gpio_pull = GPIO_PULL_NONE;

    /* configure the io0 gpio */
    gpio_init_struct.gpio_pins = AT32_GPIO_QSPI_FLASH_IO0_PIN;
    gpio_init(AT32_GPIO_QSPI_FLASH_IO0, &gpio_init_struct);
    gpio_pin_mux_config(AT32_GPIO_QSPI_FLASH_IO0, AT32_GPIO_QSPI_FLASH_IO0_SOURCE, AT32_GPIO_QSPI_FLASH_IO0_MUX);

    /* configure the io1 gpio */
    gpio_init_struct.gpio_pins = AT32_GPIO_QSPI_FLASH_IO1_PIN;
    gpio_init(AT32_GPIO_QSPI_FLASH_IO1, &gpio_init_struct);
    gpio_pin_mux_config(AT32_GPIO_QSPI_FLASH_IO1, AT32_GPIO_QSPI_FLASH_IO1_SOURCE, AT32_GPIO_QSPI_FLASH_IO1_MUX);

    /* configure the io2 gpio */
    gpio_init_struct.gpio_pins = AT32_GPIO_QSPI_FLASH_IO2_PIN;
    gpio_init(AT32_GPIO_QSPI_FLASH_IO2, &gpio_init_struct);
    gpio_pin_mux_config(AT32_GPIO_QSPI_FLASH_IO2, AT32_GPIO_QSPI_FLASH_IO2_SOURCE, AT32_GPIO_QSPI_FLASH_IO2_MUX);

    /* configure the io3 gpio */
    gpio_init_struct.gpio_pins = AT32_GPIO_QSPI_FLASH_IO3_PIN;
    gpio_init(AT32_GPIO_QSPI_FLASH_IO3, &gpio_init_struct);
    gpio_pin_mux_config(AT32_GPIO_QSPI_FLASH_IO3, AT32_GPIO_QSPI_FLASH_IO3_SOURCE, AT32_GPIO_QSPI_FLASH_IO3_MUX);

    /* configure the sck gpio */
    gpio_init_struct.gpio_pins = AT32_GPIO_QSPI_FLASH_SCK_PIN;
    gpio_init(AT32_GPIO_QSPI_FLASH_SCK, &gpio_init_struct);
    gpio_pin_mux_config(AT32_GPIO_QSPI_FLASH_SCK, AT32_GPIO_QSPI_FLASH_SCK_SOURCE, AT32_GPIO_QSPI_FLASH_SCK_MUX);

    /* configure the cs gpio */
    gpio_init_struct.gpio_pins = AT32_GPIO_QSPI_FLASH_CS_PIN;
    gpio_init(AT32_GPIO_QSPI_FLASH_CS, &gpio_init_struct);
    gpio_pin_mux_config(AT32_GPIO_QSPI_FLASH_CS, AT32_GPIO_QSPI_FLASH_CS_SOURCE, AT32_GPIO_QSPI_FLASH_CS_MUX);
}

// Wait for flag setting within timeout, return false if timeout occurs.
static bool wait_flag_set(uint32_t flag, uint32_t timeoutMS) {
    uint32_t start_tick = GET_TICKS;
    while (qspi_flag_get(AT32_QSPI_FLASH, flag) == RESET) {
        if (GetTicksDelta(start_tick) >= (timeoutMS * 1000 * 1.5)) {
            // 100ms
            return false; // timeout
        }
    }
    return true;
}

// Wait command completed
static bool wait_cmd_completed(void) {
    if (wait_flag_set(QSPI_CMDSTS_FLAG, 100)) {
        qspi_flag_clear(AT32_QSPI_FLASH, QSPI_CMDSTS_FLAG);
        return true;
    }
    return false;
}

// Read out data from qspi pio, no dma.
static bool read_wait_rx_done(uint8_t *out, uint32_t length) {
    // wait rx ready for read out.
    if (!wait_flag_set(QSPI_RXFIFORDY_FLAG, 200)) return false;
    for (uint32_t i = 0; i < length; ++i) out[i] = qspi_byte_read(AT32_QSPI_FLASH);
    return wait_cmd_completed();
}

// Get QSPI frequency division value
static qspi_clk_div_type from_baudrate_to_clk_div(uint32_t baudrate) {
    uint32_t sck_candidate_value = 0;
    uint8_t i;
    // The clock of the QSPI of the AT32 is from the AHB clock, see datasheet: system architecture & crm
    //  so we need get current ahb clk speed, to calc div value.
    crm_clocks_freq_type clk_freq_info;
    crm_clocks_freq_get(&clk_freq_info);
    // The ahb clock may be modified, so dynamic calculation is required!
    uint32_t sck_lut[8]; // map div value to clk value.
    sck_lut[QSPI_CLK_DIV_2] = clk_freq_info.ahb_freq / 2; // see datasheet 28.4.5
    sck_lut[QSPI_CLK_DIV_4] = clk_freq_info.ahb_freq / 4;
    sck_lut[QSPI_CLK_DIV_6] = clk_freq_info.ahb_freq / 6;
    sck_lut[QSPI_CLK_DIV_8] = clk_freq_info.ahb_freq / 8;
    sck_lut[QSPI_CLK_DIV_3] = clk_freq_info.ahb_freq / 3;
    sck_lut[QSPI_CLK_DIV_5] = clk_freq_info.ahb_freq / 5;
    sck_lut[QSPI_CLK_DIV_10] = clk_freq_info.ahb_freq / 10;
    sck_lut[QSPI_CLK_DIV_12] = clk_freq_info.ahb_freq / 12;
    // map search, step1, get a maximum value from sck_lut
    for (i = 0; i < 8; ++i) {
        // Take the maximum value downward, that is, if the incoming value is 1000000,
        // take the maximum clk speed value in the mapping table that is smaller than the incoming value
        if (baudrate <= sck_lut[i]) {
            if (sck_lut[i] > sck_candidate_value) {
                sck_candidate_value = sck_lut[i];
            }
        }
    }
    if (sck_candidate_value == 0) {
        return QSPI_CLK_DIV_6; // return a default div value if no candidate clk found.
    }
    // map search, step2, from clk value to div value
    for (i = 0; i < 8; ++i) {
        if (sck_candidate_value == sck_lut[i]) {
            return i; // 'i' is div value
        }
    }
    return QSPI_CLK_DIV_6; // never come here...
}

// Default baud rate for spi of current platform.
uint32_t Flash_DefaultBaudrate(void) {
    return 24000000; // TODO DXL 测试时，功能优先，速度先降下去。
}

// When returning false, it indicates that the communication with flash has timed out.
// Under normal circumstances, the return value should be within the range of U8.
static bool Flash_ReadStatReg(uint8_t reg, uint8_t *status) {
    // config update for read status register
    w25q_cmd_config.pe_mode_enable = FALSE;
    w25q_cmd_config.pe_mode_operate_code = 0;
    w25q_cmd_config.instruction_code = reg;
    w25q_cmd_config.instruction_length = QSPI_CMD_INSLEN_1_BYTE;
    w25q_cmd_config.address_code = 0;
    w25q_cmd_config.address_length = QSPI_CMD_ADRLEN_0_BYTE; // no address
    w25q_cmd_config.data_counter = 0;
    w25q_cmd_config.second_dummy_cycle_num = 0;
    w25q_cmd_config.operation_mode = QSPI_OPERATE_MODE_111;
    w25q_cmd_config.read_status_config = QSPI_RSTSC_SW_ONCE; // self to read.
    w25q_cmd_config.read_status_enable = TRUE;
    w25q_cmd_config.write_data_enable = FALSE;
    qspi_cmd_operation_kick(AT32_QSPI_FLASH, &w25q_cmd_config);

    if (!wait_cmd_completed()) return false;

    *status = AT32_QSPI_FLASH->rsts_bit.spists; // see rm doc: 28.4.10
    return true;
}

// Read state register 1
bool Flash_ReadStat1(uint8_t *status) {
    return Flash_ReadStatReg(READSTAT1, status);
}

// Read state register 1
bool Flash_ReadStat2(uint8_t *status) {
    return Flash_ReadStatReg(READSTAT2, status);
}

#ifndef AS_BOOTROM

// Write data and wait finish, no dma.
static bool write_wait_tx_done(uint8_t *in, uint32_t length) {
    // send data via qspi
    for (uint32_t i = 0; i < length; ++i) {
        if (!wait_flag_set(QSPI_TXFIFORDY_FLAG, 100)) return false;
        qspi_byte_write(AT32_QSPI_FLASH, in[i]);
    }
    return wait_cmd_completed();
}

// Write status register by CMD(0x01 or 0x31)
// If CMD == 0x01, will write status1 & status2 register
// If CMD == 0x31, will write status2 register only
static bool Flash_WriteStatReg(uint8_t reg, uint8_t *in, uint8_t length) {
    w25q_cmd_config.pe_mode_enable = FALSE;
    w25q_cmd_config.pe_mode_operate_code = 0;
    w25q_cmd_config.instruction_code = reg;
    w25q_cmd_config.instruction_length = QSPI_CMD_INSLEN_1_BYTE;
    w25q_cmd_config.address_code = 0;
    w25q_cmd_config.address_length = QSPI_CMD_ADRLEN_0_BYTE;
    w25q_cmd_config.data_counter = length;
    w25q_cmd_config.second_dummy_cycle_num = 0;
    w25q_cmd_config.operation_mode = QSPI_OPERATE_MODE_111;
    w25q_cmd_config.read_status_config = QSPI_RSTSC_HW_AUTO;
    w25q_cmd_config.read_status_enable = FALSE;
    w25q_cmd_config.write_data_enable = TRUE;
    qspi_cmd_operation_kick(AT32_QSPI_FLASH, &w25q_cmd_config);

    return write_wait_tx_done(in, length);
}

// Flash quad line communication enable
// Some chips already enable QE bit default. such as: W25Q64FVSSIQ, the Q suffix is QE bit enable default.
static bool Flash_QE_Enable(void) {
    uint8_t status[2];
    if (!Flash_ReadStat1(&status[0])) return false;
    if (!Flash_ReadStat2(&status[1])) return false;
    // Check if the QE bit has been enabled. On some winbond chips with Q as the suffix, this bit defaults to 1.
    if ((status[1] & 0x02) != 0) return true;
    // Set 'Quad Enable (QE)'(S9 bit) to 1.
    status[1] |= 1 << 1;
    // QE bit is a non-volatile Status Register bits, a standard Write Enable (06h) instruction must previously have
    // been executed for the device to accept the Write Status Register instruction (Status Register bit WEL must equal 1).
    if (!Flash_WriteEnable()) return false;
    // Some new chips support 31H instruction to set the status register 2,
    // but we need to use the 01H standard instruction to set the status register 2 for compatibility.
    if (!Flash_WriteStatReg(WRITESTAT, status, 2)) return false;
    // The BUSY bit is a 1 during the Write Status Register cycle
    // and a 0 when the cycle is finished and ready to accept other instructions again. After the Write Status
    // Register cycle has finished, the Write Enable Latch (WEL) bit in the Status Register will be cleared to 0.
    return !Flash_CheckBusy(BUSY_TIMEOUT); // Waiting for write done.
}

#endif

// Flash spi & gpio setup
bool FlashSetup(uint32_t baudrate) {
    qspi_gpio_config();
    // enable the qspi clock
    crm_periph_clock_enable(AT32_CRM_QSPI_FLASH_CLK, TRUE);
    // switch to cmd port
    qspi_xip_enable(AT32_QSPI_FLASH, FALSE);
    // set clk
    qspi_clk_division_set(AT32_QSPI_FLASH, from_baudrate_to_clk_div(baudrate));
    // set sck idle mode 0
    qspi_sck_mode_set(AT32_QSPI_FLASH, QSPI_SCK_MODE_0);
    // set wip in bit 0
    qspi_busy_config(AT32_QSPI_FLASH, QSPI_BUSY_OFFSET_0);
    // disable encrypt
    qspi_encryption_enable(AT32_QSPI_FLASH, FALSE);
    // enable auto ispc
    qspi_auto_ispc_enable(AT32_QSPI_FLASH);

#ifndef AS_BOOTROM
    return Flash_QE_Enable();
#else
    return true;
#endif
}

// Flash spi deinit
void FlashStop(void) {
    // Do not turn off the clock of GPIO. If you really want to turn off the clock,
    // you must ensure that GPIO is not currently used in other codes
    // crm_periph_clock_enable(CRM_GPIO?_PERIPH_CLOCK, TRUE);
    // crm_periph_clock_enable(CRM_GPIO?_PERIPH_CLOCK, TRUE);
    // crm_periph_clock_enable(CRM_GPIO?_PERIPH_CLOCK, TRUE);

    // disable qspi
    crm_periph_clock_enable(AT32_CRM_QSPI_FLASH_CLK, FALSE);
    qspi_interrupt_enable(AT32_QSPI_FLASH, FALSE);
}

// Read unique id for chip.
bool Flash_UniqueID(uint8_t *uid) {
    if (Flash_CheckBusy(BUSY_TIMEOUT)) return false;

    w25q_cmd_config.pe_mode_enable = FALSE;
    w25q_cmd_config.pe_mode_operate_code = 0;
    w25q_cmd_config.instruction_code = UNIQUE_ID;
    w25q_cmd_config.instruction_length = QSPI_CMD_INSLEN_1_BYTE;
    w25q_cmd_config.address_code = 0;
    // see rm doc 28.4.2, if address_length = 0, second_dummy_cycle_num will no working.
    //  so we need use addr to create dummy clk
    w25q_cmd_config.address_length = 4;
    w25q_cmd_config.data_counter = 8; // 64bit unique id
    w25q_cmd_config.second_dummy_cycle_num = 0; // dummy clk
    w25q_cmd_config.operation_mode = QSPI_OPERATE_MODE_111;
    w25q_cmd_config.read_status_config = QSPI_RSTSC_HW_AUTO;
    w25q_cmd_config.read_status_enable = FALSE;
    w25q_cmd_config.write_data_enable = FALSE;
    qspi_cmd_operation_kick(AT32_QSPI_FLASH, &w25q_cmd_config);

    read_wait_rx_done(uid, 8);

    return true;
}

#ifndef AS_BOOTROM

// Read JEDEC id
static void read_jedecid(uint8_t *jedecid) {
    w25q_cmd_config.pe_mode_enable = FALSE;
    w25q_cmd_config.pe_mode_operate_code = 0;
    w25q_cmd_config.instruction_code = JEDECID;
    w25q_cmd_config.instruction_length = QSPI_CMD_INSLEN_1_BYTE;
    w25q_cmd_config.address_code = 0;
    w25q_cmd_config.address_length = 0;
    w25q_cmd_config.data_counter = 3; // 24bit JEDECID info
    w25q_cmd_config.second_dummy_cycle_num = 0; // no dummy clk
    w25q_cmd_config.operation_mode = QSPI_OPERATE_MODE_111;
    w25q_cmd_config.read_status_config = QSPI_RSTSC_HW_AUTO;
    w25q_cmd_config.read_status_enable = FALSE;
    w25q_cmd_config.write_data_enable = FALSE;
    qspi_cmd_operation_kick(AT32_QSPI_FLASH, &w25q_cmd_config);

    read_wait_rx_done(jedecid, 3);
}

// Read Manufacturer / Device ID
// the difference between this function and the read_jedecid function is that the capacity information is missing
// so only 2byte device_id readout.
static void read_deviceid(uint8_t *device_id) {
    w25q_cmd_config.pe_mode_enable = FALSE;
    w25q_cmd_config.pe_mode_operate_code = 0;
    w25q_cmd_config.instruction_code = ID;
    w25q_cmd_config.instruction_length = QSPI_CMD_INSLEN_1_BYTE;
    w25q_cmd_config.address_code = 0;
    w25q_cmd_config.address_length = 3; // for 3 byte dummy clk
    w25q_cmd_config.data_counter = 2; // 16bit device id
    w25q_cmd_config.second_dummy_cycle_num = 0; // no dummy clk
    w25q_cmd_config.operation_mode = QSPI_OPERATE_MODE_111;
    w25q_cmd_config.read_status_config = QSPI_RSTSC_HW_AUTO;
    w25q_cmd_config.read_status_enable = FALSE;
    w25q_cmd_config.write_data_enable = FALSE;
    qspi_cmd_operation_kick(AT32_QSPI_FLASH, &w25q_cmd_config);

    read_wait_rx_done(device_id, 2);
}

// Read ID out
bool Flash_ReadID(flash_device_type_t *result, bool read_jedec) {
    if (Flash_CheckBusy(BUSY_TIMEOUT)) return false;

    if (read_jedec) {
        uint8_t juid[3];
        read_jedecid(juid);

        result->manufacturer_id = juid[0];
        result->device_id = juid[1];
        result->device_id2 = juid[2];
    } else {
        uint8_t duid[2];
        read_deviceid(duid);

        result->manufacturer_id = duid[0];
        result->device_id = duid[1];
    }

    return true;
}

uint16_t Flash_ReadDataCont(uint32_t address, uint8_t *out, uint16_t len) {
    // length should never be zero
    if (!len) return 0;

    // cmd
    w25q_cmd_config.pe_mode_enable = FALSE;
    w25q_cmd_config.pe_mode_operate_code = 0;
    w25q_cmd_config.instruction_code = FASTREAD_QO;
    w25q_cmd_config.instruction_length = QSPI_CMD_INSLEN_1_BYTE;
    // address
    w25q_cmd_config.address_code = address;
    w25q_cmd_config.address_length = QSPI_CMD_ADRLEN_3_BYTE; // 24bit address

    // dummy clk for qspi fast read output
    w25q_cmd_config.second_dummy_cycle_num = 8;

    // more...
    w25q_cmd_config.data_counter = len;
    w25q_cmd_config.operation_mode = QSPI_OPERATE_MODE_114;
    w25q_cmd_config.read_status_config = QSPI_RSTSC_SW_ONCE;
    w25q_cmd_config.read_status_enable = FALSE;
    w25q_cmd_config.write_data_enable = FALSE;

    qspi_cmd_operation_kick(AT32_QSPI_FLASH, &w25q_cmd_config);

    // readout from flash
    read_wait_rx_done(out, len);
    return len;
}

bool Flash_WriteEnable(void) {
    w25q_cmd_config.pe_mode_enable = FALSE;
    w25q_cmd_config.pe_mode_operate_code = 0;
    w25q_cmd_config.instruction_code = WRITEENABLE;
    w25q_cmd_config.instruction_length = QSPI_CMD_INSLEN_1_BYTE;
    w25q_cmd_config.address_code = 0;
    w25q_cmd_config.address_length = 0;
    w25q_cmd_config.data_counter = 0;
    w25q_cmd_config.second_dummy_cycle_num = 0;
    w25q_cmd_config.operation_mode = QSPI_OPERATE_MODE_111;
    w25q_cmd_config.read_status_config = QSPI_RSTSC_HW_AUTO;
    w25q_cmd_config.read_status_enable = FALSE;
    w25q_cmd_config.write_data_enable = TRUE;

    qspi_cmd_operation_kick(AT32_QSPI_FLASH, &w25q_cmd_config);

    if (!wait_cmd_completed()) return false;

    if (g_dbglevel > 3) Dbprintf("Flash Write enabled");

    return true;
}

uint16_t Flash_WriteDataCont(uint32_t address, uint8_t *in, uint16_t len) {
    if (!len)
        return 0;

    if (((address & 0xFF) + len) > 256) {
        Dbprintf("Flash_WriteDataCont 256 fail [ 0x%02x ] [ %u ]", (address & 0xFF) + len, len);
        return 0;
    }

    if (((address >> 16) & 0xFF) > spi_flash_pages64k) {
        Dbprintf("Flash_WriteDataCont,  block out-of-range %02x > %02x", (address >> 16) & 0xFF, spi_flash_pages64k);
        return 0;
    }

    w25q_cmd_config.pe_mode_enable = FALSE;
    w25q_cmd_config.pe_mode_operate_code = 0;
    w25q_cmd_config.instruction_code = PAGEPROG;
    w25q_cmd_config.instruction_length = QSPI_CMD_INSLEN_1_BYTE;

    w25q_cmd_config.address_code = address;
    w25q_cmd_config.address_length = QSPI_CMD_ADRLEN_3_BYTE;

    w25q_cmd_config.data_counter = len;
    w25q_cmd_config.second_dummy_cycle_num = 0;

    /*
     * WHY using 111 single line mode?
     *
     * The Quad Page Program can improve performance for PROM Programmer and applications that have slow clock speeds <5MHz.
     * Systems with faster clock speed will not realize much benefit for the Quad Page Program instruction since
     * the inherent page program time is much greater than the time it take to clock-in the data.
     */
    w25q_cmd_config.operation_mode = QSPI_OPERATE_MODE_111;

    w25q_cmd_config.read_status_config = QSPI_RSTSC_HW_AUTO;
    w25q_cmd_config.read_status_enable = FALSE;
    w25q_cmd_config.write_data_enable = TRUE;

    qspi_cmd_operation_kick(AT32_QSPI_FLASH, &w25q_cmd_config);

    write_wait_tx_done(in, len);
    return len;
}

bool Flash_Erase4k(uint8_t block, uint8_t sector) {
    if (block > spi_flash_pages64k || sector > MAX_SECTORS) return false;

    w25q_cmd_config.pe_mode_enable = FALSE;
    w25q_cmd_config.pe_mode_operate_code = 0;
    w25q_cmd_config.instruction_code = SECTORERASE;
    w25q_cmd_config.instruction_length = QSPI_CMD_INSLEN_1_BYTE;

    w25q_cmd_config.address_code = block << 16 | (sector << 4) << 8;
    w25q_cmd_config.address_length = QSPI_CMD_ADRLEN_3_BYTE;

    w25q_cmd_config.data_counter = 0;
    w25q_cmd_config.second_dummy_cycle_num = 0;
    w25q_cmd_config.operation_mode = QSPI_OPERATE_MODE_111;
    w25q_cmd_config.read_status_config = QSPI_RSTSC_HW_AUTO;
    w25q_cmd_config.read_status_enable = FALSE;
    w25q_cmd_config.write_data_enable = TRUE;
    qspi_cmd_operation_kick(AT32_QSPI_FLASH, &w25q_cmd_config);

    return wait_cmd_completed();
}

bool Flash_Erase64k(uint8_t block) {
    if (block > spi_flash_pages64k) return false;

    w25q_cmd_config.pe_mode_enable = FALSE;
    w25q_cmd_config.pe_mode_operate_code = 0;
    w25q_cmd_config.instruction_code = BLOCK64ERASE;
    w25q_cmd_config.instruction_length = QSPI_CMD_INSLEN_1_BYTE;

    w25q_cmd_config.address_code = block;
    w25q_cmd_config.address_length = QSPI_CMD_ADRLEN_3_BYTE;

    w25q_cmd_config.data_counter = 0;
    w25q_cmd_config.second_dummy_cycle_num = 0;
    w25q_cmd_config.operation_mode = QSPI_OPERATE_MODE_111;
    w25q_cmd_config.read_status_config = QSPI_RSTSC_HW_AUTO;
    w25q_cmd_config.read_status_enable = FALSE;
    w25q_cmd_config.write_data_enable = TRUE;
    qspi_cmd_operation_kick(AT32_QSPI_FLASH, &w25q_cmd_config);

    return wait_cmd_completed();
}

#endif // #ifndef AS_BOOTROM
