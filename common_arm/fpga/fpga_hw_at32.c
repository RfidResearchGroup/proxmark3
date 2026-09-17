#include "gpio_hw_at32.h"
#include "fpga_apis.h"
#include "fpga_gw_jtag.h"
#include "ticks_apis.h"
#include "gpio_apis.h"
#include "dbprint.h"
#include "pm3_cmd.h"
#include "string.h"

uint16_t g_ssc_dma_rx_count;
uint8_t g_ssc_data_byte_width;
bool g_tx_lsb_first;

void FpgaSetup24MHzClk(void) {
    gpio_init_type gpio_init_struct;
    gpio_default_para_init(&gpio_init_struct);
    // gpio clk enable
    crm_periph_clock_enable(AT32_GPIO_PERIPH_FPGA_24M_CLK, TRUE); // ARM2FPGA_PCK0 = PA8_CRM_CLKO1
    // clkout gpio init
    gpio_init_struct.gpio_drive_strength = GPIO_DRIVE_STRENGTH_STRONGER;
    gpio_init_struct.gpio_mode = GPIO_MODE_MUX;
    gpio_init_struct.gpio_pins = AT32_GPIO_FPGA_24M_CLK_PIN;
    gpio_init_struct.gpio_pull = GPIO_PULL_NONE;
    gpio_init(AT32_GPIO_FPGA_24M_CLK, &gpio_init_struct);
    // config clkout division, 288/3/4=24mhz
    crm_clkout_div_set(CRM_CLKOUT_INDEX_1, CRM_CLKOUT_DIV1_3, CRM_CLKOUT_DIV2_4);
    crm_clock_out1_set(CRM_CLKOUT1_PLL); // config clkout1 clock

    /* 48m pll -> 24m clkout
    gpio_init_type gpio_init_struct;
    // enable periph clock
    crm_periph_clock_enable(AT32_GPIO_PERIPH_FPGA_24M_CLK, TRUE); // ARM2FPGA_PCK0 = PA8_CRM_CLKO1
    // set default parameter
    gpio_default_para_init(&gpio_init_struct);
    // config gpio mux function
    gpio_pin_mux_config(AT32_GPIO_FPGA_24M_CLK, GPIO_PINS_SOURCE8, GPIO_MUX_0);
    // config gpio
    gpio_init_struct.gpio_drive_strength = GPIO_DRIVE_STRENGTH_STRONGER;
    gpio_init_struct.gpio_out_type  = GPIO_OUTPUT_PUSH_PULL;
    gpio_init_struct.gpio_mode = GPIO_MODE_MUX;
    gpio_init_struct.gpio_pins = AT32_GPIO_FPGA_24M_CLK_PIN;
    gpio_init_struct.gpio_pull = GPIO_PULL_NONE;
    gpio_init(AT32_GPIO_FPGA_24M_CLK, &gpio_init_struct);
    // config clkout1 output clock source
    crm_clock_out1_set(CRM_CLKOUT1_PLL);
    // config clkout1 div
    crm_clkout_div_set(CRM_CLKOUT_INDEX_1, CRM_CLKOUT_DIV1_2, CRM_CLKOUT_DIV2_1);
    */
}

// gpio for spi-timode init
static void spi_ssc_gpio_setup(void) {
    gpio_init_type gpio_initstructure;

    crm_periph_clock_enable(CRM_GPIOB_PERIPH_CLOCK, TRUE);

    // PB9_SPI4_MOSI = fpga -> arm
    // PB8_SPI4_MISO = arm  -> fpga
    // PB7_SPI4_SCK  = clk
    // PB6_SPI4_CS   = frame

    gpio_default_para_init(&gpio_initstructure);
    gpio_initstructure.gpio_out_type       = GPIO_OUTPUT_PUSH_PULL;
    gpio_initstructure.gpio_drive_strength = GPIO_DRIVE_STRENGTH_STRONGER;
    gpio_initstructure.gpio_pull           = GPIO_PULL_DOWN;
    gpio_initstructure.gpio_mode           = GPIO_MODE_MUX;

    /* cs pin -> frame pin */
    gpio_initstructure.gpio_pull           = GPIO_PULL_DOWN;
    gpio_initstructure.gpio_pins           = AT32_GPIO_SSC_FRAME_PIN;
    gpio_init(AT32_GPIO_SSC_FRAME, &gpio_initstructure);
    gpio_pin_mux_config(AT32_GPIO_SSC_FRAME, AT32_GPIO_SSC_FRAME_SOURCE, AT32_GPIO_SSC_FRAME_MUX);

    /* sck pin -> clk pin */
    gpio_initstructure.gpio_pull           = GPIO_PULL_DOWN;
    gpio_initstructure.gpio_pins           = AT32_GPIO_SSC_CLK_PIN;
    gpio_init(AT32_GPIO_SSC_CLK, &gpio_initstructure);
    gpio_pin_mux_config(AT32_GPIO_SSC_CLK, AT32_GPIO_SSC_CLK_SOURCE, AT32_GPIO_SSC_CLK_MUX);

    /**
     * miso pin -> SSC_DOUT
     * ---
     * SPI is configured in TI mode and ARM is the slave.
     * In this case, according to the document description:
     * "If the slave still does not detect a valid CS pulse when receiving the last bit of the current data frame,
     * then after 1/2T SCK+3T PCLK, the output function of MISO will be turned off to control MISO floating. ”,
     * If we do not perform weak pull-down, it will cause DOUT to be in an uncontrollable state,
     * and some modules will use this pin for RF field modulation.
     * ---
     * It is best to configure it as a weak pull-down,
     * otherwise the lf_init function of the lfadc.c module will collect the voltage value of the modulated field due to default pull-up.
     * ---
     * What would happen if gpio_pull is GPIO_PULL_UP?
     * 1. call the FpgaSetupSsc to setup spi-timode
     *   ssc_dout pin will be controlled by SPI
     * 2. call the gpio_fpga_mod_only_setup() to steal the dout pin for modulation
     *   and call Gpio_SSC_DOUT_Low()
     * 3. call the adc read value by fpga immediately, you will get a wrong adc value,
     *   because it has been always modulation and no time to wait stable.
     */
    gpio_initstructure.gpio_pull           = GPIO_PULL_DOWN; // So, make sure the dout pin to be GPIO_PULL_DOWN is a good idea.
    gpio_initstructure.gpio_pins           = AT32_GPIO_SSC_DOUT_PIN;
    gpio_init(AT32_GPIO_SSC_DOUT, &gpio_initstructure);
    gpio_pin_mux_config(AT32_GPIO_SSC_DOUT, AT32_GPIO_SSC_DOUT_SOURCE, AT32_GPIO_SSC_DOUT_MUX);

    /* mosi pin -> SSC_DIN */
    gpio_initstructure.gpio_pull           = GPIO_PULL_UP;
    gpio_initstructure.gpio_pins           = AT32_GPIO_SSC_DIN_PIN;
    gpio_init(AT32_GPIO_SSC_DIN, &gpio_initstructure);
    gpio_pin_mux_config(AT32_GPIO_SSC_DIN, AT32_GPIO_SSC_DIN_SOURCE, AT32_GPIO_SSC_DIN_MUX);
}

void FpgaSetupSsc(uint16_t fpga_mode) {
    spi_init_type spi_init_struct;

    crm_periph_clock_enable(SPI_CRM_CLOCK_SSC, TRUE);
    spi_ssc_gpio_setup();

    spi_default_para_init(&spi_init_struct);
    spi_init_struct.transmission_mode = SPI_TRANSMIT_FULL_DUPLEX;
    spi_init_struct.master_slave_mode = SPI_MODE_SLAVE; // 配置为从机模式，数据传输的时钟由fpga提供
    spi_init_struct.mclk_freq_division = SPI_MCLK_DIV_8;
    spi_init_struct.first_bit_transmission = SPI_FIRST_BIT_MSB; // msb always default
    g_tx_lsb_first = false; // msb always default
    // 8 or 16 bits data for current fpga mode.
    if (FpgaIs16BitMsbMode(fpga_mode)) {
        spi_init_struct.frame_bit_num = SPI_FRAME_16BIT;
        g_ssc_data_byte_width = 2;
    } else {
        spi_init_struct.frame_bit_num = SPI_FRAME_8BIT;
        g_ssc_data_byte_width = 1;
    }
    // The setting in clock_polarity/clock_phase/cs_mode_selection invalid for ti-mode
    // spi_init_struct.clock_polarity = SPI_CLOCK_POLARITY_LOW;
    // spi_init_struct.clock_phase = SPI_CLOCK_PHASE_2EDGE;
    // spi_init_struct.cs_mode_selection = SPI_CS_HARDWARE_MODE;
    // spi_init_struct.cs_mode_selection = SPI_CS_SOFTWARE_MODE;
    spi_i2s_reset(SPI_SSC); // full reset spi-ti_mode
    spi_init(SPI_SSC, &spi_init_struct);
    spi_ti_mode_enable(SPI_SSC, TRUE); // enable ti mode(Somewhat similar to SSC of AT91)
    spi_i2s_dma_receiver_enable(SPI_SSC, TRUE); // RX DMA enabled.
    spi_enable(SPI_SSC, TRUE);
}

void FpgaUpdateFrameMode(uint8_t bits, bool rx_msb, bool tx_msb) {
    // Update the data width
    g_ssc_data_byte_width = bits / 8;
    // spi_frame_bit_num_set(SPI_SSC, SPI_FRAME_8BIT);
    SPI_SSC->ctrl1_bit.fbn = g_ssc_data_byte_width - 1; // SPI_FRAME_8BIT = 0, SPI_FRAME_16BIT = 1
    // The AT32 encapsulation library does not provide a function to update the LFT register.
    SPI_SSC->ctrl1_bit.ltf = rx_msb ? SPI_FIRST_BIT_MSB : SPI_FIRST_BIT_LSB; // SPI_FIRST_BIT_MSB = 0, SPI_FIRST_BIT_LSB = 1
    // Is the order of bits for tx and rx different?
    g_tx_lsb_first = tx_msb == false;
    // modify data width & bits order don't need spi disable.
}

bool FpgaSetupSscRxDmaRepeat(void *buf, uint16_t len) {
    // FpgaSetupSscRxDmaRepeat() 函数是替代原先的 FpgaSetupSscDma 的操作
    //  而 FpgaSetupSscRxDmaSingle() 函数是即将要实现的新的函数，作用是只设置主缓冲，对于AT91来说，就是下一buf不会被设置，避免覆盖数据
    //  对于at32来说，两者功能是一致的，所以 FpgaSetupSscRxDmaRepeat 内部直接封装调用 FpgaSetupSscRxDmaSingle 即可，两者功能是一致的。
    return FpgaSetupSscRxDmaSingle(buf, len);
}

bool FpgaSetupSscRxDmaSingle(void *buf, uint16_t len) {
    dma_init_type dma_init_struct;

    if (buf == NULL) {
        return false;
    }

    g_ssc_dma_rx_count = len; // Be sure to save the length value to this variable.

    crm_periph_clock_enable(DMA_CRM_CLOCK_SSC, TRUE);
    dmamux_enable(DMA_SSC, TRUE);

    dma_reset(DMA_CHANNEL_SSC);
    dma_default_para_init(&dma_init_struct);
    dma_init_struct.buffer_size = len;
    dma_init_struct.memory_inc_enable = TRUE; // address of buffer in memory need increment.
    dma_init_struct.peripheral_inc_enable = FALSE; // peripheral data register is fixed.
    // 我们在初始化DMA的时候，需要指定数据的宽度值但此函数是不具备宽度参数的，需要从SSC(SPI-TIMODE) 中了解到当前选择的数据宽度，然后做出映射。
    dma_init_struct.memory_data_width = g_ssc_data_byte_width == 1 ? DMA_MEMORY_DATA_WIDTH_BYTE : DMA_MEMORY_DATA_WIDTH_HALFWORD;
    dma_init_struct.peripheral_data_width = g_ssc_data_byte_width == 1 ? DMA_PERIPHERAL_DATA_WIDTH_BYTE : DMA_PERIPHERAL_DATA_WIDTH_HALFWORD;
    dma_init_struct.priority = DMA_PRIORITY_HIGH;
    dma_init_struct.loop_mode_enable = FALSE; // loop disabled, only one time running.
    dma_init_struct.memory_base_addr = (uint32_t)buf;
    dma_init_struct.peripheral_base_addr = (uint32_t) & (SPI_SSC->dt);
    dma_init_struct.direction = DMA_DIR_PERIPHERAL_TO_MEMORY; // receive data from SPI-TI_MODE(SSC)
    dma_init(DMA_CHANNEL_SSC, &dma_init_struct);
    dmamux_init(DMA_CHANNEL_MUX_SSC, DMA_MUX_REQ_ID_SSC);

    if (FPGA_SSC_RX_Ready()) {
        ((uint8_t *)buf)[0] = FPGA_SSC_RX_Value(); // Readout and discard old byte. It's important!
    }

    FPGA_SSC_DMA_RX_Enable(); // Start rx channel

    return true;
}

// gpio for spi-cmd init
static void spi_cmd_gpio_setup(void) {
    gpio_init_type gpio_initstructure;

    AT32_GPIO_PERIPH_CLKS_ENABLE(AT32_GPIO_PERIPH_SPI_CLK);

    // init gpio structure
    gpio_default_para_init(&gpio_initstructure);
    gpio_initstructure.gpio_out_type       = GPIO_OUTPUT_PUSH_PULL;
    gpio_initstructure.gpio_drive_strength = GPIO_DRIVE_STRENGTH_STRONGER;
    gpio_initstructure.gpio_pull           = GPIO_PULL_NONE;
    gpio_initstructure.gpio_mode           = GPIO_MODE_MUX;

    /* sck pin */
    gpio_initstructure.gpio_pull           = GPIO_PULL_NONE;
    gpio_initstructure.gpio_pins           = AT32_GPIO_SPI_SCK_PIN;
    gpio_init(AT32_GPIO_SPI_SCK, &gpio_initstructure);
    gpio_pin_mux_config(AT32_GPIO_SPI_SCK, AT32_GPIO_SPI_SCK_SOURCE, AT32_GPIO_SPI_SCK_MUX);

    /* miso pin */
    gpio_initstructure.gpio_pull           = GPIO_PULL_NONE;
    gpio_initstructure.gpio_pins           = AT32_GPIO_SPI_MISO_PIN;
    gpio_init(AT32_GPIO_SPI_MISO, &gpio_initstructure);
    gpio_pin_mux_config(AT32_GPIO_SPI_MISO, AT32_GPIO_SPI_MISO_SOURCE, AT32_GPIO_SPI_MISO_MUX);

    /* mosi pin */
    gpio_initstructure.gpio_pull           = GPIO_PULL_NONE;
    gpio_initstructure.gpio_pins           = AT32_GPIO_SPI_MOSI_PIN;
    gpio_init(AT32_GPIO_SPI_MOSI, &gpio_initstructure);
    gpio_pin_mux_config(AT32_GPIO_SPI_MOSI, AT32_GPIO_SPI_MOSI_SOURCE, AT32_GPIO_SPI_MOSI_MUX);

    // cs software
    gpio_initstructure.gpio_out_type = GPIO_OUTPUT_PUSH_PULL;
    gpio_initstructure.gpio_pull = GPIO_PULL_NONE;
    gpio_initstructure.gpio_drive_strength = GPIO_DRIVE_STRENGTH_STRONGER;
    gpio_initstructure.gpio_pins           = AT32_GPIO_SPI_CS_PIN;
    gpio_initstructure.gpio_mode           = GPIO_MODE_OUTPUT;
    gpio_init(AT32_GPIO_SPI_CS, &gpio_initstructure);
    gpio_bits_set(AT32_GPIO_SPI_CS, AT32_GPIO_SPI_CS_PIN); // default CS set to high for deselect
}

static void spi_cmd_setup(void) {
    spi_init_type spi_init_struct;

    // master spi initialization
    crm_periph_clock_enable(SPI_CRM_CLOCK_CMD, TRUE);
    spi_cmd_gpio_setup();

    spi_default_para_init(&spi_init_struct);

    spi_init_struct.transmission_mode = SPI_TRANSMIT_FULL_DUPLEX;
    spi_init_struct.master_slave_mode = SPI_MODE_MASTER; // arm master, fpga slave
    spi_init_struct.mclk_freq_division = SPI_MCLK_DIV_4; // 144MHZ / 4 == 36MHZ(48MHZ MAX)
    spi_init_struct.first_bit_transmission = SPI_FIRST_BIT_MSB;
    spi_init_struct.frame_bit_num = SPI_FRAME_16BIT;
    spi_init_struct.clock_polarity = SPI_CLOCK_POLARITY_LOW;
    spi_init_struct.clock_phase = SPI_CLOCK_PHASE_1EDGE;
    spi_init_struct.cs_mode_selection = SPI_CS_SOFTWARE_MODE;
    spi_init(SPI_CMD, &spi_init_struct);
    spi_enable(SPI_CMD, TRUE);
}

void FpgaSendCommand(uint16_t cmd, uint16_t v) {
    // Init spi
    spi_cmd_setup();
    // Send data
    gpio_bits_reset(AT32_GPIO_SPI_CS, AT32_GPIO_SPI_CS_PIN); // CS LOW
    while (spi_i2s_flag_get(SPI_CMD, SPI_I2S_TDBE_FLAG) == RESET) {}
    spi_i2s_data_transmit(SPI_CMD, cmd | v);
    while (spi_i2s_flag_get(SPI_CMD, SPI_I2S_BF_FLAG) != RESET) {} // Waiting for SPI transmit finish.
    gpio_bits_set(AT32_GPIO_SPI_CS, AT32_GPIO_SPI_CS_PIN); // CS HIGH
}

void Fpga_print_status(void) {
    DbpString(_CYAN_("Current FPGA image"));
    Dbprintf("  mode.................... All-In-One");
}

// Define a static configuration context for the Gowin JTAG configuration process
static gowin_config_ctx_t gci = {
    .tx_pos = 0,
    .tx_total = 0,
    .is_cfg_sram = false,
};

int FpgaStartConfig(bool configSram, uint32_t fileLength) {

    // Check if the file length exceeds the maximum allowed size for FPGA bitstream files
    if (fileLength > FPGA_BITSTREAM_FILE_SIZE_MAX) {
        return PM3_ELENGTH;
    }

    // Init jtag hardware link.
    gpio_fpga_download_setup();

    // Reset for restart a new transfer
    gci.tx_pos = 0;
    gci.tx_total = fileLength;
    gci.is_cfg_sram = configSram; // Is it SRAM or Flash configuration?

    gowin_jtag_start_config(&gci);
    if (gci.status != GOWIN_JTAG_OK) {
        return PM3_EFAILED;
    }

    return PM3_SUCCESS;
}

int FpgaConfigWrite(uint8_t *data, uint32_t data_length) {

    // Check if the data length exceeds the remaining space in the configuration context
    // When writing flash, the internal system will also check whether the number of caches plus the current number will overflow.
    if (gci.tx_pos + data_length > gci.tx_total) {
        return PM3_ELENGTH;
    }

    gowin_jtag_config_write(data, data_length, &gci);
    if (gci.status != GOWIN_JTAG_OK) {
        return PM3_EFAILED;
    }
    return PM3_SUCCESS;
}

int FpgaStopConfig(void) {
    gowin_jtag_stop_config(&gci);
    if (gci.status != GOWIN_JTAG_OK) {
        return PM3_EFAILED;
    }
    return PM3_SUCCESS;
}

uint32_t FpgaConfigPlatformStatus(void) {
    return gci.status;
}

void FpgaResetComInterface(void) {
    spi_i2s_reset(SPI_SSC); // full reset spi
    spi_i2s_reset(SPI_CMD); // full reset spi
    crm_periph_clock_enable(SPI_CRM_CLOCK_SSC, FALSE);
    crm_periph_clock_enable(SPI_CRM_CLOCK_CMD, FALSE);
    // Do not reset GPIO, or disable GPIO clock, as other functions may depend on GPIO.

    // Init JTAG link of FPGA to waiting for fpga work status check.
    gpio_fpga_download_setup();
    while (1) {
        gowin_jtag_status_t status = gowin_jtag_init();
        if (status == GOWIN_JTAG_OK) {
            break;
        }
        SpinDelay(100); // Wait for 100ms before retrying
        Gpio_LED_B_Inv(); // Show some indication that we are retrying to init JTAG link, which means waiting for FPGA to be ready.
    }
    gowin_jtag_deinit();
}
