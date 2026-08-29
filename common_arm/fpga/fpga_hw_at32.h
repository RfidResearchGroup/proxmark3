#ifndef _FPGA_HW_AT32_H_
#define _FPGA_HW_AT32_H_

#include "common.h"
#include "at32f435_437_spi.h"
#include "at32f435_437_dma.h"
#include "fpga_gw_jtag.h"

#define FPGA_BITSTREAM_FILE_SIZE_MAX  (217 * 1024) // 217KB, the max size of bitstream file for GW1N-4(UV4) of PM5

// The DMA memory address of AT32 does not self increment,
// and there are no useful registers to know the initial set count value,
// so we can only use one variable to store the set count value.
extern uint16_t g_ssc_dma_rx_count;
// Save the data width in bytes required for the fpga_mode parameter passed by the FpgaSetupSsc function.
extern uint8_t g_ssc_data_byte_width;
// Is tx lsb first? If diff with rx frame settings, the data will reverse before send.
extern bool g_tx_lsb_first;

// TODO DXL 纠正SPI和DMA通道选择，为了方便修改，此处可先暂时定义SPI和DMA外设和DMA通道的对应宏
//  spi-ti_mode 用到了 SPI4, DMA1
//  spi-cmd     用到了 SPI3，无DMA
#define SPI_SSC              SPI4
#define SPI_CRM_CLOCK_SSC    CRM_SPI4_PERIPH_CLOCK
#define DMA_SSC              DMA1
#define DMA_CHANNEL_SSC      DMA1_CHANNEL1
#define DMA_CRM_CLOCK_SSC    CRM_DMA1_PERIPH_CLOCK
#define DMA_CHANNEL_MUX_SSC  DMA1MUX_CHANNEL1
#define DMA_MUX_REQ_ID_SSC   DMAMUX_DMAREQ_ID_SPI4_RX
#define DMA_SSC_RX_DONE_FLAG DMA1_FDT1_FLAG // If the channel is changed, this FLAG also needs to be modified.
#define SPI_CMD              SPI3
#define SPI_CRM_CLOCK_CMD    CRM_SPI3_PERIPH_CLOCK

STATIC_FORCE_INLINE bool FPGA_SSC_RX_Ready(void) {
    /*
     * Note that according to the manual description, if SPI receives data but does not read it after startup,
     * the SPI peripheral will generate an overflow interrupt and no longer receive new data. At this time,
     * the RXRDY flag will remain set. If we read and use this data, we may obtain an incorrect result,
     * resulting in decoding failure.
     */

    // When the following conditions are met, we can consider the data to have been effectively received.
    //  1. spi_i2s_flag_get(SPI_SSC, SPI_I2S_RDBF_FLAG) == SET
    //  2. spi_i2s_flag_get(SPI_SSC, SPI_I2S_ROERR_FLAG) == RESET
    // Easy understand: Not overflow error and data buffer is full, when sts & 0x41 == 0x01, ROERR == 0.
    // ---
    // Reading SPI_DT register and SPI_STS register sequentially can clear ROERR(Must to read DT reg)
    // Only when the ROERR flag is set, it is necessary to read DT, so the '&&' condition is very important.
    // If the former does not hold, the DT register will not be read.
    return ((SPI_SSC->sts & (SPI_I2S_RDBF_FLAG | SPI_I2S_ROERR_FLAG)) == SPI_I2S_RDBF_FLAG)
           || (((SPI_SSC->sts & SPI_I2S_ROERR_FLAG) == SPI_I2S_ROERR_FLAG) && (SPI_SSC->dt & 0)); // Readout data for clear the ROERR flag. IMPORTANT!
}

STATIC_FORCE_INLINE bool FPGA_SSC_TX_Ready(void) {
    // spi_i2s_flag_get(SPI_SSC, SPI_I2S_TDBE_FLAG) == SET
    return (SPI_SSC->sts & SPI_I2S_TDBE_FLAG) == SPI_I2S_TDBE_FLAG;
}

STATIC_FORCE_INLINE bool FPGA_SSC_TX_Done(void) {
    // spi_i2s_flag_get(SPI_SSC, SPI_I2S_BF_FLAG) == RESET
    return (SPI_SSC->sts & SPI_I2S_BF_FLAG) != SPI_I2S_BF_FLAG; // SPI currently has no transmission transactions.
}

STATIC_FORCE_INLINE uint32_t FPGA_SSC_RX_Value(void) {
    // spi_i2s_data_receive(SPI_SSC)
    return (uint16_t)SPI_SSC->dt;
}

STATIC_FORCE_INLINE void FPGA_SSC_TX_Value(uint32_t v) {
    // 'SPI_SSC->dt' is from 'spi_i2s_data_transmit()'
    if (SPI_SSC->ctrl1_bit.ltf == g_tx_lsb_first) {
        SPI_SSC->dt = (uint16_t)v; // The order of bits for tx and rx is the same, so we can send them directly.
    } else { // Is different between tx&rx, need to reverse the data.
        if (SPI_SSC->ctrl1_bit.fbn) {
            SPI_SSC->dt = (__RBIT(v) >> 16) & 0xFFFF;
        } else {
            SPI_SSC->dt = (__RBIT(v) >> 24) & 0xFF;
        }
    }
}

STATIC_FORCE_INLINE void FPGA_SSC_TX_Clear(void) {
    while (!FPGA_SSC_TX_Ready()) {
        // Waiting for last transfer finish.
        // Nothing to do here...
    }
    FPGA_SSC_TX_Value(0x00); // Send a dummy data to clear the shift register and make the last data out.
}

STATIC_FORCE_INLINE bool FPGA_SSC_DMA_RX_Done(void) {
    // dma_flag_get(DMA_SSC_RX_DONE_FLAG) == RESET
    // Note: Reading this register will not automatically clear the flag,
    // and we need to write to the DMA_CR register to clear it. However,
    // we can write it in the FPGA_SSC_DMA_RX_Refresh_XXX function
    // because that function will always be called after FPGA_SSC_DMA_RX_Done returns true.
    // see: FPGA_SSC_DMA_RX_Refresh_Single()
    return DMA_SSC->sts & DMA_SSC_RX_DONE_FLAG;
}

STATIC_FORCE_INLINE void FPGA_SSC_DMA_RX_Disable(void) {
    // dma_channel_enable(DMA_CHANNEL_SSC, FALSE);
    DMA_CHANNEL_SSC->ctrl_bit.chen = 0;
}

STATIC_FORCE_INLINE void FPGA_SSC_DMA_RX_Enable(void) {
    // dma_channel_enable(DMA_CHANNEL_SSC, TRUE);
    DMA_CHANNEL_SSC->ctrl_bit.chen = 1;
}

STATIC_FORCE_INLINE uint32_t *FPGA_SSC_DMA_RX_Current_Address(void) {

    // The DMA address of AT32 does not self increment. So reading the maddr register yields a fixed initial BUF starting address
    // We can calculate the current rx address: Starting address + Current rx count
    // Note: the count value register will increment on working, so we need save it.
    //  ret = starting_address(uint8) + ((g_ssc_dma_rx_count - remaining_count) * g_ssc_data_byte_width)
    //  > starting_address = DMA_CHANNEL_SSC->maddr
    //  > remaining_count  = FPGA_SSC_DMA_RX_Remaining_Count()

    // Warn: Calc byte count first, last to convert to U32*

    return (uint32_t *)((uint8_t *)DMA_CHANNEL_SSC->maddr + ((g_ssc_dma_rx_count - FPGA_SSC_DMA_RX_Remaining_Count()) * g_ssc_data_byte_width));
}

STATIC_FORCE_INLINE uint16_t FPGA_SSC_DMA_RX_Remaining_Count(void) {
    // dma_data_number_get(DMA_CHANNEL_SSC) or dma_init()
    return (uint16_t)DMA_CHANNEL_SSC->dtcnt_bit.cnt;
}

STATIC_FORCE_INLINE void FPGA_SSC_DMA_RX_Refresh_Repeat(void *buf, uint16_t len) {
    // AT32 no next buf, so repeat & single is same logic.
    FPGA_SSC_DMA_RX_Refresh_Single(buf, len);
}

STATIC_FORCE_INLINE void FPGA_SSC_DMA_RX_Refresh_Single(void *buf, uint16_t len) {
    g_ssc_dma_rx_count = len;
    DMA_SSC->clr = DMA_SSC_RX_DONE_FLAG & 0x0FFFFFFF; // dma_flag_clear(DMA_SSC)
    FPGA_SSC_DMA_RX_Disable(); // Writing to the CNT & ADDR registers requires closing the channel first.
    DMA_CHANNEL_SSC->dtcnt_bit.cnt = len;
    DMA_CHANNEL_SSC->maddr = (uint32_t)buf;
    FPGA_SSC_DMA_RX_Enable();
}

STATIC_FORCE_INLINE bool FPGA_SSC_DMA_RX_Primary_Done(void) {
    // AT32 has no "primary + next" double buffer. The single-shot DMA simply
    // stops when the buffer is full, and that is the normal end of one
    // reception cycle (the data is still valid), not the "both buffers
    // exhausted" hard stall this hook describes. So it never applies here.
    return false;
}

STATIC_FORCE_INLINE bool FPGA_SSC_DMA_RX_Secondary_Done(void) {
    // The single-shot DMA counter reaching 0 means the buffer is full and the
    // next reception must be re-armed — this is the "secondary buffer" role on
    // AT32 (the buffer that comes after the current one finishes).
    return FPGA_SSC_DMA_RX_Done();
}

STATIC_FORCE_INLINE void FPGA_SSC_DMA_RX_Refresh_Both(void *buf, uint16_t len) {
    // AT32 does not support a primary-buffer refresh (there is no double
    // buffer), so this is intentionally a no-op. Primary_Done() is always
    // false, so the caller never reaches this path anyway.
    (void)buf;
    (void)len;
}

STATIC_FORCE_INLINE void FPGA_SSC_DMA_RX_Refresh_Secondary(void *buf, uint16_t len) {
    // Re-arm the single buffer to start the next reception.
    FPGA_SSC_DMA_RX_Refresh_Single(buf, len);
}

#endif
