#ifndef _FPGA_HW_AT91_H_
#define _FPGA_HW_AT91_H_

#include "common.h"
#include "at91sam7s512.h"

STATIC_FORCE_INLINE bool FPGA_SSC_RX_Ready(void) {
    // There is no need to check the overflow flag,
    // as according to the datasheet description,
    // the latest data always moves from the shift register to the RHR register for overwriting.
    return (AT91C_BASE_SSC->SSC_SR & AT91C_SSC_RXRDY) == AT91C_SSC_RXRDY;
}

STATIC_FORCE_INLINE bool FPGA_SSC_TX_Ready(void) {
    return (AT91C_BASE_SSC->SSC_SR & AT91C_SSC_TXRDY) == AT91C_SSC_TXRDY;
}

STATIC_FORCE_INLINE bool FPGA_SSC_DMA_RX_Done(void) {
    return (AT91C_BASE_SSC->SSC_SR & AT91C_SSC_ENDRX) == AT91C_SSC_ENDRX;
}

STATIC_FORCE_INLINE bool FPGA_SSC_TX_Done(void) {
    return (AT91C_BASE_SSC->SSC_SR & AT91C_SSC_TXEMPTY) == AT91C_SSC_TXEMPTY;
}

STATIC_FORCE_INLINE uint32_t FPGA_SSC_RX_Value(void) {
    return AT91C_BASE_SSC->SSC_RHR;
}

STATIC_FORCE_INLINE void FPGA_SSC_TX_Value(uint32_t v) {
    AT91C_BASE_SSC->SSC_THR = v;
}

STATIC_FORCE_INLINE void FPGA_SSC_TX_Clear(void) {
    // TODO DXL: It is best to perform a clearing,
    // but currently it seems that not clearing on RDV4 will not result in erroneous modulation.
    // Afterwards, when we have time, we can conduct a test to see if adding the clearing logic affects anything.
}

STATIC_FORCE_INLINE void FPGA_SSC_DMA_RX_Disable(void) {
    AT91C_BASE_PDC_SSC->PDC_PTCR = AT91C_PDC_RXTDIS;
}

STATIC_FORCE_INLINE void FPGA_SSC_DMA_RX_Enable(void) {
    AT91C_BASE_PDC_SSC->PDC_PTCR = AT91C_PDC_RXTEN;
}

STATIC_FORCE_INLINE uint32_t *FPGA_SSC_DMA_RX_Current_Address(void) {
    return (uint32_t *)AT91C_BASE_PDC_SSC->PDC_RPR;
}

STATIC_FORCE_INLINE uint16_t FPGA_SSC_DMA_RX_Remaining_Count(void) {
    return AT91C_BASE_PDC_SSC->PDC_RCR;
}

STATIC_FORCE_INLINE void FPGA_SSC_DMA_RX_Refresh_Repeat(void *buf, uint16_t len) {
    // primary buffer was stopped( <-- we lost data!
    if (AT91C_BASE_PDC_SSC->PDC_RCR == 0) {
        AT91C_BASE_PDC_SSC->PDC_RPR = (uint32_t) buf;
        AT91C_BASE_PDC_SSC->PDC_RCR = len;
        // Dbprintf("[-] RxEmpty ERROR | data length %d", len); // temporary
    }
    // secondary buffer sets as primary, secondary buffer was stopped
    if (AT91C_BASE_PDC_SSC->PDC_RNCR == 0) {
        AT91C_BASE_PDC_SSC->PDC_RNPR = (uint32_t) buf;
        AT91C_BASE_PDC_SSC->PDC_RNCR = len;
    }
}

STATIC_FORCE_INLINE void FPGA_SSC_DMA_RX_Refresh_Single(void *buf, uint16_t len) {
    // The previous code logic was to update the NEXT BUF information first and then wait for the event of receiving completion to arrive (the main receiving register count is reset to zero)
    // Achieve the effect of setting buf ->waiting for reception completion and data processing (automatic rotation buf) ->setting buf (next cycle) ->waiting for reception completion and data processing (automatic rotation buf)
    // Seamlessly initiate the next reception and ensure that data is not overwritten, as the address of the buf set each time is different. Therefore, the logic of AT91 can be implemented using NEXT buf, and the key is to prevent the main buf from stopping
    // Otherwise, once the main buf stops, NEXT BUF will not be able to continue refreshing the next reception. Only when the main buf works normally until it ends, will it automatically rotate the reception information of NEXT BUF
    // Therefore, based on the timing of the call, if the end of reception is judged first, the main buf should be used for refreshing. If the buf is refreshed first, the end of reception should be judged later!
    // But in reality, for the sake of compatibility between platforms, we can only use the logic of first judging the end of the reception and then refreshing the reception buf! Because AT32 does not support NEXT BUF.

    // Warn: This code cannot be used because the NEXT BUF will only work when the MAIN BUF is working.
    // AT91C_BASE_PDC_SSC->PDC_RNPR = (uint32_t)next_buf;
    // AT91C_BASE_PDC_SSC->PDC_RNCR = PM3_CMD_DATA_SIZE;

    AT91C_BASE_PDC_SSC->PDC_RPR = (uint32_t) buf;      // start transfer to this memory address
    AT91C_BASE_PDC_SSC->PDC_RCR = len;                 // transfer this many samples
}

STATIC_FORCE_INLINE bool FPGA_SSC_DMA_RX_Primary_Done(void) {
    return AT91C_BASE_PDC_SSC->PDC_RCR == 0;
}

STATIC_FORCE_INLINE bool FPGA_SSC_DMA_RX_Secondary_Done(void) {
    return AT91C_BASE_PDC_SSC->PDC_RNCR == 0;
}

STATIC_FORCE_INLINE void FPGA_SSC_DMA_RX_Refresh_Both(void *buf, uint16_t len) {
    AT91C_BASE_PDC_SSC->PDC_RPR  = (uint32_t) buf;     // primary buffer address
    AT91C_BASE_PDC_SSC->PDC_RCR  = len;                // primary buffer count
    AT91C_BASE_PDC_SSC->PDC_RNPR = (uint32_t) buf;     // next buffer address
    AT91C_BASE_PDC_SSC->PDC_RNCR = len;                // next buffer count
}

STATIC_FORCE_INLINE void FPGA_SSC_DMA_RX_Refresh_Secondary(void *buf, uint16_t len) {
    AT91C_BASE_PDC_SSC->PDC_RNPR = (uint32_t) buf;     // next buffer address
    AT91C_BASE_PDC_SSC->PDC_RNCR = len;                // next buffer count
}

#endif
