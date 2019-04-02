//-----------------------------------------------------------------------------
// Iceman, July 2018
// edits by - Anticat, August 2018
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// The main USART code, for serial communications over FPC connector
//-----------------------------------------------------------------------------
#include "usart.h"
#include "string.h"
#include "apps.h"  // for Dbprintf

#define AT91_BAUD_RATE 115200

volatile AT91PS_USART pUS1 = AT91C_BASE_US1;
volatile AT91PS_PIO pPIO   = AT91C_BASE_PIOA;
volatile AT91PS_PDC pPDC   = AT91C_BASE_PDC_US1;

/*
void usart_close(void) {
    // Reset the USART mode
    pUS1->US_MR = 0;

    // Reset the baud rate divisor register
    pUS1->US_BRGR = 0;

    // Reset the Timeguard Register
    pUS1->US_TTGR = 0;

    // Disable all interrupts
    pUS1->US_IDR = 0xFFFFFFFF;

    // Abort the Peripheral Data Transfers
    pUS1->US_PTCR = AT91C_PDC_RXTDIS | AT91C_PDC_TXTDIS;

    // Disable receiver and transmitter and stop any activity immediately
    pUS1->US_CR = AT91C_US_TXDIS | AT91C_US_RXDIS | AT91C_US_RSTTX | AT91C_US_RSTRX;
}
*/

static uint8_t us_inbuf[sizeof(UsbCommand)];
static uint8_t us_outbuf[sizeof(UsbCommand)];

// transfer from client to device
inline int16_t usart_readbuffer(uint8_t *data) {
    uint32_t rcr = pUS1->US_RCR;
    if (rcr < sizeof(us_inbuf)) {
        pUS1->US_PTCR = AT91C_PDC_RXTDIS;
        memcpy(data, us_inbuf, sizeof(us_inbuf) - rcr);
        // Reset DMA buffer
        pUS1->US_RPR = (uint32_t)us_inbuf;
        pUS1->US_RCR = sizeof(us_inbuf);
        pUS1->US_PTCR = AT91C_PDC_RXTEN;
        return sizeof(us_inbuf) - rcr;
    } else {
        return 0;
    }
}

inline bool usart_dataavailable(void) {
    return pUS1->US_RCR < sizeof(us_inbuf);
}

inline int16_t usart_readcommand(uint8_t *data) {
    if (pUS1->US_RCR == 0)
        return usart_readbuffer(data);
    else
        return 0;
}

inline bool usart_commandavailable(void) {
    return pUS1->US_RCR == 0;
}

// transfer from device to client
inline int16_t usart_writebuffer(uint8_t *data, size_t len) {


    if (pUS1->US_CSR & AT91C_US_ENDTX) {
        memcpy(us_outbuf, data, len);
        pUS1->US_TPR = (uint32_t)us_outbuf;
        pUS1->US_TCR = len;
        pUS1->US_PTCR = AT91C_PDC_TXTEN;
        while (!(pUS1->US_CSR & AT91C_US_ENDTX)) {};
        pUS1->US_PTCR = AT91C_PDC_TXTDIS;
        return len;
    } else {
        return 0;
    }
}


void usart_init(void) {

    // For a nice detailed sample, interrupt driven but still relevant.
    // See https://www.sparkfun.com/datasheets/DevTools/SAM7/at91sam7%20serial%20communications.pdf

    // disable & reset receiver / transmitter for configuration
    pUS1->US_CR = (AT91C_US_RSTRX | AT91C_US_RSTTX | AT91C_US_RXDIS | AT91C_US_TXDIS);

    //enable the USART1 Peripheral clock
    AT91C_BASE_PMC->PMC_PCER = (1 << AT91C_ID_US1);

    // disable PIO control of receive / transmit pins
    pPIO->PIO_PDR |= (AT91C_PA21_RXD1 | AT91C_PA22_TXD1);

    // enable peripheral mode A on receive / transmit pins
    pPIO->PIO_ASR |= (AT91C_PA21_RXD1 | AT91C_PA22_TXD1);
    pPIO->PIO_BSR = 0;

    // enable pull-up on receive / transmit pins (see 31.5.1 I/O Lines)
    pPIO->PIO_PPUER |= (AT91C_PA21_RXD1 | AT91C_PA22_TXD1);

    // set mode
    pUS1->US_MR = AT91C_US_USMODE_NORMAL |      // normal mode
                  AT91C_US_CLKS_CLOCK |            // MCK (48MHz)
                  AT91C_US_OVER |                  // oversampling
                  AT91C_US_CHRL_8_BITS |           // 8 bits
                  AT91C_US_PAR_NONE |              // parity: none
                  AT91C_US_NBSTOP_1_BIT |          // 1 stop bit
                  AT91C_US_CHMODE_NORMAL;          // channel mode: normal

    // all interrupts disabled
    pUS1->US_IDR = 0xFFFF;

    pUS1->US_BRGR =  48054841 / (115200 << 3);
    // Need speed?
    //pUS1->US_BRGR =  48054841 / (460800 << 3);

    // Write the Timeguard Register
    pUS1->US_TTGR = 0;
    pUS1->US_RTOR = 0;
    pUS1->US_FIDI = 0;
    pUS1->US_IF = 0;

    // Disable double buffers for now
    pUS1->US_TNPR = (uint32_t)0;
    pUS1->US_TNCR = 0;
    pUS1->US_RNPR = (uint32_t)0;
    pUS1->US_RNCR = 0;


    // re-enable receiver / transmitter
    pUS1->US_CR = (AT91C_US_RXEN | AT91C_US_TXEN);
    // ready to receive
    pUS1->US_RPR = (uint32_t)us_inbuf;
    pUS1->US_RCR = sizeof(us_inbuf);
    pUS1->US_PTCR = AT91C_PDC_RXTEN;
}
