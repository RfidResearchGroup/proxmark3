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

static uint8_t us_outbuf[sizeof(UsbCommand)];

/// Reads data from an USART peripheral
/// \param data  Pointer to the buffer where the received data will be stored.
/// \param len  Size of the data buffer (in bytes).
inline int16_t usart_readbuffer(uint8_t *data, size_t len) {

    // Check if the first PDC bank is free
    if (!(pUS1->US_RCR)) {
        pUS1->US_RPR = (uint32_t)data;
        pUS1->US_RCR = len;

        pUS1->US_PTCR = AT91C_PDC_RXTEN | AT91C_PDC_TXTDIS;
        return 2;
    }
    // Check if the second PDC bank is free
    else if (!(pUS1->US_RNCR)) {
        pUS1->US_RNPR = (uint32_t)data;
        pUS1->US_RNCR = len;

        pUS1->US_PTCR = AT91C_PDC_RXTEN | AT91C_PDC_TXTDIS;
        return 1;
    } else {
        return 0;
    }
}


// transfer from device to client
inline int16_t usart_writebuffer(uint8_t *data, size_t len) {

    // Check if the first PDC bank is free
    if (!(pUS1->US_TCR)) {
        memcpy(us_outbuf, data, len);
        pUS1->US_TPR = (uint32_t)us_outbuf;
        pUS1->US_TCR = sizeof(us_outbuf);

        pUS1->US_PTCR = AT91C_PDC_TXTEN | AT91C_PDC_RXTDIS;
        return 2;
    }
    // Check if the second PDC bank is free
    else if (!(pUS1->US_TNCR)) {
        memcpy(us_outbuf, data, len);
        pUS1->US_TNPR = (uint32_t)us_outbuf;
        pUS1->US_TNCR = sizeof(us_outbuf);

        pUS1->US_PTCR = AT91C_PDC_TXTEN | AT91C_PDC_RXTDIS;
        return 1;
    } else {
        return 0;
    }
}

void usart_init(void) {

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
                  AT91C_US_CHRL_8_BITS |           // 8 bits
                  AT91C_US_PAR_NONE |              // parity: none
                  AT91C_US_NBSTOP_1_BIT |          // 1 stop bit
                  AT91C_US_CHMODE_NORMAL;          // channel mode: normal

    // all interrupts disabled
    pUS1->US_IDR = 0xFFFF;

    // iceman,  setting 115200 doesn't work. Only speed I got to work is 9600.
    // something fishy with the AT91SAM7S512 USART..  Or I missed something
    // For a nice detailed sample, interrupt driven but still relevant.
    // See https://www.sparkfun.com/datasheets/DevTools/SAM7/at91sam7%20serial%20communications.pdf

    // set baudrate to 115200
    // 115200 * 16 == 1843200
    //
    //pUS1->US_BRGR = (48UL*1000*1000) / (9600*16);
    pUS1->US_BRGR =  48054841 / (9600 << 4);

    // Write the Timeguard Register
    pUS1->US_TTGR = 0;
    pUS1->US_RTOR = 0;
    pUS1->US_FIDI = 0;
    pUS1->US_IF = 0;

    // re-enable receiver / transmitter
    pUS1->US_CR = (AT91C_US_RXEN | AT91C_US_TXEN);
}
