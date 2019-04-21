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
#include "../armsrc/ticks.h"  // startcountus

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

static uint8_t us_inbuf1[USART_BUFFLEN];
static uint8_t us_inbuf2[USART_BUFFLEN];
uint8_t *usart_cur_inbuf = NULL;
uint16_t usart_cur_inbuf_off = 0;
static uint8_t us_rxfifo[USART_FIFOLEN];
static size_t us_rxfifo_low = 0;
static size_t us_rxfifo_high = 0;


static void usart_fill_rxfifo(void) {
    if (pUS1->US_RNCR == 0) { // One buffer got filled, backup buffer being used
// TODO check if we have room...
        uint16_t available = USART_BUFFLEN - usart_cur_inbuf_off;
        for (uint16_t i = 0; i < available; i++) {
            us_rxfifo[us_rxfifo_high++] = usart_cur_inbuf[usart_cur_inbuf_off + i];
            if (us_rxfifo_high == sizeof(us_rxfifo))
                us_rxfifo_high = 0;
        }
        // Give next buffer
        pUS1->US_RNPR = (uint32_t)usart_cur_inbuf;
        pUS1->US_RNCR = USART_BUFFLEN;
        // Swap current buff
        if (usart_cur_inbuf == us_inbuf1)
            usart_cur_inbuf = us_inbuf2;
        else
            usart_cur_inbuf = us_inbuf1;
        usart_cur_inbuf_off = 0;
    }
    if (pUS1->US_RCR < USART_BUFFLEN - usart_cur_inbuf_off) { // Current buffer partially filled
        uint16_t available = USART_BUFFLEN - pUS1->US_RCR - usart_cur_inbuf_off;
// TODO check if we have room...
        for (uint16_t i = 0; i < available; i++) {
            us_rxfifo[us_rxfifo_high++] = usart_cur_inbuf[usart_cur_inbuf_off + i];
            if (us_rxfifo_high == sizeof(us_rxfifo))
                us_rxfifo_high = 0;
        }
        usart_cur_inbuf_off += available;
    }
}

uint16_t usart_rxdata_available(void) {
    usart_fill_rxfifo();
    if (us_rxfifo_low <= us_rxfifo_high)
        return us_rxfifo_high - us_rxfifo_low;
    else
        return sizeof(us_rxfifo) - us_rxfifo_low + us_rxfifo_high;
}

extern bool reply_via_fpc;
extern void Dbprintf(const char *fmt, ...);
#define Dbprintf_usb(...) {\
        bool tmp = reply_via_fpc;\
        reply_via_fpc = false;\
        Dbprintf(__VA_ARGS__);\
        reply_via_fpc = tmp;}

uint32_t usart_read_ng(uint8_t *data, size_t len) {
    if (len == 0) return 0;
    uint32_t packetSize, nbBytesRcv = 0;
    uint32_t try = 0;
//    uint32_t highest_observed_try = 0;
    // Empirical max try observed: 3000000 / USART_BAUD_RATE
    // Let's take 10x
    uint32_t maxtry = 10 * (3000000 / USART_BAUD_RATE);

    while (len) {
        uint32_t available = usart_rxdata_available();

        packetSize = MIN(available, len);
        if (available > 0) {
//            Dbprintf_usb("Dbg USART ask %d bytes, available %d bytes, packetsize %d bytes", len, available, packetSize);
//            highest_observed_try = MAX(highest_observed_try, try);
            try = 0;
        }
        len -= packetSize;
        while (packetSize--) {
            data[nbBytesRcv++] = us_rxfifo[us_rxfifo_low++];
            if (us_rxfifo_low == sizeof(us_rxfifo))
                us_rxfifo_low = 0;
        }
        if (try++ == maxtry) {
//            Dbprintf_usb("Dbg USART TIMEOUT");
                break;
            }
    }
//    highest_observed_try = MAX(highest_observed_try, try);
//    Dbprintf_usb("Dbg USART max observed try %i", highest_observed_try);
    return nbBytesRcv;
}

// transfer from device to client
inline int16_t usart_writebuffer(uint8_t *data, size_t len) {

    // Wait for one free PDC bank
    while (pUS1->US_TCR && pUS1->US_TNCR) {};

    // Check if the current PDC bank is free
    if (pUS1->US_TCR == 0) {
        pUS1->US_TPR = (uint32_t)data;
        pUS1->US_TCR = len;
    }
    // Check if the backup PDC bank is free
    else if (pUS1->US_TNCR == 0) {
        pUS1->US_TNPR = (uint32_t)data;
        pUS1->US_TNCR = len;
    } else {
        // we shouldn't be here
        return 0;
    }
    //wait until finishing all transfers
    while (pUS1->US_TNCR || pUS1->US_TCR) {};
    return len;
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

    pUS1->US_BRGR =  48054841 / (USART_BAUD_RATE << 3);

    // Write the Timeguard Register
    pUS1->US_TTGR = 0;
    pUS1->US_RTOR = 0;
    pUS1->US_FIDI = 0;
    pUS1->US_IF = 0;

    // Initialize DMA buffers
    pUS1->US_TPR = (uint32_t)0;
    pUS1->US_TCR = 0;
    pUS1->US_TNPR = (uint32_t)0;
    pUS1->US_TNCR = 0;
    pUS1->US_RPR = (uint32_t)us_inbuf1;
    pUS1->US_RCR = USART_BUFFLEN;
    usart_cur_inbuf = us_inbuf1;
    pUS1->US_RNPR = (uint32_t)us_inbuf2;
    pUS1->US_RNCR = USART_BUFFLEN;

    // re-enable receiver / transmitter
    pUS1->US_CR = (AT91C_US_RXEN | AT91C_US_TXEN);

    // ready to receive and transmit
    pUS1->US_PTCR = AT91C_PDC_RXTEN | AT91C_PDC_TXTEN;
}
