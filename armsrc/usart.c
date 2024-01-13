//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------
// The main USART code, for serial communications over FPC connector
//-----------------------------------------------------------------------------
#include "usart.h"
#include "proxmark3_arm.h"

#define Dbprintf_usb(...) {\
        bool tmpfpc = g_reply_via_fpc;\
        bool tmpusb = g_reply_via_usb;\
        g_reply_via_fpc = false;\
        g_reply_via_usb = true;\
        Dbprintf(__VA_ARGS__);\
        g_reply_via_fpc = tmpfpc;\
        g_reply_via_usb = tmpusb;}

#define Dbprintf_fpc(...) {\
        bool tmpfpc = g_reply_via_fpc;\
        bool tmpusb = g_reply_via_usb;\
        g_reply_via_fpc = true;\
        g_reply_via_usb = false;\
        Dbprintf(__VA_ARGS__);\
        g_reply_via_fpc = tmpfpc;\
        g_reply_via_usb = tmpusb;}

#define Dbprintf_all(...) {\
        bool tmpfpc = g_reply_via_fpc;\
        bool tmpusb = g_reply_via_usb;\
        g_reply_via_fpc = true;\
        g_reply_via_usb = true;\
        Dbprintf(__VA_ARGS__);\
        g_reply_via_fpc = tmpfpc;\
        g_reply_via_usb = tmpusb;}


static volatile AT91PS_USART pUS1 = AT91C_BASE_US1;
static volatile AT91PS_PIO pPIO   = AT91C_BASE_PIOA;
static volatile AT91PS_PDC pPDC   = AT91C_BASE_PDC_US1;

uint32_t g_usart_baudrate = 0;
uint8_t g_usart_parity = 0;
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

static uint8_t us_in_a[USART_BUFFLEN];
static uint8_t us_in_b[USART_BUFFLEN];
static uint8_t *usart_cur_inbuf = NULL;
static uint16_t usart_cur_inbuf_off = 0;
static uint8_t us_rxfifo[USART_FIFOLEN];
static size_t us_rxfifo_low = 0;
static size_t us_rxfifo_high = 0;


static void usart_fill_rxfifo(void) {

    uint16_t rxfifo_free = 0;

    if (pUS1->US_RNCR == 0) { // One buffer got filled, backup buffer being used

        if (us_rxfifo_low > us_rxfifo_high)
            rxfifo_free = us_rxfifo_low - us_rxfifo_high;
        else
            rxfifo_free = sizeof(us_rxfifo) - us_rxfifo_high + us_rxfifo_low;

        uint16_t available = USART_BUFFLEN - usart_cur_inbuf_off;

        if (available <= rxfifo_free) {

            for (uint16_t i = 0; i < available; i++) {
                us_rxfifo[us_rxfifo_high++] = usart_cur_inbuf[usart_cur_inbuf_off + i];
                if (us_rxfifo_high == sizeof(us_rxfifo))
                    us_rxfifo_high = 0;
            }

            // Give next buffer
            pUS1->US_RNPR = (uint32_t)usart_cur_inbuf;
            pUS1->US_RNCR = USART_BUFFLEN;

            // Swap current buff
            if (usart_cur_inbuf == us_in_a)
                usart_cur_inbuf = us_in_b;
            else
                usart_cur_inbuf = us_in_a;

            usart_cur_inbuf_off = 0;
        } else {
            // Take only what we have room for
            available = rxfifo_free;
            for (uint16_t i = 0; i < available; i++) {

                us_rxfifo[us_rxfifo_high++] = usart_cur_inbuf[usart_cur_inbuf_off + i];

                if (us_rxfifo_high == sizeof(us_rxfifo)) {
                    us_rxfifo_high = 0;
                }
            }
            usart_cur_inbuf_off += available;
            return;
        }
    }

    if (pUS1->US_RCR < USART_BUFFLEN - usart_cur_inbuf_off) { // Current buffer partially filled

        if (us_rxfifo_low > us_rxfifo_high)
            rxfifo_free = (us_rxfifo_low - us_rxfifo_high);
        else
            rxfifo_free = (sizeof(us_rxfifo) - us_rxfifo_high + us_rxfifo_low);

        uint16_t available = (USART_BUFFLEN - pUS1->US_RCR - usart_cur_inbuf_off);

        if (available > rxfifo_free)
            available = rxfifo_free;

        for (uint16_t i = 0; i < available; i++) {
            us_rxfifo[us_rxfifo_high++] = usart_cur_inbuf[usart_cur_inbuf_off + i];
            if (us_rxfifo_high == sizeof(us_rxfifo)) {
                us_rxfifo_high = 0;
            }
        }
        usart_cur_inbuf_off += available;
    }
}

uint16_t usart_rxdata_available(void) {
    usart_fill_rxfifo();
    if (us_rxfifo_low <= us_rxfifo_high)
        return (us_rxfifo_high - us_rxfifo_low);
    else
        return (sizeof(us_rxfifo) - us_rxfifo_low + us_rxfifo_high);
}

uint32_t usart_read_ng(uint8_t *data, size_t len) {
    if (len == 0) return 0;
    uint32_t bytes_rcv = 0;
    uint32_t try = 0;
//    uint32_t highest_observed_try = 0;
    // Empirical max try observed: 3000000 / USART_BAUD_RATE
    // Let's take 10x

    uint32_t tryconstant = 0;
#ifdef USART_SLOW_LINK
    // Experienced up to 13200 tries on BT link even at 460800
    tryconstant = 50000;
#endif

    uint32_t maxtry = 10 * (3000000 / USART_BAUD_RATE) + tryconstant;

    while (len) {

        uint32_t available = usart_rxdata_available();
        uint32_t packetSize = MIN(available, len);

        if (available > 0) {
//            Dbprintf_usb("Dbg USART ask %d bytes, available %d bytes, packetsize %d bytes", len, available, packetSize);
//            highest_observed_try = MAX(highest_observed_try, try);
            try = 0;
        }
        len -= packetSize;
        while (packetSize--) {
            if (us_rxfifo_low == sizeof(us_rxfifo)) {
                us_rxfifo_low = 0;
            }
            data[bytes_rcv++] = us_rxfifo[us_rxfifo_low++];
        }
        if (try++ == maxtry) {
//            Dbprintf_usb("Dbg USART TIMEOUT");
                break;
            }
    }
//    highest_observed_try = MAX(highest_observed_try, try);
//    Dbprintf_usb("Dbg USART max observed try %i", highest_observed_try);
    return bytes_rcv;
}

// transfer from device to client
int usart_writebuffer_sync(uint8_t *data, size_t len) {

    // Wait for current PDC bank to be free
    // (and check next bank too, in case there will be a usart_writebuffer_async)
    while (pUS1->US_TNCR || pUS1->US_TCR) {};
    pUS1->US_TPR = (uint32_t)data;
    pUS1->US_TCR = len;
    // Wait until finishing all transfers to make sure "data" buffer can be discarded
    // (if we don't wait here, bulk send as e.g. "hw status" will fail)
    while (pUS1->US_TNCR || pUS1->US_TCR) {};
    return PM3_SUCCESS;
}

void usart_init(uint32_t baudrate, uint8_t parity) {

    if (baudrate != 0) {
        g_usart_baudrate = baudrate;
    }

    if ((parity == 'N') || (parity == 'O') || (parity == 'E')) {
        g_usart_parity = parity;
    }

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
    uint32_t mode = AT91C_US_USMODE_NORMAL |         // normal mode
                    AT91C_US_CLKS_CLOCK |            // MCK (48MHz)
                    AT91C_US_OVER |                  // oversampling
                    AT91C_US_CHRL_8_BITS |           // 8 bits
                    AT91C_US_NBSTOP_1_BIT |          // 1 stop bit
                    AT91C_US_CHMODE_NORMAL;          // channel mode: normal

    switch (g_usart_parity) {
        case 'N':
            mode |= AT91C_US_PAR_NONE;               // parity: none
            break;
        case 'O':
            mode |= AT91C_US_PAR_ODD;                // parity: odd
            break;
        case 'E':
            mode |= AT91C_US_PAR_EVEN;               // parity: even
            break;
    }
    pUS1->US_MR = mode;

    // all interrupts disabled
    pUS1->US_IDR = 0xFFFF;

    // http://ww1.microchip.com/downloads/en/DeviceDoc/doc6175.pdf
    // note that for very large baudrates, error is not neglectible:
    // b921600  => 8.6%
    // b1382400 => 8.6%
    // FP, Fractional Part  (Datasheet p402, Supported in AT91SAM512 / 256) (31.6.1.3)
    // FP = 0 disabled;
    // FP = 1-7 Baudrate resolution,
    // CD, Clock divider,
    //    sync == 0 , (async?)
    //       OVER = 0,  -no
    //          baudrate == selected clock/16/CD
    //       OVER = 1,  -yes we are oversampling
    //          baudrate == selected clock/8/CD    --> this is ours
    //
    uint32_t brgr = MCK / (g_usart_baudrate << 3);
    // doing fp = round((mck / (g_usart_baudrate << 3) - brgr) * 8) with integers:
    uint32_t fp = ((16 * MCK / (g_usart_baudrate << 3) - 16 * brgr) + 1) / 2;

    pUS1->US_BRGR = (fp << 16) | brgr;

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
    pUS1->US_RPR = (uint32_t)us_in_a;
    pUS1->US_RCR = USART_BUFFLEN;
    usart_cur_inbuf = us_in_a;
    usart_cur_inbuf_off = 0;
    pUS1->US_RNPR = (uint32_t)us_in_b;
    pUS1->US_RNCR = USART_BUFFLEN;

    // Initialize our fifo
    us_rxfifo_low = 0;
    us_rxfifo_high = 0;

    // re-enable receiver / transmitter
    pUS1->US_CR = (AT91C_US_RXEN | AT91C_US_TXEN);

    // ready to receive and transmit
    pUS1->US_PTCR = AT91C_PDC_RXTEN | AT91C_PDC_TXTEN;
}
