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
#include "string.h"   // memcpy

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

// PDC receive double buffer.  The peripheral fills one bank while the other is
// armed as "next"; when a bank fills, the hardware promotes the armed one into
// US_RPR/US_RCR and clears US_RNCR.  We consume straight out of these two banks.
//
// There used to be an extra USART_FIFOLEN (1 kB) software ring stacked on top of
// them, which every byte was copied into and then out of again.  It cost 1 kB of
// .bss - which on AT91 comes straight out of BigBuf - bought no extra tolerance
// (the window before an overrun is set by the two PDC banks, not by the ring),
// and its free/used accounting could not tell "exactly full" from "empty":
// filling it to precisely sizeof(us_rxfifo) left low == high, so
// usart_rxdata_available() returned 0 and the next bank overwrote all of it.
static uint8_t us_in_a[USART_BUFFLEN];
static uint8_t us_in_b[USART_BUFFLEN];

static uint8_t *us_rx_cur = NULL;     // bank the PDC is filling right now
static uint16_t us_rx_cur_off = 0;    // bytes already handed to the caller from it
static uint8_t *us_rx_done = NULL;    // bank the PDC has finished, not yet drained
static uint16_t us_rx_done_off = 0;   // bytes already handed to the caller from it

// Notice a completed bank.  US_RNCR == 0 means the PDC finished the bank it was
// filling and promoted the one we had armed.  Only one completed bank can be
// tracked at a time: until it is drained and re-armed the peripheral has no spare,
// so a second bank filling up would overrun - the same 2 x USART_BUFFLEN window
// the ring-based version had.
static void usart_rx_rearm_done(void) {
    if ((us_rx_done != NULL) && (us_rx_done_off == USART_BUFFLEN)) {
        pUS1->US_RNPR = (uint32_t)us_rx_done;
        pUS1->US_RNCR = USART_BUFFLEN;
        us_rx_done = NULL;
        us_rx_done_off = 0;
    }
}

static void usart_rx_poll(void) {
    // give a drained bank back before looking for a new one, so the peripheral
    // spends as little time as possible with no spare bank armed
    usart_rx_rearm_done();

    if ((us_rx_done == NULL) && (pUS1->US_RNCR == 0)) {
        us_rx_done = us_rx_cur;
        us_rx_done_off = us_rx_cur_off;
        us_rx_cur = (us_rx_cur == us_in_a) ? us_in_b : us_in_a;
        us_rx_cur_off = 0;
        // the promoted bank may already have been fully consumed before it
        // completed, in which case it can go straight back
        usart_rx_rearm_done();
    }
}

// how many bytes the peripheral has already written into the bank it is filling.
// US_RCR counts down as bytes land, so this is a lower bound - never an
// over-estimate, which is the safe direction.
static inline uint16_t usart_rx_cur_filled(void) {
    uint16_t filled = USART_BUFFLEN - pUS1->US_RCR;
    return (filled > us_rx_cur_off) ? (filled - us_rx_cur_off) : 0;
}

uint16_t usart_rxdata_available(void) {
    usart_rx_poll();
    uint16_t n = usart_rx_cur_filled();
    if (us_rx_done != NULL) {
        n += USART_BUFFLEN - us_rx_done_off;
    }
    return n;
}

// Copy out at most "want" bytes, completed bank first so ordering is preserved.
static uint16_t usart_rx_take(uint8_t *dst, uint16_t want) {
    uint16_t got = 0;

    while (want && (us_rx_done != NULL)) {
        uint16_t chunk = USART_BUFFLEN - us_rx_done_off;
        if (chunk > want) {
            chunk = want;
        }
        memcpy(dst + got, us_rx_done + us_rx_done_off, chunk);
        us_rx_done_off += chunk;
        got += chunk;
        want -= chunk;

        // fully drained - hand it back to the PDC as the next target
        usart_rx_rearm_done();
    }

    if (want) {
        uint16_t chunk = usart_rx_cur_filled();
        if (chunk > want) {
            chunk = want;
        }
        if (chunk) {
            memcpy(dst + got, us_rx_cur + us_rx_cur_off, chunk);
            us_rx_cur_off += chunk;
            got += chunk;
        }
    }

    return got;
}

uint32_t usart_read_ng(uint8_t *data, size_t len) {

    if (len == 0) {
        return 0;
    }

    uint32_t bytes_rcv = 0;
    uint32_t try = 0;
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

        if (available > 0) {
            try = 0;
        }

        uint16_t want = (available < len) ? (uint16_t)available : (uint16_t)len;

        if (want) {
            uint16_t got = usart_rx_take(data + bytes_rcv, want);
            bytes_rcv += got;
            len -= got;
        }

        if (try++ == maxtry) {
                break;
            }
    }

    return bytes_rcv;
}


// transfer from device to client
int usart_writebuffer_sync(const uint8_t *data, size_t len) {

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
    pUS1->US_RNPR = (uint32_t)us_in_b;
    pUS1->US_RNCR = USART_BUFFLEN;

    // Track the banks the same way the hardware does
    us_rx_cur = us_in_a;
    us_rx_cur_off = 0;
    us_rx_done = NULL;
    us_rx_done_off = 0;

    // re-enable receiver / transmitter
    pUS1->US_CR = (AT91C_US_RXEN | AT91C_US_TXEN);

    // ready to receive and transmit
    pUS1->US_PTCR = AT91C_PDC_RXTEN | AT91C_PDC_TXTEN;
}
