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
// at91sam7s USB CDC device implementation
// based on the "Basic USB Example" from ATMEL (doc6123.pdf)
//-----------------------------------------------------------------------------

#include "usb_cdc_apis.h"
#include "at91sam7s512.h"
#include "proxmark3_arm.h"
#include "usart_defs.h"
#include "ticks_apis.h"
#include "usb_read_ng.h"
#include "usb_cdc_desc.h"

/*
AT91SAM7S256  USB Device Port
• Embedded 328-byte dual-port RAM for endpoints
• Four endpoints
– Endpoint 0: 8 bytes
– Endpoint 1 and 2: 64 bytes ping-pong
– Endpoint 3: 64 bytes
– Ping-pong Mode (two memory banks) for bulk endpoints
*/

// EP for CDC definition
#define AT91C_EP_CONTROL                0
#define AT91C_EP_OUT                    1  // cfg bulk out                  - 0x01
#define AT91C_EP_IN                     2  // cfg bulk in                   - 0x82
#define AT91C_EP_NOTIFY                 3  // cfg cdc notification interrup - 0x83

// The definition of endpoint size has been moved back from the original file to this source file.
// Because the usb_cdc.h header file is now a universally defined header file.
#define AT91C_USB_EP_CONTROL_SIZE       8
#define AT91C_USB_EP_OUT_SIZE           64
#define AT91C_USB_EP_IN_SIZE            64

/* WCID specific Request Code */
#define MS_OS_DESCRIPTOR_INDEX          0xEE
#define MS_VENDOR_CODE                  0x1C
#define MS_EXTENDED_COMPAT_ID           0x04
#define MS_EXTENDED_PROPERTIES          0x05
#define MS_WCID_GET_DESCRIPTOR          0xC0
#define MS_WCID_GET_FEATURE_DESCRIPTOR  0xC1

/* USB standard request code */
#define STD_GET_STATUS_ZERO           0x0080
#define STD_GET_STATUS_INTERFACE      0x0081
#define STD_GET_STATUS_ENDPOINT       0x0082

#define STD_CLEAR_FEATURE_ZERO        0x0100
#define STD_CLEAR_FEATURE_INTERFACE   0x0101
#define STD_CLEAR_FEATURE_ENDPOINT    0x0102

#define STD_SET_FEATURE_ZERO          0x0300
#define STD_SET_FEATURE_INTERFACE     0x0301
#define STD_SET_FEATURE_ENDPOINT      0x0302

#define STD_SET_ADDRESS               0x0500
#define STD_GET_DESCRIPTOR            0x0680
#define STD_SET_DESCRIPTOR            0x0700
#define STD_GET_CONFIGURATION         0x0880
#define STD_SET_CONFIGURATION         0x0900
#define STD_GET_INTERFACE             0x0A81
#define STD_SET_INTERFACE             0x0B01
#define STD_SYNCH_FRAME               0x0C82

/* CDC Class Specific Request Code */
#define GET_LINE_CODING               0x21A1
#define SET_LINE_CODING               0x2021
#define SET_CONTROL_LINE_STATE        0x2221

// !!!! NOTE: If we need inline a function, then don't set the variables to static.

bool isAsyncRequestFinished = false;
AT91PS_UDP pUdp = AT91C_BASE_UDP;

static uint8_t btConfiguration = 0;
static uint8_t btConnection    = 0;
static uint8_t btReceiveBank   = AT91C_UDP_RX_DATA_BK0;

// -- pre def functions
void AT91F_USB_SendData(AT91PS_UDP pudp, const char *pData, uint32_t length);
void AT91F_USB_SendZlp(AT91PS_UDP pudp);
void AT91F_USB_SendStall(AT91PS_UDP pudp);
void AT91F_CDC_Enumerate(void);
// --
void SetUSBreconnect(int value);
int GetUSBreconnect(void);
void SetUSBconfigured(int value);
int GetUSBconfigured(void);

static const char *getStringDescriptor(uint8_t idx) {
    switch (idx) {
        case 0:
            return StrLanguageCodes;
        case 1:
            return StrManufacturer;
        case 2:
            return StrProduct;
        case 3:
            return StrSerialNumber;
        case MS_OS_DESCRIPTOR_INDEX:
            return StrMS_OSDescriptor;
        default:
            return (NULL);
    }
}

// Bitmap for all status bits in CSR which must be written as 1 to cause no effect
#define REG_NO_EFFECT_1_ALL      AT91C_UDP_RX_DATA_BK0 | AT91C_UDP_RX_DATA_BK1 \
    |AT91C_UDP_STALLSENT   | AT91C_UDP_RXSETUP \
    |AT91C_UDP_TXCOMP

// Clear flags in the UDP_CSR register and waits for synchronization
#define UDP_CLEAR_EP_FLAGS(endpoint, flags) { \
        volatile unsigned int reg; \
        reg = pUdp->UDP_CSR[(endpoint)]; \
        reg |= REG_NO_EFFECT_1_ALL; \
        reg &= ~(flags); \
        pUdp->UDP_CSR[(endpoint)] = reg; \
    }

// reset flags in the UDP_CSR register and waits for synchronization
#define UDP_SET_EP_FLAGS(endpoint, flags) { \
        volatile unsigned int reg; \
        reg = pUdp->UDP_CSR[(endpoint)]; \
        reg |= REG_NO_EFFECT_1_ALL; \
        reg |= (flags); \
        pUdp->UDP_CSR[(endpoint)] = reg; \
    }


typedef struct {
    uint32_t BitRate;
    uint8_t Format;
    uint8_t ParityType;
    uint8_t DataBits;
} AT91S_CDC_LINE_CODING, *AT91PS_CDC_LINE_CODING;

static AT91S_CDC_LINE_CODING line = { // purely informative, actual values don't matter
    USART_BAUD_RATE, // baudrate
    0,               // 1 Stop Bit
    0,               // None Parity
    8                // 8 Data bits
};

#ifndef AS_BOOTROM

// buffer of read_ng apis.
static uint8_t usb_read_ng_buffer[64] = {0};

// Implemented for read_ng
static bool usb_read_ng_link_ready(void) {
    // old: if (usb_check() == false)
    return usb_check(); // reuse 'usb_check()'
}

// Implemented for read_ng
static bool usb_read_ng_data_ready(void) {
    // old: if ((pUdp->UDP_CSR[AT91C_EP_OUT] & bank))
    return (pUdp->UDP_CSR[AT91C_EP_OUT] & btReceiveBank) != 0;
}

// Implemented for read_ng
static uint16_t usb_read_ng_data_available(void) {
    // old: uint16_t available = (((pUdp->UDP_CSR[AT91C_EP_OUT] & AT91C_UDP_RXBYTECNT) >> 16) & 0x7FF);
    return usb_available_length();
}

// Implemented for read_ng
static uint8_t usb_read_ng_data_read(void) {
    return pUdp->UDP_FDR[AT91C_EP_OUT];
}

// Implemented for read_ng
static void usb_read_ng_clear(void) {
    // flip bank
    UDP_CLEAR_EP_FLAGS(AT91C_EP_OUT, btReceiveBank)
    if (btReceiveBank == AT91C_UDP_RX_DATA_BK0) {
        btReceiveBank = AT91C_UDP_RX_DATA_BK1;
    } else {
        btReceiveBank = AT91C_UDP_RX_DATA_BK0;
    }
}

// Instance for 'read_ng' apis
static const usb_read_ng_config_t g_usb_read_ng_config = {
    .is_link_ready    = usb_read_ng_link_ready,
    .is_data_ready    = usb_read_ng_data_ready,
    .get_byte_count   = usb_read_ng_data_available,
    .read_fifo        = usb_read_ng_data_read,
    .clear_ready      = usb_read_ng_clear,
    .buffer           = usb_read_ng_buffer,
    .buffer_size      = sizeof(usb_read_ng_buffer),
    .timeout          = 0x1FFF
};
#endif

/*
 *----------------------------------------------------------------------------
 * \fn    usb_disable
 * \brief This function deactivates the USB device
 *----------------------------------------------------------------------------
*/
void usb_disable(void) {
    // Disconnect the USB device
    AT91C_BASE_PIOA->PIO_ODR = GPIO_USB_PU;

    // Clear all lingering interrupts
    if (pUdp->UDP_ISR & AT91C_UDP_ENDBUSRES) {
        pUdp->UDP_ICR = AT91C_UDP_ENDBUSRES;
    }
}

/*
 *----------------------------------------------------------------------------
 * \fn    usb_enable
 * \brief This function Activates the USB device
 *----------------------------------------------------------------------------
*/
void usb_enable(void) {
    // Set the PLL USB Divider
    AT91C_BASE_CKGR->CKGR_PLLR |= AT91C_CKGR_USBDIV_1 ;

    // Specific Chip USB Initialisation
    // Enables the 48MHz USB clock UDPCK and System Peripheral USB Clock
    AT91C_BASE_PMC->PMC_SCER |= AT91C_PMC_UDP;
    AT91C_BASE_PMC->PMC_PCER = (1 << AT91C_ID_UDP);

    AT91C_BASE_UDP->UDP_FADDR = 0;
    AT91C_BASE_UDP->UDP_GLBSTATE = 0;

    // Enable UDP PullUp (USB_DP_PUP) : enable & Clear of the corresponding PIO
    // Set in PIO mode and Configure in Output
    AT91C_BASE_PIOA->PIO_PER = GPIO_USB_PU; // Set in PIO mode
    AT91C_BASE_PIOA->PIO_OER = GPIO_USB_PU; // Configure as Output

    // Clear for set the Pullup resistor
    AT91C_BASE_PIOA->PIO_CODR = GPIO_USB_PU;

    // Disconnect and reconnect USB controller for 100ms
    usb_disable();

    SpinDelayUs(100 * 1000);
    // Wait for a short while
    //for (volatile size_t i=0; i<0x100000; i++) {};

    // Reconnect USB reconnect
    AT91C_BASE_PIOA->PIO_SODR = GPIO_USB_PU;
    AT91C_BASE_PIOA->PIO_OER = GPIO_USB_PU;

#ifndef AS_BOOTROM
    // setup read_ng implement.
    usb_read_ng_init(&g_usb_read_ng_config);
#endif
}

static int usb_reconnect = 0;
static int usb_configured = 0;
void SetUSBreconnect(int value) {
    usb_reconnect = value;
}
int GetUSBreconnect(void) {
    return usb_reconnect;
}
void SetUSBconfigured(int value) {
    usb_configured = value;
}
int GetUSBconfigured(void) {
    return usb_configured;
}

/*
 *----------------------------------------------------------------------------
 * \fn    usb_check
 * \brief Test if the device is configured and handle enumeration
 *----------------------------------------------------------------------------
*/
bool usb_check(void) {

    /*
    // reconnected ONCE and
    if ( !USB_ATTACHED() ){
        usb_reconnect = 1;
        return false;
    }

    // only one time after USB been disengaged and re-engaged
    if ( USB_ATTACHED() && usb_reconnect == 1 ) {

        if ( usb_configured == 0) {
            usb_disable();
            usb_enable();

            AT91F_CDC_Enumerate();

            usb_configured = 1;
            return false;
        }
    }
    */

    // interrupt status register
    AT91_REG isr = pUdp->UDP_ISR;

    // end of bus reset
    if (isr & AT91C_UDP_ENDBUSRES) {
        pUdp->UDP_ICR = AT91C_UDP_ENDBUSRES;
        // reset all endpoints
        pUdp->UDP_RSTEP  = (unsigned int) - 1;
        pUdp->UDP_RSTEP  = 0;
        // Enable the function
        pUdp->UDP_FADDR = AT91C_UDP_FEN;
        // Configure endpoint 0  (enable control endpoint)
        pUdp->UDP_CSR[AT91C_EP_CONTROL] = (AT91C_UDP_EPEDS | AT91C_UDP_EPTYPE_CTRL);
    } else if (isr & AT91C_UDP_EPINT0) {
        pUdp->UDP_ICR = AT91C_UDP_EPINT0;
        AT91F_CDC_Enumerate();
    }
    /*
    else if (isr & AT91C_UDP_EPINT3 ) {
        pUdp->UDP_ICR = AT91C_UDP_EPINT3;
        AT91F_CDC_Enumerate();
        //pUdp->UDP_ICR |= AT91C_UDP_EPINT3;
    }
    */
    return (btConfiguration) ? true : false;
}

/*
 *----------------------------------------------------------------------------
 * \fn    usb_poll
 * \brief Test if the device link ok and data received.
 *----------------------------------------------------------------------------
*/
bool usb_poll(void) {
    if (usb_check() == false) {
        return false;
    }
    return (pUdp->UDP_CSR[AT91C_EP_OUT] & btReceiveBank);
}

/*
 *----------------------------------------------------------------------------
 * \fn    usb_available_length
 * \brief Get data received length of out endpoint.
 *----------------------------------------------------------------------------
*/
FORCE_INLINE uint16_t usb_available_length(void) {
    return (((pUdp->UDP_CSR[AT91C_EP_OUT] & AT91C_UDP_RXBYTECNT) >> 16) & 0x7FF);
}

/**
    In github PR #129, some users appears to get a false positive from
    usb_poll, which returns true, but the usb_read operation
    still returns 0.
    This check is basically the same as above, but also checks
    that the length available to read is non-zero, thus hopefully fixes the
    bug.
**/
bool usb_poll_validate_length(void) {
    // Reuse 'usb_poll()' implemented.
    if (usb_poll() == false) {
        return false;
    }
    // Why code this: return (((pUdp->UDP_CSR[AT91C_EP_OUT] & AT91C_UDP_RXBYTECNT) >> 16) > 0);
    // For speed? but 'usb_available_length()' is a inline function.
    return (usb_available_length() > 0);
}

/*
 *----------------------------------------------------------------------------
 * \fn    usb_read
 * \brief Read available data from Endpoint 1 OUT (host to device, blocking read.)
 *----------------------------------------------------------------------------
*/
uint32_t usb_read(uint8_t *data, size_t len) {

    if (len == 0) {
        return 0;
    }

    uint8_t bank = btReceiveBank;
    uint16_t packetSize, nbBytesRcv = 0;
    uint16_t time_out = 0;

    while (len)  {
        if (usb_check() == false) {
            break;
        }

        if (pUdp->UDP_CSR[AT91C_EP_OUT] & bank) {

            packetSize = (((pUdp->UDP_CSR[AT91C_EP_OUT] & AT91C_UDP_RXBYTECNT) >> 16) & 0x7FF);
            packetSize = MIN(packetSize, len);
            len -= packetSize;

            while (packetSize--) {
                data[nbBytesRcv++] = pUdp->UDP_FDR[AT91C_EP_OUT];
            }

            // flip bank
            UDP_CLEAR_EP_FLAGS(AT91C_EP_OUT, bank)

            if (bank == AT91C_UDP_RX_DATA_BK0) {
                bank = AT91C_UDP_RX_DATA_BK1;
            } else {
                bank = AT91C_UDP_RX_DATA_BK0;
            }
        }

        if (time_out++ == 0x1FFF) {
            break;
        }
    }

    btReceiveBank = bank;
    return nbBytesRcv;
}

/*
 *----------------------------------------------------------------------------
 * \fn    usb_write
 * \brief Send through endpoint 2 (device to host, blocking write.)
 *----------------------------------------------------------------------------
*/
int usb_write(const uint8_t *data, const size_t len) {

    if (len == 0) {
        return PM3_EINVARG;
    }

    if (usb_check() == false) {
        return PM3_EIO;
    }

    // can we write?
    if ((pUdp->UDP_CSR[AT91C_EP_IN] & AT91C_UDP_TXPKTRDY) != 0) {
        return PM3_EIO;
    }

    size_t length = len;
    uint32_t cpt = 0;

    // send first chunk
    cpt = MIN(length, AT91C_USB_EP_IN_SIZE);
    length -= cpt;
    while (cpt--) {
        pUdp->UDP_FDR[AT91C_EP_IN] = *data++;
    }

    UDP_SET_EP_FLAGS(AT91C_EP_IN, AT91C_UDP_TXPKTRDY);
    while (!(pUdp->UDP_CSR[AT91C_EP_IN] & AT91C_UDP_TXPKTRDY)) {};

    while (length) {
        // Send next chunk
        cpt = MIN(length, AT91C_USB_EP_IN_SIZE);
        length -= cpt;
        while (cpt--) {
            pUdp->UDP_FDR[AT91C_EP_IN] = *data++;
        }

        // Wait for previous chunk to be sent
        // (iceman) when is the bankswapping done?
        while (!(pUdp->UDP_CSR[AT91C_EP_IN] & AT91C_UDP_TXCOMP)) {
            if (usb_check() == false) {
                return PM3_EIO;
            }
        }

        UDP_CLEAR_EP_FLAGS(AT91C_EP_IN, AT91C_UDP_TXCOMP);
        while (pUdp->UDP_CSR[AT91C_EP_IN] & AT91C_UDP_TXCOMP) {};

        UDP_SET_EP_FLAGS(AT91C_EP_IN, AT91C_UDP_TXPKTRDY);
        while (!(pUdp->UDP_CSR[AT91C_EP_IN] & AT91C_UDP_TXPKTRDY)) {};
    }

    // Wait for the end of transfer
    while (!(pUdp->UDP_CSR[AT91C_EP_IN] & AT91C_UDP_TXCOMP)) {
        if (usb_check() == false) {
            return PM3_EIO;
        }
    }

    UDP_CLEAR_EP_FLAGS(AT91C_EP_IN, AT91C_UDP_TXCOMP);
    while (pUdp->UDP_CSR[AT91C_EP_IN] & AT91C_UDP_TXCOMP) {};


    if (len % AT91C_USB_EP_IN_SIZE == 0) {
        // like AT91F_USB_SendZlp(), in non ping-pong mode
        UDP_SET_EP_FLAGS(AT91C_EP_IN, AT91C_UDP_TXPKTRDY);
        while (!(pUdp->UDP_CSR[AT91C_EP_IN] & AT91C_UDP_TXCOMP)) {};

        UDP_CLEAR_EP_FLAGS(AT91C_EP_IN, AT91C_UDP_TXCOMP);
        while (pUdp->UDP_CSR[AT91C_EP_IN] & AT91C_UDP_TXCOMP) {};
    }

    return PM3_SUCCESS;
}

/*
 *----------------------------------------------------------------------------
 * \fn     async_usb_write_start
 * \brief  Start async write process
 * \return PM3_EIO if USB is invalid, PM3_SUCCESS if it is ready for write
 *
 * This function checks if the USB is connected, and wait until the FIFO
 * is ready to be filled.
 *
 * Warning: usb_write() should not be called between
 * async_usb_write_start() and async_usb_write_stop().
 *----------------------------------------------------------------------------
*/
int async_usb_write_start(void) {

    if (usb_check() == false) {
        return PM3_EIO;
    }

    while (pUdp->UDP_CSR[AT91C_EP_IN] & AT91C_UDP_TXPKTRDY) {
        if (usb_check() == false) {
            return PM3_EIO;
        }
    }

    isAsyncRequestFinished = false;
    return PM3_SUCCESS;
}

/*
 *----------------------------------------------------------------------------
 * \fn    async_usb_write_pushByte
 * \brief Push one byte to the FIFO of IN endpoint (time-critical)
 *
 * This function simply push a byte to the FIFO of IN endpoint.
 * The FIFO size is AT91C_USB_EP_IN_SIZE. Make sure this function is not called
 * over AT91C_USB_EP_IN_SIZE times between each async_usb_write_requestWrite().
 *----------------------------------------------------------------------------
*/
inline void async_usb_write_pushByte(uint8_t data) {
    pUdp->UDP_FDR[AT91C_EP_IN] = data;
    isAsyncRequestFinished = false;
}

/*
 *----------------------------------------------------------------------------
 * \fn     async_usb_write_requestWrite
 * \brief  Request a write operation (time-critical)
 * \return false if the last write request is not finished, true if success
 *
 * This function requests a write operation from FIFO to the USB bus,
 * and switch the internal banks of FIFO. It doesn't wait for the end of
 * transmission from FIFO to the USB bus.
 *
 * Note: This function doesn't check if the usb is valid, as it is
 * time-critical.
 *----------------------------------------------------------------------------
*/
inline bool async_usb_write_requestWrite(void) {

    // check if last request is finished
    if (pUdp->UDP_CSR[AT91C_EP_IN] & AT91C_UDP_TXPKTRDY) {
        return false;
    }

    // clear transmission completed flag
    UDP_CLEAR_EP_FLAGS(AT91C_EP_IN, AT91C_UDP_TXCOMP);
    while (pUdp->UDP_CSR[AT91C_EP_IN] & AT91C_UDP_TXCOMP) {};

    // start of transmission
    UDP_SET_EP_FLAGS(AT91C_EP_IN, AT91C_UDP_TXPKTRDY);

    // hack: no need to wait if UDP_CSR and UDP_FDR are not used immediately.
    // while (!(pUdp->UDP_CSR[AT91C_EP_IN] & AT91C_UDP_TXPKTRDY)) {};
    isAsyncRequestFinished = true;
    return true;
}

/*
 *----------------------------------------------------------------------------
 * \fn     async_usb_write_stop
 * \brief  Stop async write process
 * \return PM3_EIO if USB is invalid, PM3_SUCCESS if data is written
 *
 * This function makes sure the data left in the FIFO is written to the
 * USB bus.
 *
 * Warning: usb_write() should not be called between
 * async_usb_write_start() and async_usb_write_stop().
 *----------------------------------------------------------------------------
*/
int async_usb_write_stop(void) {
    // Wait for the end of transfer
    while (pUdp->UDP_CSR[AT91C_EP_IN] & AT91C_UDP_TXPKTRDY) {
        if (usb_check() == false) {
            return PM3_EIO;
        }
    }

    // clear transmission completed flag
    UDP_CLEAR_EP_FLAGS(AT91C_EP_IN, AT91C_UDP_TXCOMP);
    while (pUdp->UDP_CSR[AT91C_EP_IN] & AT91C_UDP_TXCOMP) {};

    // FIFO is not empty, request a write in non-ping-pong mode
    if (isAsyncRequestFinished == false) {
        UDP_SET_EP_FLAGS(AT91C_EP_IN, AT91C_UDP_TXPKTRDY);

        while (!(pUdp->UDP_CSR[AT91C_EP_IN] & AT91C_UDP_TXCOMP)) {
            if (usb_check() == false) {
                return PM3_EIO;
            }
        }

        UDP_CLEAR_EP_FLAGS(AT91C_EP_IN, AT91C_UDP_TXCOMP);
        while (pUdp->UDP_CSR[AT91C_EP_IN] & AT91C_UDP_TXCOMP) {};
    }
    return PM3_SUCCESS;
}

/*
 *----------------------------------------------------------------------------
 * \fn    AT91F_USB_SendData
 * \brief Send Data through the control endpoint
 *----------------------------------------------------------------------------
*/
void AT91F_USB_SendData(AT91PS_UDP pudp, const char *pData, uint32_t length) {
    AT91_REG csr;

    do {
        uint32_t cpt = MIN(length, AT91C_USB_EP_CONTROL_SIZE);
        length -= cpt;

        while (cpt--) {
            pudp->UDP_FDR[AT91C_EP_CONTROL] = *pData++;
        }

        if (pudp->UDP_CSR[AT91C_EP_CONTROL] & AT91C_UDP_TXCOMP) {
            UDP_CLEAR_EP_FLAGS(AT91C_EP_CONTROL, AT91C_UDP_TXCOMP);
            while (pudp->UDP_CSR[AT91C_EP_CONTROL] & AT91C_UDP_TXCOMP) {};
        }

        UDP_SET_EP_FLAGS(AT91C_EP_CONTROL, AT91C_UDP_TXPKTRDY);

        do {
            csr = pudp->UDP_CSR[AT91C_EP_CONTROL];
            // Data IN stage has been stopped by a status OUT
            if (csr & AT91C_UDP_RX_DATA_BK0) {

                UDP_CLEAR_EP_FLAGS(AT91C_EP_CONTROL, AT91C_UDP_RX_DATA_BK0)
                return;
            }
        } while (!(csr & AT91C_UDP_TXCOMP));

    } while (length);

    if (pudp->UDP_CSR[AT91C_EP_CONTROL] & AT91C_UDP_TXCOMP) {
        UDP_CLEAR_EP_FLAGS(AT91C_EP_CONTROL, AT91C_UDP_TXCOMP);
        while (pudp->UDP_CSR[AT91C_EP_CONTROL] & AT91C_UDP_TXCOMP) {};
    }
}

//*----------------------------------------------------------------------------
//* \fn    AT91F_USB_SendZlp
//* \brief Send zero length packet through the control endpoint
//*----------------------------------------------------------------------------
void AT91F_USB_SendZlp(AT91PS_UDP pudp) {
    UDP_SET_EP_FLAGS(AT91C_EP_CONTROL, AT91C_UDP_TXPKTRDY);
    // for non ping-pong operation, wait until the FIFO is released
    // the flag for FIFO released is AT91C_UDP_TXCOMP rather than AT91C_UDP_TXPKTRDY
    while (!(pudp->UDP_CSR[AT91C_EP_CONTROL] & AT91C_UDP_TXCOMP)) {};
    UDP_CLEAR_EP_FLAGS(AT91C_EP_CONTROL, AT91C_UDP_TXCOMP);
    while (pudp->UDP_CSR[AT91C_EP_CONTROL] & AT91C_UDP_TXCOMP) {};
}

//*----------------------------------------------------------------------------
//* \fn    AT91F_USB_SendStall
//* \brief Stall the control endpoint
//*----------------------------------------------------------------------------
void AT91F_USB_SendStall(AT91PS_UDP pudp) {
    UDP_SET_EP_FLAGS(AT91C_EP_CONTROL, AT91C_UDP_FORCESTALL);
    while (!(pudp->UDP_CSR[AT91C_EP_CONTROL] & AT91C_UDP_ISOERROR)) {};
    UDP_CLEAR_EP_FLAGS(AT91C_EP_CONTROL, (AT91C_UDP_FORCESTALL | AT91C_UDP_ISOERROR));
    while (pudp->UDP_CSR[AT91C_EP_CONTROL] & (AT91C_UDP_FORCESTALL | AT91C_UDP_ISOERROR)) {};
}

//*----------------------------------------------------------------------------
//* \fn    AT91F_CDC_Enumerate
//* \brief This function is a callback invoked when a SETUP packet is received
//* problem:
//* 1. this is for USB endpoint0.  the control endpoint.
//* 2. mixed with CDC ACM endpoint3 , interrupt, control endpoint
//*----------------------------------------------------------------------------
void AT91F_CDC_Enumerate(void) {
    uint8_t bmRequestType, bRequest;
    uint16_t wValue, wIndex, wLength, wStatus;

    if (!(pUdp->UDP_CSR[AT91C_EP_CONTROL] & AT91C_UDP_RXSETUP)) {
        return;
    }

    bmRequestType = pUdp->UDP_FDR[AT91C_EP_CONTROL];
    bRequest      = pUdp->UDP_FDR[AT91C_EP_CONTROL];
    wValue        = (pUdp->UDP_FDR[AT91C_EP_CONTROL] & 0xFF);
    wValue       |= (pUdp->UDP_FDR[AT91C_EP_CONTROL] << 8);
    wIndex        = (pUdp->UDP_FDR[AT91C_EP_CONTROL] & 0xFF);
    wIndex       |= (pUdp->UDP_FDR[AT91C_EP_CONTROL] << 8);
    wLength       = (pUdp->UDP_FDR[AT91C_EP_CONTROL] & 0xFF);
    wLength      |= (pUdp->UDP_FDR[AT91C_EP_CONTROL] << 8);

    if (bmRequestType & 0x80) {        // Data Phase Transfer Direction Device to Host
        UDP_SET_EP_FLAGS(AT91C_EP_CONTROL, AT91C_UDP_DIR);
        while (!(pUdp->UDP_CSR[AT91C_EP_CONTROL] & AT91C_UDP_DIR)) {};
    }
    UDP_CLEAR_EP_FLAGS(AT91C_EP_CONTROL, AT91C_UDP_RXSETUP);
    while ((pUdp->UDP_CSR[AT91C_EP_CONTROL] & AT91C_UDP_RXSETUP)) {};

    /*
    if ( bRequest == MS_VENDOR_CODE) {
        if ( bmRequestType == MS_WCID_GET_DESCRIPTOR ) { // C0
            if ( wIndex == MS_EXTENDED_COMPAT_ID ) {  // 4
                //AT91F_USB_SendData(pUdp, CompatIDFeatureDescriptor, MIN(sizeof(CompatIDFeatureDescriptor), wLength));
                //return;
            }
        }

        if ( bmRequestType == MS_WCID_GET_FEATURE_DESCRIPTOR ) {  //C1
            // if ( wIndex == MS_EXTENDED_PROPERTIES ) { // 5  - winusb bug with wIndex == interface index,  so I just send it always)
                //AT91F_USB_SendData(pUdp, OSprop, MIN(sizeof(OSprop), wLength));
                //return;
            // }
        }
    }
    */

    // Handle supported standard device request Cf Table 9-3 in USB specification Rev 1.1
    switch ((bRequest << 8) | bmRequestType) {
        case STD_GET_DESCRIPTOR: {

            if (wValue == 0x100) {        // Return Device Descriptor
                AT91F_USB_SendData(pUdp, devDescriptor, MIN(sizeof(devDescriptor), wLength));
            } else if (wValue == 0x200) {   // Return Configuration Descriptor
                AT91F_USB_SendData(pUdp, cfgDescriptor, MIN(sizeof(cfgDescriptor), wLength));
            } else if ((wValue & 0xF00) == 0xF00) { // Return BOS Descriptor
                AT91F_USB_SendData(pUdp, bosDescriptor, MIN(sizeof(bosDescriptor), wLength));
            } else if ((wValue & 0x300) == 0x300) {  // Return String Descriptor

                const char *strDescriptor = getStringDescriptor(wValue & 0xff);
                if (strDescriptor != NULL) {
                    AT91F_USB_SendData(pUdp, strDescriptor, MIN(strDescriptor[0], wLength));
                } else {
                    AT91F_USB_SendStall(pUdp);
                }
            } else {
                AT91F_USB_SendStall(pUdp);
            }
        }
        break;
        case STD_SET_ADDRESS:
            AT91F_USB_SendZlp(pUdp);
            pUdp->UDP_FADDR = (AT91C_UDP_FEN | (wValue & 0x7F));
            pUdp->UDP_GLBSTATE  = (wValue) ? AT91C_UDP_FADDEN : 0;
            break;
        case STD_SET_CONFIGURATION:

            /*
            *   Set or clear the device "configured" state.
            *   The LSB of wValue is the "Configuration Number". If this value is non-zero,
            *   it should be the same number as defined in the Configuration Descriptor;
            *   otherwise an error must have occurred.
            *   This device has only one configuration and its Config Number is CONF_NB (= 1).
            */
            AT91F_USB_SendZlp(pUdp);
            btConfiguration = wValue;
            pUdp->UDP_GLBSTATE  = (wValue) ? AT91C_UDP_CONFG : AT91C_UDP_FADDEN;

            // make sure we are not stalled
            /*
            UDP_CLEAR_EP_FLAGS(AT91C_EP_OUT   , AT91C_UDP_FORCESTALL);
            UDP_CLEAR_EP_FLAGS(AT91C_EP_IN    , AT91C_UDP_FORCESTALL);
            UDP_CLEAR_EP_FLAGS(AT91C_EP_NOTIFY, AT91C_UDP_FORCESTALL);
            */

            // enable endpoints
            pUdp->UDP_CSR[AT91C_EP_OUT]    = (wValue) ? (AT91C_UDP_EPEDS | AT91C_UDP_EPTYPE_BULK_OUT) : 0;
            pUdp->UDP_CSR[AT91C_EP_IN]     = (wValue) ? (AT91C_UDP_EPEDS | AT91C_UDP_EPTYPE_BULK_IN)  : 0;
            pUdp->UDP_CSR[AT91C_EP_NOTIFY] = (wValue) ? (AT91C_UDP_EPEDS | AT91C_UDP_EPTYPE_INT_IN)   : 0;
            break;
        case STD_GET_CONFIGURATION:
            AT91F_USB_SendData(pUdp, (char *) & (btConfiguration), sizeof(btConfiguration));
            break;
        case STD_GET_STATUS_ZERO:
            wStatus = 0;   // Device is Bus powered, remote wakeup disabled
            AT91F_USB_SendData(pUdp, (char *) &wStatus, sizeof(wStatus));
            break;
        case STD_GET_STATUS_INTERFACE:
            wStatus = 0;   // reserved for future use
            AT91F_USB_SendData(pUdp, (char *) &wStatus, sizeof(wStatus));
            break;
        case STD_GET_STATUS_ENDPOINT:
            wStatus = 0;
            wIndex &= 0x0F;
            if ((pUdp->UDP_GLBSTATE & AT91C_UDP_CONFG) && (wIndex <= AT91C_EP_NOTIFY)) {
                wStatus = (pUdp->UDP_CSR[wIndex] & AT91C_UDP_EPEDS) ? 0 : 1;
                AT91F_USB_SendData(pUdp, (char *) &wStatus, sizeof(wStatus));
            } else if ((pUdp->UDP_GLBSTATE & AT91C_UDP_FADDEN) && (wIndex == AT91C_EP_CONTROL)) {
                wStatus = (pUdp->UDP_CSR[wIndex] & AT91C_UDP_EPEDS) ? 0 : 1;
                AT91F_USB_SendData(pUdp, (char *) &wStatus, sizeof(wStatus));
            } else {
                AT91F_USB_SendStall(pUdp);
            }
            break;
        case STD_SET_FEATURE_ZERO:
            AT91F_USB_SendStall(pUdp);
            break;
        case STD_SET_FEATURE_INTERFACE:
            AT91F_USB_SendZlp(pUdp);
            break;
        case STD_SET_FEATURE_ENDPOINT:
            wIndex &= 0x0F;
            if ((wValue == 0) && (wIndex >= AT91C_EP_OUT) && (wIndex <= AT91C_EP_NOTIFY)) {
                pUdp->UDP_CSR[wIndex] = 0;
                AT91F_USB_SendZlp(pUdp);
            } else {
                AT91F_USB_SendStall(pUdp);
            }
            break;
        case STD_CLEAR_FEATURE_ZERO:
            AT91F_USB_SendStall(pUdp);
            break;
        case STD_CLEAR_FEATURE_INTERFACE:
            AT91F_USB_SendZlp(pUdp);
            break;
        case STD_CLEAR_FEATURE_ENDPOINT:
            wIndex &= 0x0F;
            if ((wValue == 0) && (wIndex >= AT91C_EP_OUT) && (wIndex <= AT91C_EP_NOTIFY)) {

                if (wIndex == AT91C_EP_OUT) {
                    pUdp->UDP_CSR[AT91C_EP_OUT] = (AT91C_UDP_EPEDS | AT91C_UDP_EPTYPE_BULK_OUT);
                } else if (wIndex == AT91C_EP_IN) {
                    pUdp->UDP_CSR[AT91C_EP_IN] = (AT91C_UDP_EPEDS | AT91C_UDP_EPTYPE_BULK_IN);
                } else if (wIndex == AT91C_EP_NOTIFY) {
                    pUdp->UDP_CSR[AT91C_EP_NOTIFY] = (AT91C_UDP_EPEDS | AT91C_UDP_EPTYPE_INT_IN);
                }

                AT91F_USB_SendZlp(pUdp);
            } else {
                AT91F_USB_SendStall(pUdp);
            }
            break;

        // handle CDC class requests
        case SET_LINE_CODING: {
            /*
                uint8_t i;
                for ( i = 0 ; i < 7 ; i++ )  {
                    ((uint8_t*)&line)[i] =  pUdp->UDP_FDR[AT91C_EP_CONTROL];
                }  */
            // ignore SET_LINE_CODING...
            while (!(pUdp->UDP_CSR[AT91C_EP_CONTROL] & AT91C_UDP_RX_DATA_BK0)) {};
            UDP_CLEAR_EP_FLAGS(AT91C_EP_CONTROL, AT91C_UDP_RX_DATA_BK0);
            AT91F_USB_SendZlp(pUdp);
            break;
        }
        case GET_LINE_CODING:
            AT91F_USB_SendData(pUdp, (char *) &line, MIN(sizeof(line), wLength));
            break;
        case SET_CONTROL_LINE_STATE:
            btConnection = wValue;
            AT91F_USB_SendZlp(pUdp);
            break;
        default:
            AT91F_USB_SendStall(pUdp);
            break;
    }
}

//*----------------------------------------------------------------------------
//* \fn    usb_get_ep_size
//* \brief This function can get usb endpoint buffer size
//*----------------------------------------------------------------------------
void usb_get_ep_size(uint32_t *epCtl, uint32_t *epIn, uint32_t *epOut) {
    if (epCtl) *epCtl = AT91C_USB_EP_CONTROL_SIZE;
    if (epIn) *epIn = AT91C_USB_EP_IN_SIZE;
    if (epOut) *epOut = AT91C_USB_EP_OUT_SIZE;
}
