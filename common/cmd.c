/*
 * Proxmark send and receive commands
 *
 * Copyright (c) 2012, Roel Verdult
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holders nor the
 * names of its contributors may be used to endorse or promote products
 * derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * @file cmd.c
 * @brief
 */
#include "cmd.h"
#include "crc16.h"

#ifdef WITH_FPC_HOST
// "Session" flag, to tell via which interface next msgs should be sent: USB or FPC USART
bool reply_via_fpc = false;

extern void Dbprintf(const char *fmt, ...);
#define Dbprintf_usb(...) {\
        reply_via_fpc = false;\
        Dbprintf(__VA_ARGS__);\
        reply_via_fpc = true;}
#endif

uint8_t reply_old(uint64_t cmd, uint64_t arg0, uint64_t arg1, uint64_t arg2, void *data, size_t len) {
    PacketResponseOLD txcmd;

    for (size_t i = 0; i < sizeof(PacketResponseOLD); i++)
        ((uint8_t *)&txcmd)[i] = 0x00;

    // Compose the outgoing command frame
    txcmd.cmd = cmd;
    txcmd.arg[0] = arg0;
    txcmd.arg[1] = arg1;
    txcmd.arg[2] = arg2;

    // Add the (optional) content to the frame, with a maximum size of USB_CMD_DATA_SIZE
    if (data && len) {
        len = MIN(len, USB_CMD_DATA_SIZE);
        for (size_t i = 0; i < len; i++) {
            txcmd.d.asBytes[i] = ((uint8_t *)data)[i];
        }
    }

    uint32_t sendlen = 0;
    // Send frame and make sure all bytes are transmitted

#ifdef WITH_FPC_HOST
    if (reply_via_fpc) {
        sendlen = usart_writebuffer((uint8_t *)&txcmd, sizeof(PacketResponseOLD));
//        Dbprintf_usb("Sent %i bytes over usart", len);
    } else {
        sendlen = usb_write((uint8_t *)&txcmd, sizeof(PacketResponseOLD));
    }
#else
    sendlen = usb_write((uint8_t *)&txcmd, sizeof(PacketResponseOLD));
#endif

    return sendlen;
}

uint8_t reply_ng(uint16_t cmd, int16_t status, uint8_t *data, size_t len) {
    PacketResponseNGRaw txBufferNG;
    size_t txBufferNGLen;
//    for (size_t i = 0; i < sizeof(txBufferNG); i++)
//        ((uint8_t *)&txBufferNG)[i] = 0x00;

    // Compose the outgoing command frame
    txBufferNG.pre.magic = USB_REPLYNG_PREAMBLE_MAGIC;
    txBufferNG.pre.cmd = cmd;
    txBufferNG.pre.status = status;
    if (len > USB_CMD_DATA_SIZE) {
        len = USB_CMD_DATA_SIZE;
        // overwrite status
        txBufferNG.pre.status = PM3_EOVFLOW;
    }
    txBufferNG.pre.length = len;

    // Add the (optional) content to the frame, with a maximum size of USB_CMD_DATA_SIZE
    if (data && len) {
        for (size_t i = 0; i < len; i++) {
            txBufferNG.data[i] = data[i];
        }
    }

    uint8_t first, second;
    compute_crc(CRC_14443_A, (uint8_t *)&txBufferNG, sizeof(PacketResponseNGPreamble) + len, &first, &second);

    PacketResponseNGPostamble *tx_post = (PacketResponseNGPostamble *)((uint8_t *)&txBufferNG + sizeof(PacketResponseNGPreamble) + len);
    tx_post->crc = (first << 8) + second;
    txBufferNGLen = sizeof(PacketResponseNGPreamble) + len + sizeof(PacketResponseNGPostamble);

    uint32_t sendlen = 0;
    // Send frame and make sure all bytes are transmitted

#ifdef WITH_FPC_HOST
    if (reply_via_fpc) {
        sendlen = usart_writebuffer((uint8_t *)&txBufferNG, txBufferNGLen);
//        Dbprintf_usb("Sent %i bytes over usart", len);
    } else {
        sendlen = usb_write((uint8_t *)&txBufferNG, txBufferNGLen);
    }
#else
    sendlen = usb_write((uint8_t *)&txBufferNG, txBufferNGLen);
#endif

    return sendlen;
}

int16_t receive_ng(PacketCommandNG *rx) {
    PacketCommandNGRaw rx_raw;
    size_t bytes = usb_read_ng((uint8_t *)&rx_raw.pre, sizeof(PacketCommandNGPreamble));
    if (bytes != sizeof(PacketCommandNGPreamble))
        return PM3_EIO;
    rx->magic = rx_raw.pre.magic;
    rx->length = rx_raw.pre.length;
    rx->cmd = rx_raw.pre.cmd;
    if (rx->magic == USB_COMMANDNG_PREAMBLE_MAGIC) { // New style NG command
        if (rx->length > USB_CMD_DATA_SIZE)
            return PM3_EOVFLOW;
        // Get the core and variable length payload
        bytes = usb_read_ng((uint8_t *)&rx_raw.data, rx->length);
        if (bytes != rx->length)
            return PM3_EIO;
        memcpy(rx->data.asBytes, rx_raw.data, rx->length);
        // Get the postamble
        bytes = usb_read_ng((uint8_t *)&rx_raw.foopost, sizeof(PacketCommandNGPostamble));
        if (bytes != sizeof(PacketCommandNGPostamble))
            return PM3_EIO;
        // Check CRC
        rx->crc = rx_raw.foopost.crc;
        uint8_t first, second;
        compute_crc(CRC_14443_A, (uint8_t *)&rx_raw, sizeof(PacketCommandNGPreamble) + rx->length, &first, &second);
        if ((first << 8) + second != rx->crc)
            return PM3_EIO;
#ifdef WITH_FPC_HOST
        reply_via_fpc = false;
#endif
        rx->ng = true;
    } else {                               // Old style command
        PacketCommandOLD rx_old;
        memcpy(&rx_old, &rx_raw.pre, sizeof(PacketCommandNGPreamble));
        bytes = usb_read_ng(((uint8_t *)&rx_old) + sizeof(PacketCommandNGPreamble), sizeof(PacketCommandOLD) - sizeof(PacketCommandNGPreamble));
        if (bytes != sizeof(PacketCommandOLD) - sizeof(PacketCommandNGPreamble))
            return PM3_EIO;
#ifdef WITH_FPC_HOST
        reply_via_fpc = false;
#endif
        rx->ng = false;
        rx->magic = 0;
        rx->crc = 0;
        rx->cmd = rx_old.cmd;
        rx->oldarg[0] = rx_old.arg[0];
        rx->oldarg[1] = rx_old.arg[1];
        rx->oldarg[2] = rx_old.arg[2];
        rx->length = USB_CMD_DATA_SIZE;
        memcpy(&rx->data, &rx_old.d.asBytes, rx->length);
    }
    return PM3_SUCCESS;
}
