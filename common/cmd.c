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

uint8_t cmd_send(uint64_t cmd, uint64_t arg0, uint64_t arg1, uint64_t arg2, void *data, size_t len) {
    UsbCommand txcmd;

    for (size_t i = 0; i < sizeof(UsbCommand); i++)
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
        sendlen = usart_writebuffer((uint8_t *)&txcmd, sizeof(UsbCommand));
//        Dbprintf_usb("Sent %i bytes over usart", len);
    } else {
        sendlen = usb_write((uint8_t *)&txcmd, sizeof(UsbCommand));
    }
#else
    sendlen = usb_write((uint8_t *)&txcmd, sizeof(UsbCommand));
#endif

    return sendlen;
}

uint8_t reply_ng(uint16_t cmd, int16_t status, uint8_t *data, size_t len) {
    uint8_t txBufferNG[USB_REPLYNG_MAXLEN];
    size_t txBufferNGLen;
//    for (size_t i = 0; i < sizeof(txBufferNG); i++)
//        ((uint8_t *)&txBufferNG)[i] = 0x00;

    // Compose the outgoing command frame
    UsbReplyNGPreamble *tx_pre = (UsbReplyNGPreamble *)txBufferNG;
    tx_pre->magic = USB_REPLYNG_PREAMBLE_MAGIC;
    tx_pre->cmd = cmd;
    tx_pre->status = status;
    if (len > USB_DATANG_SIZE) {
        len = USB_DATANG_SIZE;
        // overwrite status
        tx_pre->status = PM3_EOVFLOW;
    }
    tx_pre->length = len;
    uint8_t *tx_data = txBufferNG + sizeof(UsbReplyNGPreamble);
    UsbReplyNGPostamble *tx_post = (UsbReplyNGPostamble *)(txBufferNG + sizeof(UsbReplyNGPreamble) + len);

    // Add the (optional) content to the frame, with a maximum size of USB_DATANG_SIZE
    if (data && len) {
        for (size_t i = 0; i < len; i++) {
            tx_data[i] = data[i];
        }
    }

    uint8_t first, second;
    compute_crc(CRC_14443_A, txBufferNG, sizeof(UsbReplyNGPreamble) + len, &first, &second);
    tx_post->crc = (first << 8) + second;
    txBufferNGLen = sizeof(UsbReplyNGPreamble) + len + sizeof(UsbReplyNGPostamble);


    uint32_t sendlen = 0;
    // Send frame and make sure all bytes are transmitted

#ifdef WITH_FPC_HOST
    if (reply_via_fpc) {
        sendlen = usart_writebuffer(txBufferNG, txBufferNGLen);
//        Dbprintf_usb("Sent %i bytes over usart", len);
    } else {
        sendlen = usb_write(txBufferNG, txBufferNGLen);
    }
#else
    sendlen = usb_write(txBufferNG, txBufferNGLen);
#endif

    return sendlen;
}
