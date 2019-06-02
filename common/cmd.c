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

// Flags to tell where to add CRC on sent replies
bool reply_with_crc_on_usb = false;
bool reply_with_crc_on_fpc = true;
// "Session" flag, to tell via which interface next msgs should be sent: USB or FPC USART
bool reply_via_fpc = false;
bool reply_via_usb = false;

int reply_old(uint64_t cmd, uint64_t arg0, uint64_t arg1, uint64_t arg2, void *data, size_t len) {
    PacketResponseOLD txcmd;

    for (size_t i = 0; i < sizeof(PacketResponseOLD); i++)
        ((uint8_t *)&txcmd)[i] = 0x00;

    // Compose the outgoing command frame
    txcmd.cmd = cmd;
    txcmd.arg[0] = arg0;
    txcmd.arg[1] = arg1;
    txcmd.arg[2] = arg2;

    // Add the (optional) content to the frame, with a maximum size of PM3_CMD_DATA_SIZE
    if (data && len) {
        len = MIN(len, PM3_CMD_DATA_SIZE);
        for (size_t i = 0; i < len; i++) {
            txcmd.d.asBytes[i] = ((uint8_t *)data)[i];
        }
    }

    int resultfpc = PM3_EUNDEF;
    int resultusb = PM3_EUNDEF;
    // Send frame and make sure all bytes are transmitted

    if (reply_via_usb) {
        resultusb = usb_write((uint8_t *)&txcmd, sizeof(PacketResponseOLD));
    }

    if (reply_via_fpc) {
#ifdef WITH_FPC_USART_HOST
        resultfpc = usart_writebuffer_sync((uint8_t *)&txcmd, sizeof(PacketResponseOLD));
#else
        return PM3_EDEVNOTSUPP;
#endif
    }
    // we got two results, let's prioritize the faulty one and USB over FPC.
    if (reply_via_usb && (resultusb != PM3_SUCCESS)) return resultusb;
    if (reply_via_fpc && (resultfpc != PM3_SUCCESS)) return resultfpc;
    return PM3_SUCCESS;
}

static int reply_ng_internal(uint16_t cmd, int16_t status, uint8_t *data, size_t len, bool ng) {
    PacketResponseNGRaw txBufferNG;
    size_t txBufferNGLen;

    // Compose the outgoing command frame
    txBufferNG.pre.magic = RESPONSENG_PREAMBLE_MAGIC;
    txBufferNG.pre.cmd = cmd;
    txBufferNG.pre.status = status;
    txBufferNG.pre.ng = ng;
    if (len > PM3_CMD_DATA_SIZE) {
        len = PM3_CMD_DATA_SIZE;
        // overwrite status
        txBufferNG.pre.status = PM3_EOVFLOW;
    }
    txBufferNG.pre.length = len;

    // Add the (optional) content to the frame, with a maximum size of PM3_CMD_DATA_SIZE
    if (data && len) {
        for (size_t i = 0; i < len; i++) {
            txBufferNG.data[i] = data[i];
        }
    }

    PacketResponseNGPostamble *tx_post = (PacketResponseNGPostamble *)((uint8_t *)&txBufferNG + sizeof(PacketResponseNGPreamble) + len);
    // Note: if we send to both FPC & USB, we'll set CRC for both if any of them require CRC
    if ((reply_via_fpc && reply_with_crc_on_fpc) || ((reply_via_usb) && reply_with_crc_on_usb)) {
        uint8_t first, second;
        compute_crc(CRC_14443_A, (uint8_t *)&txBufferNG, sizeof(PacketResponseNGPreamble) + len, &first, &second);
        tx_post->crc = (first << 8) + second;
    } else {
        tx_post->crc = RESPONSENG_POSTAMBLE_MAGIC;
    }
    txBufferNGLen = sizeof(PacketResponseNGPreamble) + len + sizeof(PacketResponseNGPostamble);

    int resultfpc = PM3_EUNDEF;
    int resultusb = PM3_EUNDEF;
    // Send frame and make sure all bytes are transmitted

    if (reply_via_usb) {
        resultusb = usb_write((uint8_t *)&txBufferNG, txBufferNGLen);
    }
    if (reply_via_fpc) {
#ifdef WITH_FPC_USART_HOST
        resultfpc = usart_writebuffer_sync((uint8_t *)&txBufferNG, txBufferNGLen);
#else
        return PM3_EDEVNOTSUPP;
#endif
    }
    // we got two results, let's prioritize the faulty one and USB over FPC.
    if (reply_via_usb && (resultusb != PM3_SUCCESS)) return resultusb;
    if (reply_via_fpc && (resultfpc != PM3_SUCCESS)) return resultfpc;
    return PM3_SUCCESS;
}

int reply_ng(uint16_t cmd, int16_t status, uint8_t *data, size_t len) {
    return reply_ng_internal(cmd, status, data, len, true);
}

int reply_mix(uint64_t cmd, uint64_t arg0, uint64_t arg1, uint64_t arg2, void *data, size_t len) {
    uint16_t status = PM3_SUCCESS;
    uint64_t arg[3] = {arg0, arg1, arg2};
    if (len > PM3_CMD_DATA_SIZE - sizeof(arg)) {
        len = PM3_CMD_DATA_SIZE - sizeof(arg);
        status = PM3_EOVFLOW;
    }
    uint8_t cmddata[PM3_CMD_DATA_SIZE];
    memcpy(cmddata, arg, sizeof(arg));
    if (len && data)
        memcpy(cmddata + sizeof(arg), data, len);

    return reply_ng_internal(cmd, status, cmddata, len + sizeof(arg), false);
}

static int receive_ng_internal(PacketCommandNG *rx, uint32_t read_ng(uint8_t *data, size_t len), bool usb, bool fpc) {
    PacketCommandNGRaw rx_raw;
    size_t bytes = read_ng((uint8_t *)&rx_raw.pre, sizeof(PacketCommandNGPreamble));

    if (bytes == 0)
        return PM3_ENODATA;

    if (bytes != sizeof(PacketCommandNGPreamble))
        return PM3_EIO;

    rx->magic = rx_raw.pre.magic;
    rx->ng = rx_raw.pre.ng;
    uint16_t length = rx_raw.pre.length;
    rx->cmd = rx_raw.pre.cmd;

    if (rx->magic == COMMANDNG_PREAMBLE_MAGIC) { // New style NG command
        if (length > PM3_CMD_DATA_SIZE)
            return PM3_EOVFLOW;

        // Get the core and variable length payload
        bytes = read_ng((uint8_t *)&rx_raw.data, length);
        if (bytes != length)
            return PM3_EIO;

        if (rx->ng) {
            memcpy(rx->data.asBytes, rx_raw.data, length);
            rx->length = length;
        } else {
            uint64_t arg[3];
            if (length < sizeof(arg))
                return PM3_EIO;

            memcpy(arg, rx_raw.data, sizeof(arg));
            rx->oldarg[0] = arg[0];
            rx->oldarg[1] = arg[1];
            rx->oldarg[2] = arg[2];
            memcpy(rx->data.asBytes, rx_raw.data + sizeof(arg), length - sizeof(arg));
            rx->length = length - sizeof(arg);
        }
        // Get the postamble
        bytes = read_ng((uint8_t *)&rx_raw.foopost, sizeof(PacketCommandNGPostamble));
        if (bytes != sizeof(PacketCommandNGPostamble))
            return PM3_EIO;

        // Check CRC, accept MAGIC as placeholder
        rx->crc = rx_raw.foopost.crc;
        if (rx->crc != COMMANDNG_POSTAMBLE_MAGIC) {
            uint8_t first, second;
            compute_crc(CRC_14443_A, (uint8_t *)&rx_raw, sizeof(PacketCommandNGPreamble) + length, &first, &second);
            if ((first << 8) + second != rx->crc)
                return PM3_EIO;
        }
        reply_via_usb = usb;
        reply_via_fpc = fpc;
    } else {                               // Old style command
        PacketCommandOLD rx_old;
        memcpy(&rx_old, &rx_raw.pre, sizeof(PacketCommandNGPreamble));
        bytes = read_ng(((uint8_t *)&rx_old) + sizeof(PacketCommandNGPreamble), sizeof(PacketCommandOLD) - sizeof(PacketCommandNGPreamble));
        if (bytes != sizeof(PacketCommandOLD) - sizeof(PacketCommandNGPreamble))
            return PM3_EIO;

        reply_via_usb = usb;
        reply_via_fpc = fpc;
        rx->ng = false;
        rx->magic = 0;
        rx->crc = 0;
        rx->cmd = rx_old.cmd;
        rx->oldarg[0] = rx_old.arg[0];
        rx->oldarg[1] = rx_old.arg[1];
        rx->oldarg[2] = rx_old.arg[2];
        rx->length = PM3_CMD_DATA_SIZE;
        memcpy(&rx->data, &rx_old.d.asBytes, rx->length);
    }
    return PM3_SUCCESS;
}

int receive_ng(PacketCommandNG *rx) {

    // Check if there is a packet available
    if (usb_poll_validate_length())
        return receive_ng_internal(rx, usb_read_ng, true, false);

#ifdef WITH_FPC_USART_HOST
    // Check if there is a FPC packet available
    if (usart_rxdata_available() > 0)
        return receive_ng_internal(rx, usart_read_ng, false, true);
#endif
    return PM3_ENODATA;
}
