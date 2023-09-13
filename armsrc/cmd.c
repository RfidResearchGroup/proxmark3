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
#include "cmd.h"
#include "usb_cdc.h"
#include "usart.h"
#include "crc16.h"
#include "string.h"

// Flags to tell where to add CRC on sent replies
bool g_reply_with_crc_on_usb = false;
bool g_reply_with_crc_on_fpc = true;
// "Session" flag, to tell via which interface next msgs should be sent: USB or FPC USART
bool g_reply_via_fpc = false;
bool g_reply_via_usb = false;

int reply_old(uint64_t cmd, uint64_t arg0, uint64_t arg1, uint64_t arg2, const void *data, size_t len) {
    PacketResponseOLD txcmd = {CMD_UNKNOWN, {0, 0, 0}, {{0}}};

//    for (size_t i = 0; i < sizeof(PacketResponseOLD); i++)
//        ((uint8_t *)&txcmd)[i] = 0x00;

    // Compose the outgoing command frame
    txcmd.cmd = cmd;
    txcmd.arg[0] = arg0;
    txcmd.arg[1] = arg1;
    txcmd.arg[2] = arg2;

    // Add the (optional) content to the frame, with a maximum size of PM3_CMD_DATA_SIZE
    if (data && len) {
        len = MIN(len, PM3_CMD_DATA_SIZE);
        for (size_t i = 0; i < len; i++) {
            txcmd.d.asBytes[i] = ((const uint8_t *)data)[i];
        }
    }

#ifdef WITH_FPC_USART_HOST
    int resultfpc = PM3_EUNDEF;
#endif
    int resultusb = PM3_EUNDEF;
    // Send frame and make sure all bytes are transmitted

    if (g_reply_via_usb) {
        resultusb = usb_write((uint8_t *)&txcmd, sizeof(PacketResponseOLD));
    }

    if (g_reply_via_fpc) {
#ifdef WITH_FPC_USART_HOST
        resultfpc = usart_writebuffer_sync((uint8_t *)&txcmd, sizeof(PacketResponseOLD));
#else
        return PM3_EDEVNOTSUPP;
#endif
    }
    // we got two results, let's prioritize the faulty one and USB over FPC.
    if (g_reply_via_usb && (resultusb != PM3_SUCCESS)) return resultusb;
#ifdef WITH_FPC_USART_HOST
    if (g_reply_via_fpc && (resultfpc != PM3_SUCCESS)) return resultfpc;
#endif
    return PM3_SUCCESS;
}

static int reply_ng_internal(uint16_t cmd, int16_t status, const uint8_t *data, size_t len, bool ng) {
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

    // length is only 15bit (32768)
    txBufferNG.pre.length = (len & 0x7FFF);

    // Add the (optional) content to the frame, with a maximum size of PM3_CMD_DATA_SIZE
    if (data && len) {
        for (size_t i = 0; i < len; i++) {
            txBufferNG.data[i] = data[i];
        }
    }

    PacketResponseNGPostamble *tx_post = (PacketResponseNGPostamble *)((uint8_t *)&txBufferNG + sizeof(PacketResponseNGPreamble) + len);
    // Note: if we send to both FPC & USB, we'll set CRC for both if any of them require CRC
    if ((g_reply_via_fpc && g_reply_with_crc_on_fpc) || ((g_reply_via_usb) && g_reply_with_crc_on_usb)) {
        uint8_t first, second;
        compute_crc(CRC_14443_A, (uint8_t *)&txBufferNG, sizeof(PacketResponseNGPreamble) + len, &first, &second);
        tx_post->crc = ((first << 8) | second);
    } else {
        tx_post->crc = RESPONSENG_POSTAMBLE_MAGIC;
    }
    txBufferNGLen = sizeof(PacketResponseNGPreamble) + len + sizeof(PacketResponseNGPostamble);

#ifdef WITH_FPC_USART_HOST
    int resultfpc = PM3_EUNDEF;
#endif
    int resultusb = PM3_EUNDEF;
    // Send frame and make sure all bytes are transmitted

    if (g_reply_via_usb) {
        resultusb = usb_write((uint8_t *)&txBufferNG, txBufferNGLen);
    }
    if (g_reply_via_fpc) {
#ifdef WITH_FPC_USART_HOST
        resultfpc = usart_writebuffer_sync((uint8_t *)&txBufferNG, txBufferNGLen);
#else
        return PM3_EDEVNOTSUPP;
#endif
    }
    // we got two results, let's prioritize the faulty one and USB over FPC.
    if (g_reply_via_usb && (resultusb != PM3_SUCCESS)) return resultusb;
#ifdef WITH_FPC_USART_HOST
    if (g_reply_via_fpc && (resultfpc != PM3_SUCCESS)) return resultfpc;
#endif
    return PM3_SUCCESS;
}

int reply_ng(uint16_t cmd, int16_t status, const uint8_t *data, size_t len) {
    return reply_ng_internal(cmd, status, data, len, true);
}

int reply_mix(uint64_t cmd, uint64_t arg0, uint64_t arg1, uint64_t arg2, const void *data, size_t len) {
    int16_t status = PM3_SUCCESS;
    uint64_t arg[3] = {arg0, arg1, arg2};
    if (len > PM3_CMD_DATA_SIZE - sizeof(arg)) {
        len = PM3_CMD_DATA_SIZE - sizeof(arg);
        status = PM3_EOVFLOW;
    }
    uint8_t cmddata[PM3_CMD_DATA_SIZE];
    memcpy(cmddata, arg, sizeof(arg));
    if (len && data)
        memcpy(cmddata + sizeof(arg), data, (int)len);

    return reply_ng_internal((cmd & 0xFFFF), status, cmddata, len + sizeof(arg), false);
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
        g_reply_via_usb = usb;
        g_reply_via_fpc = fpc;
    } else {                               // Old style command
        PacketCommandOLD rx_old;
        memcpy(&rx_old, &rx_raw.pre, sizeof(PacketCommandNGPreamble));
        bytes = read_ng(((uint8_t *)&rx_old) + sizeof(PacketCommandNGPreamble), sizeof(PacketCommandOLD) - sizeof(PacketCommandNGPreamble));
        if (bytes != sizeof(PacketCommandOLD) - sizeof(PacketCommandNGPreamble))
            return PM3_EIO;

        g_reply_via_usb = usb;
        g_reply_via_fpc = fpc;
        rx->ng = false;
        rx->magic = 0;
        rx->crc = 0;
        rx->cmd = (rx_old.cmd & 0xFFFF);
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
