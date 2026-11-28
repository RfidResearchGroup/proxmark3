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
// USB CCID smart card reader, class driver for the USB host on the CEP port.
// One slot, bulk pipes only, one message in flight (CCID rev 1.1).
// TPDU level readers with automatic PPS and voltage. T=0: the reader handles the procedure
// bytes. T=1: the blocks are built here.
//-----------------------------------------------------------------------------

#define USE_OTG_HOST_MODE
#include "ccid_reader.h"
#include "pm5_cep_usb_host.h"
#include "pm3_cmd.h"
#include "dbprint.h"
#include "ticks_apis.h"
#include "usb_std.h"
#include "usbh_ctrl.h"
#include "smartcard_rate.h"
#include "string.h"

#define CCID_CLASS_CODE          0x0B
#define CCID_DESCRIPTOR_TYPE     0x21
#define CCID_DESCRIPTOR_SIZE     0x36
#define CCID_HEADER_SIZE         10
#define CCID_PACKET_MAX          64
#define CCID_TIMEOUT_MS          10000   // per answer, a time extension restarts it

// dwFeatures of the class descriptor
#define CCID_FEATURE_AUTO_ACTIVATION 0x00000004
#define CCID_FEATURE_AUTO_VOLTAGE    0x00000008
#define CCID_FEATURE_AUTO_PPS        0x00000080   // runs the PPS that SetParameters asks for
#define CCID_FEATURE_AUTO_IFSD       0x00000400
#define CCID_FEATURE_LEVEL_MASK      0x00070000
#define CCID_FEATURE_LEVEL_TPDU      0x00010000

#define PC_TO_RDR_SET_PARAMETERS 0x61
#define PC_TO_RDR_ICC_POWER_ON   0x62
#define PC_TO_RDR_ICC_POWER_OFF  0x63
#define PC_TO_RDR_XFR_BLOCK      0x6F
#define RDR_TO_PC_DATA_BLOCK     0x80
#define RDR_TO_PC_SLOT_STATUS    0x81
#define RDR_TO_PC_PARAMETERS     0x82

// bStatus: command status in bits 7-6, card status in bits 1-0
#define CCID_COMMAND_STATUS(s)   ((s) >> 6)
#define CCID_COMMAND_FAILED      1
#define CCID_TIME_EXTENSION      2
#define CCID_ICC_STATUS(s)       ((s) & 0x03)
#define CCID_ICC_ABSENT          2
// bError
#define CCID_ICC_MUTE            0xFE

#define ATR_FIDI_DEFAULT         0x11
#define ATR_BWI_CWI_DEFAULT      0x4D
#define ATR_WI_DEFAULT           10

// T=0 commands (ISO 7816-3 12.2): CLA INS P1 P2 P3, then the data
#define T0_HEADER_SIZE           5
#define T0_TPDU_MAX              (T0_HEADER_SIZE + 255)

// T=1 blocks (ISO 7816-3 11.3): NAD PCB LEN INF LRC
#define T1_NAD                   0x00
#define T1_IFS_DEFAULT           32
#define T1_INF_MAX               254
#define T1_BLOCK_MAX             (3 + T1_INF_MAX + 1)
#define T1_I_BLOCK(ns, more)     (uint8_t)(((ns) << 6) | ((more) << 5))
#define T1_R_BLOCK(nr, error)    (uint8_t)(0x80 | ((nr) << 4) | (error))
#define T1_R_ERROR_EDC           0x01
#define T1_R_ERROR_OTHER         0x02
#define T1_IS_I(pcb)             (((pcb) & 0x80) == 0x00)
#define T1_IS_R(pcb)             (((pcb) & 0xC0) == 0x80)
#define T1_I_NS(pcb)             (((pcb) >> 6) & 1)
#define T1_I_MORE(pcb)           (((pcb) >> 5) & 1)
#define T1_R_NR(pcb)             (((pcb) >> 4) & 1)
#define T1_S_IFS_REQUEST         0xC1
#define T1_S_IFS_RESPONSE        0xE1
#define T1_S_WTX_REQUEST         0xC3
#define T1_S_WTX_RESPONSE        0xE3
#define T1_RETRIES               3
#define T1_S_REQUESTS_MAX        100     // waiting time extensions in a row

#define CCID_DATA_MAX            T0_TPDU_MAX    // the longest message, a block is two bytes shorter

typedef enum {
    CCID_XFER_IDLE,
    CCID_XFER_OUT,
    CCID_XFER_IN,
    CCID_XFER_DONE,
    CCID_XFER_FAILED
} ccid_xfer_t;

// what the ATR says about speed, T=0 and T=1 (ISO 7816-3 8.2)
typedef struct {
    uint8_t ta1;        // Fi/Di
    uint8_t tc1;        // extra guard time
    uint8_t wi;         // T=0 waiting integer
    uint8_t ifsc;       // block size of the card
    uint8_t bwi_cwi;    // waiting times
    uint8_t specific_protocol;
    uint8_t protocol;   // the one the card runs after the reset
    bool t0;            // T=0 offered
    bool t1;            // T=1 offered
    bool specific;      // TA2 present: specific_protocol is the only one
    bool crc;           // CRC instead of LRC
    bool inverse;
} ccid_atr_t;

static usbh_core_type *s_host;
static bool s_ready;
static bool s_channels_open;
static bool s_descriptor_pending;
static uint8_t s_error;
static uint8_t s_interface;
static uint32_t s_features;
static uint32_t s_default_clock;    // kHz
static uint32_t s_data_rate;        // bit/s at the default clock
static uint32_t s_max_data_rate;
static uint32_t s_max_ifsd;
static uint32_t s_max_message;
static uint8_t s_bulk_in_addr;
static uint8_t s_bulk_out_addr;
static uint16_t s_bulk_in_size;
static uint16_t s_bulk_out_size;
static uint8_t s_bulk_in_channel;
static uint8_t s_bulk_out_channel;
static uint8_t s_seq;
static uint8_t s_t1_ns;         // N(S) of our next I-block
static uint8_t s_t1_nr;         // N(S) expected in the next I-block of the card
static uint8_t s_t1_ifsc;
static bool s_t0_ready;         // the card is in T=0, commands can go
static bool s_t1_ready;         // the card is in T=1, blocks can go
static ccid_atr_t s_atr;        // of the card that last answered to reset
static bool s_atr_valid;
static volatile ccid_xfer_t s_xfer;
static bool s_out_pending;
static uint16_t s_out_inflight;
static uint16_t s_msg_len;
static uint16_t s_msg_sent;
static uint16_t s_rsp_len;
static uint8_t s_msg[CCID_HEADER_SIZE + CCID_DATA_MAX];
static uint8_t s_rsp[CCID_HEADER_SIZE + CCID_DATA_MAX];
// the host library moves whole 32-bit words
static uint8_t s_out_packet[CCID_PACKET_MAX] __attribute__((aligned(4)));
static uint8_t s_in_packet[CCID_PACKET_MAX] __attribute__((aligned(4)));

static uint32_t le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static bool parse_endpoints(usbh_core_type *host) {
    usb_cfg_desc_type *cfg = &host->dev.cfg_desc;
    if (cfg->cfg.bNumInterfaces == 0 || cfg->cfg.bNumInterfaces > USBH_MAX_INTERFACE) {
        return false;
    }
    for (uint8_t i = 0; i < cfg->cfg.bNumInterfaces; i++) {
        usb_itf_desc_type *itf = &cfg->interface[i];
        if (itf->interface.bInterfaceClass != CCID_CLASS_CODE ||
                itf->interface.bAlternateSetting != 0 ||
                itf->interface.bNumEndpoints > USBH_MAX_ENDPOINT) {
            continue;
        }
        s_bulk_in_addr = 0;
        s_bulk_out_addr = 0;
        for (uint8_t j = 0; j < itf->interface.bNumEndpoints; j++) {
            usb_endpoint_desc_type *ep = &itf->endpoint[j];
            uint8_t type = ep->bmAttributes & 0x03;
            uint8_t address = ep->bEndpointAddress;
            uint16_t packet = ep->wMaxPacketSize & 0x07FF;
            if (type != EPT_BULK_TYPE || packet < 8 || packet > CCID_PACKET_MAX) {
                continue;
            }
            if ((address & 0x80) && !s_bulk_in_addr) {
                s_bulk_in_addr = address;
                s_bulk_in_size = packet;
            } else if (!(address & 0x80) && !s_bulk_out_addr) {
                s_bulk_out_addr = address;
                s_bulk_out_size = packet;
            }
        }
        if (s_bulk_in_addr && s_bulk_out_addr) {
            s_interface = itf->interface.bInterfaceNumber;
            return true;
        }
    }
    return false;
}

// The host library keeps interfaces and endpoints only: find the CCID class
// descriptor of our interface in the raw configuration descriptor.
static bool parse_class_descriptor(const uint8_t *cfg, uint16_t length) {
    uint16_t offset = 0;
    bool ours = false;
    while (length - offset >= 2) {
        uint8_t size = cfg[offset];
        uint8_t type = cfg[offset + 1];
        if (size < 2 || size > length - offset) {
            break;
        }
        if (type == USB_DESCIPTOR_TYPE_INTERFACE && size >= 9) {
            ours = cfg[offset + 2] == s_interface && cfg[offset + 3] == 0;
        } else if (type == CCID_DESCRIPTOR_TYPE && ours && size >= CCID_DESCRIPTOR_SIZE) {
            s_default_clock = le32(cfg + offset + 10);
            s_data_rate = le32(cfg + offset + 19);
            s_max_data_rate = le32(cfg + offset + 23);
            s_max_ifsd = le32(cfg + offset + 28);
            s_features = le32(cfg + offset + 40);
            s_max_message = le32(cfg + offset + 44);
            return true;
        }
        offset = (uint16_t)(offset + size);
    }
    return false;
}

usb_sts_type ccid_reader_init_handler(void *data) {
    usbh_core_type *host = data;
    if (!parse_endpoints(host)) {
        return USB_NOT_SUPPORT;
    }
    s_host = host;
    s_ready = false;
    s_channels_open = false;
    s_descriptor_pending = false;
    s_error = CCID_ERROR_NONE;
    s_xfer = CCID_XFER_IDLE;
    s_out_pending = false;
    return USB_OK;
}

// usbh_alloc_channel() returns USB_FAIL, a valid channel number, when none is free
static uint16_t alloc_channel(uint8_t ept_addr) {
    if (usbh_get_free_channel(s_host) == HCH_ERROR) {
        return HCH_ERROR;
    }
    return usbh_alloc_channel(s_host, ept_addr);
}

usb_sts_type ccid_reader_request_handler(void *data) {
    s_host = data;
    // the configuration descriptor again, this time for its class descriptor
    if (!s_descriptor_pending) {
        usbh_get_descriptor(s_host, s_host->dev.cfg_desc.cfg.wTotalLength,
                            USB_REQ_RECIPIENT_DEVICE | USB_REQ_TYPE_STANDARD,
                            (USB_DESCIPTOR_TYPE_CONFIGURATION << 8) & 0xFF00, s_host->rx_buffer);
        s_descriptor_pending = true;
        return USB_WAIT;
    }
    usb_sts_type status = usbh_ctrl_transfer_loop(s_host);
    if (status == USB_WAIT) {
        return USB_WAIT;
    }
    if (status != USB_OK) {
        return status;
    }
    s_descriptor_pending = false;
    s_host->req_state = CMD_SEND;
    s_host->ctrl.state = CONTROL_IDLE;
    if (!parse_class_descriptor(s_host->rx_buffer, s_host->dev.cfg_desc.cfg.wTotalLength)) {
        s_error = CCID_ERROR_DESCRIPTOR;
        return USB_NOT_SUPPORT;
    }
    if ((s_features & CCID_FEATURE_LEVEL_MASK) != CCID_FEATURE_LEVEL_TPDU) {
        s_error = CCID_ERROR_LEVEL;
        return USB_NOT_SUPPORT;
    }
    // no PPS and no voltage choice of ours
    if ((s_features & CCID_FEATURE_AUTO_PPS) == 0 ||
            (s_features & (CCID_FEATURE_AUTO_VOLTAGE | CCID_FEATURE_AUTO_ACTIVATION)) == 0) {
        s_error = CCID_ERROR_FEATURES;
        return USB_NOT_SUPPORT;
    }

    uint16_t in = alloc_channel(s_bulk_in_addr);
    uint16_t out = alloc_channel(s_bulk_out_addr);
    if (in >= USB_HOST_CHANNEL_NUM || out >= USB_HOST_CHANNEL_NUM) {
        return USB_ERROR;
    }
    s_bulk_in_channel = (uint8_t)in;
    s_bulk_out_channel = (uint8_t)out;
    usbh_hc_open(s_host, s_bulk_in_channel, s_bulk_in_addr,
                 s_host->dev.address, EPT_BULK_TYPE, s_bulk_in_size,
                 s_host->dev.speed);
    usbh_hc_open(s_host, s_bulk_out_channel, s_bulk_out_addr,
                 s_host->dev.address, EPT_BULK_TYPE, s_bulk_out_size,
                 s_host->dev.speed);
    // a device that re-enumerates starts again from DATA0
    usbh_set_toggle(s_host, s_bulk_in_channel, 0);
    usbh_set_toggle(s_host, s_bulk_out_channel, 0);
    s_channels_open = true;
    s_ready = true;
    return USB_OK;
}

static void xfer_fail(uint8_t error) {
    s_error = error;
    s_xfer = CCID_XFER_FAILED;
    s_ready = false;
    s_host->global_state = USBH_ERROR_STATE;
}

static void in_submit(void) {
    usbh_bulk_recv(s_host, s_bulk_in_channel, s_in_packet, s_bulk_in_size);
}

// true when the answer is complete, or cut short by a short packet
static bool in_take(uint16_t count) {
    // a zero length packet may close a previous answer
    if (count == 0 && s_rsp_len == 0) {
        return false;
    }
    if (count > sizeof(s_rsp) - s_rsp_len) {
        count = (uint16_t)(sizeof(s_rsp) - s_rsp_len);
    }
    memcpy(s_rsp + s_rsp_len, s_in_packet, count);
    s_rsp_len = (uint16_t)(s_rsp_len + count);
    if (s_rsp_len >= CCID_HEADER_SIZE &&
            s_rsp_len >= CCID_HEADER_SIZE + le32(s_rsp + 1)) {
        return true;
    }
    return count < s_bulk_in_size || s_rsp_len == sizeof(s_rsp);
}

usb_sts_type ccid_reader_process_handler(void *data) {
    s_host = data;
    if (!s_ready || !s_channels_open) {
        return USB_OK;
    }

    if (s_xfer == CCID_XFER_OUT) {
        if (s_out_pending) {
            urb_sts_type state = usbh_get_urb_status(s_host, s_bulk_out_channel);
            if (state == URB_DONE) {
                s_msg_sent = (uint16_t)(s_msg_sent + s_out_inflight);
                s_out_pending = false;
            } else if (state == URB_NOTREADY) {
                // NAKed: the host library leaves the resend to us
                s_out_pending = false;
            } else if (state == URB_ERROR || state == URB_STALL) {
                xfer_fail(state == URB_STALL ? CCID_ERROR_OUT_STALL : CCID_ERROR_OUT_URB);
                return USB_ERROR;
            }
        }
        if (!s_out_pending) {
            if (s_msg_sent == s_msg_len) {
                s_xfer = CCID_XFER_IN;
                s_rsp_len = 0;
                in_submit();
            } else {
                uint16_t count = (uint16_t)(s_msg_len - s_msg_sent);
                if (count > s_bulk_out_size) {
                    count = s_bulk_out_size;
                }
                memcpy(s_out_packet, s_msg + s_msg_sent, count);
                s_out_inflight = count;
                usbh_bulk_send(s_host, s_bulk_out_channel, s_out_packet, count);
                s_out_pending = true;
            }
        }
    } else if (s_xfer == CCID_XFER_IN) {
        // a NAKed IN is re-armed by the host library IRQ handler
        urb_sts_type state = usbh_get_urb_status(s_host, s_bulk_in_channel);
        if (state == URB_DONE) {
            if (in_take((uint16_t)s_host->hch[s_bulk_in_channel].trans_count)) {
                s_xfer = CCID_XFER_DONE;
            } else {
                in_submit();
            }
        } else if (state == URB_ERROR || state == URB_STALL) {
            xfer_fail(state == URB_STALL ? CCID_ERROR_IN_STALL : CCID_ERROR_IN_URB);
            return USB_ERROR;
        }
    }
    return USB_OK;
}

usb_sts_type ccid_reader_reset_handler(void *data) {
    (void)data;
    s_ready = false;
    s_atr_valid = false;
    s_t0_ready = false;
    s_t1_ready = false;
    s_channels_open = false;
    s_descriptor_pending = false;
    s_out_pending = false;
    s_error = CCID_ERROR_NONE;
    if (s_xfer != CCID_XFER_IDLE) {
        s_xfer = CCID_XFER_FAILED;
    }
    return USB_OK;
}

bool ccid_reader_ready(void) {
    return s_ready;
}

bool ccid_reader_busy(void) {
    return s_xfer == CCID_XFER_OUT || s_xfer == CCID_XFER_IN;
}

uint8_t ccid_reader_error(void) {
    return s_error;
}

bool ccid_reader_error_is_final(uint8_t error) {
    return error == CCID_ERROR_DESCRIPTOR || error == CCID_ERROR_LEVEL || error == CCID_ERROR_FEATURES;
}

const char *ccid_reader_error_text(uint8_t error) {
    switch (error) {
        case CCID_ERROR_DESCRIPTOR:
            return "no CCID class descriptor";
        case CCID_ERROR_LEVEL:
            return "not a TPDU level reader";
        case CCID_ERROR_FEATURES:
            return "no automatic PPS or voltage selection";
        case CCID_ERROR_TIMEOUT:
            return "reader does not answer";
        case CCID_ERROR_BAD_ANSWER:
            return "unexpected answer from the reader";
        default:
            return "USB transfer error";
    }
}

// Sends one message and waits for its answer. params: the three message specific header bytes.
static int ccid_transact(uint8_t type, const uint8_t params[3], const uint8_t *data, uint16_t length,
                         uint8_t answer_type) {
    if (!s_ready) {
        return PM3_EIO;
    }
    if (length > CCID_DATA_MAX) {
        return PM3_EINVARG;
    }
    uint8_t seq = s_seq++;
    s_msg[0] = type;
    s_msg[1] = (uint8_t)length;
    s_msg[2] = (uint8_t)(length >> 8);
    s_msg[3] = 0;
    s_msg[4] = 0;
    s_msg[5] = 0;   // slot
    s_msg[6] = seq;
    memcpy(s_msg + 7, params, 3);
    if (length) {
        memcpy(s_msg + CCID_HEADER_SIZE, data, length);
    }
    s_msg_len = (uint16_t)(CCID_HEADER_SIZE + length);
    s_msg_sent = 0;
    s_out_pending = false;
    s_xfer = CCID_XFER_OUT;

    uint32_t start = GetTickCount();
    for (;;) {
        cep_usb_host_task();
        if (s_xfer == CCID_XFER_FAILED || !s_ready) {
            s_xfer = CCID_XFER_IDLE;
            return PM3_EIO;
        }
        if (s_xfer == CCID_XFER_DONE) {
            if (s_rsp_len < CCID_HEADER_SIZE || s_rsp[0] != answer_type || s_rsp[6] != seq ||
                    s_rsp_len < CCID_HEADER_SIZE + le32(s_rsp + 1)) {
                s_xfer = CCID_XFER_IDLE;
                s_error = CCID_ERROR_BAD_ANSWER;
                return PM3_EWRONGANSWER;
            }
            if (CCID_COMMAND_STATUS(s_rsp[7]) != CCID_TIME_EXTENSION) {
                s_xfer = CCID_XFER_IDLE;
                break;
            }
            // the card asked for more time, the real answer follows
            s_xfer = CCID_XFER_IN;
            s_rsp_len = 0;
            in_submit();
            start = GetTickCount();
        }
        if (GetTickCountDelta(start) > CCID_TIMEOUT_MS) {
            xfer_fail(CCID_ERROR_TIMEOUT);
            s_xfer = CCID_XFER_IDLE;
            return PM3_ETIMEOUT;
        }
    }

    if (CCID_COMMAND_STATUS(s_rsp[7]) == CCID_COMMAND_FAILED) {
        bool absent = CCID_ICC_STATUS(s_rsp[7]) == CCID_ICC_ABSENT;
        bool mute = s_rsp[8] == CCID_ICC_MUTE;
        if (g_dbglevel >= DBG_ERROR) {
            if (absent) {
                DbpString("CCID: no card in the reader");
            } else if (mute) {
                // some readers call an empty slot a card that is there
                DbpString("CCID: the card does not answer");
            }
        }
        if (g_dbglevel >= ((absent || mute) ? DBG_INFO : DBG_ERROR)) {
            Dbprintf("CCID: message %02x failed, status %02x error %02x", type, s_rsp[7], s_rsp[8]);
        }
        return absent ? PM3_ENODATA : PM3_ECARDEXCHANGE;
    }
    return PM3_SUCCESS;
}

// copies the data of the last answer
static int answer_data(uint8_t *dest, uint16_t *dest_len, uint16_t dest_max) {
    uint32_t length = le32(s_rsp + 1);
    if (length > dest_max) {
        return PM3_EOVFLOW;
    }
    *dest_len = (uint16_t)length;
    memcpy(dest, s_rsp + CCID_HEADER_SIZE, *dest_len);
    return PM3_SUCCESS;
}

static bool atr_parse(const uint8_t *atr, uint16_t length, ccid_atr_t *info) {
    memset(info, 0, sizeof(*info));
    info->ta1 = ATR_FIDI_DEFAULT;
    info->wi = ATR_WI_DEFAULT;
    info->ifsc = T1_IFS_DEFAULT;
    info->bwi_cwi = ATR_BWI_CWI_DEFAULT;
    if (length < 2) {
        return false;
    }
    info->inverse = atr[0] == 0x3F;
    // no TD1: T=0 is the only offer
    info->t0 = (atr[1] & 0x80) == 0;

    uint8_t present = atr[1] >> 4;  // which of TAi TBi TCi TDi follow
    uint8_t protocol = 0;           // the one the bytes of this round belong to
    uint16_t pos = 2;
    bool ifsc_set = false;
    bool waits_set = false;
    for (uint8_t i = 1; ; i++) {
        for (uint8_t bit = 0; bit < 3; bit++) {
            if ((present & (1 << bit)) == 0) {
                continue;
            }
            if (pos >= length) {
                return false;
            }
            uint8_t value = atr[pos++];
            if (i == 1 && bit == 0) {
                info->ta1 = value;
            } else if (i == 1 && bit == 2) {
                info->tc1 = value;
            } else if (i == 2 && bit == 0) {
                info->specific = true;
                info->specific_protocol = value & 0x0F;
                // b5: implicit Fi/Di
                if (value & 0x10) {
                    info->ta1 = ATR_FIDI_DEFAULT;
                }
            } else if (i == 2 && bit == 2 && value != 0) {
                info->wi = value;
            } else if (i > 2 && protocol == 1) {
                if (bit == 0 && ifsc_set == false) {
                    info->ifsc = value > T1_INF_MAX ? T1_INF_MAX : value;
                    ifsc_set = true;
                } else if (bit == 1 && waits_set == false) {
                    info->bwi_cwi = value;
                    waits_set = true;
                } else if (bit == 2) {
                    info->crc = (value & 0x01) != 0;
                }
            }
        }
        if ((present & 0x08) == 0) {
            break;
        }
        if (pos >= length) {
            return false;
        }
        uint8_t td = atr[pos++];
        protocol = td & 0x0F;
        if (i == 1) {
            info->protocol = protocol;
        }
        if (protocol == 0) {
            info->t0 = true;
        } else if (protocol == 1) {
            info->t1 = true;
        }
        present = td >> 4;
    }
    if (info->specific) {
        info->protocol = info->specific_protocol;
    }
    return true;
}

static int card_power(bool on) {
    // on: voltage chosen by the reader
    const uint8_t params[3] = {0x00, 0x00, 0x00};
    if (on) {
        return ccid_transact(PC_TO_RDR_ICC_POWER_ON, params, NULL, 0, RDR_TO_PC_DATA_BLOCK);
    }
    return ccid_transact(PC_TO_RDR_ICC_POWER_OFF, params, NULL, 0, RDR_TO_PC_SLOT_STATUS);
}

static int set_parameters(uint8_t protocol, uint8_t fidi, const ccid_atr_t *info) {
    const uint8_t params[3] = {protocol, 0x00, 0x00};   // bProtocolNum
    uint8_t convention = info->inverse ? 0x02 : 0x00;
    if (protocol == 0) {
        // bmFindexDindex, bmTCCKST0, bGuardTimeT0, bWaitingIntegerT0, bClockStop
        const uint8_t t0[5] = {fidi, convention, info->tc1, info->wi, 0x00};
        return ccid_transact(PC_TO_RDR_SET_PARAMETERS, params, t0, sizeof(t0), RDR_TO_PC_PARAMETERS);
    }
    // bmFindexDindex, bmTCCKST1 (LRC), bGuardTimeT1, bWaitingIntegersT1, bClockStop, bIFSC, bNadValue
    const uint8_t t1[7] = {fidi, (uint8_t)(0x10 | convention), info->tc1, info->bwi_cwi, 0x00, info->ifsc, T1_NAD};
    return ccid_transact(PC_TO_RDR_SET_PARAMETERS, params, t1, sizeof(t1), RDR_TO_PC_PARAMETERS);
}

static uint8_t t1_lrc(const uint8_t *data, uint16_t length) {
    uint8_t lrc = 0;
    while (length--) {
        lrc ^= *data++;
    }
    return lrc;
}

// One block out, the next block of the card back. bwi stretches the block waiting time.
// PM3_ECRC and PM3_EWRONGANSWER: a block arrived but it is not a valid one.
static int t1_exchange(uint8_t pcb, const uint8_t *inf, uint8_t length, uint8_t bwi,
                       uint8_t *answer, uint16_t *answer_len) {
    uint8_t block[T1_BLOCK_MAX];
    block[0] = T1_NAD;
    block[1] = pcb;
    block[2] = length;
    if (length) {
        memcpy(block + 3, inf, length);
    }
    block[3 + length] = t1_lrc(block, (uint16_t)(3 + length));
    const uint8_t params[3] = {bwi, 0x00, 0x00};
    int res = ccid_transact(PC_TO_RDR_XFR_BLOCK, params, block, (uint16_t)(4 + length), RDR_TO_PC_DATA_BLOCK);
    if (res != PM3_SUCCESS) {
        return res;
    }
    res = answer_data(answer, answer_len, T1_BLOCK_MAX);
    if (res != PM3_SUCCESS) {
        return res;
    }
    if (*answer_len < 4 || *answer_len != 4 + answer[2]) {
        return PM3_EWRONGANSWER;
    }
    return t1_lrc(answer, *answer_len) == 0 ? PM3_SUCCESS : PM3_ECRC;
}

// a whole block has to fit in one CCID message
static uint8_t t1_ifsc_limit(uint8_t ifsc) {
    if (s_max_message > CCID_HEADER_SIZE + 4 && ifsc > s_max_message - CCID_HEADER_SIZE - 4) {
        ifsc = (uint8_t)(s_max_message - CCID_HEADER_SIZE - 4);
    }
    if (ifsc == 0 || ifsc > T1_INF_MAX) {
        ifsc = T1_IFS_DEFAULT;
    }
    return ifsc;
}

// as t1_exchange(), answering the card when it asks for more time or for another block size
static int t1_transceive(uint8_t pcb, const uint8_t *inf, uint8_t length,
                         uint8_t *answer, uint16_t *answer_len) {
    int res = t1_exchange(pcb, inf, length, 0, answer, answer_len);
    for (uint8_t i = 0; res == PM3_SUCCESS && answer[2] == 1 &&
            (answer[1] == T1_S_WTX_REQUEST || answer[1] == T1_S_IFS_REQUEST); i++) {
        if (i == T1_S_REQUESTS_MAX) {
            return PM3_ETIMEOUT;
        }
        uint8_t value = answer[3];
        if (answer[1] == T1_S_IFS_REQUEST) {
            s_t1_ifsc = t1_ifsc_limit(value);
            res = t1_exchange(T1_S_IFS_RESPONSE, &value, 1, 0, answer, answer_len);
        } else {
            res = t1_exchange(T1_S_WTX_RESPONSE, &value, 1, value, answer, answer_len);
        }
    }
    return res;
}

// Fresh T=1 link: sequence numbers at zero, then our block size unless the reader announces it.
static int t1_start(const ccid_atr_t *info) {
    s_t1_ns = 0;
    s_t1_nr = 0;
    s_t1_ifsc = t1_ifsc_limit(info->ifsc);
    if (s_features & CCID_FEATURE_AUTO_IFSD) {
        return PM3_SUCCESS;
    }
    uint8_t ifsd = s_max_ifsd > T1_INF_MAX ? T1_INF_MAX : (uint8_t)s_max_ifsd;
    if (ifsd <= T1_IFS_DEFAULT) {
        return PM3_SUCCESS;
    }
    uint8_t answer[T1_BLOCK_MAX];
    uint16_t answer_len = 0;
    int res = PM3_ECARDEXCHANGE;
    for (uint8_t i = 0; i < T1_RETRIES; i++) {
        res = t1_exchange(T1_S_IFS_REQUEST, &ifsd, 1, 0, answer, &answer_len);
        if (res == PM3_SUCCESS && answer[1] == T1_S_IFS_RESPONSE && answer[2] == 1 && answer[3] == ifsd) {
            return PM3_SUCCESS;
        }
        if (res != PM3_SUCCESS && res != PM3_ECRC && res != PM3_EWRONGANSWER) {
            return res;
        }
    }
    return res == PM3_SUCCESS ? PM3_EWRONGANSWER : res;
}

// One APDU out in chained I-blocks, its answer back (ISO 7816-3 11.6.2 and 11.6.3).
// tx and rx may be the same buffer: rx is written only once the card has all of tx.
static int t1_apdu(const uint8_t *tx, uint16_t tx_len, uint8_t *rx, uint16_t *rx_len, uint16_t rx_max) {
    uint8_t answer[T1_BLOCK_MAX];
    uint16_t answer_len = 0;
    uint16_t sent = 0;
    uint8_t chunk = 0;
    uint8_t retries = 0;
    uint8_t request = 0;    // R-block to send instead of our I-block, 0 for none
    bool more = false;      // our last I-block was not the final one
    bool sending = true;
    *rx_len = 0;

    for (;;) {
        int res;
        if (request) {
            res = t1_transceive(request, NULL, 0, answer, &answer_len);
        } else {
            uint16_t left = (uint16_t)(tx_len - sent);
            chunk = (uint8_t)(left > s_t1_ifsc ? s_t1_ifsc : left);
            more = left > chunk;
            res = t1_transceive(T1_I_BLOCK(s_t1_ns, more), tx + sent, chunk, answer, &answer_len);
        }
        // anything but a block, good or bad: the reader or the USB link failed
        if (res != PM3_SUCCESS && res != PM3_ECRC && res != PM3_EWRONGANSWER && res != PM3_ECARDEXCHANGE) {
            return res;
        }

        if (res == PM3_SUCCESS && sending && T1_IS_R(answer[1])) {
            if (T1_R_NR(answer[1]) == s_t1_ns) {
                // the card wants our block again
                if (++retries > T1_RETRIES) {
                    return PM3_ECARDEXCHANGE;
                }
                request = 0;
                continue;
            }
            if (more) {
                // chained block acknowledged, next one
                s_t1_ns ^= 1;
                sent = (uint16_t)(sent + chunk);
                retries = 0;
                request = 0;
                continue;
            }
        } else if (res == PM3_SUCCESS && T1_IS_I(answer[1]) && T1_I_NS(answer[1]) == s_t1_nr &&
                   (sending == false || more == false)) {
            // an I-block of the card also acknowledges our last one
            if (sending) {
                s_t1_ns ^= 1;
                sending = false;
            }
            if (answer[2] > rx_max - *rx_len) {
                return PM3_EOVFLOW;
            }
            memcpy(rx + *rx_len, answer + 3, answer[2]);
            *rx_len = (uint16_t)(*rx_len + answer[2]);
            s_t1_nr ^= 1;
            retries = 0;
            if (T1_I_MORE(answer[1]) == 0) {
                return PM3_SUCCESS;
            }
            request = T1_R_BLOCK(s_t1_nr, 0);
            continue;
        }

        // not the block we expect: ask for it again
        if (++retries > T1_RETRIES) {
            if (g_dbglevel >= DBG_ERROR) {
                Dbprintf("CCID: T=1 exchange failed, result %d", res);
            }
            return PM3_ECARDEXCHANGE;
        }
        request = T1_R_BLOCK(s_t1_nr, res == PM3_ECRC ? T1_R_ERROR_EDC : T1_R_ERROR_OTHER);
    }
}

// One command in T=0, the data and SW1 SW2 of the card back (CCID 3.2.1, ISO 7816-3 12.2).
// The reader adds P3 to case 1. Case 4 goes as case 3, the card asks for GET RESPONSE with 61xx.
static int t0_tpdu(const uint8_t *tx, uint16_t tx_len, uint8_t *rx, uint16_t *rx_len, uint16_t rx_max) {
    uint16_t length = tx_len;
    if (tx_len > T0_HEADER_SIZE) {
        uint8_t lc = tx[T0_HEADER_SIZE - 1];
        if (tx_len == T0_HEADER_SIZE + lc + 1 && lc != 0) {
            length = (uint16_t)(T0_HEADER_SIZE + lc);
        } else if (tx_len != T0_HEADER_SIZE + lc) {
            return PM3_EINVARG;
        }
    } else if (tx_len < T0_HEADER_SIZE - 1) {
        return PM3_EINVARG;
    }
    if ((uint32_t)(CCID_HEADER_SIZE + length) > s_max_message) {
        return PM3_EOVFLOW;
    }
    const uint8_t params[3] = {0x00, 0x00, 0x00};
    int res = ccid_transact(PC_TO_RDR_XFR_BLOCK, params, tx, length, RDR_TO_PC_DATA_BLOCK);
    if (res != PM3_SUCCESS) {
        return res;
    }
    res = answer_data(rx, rx_len, rx_max);
    if (res != PM3_SUCCESS) {
        return res;
    }
    return (*rx_len < 2) ? PM3_EWRONGANSWER : PM3_SUCCESS;
}

// T=0 or T=1 at the given speed for a card that just answered to reset: the reader runs the PPS.
static int card_select(const ccid_atr_t *info, uint8_t protocol, uint8_t fidi) {
    bool offered = (protocol == 0) ? info->t0 : (protocol == 1 && info->t1 && info->crc == false);
    if (offered == false || (info->specific && info->specific_protocol != protocol)) {
        if (g_dbglevel >= DBG_ERROR) {
            Dbprintf("CCID: the card does not offer T=%u%s", protocol, (protocol == 1) ? " with LRC" : "");
        }
        return PM3_ENOTIMPL;
    }
    int res = set_parameters(protocol, fidi, info);
    if (res != PM3_SUCCESS) {
        return res;
    }
    if (protocol == 1) {
        res = t1_start(info);
        if (res != PM3_SUCCESS) {
            return res;
        }
    }
    if (g_dbglevel >= DBG_INFO) {
        Dbprintf("CCID: card runs T=%u, Fi/Di %02x", protocol, fidi);
    }
    return PM3_SUCCESS;
}

int ccid_reader_power_on(uint8_t *atr, uint16_t *atr_len, uint16_t atr_max) {
    s_atr_valid = false;
    s_t0_ready = false;
    s_t1_ready = false;
    // always a cold reset: a reader can keep the slot active after a failed power on
    card_power(false);
    int res = card_power(true);
    if (res != PM3_SUCCESS) {
        return res;
    }
    res = answer_data(atr, atr_len, atr_max);
    if (res != PM3_SUCCESS) {
        return res;
    }
    if (atr_parse(atr, *atr_len, &s_atr) == false) {
        return PM3_EWRONGANSWER;
    }
    s_atr_valid = true;
    return PM3_SUCCESS;
}

int ccid_reader_select(uint8_t protocol, uint8_t fidi) {
    // once per reset, as the PPS it stands for
    if (s_atr_valid == false) {
        return PM3_ECARDEXCHANGE;
    }
    s_atr_valid = false;
    s_t0_ready = false;
    s_t1_ready = false;
    int res = card_select(&s_atr, protocol, fidi);
    s_t0_ready = (res == PM3_SUCCESS) && (protocol == 0);
    s_t1_ready = (res == PM3_SUCCESS) && (protocol == 1);
    return res;
}

int ccid_reader_protocol(void) {
    if (s_t0_ready || s_t1_ready) {
        return s_t1_ready ? 1 : 0;
    }
    return s_atr_valid ? s_atr.protocol : -1;
}

int ccid_reader_select_fastest(uint8_t protocol, uint8_t *fidi) {
    if (s_atr_valid == false) {
        return PM3_ECARDEXCHANGE;
    }
    // TA2: the card runs its own rate, no PPS changes it
    if (s_atr.specific) {
        *fidi = s_atr.ta1;
        return ccid_reader_select(protocol, *fidi);
    }
    ccid_atr_t card;
    memcpy(&card, &s_atr, sizeof(card));
    uint32_t below = SmartCard_RateBps(card.ta1, s_default_clock) + 1;
    for (;;) {
        // the card's Fi, the fastest Di the reader declares under the last try
        uint8_t pick = ATR_FIDI_DEFAULT;
        uint32_t best = 0;
        for (uint8_t di = 1; di < 16; di++) {
            uint8_t candidate = (uint8_t)((card.ta1 & 0xF0) | di);
            uint32_t rate = SmartCard_RateBps(candidate, s_default_clock);
            if ((rate > best) && (rate < below) && (rate >= s_data_rate) && (rate <= s_max_data_rate)) {
                best = rate;
                pick = candidate;
            }
        }
        *fidi = pick;
        int res = ccid_reader_select(protocol, pick);
        if ((res == PM3_SUCCESS) || (pick == ATR_FIDI_DEFAULT) ||
                ((res != PM3_ECARDEXCHANGE) && (res != PM3_EWRONGANSWER) && (res != PM3_ECRC))) {
            return res;
        }
        // refused, or no valid answer at that rate: cold reset, then a slower one
        if (g_dbglevel >= DBG_INFO) {
            Dbprintf("CCID: Fi/Di %02x failed, card reset", pick);
        }
        uint8_t atr[sizeof(((smart_card_atr_t *)0)->atr)];
        uint16_t atr_len = 0;
        res = ccid_reader_power_on(atr, &atr_len, sizeof(atr));
        if (res != PM3_SUCCESS) {
            return res;
        }
        if (memcmp(&card, &s_atr, sizeof(card)) != 0) {
            return PM3_ECARDEXCHANGE;
        }
        below = best;
    }
}

int ccid_reader_power_off(void) {
    s_atr_valid = false;
    s_t0_ready = false;
    s_t1_ready = false;
    return card_power(false);
}

int ccid_reader_xfr_apdu(const uint8_t *tx, uint16_t tx_len, uint8_t *rx, uint16_t *rx_len, uint16_t rx_max) {
    // no PPS since the reset: the reader is told the protocol the card came up in, at its speed
    if (s_t0_ready == false && s_t1_ready == false && s_atr_valid) {
        int res = ccid_reader_select(s_atr.protocol, s_atr.specific ? s_atr.ta1 : ATR_FIDI_DEFAULT);
        if (res != PM3_SUCCESS) {
            return res;
        }
    }
    if (s_t1_ready) {
        return t1_apdu(tx, tx_len, rx, rx_len, rx_max);
    }
    if (s_t0_ready) {
        return t0_tpdu(tx, tx_len, rx, rx_len, rx_max);
    }
    return PM3_ECARDEXCHANGE;
}
