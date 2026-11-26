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
// Proxmark5 USB host CDC (ACM) driver - see pm5_usb_host_cdc.h.
//-----------------------------------------------------------------------------

#include "pm5_usb_host_cdc.h"

#include <string.h>

#include "pm5_cep.h"
#include "ticks_apis.h"

#include "usb_conf.h"
#include "usb_core.h"
#include "usb_std.h"
#include "usbh_core.h"
#include "usbh_ctrl.h"
#include "usbh_int.h"

#include "at32f435_437_crm.h"
#include "at32f435_437_gpio.h"
#include "at32f435_437_misc.h"
#include "at32f435_437_usb.h"

// CDC-ACM class request not exposed by usb_std.h.
#define CDC_SET_CONTROL_LINE_STATE 0x22
// DTR | RTS, per the ACM SET_CONTROL_LINE_STATE wValue.
#define CDC_CTRL_LINE_DTR_RTS 0x0003
// 115200 baud, 1 stop bit, no parity, 8 data bits.
#define CDC_LINE_CODING_115200 115200
#define CDC_LINE_CODING_BITS 8

// Wall-clock timeout for a blocking bulk transfer. Long enough that a real
// device answers, short enough not to hang the main loop on a dead link.
#define CDC_XFER_TIMEOUT_MS 1000
// Once a reply has started, no new byte for this long marks the end of the
// stream. The ICSD device emits its answer as several short CDC packets, so a
// single short packet is not the end.
#define CDC_IDLE_GAP_MS 200
// Timeout for draining stale bulk IN data before a new command.
#define CDC_DRAIN_TIMEOUT_MS 20

typedef enum {
    CDC_REQ_LINE_CODING = 0,
    CDC_REQ_LINE_CODING_WAIT,
    CDC_REQ_CTRL_STATE,
    CDC_REQ_CTRL_STATE_WAIT,
    CDC_REQ_DONE,
    CDC_REQ_FAIL
} cdc_req_state_type;

typedef struct {
    uint8_t ctrl_if;          // communication interface number (SET_LINE_CODING wIndex)
    uint8_t bulk_in;          // bulk IN endpoint address (0x8x)
    uint8_t bulk_out;         // bulk OUT endpoint address (0x0x)
    uint16_t bulk_in_mp;      // bulk IN max packet size
    uint16_t bulk_out_mp;     // bulk OUT max packet size
    linecoding_type line;     // active line coding
    cdc_req_state_type req_state;
} cdc_ctx_type;

static otg_core_type g_otg;
static cdc_ctx_type g_cdc;
static bool g_initialized = false;
static bool g_connected = false;

static uint8_t g_ch_in;
static uint8_t g_ch_out;
static bool g_channels_open = false;
static uint8_t s_rx_staging[64] __attribute__((aligned(4)));

static usbh_class_handler_type g_cdc_class_handler;
static usbh_user_handler_type g_usbhost_user_handler;

// ---------------------------------------------------------------------------
// user callbacks (required by usbh_core_type; most are unused stubs)
// ---------------------------------------------------------------------------

static usb_sts_type usbhost_user_init(void) {
    return USB_OK;
}

static usb_sts_type usbhost_user_reset(void) {
    return USB_OK;
}

static usb_sts_type usbhost_user_attached(void) {
    return USB_OK;
}

static usb_sts_type usbhost_user_disconnect(void) {
    g_connected = false;
    g_channels_open = false;
    return USB_OK;
}

static usb_sts_type usbhost_user_speed(uint8_t speed) {
    (void)speed;
    return USB_OK;
}

static usb_sts_type usbhost_user_mfc_string(void *p) {
    (void)p;
    return USB_OK;
}

static usb_sts_type usbhost_user_product_string(void *p) {
    (void)p;
    return USB_OK;
}

static usb_sts_type usbhost_user_serial_string(void *p) {
    (void)p;
    return USB_OK;
}

static usb_sts_type usbhost_user_enum_done(void) {
    return USB_OK;
}

static usb_sts_type usbhost_user_application(void) {
    return USB_OK;
}

static usb_sts_type usbhost_user_active_vbus(void *uhost, confirm_state state) {
    (void)uhost;
    (void)state;
    return USB_OK;
}

static usb_sts_type usbhost_user_not_support(void) {
    return USB_OK;
}

// ---------------------------------------------------------------------------
// CDC class callbacks
// ---------------------------------------------------------------------------

static void cdc_setup_line_coding(usbh_core_type *uhost) {
    g_cdc.line.bitrate = CDC_LINE_CODING_115200;
    g_cdc.line.format = 0;               // 1 stop bit
    g_cdc.line.parity = 0;               // none
    g_cdc.line.data = CDC_LINE_CODING_BITS;

    uhost->ctrl.setup.bmRequestType = USB_DIR_H2D | USB_REQ_TYPE_CLASS | USB_REQ_RECIPIENT_INTERFACE;
    uhost->ctrl.setup.bRequest = SET_LINE_CODING;
    uhost->ctrl.setup.wValue = 0;
    uhost->ctrl.setup.wIndex = g_cdc.ctrl_if;
    uhost->ctrl.setup.wLength = (uint16_t)sizeof(linecoding_type);

    // usbh_ctrl_request only queues when req_state == CMD_SEND; reset it first.
    uhost->req_state = CMD_SEND;
    usbh_ctrl_request(uhost, (uint8_t *)&g_cdc.line, (uint16_t)sizeof(linecoding_type));
}

static void cdc_setup_control_line_state(usbh_core_type *uhost) {
    uhost->ctrl.setup.bmRequestType = USB_DIR_H2D | USB_REQ_TYPE_CLASS | USB_REQ_RECIPIENT_INTERFACE;
    uhost->ctrl.setup.bRequest = CDC_SET_CONTROL_LINE_STATE;
    uhost->ctrl.setup.wValue = CDC_CTRL_LINE_DTR_RTS;
    uhost->ctrl.setup.wIndex = g_cdc.ctrl_if;
    uhost->ctrl.setup.wLength = 0;

    // Reset req_state (left at CMD_WAIT by the previous transfer) or this
    // request is dropped and DTR/RTS is never asserted.
    uhost->req_state = CMD_SEND;
    usbh_ctrl_request(uhost, NULL, 0);
}

static usb_sts_type cdc_class_init(void *phost) {
    usbh_core_type *uhost = (usbh_core_type *)phost;
    usb_cfg_desc_type *cfg = &uhost->dev.cfg_desc;
    uint8_t i, e;
    bool have_in = false, have_out = false;

    g_cdc.ctrl_if = 0;
    g_cdc.bulk_in = 0;
    g_cdc.bulk_out = 0;
    g_cdc.bulk_in_mp = USB_MAX_EP0_SIZE;
    g_cdc.bulk_out_mp = USB_MAX_EP0_SIZE;
    g_cdc.req_state = CDC_REQ_LINE_CODING;

    for (i = 0; i < cfg->cfg.bNumInterfaces && i < USBH_MAX_INTERFACE; i++) {
        usb_itf_desc_type *itf = &cfg->interface[i];
        if (itf->interface.bInterfaceClass == USB_CLASS_CODE_CDC) {
            g_cdc.ctrl_if = itf->interface.bInterfaceNumber;
        }
        for (e = 0; e < itf->interface.bNumEndpoints && e < USBH_MAX_ENDPOINT; e++) {
            usb_endpoint_desc_type *ep = &itf->endpoint[e];
            if ((ep->bmAttributes & 0x03) != USB_EPT_DESC_BULK) {
                continue;
            }
            if (ep->bEndpointAddress & 0x80) {
                g_cdc.bulk_in = ep->bEndpointAddress;
                g_cdc.bulk_in_mp = ep->wMaxPacketSize;
                have_in = true;
            } else {
                g_cdc.bulk_out = ep->bEndpointAddress;
                g_cdc.bulk_out_mp = ep->wMaxPacketSize;
                have_out = true;
            }
        }
    }

    // Full-speed bulk endpoints never exceed 64 bytes; clamp so the bounce
    // buffer in pm5_icsd_read_response() can never overflow.
    if (g_cdc.bulk_in_mp == 0 || g_cdc.bulk_in_mp > USB_MAX_EP0_SIZE) {
        g_cdc.bulk_in_mp = USB_MAX_EP0_SIZE;
    }
    if (g_cdc.bulk_out_mp == 0 || g_cdc.bulk_out_mp > USB_MAX_EP0_SIZE) {
        g_cdc.bulk_out_mp = USB_MAX_EP0_SIZE;
    }

    if (!have_in || !have_out || g_cdc.bulk_in == 0 || g_cdc.bulk_out == 0) {
        return USB_NOT_SUPPORT;
    }
    return USB_OK;
}

static usb_sts_type cdc_class_reset(void *phost) {
    (void)phost;
    g_connected = false;
    g_channels_open = false;
    g_cdc.req_state = CDC_REQ_LINE_CODING;
    return USB_OK;
}

static usb_sts_type cdc_class_request(void *phost) {
    usbh_core_type *uhost = (usbh_core_type *)phost;
    usb_sts_type status;

    switch (g_cdc.req_state) {
        case CDC_REQ_LINE_CODING:
            cdc_setup_line_coding(uhost);
            g_cdc.req_state = CDC_REQ_LINE_CODING_WAIT;
            return USB_WAIT;

        case CDC_REQ_LINE_CODING_WAIT:
            status = usbh_ctrl_transfer_loop(uhost);
            if (status == USB_WAIT) {
                return USB_WAIT;
            }
            if (status == USB_ERROR) {
                g_cdc.req_state = CDC_REQ_FAIL;
                return USB_ERROR;
            }
            // OK or NOT_SUPPORT (device without ACM): proceed to DTR/RTS.
            g_cdc.req_state = CDC_REQ_CTRL_STATE;
            return USB_WAIT;

        case CDC_REQ_CTRL_STATE:
            cdc_setup_control_line_state(uhost);
            g_cdc.req_state = CDC_REQ_CTRL_STATE_WAIT;
            return USB_WAIT;

        case CDC_REQ_CTRL_STATE_WAIT:
            status = usbh_ctrl_transfer_loop(uhost);
            if (status == USB_WAIT) {
                return USB_WAIT;
            }
            if (status == USB_OK) {
                g_cdc.req_state = CDC_REQ_DONE;
                return USB_OK;
            }
            g_cdc.req_state = CDC_REQ_FAIL;
            return USB_ERROR;

        case CDC_REQ_DONE:
            return USB_OK;

        case CDC_REQ_FAIL:
        default:
            return USB_ERROR;
    }
}

static usb_sts_type cdc_class_process(void *phost) {
    (void)phost;
    g_connected = true;
    return USB_OK;
}

// ---------------------------------------------------------------------------
// bulk transfer helpers
// ---------------------------------------------------------------------------

static bool cdc_ensure_channels(usbh_core_type *uhost) {
    uint16_t ch;

    if (!g_connected) {
        return false;
    }
    if (g_channels_open) {
        return true;
    }

    ch = usbh_alloc_channel(uhost, g_cdc.bulk_in);
    if (ch == (uint16_t)USB_FAIL || ch >= (uint16_t)USB_HOST_CHANNEL_NUM) {
        return false;
    }
    g_ch_in = (uint8_t)ch;
    usbh_hc_open(uhost, g_ch_in, g_cdc.bulk_in, uhost->dev.address,
                 EPT_BULK_TYPE, g_cdc.bulk_in_mp, uhost->dev.speed);

    ch = usbh_alloc_channel(uhost, g_cdc.bulk_out);
    if (ch == (uint16_t)USB_FAIL || ch >= (uint16_t)USB_HOST_CHANNEL_NUM) {
        usbh_free_channel(uhost, g_ch_in);
        return false;
    }
    g_ch_out = (uint8_t)ch;
    usbh_hc_open(uhost, g_ch_out, g_cdc.bulk_out, uhost->dev.address,
                 EPT_BULK_TYPE, g_cdc.bulk_out_mp, uhost->dev.speed);

    g_channels_open = true;
    return true;
}

// Wait for a channel to reach a terminal URB state. Returns 0 when URB_DONE,
// -1 on error/stall/timeout.
static int cdc_wait_channel(usbh_core_type *uhost, uint8_t ch, uint32_t timeout_ms) {
    uint32_t start = GetTickCount();
    while (GetTickCountDelta(start) < timeout_ms) {
        urb_sts_type st = usbh_get_urb_status(uhost, ch);
        if (st == URB_DONE) {
            return 0;
        }
        if (st == URB_STALL || st == URB_ERROR) {
            return -1;
        }
    }
    return -1;
}

static int cdc_bulk_out(usbh_core_type *uhost, const uint8_t *buf, uint16_t len, uint32_t timeout_ms) {
    if (!cdc_ensure_channels(uhost)) {
        return -1;
    }
    usbh_bulk_send(uhost, g_ch_out, (uint8_t *)buf, len);
    return cdc_wait_channel(uhost, g_ch_out, timeout_ms);
}

// Received bytes are tracked by the RX-FIFO ISR in hch[].trans_count, the
// authoritative count; HCTSIZ's remaining-size field can lag the FIFO drain.
static int cdc_bulk_in(usbh_core_type *uhost, uint8_t *buf, uint16_t len, uint32_t timeout_ms) {
    uint32_t got;

    if (!cdc_ensure_channels(uhost)) {
        return -1;
    }
    usbh_bulk_recv(uhost, g_ch_in, s_rx_staging, len);
    if (cdc_wait_channel(uhost, g_ch_in, timeout_ms) != 0) {
        usbh_ch_disable(uhost, g_ch_in);
        return -1;
    }

    got = uhost->hch[g_ch_in].trans_count;
    if (got > len) {
        got = len;
    }
    usbh_ch_disable(uhost, g_ch_in);
    if (got > 0 && buf != NULL) {
        memcpy(buf, s_rx_staging, got);
    }
    return (int)got;
}

// Discard stale bulk IN data so a previous, partially-read reply cannot leak
// into the next command's response.
static void cdc_drain_rx(usbh_core_type *uhost) {
    int i;

    if (!g_connected || !g_channels_open) {
        return;
    }
    for (i = 0; i < 8; i++) {
        if (cdc_bulk_in(uhost, NULL, sizeof(s_rx_staging), CDC_DRAIN_TIMEOUT_MS) <= 0) {
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// public API
// ---------------------------------------------------------------------------

void pm5_usb_host_cdc_init(void) {
    gpio_init_type gpio_init_struct;

    if (g_initialized) {
        return;
    }

    // The 48 MHz USB clock and ACC SOF trim are already set up at boot for the
    // device port (OTGFS2 owns ACC_SOF_OTG2 for the PC client link). Don't touch
    // the ACC here: stealing the SOF trim (ACC_SOF_OTG1) breaks OTGFS2
    // enumeration. OTGFS1 shares the same 48 MHz clock.

    // OTGFS1 (host) peripheral clock + DP/DM pins.
    crm_periph_clock_enable(USB_HOST_CLOCK, TRUE);
    crm_periph_clock_enable(USB_HOST_PIN_GPIO_CLOCK, TRUE);

    gpio_default_para_init(&gpio_init_struct);
    gpio_init_struct.gpio_drive_strength = GPIO_DRIVE_STRENGTH_STRONGER;
    gpio_init_struct.gpio_out_type = GPIO_OUTPUT_PUSH_PULL;
    gpio_init_struct.gpio_mode = GPIO_MODE_MUX;
    gpio_init_struct.gpio_pull = GPIO_PULL_NONE;
    gpio_init_struct.gpio_pins = USB_HOST_PIN_DP | USB_HOST_PIN_DM;
    gpio_init(USB_HOST_PIN_GPIO, &gpio_init_struct);
    gpio_pin_mux_config(USB_HOST_PIN_GPIO, USB_HOST_PIN_DP_SOURCE, USB_HOST_PIN_MUX);
    gpio_pin_mux_config(USB_HOST_PIN_GPIO, USB_HOST_PIN_DM_SOURCE, USB_HOST_PIN_MUX);

    /* Artery host core is interrupt-driven: only usbh_irq_handler() clears the
       port/channel/RX-FIFO interrupts and sets conn_sts, port_enable, URB_DONE.
       The NVIC line must be enabled too, or the FSM never leaves USBH_IDLE. Set
       g_initialized first - a pending SOF/port interrupt must find the ISR ready
       to service it, not skip it and storm. Priority 5 (low) so OTGFS1 can't
       preempt or starve the OTGFS2 client link, which sits at priority 0. */
    usbh_init(&g_otg, USB_FULL_SPEED_CORE_ID, USB_OTG1_ID, &g_cdc_class_handler, &g_usbhost_user_handler);

    g_connected = false;
    g_channels_open = false;
    g_initialized = true;

    NVIC_ClearPendingIRQ(USB_HOST_IRQ);
    nvic_irq_enable(USB_HOST_IRQ, 5, 0);
}

void pm5_usb_host_cdc_deinit(void) {
    if (!g_initialized) {
        return;
    }
    if (g_channels_open) {
        usbh_ch_disable(&g_otg.host, g_ch_in);
        usbh_ch_disable(&g_otg.host, g_ch_out);
        usbh_free_channel(&g_otg.host, g_ch_in);
        usbh_free_channel(&g_otg.host, g_ch_out);
        g_channels_open = false;
    }
    nvic_irq_disable(USB_HOST_IRQ);
    NVIC_ClearPendingIRQ(USB_HOST_IRQ);
    g_otg.host.usb_reg->gintmsk &= ~USB_OTG_SOF_INT;
    usb_port_power_on(g_otg.host.usb_reg, FALSE);
    g_connected = false;
    g_initialized = false;
    crm_periph_clock_enable(CRM_OTGFS1_PERIPH_CLOCK, FALSE);
}

void pm5_usb_host_cdc_poll(void) {
    if (!g_initialized || !cep_is_usb_host_active()) {
        return;
    }

    /* Pump Artery's host state machine */
    usbh_loop_handler(&g_otg.host);
}

void pm5_icsd_get_debug_state(uint8_t *initialized, uint8_t *connected,
                              uint8_t *global_state, uint8_t *enum_state, uint8_t *req_state,
                              uint8_t *conn_sts, uint8_t *port_enable) {
    if (initialized)  *initialized  = g_initialized ? 1 : 0;
    if (connected)    *connected    = g_connected ? 1 : 0;
    if (global_state) *global_state = g_otg.host.global_state;
    if (enum_state)   *enum_state   = g_otg.host.enum_state;
    if (req_state)    *req_state    = g_otg.host.req_state;
    if (conn_sts)     *conn_sts     = (uint8_t)g_otg.host.conn_sts;
    if (port_enable)  *port_enable  = (uint8_t)g_otg.host.port_enable;
}

bool pm5_icsd_is_connected(void) {
    return g_connected;
}

static void cdc_wait_connected(uint32_t timeout_ms) {
    uint32_t start = GetTickCount();
    while (!g_connected) {
        pm5_usb_host_cdc_poll();
        if (GetTickCountDelta(start) >= timeout_ms) {
            break;
        }
        SpinDelayUs(1000);
    }
}

int pm5_icsd_send_cmd(const char *cmd) {
    if (cmd == NULL) {
        return -1;
    }
    if (!g_initialized) {
        cep_ensure_usb_host_mode();
    }
    if (!g_connected) {
        cdc_wait_connected(500);
    }
    if (!g_connected) {
        return -1;
    }

    // Discard stale bulk IN data from a previous, partially-read reply.
    cdc_drain_rx(&g_otg.host);

    char tx_buf[64];
    size_t len = strlen(cmd);
    if (len == 0 || len > sizeof(tx_buf) - 3) {
        return -1;
    }
    memcpy(tx_buf, cmd, len);
    if (tx_buf[len - 1] != '\n') {
        if (tx_buf[len - 1] == '\r') {
            tx_buf[len++] = '\n';
        } else {
            tx_buf[len++] = '\r';
            tx_buf[len++] = '\n';
        }
    }
    tx_buf[len] = '\0';

    return (cdc_bulk_out(&g_otg.host, (const uint8_t *)tx_buf, (uint16_t)len, CDC_XFER_TIMEOUT_MS) == 0) ? 0 : -1;
}

int pm5_icsd_read_response(char *buf, size_t max_len, uint32_t timeout_ms) {
    uint8_t chunk_buf[USB_MAX_EP0_SIZE];
    size_t total = 0;
    bool got_any = false;

    if (buf == NULL) {
        return -1;
    }
    if (max_len == 0) {
        return 0;
    }
    if (!g_initialized) {
        cep_ensure_usb_host_mode();
    }
    if (!g_connected) {
        cdc_wait_connected(500);
    }
    if (!g_connected) {
        return -1;
    }
    // Keep one byte for the NUL terminator.
    while (total + 1 < max_len) {
        size_t room = max_len - 1 - total;
        uint16_t chunk = (uint16_t)((room >= (size_t)g_cdc.bulk_in_mp) ? g_cdc.bulk_in_mp : room);
        // First byte: generous timeout; afterwards a short idle gap ends the stream.
        uint32_t wait = got_any ? CDC_IDLE_GAP_MS : timeout_ms;
        int got = cdc_bulk_in(&g_otg.host, chunk_buf, chunk, wait);
        size_t n;

        // No (more) data: end of stream. Return what we have, if any.
        if (got <= 0) {
            break;
        }
        n = (size_t)got;
        if (n > (size_t)chunk) {
            n = (size_t)chunk;
        }
        memcpy(buf + total, chunk_buf, n);
        total += n;
        got_any = true;
        // A short packet is not the end for this device; keep reading until
        // the idle gap expires.
    }
    buf[total] = '\0';
    return got_any ? (int)total : -1;
}

// OTGFS1 interrupt. Only usbh_irq_handler() clears port/channel/RX-FIFO
// interrupts and drives URB_DONE; without this ISR the host core stalls in
// USBH_IDLE. A pending pre-init interrupt is disabled to avoid re-entry.
void OTGFS1_IRQHandler(void) {
    if (g_initialized) {
        usbh_irq_handler(&g_otg);
    } else {
        nvic_irq_disable(USB_HOST_IRQ);
    }
}

// ---------------------------------------------------------------------------
// handler tables (referenced above; keep at end for readability)
// ---------------------------------------------------------------------------

static usbh_class_handler_type g_cdc_class_handler = {
    .init_handler = cdc_class_init,
    .reset_handler = cdc_class_reset,
    .request_handler = cdc_class_request,
    .process_handler = cdc_class_process,
    .pdata = NULL,
};

static usbh_user_handler_type g_usbhost_user_handler = {
    .user_init = usbhost_user_init,
    .user_reset = usbhost_user_reset,
    .user_attached = usbhost_user_attached,
    .user_disconnect = usbhost_user_disconnect,
    .user_speed = usbhost_user_speed,
    .user_mfc_string = usbhost_user_mfc_string,
    .user_product_string = usbhost_user_product_string,
    .user_serial_string = usbhost_user_serial_string,
    .user_enumeration_done = usbhost_user_enum_done,
    .user_application = usbhost_user_application,
    .user_active_vbus = usbhost_user_active_vbus,
    .user_not_support = usbhost_user_not_support,
};
