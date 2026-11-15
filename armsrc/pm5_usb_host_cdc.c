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

#include "usb_conf.h"
#include "usb_core.h"
#include "usb_std.h"
#include "usbh_core.h"
#include "usbh_ctrl.h"
#include "usbh_int.h"

#include "at32f435_437_crm.h"
#include "at32f435_437_gpio.h"
#include "at32f435_437_misc.h"
#include "at32f435_437_acc.h"

// CDC-ACM class request not exposed by usb_std.h.
#define CDC_SET_CONTROL_LINE_STATE 0x22
// DTR | RTS, per the ACM SET_CONTROL_LINE_STATE wValue.
#define CDC_CTRL_LINE_DTR_RTS 0x0003
// 115200 baud, 1 stop bit, no parity, 8 data bits.
#define CDC_LINE_CODING_115200 115200
#define CDC_LINE_CODING_BITS 8

// Spin budget for a blocking transfer. Each iteration reads one volatile
// register, so this is a rough wall-clock stand-in: long enough that a real
// device answers, short enough not to hang the main loop on a dead link.
#define CDC_SPINS_PER_MS 2000
#define CDC_XFER_SPINS 200000

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

    usbh_ctrl_request(uhost, (uint8_t *)&g_cdc.line, (uint16_t)sizeof(linecoding_type));
}

static void cdc_setup_control_line_state(usbh_core_type *uhost) {
    uhost->ctrl.setup.bmRequestType = USB_DIR_H2D | USB_REQ_TYPE_CLASS | USB_REQ_RECIPIENT_INTERFACE;
    uhost->ctrl.setup.bRequest = CDC_SET_CONTROL_LINE_STATE;
    uhost->ctrl.setup.wValue = CDC_CTRL_LINE_DTR_RTS;
    uhost->ctrl.setup.wIndex = g_cdc.ctrl_if;
    uhost->ctrl.setup.wLength = 0;

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

static bool cdc_wait_channel(usbh_core_type *uhost, uint8_t ch, uint32_t spins) {
    while (spins--) {
        urb_sts_type st = usbh_get_urb_status(uhost, ch);
        if (st != URB_IDLE && st != URB_NOTREADY) {
            return true;
        }
    }
    return false;
}

static int cdc_bulk_out(usbh_core_type *uhost, const uint8_t *buf, uint16_t len) {
    if (!cdc_ensure_channels(uhost)) {
        return -1;
    }
    usbh_bulk_send(uhost, g_ch_out, (uint8_t *)buf, len);
    if (!cdc_wait_channel(uhost, g_ch_out, CDC_XFER_SPINS)) {
        return -1;
    }
    return (usbh_get_urb_status(uhost, g_ch_out) == URB_DONE) ? 0 : -1;
}

static int cdc_bulk_in(usbh_core_type *uhost, uint8_t *buf, uint16_t len, uint32_t spins) {
    uint32_t expected, remain, got;

    if (!cdc_ensure_channels(uhost)) {
        return -1;
    }
    usbh_bulk_recv(uhost, g_ch_in, buf, len);
    if (!cdc_wait_channel(uhost, g_ch_in, spins)) {
        return -1;
    }
    if (usbh_get_urb_status(uhost, g_ch_in) != URB_DONE) {
        return -1;
    }

    // The driver rounds the request up to a whole packet; the register holds
    // how many bytes are still pending, so received = expected - remaining.
    expected = ((uint32_t)len + g_cdc.bulk_in_mp - 1) / g_cdc.bulk_in_mp * g_cdc.bulk_in_mp;
    remain = USB_CHL(uhost->usb_reg, g_ch_in)->hctsiz_bit.xfersize;
    got = (expected > remain) ? (expected - remain) : 0;
    if (got > len) {
        got = len;
    }
    return (int)got;
}

// ---------------------------------------------------------------------------
// public API
// ---------------------------------------------------------------------------

void pm5_usb_host_cdc_init(void) {
    gpio_init_type gpio_init_struct;

    if (g_initialized) {
        return;
    }

    // USB 48 MHz: HICK + ACC trim, the same source the device port uses.
    crm_usb_clock_source_select(CRM_USB_CLOCK_SOURCE_HICK);
    crm_periph_clock_enable(CRM_ACC_PERIPH_CLOCK, TRUE);
    acc_write_c1(7980);
    acc_write_c2(8000);
    acc_write_c3(8020);
    acc_sof_select(ACC_SOF_OTG1);
    acc_calibration_mode_enable(ACC_CAL_HICKTRIM, TRUE);

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

    nvic_irq_enable(USB_HOST_IRQ, 0, 0);
    usbh_init(&g_otg, USB_FULL_SPEED_CORE_ID, USB_OTG1_ID, &g_cdc_class_handler, &g_usbhost_user_handler);

    g_connected = false;
    g_channels_open = false;
    g_initialized = true;
}

void pm5_usb_host_cdc_deinit(void) {
    if (!g_initialized) {
        return;
    }
    nvic_irq_disable(USB_HOST_IRQ);
    NVIC_ClearPendingIRQ(USB_HOST_IRQ);
    g_connected = false;
    g_channels_open = false;
    g_initialized = false;
}

void pm5_usb_host_cdc_poll(void) {
    if (!g_initialized) {
        return;
    }
    usbh_loop_handler(&g_otg.host);
}

bool pm5_icsd_is_connected(void) {
    return g_connected;
}

int pm5_icsd_send_cmd(const char *cmd) {
    uint16_t len = 0;

    if (cmd == NULL || !g_connected) {
        return -1;
    }
    while (len < 0xFFFF && cmd[len] != '\0') {
        len++;
    }
    if (len == 0) {
        return 0;
    }
    return (cdc_bulk_out(&g_otg.host, (const uint8_t *)cmd, len) == 0) ? 0 : -1;
}

int pm5_icsd_read_response(char *buf, size_t max_len, uint32_t timeout_ms) {
    uint8_t chunk_buf[USB_MAX_EP0_SIZE];
    uint32_t spins;
    size_t total = 0;

    if (buf == NULL || !g_connected) {
        return -1;
    }
    spins = (timeout_ms > 0) ? (timeout_ms * CDC_SPINS_PER_MS) : CDC_XFER_SPINS;
    if (spins == 0) {
        spins = CDC_XFER_SPINS;
    }

    while (total < max_len) {
        uint16_t chunk = (uint16_t)((max_len - total >= (size_t)g_cdc.bulk_in_mp) ? g_cdc.bulk_in_mp : (max_len - total));
        int got = cdc_bulk_in(&g_otg.host, chunk_buf, chunk, spins);
        size_t n;

        if (got <= 0) {
            return (total > 0) ? (int)total : -1;
        }
        n = (size_t)got;
        if (n > (size_t)chunk) {
            n = (size_t)chunk;
        }
        for (size_t k = 0; k < n; k++) {
            buf[total + k] = (char)chunk_buf[k];
        }
        total += n;

        // A short packet marks the end of the response.
        if ((size_t)got < (size_t)chunk) {
            break;
        }
    }
    return (int)total;
}

// ---------------------------------------------------------------------------
// OTGFS1 interrupt (weak Default_Handler in startup_at32f435_437.s)
// ---------------------------------------------------------------------------

void OTGFS1_IRQHandler(void) {
    usbh_irq_handler(&g_otg);
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
