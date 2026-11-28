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
// Proxmark5 USB host on the CEP (Type-C Extended Port), OTGFS1
//-----------------------------------------------------------------------------

#define USE_OTG_HOST_MODE
#include "../armlib/at32_usb/usb_conf.h"
#include "pm5_cep_usb_host.h"
#include "ccid_reader.h"
#include "at32f435_437_crm.h"
#include "at32f435_437_gpio.h"
#include "at32f435_437_misc.h"
#include "usbh_int.h"
#include "i2c_apis.h"
#include "ticks_apis.h"
#include "pm5_power.h"
#include "string.h"

#define CEP_USB_HOST_START_DELAY_MS 150   // VBUS on the port settles
#define CEP_USB_HOST_NAME_MAX       32

// TUSB320, the CC controller of the port
#define CEP_CC_CONTROLLER_ADDR      0x47
#define CEP_CC_STATUS_REG           0x09
#define CEP_CC_ATTACHED_SRC         0x01  // attach state: the PM5 powers the port
#define CEP_CC_INT_LATCH            0x10
#define CEP_CC_POLL_MS              50
#define CEP_CC_READ_FAILS_MAX       3     // consecutive failed CC reads that count as a detach

static otg_core_type s_otg;
static usbh_class_handler_type s_class_handler;
static usbh_user_handler_type s_user_handler;
static bool s_started;
static bool s_failed;
static uint8_t s_fail_error;    // class driver error that stopped the host
static bool s_fail_unsupported; // the class driver did not take the device
static bool s_source_attached;
static uint32_t s_source_since;
static uint32_t s_sync_tick;    // GetTickCount() at the last host timer sync
static uint32_t s_sync_timer;   // host timer at the last sync
static bool s_clock_held;       // this host keeps the core at full speed
static char s_product[CEP_USB_HOST_NAME_MAX];

static usb_sts_type user_init(void) {
    return USB_OK;
}

static usb_sts_type user_reset(void) {
    return USB_OK;
}

static usb_sts_type user_attached(void) {
    return USB_OK;
}

static usb_sts_type user_disconnect(void) {
    ccid_reader_reset_handler(&s_otg.host);
    return USB_OK;
}

static usb_sts_type user_speed(uint8_t speed) {
    (void)speed;
    return USB_OK;
}

static usb_sts_type user_string(void *data) {
    (void)data;
    return USB_OK;
}

// The host library hands the product string over as ASCII: keep its printable start.
static usb_sts_type user_product(void *data) {
    const uint8_t *text = data;
    uint8_t n = 0;
    if (s_otg.host.dev.dev_desc.iProduct) {
        while (n < sizeof(s_product) - 1 && text[n] >= 0x20 && text[n] < 0x7F) {
            s_product[n] = (char)text[n];
            n++;
        }
    }
    s_product[n] = '\0';
    return USB_OK;
}

static usb_sts_type user_enumeration_done(void) {
    return USB_OK;
}

static usb_sts_type user_application(void) {
    return USB_OK;
}

static usb_sts_type user_active_vbus(void *data, confirm_state state) {
    (void)data;
    (void)state;
    return USB_OK;
}

static usb_sts_type user_not_support(void) {
    return USB_NOT_SUPPORT;
}

// The IRQ handler only serves a started host: mask it before s_started drops,
// or a pending OTG IRQ re-enters forever.
static void host_irq_disable(void) {
    nvic_irq_disable(OTGFS1_IRQn);
    NVIC_ClearPendingIRQ(OTGFS1_IRQn);
}

static void host_init(void) {
    host_irq_disable();
    s_started = false;

    crm_periph_clock_enable(CRM_GPIOA_PERIPH_CLOCK, TRUE);
    crm_periph_clock_enable(CRM_OTGFS1_PERIPH_CLOCK, TRUE);

    gpio_init_type gpio;
    gpio_default_para_init(&gpio);
    gpio.gpio_drive_strength = GPIO_DRIVE_STRENGTH_STRONGER;
    gpio.gpio_out_type = GPIO_OUTPUT_PUSH_PULL;
    gpio.gpio_mode = GPIO_MODE_MUX;
    gpio.gpio_pull = GPIO_PULL_NONE;
    gpio.gpio_pins = GPIO_PINS_11 | GPIO_PINS_12;
    gpio_init(GPIOA, &gpio);
    gpio_pin_mux_config(GPIOA, GPIO_PINS_SOURCE11, GPIO_MUX_10);
    gpio_pin_mux_config(GPIOA, GPIO_PINS_SOURCE12, GPIO_MUX_10);

    s_class_handler.init_handler = ccid_reader_init_handler;
    s_class_handler.request_handler = ccid_reader_request_handler;
    s_class_handler.process_handler = ccid_reader_process_handler;
    s_class_handler.reset_handler = ccid_reader_reset_handler;
    s_class_handler.pdata = NULL;
    s_user_handler.user_init = user_init;
    s_user_handler.user_reset = user_reset;
    s_user_handler.user_attached = user_attached;
    s_user_handler.user_disconnect = user_disconnect;
    s_user_handler.user_speed = user_speed;
    s_user_handler.user_mfc_string = user_string;
    s_user_handler.user_product_string = user_product;
    s_user_handler.user_serial_string = user_string;
    s_user_handler.user_enumeration_done = user_enumeration_done;
    s_user_handler.user_application = user_application;
    s_user_handler.user_active_vbus = user_active_vbus;
    s_user_handler.user_not_support = user_not_support;

    memset(&s_otg, 0, sizeof(s_otg));
    s_product[0] = '\0';
    s_otg.usb_reg = usb_global_select_core(USB_OTG1_ID);
    usbh_core_init(&s_otg.host, s_otg.usb_reg, &s_class_handler,
                   &s_user_handler, USB_FULL_SPEED_CORE_ID);
    // The host IRQ handler does not clear the suspend flag.
    s_otg.usb_reg->gintmsk &= ~USB_OTG_USBSUSP_INT;
    usb_global_clear_interrupt(s_otg.usb_reg, USB_OTG_USBSUSP_FLAG);
    s_sync_tick = GetTickCount();
    s_sync_timer = s_otg.host.timer;
    s_started = true;
    nvic_irq_enable(OTGFS1_IRQn, 5, 0);
}

// enumeration and transfers need the full clock
static bool host_busy(void) {
    if (!s_started || !s_otg.host.conn_sts) {
        return false;
    }
    return s_otg.host.global_state != USBH_CLASS || ccid_reader_busy();
}

static void host_clock_hold(bool hold) {
    if (hold && !s_clock_held) {
        pm5_power_boost();
        s_clock_held = true;
    } else if (!hold && s_clock_held) {
        pm5_power_unboost();
        s_clock_held = false;
    }
}

// Common part of a stop: the core is quiet, the class driver forgets the device.
static void host_halt(void) {
    host_irq_disable();
    s_started = false;
    usb_interrupt_disable(s_otg.usb_reg);
    usb_port_power_on(s_otg.usb_reg, FALSE);
    ccid_reader_reset_handler(&s_otg.host);
    host_clock_hold(false);
}

static void host_stop(void) {
    // a host stopped by an error still holds the core and stale device state
    if (!s_started && !s_failed) {
        return;
    }
    host_halt();
    usb_host_disable(s_otg.usb_reg);
    usb_global_reset(s_otg.usb_reg);
    s_failed = false;
    memset(&s_otg.host, 0, sizeof(s_otg.host));
    s_product[0] = '\0';
    crm_periph_clock_enable(CRM_OTGFS1_PERIPH_CLOCK, FALSE);
}

static void host_source_update(bool source) {
    if (source != s_source_attached) {
        if (!source) {
            host_stop();
        }
        s_source_attached = source;
        s_source_since = GetTickCount();
        s_failed = false;
    }
}

// The CC controller says who powers the port: the host runs only while the PM5 does.
static void cc_poll(void) {
    static uint32_t last_tick;
    static uint8_t read_fails;

    if ((last_tick != 0) && (GetTickCountDelta(last_tick) < CEP_CC_POLL_MS)) {
        return;
    }
    last_tick = GetTickCount();

    // LF/HF code stops the ticks timer that I2C needs
    StartTicks();
    I2C_init(true);

    uint8_t status;
    if (I2C_BufferRead(&status, 1, CEP_CC_STATUS_REG, CEP_CC_CONTROLLER_ADDR << 1) <= 0) {
        // one failed read is bus noise, not a detach
        if (read_fails < CEP_CC_READ_FAILS_MAX) {
            read_fails++;
        }
        if (read_fails == CEP_CC_READ_FAILS_MAX) {
            host_source_update(false);
        }
        return;
    }
    read_fails = 0;

    host_source_update(((status >> 6) & 0x03) == CEP_CC_ATTACHED_SRC);

    // writing the latch bit back clears it
    if (status & CEP_CC_INT_LATCH) {
        I2C_BufferWrite(&status, 1, CEP_CC_STATUS_REG, CEP_CC_CONTROLLER_ADDR << 1);
    }
}

void cep_usb_host_poll(void) {
    cc_poll();
    cep_usb_host_task();
}

bool cep_usb_host_restart(void) {
    // a device the class driver turned down stays turned down until it is unplugged
    if (s_failed && s_fail_unsupported == false && ccid_reader_error_is_final(s_fail_error) == false) {
        // cep_usb_host_task() starts the host again
        usb_host_disable(s_otg.usb_reg);
        usb_global_reset(s_otg.usb_reg);
        s_failed = false;
        s_source_since = GetTickCount();
    }
    return s_source_attached;
}

void cep_usb_host_task(void) {
    if (!s_source_attached) {
        return;
    }
    if (s_failed) {
        return;
    }
    if (!s_started) {
        if (GetTickCountDelta(s_source_since) < CEP_USB_HOST_START_DELAY_MS) {
            return;
        }
        host_init();
    }
    // Keep host timeouts moving before the core starts producing SOFs.
    // The SOF IRQ counts it too: add only the ms it has not counted since the last call.
    uint32_t now = GetTickCount();
    uint32_t elapsed = now - s_sync_tick;
    uint32_t counted = s_otg.host.timer - s_sync_timer;
    if (elapsed > counted) {
        s_otg.host.timer += elapsed - counted;
    }
    s_sync_tick = now;
    s_sync_timer = s_otg.host.timer;
    host_clock_hold(host_busy());
    usbh_loop_handler(&s_otg.host);
    if (s_otg.host.global_state == USBH_ERROR_STATE ||
            s_otg.host.global_state == USBH_UNSUPPORT) {
        s_failed = true;
        s_fail_error = ccid_reader_error();
        s_fail_unsupported = s_otg.host.global_state == USBH_UNSUPPORT;
        host_halt();
    }
}

bool cep_usb_host_ready(void) {
    return s_started && ccid_reader_ready();
}

bool cep_usb_host_connected(void) {
    return s_otg.host.conn_sts != 0;
}

uint16_t cep_usb_host_vid(void) {
    return s_otg.host.dev.dev_desc.idVendor;
}

uint16_t cep_usb_host_pid(void) {
    return s_otg.host.dev.dev_desc.idProduct;
}

uint16_t cep_usb_host_release(void) {
    return s_otg.host.dev.dev_desc.bcdDevice;
}

const char *cep_usb_host_product(void) {
    return s_product;
}

bool cep_usb_host_failed(void) {
    return s_failed;
}

const char *cep_usb_host_failure(void) {
    if (s_fail_unsupported) {
        return "not a CCID reader";
    }
    if (s_fail_error != CCID_ERROR_NONE) {
        return ccid_reader_error_text(s_fail_error);
    }
    return "enumeration failed";
}

void OTGFS1_IRQHandler(void) {
    if (s_started) {
        usbh_irq_handler(&s_otg);
    }
}
