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
// PM5 card side. The controller's I2C registers switch the card's voltage,
// activation and reset; the card's I/O line is wired straight to USART2, so
// the bytes on the wire are exactly what this file writes and reads. That also
// means the ISO 7816 T=0 dialogue is ours, not the controller's.
//-----------------------------------------------------------------------------
#include "smartcard_hw_pm5.h"

#include "smartcard_apis.h"
#include "smartcard_rate.h"

#include "at32f435_437.h"
#include "at32f435_437_crm.h"
#include "at32f435_437_gpio.h"
#include "at32f435_437_usart.h"
#include "at32f435_437_tmr.h"

#include "i2c_apis.h"
#include "gpio_apis.h"
#include "ticks_apis.h"
#include "dbprint.h"
#include "pm3_cmd.h"
#include "string.h"

// Smartcard mode is single wire on its own: the TX pin both sends and receives.
// Opening the half-duplex select as well masks the transmitted waveform.
#define SC_PM5_UART         USART2
#define SC_PM5_UART_CRM     CRM_USART2_PERIPH_CLOCK
#define SC_PM5_GPIO_CRM     CRM_GPIOA_PERIPH_CLOCK
#define SC_PM5_GPIO         GPIOA
#define SC_PM5_IO_PIN       GPIO_PINS_2
#define SC_PM5_IO_SRC       GPIO_PINS_SOURCE2
#define SC_PM5_IO_MUX       GPIO_MUX_7

// The card clock is not the USART's: a timer channel drives the front end's
// clock input, and the front end divides that down for the card.
#define SC_PM5_CLK_PIN      GPIO_PINS_3
#define SC_PM5_CLK_SRC      GPIO_PINS_SOURCE3
#define SC_PM5_CLK_MUX      GPIO_MUX_1
#define SC_PM5_CLK_TMR      TMR2
#define SC_PM5_CLK_CH       TMR_SELECT_CHANNEL_4
#define SC_PM5_CLKIN_HZ     7200000u

#define SC_PM5_DEFAULT_ETU  372
#define SC_PM5_GUARD_ETU    2

// Timeouts, in milliseconds. T=0 allows 960 etu of work waiting time, about
// 100 ms at the default rate, so the receive budget has to be larger than that.
#define SC_PM5_RX_TIMEOUT_MS    150
#define SC_PM5_TX_TIMEOUT_MS    50
#define SC_PM5_ATR_IDLE_MS      100
// Silence that ends a raw response, which has no length field of its own.
#define SC_PM5_RAW_GAP_MS       20
// Silence that ends a PPS response after its first byte.
#define SC_PM5_PPS_GAP_MS       10

// GetTicks() runs at 1.5 MHz, so a millisecond is 1500 ticks.
#define SC_PM5_TICKS_PER_MS     1500u

// Upper layers pass the adapter's I2C iteration budget; the USART waits take
// milliseconds.
static uint32_t wait_to_ms(uint32_t wait) {
    uint32_t ms = wait / I2C_ITERS_PER_MS;
    return (ms == 0) ? 1 : ms;
}

static uint32_t s_clkin_hz = SC_PM5_CLKIN_HZ;
static uint32_t s_card_clk_hz = SC_PM5_DEFAULT_CARD_CLK_HZ;
static uint8_t s_clk_div = SC_PM5_CLK_DIV_2;
static uint32_t s_etu = SC_PM5_DEFAULT_ETU;
static uint32_t s_baud = SC_PM5_DEFAULT_CARD_CLK_HZ / SC_PM5_DEFAULT_ETU;
static smartcard_vcc_t s_vcc = SC_VCC_3V0;

// A T=0 exchange is a dialogue, not a send followed by a read, so the answer is
// collected here and handed back through SmartCard_HwRecv().
static uint8_t s_resp[SC_PM5_MAX_FRAME];
static uint16_t s_resp_len = 0;
static bool s_resp_ready = false;

// --- controller ------------------------------------------------------------

static bool ctrl_write(uint8_t reg, uint8_t val) {
    return I2C_WriteByte(val, reg, SC_PM5_CTRL_ADDR);
}

static bool ctrl_read(uint8_t reg, uint8_t *buf, uint16_t len) {
    return I2C_BufferRead(buf, len, reg, SC_PM5_CTRL_ADDR) == (int16_t)len;
}

static uint8_t vcc_register(smartcard_vcc_t v) {
    switch (v) {
        case SC_VCC_1V8:
            return 0;
        case SC_VCC_5V0:
            return 2;
        case SC_VCC_3V0:
        default:
            return 1;
    }
}

static uint8_t clk_div_register(uint8_t div) {
    switch (div) {
        case 8:
            return 0;
        case 4:
            return 1;
        case 2:
            return 2;
        case 1:
        default:
            return 3;
    }
}

// --- card I/O line ---------------------------------------------------------

static void uart_pins_init(void) {
    crm_periph_clock_enable(SC_PM5_UART_CRM, TRUE);
    crm_periph_clock_enable(SC_PM5_GPIO_CRM, TRUE);

    gpio_init_type g;
    gpio_default_para_init(&g);
    g.gpio_drive_strength = GPIO_DRIVE_STRENGTH_STRONGER;
    g.gpio_out_type = GPIO_OUTPUT_OPEN_DRAIN;
    g.gpio_mode = GPIO_MODE_MUX;
    g.gpio_pins = SC_PM5_IO_PIN;
    g.gpio_pull = GPIO_PULL_UP;
    gpio_init(SC_PM5_GPIO, &g);
    gpio_pin_mux_config(SC_PM5_GPIO, SC_PM5_IO_SRC, SC_PM5_IO_MUX);
}

// Drive the front end's clock input. The timer clock is twice APB1, so a
// 288 MHz core gives 7.2 MHz at period 40.
static void clock_pwm_set(uint32_t hz) {
    if (hz == 0) {
        return;
    }
    uint32_t period = system_core_clock / hz;
    if (period < 2) {
        return;
    }

    tmr_counter_enable(SC_PM5_CLK_TMR, FALSE);
    tmr_base_init(SC_PM5_CLK_TMR, period - 1, 0);
    tmr_channel_value_set(SC_PM5_CLK_TMR, SC_PM5_CLK_CH, period / 2);
    tmr_counter_enable(SC_PM5_CLK_TMR, TRUE);
}

// Clock into the front end. Push-pull and no pull, because this pin is an
// output that drives a clock input, not a signal that idles.
static void clock_pwm_init(void) {
    crm_periph_clock_enable(CRM_TMR2_PERIPH_CLOCK, TRUE);

    gpio_init_type g;
    gpio_default_para_init(&g);
    g.gpio_drive_strength = GPIO_DRIVE_STRENGTH_STRONGER;
    g.gpio_out_type = GPIO_OUTPUT_PUSH_PULL;
    g.gpio_pull = GPIO_PULL_NONE;
    g.gpio_mode = GPIO_MODE_MUX;
    g.gpio_pins = SC_PM5_CLK_PIN;
    gpio_init(SC_PM5_GPIO, &g);
    gpio_pin_mux_config(SC_PM5_GPIO, SC_PM5_CLK_SRC, SC_PM5_CLK_MUX);

    tmr_internal_clock_set(SC_PM5_CLK_TMR);
    tmr_reset(SC_PM5_CLK_TMR);

    tmr_output_config_type o;
    tmr_output_default_para_init(&o);
    o.oc_mode = TMR_OUTPUT_CONTROL_PWM_MODE_A;
    o.oc_polarity = TMR_OUTPUT_ACTIVE_HIGH;
    o.oc_output_state = TRUE;
    tmr_output_channel_config(SC_PM5_CLK_TMR, SC_PM5_CLK_CH, &o);
    clock_pwm_set(s_clkin_hz);
}

// The frame-format bits are locked while the smartcard mode is on, so it has
// to be dropped around a baud change.
static void uart_apply_baud(uint32_t baud) {
    usart_enable(SC_PM5_UART, FALSE);
    usart_smartcard_mode_enable(SC_PM5_UART, FALSE);
    usart_init(SC_PM5_UART, baud, USART_DATA_9BITS, USART_STOP_1_5_BIT);
    usart_parity_selection_config(SC_PM5_UART, USART_PARITY_EVEN);
    usart_smartcard_mode_enable(SC_PM5_UART, TRUE);
    usart_enable(SC_PM5_UART, TRUE);
}

static void uart_init(uint32_t baud) {
    crm_periph_clock_enable(SC_PM5_UART_CRM, TRUE);

    usart_enable(SC_PM5_UART, FALSE);
    usart_init(SC_PM5_UART, baud, USART_DATA_9BITS, USART_STOP_1_5_BIT);
    usart_parity_selection_config(SC_PM5_UART, USART_PARITY_EVEN);
    usart_smartcard_guard_time_set(SC_PM5_UART, SC_PM5_GUARD_ETU);
    // The card clock comes in on its own pin; the USART clock output is not
    // wired, and leaving it on would drive a pin that goes nowhere.
    usart_clock_enable(SC_PM5_UART, FALSE);
    // Smartcard mode is already single wire; the half-duplex select would mask
    // the transmitted waveform.
    usart_single_line_halfduplex_select(SC_PM5_UART, FALSE);
    usart_transmitter_enable(SC_PM5_UART, TRUE);
    usart_receiver_enable(SC_PM5_UART, TRUE);
    usart_enable(SC_PM5_UART, TRUE);
    // Same order as the reference bring-up: enable the peripheral first, then
    // NACK and the smartcard mode.
    usart_smartcard_nack_set(SC_PM5_UART, TRUE);
    usart_smartcard_mode_enable(SC_PM5_UART, TRUE);
}

// TC1 asks for extra guard time on top of the 2 etu the controller adds. 0xFF
// means the card asks for none.
static uint8_t atr_guard_time(const uint8_t *atr, uint16_t len) {

    if (len < 3) {
        return SC_PM5_GUARD_ETU;
    }

    uint8_t y1 = (uint8_t)(atr[1] >> 4);
    uint16_t idx = 2;
    if (y1 & 0x01) idx++;               // TA1
    if (y1 & 0x02) idx++;               // TB1
    if (((y1 & 0x04) == 0) || (idx >= len)) {
        return SC_PM5_GUARD_ETU;
    }

    uint8_t tc1 = atr[idx];
    if (atr[0] == 0x3F) {
        tc1 = (uint8_t)~tc1;            // inverse convention
    }
    if (tc1 == 0xFF) {
        return SC_PM5_GUARD_ETU;
    }
    uint16_t gt = (uint16_t)tc1 + 2;
    return (uint8_t)((gt > 254) ? 254 : gt);
}

static void uart_guard_set(uint8_t gt) {
    usart_enable(SC_PM5_UART, FALSE);
    usart_smartcard_guard_time_set(SC_PM5_UART, gt);
    usart_enable(SC_PM5_UART, TRUE);
}

static void uart_flush(void) {
    while (usart_flag_get(SC_PM5_UART, USART_RDBF_FLAG) != RESET) {
        (void)usart_data_receive(SC_PM5_UART);
    }
    usart_flag_clear(SC_PM5_UART, USART_PERR_FLAG | USART_FERR_FLAG |
                     USART_NERR_FLAG | USART_ROERR_FLAG | USART_TDC_FLAG);
}

static bool uart_send_byte(uint8_t b) {
    uint32_t start = GetTicks();
    while (usart_flag_get(SC_PM5_UART, USART_TDBE_FLAG) == RESET) {
        if (GetTicksDelta(start) > (SC_PM5_TX_TIMEOUT_MS * SC_PM5_TICKS_PER_MS)) {
            return false;
        }
    }
    usart_data_transmit(SC_PM5_UART, b);

    // TDBE only says the data register is free. Releasing the line that early
    // cuts the last bits off, so wait for the character to leave.
    start = GetTicks();
    while (usart_flag_get(SC_PM5_UART, USART_TDC_FLAG) == RESET) {
        if (GetTicksDelta(start) > (SC_PM5_TX_TIMEOUT_MS * SC_PM5_TICKS_PER_MS)) {
            return false;
        }
    }
    usart_flag_clear(SC_PM5_UART, USART_TDC_FLAG);

    // The receiver sits on the same wire and hears our own byte; drop it. A
    // card cannot answer within a few microseconds of TDC.
    while (usart_flag_get(SC_PM5_UART, USART_RDBF_FLAG) != RESET) {
        (void)usart_data_receive(SC_PM5_UART);
    }
    return true;
}

static bool uart_recv_byte(uint8_t *b, uint32_t timeout_ms) {
    uint32_t start = GetTicks();
    while (usart_flag_get(SC_PM5_UART, USART_RDBF_FLAG) == RESET) {
        if (GetTicksDelta(start) > (timeout_ms * SC_PM5_TICKS_PER_MS)) {
            return false;
        }
    }
    *b = (uint8_t)usart_data_receive(SC_PM5_UART);
    return true;
}

// --- ISO 7816 T=0 -----------------------------------------------------------
//
// After the command header the card answers with a procedure byte:
//   0x60      NULL, keep waiting
//   INS       accept the rest of the data, or start sending everything
//   ~INS      accept one more byte only
//   0x6C xx   wrong Le, resend the header with xx
//   0x61 xx   xx bytes are waiting, fetch them with GET RESPONSE
//   other 6X/9X  SW1, followed by SW2, exchange over

static uint16_t t0_exchange(uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2,
                            const uint8_t *in, uint8_t lc, uint8_t le, bool has_le,
                            uint8_t *out, uint16_t out_max, uint16_t *out_len) {

    uint8_t  cur_ins = ins;
    uint8_t  rx = 0;
    uint8_t  sent = 0;
    uint16_t n = 0;
    // A zero Le means 256, and case 4 carries both Lc and Le.
    uint16_t remain = has_le ? (le ? le : 256) : 0;

    *out_len = 0;
    uart_flush();

    if (!uart_send_byte(cla) || !uart_send_byte(ins) || !uart_send_byte(p1) ||
            !uart_send_byte(p2) || !uart_send_byte(lc ? lc : le)) {
        return 0xFFFF;
    }

    for (uint16_t guard = 0; guard < 1000; guard++) {

        if (!uart_recv_byte(&rx, SC_PM5_RX_TIMEOUT_MS)) {
            return 0xFFFF;
        }

        if (rx == 0x60) {
            continue;
        }

        // Data being accepted: the card ACKs, then we send.
        if (sent < lc && (rx == cur_ins || rx == (uint8_t)~cur_ins)) {
            uint8_t cnt = (rx == cur_ins) ? (uint8_t)(lc - sent) : 1;
            while (cnt-- > 0 && sent < lc) {
                if (!uart_send_byte(in[sent++])) {
                    return 0xFFFF;
                }
            }
            continue;
        }

        // Data being handed over: INS means all of it, ~INS one byte at a time.
        if (remain > 0 && (rx == cur_ins || rx == (uint8_t)~cur_ins)) {
            uint16_t cnt = (rx == cur_ins) ? remain : 1;
            while (cnt-- > 0 && remain > 0) {
                if (!uart_recv_byte(&rx, SC_PM5_RX_TIMEOUT_MS)) {
                    return 0xFFFF;
                }
                if (n < out_max) {
                    out[n++] = rx;
                }
                remain--;
            }
            *out_len = n;
            continue;
        }

        if (rx == 0x61) {
            uint8_t more = 0;
            if (!uart_recv_byte(&more, SC_PM5_RX_TIMEOUT_MS)) {
                return 0xFFFF;
            }
            // GET RESPONSE rides logical channel 0, whatever the command used.
            uint8_t resp_cla = (uint8_t)(cla & 0x03);
            if (!uart_send_byte(resp_cla) || !uart_send_byte(0xC0) ||
                    !uart_send_byte(0x00) || !uart_send_byte(0x00) ||
                    !uart_send_byte(more)) {
                return 0xFFFF;
            }
            cur_ins = 0xC0;
            sent = lc;
            remain = more;
            continue;
        }

        if (rx == 0x6C && lc == 0) {
            uint8_t want = 0;
            if (!uart_recv_byte(&want, SC_PM5_RX_TIMEOUT_MS)) {
                return 0xFFFF;
            }
            if (!uart_send_byte(cla) || !uart_send_byte(cur_ins) ||
                    !uart_send_byte(p1) || !uart_send_byte(p2) ||
                    !uart_send_byte(want)) {
                return 0xFFFF;
            }
            remain = want;
            continue;
        }

        uint8_t sw2 = 0;
        if (!uart_recv_byte(&sw2, SC_PM5_RX_TIMEOUT_MS)) {
            return 0xFFFF;
        }
        *out_len = n;
        return ((uint16_t)rx << 8) | sw2;
    }

    *out_len = n;
    return 0xFFFF;
}

// --- porting layer ---------------------------------------------------------

void SmartCard_HwOpen(void) {
    I2C_init(true);
    uart_pins_init();
    clock_pwm_init();
    // A link reset puts the card back on its default rate.
    s_etu = SC_PM5_DEFAULT_ETU;
    s_baud = s_card_clk_hz / s_etu;
    s_resp_ready = false;
    uart_init(s_baud);
}

void SmartCard_HwClose(void) {
    // Deactivate the card; the front end runs the power-down sequence.
    ctrl_write(SC_PM5_REG_CARD_CTRL, 0);
    s_resp_ready = false;
}

bool SmartCard_HwATR(uint8_t *atr, uint16_t *len, uint32_t wait) {

    if ((atr == NULL) || (len == NULL)) {
        return false;
    }

    s_resp_ready = false;

    // Voltage may only change while the card is off, and a warm card keeps the
    // rate the last PPS put it at until a reset pulse - which this is.
    if (ctrl_write(SC_PM5_REG_CARD_CTRL, 0) == false) {
        return false;
    }
    WaitMS(20);
    if (ctrl_write(SC_PM5_REG_RST, 0) == false) {
        return false;
    }
    if (ctrl_write(SC_PM5_REG_VCC, vcc_register(s_vcc)) == false) {
        return false;
    }
    // The card clock is the front end's clock input divided down; keep the
    // divider the host selected.
    if (ctrl_write(SC_PM5_REG_CLK_DIV, clk_div_register(s_clk_div)) == false) {
        return false;
    }
    if (ctrl_write(SC_PM5_REG_CARD_CTRL, 1) == false) {
        return false;
    }

    // The front end runs its own power-up ramp before the reset may be
    // released, and a slow one is normal on an adapter card.
    WaitMS(50);

    s_etu = SC_PM5_DEFAULT_ETU;
    s_baud = s_card_clk_hz / s_etu;
    uart_apply_baud(s_baud);
    uart_flush();

    // RST high releases the card; it answers with its ATR.
    if (ctrl_write(SC_PM5_REG_RST, 1) == false) {
        return false;
    }

    // The ATR has no length field, so it ends when the line goes quiet. Give
    // up entirely at the caller's budget.
    uint16_t n = 0;
    uint8_t b = 0;
    uint32_t budget_ms = wait_to_ms(wait);
    uint32_t start = GetTicks();
    uint32_t idle_start = start;
    while (n < *len) {
        if (usart_flag_get(SC_PM5_UART, USART_RDBF_FLAG) != RESET) {
            b = (uint8_t)usart_data_receive(SC_PM5_UART);
            atr[n++] = b;
            idle_start = GetTicks();
            continue;
        }
        if (GetTicksDelta(idle_start) > (SC_PM5_ATR_IDLE_MS * SC_PM5_TICKS_PER_MS)) {
            break;
        }
        if (GetTicksDelta(start) > (budget_ms * SC_PM5_TICKS_PER_MS)) {
            break;
        }
    }
    *len = n;

    if (n > 0) {
        uart_guard_set(atr_guard_time(atr, n));
    }

    if ((g_dbglevel >= DBG_DEBUG) && (n < 2)) {
        uint8_t offn = 0;
        Dbprintf("SC: no ATR (I/O=%d)", GpioInputStatus(SC_PM5_GPIO, SC_PM5_IO_PIN));
        if (ctrl_read(SC_PM5_REG_OFFN, &offn, 1) && (offn & 0x01) == 0) {
            DbpString("SC: card reports a fault or no card");
        }
    }
    return n > 0;
}

bool SmartCard_HwSend(smartcard_mode_t mode, const uint8_t *data, uint16_t len) {

    s_resp_ready = false;

    if (mode == SC_MODE_T1) {
        // The T=1 block layer is not implemented on this board.
        return false;
    }

    if (mode == SC_MODE_RAW) {
        // Raw: the host owns the framing, so the bytes go out unchanged.
        for (uint16_t i = 0; i < len; i++) {
            if (!uart_send_byte(data[i])) {
                return false;
            }
        }
        return true;
    }

    // A short APDU: CLA INS P1 P2 P3, then Lc data bytes; a case 4 command
    // appends Le after the data.
    if (len < 5) {
        return false;
    }

    uint8_t lc = 0;
    uint8_t le = 0;
    bool has_le = false;
    if (len == 5) {
        le = data[4];
        has_le = true;
    } else {
        lc = data[4];
        uint16_t body = (uint16_t)5 + lc;
        if (len == body) {
            // case 3: data only
        } else if (len == body + 1) {
            le = data[body];
            has_le = true;
        } else {
            return false;
        }
    }

    uint16_t out_len = 0;
    uint16_t sw = t0_exchange(data[0], data[1], data[2], data[3],
                              data + 5, lc, le, has_le,
                              s_resp, sizeof(s_resp) - 2, &out_len);
    if (sw == 0xFFFF) {
        return false;
    }

    // Hand the whole answer back the way the upper layers read it: data, then
    // the status word.
    s_resp[out_len++] = (uint8_t)(sw >> 8);
    s_resp[out_len++] = (uint8_t)(sw & 0xFF);
    s_resp_len = out_len;
    s_resp_ready = true;
    return true;
}

bool SmartCard_HwRecv(uint8_t *dest, uint16_t *len, uint32_t wait) {

    if (s_resp_ready) {
        uint16_t n = s_resp_len;
        if (n > *len) {
            n = *len;
        }
        memcpy(dest, s_resp, n);
        *len = n;
        s_resp_ready = false;
        return n > 0;
    }

    // Raw path: whatever the card says next, ended by one character of silence.
    uint16_t cap = *len;
    uint16_t n = 0;
    uint8_t b = 0;

    if (uart_recv_byte(&b, wait_to_ms(wait)) == false) {
        *len = 0;
        return false;
    }
    dest[n++] = b;

    while (n < cap && uart_recv_byte(&b, SC_PM5_RAW_GAP_MS)) {
        dest[n++] = b;
    }
    *len = n;
    return true;
}

bool SmartCard_HwPPS(const uint8_t *req, uint8_t req_len, uint8_t out[3], uint32_t wait) {

    (void)wait;

    if ((req_len < 1) || (req_len > 2)) {
        return false;
    }

    s_resp_ready = false;

    uint8_t proto = (uint8_t)(req[0] & 0x0F);
    bool has_ta1 = (req_len == 2);

    // The card expects the full PPS frame, including its checksum; the
    // adapter on the RDV4 builds this for us, here we build it ourselves.
    uint8_t frame[4];
    uint8_t n = 0;
    frame[n++] = 0xFF;
    frame[n++] = (uint8_t)(proto | (has_ta1 ? 0x10 : 0x00));
    if (has_ta1) {
        frame[n++] = req[1];
    }
    uint8_t pck = 0;
    for (uint8_t i = 0; i < n; i++) {
        pck ^= frame[i];
    }
    frame[n++] = pck;

    uart_flush();
    for (uint8_t i = 0; i < n; i++) {
        if (!uart_send_byte(frame[i])) {
            return false;
        }
    }

    uint8_t rsp[4] = {0};
    uint8_t rn = 0;
    uint8_t b = 0;
    if (uart_recv_byte(&b, SC_PM5_RX_TIMEOUT_MS) == false) {
        return false;
    }
    rsp[rn++] = b;
    while ((rn < sizeof(rsp)) && uart_recv_byte(&b, SC_PM5_PPS_GAP_MS)) {
        rsp[rn++] = b;
    }

    if ((rn < 3) || (rsp[0] != 0xFF)) {
        return false;
    }

    uint8_t rx_pck = 0;
    for (uint8_t i = 0; i < rn; i++) {
        rx_pck ^= rsp[i];
    }
    if (rx_pck != 0) {
        return false;
    }

    uint8_t active = (uint8_t)(rsp[1] & 0x0F);
    if ((active != proto) || (active != 0)) {
        return false;
    }
    if (has_ta1 && ((rsp[1] & 0x10) == 0)) {
        return false;
    }

    uint8_t ta1 = has_ta1 ? rsp[2] : 0;
    out[0] = 1;
    out[1] = active;
    out[2] = ta1;

    // A confirmed PPS moves the card, so the host moves with it.
    if (has_ta1) {
        uint16_t etu = SmartCard_RateEtu(ta1);
        if (etu != 0) {
            s_etu = etu;
            s_baud = s_card_clk_hz / s_etu;
            uart_apply_baud(s_baud);
        }
    }
    return true;
}

bool SmartCard_HwSetReload(uint16_t reload) {
    if (reload == 0) {
        return false;
    }
    s_etu = 16u * reload;
    s_baud = s_card_clk_hz / s_etu;
    uart_apply_baud(s_baud);
    return true;
}

void SmartCard_HwSetClock(uint64_t f) {
    // The client's selector is 0/1/2 for 16/8/4 MHz. The front end reaches
    // those directly with its /1 divider, so only the timer changes.
    uint32_t hz;
    switch (f) {
        case 0:
            hz = 16000000u;
            break;
        case 1:
            hz = 8000000u;
            break;
        case 2:
            hz = 4000000u;
            break;
        default:
            if (g_dbglevel >= DBG_ERROR) {
                Dbprintf("SC: unsupported card clock selector %u", (unsigned)f);
            }
            return;
    }

    s_clk_div = SC_PM5_CLK_DIV_1;
    s_clkin_hz = hz;
    s_card_clk_hz = hz;
    clock_pwm_set(s_clkin_hz);

    // The front end takes its divider from the register; write it now so a
    // running card follows too.
    ctrl_write(SC_PM5_REG_CLK_DIV, clk_div_register(s_clk_div));

    s_baud = s_card_clk_hz / s_etu;
    uart_apply_baud(s_baud);
}

bool SmartCard_HwSetVoltage(smartcard_vcc_t v) {
    if ((v != SC_VCC_1V8) && (v != SC_VCC_3V0) && (v != SC_VCC_5V0)) {
        return false;
    }
    // Recorded here and applied by the next reset, where the card is off.
    s_vcc = v;
    return true;
}

int SmartCard_HwAdapterInfo(uint8_t *major, uint8_t *minor, void *info) {
    (void)info;

    uint8_t ver[2] = {0};
    if (ctrl_read(SC_PM5_REG_FW_VERSION, ver, sizeof(ver)) == false) {
        return PM3_EDEVNOTSUPP;
    }
    *major = ver[0];
    *minor = ver[1];
    return PM3_SUCCESS;
}
