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
// Standalone GDB gateway: GDB Remote Serial Protocol over the USB CDC link.
// Reads flash and SRAM, writes SRAM and flash (gdb 'load'), no execution control.
// Flash writes are limited to the space above the running image; the bootrom is
// never writable. 'monitor unlock-app' opens the app area, 'monitor lock' closes it.
// Start with 'hw standalone', quit the client, then:
//   arm-none-eabi-gdb -ex 'target remote /dev/ttyACM0'
// Leave with 'monitor exit' or a button press.
//-----------------------------------------------------------------------------

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#define GDB_PKT_MAX   0x400u              // advertised PacketSize
#define GDB_MEM_MAX   ((GDB_PKT_MAX - 8u) / 2u)
#define GDB_NREGS     17u                 // r0-r12, sp, lr, pc, xpsr

#define GW_FLASH_BASE 0x08000000u
#define GW_FLASH_SIZE 0x00100000u
#define GW_APP_BASE   0x08004000u         // bootrom below this is never writable
#define GW_SECTOR     0x800u              // 1 MB part: 2 KB sectors
#define GW_SRAM_BASE  0x20000000u
#define GW_SRAM_SIZE  0x00080000u         // 512K, set by Extend_SRAM() in the bootrom

typedef struct {
    void (*tx)(const uint8_t *data, size_t len);
    // Copy up to len bytes from addr; return bytes copied, 0 if addr is unreadable.
    size_t (*mem_read)(uint32_t addr, uint8_t *out, size_t len);
    // The engine checks the address window before calling these.
    bool (*ram_write)(uint32_t addr, const uint8_t *data, size_t len);
    bool (*flash_erase)(uint32_t sector_addr);
    bool (*flash_write)(uint32_t addr, const uint8_t *data, size_t len);
    uint32_t app_end;                     // first sector above the running image
} gdb_ops_t;

static const gdb_ops_t *s_ops;

static const char TARGET_XML[] =
    "<?xml version=\"1.0\"?>"
    "<!DOCTYPE target SYSTEM \"gdb-target.dtd\">"
    "<target version=\"1.0\">"
    "<architecture>armv7e-m</architecture>"
    "<feature name=\"org.gnu.gdb.arm.m-profile\">"
    "<reg name=\"r0\" bitsize=\"32\"/><reg name=\"r1\" bitsize=\"32\"/>"
    "<reg name=\"r2\" bitsize=\"32\"/><reg name=\"r3\" bitsize=\"32\"/>"
    "<reg name=\"r4\" bitsize=\"32\"/><reg name=\"r5\" bitsize=\"32\"/>"
    "<reg name=\"r6\" bitsize=\"32\"/><reg name=\"r7\" bitsize=\"32\"/>"
    "<reg name=\"r8\" bitsize=\"32\"/><reg name=\"r9\" bitsize=\"32\"/>"
    "<reg name=\"r10\" bitsize=\"32\"/><reg name=\"r11\" bitsize=\"32\"/>"
    "<reg name=\"r12\" bitsize=\"32\"/>"
    "<reg name=\"sp\" bitsize=\"32\" type=\"data_ptr\"/>"
    "<reg name=\"lr\" bitsize=\"32\"/>"
    "<reg name=\"pc\" bitsize=\"32\" type=\"code_ptr\"/>"
    "<reg name=\"xpsr\" bitsize=\"32\" regnum=\"25\"/>"
    "</feature></target>";

static const char MEMORY_MAP_XML[] =
    "<?xml version=\"1.0\"?>"
    "<!DOCTYPE memory-map PUBLIC \"+//IDN gnu.org//DTD GDB Memory Map V1.0//EN\""
    " \"http://sourceware.org/gdb/gdb-memory-map.dtd\">"
    "<memory-map>"
    "<memory type=\"flash\" start=\"0x08000000\" length=\"0x100000\">"
    "<property name=\"blocksize\">0x800</property></memory>"
    "<memory type=\"ram\" start=\"0x20000000\" length=\"0x80000\"/>"
    "</memory-map>";

static const char HEXD[] = "0123456789abcdef";

typedef enum { ST_IDLE, ST_DATA, ST_CS1, ST_CS2 } rx_state_t;

static rx_state_t s_state;
static uint8_t s_rx[GDB_PKT_MAX + 1];
static uint16_t s_rxlen;
static uint8_t s_sum;
static int s_cs_hi;
static bool s_ovf;
static bool s_ack_pending;
static bool s_exit;
static bool s_unlocked;                   // app area writable

static uint8_t s_out[GDB_PKT_MAX];        // reply payload
static uint8_t s_frame[GDB_PKT_MAX + 5];  // '+' '$' payload '#' cs cs
static uint16_t s_frame_len;
static uint16_t s_frame_off;              // start of the resendable part (after any ack)

static int hexval(uint8_t c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static bool parse_hex(const char **p, const char *end, uint32_t *v) {
    uint32_t r = 0;
    int n = 0;
    while (*p < end && hexval((uint8_t) * *p) >= 0) {
        if (n++ >= 8) return false;
        r = (r << 4) | (uint32_t)hexval((uint8_t) * *p);
        (*p)++;
    }
    *v = r;
    return n > 0;
}

static bool starts_with(const char *s, size_t len, const char *pre) {
    size_t n = strlen(pre);
    return len >= n && memcmp(s, pre, n) == 0;
}

static void send_payload(const uint8_t *pl, size_t len) {
    size_t j = 0;
    uint8_t cs = 0;
    if (len > GDB_PKT_MAX) len = GDB_PKT_MAX;
    if (s_ack_pending) {
        s_frame[j++] = '+';
        s_ack_pending = false;
    }
    s_frame_off = (uint16_t)j;
    s_frame[j++] = '$';
    for (size_t i = 0; i < len; i++) {
        s_frame[j++] = pl[i];
        cs = (uint8_t)(cs + pl[i]);
    }
    s_frame[j++] = '#';
    s_frame[j++] = (uint8_t)HEXD[cs >> 4];
    s_frame[j++] = (uint8_t)HEXD[cs & 0xF];
    s_frame_len = (uint16_t)j;
    s_ops->tx(s_frame, j);
}

static void send_str(const char *s) {
    send_payload((const uint8_t *)s, strlen(s));
}

static void send_err(uint8_t e) {
    char b[4] = { 'E', HEXD[e >> 4], HEXD[e & 0xF], 0 };
    send_str(b);
}

static bool flash_window_ok(uint32_t addr, uint32_t len) {
    uint32_t floor = s_unlocked ? GW_APP_BASE : s_ops->app_end;
    uint32_t end = addr + len;
    return len && addr >= floor && end > addr && end <= GW_FLASH_BASE + GW_FLASH_SIZE;
}

static bool sram_ok(uint32_t addr, uint32_t len) {
    uint32_t end = addr + len;
    return len && addr >= GW_SRAM_BASE && end > addr && end <= GW_SRAM_BASE + GW_SRAM_SIZE;
}

// Undo gdb binary escaping ('}' then byte ^ 0x20). Returns -1 on a dangling '}'.
static int unescape(const uint8_t *in, size_t n, uint8_t *out) {
    size_t o = 0;
    for (size_t i = 0; i < n; i++) {
        if (in[i] == '}') {
            if (++i >= n) return -1;
            out[o++] = in[i] ^ 0x20;
        } else {
            out[o++] = in[i];
        }
    }
    return (int)o;
}

// Serve a qXfer document slice for "OFF,LEN".
static void send_qxfer(const char *doc, const char *p, const char *end) {
    uint32_t off, len;
    if (!parse_hex(&p, end, &off) || p >= end || *p++ != ',' || !parse_hex(&p, end, &len)) {
        send_err(0x16);
        return;
    }
    size_t total = strlen(doc);
    if (off >= total) {
        send_str("l");
        return;
    }
    size_t n = total - off;
    if (n > len) n = len;
    if (n > GDB_PKT_MAX - 1u) n = GDB_PKT_MAX - 1u;
    s_out[0] = (off + n < total) ? 'm' : 'l';
    memcpy(&s_out[1], doc + off, n);
    send_payload(s_out, n + 1);
}

static void do_mem_read(const char *p, const char *end) {
    uint32_t addr, len;
    if (!parse_hex(&p, end, &addr) || p >= end || *p++ != ',' || !parse_hex(&p, end, &len)) {
        send_err(0x16);
        return;
    }
    if (len > GDB_MEM_MAX) len = GDB_MEM_MAX;
    uint8_t tmp[GDB_MEM_MAX];
    size_t n = len ? s_ops->mem_read(addr, tmp, len) : 0;
    if (len && n == 0) {
        send_err(0x14);   // EFAULT
        return;
    }
    for (size_t i = 0; i < n; i++) {
        s_out[2 * i] = (uint8_t)HEXD[tmp[i] >> 4];
        s_out[2 * i + 1] = (uint8_t)HEXD[tmp[i] & 0xF];
    }
    send_payload(s_out, 2 * n);
}

static void do_mem_write(const char *p, const char *end) {
    uint32_t addr, len;
    if (!parse_hex(&p, end, &addr) || p >= end || *p++ != ',' || !parse_hex(&p, end, &len) ||
            p >= end || *p++ != ':' || len > GDB_MEM_MAX || (size_t)(end - p) != 2 * (size_t)len) {
        send_err(0x16);
        return;
    }
    if (len == 0) {
        send_str("OK");
        return;
    }
    uint8_t tmp[GDB_MEM_MAX];
    for (uint32_t i = 0; i < len; i++) {
        int hi = hexval((uint8_t)p[2 * i]), lo = hexval((uint8_t)p[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            send_err(0x16);
            return;
        }
        tmp[i] = (uint8_t)((hi << 4) | lo);
    }
    if (!sram_ok(addr, len)) {
        send_err(0x02);           // flash goes through vFlashWrite
        return;
    }
    send_str(s_ops->ram_write(addr, tmp, len) ? "OK" : "E01");
}

static void do_vflash(const char *s, size_t len) {
    const char *end = s + len;
    uint32_t addr, n;
    if (starts_with(s, len, "vFlashErase:")) {
        const char *p = s + strlen("vFlashErase:");
        if (!parse_hex(&p, end, &addr) || p >= end || *p++ != ',' || !parse_hex(&p, end, &n) ||
                n == 0 || (addr % GW_SECTOR) || (n % GW_SECTOR)) {
            send_err(0x16);
            return;
        }
        if (!flash_window_ok(addr, n)) {
            send_err(0x02);
            return;
        }
        for (uint32_t a = addr; a < addr + n; a += GW_SECTOR) {
            if (!s_ops->flash_erase(a)) {
                send_err(0x01);
                return;
            }
        }
        send_str("OK");
    } else if (starts_with(s, len, "vFlashWrite:")) {
        const char *p = s + strlen("vFlashWrite:");
        if (!parse_hex(&p, end, &addr) || p >= end || *p++ != ':') {
            send_err(0x16);
            return;
        }
        uint8_t data[GDB_PKT_MAX];
        int dn = unescape((const uint8_t *)p, (size_t)(end - p), data);
        if (dn < 0) {
            send_err(0x16);
            return;
        }
        if (!flash_window_ok(addr, (uint32_t)dn)) {
            send_err(0x02);
            return;
        }
        send_str(dn == 0 || s_ops->flash_write(addr, data, (size_t)dn) ? "OK" : "E01");
    } else if (starts_with(s, len, "vFlashDone")) {
        send_str("OK");
    } else {
        send_str("");
    }
}

// monitor <cmd>: reply is the hex-encoded console text.
static void do_monitor(const char *p, const char *end) {
    char cmd[24] = {0};
    size_t n = 0;
    while (p + 1 < end && n < sizeof(cmd) - 1) {
        int hi = hexval((uint8_t)p[0]), lo = hexval((uint8_t)p[1]);
        if (hi < 0 || lo < 0) break;
        cmd[n++] = (char)((hi << 4) | lo);
        p += 2;
    }
    const char *txt;
    if (strcmp(cmd, "unlock-app") == 0) {
        s_unlocked = true;
        txt = "app area writable; erasing the running image crashes the PM5\n";
    } else if (strcmp(cmd, "lock") == 0) {
        s_unlocked = false;
        txt = "writes limited to flash above the running image\n";
    } else if (strcmp(cmd, "exit") == 0) {
        s_exit = true;
        txt = "leaving gdb gateway\n";
    } else if (strcmp(cmd, "info") == 0) {
        txt = s_unlocked ? "flash 0x08000000+1M sram 0x20000000+512K app-write on\n"
              : "flash 0x08000000+1M sram 0x20000000+512K app-write off\n";
    } else if (strcmp(cmd, "help") == 0) {
        txt = "monitor info | unlock-app | lock | exit\n";
    } else {
        txt = "unknown command\n";
    }
    size_t t = strlen(txt);
    for (size_t i = 0; i < t; i++) {
        s_out[2 * i] = (uint8_t)HEXD[(uint8_t)txt[i] >> 4];
        s_out[2 * i + 1] = (uint8_t)HEXD[(uint8_t)txt[i] & 0xF];
    }
    send_payload(s_out, 2 * t);
}

static void do_query(const char *s, size_t len) {
    const char *end = s + len;
    if (starts_with(s, len, "qSupported")) {
        send_str("PacketSize=400;qXfer:features:read+;qXfer:memory-map:read+");
    } else if (starts_with(s, len, "qXfer:features:read:target.xml:")) {
        send_qxfer(TARGET_XML, s + strlen("qXfer:features:read:target.xml:"), end);
    } else if (starts_with(s, len, "qXfer:memory-map:read::")) {
        send_qxfer(MEMORY_MAP_XML, s + strlen("qXfer:memory-map:read::"), end);
    } else if (starts_with(s, len, "qRcmd,")) {
        do_monitor(s + 6, end);
    } else if (starts_with(s, len, "qAttached")) {
        send_str("1");
    } else if (starts_with(s, len, "qfThreadInfo")) {
        send_str("m1");
    } else if (starts_with(s, len, "qsThreadInfo")) {
        send_str("l");
    } else if (len == 2 && starts_with(s, len, "qC")) {
        send_str("QC1");
    } else {
        send_str("");
    }
}

static void handle_packet(const char *s, size_t len) {
    if (len == 0) {
        send_str("");
        return;
    }
    switch (s[0]) {
        case '?':
        case 'c': case 'C': case 's': case 'S':   // no execution control
            send_str("S05");
            break;
        case 'g':                                  // registers are not available
            memset(s_out, '0', GDB_NREGS * 8);
            send_payload(s_out, GDB_NREGS * 8);
            break;
        case 'p':
            memset(s_out, '0', 8);
            send_payload(s_out, 8);
            break;
        case 'H': case 'T': case 'D':
            send_str("OK");
            break;
        case 'm':
            do_mem_read(s + 1, s + len);
            break;
        case 'M':
            do_mem_write(s + 1, s + len);
            break;
        case 'G': case 'P':                        // registers are read-only
            send_err(0x01);
            break;
        case 'v':
            do_vflash(s, len);
            break;
        case 'q':
            do_query(s, len);
            break;
        default:                                   // X, Z, z, unknown
            send_str("");
            break;
    }
}

static void gdb_reset(const gdb_ops_t *ops) {
    s_ops = ops;
    s_state = ST_IDLE;
    s_rxlen = 0;
    s_ack_pending = false;
    s_exit = false;
    s_unlocked = false;
    s_frame_len = 0;
    s_frame_off = 0;
}

static void gdb_feed(uint8_t b) {
    switch (s_state) {
        case ST_IDLE:
            if (b == '$') {
                s_rxlen = 0;
                s_sum = 0;
                s_ovf = false;
                s_state = ST_DATA;
            } else if (b == '-' && s_frame_len) {
                s_ops->tx(s_frame + s_frame_off, s_frame_len - s_frame_off);   // resend
            } else if (b == 0x03) {
                send_str("S05");                   // Ctrl-C, nothing to stop
            }
            break;
        case ST_DATA:
            if (b == '#') {
                s_state = ST_CS1;
            } else if (b == '$') {
                s_rxlen = 0;
                s_sum = 0;
                s_ovf = false;
            } else {
                if (s_rxlen < GDB_PKT_MAX) s_rx[s_rxlen++] = b;
                else s_ovf = true;
                s_sum = (uint8_t)(s_sum + b);
            }
            break;
        case ST_CS1:
            s_cs_hi = hexval(b);
            s_state = ST_CS2;
            break;
        case ST_CS2: {
            int lo = hexval(b);
            s_state = ST_IDLE;
            if (s_ovf || s_cs_hi < 0 || lo < 0 || (uint8_t)((s_cs_hi << 4) | lo) != s_sum) {
                s_ops->tx((const uint8_t *)"-", 1);
            } else {
                s_ack_pending = true;
                s_rx[s_rxlen] = 0;
                handle_packet((const char *)s_rx, s_rxlen);
                if (s_ack_pending) {               // handler sent no reply
                    s_ops->tx((const uint8_t *)"+", 1);
                    s_ack_pending = false;
                }
            }
            break;
        }
    }
}

#ifndef GDB_GATEWAY_HOST_TEST

#include "appmain.h"
#include "dbprint.h"
#include "proxmark3_arm.h"
#include "standalone.h"
#include "ticks_apis.h"
#include "util.h"
#include "usb_cdc_apis.h"
#include "usb_read_ng.h"
#include "at32f435_437_flash.h"

extern const char __os_size__[];          // linker: size of the OS image

static void usb_tx(const uint8_t *data, size_t len) {
    usb_write(data, len);
}

static size_t at32_mem_read(uint32_t addr, uint8_t *out, size_t len) {
    uint32_t end;
    if (addr - GW_FLASH_BASE < GW_FLASH_SIZE) {
        end = GW_FLASH_BASE + GW_FLASH_SIZE;
    } else if (addr - GW_SRAM_BASE < GW_SRAM_SIZE) {
        end = GW_SRAM_BASE + GW_SRAM_SIZE;
    } else {
        return 0;
    }
    if (len > end - addr) len = end - addr;
    for (size_t i = 0; i < len; i++) {
        out[i] = *(const volatile uint8_t *)(addr + i);
    }
    return len;
}

static bool at32_ram_write(uint32_t addr, const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        *(volatile uint8_t *)(addr + i) = data[i];
    }
    return true;
}

static bool at32_flash_erase(uint32_t addr) {
    WDT_HIT();
    flash_unlock();
    flash_status_type st = flash_sector_erase(addr);
    flash_lock();
    return st == FLASH_OPERATE_DONE;
}

// Words are merged with the current flash content, so partial words work
// on erased sectors. Read back to verify.
static bool at32_flash_write(uint32_t addr, const uint8_t *data, size_t len) {
    bool ok = true;
    uint32_t end = addr + (uint32_t)len;
    flash_unlock();
    for (uint32_t w = addr & ~3u; w < end && ok; w += 4) {
        uint32_t v = *(volatile uint32_t *)w;
        for (uint32_t i = 0; i < 4; i++) {
            if (w + i >= addr && w + i < end) {
                v = (v & ~(0xFFu << (8 * i))) | ((uint32_t)data[w + i - addr] << (8 * i));
            }
        }
        if (v != *(volatile uint32_t *)w) {
            ok = flash_word_program(w, v) == FLASH_OPERATE_DONE && *(volatile uint32_t *)w == v;
        }
    }
    flash_lock();
    WDT_HIT();
    return ok;
}

static gdb_ops_t s_at32_ops = { usb_tx, at32_mem_read, at32_ram_write, at32_flash_erase, at32_flash_write, 0 };

void ModInfo(void) {
    DbpString("  GDB gateway, RSP over USB CDC");
}

// No Dbprintf here: debug frames would corrupt the RSP stream.
void RunMod(void) {
    s_at32_ops.app_end = (GW_APP_BASE + (uint32_t)(uintptr_t)__os_size__ + GW_SECTOR - 1) & ~(GW_SECTOR - 1);
    gdb_reset(&s_at32_ops);
    LED_A_ON();
    while (!s_exit && !BUTTON_PRESS()) {
        WDT_HIT();
        while (usb_read_ng_has_buffered_data() || usb_poll_validate_length()) {
            uint8_t b;
            if (usb_read_ng(&b, 1) != 1) break;
            gdb_feed(b);
        }
    }
    LED_A_OFF();
    while (BUTTON_PRESS()) {   // keep the main loop from reading the press as power-off
        WDT_HIT();
        SpinDelay(10);
    }
}

#endif // GDB_GATEWAY_HOST_TEST
