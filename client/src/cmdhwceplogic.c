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
// CEP bus logic logger: fetch, decode and terminal-table helpers used by
// cmdhwcep.c's `hw cep logic` command table. Byte/timestamp resolution (see
// pm5_cep_logic.c), not electrical edge capture.
//-----------------------------------------------------------------------------

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <inttypes.h>
#include <stddef.h>

#include "cmdhwceplogic.h"
#include "comms.h"
#include "ui.h"
#include "commonutil.h"
#include "pm3_cmd.h"
#include "fileutils.h"
#include "graph.h"
#include "proxgui.h"

// 1.5 MHz tick (see pm5_cep.c) -> nanoseconds, exact integer math.
static uint64_t cep_ticks_to_ns(uint32_t ticks) {
    return ((uint64_t)ticks * 2000ULL) / 3ULL;
}

int cep_logic_ctrl(uint8_t action, bool skip_idle, cep_logic_status_t *out) {
    cep_logic_ctrl_t payload = {.action = action, .skip_idle = skip_idle};
    clearCommandBuffer();
    SendCommandNG(CMD_CEP_LOGIC_CTRL, (uint8_t *)&payload, sizeof(payload));
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_CEP_LOGIC_CTRL, &resp, 2500) == false) {
        PrintAndLogEx(WARNING, "command timeout");
        return PM3_ETIMEOUT;
    }
    if (resp.status == PM3_ENOTIMPL) {
        PrintAndLogEx(FAILED, "firmware not built with " _YELLOW_("PLATFORM_EXTRAS=CEPLOGIC") " (see Makefile.platform.sample)");
        return PM3_ENOTIMPL;
    }
    if (out) {
        memset(out, 0, sizeof(*out));
        if (resp.length >= sizeof(*out)) {
            memcpy(out, resp.data.asBytes, sizeof(*out));
        }
    }
    return resp.status;
}

void cep_logic_print_status(const cep_logic_status_t *st) {
    PrintAndLogEx(INFO, "recording.... %s", st->running ? _GREEN_("yes") : _RED_("no"));
    PrintAndLogEx(INFO, "entries...... %u", st->count);
    if (st->overflowed) {
        PrintAndLogEx(WARNING, "ring buffer wrapped - oldest entries were overwritten, fetch soon");
    }
}
// Pulls the whole trace via repeated CMD_CEP_LOGIC_FETCH calls. *out is
// malloc'd (caller frees); *n_out is how many entries landed in it.
int cep_logic_fetch_all(cep_logic_entry_t **out, uint32_t *n_out) {
    *out = NULL;
    *n_out = 0;

    uint32_t offset = 0;
    uint32_t cap = 0;
    cep_logic_entry_t *buf = NULL;
    uint32_t n = 0;
    bool gap_reported = false;

    for (;;) {
        cep_logic_fetch_req_t req = {.offset = offset};
        clearCommandBuffer();
        SendCommandNG(CMD_CEP_LOGIC_FETCH, (uint8_t *)&req, sizeof(req));
        PacketResponseNG resp;
        if (WaitForResponseTimeout(CMD_CEP_LOGIC_FETCH, &resp, 2500) == false) {
            PrintAndLogEx(WARNING, "command timeout fetching offset %u", offset);
            free(buf);
            return PM3_ETIMEOUT;
        }
        if (resp.status == PM3_ENOTIMPL) {
            PrintAndLogEx(FAILED, "firmware not built with " _YELLOW_("PLATFORM_EXTRAS=CEPLOGIC") " (see Makefile.platform.sample)");
            free(buf);
            return PM3_ENOTIMPL;
        }
        if (resp.length < offsetof(cep_logic_fetch_resp_t, entries)) {
            PrintAndLogEx(WARNING, "fetch reply too short (%u bytes), aborting", resp.length);
            free(buf);
            return PM3_EFILE;
        }
        const cep_logic_fetch_resp_t *fr = (const cep_logic_fetch_resp_t *)resp.data.asBytes;
        if (resp.length < offsetof(cep_logic_fetch_resp_t, entries) + (size_t)fr->returned * sizeof(cep_logic_entry_t)) {
            PrintAndLogEx(WARNING, "fetch reply too short for %u entries, aborting", fr->returned);
            free(buf);
            return PM3_EFILE;
        }

        if (fr->returned == 0) {
            if (offset < fr->count) {
                // Requested entries were already overwritten - jump to what's
                // still there and keep going, once.
                if (!gap_reported) {
                    PrintAndLogEx(WARNING, "ring overflow: entries %u-%u are gone, resuming at %u",
                                  offset, fr->oldest_valid > 0 ? fr->oldest_valid - 1 : 0, fr->oldest_valid);
                    gap_reported = true;
                }
                offset = fr->oldest_valid;
                continue;
            }
            break; // caught up to the recorder
        }

        if (n + fr->returned > cap) {
            cap = (cap == 0) ? 4096 : cap * 2;
            if (cap < n + fr->returned) {
                cap = n + fr->returned;
            }
            cep_logic_entry_t *grown = realloc(buf, cap * sizeof(cep_logic_entry_t));
            if (grown == NULL) {
                free(buf);
                return PM3_EMALLOC;
            }
            buf = grown;
        }
        memcpy(buf + n, fr->entries, fr->returned * sizeof(cep_logic_entry_t));
        n += fr->returned;
        offset += fr->returned;
    }

    *out = buf;
    *n_out = n;
    return PM3_SUCCESS;
}

void cep_logic_write_vcd(const char *fn, const cep_logic_entry_t *e, uint32_t n) {
    if (n == 0) {
        PrintAndLogEx(WARNING, "nothing captured, not writing a VCD file");
        return;
    }
    vcd_sample_t *samples = calloc(n, sizeof(vcd_sample_t));
    if (samples == NULL) {
        PrintAndLogEx(WARNING, "out of memory, can't build the VCD sample array");
        return;
    }
    for (uint32_t i = 0; i < n; i++) {
        samples[i].ns = cep_ticks_to_ns(e[i].t_ticks);
        samples[i].chan = (e[i].chan == CEP_LOGIC_CHAN_MOSI) ? 0 : (e[i].chan == CEP_LOGIC_CHAN_MISO) ? 1 : 2;
        samples[i].value = e[i].data;
    }
    static const char *chan_names[] = {"mosi", "miso", "uart"};
    saveFileVCD(fn, "cep", chan_names, ARRAYLEN(chan_names), samples, n);
    free(samples);
}

// Proxmark3 NG command IDs worth a name instead of raw hex. Add entries
// here as more come up; anything missing just falls back to 0x%04x.
typedef struct {
    uint16_t cmd;
    const char *name;
} cep_cmd_name_t;

static const cep_cmd_name_t cep_cmd_names[] = {
    {CMD_ACK, "ACK"},
    {CMD_DEBUG_PRINT_STRING, "DBG_STR"},
    {CMD_DEBUG_PRINT_INTEGERS, "DBG_INT"},
    {CMD_VERSION, "VERSION"},
    {CMD_STATUS, "STATUS"},
    {CMD_PING, "PING"},
    {CMD_MAIN_CHIP_UNIQUEID, "MAIN_CHIP_UNIQUEID"},
    {CMD_CAPABILITIES, "CAPABILITIES"},
    {CMD_BREAK_LOOP, "BREAK_LOOP"},
    {CMD_FLASHMEM_GET_ID, "FLASHMEM_GET_ID"},
    {CMD_FLASHMEM_GET_INFO, "FLASHMEM_GET_INFO"},
    {CMD_CEP_STATUS, "CEP_STATUS"},
    {CMD_LF_HITAG_READER, "LF_HITAG_READER"},
    {CMD_HF_ISO14443A_READER, "HF_14A_READER"},
};

static const char *cep_cmd_name(uint16_t cmd) {
    for (size_t i = 0; i < ARRAYLEN(cep_cmd_names); i++) {
        if (cep_cmd_names[i].cmd == cmd) {
            return cep_cmd_names[i].name;
        }
    }
    return NULL;
}

// One PM3 NG command/response frame found in a byte stream - preamble,
// payload, postamble. Mirrors PacketCommandNGPreamble/PacketResponseNGPreamble
// in pm3_cmd.h; see cep_decode_ng().
typedef struct {
    uint32_t start_idx, end_idx; // inclusive, into the filtered per-channel array
    uint16_t cmd, len;
    bool is_resp, complete;
    int8_t status, reason;
} cep_ng_frame_t;

// Scans one channel's bytes for a PM3 NG preamble and decodes what follows.
// Command preamble is 8 bytes (magic, length+ng, cmd); response preamble is
// 10 (magic, length+ng, status, reason, cmd) - see pm3_cmd.h. *out is
// malloc'd (caller frees); returns how many frames were found.
static uint32_t cep_decode_ng(const cep_logic_entry_t *buf, uint32_t n, bool is_resp, cep_ng_frame_t **out) {
    uint32_t magic = is_resp ? RESPONSENG_PREAMBLE_MAGIC : COMMANDNG_PREAMBLE_MAGIC;
    uint32_t hdr = is_resp ? 10 : 8;
    uint32_t cap = 0, cnt = 0;
    cep_ng_frame_t *frames = NULL;

    for (uint32_t i = 0; i + 4 <= n; i++) {
        uint32_t w = (uint32_t)buf[i].data | ((uint32_t)buf[i + 1].data << 8) |
                     ((uint32_t)buf[i + 2].data << 16) | ((uint32_t)buf[i + 3].data << 24);
        if (w != magic) {
            continue;
        }
        if (i + hdr > n) {
            break; // not enough captured yet for a full header
        }
        uint16_t lenng = (uint16_t)buf[i + 4].data | ((uint16_t)buf[i + 5].data << 8);
        uint16_t len = lenng & 0x7FFF;
        uint16_t cmd;
        int8_t status = 0, reason = 0;
        if (is_resp) {
            status = (int8_t)buf[i + 6].data;
            reason = (int8_t)buf[i + 7].data;
            cmd = (uint16_t)buf[i + 8].data | ((uint16_t)buf[i + 9].data << 8);
        } else {
            cmd = (uint16_t)buf[i + 6].data | ((uint16_t)buf[i + 7].data << 8);
        }
        uint32_t total = hdr + len + 2; // + 2-byte postamble (crc or sentinel)
        bool complete = (i + total <= n);
        uint32_t end = complete ? (i + total - 1) : (n - 1);

        if (cnt == cap) {
            cap = cap ? cap * 2 : 16;
            cep_ng_frame_t *grown = realloc(frames, cap * sizeof(cep_ng_frame_t));
            if (grown == NULL) {
                free(frames);
                *out = NULL;
                return 0;
            }
            frames = grown;
        }
        frames[cnt].start_idx = i;
        frames[cnt].end_idx = end;
        frames[cnt].cmd = cmd;
        frames[cnt].len = len;
        frames[cnt].is_resp = is_resp;
        frames[cnt].complete = complete;
        frames[cnt].status = status;
        frames[cnt].reason = reason;
        cnt++;

        if (!complete) {
            break; // nothing more to find, the rest is a cut-off frame
        }
        i = end; // loop's i++ moves past it
    }

    *out = frames;
    return cnt;
}

// One decoded event on the UART handshake line: a complete handshake
// (STX + "iamf0rupm5"), or a bad attempt (restarted by a new STX, or a byte
// that didn't match the expected next one). Indices are into the filtered
// UART-channel array, like cep_ng_frame_t.
typedef struct {
    uint32_t start_idx, end_idx; // inclusive
    bool ok;
    char reason[16]; // "" if ok; "mismatch" / "restarted" otherwise
} cep_handshake_evt_t;

#define CEP_HANDSHAKE_STX 0x02
static const char CEP_HANDSHAKE_MAGIC[] = "iamf0rupm5"; // see pm5_cep.c CEP_HANDSHAKE_STRING

// Scans the UART channel's bytes for handshake attempts. *out is malloc'd
// (caller frees); returns how many events (good or bad) were found.
static uint32_t cep_decode_handshake(const cep_logic_entry_t *buf, uint32_t n, cep_handshake_evt_t **out) {
    uint32_t cap = 0, cnt = 0;
    cep_handshake_evt_t *evts = NULL;
    uint32_t match_len = 0; // bytes of CEP_HANDSHAKE_MAGIC matched so far
    uint32_t start = 0;
    bool in_progress = false;

    for (uint32_t i = 0; i < n; i++) {
        uint8_t byte = buf[i].data;

        if (byte == CEP_HANDSHAKE_STX) {
            if (in_progress) {
                // A new STX mid-attempt means the previous one was cut short.
                if (cnt == cap) {
                    cap = cap ? cap * 2 : 8;
                    cep_handshake_evt_t *grown = realloc(evts, cap * sizeof(cep_handshake_evt_t));
                    if (grown == NULL) {
                        free(evts);
                        *out = NULL;
                        return 0;
                    }
                    evts = grown;
                }
                evts[cnt].start_idx = start;
                evts[cnt].end_idx = i - 1;
                evts[cnt].ok = false;
                strncpy(evts[cnt].reason, "restarted", sizeof(evts[cnt].reason) - 1);
                evts[cnt].reason[sizeof(evts[cnt].reason) - 1] = '\0';
                cnt++;
            }
            in_progress = true;
            match_len = 0;
            start = i;
            continue;
        }

        if (!in_progress) {
            continue; // stray byte outside any handshake attempt
        }

        bool matched = (match_len < sizeof(CEP_HANDSHAKE_MAGIC) - 1) &&
                       (byte == (uint8_t)CEP_HANDSHAKE_MAGIC[match_len]);
        if (cnt == cap) {
            cap = cap ? cap * 2 : 8;
            cep_handshake_evt_t *grown = realloc(evts, cap * sizeof(cep_handshake_evt_t));
            if (grown == NULL) {
                free(evts);
                *out = NULL;
                return 0;
            }
            evts = grown;
        }
        if (!matched) {
            evts[cnt].start_idx = start;
            evts[cnt].end_idx = i;
            evts[cnt].ok = false;
            strncpy(evts[cnt].reason, "mismatch", sizeof(evts[cnt].reason) - 1);
            evts[cnt].reason[sizeof(evts[cnt].reason) - 1] = '\0';
            cnt++;
            in_progress = false;
            continue;
        }
        match_len++;
        if (match_len == sizeof(CEP_HANDSHAKE_MAGIC) - 1) {
            evts[cnt].start_idx = start;
            evts[cnt].end_idx = i;
            evts[cnt].ok = true;
            evts[cnt].reason[0] = '\0';
            cnt++;
            in_progress = false;
        }
    }

    *out = evts;
    return cnt;
}

// Copies just one channel's entries out, keeping timestamps, plus each one's
// index in the full capture (*out_gidx, parallel array). *out/*out_gidx are
// malloc'd (caller frees); returns how many entries matched.
static uint32_t cep_filter_channel(const cep_logic_entry_t *e, uint32_t n, uint8_t chan,
                                   cep_logic_entry_t **out, uint32_t **out_gidx) {
    cep_logic_entry_t *buf = calloc(n ? n : 1, sizeof(cep_logic_entry_t));
    uint32_t *gidx = calloc(n ? n : 1, sizeof(uint32_t));
    uint32_t m = 0;
    if (buf != NULL && gidx != NULL) {
        for (uint32_t i = 0; i < n; i++) {
            if (e[i].chan == chan) {
                buf[m] = e[i];
                gidx[m] = i;
                m++;
            }
        }
    }
    *out = buf;
    *out_gidx = gidx;
    return m;
}

static uint64_t cep_entry_ns(const cep_logic_entry_t *e) {
    return cep_ticks_to_ns(e->t_ticks);
}

// elapsed ns since t0, human-sized (us below 1ms, ms below 1s, else s).
static void cep_fmt_elapsed(uint64_t ns, uint64_t t0, char *buf, size_t buflen) {
    uint64_t d = ns - t0;
    if (d < 1000ULL) {
        snprintf(buf, buflen, "%" PRIu64 " ns", d);
    } else if (d < 1000000ULL) {
        snprintf(buf, buflen, "%" PRIu64 ".%03" PRIu64 " us", d / 1000, d % 1000);
    } else if (d < 1000000000ULL) {
        snprintf(buf, buflen, "%" PRIu64 ".%03" PRIu64 " ms", d / 1000000, (d / 1000) % 1000);
    } else {
        snprintf(buf, buflen, "%" PRIu64 ".%03" PRIu64 " s", d / 1000000000, (d / 1000000) % 1000);
    }
}

// Unified data table: one row per raw byte plus one per decoded event
// (handshake/cmd/resp), sorted into capture order - mirrors Logic 2's table
// with a raw analyzer and its HLA both attached. Columns: Type, Start,
// Duration, mosi, miso, data.
typedef struct {
    uint64_t t_ns;
    uint64_t dur_ns; // 0 if unknown/instantaneous
    uint64_t seq;    // tie-break for equal t_ns: raw bytes sort before a
                     // decoded row that starts on the same byte
    char type[12];
    char mosi[8];
    char miso[8];
    char data[64];
} cep_row_t;

static void cep_row_push(cep_row_t **rows, uint32_t *cnt, uint32_t *cap, const cep_row_t *row) {
    if (*cnt == *cap) {
        *cap = *cap ? *cap * 2 : 64;
        cep_row_t *grown = realloc(*rows, *cap * sizeof(cep_row_t));
        if (grown == NULL) {
            return; // best-effort table; drop the row rather than crash
        }
        *rows = grown;
    }
    (*rows)[(*cnt)++] = *row;
}

// Sort by sequence number only. t_ns is recording order with a timebase
// applied on top (aliasing, double-logged bytes); seq is the ring buffer's
// raw recording order and isn't subject to either, so it's the reliable key.
static int cep_row_cmp(const void *a, const void *b) {
    const cep_row_t *ra = a, *rb = b;
    if (ra->seq != rb->seq) {
        return (ra->seq < rb->seq) ? -1 : 1;
    }
    return 0;
}

// Builds and sorts the unified row list described above. *out is malloc'd
// (caller frees); returns the row count.
static uint32_t cep_build_rows(const cep_logic_entry_t *e, uint32_t n, cep_row_t **out) {
    cep_row_t *rows = NULL;
    uint32_t cnt = 0, cap = 0;

    for (uint32_t i = 0; i < n; i++) {
        cep_row_t row = {0};
        row.t_ns = cep_entry_ns(&e[i]);
        row.seq = (uint64_t)i * 2;
        snprintf(row.type, sizeof(row.type), "data");
        char ascii[2] = {isprint(e[i].data) ? (char)e[i].data : '.', 0};
        switch (e[i].chan) {
            case CEP_LOGIC_CHAN_MOSI:
                snprintf(row.mosi, sizeof(row.mosi), "0x%02x", e[i].data);
                break;
            case CEP_LOGIC_CHAN_MISO:
                snprintf(row.miso, sizeof(row.miso), "0x%02x", e[i].data);
                break;
            default: // UART - Async Serial analyzers put the byte in "data"
                snprintf(row.data, sizeof(row.data), "0x%02x '%s'", e[i].data, ascii);
                break;
        }
        cep_row_push(&rows, &cnt, &cap, &row);
    }

    cep_logic_entry_t *mosi, *miso, *uart;
    uint32_t *mosi_g, *miso_g, *uart_g;
    uint32_t n_mosi = cep_filter_channel(e, n, CEP_LOGIC_CHAN_MOSI, &mosi, &mosi_g);
    uint32_t n_miso = cep_filter_channel(e, n, CEP_LOGIC_CHAN_MISO, &miso, &miso_g);
    uint32_t n_uart = cep_filter_channel(e, n, CEP_LOGIC_CHAN_UART, &uart, &uart_g);

    cep_ng_frame_t *cmds = NULL, *resps = NULL;
    uint32_t n_cmds = cep_decode_ng(mosi, n_mosi, false, &cmds);
    uint32_t n_resps = cep_decode_ng(miso, n_miso, true, &resps);
    for (uint32_t k = 0; k < n_cmds; k++) {
        uint32_t gi = mosi_g[cmds[k].start_idx], ge = mosi_g[cmds[k].end_idx];
        cep_row_t row = {0};
        row.t_ns = cep_entry_ns(&e[gi]);
        row.dur_ns = cep_entry_ns(&e[ge]) - row.t_ns;
        row.seq = (uint64_t)gi * 2 + 1;
        snprintf(row.type, sizeof(row.type), "cmd");
        const char *name = cep_cmd_name(cmds[k].cmd);
        if (name) {
            snprintf(row.data, sizeof(row.data), "CMD %s len=%u%s", name, cmds[k].len,
                     cmds[k].complete ? "" : " (cut)");
        } else {
            snprintf(row.data, sizeof(row.data), "CMD 0x%04x len=%u%s", cmds[k].cmd, cmds[k].len,
                     cmds[k].complete ? "" : " (cut)");
        }
        cep_row_push(&rows, &cnt, &cap, &row);
    }
    for (uint32_t k = 0; k < n_resps; k++) {
        uint32_t gi = miso_g[resps[k].start_idx], ge = miso_g[resps[k].end_idx];
        cep_row_t row = {0};
        row.t_ns = cep_entry_ns(&e[gi]);
        row.dur_ns = cep_entry_ns(&e[ge]) - row.t_ns;
        row.seq = (uint64_t)gi * 2 + 1;
        snprintf(row.type, sizeof(row.type), "resp");
        const char *name = cep_cmd_name(resps[k].cmd);
        if (name) {
            snprintf(row.data, sizeof(row.data), "RESP %s st=%d len=%u%s", name, resps[k].status,
                     resps[k].len, resps[k].complete ? "" : " (cut)");
        } else {
            snprintf(row.data, sizeof(row.data), "RESP 0x%04x st=%d len=%u%s", resps[k].cmd,
                     resps[k].status, resps[k].len, resps[k].complete ? "" : " (cut)");
        }
        cep_row_push(&rows, &cnt, &cap, &row);
    }

    cep_handshake_evt_t *hs = NULL;
    uint32_t n_hs = cep_decode_handshake(uart, n_uart, &hs);
    for (uint32_t k = 0; k < n_hs; k++) {
        uint32_t gi = uart_g[hs[k].start_idx], ge = uart_g[hs[k].end_idx];
        cep_row_t row = {0};
        row.t_ns = cep_entry_ns(&e[gi]);
        row.dur_ns = cep_entry_ns(&e[ge]) - row.t_ns;
        row.seq = (uint64_t)gi * 2 + 1;
        snprintf(row.type, sizeof(row.type), "handshake");
        if (hs[k].ok) {
            snprintf(row.data, sizeof(row.data), "HANDSHAKE %s", CEP_HANDSHAKE_MAGIC);
        } else {
            snprintf(row.data, sizeof(row.data), "BAD HANDSHAKE (%s)", hs[k].reason);
        }
        cep_row_push(&rows, &cnt, &cap, &row);
    }

    free(mosi);
    free(miso);
    free(uart);
    free(mosi_g);
    free(miso_g);
    free(uart_g);
    free(cmds);
    free(resps);
    free(hs);

    if (rows != NULL && cnt > 0) {
        qsort(rows, cnt, sizeof(cep_row_t), cep_row_cmp);
    }
    *out = rows;
    return cnt;
}

static void cep_print_row(uint32_t idx, const cep_row_t *row) {
    char durbuf[24] = "-";
    if (row->dur_ns > 0) {
        cep_fmt_elapsed(row->dur_ns, 0, durbuf, sizeof(durbuf));
    }
    PrintAndLogEx(NORMAL, "%4u | %10" PRIu64 " | %-9s | %-4s | %-4s | %s",
                  idx, row->t_ns / 1000, row->type, row->mosi, row->miso, row->data);
}

void cep_logic_print_table(const cep_logic_entry_t *e, uint32_t n) {
    cep_row_t *rows = NULL;
    uint32_t cnt = cep_build_rows(e, n, &rows);

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "   # | t (us)     | type      | mosi | miso | data");
    PrintAndLogEx(INFO, "-----+------------+-----------+------+------+------");
    for (uint32_t i = 0; i < cnt; i++) {
        cep_print_row(i, &rows[i]);
    }
    free(rows);
}

// One marker per decoded command/response/handshake, at its starting byte's
// capture-order position - same decode as cep_build_rows(), just placed on
// the client's own graph window instead of a standalone image.
static void cep_plot_add_markers(const cep_logic_entry_t *e, uint32_t n) {
    cep_logic_entry_t *mosi, *miso, *uart;
    uint32_t *mosi_g, *miso_g, *uart_g;
    uint32_t n_mosi = cep_filter_channel(e, n, CEP_LOGIC_CHAN_MOSI, &mosi, &mosi_g);
    uint32_t n_miso = cep_filter_channel(e, n, CEP_LOGIC_CHAN_MISO, &miso, &miso_g);
    uint32_t n_uart = cep_filter_channel(e, n, CEP_LOGIC_CHAN_UART, &uart, &uart_g);

    cep_ng_frame_t *cmds = NULL, *resps = NULL;
    uint32_t n_cmds = cep_decode_ng(mosi, n_mosi, false, &cmds);
    uint32_t n_resps = cep_decode_ng(miso, n_miso, true, &resps);
    char label[32];
    for (uint32_t k = 0; k < n_cmds; k++) {
        const char *name = cep_cmd_name(cmds[k].cmd);
        if (name) {
            snprintf(label, sizeof(label), "C %s", name);
        } else {
            snprintf(label, sizeof(label), "C 0x%04x", cmds[k].cmd);
        }
        add_temporary_marker(mosi_g[cmds[k].start_idx], label);
    }
    for (uint32_t k = 0; k < n_resps; k++) {
        const char *name = cep_cmd_name(resps[k].cmd);
        char namebuf[16];
        if (name == NULL) {
            snprintf(namebuf, sizeof(namebuf), "0x%04x", resps[k].cmd);
            name = namebuf;
        }
        if (resps[k].status) {
            snprintf(label, sizeof(label), "R %s e%d", name, resps[k].status);
        } else {
            snprintf(label, sizeof(label), "R %s", name);
        }
        add_temporary_marker(miso_g[resps[k].start_idx], label);
    }

    cep_handshake_evt_t *hs = NULL;
    uint32_t n_hs = cep_decode_handshake(uart, n_uart, &hs);
    for (uint32_t k = 0; k < n_hs; k++) {
        if (hs[k].ok) {
            snprintf(label, sizeof(label), "HS OK");
        } else {
            snprintf(label, sizeof(label), "HS BAD (%s)", hs[k].reason);
        }
        add_temporary_marker(uart_g[hs[k].start_idx], label);
    }

    free(mosi);
    free(miso);
    free(uart);
    free(mosi_g);
    free(miso_g);
    free(uart_g);
    free(cmds);
    free(resps);
    free(hs);
}

// Loads the raw capture-order byte values (mixed channels) into the client's
// graph window and marks each decoded command/response/handshake. Replaces
// the old standalone SVG plot - same decode, shown in the existing graph
// window (zoom/pan/markers) instead of a static image.
void cep_logic_plot(const cep_logic_entry_t *e, uint32_t n) {
    if (n == 0) {
        PrintAndLogEx(WARNING, "nothing captured, nothing to plot");
        return;
    }
    uint8_t *vals = calloc(n, sizeof(uint8_t));
    if (vals == NULL) {
        PrintAndLogEx(WARNING, "out of memory, can't build the plot");
        return;
    }
    for (uint32_t i = 0; i < n; i++) {
        vals[i] = e[i].data;
    }
    setGraphBuffer(vals, n);
    free(vals);

    cep_plot_add_markers(e, n);
    ShowGraphWindow();
    PrintAndLogEx(SUCCESS, "plotted " _YELLOW_("%u") " entries in the graph window", n);
}
