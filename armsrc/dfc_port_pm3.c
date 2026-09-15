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

#include "dfc_port.h"
#include "dfc_port_pm3.h"
#include "dfc_bytebuf.h"
#include "dfc_emulator.h"
#include "dfc_secure_messaging.h"
#include "dfc_virtual_picc.h"

#include "BigBuf.h"
#include "commonutil.h"
#include "dbprint.h"
#include "sys_apis.h"
#include "ticks_apis.h"
#include "crapto1.h"

#include <string.h>

#define DFC_PM3_BYTEBUF_SLOTS      3
#define DFC_PM3_RANDOM_BYTES      256

typedef struct {
    DfcEmulator emulator;
    DfcSecureMessaging secure;
    DfcVirtualPiccSession session;
    bool emulator_used;
    bool secure_used;
    bool session_used;
    DfcByteBuf bytebuf[DFC_PM3_BYTEBUF_SLOTS];
    bool bytebuf_used[DFC_PM3_BYTEBUF_SLOTS];
} dfc_pm3_workspace_t;

static dfc_pm3_workspace_t *s_workspace;

bool dfc_pm3_workspace_init(void) {
    s_workspace = (dfc_pm3_workspace_t *)BigBuf_calloc(sizeof(*s_workspace));
    return s_workspace != NULL;
}

// The simulator clears and releases the containing BigBuf slice after this.
void dfc_pm3_workspace_release(void) {
    s_workspace = NULL;
}

static uint8_t s_random[DFC_PM3_RANDOM_BYTES];
static size_t s_random_length;
static size_t s_random_offset;
static bool s_random_strict;
static bool s_random_underflow;
static uint32_t s_random_state;

void dfc_pm3_random_set(const uint8_t *data, size_t length, bool strict) {
    size_t remaining = s_random_length - s_random_offset;
    if (remaining && s_random_offset) {
        memmove(s_random, s_random + s_random_offset, remaining);
    }
    s_random_offset = 0;
    s_random_length = remaining;
    if (length > sizeof(s_random) - remaining) {
        length = sizeof(s_random) - remaining;
        s_random_underflow = true;
    }
    if (length) {
        memcpy(s_random + remaining, data, length);
        s_random_length += length;
    }
    s_random_strict = strict;
}

void dfc_pm3_random_clear(void) {
    memset(s_random, 0, sizeof(s_random));
    s_random_length = 0;
    s_random_offset = 0;
    s_random_strict = false;
    s_random_underflow = false;
}

size_t dfc_pm3_random_remaining(void) {
    return s_random_length - s_random_offset;
}

bool dfc_pm3_random_underflowed(void) {
    return s_random_underflow;
}

void dfc_random_fill(uint8_t *buffer, size_t length) {
    size_t remaining = s_random_length - s_random_offset;
    size_t copy_length = MIN(length, remaining);
    if (copy_length) {
        memcpy(buffer, s_random + s_random_offset, copy_length);
        s_random_offset += copy_length;
    }
    if (copy_length == length) {
        return;
    }
    if (s_random_strict) {
        memset(buffer + copy_length, 0, length - copy_length);
        s_random_underflow = true;
        return;
    }

    if (s_random_state == 0) {
        s_random_state = GetTickCount() ^ 0xDFC3A5E1U;
    }
    for (size_t i = copy_length; i < length; i++) {
        s_random_state = prng_successor(s_random_state ^ GetTickCount(), 8);
        buffer[i] = (uint8_t)s_random_state;
    }
}

void *dfc_platform_alloc(size_t size, DfcAllocTag tag) {
    if (s_workspace == NULL) return NULL;
    void *storage = NULL;
    size_t capacity = 0;
    bool *used = NULL;
    switch (tag) {
        case DfcAllocEmulator:
            storage = &s_workspace->emulator;
            capacity = sizeof(s_workspace->emulator);
            used = &s_workspace->emulator_used;
            break;
        case DfcAllocSecureMessaging:
            storage = &s_workspace->secure;
            capacity = sizeof(s_workspace->secure);
            used = &s_workspace->secure_used;
            break;
        case DfcAllocSession:
            storage = &s_workspace->session;
            capacity = sizeof(s_workspace->session);
            used = &s_workspace->session_used;
            break;
    }
    if (storage == NULL || used == NULL || *used || size > capacity) {
        return NULL;
    }
    memset(storage, 0, size);
    *used = true;
    return storage;
}

void dfc_platform_free(void *pointer) {
    if (s_workspace == NULL) return;
    if (pointer == &s_workspace->emulator) {
        memset(pointer, 0, sizeof(s_workspace->emulator));
        s_workspace->emulator_used = false;
    } else if (pointer == &s_workspace->secure) {
        memset(pointer, 0, sizeof(s_workspace->secure));
        s_workspace->secure_used = false;
    } else if (pointer == &s_workspace->session) {
        memset(pointer, 0, sizeof(s_workspace->session));
        s_workspace->session_used = false;
    }
}

void dfc_port_notify(void *context, DfcEvent event) {
    (void)context;
    (void)event;
}

void dfc_assert_fail(const char *file, int line) {
    Dbprintf(_RED_("DFC assertion failed: %s:%d"), file, line);
    // Returning would continue with invalid state. Reset immediately so a
    // development image can never leave the USB interface permanently stuck.
    ResetChip();
}

DfcByteBuf *dfc_bytebuf_alloc(size_t max_size) {
    if (s_workspace == NULL || max_size > DFC_BYTEBUF_MAX) {
        return NULL;
    }
    for (size_t i = 0; i < ARRAYLEN(s_workspace->bytebuf); i++) {
        if (!s_workspace->bytebuf_used[i]) {
            s_workspace->bytebuf_used[i] = true;
            memset(&s_workspace->bytebuf[i], 0, sizeof(s_workspace->bytebuf[i]));
            return &s_workspace->bytebuf[i];
        }
    }
    DbpString(_RED_("DFC byte buffer pool exhausted"));
    return NULL;
}

void dfc_bytebuf_free(DfcByteBuf *buffer) {
    if (s_workspace == NULL) return;
    for (size_t i = 0; i < ARRAYLEN(s_workspace->bytebuf); i++) {
        if (buffer == &s_workspace->bytebuf[i]) {
            memset(buffer, 0, sizeof(*buffer));
            s_workspace->bytebuf_used[i] = false;
            return;
        }
    }
}

void dfc_bytebuf_reset(DfcByteBuf *buffer) {
    buffer->size_bytes = 0;
}

void dfc_bytebuf_append_bytes(DfcByteBuf *buffer, const uint8_t *data, size_t length) {
    if (buffer->size_bytes + length > sizeof(buffer->data)) {
        return;
    }
    memcpy(buffer->data + buffer->size_bytes, data, length);
    buffer->size_bytes += length;
}

void dfc_bytebuf_append_byte(DfcByteBuf *buffer, uint8_t byte) {
    dfc_bytebuf_append_bytes(buffer, &byte, 1);
}

size_t dfc_bytebuf_get_size_bytes(const DfcByteBuf *buffer) {
    return buffer->size_bytes;
}

const uint8_t *dfc_bytebuf_get_data(const DfcByteBuf *buffer) {
    return buffer->data;
}

uint8_t dfc_bytebuf_get_byte(const DfcByteBuf *buffer, size_t index) {
    return buffer->data[index];
}
