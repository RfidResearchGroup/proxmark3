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
#include "dfc_bytebuf.h"

#include "crypto/libpcrypto.h"
#include "pm3_cmd.h"

#include <stdlib.h>
#include <string.h>

void dfc_random_fill(uint8_t *buffer, size_t length) {
    if (pcrypto_rng_fill_oneshot(buffer, length, "dfc-core") != PM3_SUCCESS) {
        memset(buffer, 0, length);
    }
}

void *dfc_platform_alloc(size_t size, DfcAllocTag tag) {
    (void)tag;
    return calloc(1, size);
}

void dfc_platform_free(void *pointer) {
    free(pointer);
}

void dfc_port_notify(void *context, DfcEvent event) {
    (void)context;
    (void)event;
}

DfcByteBuf *dfc_bytebuf_alloc(size_t max_size) {
    (void)max_size;
    return calloc(1, sizeof(DfcByteBuf));
}

void dfc_bytebuf_free(DfcByteBuf *buffer) {
    free(buffer);
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
