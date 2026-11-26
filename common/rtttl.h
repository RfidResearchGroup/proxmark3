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
// Bounded, allocation-free RTTTL parser. No hardware dependencies.
//-----------------------------------------------------------------------------
#ifndef RTTTL_H__
#define RTTTL_H__

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define RTTTL_MAX_TEXT_SIZE 2047U

typedef enum {
    RTTTL_OK = 0,
    RTTTL_DONE,
    RTTTL_ERROR_ARGUMENT,
    RTTTL_ERROR_SIZE,
    RTTTL_ERROR_SYNTAX,
    RTTTL_ERROR_RANGE,
    RTTTL_ERROR_OVERFLOW,
    RTTTL_ABORTED          // playback stopped by the button or host data, never from the parser
} rtttl_status_t;

typedef struct {
    uint16_t frequency_hz; // Zero means a pause.
    uint32_t duration_ms;
} rtttl_event_t;

// Treat all fields as read-only. Keep input alive AND unchanged until iteration
// ends. No allocation or copy of the input. Separate instances are independent.
typedef struct {
    const char *text;
    size_t length;
    size_t position;
    size_t notes_start;
    size_t error_offset; // Zero-based byte offset; length means missing at EOF.
    uint32_t total_duration_ms;
    uint32_t event_count;
    uint16_t bpm;
    uint8_t default_duration;
    uint8_t default_octave;
    bool valid;
} rtttl_parser_t;

// length excludes the optional final NUL; embedded NUL is invalid.
// Validates the entire melody before making any event available.
// Failed initialization leaves parser invalid; error_offset locates the error.
rtttl_status_t rtttl_init(rtttl_parser_t *parser, const char *text, size_t length);

// Returns OK for an event or DONE at EOF. Output is cleared on DONE/error.
// Init and next do not read outside text[0..length). Do not modify parser fields.
rtttl_status_t rtttl_next(rtttl_parser_t *parser, rtttl_event_t *event);

#endif // RTTTL_H__
