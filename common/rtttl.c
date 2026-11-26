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
// Bounded RTTTL parser, independent of the buzzer and command transport.
//-----------------------------------------------------------------------------
#include "rtttl.h"

static rtttl_status_t fail(rtttl_parser_t *parser, rtttl_status_t status) {
    parser->error_offset = parser->position;
    parser->valid = false;
    return status;
}

static char peek(const rtttl_parser_t *parser) {
    if (parser->position < parser->length) {
        return parser->text[parser->position];
    }
    return '\0';
}

static char ascii_lower(char value) {
    if (value >= 'A' && value <= 'Z') {
        return (char)(value + ('a' - 'A'));
    }
    return value;
}

static void skip_space(rtttl_parser_t *parser) {
    while (peek(parser) == ' ' || peek(parser) == '\t'
            || peek(parser) == '\r' || peek(parser) == '\n') {
        parser->position++;
    }
}

static bool is_digit(char value) {
    return value >= '0' && value <= '9';
}

static bool is_duration(uint32_t value) {
    return value >= 1U && value <= 64U;
}

static rtttl_status_t parse_number(rtttl_parser_t *parser, uint32_t *value) {
    *value = 0;
    if (is_digit(peek(parser)) == false) {
        return fail(parser, RTTTL_ERROR_SYNTAX);
    }
    while (is_digit(peek(parser))) {
        uint32_t digit = (uint32_t)(peek(parser) - '0');
        if (*value > (UINT32_MAX - digit) / 10U) {
            return fail(parser, RTTTL_ERROR_OVERFLOW);
        }
        *value = *value * 10U + digit;
        parser->position++;
    }
    return RTTTL_OK;
}

static rtttl_status_t set_default(rtttl_parser_t *parser, char key, uint32_t value) {
    if (key == 'd' && is_duration(value)) {
        parser->default_duration = (uint8_t)value;
    } else if (key == 'o' && value >= 4 && value <= 7) {
        parser->default_octave = (uint8_t)value;
    } else if (key == 'b' && value >= 25 && value <= 900) {
        parser->bpm = (uint16_t)value;
    } else {
        return fail(parser, RTTTL_ERROR_RANGE);
    }
    return RTTTL_OK;
}

static rtttl_status_t parse_defaults(rtttl_parser_t *parser) {
    // Track d/o/b assignments to reject duplicate defaults.
    uint8_t seen = 0;
    skip_space(parser);
    while (peek(parser) != ':') {
        char key = ascii_lower(peek(parser));
        uint8_t flag;
        switch (key) {
            case 'd':
                flag = 1;
                break;
            case 'o':
                flag = 2;
                break;
            case 'b':
                flag = 4;
                break;
            default:
                return fail(parser, RTTTL_ERROR_SYNTAX);
        }

        if ((seen & flag) != 0) {
            return fail(parser, RTTTL_ERROR_SYNTAX);
        }
        seen |= flag;
        parser->position++;
        skip_space(parser);
        if (peek(parser) != '=') {
            return fail(parser, RTTTL_ERROR_SYNTAX);
        }
        parser->position++;
        skip_space(parser);
        uint32_t value;
        rtttl_status_t status = parse_number(parser, &value);
        if (status != RTTTL_OK) {
            return status;
        }
        status = set_default(parser, key, value);
        if (status != RTTTL_OK) {
            return status;
        }
        skip_space(parser);
        if (peek(parser) == ':') {
            break;
        }

        if (peek(parser) != ',') {
            return fail(parser, RTTTL_ERROR_SYNTAX);
        }
        parser->position++;
        skip_space(parser);
        if (peek(parser) == ':') {
            return fail(parser, RTTTL_ERROR_SYNTAX);
        }
    }
    parser->position++;
    return RTTTL_OK;
}

static rtttl_status_t parse_pitch(rtttl_parser_t *parser, rtttl_event_t *event, bool *is_dotted) {
    // Equal temperament, A4 = 440 Hz, rounded to the nearest integer Hz.
    static const uint16_t frequencies[4][12] = {
        {262, 277, 294, 311, 330, 349, 370, 392, 415, 440, 466, 494},
        {523, 554, 587, 622, 659, 698, 740, 784, 831, 880, 932, 988},
        {1047, 1109, 1175, 1245, 1319, 1397, 1480, 1568, 1661, 1760, 1865, 1976},
        {2093, 2217, 2349, 2489, 2637, 2794, 2960, 3136, 3322, 3520, 3729, 3951},
    };
    char note = ascii_lower(peek(parser));
    int semitone;
    switch (note) {
        case 'c':
            semitone = 0;
            break;
        case 'd':
            semitone = 2;
            break;
        case 'e':
            semitone = 4;
            break;
        case 'f':
            semitone = 5;
            break;
        case 'g':
            semitone = 7;
            break;
        case 'a':
            semitone = 9;
            break;
        case 'b':
        case 'h':
            semitone = 11;
            break;
        case 'p':
            semitone = -1;
            break;
        default:
            return fail(parser, RTTTL_ERROR_SYNTAX);
    }
    parser->position++;
    if (peek(parser) == '#') {
        if (semitone < 0) {
            return fail(parser, RTTTL_ERROR_SYNTAX);
        }
        semitone++;
        parser->position++;
    }
    bool dotted = peek(parser) == '.';
    if (dotted) {
        parser->position++;
    }
    uint32_t octave = parser->default_octave;
    if (is_digit(peek(parser))) {
        // Some RTTTL sources give pauses an octave; parse it but ignore pitch.
        rtttl_status_t status = parse_number(parser, &octave);
        if (status != RTTTL_OK) {
            return status;
        }

        if (octave < 4 || octave > 7) {
            return fail(parser, RTTTL_ERROR_RANGE);
        }
    }

    if (peek(parser) == '.' && dotted == false) {
        dotted = true;
        parser->position++;
    }

    if (semitone < 0) {
        event->frequency_hz = 0;
    } else {
        // B# (or H#) crosses into the next octave; E# is F in this octave.
        if (semitone == 12) {
            semitone = 0;
            octave++;
            if (octave > 7U) {
                return fail(parser, RTTTL_ERROR_RANGE);
            }
        }
        event->frequency_hz = frequencies[octave - 4][semitone];
    }
    *is_dotted = dotted;
    return RTTTL_OK;
}

static rtttl_status_t parse_event(rtttl_parser_t *parser, rtttl_event_t *event) {
    skip_space(parser);
    if (parser->position == parser->length) {
        return RTTTL_DONE;
    }
    uint32_t duration = parser->default_duration;
    if (is_digit(peek(parser))) {
        rtttl_status_t status = parse_number(parser, &duration);
        if (status != RTTTL_OK) {
            return status;
        }

        if (is_duration(duration) == false) {
            return fail(parser, RTTTL_ERROR_RANGE);
        }
    }
    bool dotted;
    rtttl_status_t status = parse_pitch(parser, event, &dotted);
    if (status != RTTTL_OK) {
        return status;
    }
    // A whole note lasts 4 * 60000 / BPM ms; a dot adds half its duration.
    uint32_t duration_numerator = 240000U;
    if (dotted) {
        duration_numerator = 360000U;
    }
    event->duration_ms = duration_numerator / ((uint32_t)parser->bpm * duration);
    skip_space(parser);
    if (parser->position != parser->length) {
        if (peek(parser) != ',') {
            return fail(parser, RTTTL_ERROR_SYNTAX);
        }
        parser->position++;
        skip_space(parser);
        if (parser->position == parser->length) {
            return fail(parser, RTTTL_ERROR_SYNTAX);
        }
    }
    return RTTTL_OK;
}

static rtttl_status_t parse_header(rtttl_parser_t *parser) {
    size_t name_start = parser->position;
    while (parser->position < parser->length && parser->text[parser->position] != ':') {
        unsigned char value = (unsigned char)parser->text[parser->position];
        if (value < 32 || value > 126) {
            return fail(parser, RTTTL_ERROR_SYNTAX);
        }
        parser->position++;
    }

    if (parser->position == name_start || parser->position == parser->length) {
        return fail(parser, RTTTL_ERROR_SYNTAX);
    }
    parser->position++;
    return parse_defaults(parser);
}

rtttl_status_t rtttl_init(rtttl_parser_t *parser, const char *text, size_t length) {
    if (parser == NULL) {
        return RTTTL_ERROR_ARGUMENT;
    }
    *parser = (rtttl_parser_t) {0};
    if (text == NULL) {
        return RTTTL_ERROR_ARGUMENT;
    }

    if (length == 0 || length > RTTTL_MAX_TEXT_SIZE) {
        return RTTTL_ERROR_SIZE;
    }
    parser->text = text;
    parser->length = length;
    for (size_t i = 0; i < length; i++) {
        if (text[i] == '\0') {
            parser->position = i;
            return fail(parser, RTTTL_ERROR_SYNTAX);
        }
    }
    // Preserve original byte offsets and include any BOM in the size budget.
    if (length >= 3U && (unsigned char)text[0] == 0xEFU
            && (unsigned char)text[1] == 0xBBU && (unsigned char)text[2] == 0xBFU) {
        parser->position = 3U;
    }
    parser->bpm = 63;
    parser->default_duration = 4;
    parser->default_octave = 6;
    rtttl_status_t header_status = parse_header(parser);
    if (header_status != RTTTL_OK) {
        return header_status;
    }
    // Validate every note before playback, then rewind for iteration.
    parser->notes_start = parser->position;
    rtttl_event_t event;
    rtttl_status_t status;
    while ((status = parse_event(parser, &event)) == RTTTL_OK) {
        if (parser->total_duration_ms > UINT32_MAX - event.duration_ms) {
            return fail(parser, RTTTL_ERROR_OVERFLOW);
        }
        parser->total_duration_ms += event.duration_ms;
        parser->event_count++;
    }

    if (status != RTTTL_DONE) {
        return status;
    }

    if (parser->event_count == 0) {
        return fail(parser, RTTTL_ERROR_SYNTAX);
    }
    parser->position = parser->notes_start;
    parser->valid = true;
    return RTTTL_OK;
}

rtttl_status_t rtttl_next(rtttl_parser_t *parser, rtttl_event_t *event) {
    if (event == NULL) {
        return RTTTL_ERROR_ARGUMENT;
    }
    *event = (rtttl_event_t) {0};
    if (parser == NULL || parser->valid == false) {
        return RTTTL_ERROR_ARGUMENT;
    }
    rtttl_status_t status = parse_event(parser, event);
    if (status != RTTTL_OK) {
        *event = (rtttl_event_t) {0};
    }
    return status;
}
