//-----------------------------------------------------------------------------
// Borrowed initially from https://cubeatsystems.com/ntshell/index.html
// Copyright (C) 2010-2016 Shinichiro Nakamura (CuBeatSystems)
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
// Natural Tiny Shell (NT-Shell) Version 0.3.1
//-----------------------------------------------------------------------------

#ifndef VTSEND_H
#define VTSEND_H

#include "common.h"

#define VTSEND_COLOR_BLACK      (0)
#define VTSEND_COLOR_RED        (1)
#define VTSEND_COLOR_GREEN      (2)
#define VTSEND_COLOR_YELLOW     (3)
#define VTSEND_COLOR_BLUE       (4)
#define VTSEND_COLOR_MAGENTA    (5)
#define VTSEND_COLOR_CYAN       (6)
#define VTSEND_COLOR_WHITE      (7)

#define VTSEND_ATTR_OFF             (0)
#define VTSEND_ATTR_BOLD_ON         (1)
#define VTSEND_ATTR_UNDERSCORE      (4)
#define VTSEND_ATTR_BLINK_ON        (5)
#define VTSEND_ATTR_REVERSE         (7)
#define VTSEND_ATTR_CONCEALED_ON    (8)

typedef int (*VTSEND_SERIAL_WRITE)(const char *buf, const int siz, void *extobj);

typedef struct {
    VTSEND_SERIAL_WRITE uart_write;
    void *extobj;
} vtsend_t;

int vtsend_init(vtsend_t *p, VTSEND_SERIAL_WRITE uart_write, void *extobj);
int vtsend_cursor_position(vtsend_t *p, const int column, const int line);
int vtsend_cursor_up(vtsend_t *p, const int n);
int vtsend_cursor_down(vtsend_t *p, const int n);
int vtsend_cursor_forward(vtsend_t *p, const int n);
int vtsend_cursor_backward(vtsend_t *p, const int n);
int vtsend_cursor_position_save(vtsend_t *p);
int vtsend_cursor_position_restore(vtsend_t *p);
int vtsend_erase_display(vtsend_t *p);
int vtsend_erase_line(vtsend_t *p);
int vtsend_set_color_foreground(vtsend_t *p, const int color);
int vtsend_set_color_background(vtsend_t *p, const int color);
int vtsend_set_attribute(vtsend_t *p, const int attr);
int vtsend_set_scroll_region(vtsend_t *p, const int top, const int bottom);
int vtsend_set_cursor(vtsend_t *p, const int visible);
int vtsend_reset(vtsend_t *p);

int vtsend_draw_box(
    vtsend_t *p,
    const int x1, const int y1, const int x2, const int y2);
int vtsend_fill_box(
    vtsend_t *p,
    const int x1, const int y1, const int x2, const int y2);

#endif
