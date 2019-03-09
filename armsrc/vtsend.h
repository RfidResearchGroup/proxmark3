/**
 * @file vtsend.h
 * @author CuBeatSystems
 * @author Shinichiro Nakamura
 * @copyright
 * ===============================================================
 * Natural Tiny Shell (NT-Shell) Version 0.3.1
 * ===============================================================
 * Copyright (c) 2010-2016 Shinichiro Nakamura
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef VTSEND_H
#define VTSEND_H

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

#ifdef __cplusplus
extern "C" {
#endif

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

#ifdef __cplusplus
}
#endif

#endif


