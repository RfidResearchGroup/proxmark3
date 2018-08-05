/**
 * @file vtsend.c
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

#include "vtsend.h"
#include "apps.h"

#define ESC (0x1B)
//#define UART_WRITE(P, BUF, SIZ)   (P)->uart_write(BUF, SIZ, (P)->extobj)
#define UART_WRITE(BUF) DbprintfEx(FLAG_RAWPRINT, "%s", BUF)

int vtsend_init(vtsend_t *p, VTSEND_SERIAL_WRITE uart_write, void *extobj) {
    p->uart_write = uart_write;
    p->extobj = extobj;
    return 0;
}

int vtsend_cursor_position(vtsend_t *p, const int column, const int line) {
    char buf[1 + 8];
    buf[0] = ESC;
    buf[1] = '[';
    buf[2] = '0' + (line / 10);
    buf[3] = '0' + (line % 10);
    buf[4] = ';';
    buf[5] = '0' + (column / 10);
    buf[6] = '0' + (column % 10);
    buf[7] = 'H';
    buf[8] = '\0';
    UART_WRITE(buf); // UART_WRITE(p, buf, sizeof(buf));
    return 0;
}

int vtsend_cursor_up(vtsend_t *p, const int n) {
    char buf[1 + 5];
    buf[0] = ESC;
    buf[1] = '[';
    buf[2] = '0' + (n / 10);
    buf[3] = '0' + (n % 10);
    buf[4] = 'A';
    buf[5] = '\0';

    UART_WRITE(buf); // UART_WRITE(p, buf, sizeof(buf));
    return 0;
}

int vtsend_cursor_down(vtsend_t *p, const int n) {
    char buf[1 + 5];
    buf[0] = ESC;
    buf[1] = '[';
    buf[2] = '0' + (n / 10);
    buf[3] = '0' + (n % 10);
    buf[4] = 'B';
    buf[5] = '\0';

    UART_WRITE(buf); // UART_WRITE(p, buf, sizeof(buf));
    return 0;
}

int vtsend_cursor_forward(vtsend_t *p, const int n) {
    char buf[1 + 5];
    buf[0] = ESC;
    buf[1] = '[';
    buf[2] = '0' + (n / 10);
    buf[3] = '0' + (n % 10);
    buf[4] = 'C';
    buf[5] = '\0';

    UART_WRITE(buf); // UART_WRITE(p, buf, sizeof(buf));
    return 0;
}

int vtsend_cursor_backward(vtsend_t *p, const int n) {
    char buf[1 + 5];
    buf[0] = ESC;
    buf[1] = '[';
    buf[2] = '0' + (n / 10);
    buf[3] = '0' + (n % 10);
    buf[4] = 'D';
    buf[5] = '\0';

    UART_WRITE(buf); // UART_WRITE(p, buf, sizeof(buf));
    return 0;
}

int vtsend_cursor_position_save(vtsend_t *p) {
    char buf[1 + 3];
    buf[0] = ESC;
    buf[1] = '[';
    buf[2] = 's';
    buf[3] = '\0';

    UART_WRITE(buf); // UART_WRITE(p, buf, sizeof(buf));
    return 0;
}

int vtsend_cursor_position_restore(vtsend_t *p) {
    char buf[1 + 3];
    buf[0] = ESC;
    buf[1] = '[';
    buf[2] = 'u';
    buf[3] = '\0';

    UART_WRITE(buf); // UART_WRITE(p, buf, sizeof(buf));
    return 0;
}

int vtsend_erase_display(vtsend_t *p) {
    char buf[1 + 4];
    buf[0] = ESC;
    buf[1] = '[';
    buf[2] = '2';
    buf[3] = 'J';
    buf[4] = '\0';

    UART_WRITE(buf); // UART_WRITE(p, buf, sizeof(buf));
    return 0;
}

int vtsend_erase_line(vtsend_t *p) {
    char buf[1 + 4];
    buf[0] = ESC;
    buf[1] = '[';
    buf[2] = '2';
    buf[3] = 'K';
    buf[4] = '\0';

    UART_WRITE(buf); // UART_WRITE(p, buf, sizeof(buf));
    return 0;
}

int vtsend_set_color_foreground(vtsend_t *p, const int color) {
    char buf[1 + 5];
    buf[0] = ESC;
    buf[1] = '[';
    buf[2] = '0' + ((30 + color) / 10);
    buf[3] = '0' + ((30 + color) % 10);
    buf[4] = 'm';
    buf[5] = '\0';

    UART_WRITE(buf); // UART_WRITE(p, buf, sizeof(buf));
    return 0;
}

int vtsend_set_color_background(vtsend_t *p, const int color) {
    char buf[1 + 5];
    buf[0] = ESC;
    buf[1] = '[';
    buf[2] = '0' + ((40 + color) / 10);
    buf[3] = '0' + ((40 + color) % 10);
    buf[4] = 'm';
    buf[5] = '\0';

    UART_WRITE(buf); // UART_WRITE(p, buf, sizeof(buf));
    return 0;
}

int vtsend_set_attribute(vtsend_t *p, const int attr) {
    char buf[1 + 5];
    buf[0] = ESC;
    buf[1] = '[';
    buf[2] = '0' + ((attr) / 10);
    buf[3] = '0' + ((attr) % 10);
    buf[4] = 'm';
    buf[5] = '\0';

    UART_WRITE(buf); // UART_WRITE(p, buf, sizeof(buf));
    return 0;
}

int vtsend_set_scroll_region(vtsend_t *p, const int top, const int bottom) {
    char buf[1 + 8];
    buf[0] = ESC;
    buf[1] = '[';
    buf[2] = '0' + (top / 10);
    buf[3] = '0' + (top % 10);
    buf[4] = ';';
    buf[5] = '0' + (bottom / 10);
    buf[6] = '0' + (bottom % 10);
    buf[7] = 'r';
    buf[8] = '\0';

    UART_WRITE(buf); // UART_WRITE(p, buf, sizeof(buf));
    return 0;
}

int vtsend_set_cursor(vtsend_t *p, const int visible) {
    if (visible) {
        char buf[1 + 6];
        buf[0] = ESC;
        buf[1] = '[';
        buf[2] = '?';
        buf[3] = '2';
        buf[4] = '5';
        buf[5] = 'h';
        buf[6] = '\0';

        UART_WRITE(buf); // UART_WRITE(p, buf, sizeof(buf));
    } else {
        char buf[1 + 6];
        buf[0] = ESC;
        buf[1] = '[';
        buf[2] = '?';
        buf[3] = '2';
        buf[4] = '5';
        buf[5] = 'l';
        buf[6] = '\0';

        UART_WRITE(buf); // UART_WRITE(p, buf, sizeof(buf));
    }
    return 0;
}

int vtsend_reset(vtsend_t *p) {
    char buf[1 + 2];
    buf[0] = ESC;
    buf[1] = 'c';
    buf[2] = '\0';

    UART_WRITE(buf); // UART_WRITE(p, buf, sizeof(buf));
    return 0;
}

int vtsend_draw_box(vtsend_t *p, const int x1, const int y1, const int x2, const int y2) {
    int i;

    vtsend_cursor_position(p, x1, y1);
    for (i = x1; i <= x2; i++) {
        UART_WRITE("-");
    }
    vtsend_cursor_position(p, x1, y2);
    for (i = x1; i <= x2; i++) {
        UART_WRITE("-");
    }
    for (i = y1; i <= y2; i++) {
        vtsend_cursor_position(p, x1, i);
        UART_WRITE("|");
        vtsend_cursor_position(p, x2, i);
        UART_WRITE("|");
    }
    return 0;
}

int vtsend_fill_box(vtsend_t *p, const int x1, const int y1, const int x2, const int y2) {
    int i, j;
    for (i = y1; i <= y2; i++) {
        vtsend_cursor_position(p, x1, i);
        for (j = x1; j <= x2; j++) {
            UART_WRITE(" ");
        }
    }
    return 0;
}

