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

#include "frame_data2.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/ioctl.h>
#endif
#include "commonutil.h"             // ARRAYLEN

// ---- ANSI ----------------------------------------------------------------
#define CSI          "\x1b["
#define HIDE_CURSOR  CSI "?25l"
#define SHOW_CURSOR  CSI "?25h"
#define CLEAR_LINE   CSI "2K"
#define COL_RESET    CSI "0m"

#define MAX_COLS  220
#define MAX_ROWS   40
#define FRAME_MS   40.0        // 25 fps
#define FADE_MS    1200.0      // teardown fade on stop

#define TRUECOLOR 1

static const char *GLYPHS[] = {
    "\xef\xbd\xa6", "\xef\xbd\xa7", "\xef\xbd\xa8", "\xef\xbd\xa9", "\xef\xbd\xaa", "\xef\xbd\xab", "\xef\xbd\xac", "\xef\xbd\xad", "\xef\xbd\xae", "\xef\xbd\xaf", "\xef\xbd\xb0", "\xef\xbd\xb1", "\xef\xbd\xb2", "\xef\xbd\xb3", "\xef\xbd\xb4", "\xef\xbd\xb5",
    "\xef\xbd\xb6", "\xef\xbd\xb7", "\xef\xbd\xb8", "\xef\xbd\xb9", "\xef\xbd\xba", "\xef\xbd\xbb", "\xef\xbd\xbc", "\xef\xbd\xbd", "\xef\xbd\xbe", "\xef\xbd\xbf", "\xef\xbe\x80", "\xef\xbe\x81", "\xef\xbe\x82", "\xef\xbe\x83", "\xef\xbe\x84", "\xef\xbe\x85",
    "\xef\xbe\x86", "\xef\xbe\x87", "\xef\xbe\x88", "\xef\xbe\x89", "\xef\xbe\x8a", "\xef\xbe\x8b", "\xef\xbe\x8c", "\xef\xbe\x8d", "\xef\xbe\x8e", "\xef\xbe\x8f", "\xef\xbe\x90", "\xef\xbe\x91", "\xef\xbe\x92", "\xef\xbe\x93", "\xef\xbe\x94", "\xef\xbe\x95",
    "\xef\xbe\x96", "\xef\xbe\x97", "\xef\xbe\x98", "\xef\xbe\x99", "\xef\xbe\x9a", "\xef\xbe\x9b", "\xef\xbe\x9c", "\xef\xbe\x9d",
    "0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
};

#define LOGO_BOLD 1

#if LOGO_BOLD
#define FONT_W 7
#define FONT_H 9
static const char *FONT[6][FONT_H] = {
    { "#######", "#######", "..###..", "..###..", "..###..", "..###..", "..###..", "#######", "#######" }, // I
    { ".#####.", "#######", "###..##", "###....", "###....", "###....", "###..##", "#######", ".#####." }, // C
    { "#######", "#######", "###....", "###....", "#####..", "###....", "###....", "#######", "#######" }, // E
    { "##...##", "###.###", "#######", "#######", "##.#.##", "##...##", "##...##", "##...##", "##...##" }, // M
    { "..###..", ".#####.", "##...##", "##...##", "#######", "#######", "##...##", "##...##", "##...##" }, // A
    { "##...##", "###..##", "####.##", "#######", "##.####", "##..###", "##...##", "##...##", "##...##" }, // N
};
#else
#define FONT_W 5
#define FONT_H 7
static const char *FONT[6][FONT_H] = {
    { "#####", "..#..", "..#..", "..#..", "..#..", "..#..", "#####" }, // I
    { ".###.", "#...#", "#....", "#....", "#....", "#...#", ".###." }, // C
    { "#####", "#....", "#....", "####.", "#....", "#....", "#####" }, // E
    { "#...#", "##.##", "#.#.#", "#.#.#", "#...#", "#...#", "#...#" }, // M
    { ".###.", "#...#", "#...#", "#####", "#...#", "#...#", "#...#" }, // A
    { "#...#", "##..#", "#.#.#", "#.#.#", "#..##", "#...#", "#...#" }, // N
};
#endif

#define LOGO_LEN 6

static unsigned char g_mask[MAX_ROWS][MAX_COLS];

static void build_mask(int rows, int cols) {
    memset(g_mask, 0, sizeof(g_mask));

    const int gap = 2;                                  // columns between letters
    int w = LOGO_LEN * FONT_W + (LOGO_LEN - 1) * gap;
    if (rows < FONT_H || cols < w) return;

    int x0 = (cols - w) / 2;
    int y0 = (rows - FONT_H) / 2;

    for (int i = 0; i < LOGO_LEN; i++)
        for (int r = 0; r < FONT_H; r++)
            for (int c = 0; c < FONT_W; c++)
                if (FONT[i][r][c] == '#')
                    g_mask[y0 + r][x0 + i * (FONT_W + gap) + c] = 1;
}

typedef struct {
    double y;       // head position in rows (fractional -> smooth motion)
    double speed;   // rows per frame
    int    len;     // trail length
    int    delay;   // frames until respawn
} drop_t;

#define DROPS_PER_COL 2
#define FIELD_T 0.10

// ---- shared state --------------------------------------------------------
static pthread_mutex_t g_out_lock = PTHREAD_MUTEX_INITIALIZER;

static drop_t g_drop[MAX_COLS][DROPS_PER_COL];
static int    g_cell[MAX_ROWS][MAX_COLS];
static char  *g_buf;
static int    g_rows, g_cols;
static unsigned char g_seen[MAX_ROWS][MAX_COLS];
static double g_fade   = 1.0;
static int    g_fading = 0;
static volatile sig_atomic_t g_band_open = 0;   // guarded by g_out_lock,
// except for the async-signal-safe readers below
static volatile int g_running = 0;      // thread control
static pthread_t    g_thread;
static int          g_thread_rows = 12;

static volatile sig_atomic_t g_stop = 0;
static void on_sigint(int sig) { (void)sig; g_stop = 1; }

// ---- small helpers -------------------------------------------------------
static void sleep_ms(double ms) {
    struct timespec ts;
    ts.tv_sec  = (time_t)(ms / 1000.0);
    ts.tv_nsec = (long)((ms - ts.tv_sec * 1000.0) * 1e6);
    nanosleep(&ts, NULL);
}

static int term_width(void) {
#ifdef _WIN32
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    if (GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi)) {
        return csbi.srWindow.Right - csbi.srWindow.Left + 1;
    }
#else
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0)
        return ws.ws_col;
#endif
    return 80;
}

static double frand(void) {
    int r = rand();
    return (double)r / (double)RAND_MAX;
}

static void drop_respawn(drop_t *d, int rows) {
    d->y     = 0.0;
    d->speed = 0.14 + frand() * 0.34;              // slow, drifting fall
    d->len   = 6 + (int)(frand() * (rows * 1.4));  // longer trails
    d->delay = (int)(frand() * 18.0);              // shorter dead time
}

#if !TRUECOLOR
static int ramp(double t) {
    if (t > 0.82) return 46;
    if (t > 0.62) return 40;
    if (t > 0.42) return 34;
    if (t > 0.24) return 28;
    if (t > 0.10) return 23;
    return 22;      // resting field level
}
#endif

// ---- band management -----------------------------------------------------
static void band_open_locked(int rows) {
    printf(HIDE_CURSOR);
    for (int i = 0; i < rows; i++) putchar('\n');   // reserve the space
    printf(CSI "%dA", rows);                        // climb back to its top
    fflush(stdout);
    g_band_open = 1;
}

static void band_close_locked(void) {
    if (!g_band_open) return;
    for (int i = 0; i < g_rows; i++) {
        printf("\r" CLEAR_LINE);
        if (i < g_rows - 1) putchar('\n');
    }
    printf("\r" CSI "%dA" COL_RESET SHOW_CURSOR, g_rows - 1);
    fflush(stdout);
    g_band_open = 0;
}

static char *put_cell(char *p, double t, int head, const char *g) {
#if TRUECOLOR
    int gr = (int)(255.0 * t + 0.5);
    int rd = (int)((head ? 255.0 : 20.0) * t + 0.5);
    int bl = (int)((head ? 255.0 :  35.0) * t + 0.5);
    return p + sprintf(p, CSI "0;38;2;%d;%d;%dm%s", rd, gr, bl, g);
#else
    if (head && t > 0.75) return p + sprintf(p, CSI "0;1;38;5;231m%s", g);
    return p + sprintf(p, CSI "0;38;5;%dm%s", ramp(t), g);
#endif
}

// ---- terminal rescue -----------------------------------------------------
//
// Called from the client's signal handlers, so nothing here may take a lock
// or touch stdio. A hidden cursor is the one piece of state that outlives the
// process, and it is a single write() to put back.

void fx_terminal_restore(void) {
    if (g_band_open) {
        ssize_t ignored = write(STDOUT_FILENO, SHOW_CURSOR, sizeof(SHOW_CURSOR) - 1);
        (void) ignored;
    }
}

void fx_terminal_resume(void) {
    if (g_band_open) {
        ssize_t ignored = write(STDOUT_FILENO, HIDE_CURSOR, sizeof(HIDE_CURSOR) - 1);
        (void) ignored;
    }
}

// ---- renderer ------------------------------------------------------------
static void render_frame_locked(void) {
    char *p = g_buf;

    for (int y = 0; y < g_rows; y++) {
        p += sprintf(p, "\r" CLEAR_LINE);

        for (int x = 0; x < g_cols; x++) {

            if (g_mask[y][x]) {
                *p++ = ' ';
                continue;
            }

            double best = -1.0;
            int    head = 0;

            for (int k = 0; k < DROPS_PER_COL; k++) {
                drop_t *dr = &g_drop[x][k];
                if (dr->delay > 0) continue;

                double d = dr->y - (double)y;
                if (d < 0 || d >= dr->len) continue;

                if (d < 1.0) { head = 1; best = 1.0; }
                else {
                    double t = 1.0 - (d / (double)dr->len);
                    if (t > best) best = t;
                }
            }

            int is_field = 0;

            if (best < 0) {

                if (FIELD_T <= 0.0 || !g_seen[y][x]) {
                    *p++ = ' ';
                    continue;
                }
                best     = FIELD_T;
                is_field = 1;
            } else {
                g_seen[y][x] = 1;
            }

            double t = best * g_fade;
            if (t < 0.02) {
                *p++ = ' ';
                continue;
            }

            if (frand() < (is_field ? 0.01 : 0.04))
                g_cell[y][x] = (int)(frand() * ARRAYLEN(GLYPHS));

            const char *g = GLYPHS[g_cell[y][x]];

            p = put_cell(p, t, head, g);
        }
        p += sprintf(p, COL_RESET);
        if (y < g_rows - 1) *p++ = '\n';
    }

    p += sprintf(p, "\r" CSI "%dA", g_rows - 1);
    *p = '\0';

    fputs(g_buf, stdout);
    fflush(stdout);
}

static void advance(void) {
    for (int x = 0; x < g_cols; x++) {
        for (int k = 0; k < DROPS_PER_COL; k++) {
            drop_t *d = &g_drop[x][k];
            if (d->delay > 0) {
                d->delay--;
                continue;
            }
            d->y += d->speed;
            if (d->y - d->len > g_rows) {
                if (g_fading) {
                    d->delay = 1 << 24;   // let it die, no respawn
                } else {
                    drop_respawn(d, g_rows);
                }
            }
        }
    }
}

void fx_printf(const char *fmt, ...) {
    pthread_mutex_lock(&g_out_lock);

    int reopen = g_band_open;
    int rows   = g_rows;

    band_close_locked();

    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    putchar('\n');

    if (reopen) {
        band_open_locked(rows);
    } else {
        fflush(stdout);
    }

    pthread_mutex_unlock(&g_out_lock);
}

static int fx_state_init(int rows) {
    g_cols = term_width();
    if (g_cols > MAX_COLS) g_cols = MAX_COLS;
    if (rows  > MAX_ROWS)  rows   = MAX_ROWS;
    if (rows  < 3)         rows   = 3;
    g_rows = rows;

    memset(g_seen, 0, sizeof(g_seen));
    g_fade   = 1.0;
    g_fading = 0;

    time_t now = time(NULL);
    srand((unsigned)now);
    for (int x = 0; x < g_cols; x++) {
        for (int k = 0; k < DROPS_PER_COL; k++) {
            drop_respawn(&g_drop[x][k], g_rows);
            g_drop[x][k].y = -1.0 - frand() * g_rows * 0.45 - k * 2.0;
        }
    }
    for (int y = 0; y < g_rows; y++)
        for (int x = 0; x < g_cols; x++)
            g_cell[y][x] = (int)(frand() * ARRAYLEN(GLYPHS));

    build_mask(g_rows, g_cols);

    g_buf = malloc((size_t)g_rows * (g_cols * 32 + 32) + 64);
    return g_buf != NULL;
}

static void step_frame(void) {
    pthread_mutex_lock(&g_out_lock);
    render_frame_locked();
    pthread_mutex_unlock(&g_out_lock);

    advance();
    sleep_ms(FRAME_MS);

    if (g_fading) {
        g_fade -= FRAME_MS / FADE_MS;
        if (g_fade < 0.0) g_fade = 0.0;
    }
}

static void fade_out(void) {
    g_fading = 1;
    while (!g_stop && g_fade > 0.0) {
        step_frame();
    }
}

// Blocking flavour.
void fx_matrix_run(int rows, double duration_ms) {
    if (!isatty(STDOUT_FILENO)) return;

#ifdef _WIN32
    void (*old)(int) = signal(SIGINT, on_sigint);
#else
    struct sigaction sa = {0}, old;
    sa.sa_handler = on_sigint;
    sigaction(SIGINT, &sa, &old);
#endif

    if (!fx_state_init(rows)) goto out;

    pthread_mutex_lock(&g_out_lock);
    band_open_locked(g_rows);
    pthread_mutex_unlock(&g_out_lock);

    for (double t = 0; !g_stop && t < duration_ms; t += FRAME_MS)
        step_frame();

    fade_out();

    pthread_mutex_lock(&g_out_lock);
    band_close_locked();
    pthread_mutex_unlock(&g_out_lock);

    free(g_buf);
    g_buf = NULL;
out:
#ifdef _WIN32
    if (old != SIG_ERR) {
        signal(SIGINT, old);
    }
#else
    sigaction(SIGINT, &old, NULL);
#endif
    g_stop = 0;
}

static void *fx_thread(void *arg) {
    (void)arg;

    if (!fx_state_init(g_thread_rows)) return NULL;

    pthread_mutex_lock(&g_out_lock);
    band_open_locked(g_rows);
    pthread_mutex_unlock(&g_out_lock);

    while (g_running && !g_stop)
        step_frame();

    fade_out();          // g_running cleared by fx_matrix_stop()

    pthread_mutex_lock(&g_out_lock);
    band_close_locked();
    pthread_mutex_unlock(&g_out_lock);

    free(g_buf);
    g_buf = NULL;
    return NULL;
}

void fx_matrix_start(int rows) {
    if (!isatty(STDOUT_FILENO) || g_running) return;
    g_thread_rows = rows;
    g_running = 1;
    pthread_create(&g_thread, NULL, fx_thread, NULL);
}

void fx_matrix_stop(void) {
    if (!g_running) return;
    g_running = 0;
    pthread_join(g_thread, NULL);
}
