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
// Flasher progress
//-----------------------------------------------------------------------------

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <math.h>
#include <pthread.h>
#include "frame_progress.h"
#include "frame_data.h"
#include "util_posix.h"

// --- platform: terminal-width detection ----------------------------------/
#ifdef _WIN32
#  include <windows.h>
static int terminal_width(void) {
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    if (GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi)) {
        return csbi.srWindow.Right - csbi.srWindow.Left + 1;
    }
    const char *c = getenv("COLUMNS");
    if (c) {
        int w = atoi(c);
        if (w > 0) {
            return w;
        }
    }
    return 80;
}
#else
#  include <sys/ioctl.h>
#  include <unistd.h>
static int terminal_width(void) {
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0) {
        return (int)ws.ws_col;
    }
    const char *c = getenv("COLUMNS");
    if (c) {
        int w = atoi(c);
        if (w > 0) {
            return w;
        }
    }
    return 80;
}
#endif

// --- wave parameters (unchanged from hadouken_wave.c) -------------------
#define ORIGIN_X 64.0
#define ORIGIN_Y 8.0
#define ASPECT   2.0
#define K        0.60
#define OMEGA    5.0
#define FLOOR    0.45

// BAR_OVERHEAD = visible fixed chars in the bar line: " Flashing [" (11) + "] 100%" (6)
#define BAR_OVERHEAD 17
#define BAR_MIN       10     // minimum inner fill width
#define BAR_MAX      512     // guard against absurdly wide terminals
#define BAR_ROW   (FH + 2)   // terminal row for the progress bar (1-based)
#define AFTER_ROW (FH + 3)   // first free row after the animation+bar

// --- ANSI colour macros ---------------------------------------------------
#define ANSI_RESET        "\x1b[0m"     // reset all attributes
#define ANSI_BOLD         "\x1b[1m"     // bold / bright
#define ANSI_DIM          "\x1b[2m"     // dim / faint

// Progress-bar role colours
#define ANSI_BAR_LABEL    "\x1b[36m"     // label " Flashing " — cyan
#define ANSI_BAR_BRACKET  "\x1b[37m"    // brackets [ ]       — white
#define ANSI_BAR_FILLED   "\x1b[36;1m"  // filled  '='        — green bold
#define ANSI_BAR_EMPTY    "\x1b[2;37m"  // empty   '-'        — dim white
#define ANSI_BAR_PCT      "\x1b[33;1m"  // percentage number  — yellow bold

// --- cursor / screen control macros --------------------------------------
// Non-colour escape sequences.
#define ESC_CURSOR_HIDE   "\x1b[?25l"   // hide the cursor
#define ESC_CURSOR_SHOW   "\x1b[?25h"   // show the cursor
#define ESC_CURSOR_HOME   "\x1b[H"      // move to row 1, col 1
#define ESC_CURSOR_POS    "\x1b[%d;1H"  // move to row %d col 1  (needs int arg)
#define ESC_ERASE_LINE    "\x1b[2K"     // erase entire current line
#define ESC_ERASE_SCREEN  "\x1b[2J"     // erase entire screen
#define ESC_SYNC_ON       "\x1b[?2026h" // DEC 2026 synchronized output — on
#define ESC_SYNC_OFF      "\x1b[?2026l" // DEC 2026 synchronized output — off

static const char *GLYPHS = " .:;+xX#";

// --- shared state --------------------------------------------------------
static volatile sig_atomic_t g_resize = 0;   // set by SIGWINCH
static volatile int g_running  = 0;
static volatile int g_progress = 0;   // 0..100
static pthread_t g_thread;

// animation config – written once before hadouken_start()
static double g_fps        = 30.0;
static int    g_glyph_mode = 0;
static int    g_wave_mode  = 0;   // 0 = radial, 1 = beam

void hadouken_on_sigint(int s)  {
    (void)s;
    g_running = 0;
}

#ifndef _WIN32
void hadouken_on_sigwinch(int s) {
    (void)s;
    g_resize = 1;
}
#endif

/*
 * Compute the inner fill width for the progress bar from the current terminal
 * width, clamped to [BAR_MIN, BAR_MAX].
 */
static int bar_inner_width(void) {
    int w = terminal_width() - BAR_OVERHEAD;
    if (w < BAR_MIN) {
        w = BAR_MIN;
    }
    if (w > BAR_MAX) {
        w = BAR_MAX;
    }
    return w;
}

// --- colour helpers ------------------------------------------------------
static inline int clamp8(double v) {
    if (v < 0)   {
        return 0;
    }
    if (v > 255) {
        return 255;
    }
    return (int)(v + 0.5);
}

static void fire_color(int x, int y, const Cell *c, double t, int mode, int *r, int *g, int *b) {
    double dx = x - ORIGIN_X;
    double dy = (y - ORIGIN_Y) * ASPECT;
    double d  = sqrt(dx * dx + dy * dy);
    double phase_var = mode ? (dx > 0 ? dx : 0.0) : d;
    double wave  = 0.5 + 0.5 * sin(phase_var * K - OMEGA * t);
    double atten = 1.0 - d * 0.012;

    if (atten < 0.35) {
        atten = 0.35;
    }

    if (atten > 1.0)  {
        atten = 1.0;
    }

    double inten = (FLOOR + (1.0 - FLOOR) * wave) * atten;
    double crest = wave * wave;

    *r = clamp8(c->r * inten + 70  * crest);
    *g = clamp8(c->g * inten + 110 * crest);
    *b = clamp8(c->b * inten + 50  * crest);
}

// --- line renderers ------------------------------------------------------

// Render one animation row into dst (same logic as hadouken_wave.c).
static int render_anim_line(char *dst, int y, double t, int glyph_mode, int mode) {
    int len = 0;
    int last_r = -1, last_g = -1, last_b = -1, last_has = -2;
    int pending_blanks = 0;

    for (int x = 0; x < FW; x++) {

        const Cell *c = &FRAME[y][x];
        int ch = c->ch;
        int has = c->has;
        int r = 0;
        int g = 0;
        int b = 0;

        if (ch == ' ' && !has) {
            pending_blanks++;
            continue;
        }

        if (c->fire) {

            fire_color(x, y, c, t, mode, &r, &g, &b);
            has = 1;

            if (glyph_mode) {

                double lum = (r + g + b) / 765.0;

                int idx = (int)(lum * 8);
                if (idx > 7) {
                    idx = 7;
                }

                ch = GLYPHS[idx];
                if (ch == ' ') {
                    ch = '.';
                }
            }
        } else if (has) {
            r = c->r;
            g = c->g;
            b = c->b;
        }

        if (pending_blanks) {
            memset(dst + len, ' ', pending_blanks);
            len += pending_blanks;
            pending_blanks = 0;
        }

        if (has != last_has || r != last_r || g != last_g || b != last_b) {
            if (has) {
                len += sprintf(dst + len, "\x1b[38;2;%d;%d;%dm", r, g, b);
            } else {
                len += sprintf(dst + len, ANSI_RESET);
            }
            last_has = has;
            last_r = r;
            last_g = g;
            last_b = b;
        }
        dst[len++] = (char)ch;
    }

    dst[len] = '\0';
    return len;
}

/*
 * Render the progress bar into dst.  bar_width is the inner fill width,
 * computed dynamically from the current terminal width each frame.
 *
 *  Flashing [========================================----] 100%
 *           ^<---------  bar_width chars  ----------->^
 */
static int render_progress_bar(char *dst, int pct, int bar_width) {
    int len = 0;
    int filled = (bar_width * pct) / 100;

    if (filled > bar_width) {
        filled = bar_width;
    }

    // label
    len += sprintf(dst + len, ANSI_BAR_LABEL " Flashing " ANSI_RESET ANSI_BAR_BRACKET "[" ANSI_RESET);

    // filled portion
    if (filled > 0) {
        len += sprintf(dst + len, ANSI_BAR_FILLED);
        for (int i = 0; i < filled; i++) {
            dst[len++] = '=';
        }
    }

    // empty portion
    if (filled < bar_width) {
        len += sprintf(dst + len, ANSI_BAR_EMPTY);
        for (int i = filled; i < bar_width; i++) {
            dst[len++] = '-';
        }
    }

    // closing bracket + percentage
    len += sprintf(dst + len, ANSI_RESET ANSI_BAR_BRACKET "] " ANSI_RESET ANSI_BAR_PCT "%3d%%" ANSI_RESET, pct);
    dst[len] = '\0';
    return len;
}

static double now_sec(void) {
    return msclock() / 1000.0;
}

// --- animation thread ----------------------------------------------------
static void *anim_thread(void *arg) {
    (void)arg;

    // static keeps these off the thread stack (BSS)
    static char cur [FH][FW * 24 + 16];
    static char prev[FH][FW * 24 + 16];
    static char out [FH * (FW * 24 + 32) + 512];

    // bar buf: BAR_MAX fill chars + ANSI escapes per char + fixed overhead
    static char bar [BAR_MAX + 256];

    int have_prev = 0;
    double frame_dt = 1.0 / g_fps;
    double start = now_sec();

    while (g_running) {
        double t0 = now_sec();
        double t = t0 - start;
        int pct = g_progress;   // single-read snapshot

        // On terminal resize: flush the diff cache so all rows redraw cleanly
        if (g_resize) {
            g_resize   = 0;
            have_prev  = 0;
        }

        // dynamic: re-queried every frame
        int bw = bar_inner_width();

        int n = 0;

        // sync on, home
        n += sprintf(out + n, ESC_SYNC_ON ESC_CURSOR_HOME);

        // animation rows (with per-line diffing)
        for (int y = 0; y < FH; y++) {

            int len = render_anim_line(cur[y], y, t, g_glyph_mode, g_wave_mode);

            if (have_prev && strcmp(cur[y], prev[y]) == 0) {
                continue;
            }

            n += sprintf(out + n, ESC_CURSOR_POS ESC_ERASE_LINE, y + 1);
            memcpy(out + n, cur[y], len);

            n += len;
            memcpy(prev[y], cur[y], len + 1);
        }

        // progress bar (always redrawn, width adapts to terminal)
        int blen = render_progress_bar(bar, pct, bw);
        n += sprintf(out + n, ESC_CURSOR_POS ESC_ERASE_LINE, BAR_ROW);
        memcpy(out + n, bar, blen);
        n += blen;

        // reset, sync off
        n += sprintf(out + n, ANSI_RESET ESC_SYNC_OFF);
        have_prev = 1;

        fwrite(out, 1, n, stdout);
        fflush(stdout);

        // fixed-timestep with render-time compensation
        double remain = frame_dt - (now_sec() - t0);
        if (remain > 0) {
            msleep((uint32_t)(remain * 1000));
        }
    }

    return NULL;
}

/*
 * Start the animation thread.
 *   fps        – frames per second (e.g. 30.0)
 *   glyph_mode – 1 = ASCII glyphs instead of colour blocks
 *   wave_mode  – 0 = radial rings, 1 = forward beam
 */
void hadouken_start(double fps, int glyph_mode, int wave_mode) {
    g_fps        = (fps > 0) ? fps : 30.0;
    g_glyph_mode = glyph_mode;
    g_wave_mode  = wave_mode;
    g_progress   = 0;
    g_running    = 1;

    // hide cursor, clear screen
    fputs(ESC_CURSOR_HIDE ESC_ERASE_SCREEN, stdout);
    fflush(stdout);
    pthread_create(&g_thread, NULL, anim_thread, NULL);
}

/*
 * Update the progress bar.
 * Safe to call from any thread.
 * pct is clamped to [0, 100].
 */
void hadouken_set_progress(int pct) {
    if (pct < 0) {
        pct = 0;
    }

    if (pct > 100) {
        pct = 100;
    }
    g_progress = pct;
}

/*
 * Stop the animation thread, then position the cursor on the line below the
 * progress bar and restore it so subsequent printf/puts output is visible.
 */
void hadouken_stop(void) {
    /* Wait 2 frame durations so the thread renders at least one more frame
     * with the final g_progress value (e.g. 100%) before we signal exit.
     * Without this, the thread may be mid-sleep and exit before painting 100%. */
    msleep((uint32_t)(2000.0 / g_fps));

    g_running = 0;
    pthread_join(g_thread, NULL);

    // Move below the progress bar, restore cursor visibility
    fprintf(stdout, ESC_CURSOR_POS ANSI_RESET ESC_CURSOR_SHOW "\n", AFTER_ROW);
    fflush(stdout);
}
