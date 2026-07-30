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
// Host side DSP primitives - FFT, windows, power spectrum, STFT
//-----------------------------------------------------------------------------

#include "pm3_dsp.h"

#include <stdlib.h>
#include <string.h>
#include <math.h>

#include "pm3_cmd.h"
#include "commonutil.h"    // ARRAYLEN

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

// refuse to allocate a spectrogram larger than this, in doubles
#define PM3_DSP_MAX_STFT_CELLS  (8 * 1024 * 1024)

// peaks closer together than this many bins are treated as the same peak
#define PM3_DSP_PEAK_SEP        3
// half width of the neighbourhood used to estimate the local noise floor
#define PM3_DSP_FLOOR_SPAN      48
// a peak has to be at least this prominent to take part in comb finding
#define COMB_MIN_PROMINENCE     8.0
// autocorrelation lag window when hunting for the message repeat period
#define PM3_DSP_ACORR_MIN_LAG       256
#define PM3_DSP_ACORR_MAX_LAG       32768
#define PM3_DSP_ACORR_MIN_STRENGTH  0.25
// Schmitt trigger level for run length extraction, in standard deviations
#define PM3_DSP_RUN_HYST            0.35
// longest run over chip, above which the code is carrying raw levels
#define PM3_DSP_RUN_TRANSITION      2.6
// a run this many chips long or less counts as short
#define PM3_DSP_RUN_SHORT           2.5
// Transition codes put essentially every run under that limit, raw levels
// leave a quarter of them above it.  Measured over the T5577 corpus the two
// populations sit at 0.95..0.99 and 0.61..0.81, so the boundary goes in the
// middle of that gap rather than at the edge of either.
#define PM3_DSP_RUN_SHORT_FRAC      0.88
// harmonics past this are not worth chasing
#define COMB_MAX_HARMONIC       12
// symbol clocks outside this range are not something any LF tag uses
#define COMB_MIN_CLK            4.0
#define COMB_MAX_CLK            600.0

size_t pm3_next_pow2(size_t v) {
    size_t p = 1;
    while (p < v && p < PM3_DSP_MAX_FFT) {
        p <<= 1;
    }
    return p;
}

static bool is_pow2(size_t v) {
    return (v != 0) && ((v & (v - 1)) == 0);
}

pm3_fft_plan_t *pm3_fft_plan_create(size_t n) {

    if (is_pow2(n) == false || n < 2 || n > PM3_DSP_MAX_FFT) {
        return NULL;
    }

    pm3_fft_plan_t *plan = calloc(1, sizeof(pm3_fft_plan_t));
    if (plan == NULL) {
        return NULL;
    }

    plan->n = n;
    plan->twiddle = calloc(n / 2, sizeof(pm3_cplx_t));
    plan->rev = calloc(n, sizeof(uint32_t));
    if (plan->twiddle == NULL || plan->rev == NULL) {
        pm3_fft_plan_destroy(plan);
        return NULL;
    }

    for (size_t k = 0; k < n / 2; k++) {
        double ang = -2.0 * M_PI * (double)k / (double)n;
        plan->twiddle[k].re = cos(ang);
        plan->twiddle[k].im = sin(ang);
    }

    // bit reversal permutation, built incrementally so we never need to know the width
    size_t shift = 0;
    while ((((size_t)1) << shift) < n) {
        shift++;
    }

    for (size_t i = 0; i < n; i++) {

        size_t r = 0;
        for (size_t b = 0; b < shift; b++) {

            if (i & (((size_t)1) << b)) {
                r |= ((size_t)1) << (shift - 1 - b);
            }
        }
        plan->rev[i] = (uint32_t)r;
    }

    return plan;
}

void pm3_fft_plan_destroy(pm3_fft_plan_t *plan) {
    if (plan == NULL) {
        return;
    }
    free(plan->twiddle);
    free(plan->rev);
    free(plan);
}

void pm3_fft(const pm3_fft_plan_t *plan, pm3_cplx_t *data, bool inverse) {

    if (plan == NULL || data == NULL) {
        return;
    }

    const size_t n = plan->n;

    // the inverse transform is the forward transform of the conjugate,
    // conjugated again and scaled.  Keeps a single twiddle table.
    if (inverse) {
        for (size_t i = 0; i < n; i++) {
            data[i].im = -data[i].im;
        }
    }

    for (size_t i = 0; i < n; i++) {
        size_t j = plan->rev[i];
        if (j > i) {
            pm3_cplx_t tmp = data[i];
            data[i] = data[j];
            data[j] = tmp;
        }
    }

    for (size_t span = 2; span <= n; span <<= 1) {

        const size_t half = span / 2;
        const size_t step = n / span;

        for (size_t base = 0; base < n; base += span) {
            for (size_t k = 0; k < half; k++) {

                const pm3_cplx_t w = plan->twiddle[k * step];
                pm3_cplx_t *lo = &data[base + k];
                pm3_cplx_t *hi = &data[base + k + half];

                const double tr = hi->re * w.re - hi->im * w.im;
                const double ti = hi->re * w.im + hi->im * w.re;

                hi->re = lo->re - tr;
                hi->im = lo->im - ti;
                lo->re += tr;
                lo->im += ti;
            }
        }
    }

    if (inverse) {
        const double scale = 1.0 / (double)n;
        for (size_t i = 0; i < n; i++) {
            data[i].re *= scale;
            data[i].im *= -scale;
        }
    }
}

bool pm3_window_from_str(const char *str, pm3_window_t *out) {

    if (str == NULL || out == NULL) {
        return false;
    }

    if (strcmp(str, "hann") == 0) {
        *out = PM3_WIN_HANN;
    } else if (strcmp(str, "hamming") == 0) {
        *out = PM3_WIN_HAMMING;
    } else if (strcmp(str, "blackman") == 0) {
        *out = PM3_WIN_BLACKMAN;
    } else if (strcmp(str, "rect") == 0) {
        *out = PM3_WIN_RECT;
    } else {
        return false;
    }
    return true;
}

const char *pm3_window_name(pm3_window_t win) {
    switch (win) {
        case PM3_WIN_HANN:
            return "hann";
        case PM3_WIN_HAMMING:
            return "hamming";
        case PM3_WIN_BLACKMAN:
            return "blackman";
        case PM3_WIN_RECT:
            return "rect";
    }
    return "unknown";
}

void pm3_apply_window(double *data, size_t len, pm3_window_t win) {

    if (data == NULL || len == 0 || win == PM3_WIN_RECT) {
        return;
    }

    if (len == 1) {
        data[0] = 0;
        return;
    }

    const double denom = (double)(len - 1);

    for (size_t i = 0; i < len; i++) {

        const double phase = 2.0 * M_PI * (double)i / denom;
        double w = 1.0;

        switch (win) {
            case PM3_WIN_HANN: {
                w = 0.5 * (1.0 - cos(phase));
                break;
            }
            case PM3_WIN_HAMMING: {
                w = 0.54 - 0.46 * cos(phase);
                break;
            }
            case PM3_WIN_BLACKMAN: {
                w = 0.42 - 0.5 * cos(phase) + 0.08 * cos(2.0 * phase);
                break;
            }
            case PM3_WIN_RECT: {
                break;
            }
        }
        data[i] *= w;
    }
}

void pm3_remove_mean(double *data, size_t len) {

    if (data == NULL || len == 0) {
        return;
    }

    double sum = 0.0;
    for (size_t i = 0; i < len; i++) {
        sum += data[i];
    }

    const double mean = sum / (double)len;
    for (size_t i = 0; i < len; i++) {
        data[i] -= mean;
    }
}

double *pm3_extract(const int32_t *src, size_t len, size_t start, size_t count) {

    if (src == NULL || count == 0 || start >= len || (len - start) < count) {
        return NULL;
    }

    double *out = calloc(count, sizeof(double));
    if (out == NULL) {
        return NULL;
    }

    for (size_t i = 0; i < count; i++) {
        out[i] = (double)src[start + i];
    }

    // LF captures carry a large DC offset.  Left in place it dominates bin 0
    // and its leakage skirt swamps everything we care about.
    pm3_remove_mean(out, count);

    double energy = 0.0;
    for (size_t i = 0; i < count; i++) {
        energy += out[i] * out[i];
    }

    // a constant input leaves nothing behind, hand back the zeros and let the
    // caller decide what to say about it
    if (energy > 0.0) {
        const double scale = 1.0 / sqrt(energy / (double)count);
        for (size_t i = 0; i < count; i++) {
            out[i] *= scale;
        }
    }

    return out;
}

void pm3_delay_multiply(const double *in, size_t len, size_t lag, double *out) {

    if (in == NULL || out == NULL || len == 0) {
        return;
    }

    for (size_t i = 0; i < len; i++) {
        out[i] = (i < lag) ? 0.0 : in[i] * in[i - lag];
    }

    pm3_remove_mean(out, len);
}

int pm3_spectrum(const double *sig, size_t len, size_t n, pm3_window_t win, pm3_spectrum_t *out) {

    if (sig == NULL || out == NULL || len == 0 || is_pow2(n) == false || n < 2) {
        return PM3_EINVARG;
    }

    memset(out, 0, sizeof(pm3_spectrum_t));

    pm3_fft_plan_t *plan = pm3_fft_plan_create(n);
    if (plan == NULL) {
        return PM3_EMALLOC;
    }

    pm3_cplx_t *buf = calloc(n, sizeof(pm3_cplx_t));
    double *win_buf = calloc(n, sizeof(double));
    if (buf == NULL || win_buf == NULL) {
        free(buf);
        free(win_buf);
        pm3_fft_plan_destroy(plan);
        return PM3_EMALLOC;
    }

    const size_t take = (len < n) ? len : n;
    memcpy(win_buf, sig, take * sizeof(double));
    pm3_apply_window(win_buf, n, win);

    for (size_t i = 0; i < n; i++) {
        buf[i].re = win_buf[i];
        buf[i].im = 0.0;
    }
    free(win_buf);

    pm3_fft(plan, buf, false);
    pm3_fft_plan_destroy(plan);

    out->n = n;
    out->nbins = (n / 2) + 1;
    out->mag = calloc(out->nbins, sizeof(double));
    if (out->mag == NULL) {
        free(buf);
        memset(out, 0, sizeof(pm3_spectrum_t));
        return PM3_EMALLOC;
    }

    for (size_t i = 0; i < out->nbins; i++) {
        out->mag[i] = sqrt(buf[i].re * buf[i].re + buf[i].im * buf[i].im);
    }
    free(buf);

    out->peak = 0.0;
    out->peak_bin = 0;
    for (size_t i = PM3_DSP_DC_GUARD; i < out->nbins; i++) {
        if (out->mag[i] > out->peak) {
            out->peak = out->mag[i];
            out->peak_bin = i;
        }
    }

    return PM3_SUCCESS;
}

void pm3_spectrum_free(pm3_spectrum_t *spec) {
    if (spec == NULL) {
        return;
    }
    free(spec->mag);
    memset(spec, 0, sizeof(pm3_spectrum_t));
}

// noise floor around `bin`, ignoring the peak itself and its immediate skirt
static double local_floor(const pm3_spectrum_t *spec, size_t bin) {

    double sum = 0.0;
    size_t cnt = 0;

    const size_t lo = (bin > PM3_DSP_FLOOR_SPAN) ? bin - PM3_DSP_FLOOR_SPAN : PM3_DSP_DC_GUARD;
    size_t hi = bin + PM3_DSP_FLOOR_SPAN;
    if (hi >= spec->nbins) {
        hi = spec->nbins - 1;
    }

    for (size_t i = lo; i <= hi; i++) {
        if (i + PM3_DSP_PEAK_SEP >= bin && i <= bin + PM3_DSP_PEAK_SEP) {
            continue;
        }
        sum += spec->mag[i];
        cnt++;
    }

    if (cnt == 0) {
        return 0.0;
    }
    return sum / (double)cnt;
}

size_t pm3_find_peaks(const pm3_spectrum_t *spec, pm3_peak_t *peaks, size_t max_peaks) {

    if (spec == NULL || spec->mag == NULL || peaks == NULL || max_peaks == 0) {
        return 0;
    }
    if (spec->nbins < PM3_DSP_DC_GUARD + 3) {
        return 0;
    }

    size_t found = 0;

    // greedy: repeatedly take the strongest local maximum that is not already
    // covered by something we picked
    for (size_t pick = 0; pick < max_peaks; pick++) {

        double best = 0.0;
        size_t best_bin = 0;
        bool have = false;

        for (size_t i = PM3_DSP_DC_GUARD + 1; i + 1 < spec->nbins; i++) {

            if (spec->mag[i] < spec->mag[i - 1] || spec->mag[i] < spec->mag[i + 1]) {
                continue;
            }

            bool taken = false;
            for (size_t k = 0; k < found; k++) {
                const size_t d = (peaks[k].bin > i) ? peaks[k].bin - i : i - peaks[k].bin;
                if (d <= PM3_DSP_PEAK_SEP) {
                    taken = true;
                    break;
                }
            }
            if (taken) {
                continue;
            }

            if (have == false || spec->mag[i] > best) {
                best = spec->mag[i];
                best_bin = i;
                have = true;
            }
        }

        if (have == false || best <= 0.0) {
            break;
        }

        // parabolic interpolation over the three bins around the peak, in dB.
        // The fractional part is the whole point of this table.
        const double a = 20.0 * log10(spec->mag[best_bin - 1] + 1e-30);
        const double b = 20.0 * log10(spec->mag[best_bin] + 1e-30);
        const double c = 20.0 * log10(spec->mag[best_bin + 1] + 1e-30);
        const double denom = a - (2.0 * b) + c;

        double delta = 0.0;
        if (fabs(denom) > 1e-12) {
            delta = 0.5 * (a - c) / denom;
        }
        if (delta > 0.5) {
            delta = 0.5;
        }
        if (delta < -0.5) {
            delta = -0.5;
        }

        peaks[found].bin = best_bin;
        peaks[found].freq = ((double)best_bin + delta) / (double)spec->n;
        peaks[found].clk = (peaks[found].freq > 0.0) ? 1.0 / peaks[found].freq : 0.0;
        peaks[found].mag_db = 20.0 * log10((best / (spec->peak + 1e-30)) + 1e-30);

        const double floor_mag = local_floor(spec, best_bin);
        peaks[found].prominence = 20.0 * log10((best / (floor_mag + 1e-30)) + 1e-30);

        found++;
    }

    return found;
}

int pm3_stft(const double *sig, size_t len, size_t n, size_t hop, pm3_window_t win, double anchor, pm3_stft_t *out) {

    if (sig == NULL || out == NULL || hop == 0 || is_pow2(n) == false || n < 2) {
        return PM3_EINVARG;
    }
    if (len < n) {
        return PM3_EINVARG;
    }

    memset(out, 0, sizeof(pm3_stft_t));

    const size_t nframes = ((len - n) / hop) + 1;
    const size_t nbins = (n / 2) + 1;

    if (nframes == 0 || (nframes * nbins) > PM3_DSP_MAX_STFT_CELLS) {
        return PM3_EINVARG;
    }

    out->n = n;
    out->hop = hop;
    out->nframes = nframes;
    out->nbins = nbins;
    out->frame_start = calloc(nframes, sizeof(size_t));
    out->peak_freq = calloc(nframes, sizeof(double));
    out->peak_mag = calloc(nframes, sizeof(double));
    out->frame_energy = calloc(nframes, sizeof(double));
    out->ridge = calloc(nframes * nbins, sizeof(double));

    if (out->frame_start == NULL || out->peak_freq == NULL || out->peak_mag == NULL || out->frame_energy == NULL || out->ridge == NULL) {
        pm3_stft_free(out);
        return PM3_EMALLOC;
    }

    pm3_fft_plan_t *plan = pm3_fft_plan_create(n);
    pm3_cplx_t *buf = calloc(n, sizeof(pm3_cplx_t));
    double *frame = calloc(n, sizeof(double));

    if (plan == NULL || buf == NULL || frame == NULL) {
        pm3_fft_plan_destroy(plan);
        free(buf);
        free(frame);
        pm3_stft_free(out);
        return PM3_EMALLOC;
    }

    for (size_t f = 0; f < nframes; f++) {

        const size_t off = f * hop;
        out->frame_start[f] = off;

        memcpy(frame, sig + off, n * sizeof(double));
        pm3_remove_mean(frame, n);
        pm3_apply_window(frame, n, win);

        for (size_t i = 0; i < n; i++) {
            buf[i].re = frame[i];
            buf[i].im = 0.0;
        }

        pm3_fft(plan, buf, false);

        double best = 0.0;
        size_t best_bin = 0;
        double energy = 0.0;

        size_t search_lo = PM3_DSP_DC_GUARD;
        size_t search_hi = nbins;

        if (anchor > 0.0) {

            const double lo = (anchor / 1.2) * (double)n;
            const double hi = (anchor * 1.2) * (double)n;

            if (lo > (double)search_lo) {
                search_lo = (size_t)lo;
            }

            if (hi < (double)search_hi) {
                search_hi = (size_t)hi + 1;
            }

            if (search_hi <= search_lo + 2) {
                search_lo = PM3_DSP_DC_GUARD;
                search_hi = nbins;
            }
        }

        for (size_t i = 0; i < nbins; i++) {

            const double m = sqrt(buf[i].re * buf[i].re + buf[i].im * buf[i].im);

            out->ridge[(f * nbins) + i] = m;

            if (i >= PM3_DSP_DC_GUARD) {
                energy += m * m;
            }

            if (i >= search_lo && i < search_hi && m > best) {
                best = m;
                best_bin = i;
            }
        }

        // sub bin refine the dominant line so drift shows up as a smooth curve
        // rather than a staircase of whole bins
        double delta = 0.0;
        if (best_bin > 0 && best_bin + 1 < nbins) {

            const double a = 20.0 * log10(out->ridge[(f * nbins) + best_bin - 1] + 1e-30);
            const double b = 20.0 * log10(out->ridge[(f * nbins) + best_bin] + 1e-30);
            const double c = 20.0 * log10(out->ridge[(f * nbins) + best_bin + 1] + 1e-30);
            const double denom = a - (2.0 * b) + c;

            if (fabs(denom) > 1e-12) {
                delta = 0.5 * (a - c) / denom;
            }

            if (delta > 0.5) {
                delta = 0.5;
            }

            if (delta < -0.5) {
                delta = -0.5;
            }
        }

        out->peak_mag[f] = best;
        out->peak_freq[f] = ((double)best_bin + delta) / (double)n;
        out->frame_energy[f] = sqrt(energy);
    }

    pm3_fft_plan_destroy(plan);
    free(buf);
    free(frame);
    return PM3_SUCCESS;
}

void pm3_stft_free(pm3_stft_t *st) {
    if (st == NULL) {
        return;
    }
    free(st->frame_start);
    free(st->peak_freq);
    free(st->peak_mag);
    free(st->frame_energy);
    free(st->ridge);
    memset(st, 0, sizeof(pm3_stft_t));
}

const char *pm3_family_name(pm3_family_t fam) {
    switch (fam) {
        case PM3_FAM_UNKNOWN:
            return "unknown";
        case PM3_FAM_ASK:
            return "ASK";
        case PM3_FAM_FSK:
            return "FSK";
        case PM3_FAM_PSK:
            return "PSK";
        case PM3_FAM_NRZ:
            return "NRZ";
        case PM3_FAM_MANCHESTER:
            return "MANCHESTER";
    }
    return "unknown";
}

const char *pm3_confidence_name(pm3_confidence_t conf) {
    switch (conf) {
        case PM3_CONF_NONE:
            return "none";
        case PM3_CONF_LOW:
            return "low";
        case PM3_CONF_MEDIUM:
            return "medium";
        case PM3_CONF_HIGH:
            return "high";
    }
    return "none";
}

// prominence of the plain spectrum at an arbitrary frequency, used to ask
// "is there a line here as well, or only after the non linearity?"
static double prominence_at(const pm3_spectrum_t *spec, double freq) {

    if (freq <= 0.0) {
        return 0.0;
    }

    size_t bin = (size_t)((freq * (double)spec->n) + 0.5);
    if (bin < PM3_DSP_DC_GUARD || bin + 1 >= spec->nbins) {
        return 0.0;
    }

    // take the strongest of the three bins around the target, a fractional
    // clock puts the line between bins
    double best = spec->mag[bin];
    if (spec->mag[bin - 1] > best) {
        best = spec->mag[bin - 1];
    }

    if (spec->mag[bin + 1] > best) {
        best = spec->mag[bin + 1];
    }

    return 20.0 * log10((best / (local_floor(spec, bin) + 1e-30)) + 1e-30);
}

// strongest peak whose implied clock falls inside [lo, hi] samples/symbol
static const pm3_peak_t *peak_in_range(const pm3_peak_t *peaks, size_t n, double lo, double hi) {

    const pm3_peak_t *best = NULL;

    for (size_t i = 0; i < n; i++) {
        if (peaks[i].clk < lo || peaks[i].clk > hi) {
            continue;
        }

        if (best == NULL || peaks[i].prominence > best->prominence) {
            best = &peaks[i];
        }
    }
    return best;
}

static bool near(double got, double want, double tol) {
    return fabs(got - want) <= (want * tol);
}

// Look for the two field clock lines the existing FSK demodulators expect.
static bool find_fsk_pair(const pm3_peak_t *peaks, size_t n, double *lo, double *hi, double *ratio) {

    static const double pairs[][2] = { {8.0, 10.0}, {5.0, 8.0} };

    for (size_t p = 0; p < ARRAYLEN(pairs); p++) {

        const pm3_peak_t *a = NULL;
        const pm3_peak_t *b = NULL;

        for (size_t i = 0; i < n; i++) {
            if (near(peaks[i].clk, pairs[p][0], 0.12) && (a == NULL || peaks[i].prominence > a->prominence)) {
                a = &peaks[i];
            }

            if (near(peaks[i].clk, pairs[p][1], 0.12) && (b == NULL || peaks[i].prominence > b->prominence)) {
                b = &peaks[i];
            }
        }

        // Both tones have to be genuinely strong, and comparable to each
        // other: an FSK stream spends time on each, so neither line dominates.
        // A single PSK subcarrier plus one spurious neighbour would otherwise pass for a pair.
        if (a != NULL && b != NULL
                && a->prominence > 10.0 && b->prominence > 10.0
                && fabs(a->mag_db - b->mag_db) < 10.0) {

            *hi = a->clk;
            *lo = b->clk;
            *ratio = b->clk / a->clk;
            return true;
        }
    }
    return false;
}

// Find the spacing of the harmonic comb that best explains a set of peaks.
//
// Squaring a symbol stream produces energy at every integer multiple of the symbol rate.
// Picking the tallest line therefore lands on a harmonic as often as not.
// Try each peak and each peak divided by a small integer as a candidate spacing
// and keep whichever one places the most peaks on a multiple of itself
static double comb_fundamental(const pm3_peak_t *peaks, size_t npeaks, size_t n, double min_clk) {

    double best = 0.0;
    size_t best_count = 0;

    for (size_t i = 0; i < npeaks; i++) {

        if (peaks[i].prominence < COMB_MIN_PROMINENCE) {
            continue;
        }

        for (size_t div = 1; div <= 4; div++) {

            const double cand = peaks[i].freq / (double)div;
            if (cand <= 0.0) {
                continue;
            }

            size_t count = 0;
            for (size_t j = 0; j < npeaks; j++) {

                if (peaks[j].prominence < COMB_MIN_PROMINENCE) {
                    continue;
                }

                const double k = floor((peaks[j].freq / cand) + 0.5);
                if (k < 1.0 || k > (double)COMB_MAX_HARMONIC) {
                    continue;
                }

                // a line may sit about a bin away from the ideal multiple.
                // The tolerance is tied to the peak's own frequency, not to the candidate spacing
                const double tol = (1.5 / (double)n) + (0.015 * peaks[j].freq);
                if (fabs(peaks[j].freq - (k * cand)) <= tol) {
                    count++;
                }
            }

            if (count > best_count || (count == best_count && cand > best)) {
                best_count = count;
                best = cand;
            }
        }
    }

    // a single line is not a comb
    if (best_count < 2) {
        return 0.0;
    }
    // and no LF tag clocks itself outside this range
    if (best < (1.0 / COMB_MAX_CLK) || best > (1.0 / min_clk)) {
        return 0.0;
    }
    return best;
}

static pm3_confidence_t confidence_from_db(double db) {
    if (db >= 12.0) {
        return PM3_CONF_HIGH;
    }

    if (db >= 6.0) {
        return PM3_CONF_MEDIUM;
    }

    if (db >= 2.0) {
        return PM3_CONF_LOW;
    }

    return PM3_CONF_NONE;
}

static int cmp_double(const void *a, const void *b);

// Rectified, low passed copy of `sig` with its own DC left in place.
// The window is centred so a switching edge keeps its position
static double *envelope_raw(const double *sig, size_t len, size_t smooth) {

    if (sig == NULL || len == 0) {
        return NULL;
    }

    if (smooth == 0) {
        smooth = PM3_DSP_ENVELOPE_SMOOTH;
    }
    if (smooth > len) {
        smooth = len;
    }

    double *out = calloc(len, sizeof(double));
    double *ps = calloc(len + 1, sizeof(double));
    if (out == NULL || ps == NULL) {
        free(out);
        free(ps);
        return NULL;
    }

    double mean = 0.0;
    for (size_t i = 0; i < len; i++) {
        mean += sig[i];
    }
    mean /= (double)len;

    for (size_t i = 0; i < len; i++) {
        ps[i + 1] = ps[i] + fabs(sig[i] - mean);
    }

    const size_t half = smooth / 2;

    for (size_t i = 0; i < len; i++) {
        const size_t lo = (i > half) ? (i - half) : 0;
        size_t hi = i + smooth - half;
        if (hi > len) {
            hi = len;
        }
        out[i] = (ps[hi] - ps[lo]) / (double)(hi - lo);
    }

    free(ps);
    return out;
}

double *pm3_envelope(const double *sig, size_t len, size_t smooth) {

    double *out = envelope_raw(sig, len, smooth);
    if (out == NULL) {
        return NULL;
    }

    pm3_remove_mean(out, len);

    double energy = 0.0;
    for (size_t i = 0; i < len; i++) {
        energy += out[i] * out[i];
    }

    if (energy > 0.0) {
        const double scale = 1.0 / sqrt(energy / (double)len);
        for (size_t i = 0; i < len; i++) {
            out[i] *= scale;
        }
    }

    return out;
}

double pm3_envelope_depth(const double *sig, size_t len) {

    if (sig == NULL || len < 32) {
        return 0.0;
    }

    double *env = envelope_raw(sig, len, 0);
    if (env == NULL) {
        return 0.0;
    }

    // percentiles rather than min and max.
    // one clipped sample or one dead spot in the capture does not impact
    const size_t want = 8192;
    const size_t stride = (len > want) ? (len / want) : 1;

    double *s = calloc((len / stride) + 1, sizeof(double));
    if (s == NULL) {
        free(env);
        return 0.0;
    }

    size_t cnt = 0;
    for (size_t i = 0; i < len; i += stride) {
        s[cnt++] = env[i];
    }
    free(env);

    if (cnt < 16) {
        free(s);
        return 0.0;
    }

    qsort(s, cnt, sizeof(double), cmp_double);

    const double hi = s[(size_t)((double)cnt * 0.9)];
    const double lo = s[(size_t)((double)cnt * 0.1)];
    free(s);

    return ((hi + lo) > 0.0) ? ((hi - lo) / (hi + lo)) : 0.0;
}

void pm3_slice_free(pm3_slice_t *out) {

    if (out == NULL) {
        return;
    }
    free(out->bits);
    out->bits = NULL;
    out->nbits = 0;
}

int pm3_ask_slice(const double *sig, size_t len, double clk, pm3_slice_t *out) {

    if (sig == NULL || out == NULL || clk < 2.0 || len < (size_t)(clk * 4.0)) {
        return PM3_EINVARG;
    }

    memset(out, 0, sizeof(pm3_slice_t));

    // Prefix sums, so the average over a chip window costs two lookups no matter how wide the chip is.
    double *ps = calloc(len + 1, sizeof(double));
    if (ps == NULL) {
        return PM3_EMALLOC;
    }
    for (size_t i = 0; i < len; i++) {
        ps[i + 1] = ps[i] + sig[i];
    }

    // Robust levels rather than min and max: one clipped sample does not set the threshold for the capture.
    const size_t want = 4096;
    const size_t stride = (len > want) ? (len / want) : 1;

    double *s = calloc((len / stride) + 1, sizeof(double));
    if (s == NULL) {
        free(ps);
        return PM3_EMALLOC;
    }

    size_t cnt = 0;
    for (size_t i = 0; i < len; i += stride) {
        s[cnt++] = sig[i];
    }
    qsort(s, cnt, sizeof(double), cmp_double);

    const double lo = s[(size_t)((double)cnt * 0.1)];
    const double hi = s[(size_t)((double)cnt * 0.9)];
    free(s);

    const double thr = (hi + lo) * 0.5;
    const double span = (hi - lo) * 0.5;

    if (span <= 0.0) {
        free(ps);
        return PM3_ESOFT;
    }

    const size_t nsym = (size_t)(((double)len - clk) / clk);
    if (nsym < 4) {
        free(ps);
        return PM3_ESOFT;
    }

    // The middle half of the chip. Wide enough to average the noise down,
    // narrow enough that a late edge on either side never reaches it.
    const size_t half = (size_t)(clk * 0.25);
    const size_t nphase = (size_t)clk;

    double best_score = -1.0;
    size_t best_phase = 0;

    for (size_t p = 0; p < nphase; p++) {

        double score = 0.0;

        for (size_t k = 0; k < nsym; k++) {

            const double centre = (double)p + ((double)k + 0.5) * clk;
            const size_t a = (size_t)(centre - (double)half);
            const size_t b = (size_t)(centre + (double)half);

            if (b >= len || b <= a) {
                break;
            }

            const double mean = (ps[b] - ps[a]) / (double)(b - a);
            score += fabs(mean - thr);
        }

        if (score > best_score) {
            best_score = score;
            best_phase = p;
        }
    }

    out->bits = calloc(nsym, sizeof(uint8_t));
    if (out->bits == NULL) {
        free(ps);
        return PM3_EMALLOC;
    }

    const double dead = span * 0.15;
    double eye = 0.0;

    for (size_t k = 0; k < nsym; k++) {

        const double centre = (double)best_phase + ((double)k + 0.5) * clk;
        const size_t a = (size_t)(centre - (double)half);
        const size_t b = (size_t)(centre + (double)half);

        if (b >= len || b <= a) {
            break;
        }

        const double mean = (ps[b] - ps[a]) / (double)(b - a);
        const double dist = fabs(mean - thr);

        if (dist < dead) {
            out->bits[out->nbits] = 7;
            out->nerrors++;
        } else {
            out->bits[out->nbits] = (mean > thr) ? 1 : 0;
        }

        eye += dist / span;
        out->nbits++;
    }

    free(ps);

    out->phase = best_phase;
    out->eye = (out->nbits) ? (eye / (double)out->nbits) : 0.0;

    return (out->nbits > 0) ? PM3_SUCCESS : PM3_ESOFT;
}

bool pm3_is_switched_carrier(const double *sig, size_t len) {

    if (sig == NULL || len < 256) {
        return false;
    }

    double mean = 0.0;
    for (size_t i = 0; i < len; i++) {
        mean += sig[i];
    }
    mean /= (double)len;

    size_t flips = 0, pairs = 0;
    int prev = 0;

    for (size_t i = 0; i < len; i++) {

        const double d = sig[i] - mean;
        const int s = (d > 0.0) ? 1 : ((d < 0.0) ? -1 : 0);

        if (s == 0) {
            continue;
        }

        if (prev != 0) {
            pairs++;
            if (s != prev) {
                flips++;
            }
        }
        prev = s;
    }

    if (pairs == 0) {
        return false;
    }

    if (((double)flips / (double)pairs) < PM3_DSP_FLIP_FRAC) {
        return false;
    }

    return (pm3_envelope_depth(sig, len) > PM3_DSP_ENVELOPE_DEPTH);
}

static int analyse_once(const double *sig, size_t len, size_t n, pm3_window_t win, pm3_spec_analysis_t *out) {

    if (sig == NULL || out == NULL || len == 0) {
        return PM3_EINVARG;
    }

    memset(out, 0, sizeof(pm3_spec_analysis_t));

    const size_t top = PM3_DSP_MAX_PEAKS;

    pm3_spectrum_t plain;
    int res = pm3_spectrum(sig, len, n, win, &plain);
    if (res != PM3_SUCCESS) {
        return res;
    }

    out->npeaks = pm3_find_peaks(&plain, out->peaks, top);

    double *work = calloc(len, sizeof(double));
    if (work == NULL) {
        pm3_spectrum_free(&plain);
        return PM3_EMALLOC;
    }

    pm3_spectrum_t sq;
    memset(&sq, 0, sizeof(sq));

    pm3_delay_multiply(sig, len, 0, work);
    if (pm3_spectrum(work, len, n, win, &sq) == PM3_SUCCESS) {
        out->have_sq = true;
        out->nsq_peaks = pm3_find_peaks(&sq, out->sq_peaks, top);
    }

    static const size_t lags[PM3_DSP_NDELAYS] = { 1, 2, 4, 8 };
    out->ndelay = PM3_DSP_NDELAYS;

    for (size_t i = 0; i < PM3_DSP_NDELAYS; i++) {

        out->delay[i] = lags[i];
        pm3_delay_multiply(sig, len, lags[i], work);

        pm3_spectrum_t ds;
        if (pm3_spectrum(work, len, n, win, &ds) != PM3_SUCCESS) {
            continue;
        }

        pm3_peak_t got[1];
        if (pm3_find_peaks(&ds, got, 1) == 1) {
            out->delay_peak[i] = got[0];
            out->delay_valid[i] = true;
        }
        pm3_spectrum_free(&ds);
    }
    free(work);

    // low frequency energy relative to the strongest line.
    // NRZ piles up at DC,
    // Manchester and biphase have null.
    double dc_sum = 0.0;
    size_t dc_cnt = 0;
    const size_t dc_hi = (plain.nbins < 32) ? plain.nbins : 32;
    for (size_t i = PM3_DSP_DC_GUARD; i < dc_hi; i++) {
        dc_sum += plain.mag[i];
        dc_cnt++;
    }
    out->dc_ratio = (dc_cnt && plain.peak > 0.0) ? (dc_sum / (double)dc_cnt) / plain.peak : 0.0;

    const pm3_peak_t *carrier = peak_in_range(out->peaks, out->npeaks, 1.8, 12.0);
    if (carrier != NULL && carrier->prominence > 4.0) {
        out->have_carrier = true;
        out->carrier_clk = carrier->clk;
    }

    if (out->have_carrier && out->carrier_clk <= PM3_DSP_NYQUIST_CLK) {
        out->carrier_at_nyquist = true;
        out->envelope_depth = pm3_envelope_depth(sig, len);
        out->needs_envelope = (out->envelope_depth > PM3_DSP_ENVELOPE_DEPTH);
    }

    const bool is_fsk = find_fsk_pair(out->peaks, out->npeaks, &out->fsk_clk_lo, &out->fsk_clk_hi, &out->fsk_ratio);

    const double min_clk = is_fsk ? (out->fsk_clk_lo * 2.0) : COMB_MIN_CLK;

    double fundamental = 0.0;
    if (out->have_sq) {
        fundamental = comb_fundamental(out->sq_peaks, out->nsq_peaks, sq.n, min_clk);
    }

    if (fundamental > 0.0) {

        out->symbol_clk = 1.0 / fundamental;
        out->have_symbol_clk = true;
        out->sq_prominence = prominence_at(&sq, fundamental);

        const double second = prominence_at(&sq, fundamental * 2.0);
        out->transition_coded = (second - out->sq_prominence) > 6.0;

    } else {
        const pm3_peak_t *sym_plain = peak_in_range(out->peaks, out->npeaks, 12.0, 600.0);
        if (sym_plain != NULL) {
            out->symbol_clk = sym_plain->clk;
            out->have_symbol_clk = true;
        }
    }

    if (out->have_symbol_clk) {
        out->sym_prominence = prominence_at(&plain, 1.0 / out->symbol_clk);
    }

    if (is_fsk) {

        out->family = PM3_FAM_FSK;
        out->confidence = confidence_from_db(
                              0.5 * (prominence_at(&plain, 1.0 / out->fsk_clk_lo) + prominence_at(&plain, 1.0 / out->fsk_clk_hi))
                          );

    } else if (out->have_carrier) {

        out->family = PM3_FAM_PSK;
        out->confidence = confidence_from_db(prominence_at(&plain, 1.0 / out->carrier_clk));

    } else if (out->transition_coded) {

        out->family = PM3_FAM_MANCHESTER;
        out->confidence = confidence_from_db(out->sq_prominence);

    } else if (out->dc_ratio > 0.4) {

        out->family = PM3_FAM_NRZ;
        out->confidence = confidence_from_db(out->sq_prominence);

    } else if (out->have_symbol_clk && out->sq_prominence > 6.0) {

        out->family = PM3_FAM_ASK;
        out->confidence = confidence_from_db(out->sq_prominence);

    } else {
        out->family = PM3_FAM_UNKNOWN;
        out->confidence = PM3_CONF_NONE;
    }

    pm3_spectrum_free(&plain);
    if (out->have_sq) {
        pm3_spectrum_free(&sq);
    }
    return PM3_SUCCESS;
}

int pm3_analyse(const double *sig, size_t len, size_t n, pm3_window_t win, pm3_spec_analysis_t *out) {

    int res = analyse_once(sig, len, n, win, out);
    if (res != PM3_SUCCESS || out->needs_envelope == false) {
        return res;
    }

    const double carrier_clk = out->carrier_clk;
    const double depth = out->envelope_depth;

    double *env = pm3_envelope(sig, len, 0);
    if (env == NULL) {
        return res;
    }

    pm3_spec_analysis_t inner;
    const int inner_res = analyse_once(env, len, n, win, &inner);
    free(env);

    if (inner_res != PM3_SUCCESS) {
        return res;
    }

    *out = inner;
    out->carrier_at_nyquist = true;
    out->needs_envelope = true;
    out->envelope_depth = depth;
    out->carrier_clk = carrier_clk;
    out->have_carrier = true;

    return PM3_SUCCESS;
}

static int cmp_double(const void *a, const void *b) {

    const double x = *(const double *)a;
    const double y = *(const double *)b;

    if (x < y) {
        return -1;
    }

    if (x > y) {
        return 1;
    }
    return 0;
}

int pm3_signal_stats(const double *sig, size_t len, pm3_sigstat_t *out) {

    if (sig == NULL || out == NULL || len < 256) {
        return PM3_EINVARG;
    }

    memset(out, 0, sizeof(pm3_sigstat_t));

    double sumsq = 0.0;
    for (size_t i = 0; i < len; i++) {
        sumsq += sig[i] * sig[i];
    }

    const double sd = sqrt(sumsq / (double)len);
    if (sd <= 0.0) {
        return PM3_ESOFT;
    }

    const double hi_th = sd * PM3_DSP_RUN_HYST;
    const double lo_th = -hi_th;

    double *runs = calloc(len + 1, sizeof(double));
    if (runs == NULL) {
        return PM3_EMALLOC;
    }

    size_t nruns = 0;
    int state = 0;
    size_t last_edge = 0;

    for (size_t i = 0; i < len; i++) {

        int next = state;
        if (sig[i] > hi_th) {
            next = 1;
        } else if (sig[i] < lo_th) {
            next = -1;
        }

        if (state == 0) {
            state = next;
            last_edge = i;
            continue;
        }

        if (next != state) {
            if (i > last_edge) {
                runs[nruns++] = (double)(i - last_edge);
            }
            last_edge = i;
            state = next;
        }
    }

    if (nruns < 16) {
        free(runs);
        return PM3_ESOFT;
    }

    qsort(runs, nruns, sizeof(double), cmp_double);

    // The chip is the shortest run that actually repeats.  Taking the outright
    // minimum would pick up a glitch, so use a low percentile.
    out->chip = runs[nruns / 10];
    out->long_run = runs[(nruns * 95) / 100];

    if (out->chip <= 0.0) {
        free(runs);
        return PM3_ESOFT;
    }

    out->run_ratio = out->long_run / out->chip;

    size_t shortish = 0;
    const double limit = out->chip * PM3_DSP_RUN_SHORT;
    for (size_t i = 0; i < nruns; i++) {
        if (runs[i] <= limit) {
            shortish++;
        }
    }
    out->short_fraction = (double)shortish / (double)nruns;
    out->transition_coded = (out->short_fraction > PM3_DSP_RUN_SHORT_FRAC);
    out->valid = true;

    free(runs);

    out->period = pm3_autocorr_period(sig, len, &out->period_strength);
    return PM3_SUCCESS;
}

double pm3_autocorr_period(const double *sig, size_t len, double *strength) {

    if (strength != NULL) {
        *strength = 0.0;
    }

    if (sig == NULL || len < (PM3_DSP_ACORR_MIN_LAG * 4)) {
        return 0.0;
    }

    size_t n = pm3_next_pow2(len * 2);
    if (n > PM3_DSP_MAX_FFT) {
        n = PM3_DSP_MAX_FFT;
    }

    pm3_fft_plan_t *plan = pm3_fft_plan_create(n);
    pm3_cplx_t *buf = calloc(n, sizeof(pm3_cplx_t));
    if (plan == NULL || buf == NULL) {
        pm3_fft_plan_destroy(plan);
        free(buf);
        return 0.0;
    }

    const size_t take = (len < n / 2) ? len : n / 2;
    for (size_t i = 0; i < take; i++) {
        buf[i].re = sig[i];
    }

    pm3_fft(plan, buf, false);

    // Wiener-Khinchin: the autocorrelation is the inverse transform of the power spectrum
    for (size_t i = 0; i < n; i++) {
        const double p = (buf[i].re * buf[i].re) + (buf[i].im * buf[i].im);
        buf[i].re = p;
        buf[i].im = 0.0;
    }

    pm3_fft(plan, buf, true);
    pm3_fft_plan_destroy(plan);

    const double energy = buf[0].re;
    if (energy <= 0.0) {
        free(buf);
        return 0.0;
    }

    size_t hi = take / 2;
    if (hi > PM3_DSP_ACORR_MAX_LAG) {
        hi = PM3_DSP_ACORR_MAX_LAG;
    }

    double best = 0.0;
    size_t best_lag = 0;

    for (size_t lag = PM3_DSP_ACORR_MIN_LAG; lag < hi; lag++) {

        const double r = buf[lag].re / energy;
        if (r <= best) {
            continue;
        }
        // only interested in genuine local maxima
        if (buf[lag].re < buf[lag - 1].re || buf[lag].re < buf[lag + 1].re) {
            continue;
        }
        best = r;
        best_lag = lag;
    }

    double period = 0.0;

    if (best_lag > 0 && best >= PM3_DSP_ACORR_MIN_STRENGTH) {

        // sub sample refine
        const double a = buf[best_lag - 1].re;
        const double b = buf[best_lag].re;
        const double c = buf[best_lag + 1].re;
        const double denom = a - (2.0 * b) + c;

        double delta = 0.0;
        if (fabs(denom) > 1e-30) {
            delta = 0.5 * (a - c) / denom;
        }

        if (delta > 0.5) {
            delta = 0.5;
        }

        if (delta < -0.5) {
            delta = -0.5;
        }

        period = (double)best_lag + delta;
        if (strength != NULL) {
            *strength = best;
        }
    }

    free(buf);
    return period;
}

double *pm3_resample(const double *in, size_t len, double ratio, size_t *out_len) {

    if (in == NULL || out_len == NULL || len < 2 || ratio <= 0.0) {
        return NULL;
    }

    const double want = (double)len * ratio;
    if (want < 2.0 || want > (double)PM3_DSP_MAX_RESAMPLE) {
        return NULL;
    }

    const size_t n = (size_t)want;
    double *out = calloc(n, sizeof(double));
    if (out == NULL) {
        return NULL;
    }

    for (size_t i = 0; i < n; i++) {

        const double pos = (double)i / ratio;
        size_t idx = (size_t)pos;

        if (idx + 1 >= len) {
            out[i] = in[len - 1];
            continue;
        }

        const double frac = pos - (double)idx;
        out[i] = (in[idx] * (1.0 - frac)) + (in[idx + 1] * frac);
    }

    *out_len = n;
    return out;
}

// Coherent PSK receiver.
int pm3_psk_demod(const double *sig, size_t len, int fc, double clk,
                  uint8_t *bits, size_t *nbits, double *clk_out, int *phase_out,
                  double *score_out, uint8_t *abs_bits) {

    if (sig == NULL || bits == NULL || nbits == NULL) {
        return PM3_EINVARG;
    }

    const size_t w = (size_t)(clk + 0.5);
    if (fc < 2 || clk < 4.0 || w < 4 || len < w * 8) {
        return PM3_EINVARG;
    }

    const size_t zlen = len - w + 1;

    double *zr = calloc(zlen, sizeof(double));
    double *zi = calloc(zlen, sizeof(double));
    if (zr == NULL || zi == NULL) {
        free(zr);
        free(zi);
        return PM3_EMALLOC;
    }

    // Mix down by the subcarrier and integrate over one symbol
    {
        double sr = 0.0, si = 0.0;
        for (size_t i = 0; i < w; i++) {
            const double a = -2.0 * M_PI * (double)i / (double)fc;
            sr += sig[i] * cos(a);
            si += sig[i] * sin(a);
        }
        zr[0] = sr;
        zi[0] = si;

        for (size_t i = 1; i < zlen; i++) {
            const double aout = -2.0 * M_PI * (double)(i - 1) / (double)fc;
            const double ain  = -2.0 * M_PI * (double)(i + w - 1) / (double)fc;
            sr += (sig[i + w - 1] * cos(ain)) - (sig[i - 1] * cos(aout));
            si += (sig[i + w - 1] * sin(ain)) - (sig[i - 1] * sin(aout));
            zr[i] = sr;
            zi[i] = si;
        }
    }

    // Symbol timing.
    double best_clk = clk, best_score = -1.0;
    int best_phase = 0;

    for (int step = -20; step <= 20; step++) {

        const double c = clk + ((double)step * 0.1);
        if (c < 4.0) {
            continue;
        }

        for (size_t p = 0; p < w; p++) {

            double sum = 0.0;
            size_t cnt = 0;

            for (double pos = (double)p; pos < (double)zlen; pos += c) {
                const size_t k = (size_t)(pos + 0.5);
                if (k >= zlen) {
                    break;
                }
                sum += sqrt((zr[k] * zr[k]) + (zi[k] * zi[k]));
                cnt++;
            }

            if (cnt < 8) {
                continue;
            }

            const double score = sum / (double)cnt;
            if (score > best_score) {
                best_score = score;
                best_clk = c;
                best_phase = (int)p;
            }
        }
    }

    if (best_score < 0.0) {
        free(zr);
        free(zi);
        return PM3_ESOFT;
    }

    // Absolute phase reference, when the caller wants one.
    double ref_r = 1.0, ref_i = 0.0;

    if (abs_bits != NULL) {

        double sr = 0.0, si = 0.0;
        for (double pos = (double)best_phase; pos < (double)zlen; pos += best_clk) {
            const size_t k = (size_t)(pos + 0.5);
            if (k >= zlen) {
                break;
            }
            sr += (zr[k] * zr[k]) - (zi[k] * zi[k]);
            si += 2.0 * zr[k] * zi[k];
        }

        const double mag = sqrt((sr * sr) + (si * si));
        if (mag > 1e-12) {
            const double half = 0.5 * atan2(si, sr);
            ref_r = cos(half);
            ref_i = sin(half);
        }
    }

    // Differential detection at the recovered timing.
    size_t n = 0;
    double prev_r = 0.0, prev_i = 0.0;
    uint8_t phase = 0;
    bool first = true;

    for (double pos = (double)best_phase; pos < (double)zlen && n < *nbits; pos += best_clk) {

        const size_t k = (size_t)(pos + 0.5);
        if (k >= zlen) {
            break;
        }

        if (first == false) {
            // Re( s * conj(s_prev) ) - negative means the phase reversed
            if (((zr[k] * prev_r) + (zi[k] * prev_i)) < 0.0) {
                phase ^= 1;
            }
        }

        prev_r = zr[k];
        prev_i = zi[k];
        first = false;

        if (abs_bits != NULL) {
            // Re( z * conj(ref) ) - which side of the axis this symbol sits on
            abs_bits[n] = (((zr[k] * ref_r) + (zi[k] * ref_i)) < 0.0) ? 1 : 0;
        }

        bits[n++] = phase;
    }

    free(zr);
    free(zi);

    *nbits = n;
    if (clk_out != NULL) {
        *clk_out = best_clk;
    }
    if (phase_out != NULL) {
        *phase_out = best_phase;
    }
    if (score_out != NULL) {
        *score_out = best_score;
    }
    return (n >= 32) ? PM3_SUCCESS : PM3_ESOFT;
}

// Coherent chip slicer for amplitude keyed traces.
int pm3_ask_chips(const double *sig, size_t len, double chip,
                  uint8_t *chips, size_t *nchips, double *chip_out, int *phase_out) {

    if (sig == NULL || chips == NULL || nchips == NULL) {
        return PM3_EINVARG;
    }

    const size_t w = (size_t)(chip + 0.5);
    if (chip < 2.0 || w < 2 || len < w * 16) {
        return PM3_EINVARG;
    }

    const size_t clen = len - w + 1;

    double *c = calloc(clen, sizeof(double));
    if (c == NULL) {
        return PM3_EMALLOC;
    }

    double run = 0.0;
    for (size_t i = 0; i < w; i++) {
        run += sig[i];
    }
    c[0] = run;
    for (size_t i = 1; i < clen; i++) {
        run += sig[i + w - 1] - sig[i - 1];
        c[i] = run;
    }

    double best_chip = chip, best_score = -1.0;
    int best_phase = 0;

    for (int step = -20; step <= 20; step++) {

        const double cc = chip + ((double)step * 0.05);
        if (cc < 2.0) {
            continue;
        }

        for (size_t p = 0; p < w; p++) {

            double sum = 0.0;
            size_t cnt = 0;

            for (double pos = (double)p; pos < (double)clen; pos += cc) {
                const size_t k = (size_t)(pos + 0.5);
                if (k >= clen) {
                    break;
                }
                sum += fabs(c[k]);
                cnt++;
            }

            if (cnt < 64) {
                continue;
            }

            const double score = sum / (double)cnt;
            if (score > best_score) {
                best_score = score;
                best_chip = cc;
                best_phase = (int)p;
            }
        }
    }

    if (best_score < 0.0) {
        free(c);
        return PM3_ESOFT;
    }

    size_t n = 0;
    for (double pos = (double)best_phase; pos < (double)clen && n < *nchips; pos += best_chip) {
        const size_t k = (size_t)(pos + 0.5);
        if (k >= clen) {
            break;
        }
        chips[n++] = (c[k] > 0.0) ? 1 : 0;
    }

    free(c);

    *nchips = n;
    if (chip_out != NULL) {
        *chip_out = best_chip;
    }

    if (phase_out != NULL) {
        *phase_out = best_phase;
    }

    return (n >= 64) ? PM3_SUCCESS : PM3_ESOFT;
}
