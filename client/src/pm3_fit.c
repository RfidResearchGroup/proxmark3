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
// Symbol template generation and matched filter hypothesis scoring
//-----------------------------------------------------------------------------

#include "pm3_fit.h"

#include <stdlib.h>
#include <string.h>
#include <math.h>

#include "pm3_cmd.h"
#include "commonutil.h"     // ARRAYLEN
#include "pm3_dsp.h"

#define PM3_FIT_VAR_FLOOR       0.01
#define PM3_FIT_MIN_CONTRAST    0.15
#define PM3_FIT_OCTAVE_TOL      6.0
#define PM3_FIT_MAX_MID         0.85
#define PM3_FIT_MAX_MID_FSK     0.78
#define PM3_FIT_MIN_TONE_SPLIT  0.30
#define PM3_FIT_MIN_SURVIVAL    0.01
#define PM3_FIT_MIN_TONE_BALANCE 0.15
#define PM3_FIT_MIN_TONE_ENERGY 0.30
#define PM3_FIT_FSK_MIN_CYCLES  4
#define PM3_FIT_AGC_SYMBOLS     8
#define PM3_FIT_CHIP_PAIR       0.90
#define PM3_FIT_STRUCT_MIN_CLK  16.0
#define PM3_FIT_STRUCT_TOL      0.25

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

// Clock candidates.
static const int g_fit_clocks[] = { 8, 16, 32, 40, 50, 64, 100, 128, 256, 272, 384 };

// FSK field clock pairs, as fchigh / fclow.
static const int g_fsk_pairs[][2] = { {10, 8}, {8, 5} };

// PSK subcarrier periods.
static const int g_psk_fc[] = { 2, 4, 8 };

static const int g_fit_q[] = { 2, 8, 20, 50 };

const char *pm3_mod_name(pm3_mod_t mod) {
    switch (mod) {
        case PM3_MOD_ASK:
            return "ASK";
        case PM3_MOD_FSK:
            return "FSK";
        case PM3_MOD_PSK:
            return "PSK";
        case PM3_MOD_NRZ:
            return "NRZ";
    }
    return "?";
}

const char *pm3_enc_name(pm3_enc_t enc) {
    switch (enc) {
        case PM3_ENC_RAW:
            return "raw";
        case PM3_ENC_MANCHESTER:
            return "manchester";
        case PM3_ENC_BIPHASE:
            return "biphase";
    }
    return "?";
}

size_t pm3_fit_clocks(const int **clocks) {
    if (clocks != NULL) {
        *clocks = g_fit_clocks;
    }
    return ARRAYLEN(g_fit_clocks);
}

// Apply a single pole antenna response to a template, in place.
static void shape_for_q(double *tpl, size_t len, int q) {

    const double tau = (double)q / M_PI;
    if (tau < 1.0) {
        return;
    }

    const double a = 1.0 / tau;
    double y = 0.0;

    for (size_t i = 0; i < len; i++) {
        y += a * (tpl[i] - y);
        tpl[i] = y;
    }
}

static bool normalise_energy(double *tpl, size_t len) {

    double e = 0.0;
    for (size_t i = 0; i < len; i++) {
        e += tpl[i] * tpl[i];
    }

    if (e < (1e-6 * (double)len)) {
        return false;
    }

    const double scale = 1.0 / sqrt(e);
    for (size_t i = 0; i < len; i++) {
        tpl[i] *= scale;
    }
    return true;
}

static bool build_template(const pm3_hyp_t *hyp, double *tpl, size_t len, int variant) {

    memset(tpl, 0, len * sizeof(double));

    switch (hyp->tpl) {

        case PM3_TPL_FLAT:
            for (size_t i = 0; i < len; i++) {
                tpl[i] = 1.0;
            }
            break;

        case PM3_TPL_HALF:
            for (size_t i = 0; i < len; i++) {
                tpl[i] = (i < (len / 2)) ? 1.0 : -1.0;
            }
            break;

        case PM3_TPL_PSK:
            for (size_t i = 0; i < len; i++) {
                tpl[i] = ((i % (size_t)hyp->fc) < ((size_t)hyp->fc / 2)) ? 1.0 : -1.0;
            }
            break;

        case PM3_TPL_FSK: {
            const size_t fc = (size_t)((variant == 0) ? hyp->fc_hi : hyp->fc_lo);
            for (size_t i = 0; i < len; i++) {
                tpl[i] = ((i % fc) < (fc / 2)) ? 1.0 : -1.0;
            }
            break;
        }
    }

    double raw_energy = 0.0;
    for (size_t i = 0; i < len; i++) {
        raw_energy += tpl[i] * tpl[i];
    }

    shape_for_q(tpl, len, hyp->q);

    double shaped_energy = 0.0;
    for (size_t i = 0; i < len; i++) {
        shaped_energy += tpl[i] * tpl[i];
    }

    if (raw_energy <= 0.0 || (shaped_energy / raw_energy) < PM3_FIT_MIN_SURVIVAL) {
        return false;
    }

    return normalise_energy(tpl, len);
}

// Correlate the whole trace against a single symbol.
static int correlate(const pm3_fft_plan_t *plan, const pm3_cplx_t *sig_fft,
                     const double *tpl, size_t tpl_len, pm3_cplx_t *scratch, double *out) {

    const size_t n = plan->n;

    memset(scratch, 0, n * sizeof(pm3_cplx_t));
    for (size_t i = 0; i < tpl_len; i++) {
        scratch[i].re = tpl[i];
    }

    pm3_fft(plan, scratch, false);

    for (size_t i = 0; i < n; i++) {
        const double xr = sig_fft[i].re, xi = sig_fft[i].im;
        const double tr = scratch[i].re, ti = -scratch[i].im;   // conjugate
        scratch[i].re = (xr * tr) - (xi * ti);
        scratch[i].im = (xr * ti) + (xi * tr);
    }

    pm3_fft(plan, scratch, true);

    for (size_t i = 0; i < n; i++) {
        out[i] = scratch[i].re;
    }
    return PM3_SUCCESS;
}

static double eye_mean(const double *work, size_t limit, double clk, double phase, size_t *count) {

    const double half = clk / 2.0;
    double sum = 0.0;
    size_t cnt = 0;

    for (double pos = phase; (pos + half) < (double)limit; pos += clk) {
        sum += work[(size_t)(pos + 0.5)] - work[(size_t)(pos + half + 0.5)];
        cnt++;
    }

    if (count != NULL) {
        *count = cnt;
    }
    if (cnt == 0) {
        return -1e30;
    }
    return sum / (double)cnt;
}

static bool score_hypothesis(pm3_hyp_t *hyp, const double *stat_in, const double *aux, const double *sgn,
                             size_t valid, double *work, double *agc) {

    const double *stat = stat_in;

    const size_t clk = (size_t)hyp->clk;
    if (clk < 2 || valid < clk * PM3_FIT_MIN_SYMBOLS) {
        return false;
    }

    // Flatten slow amplitude variation, for timing recovery only.
    {
        size_t win = clk * PM3_FIT_AGC_SYMBOLS;
        if (win < 8) {
            win = 8;
        }
        if (win > valid) {
            win = valid;
        }

        double run = 0.0;
        size_t lo = 0, hi = 0;
        while (hi < win) {
            run += stat[hi++];
        }

        for (size_t i = 0; i < valid; i++) {

            const size_t want_lo = (i > win / 2) ? i - (win / 2) : 0;
            size_t want_hi = want_lo + win;
            if (want_hi > valid) {
                want_hi = valid;
            }

            while (hi < want_hi) {
                run += stat[hi++];
            }
            while (lo < want_lo) {
                run -= stat[lo++];
            }

            const size_t cnt = hi - lo;
            const double mean = (cnt > 0) ? (run / (double)cnt) : 0.0;
            agc[i] = (mean > 1e-12) ? (stat[i] / mean) : 0.0;
        }
    }

    // standardise the flattened copy, this is what the timing search sees
    {
        double sum = 0.0, sumsq = 0.0;
        for (size_t i = 0; i < valid; i++) {
            sum += agc[i];
            sumsq += agc[i] * agc[i];
        }
        const double mean = sum / (double)valid;
        double var = (sumsq / (double)valid) - (mean * mean);
        if (var < 1e-30) {
            return false;
        }
        const double sd = sqrt(var);
        for (size_t i = 0; i < valid; i++) {
            agc[i] = (agc[i] - mean) / sd;
        }
    }

    // standardise the untouched statistic
    double sum = 0.0, sumsq = 0.0;
    for (size_t i = 0; i < valid; i++) {
        sum += stat[i];
        sumsq += stat[i] * stat[i];
    }

    const double gmean = sum / (double)valid;
    double gvar = (sumsq / (double)valid) - (gmean * gmean);
    if (gvar < 1e-30) {
        return false;
    }
    const double gsd = sqrt(gvar);

    for (size_t i = 0; i < valid; i++) {
        work[i] = (stat[i] - gmean) / gsd;
    }

    // Stage 1 - find the phase over a short prefix.
    size_t prefix = clk * 32;
    if (prefix > valid) {
        prefix = valid;
    }

    double best_phase = 0.0;
    double best_mean = -1e30;

    for (size_t phase = 0; phase < clk; phase++) {
        const double m = eye_mean(agc, prefix, (double)clk, (double)phase, NULL);
        if (m > best_mean) {
            best_mean = m;
            best_phase = (double)phase;
        }
    }

    // Stage 2 - refine the clock as a fraction, over the full length.
    double best_clk = (double)clk;
    double full_best = eye_mean(agc, valid, best_clk, best_phase, NULL);

    for (int step = -30; step <= 30; step++) {

        const double c = (double)clk + ((double)step * 0.02);
        if (c < 2.0) {
            continue;
        }
        const double m = eye_mean(agc, valid, c, best_phase, NULL);
        if (m > full_best) {
            full_best = m;
            best_clk = c;
        }
    }

    // Stage 3 - re-fit the phase now that the clock is right
    best_mean = -1e30;
    for (size_t phase = 0; phase < clk; phase++) {
        const double m = eye_mean(agc, valid, best_clk, (double)phase, NULL);
        if (m > best_mean) {
            best_mean = m;
            best_phase = (double)phase;
        }
    }

    if (best_mean < PM3_FIT_MIN_CONTRAST) {
        return false;
    }

    // Timing is settled; score the decision instants themselves.
    const double half = best_clk / 2.0;

    // See the chip rate test after this loop.
    size_t pair_diff[2] = { 0, 0 };
    size_t pair_tot[2] = { 0, 0 };
    bool prev_bit = false;

    double zsum = 0.0, zsumsq = 0.0;
    double rsum = 0.0, rlow = 0.0, mid_sum = 0.0;
    size_t cnt = 0;

    for (double pos = best_phase; (pos + half) < (double)valid; pos += best_clk) {

        const size_t idx = (size_t)(pos + 0.5);
        const size_t mid = (size_t)(pos + half + 0.5);

        const double z = work[idx];
        zsum += z;
        zsumsq += z * z;

        rsum += stat[idx];
        mid_sum += stat[mid];
        if (cnt == 0 || stat[idx] < rlow) {
            rlow = stat[idx];
        }

        // running tally for the chip rate test below
        const bool bit = (sgn[idx] >= 0.0);
        if (cnt > 0) {
            const size_t align = (cnt - 1) & 1;
            pair_tot[align]++;
            if (bit != prev_bit) {
                pair_diff[align]++;
            }
        }
        prev_bit = bit;

        cnt++;
    }

    if (cnt < PM3_FIT_MIN_SYMBOLS) {
        return false;
    }

    const double zmean = zsum / (double)cnt;
    double zvar = (zsumsq / (double)cnt) - (zmean * zmean);

    // Floor the variance.
    if (zvar < PM3_FIT_VAR_FLOOR) {
        zvar = PM3_FIT_VAR_FLOOR;
    }

    const double rmean = rsum / (double)cnt;

    // Chip rate test.
    hyp->chip_rate = false;
    for (size_t align = 0; align < 2; align++) {
        if (pair_tot[align] < 16) {
            continue;
        }
        const double frac = (double)pair_diff[align] / (double)pair_tot[align];
        if (frac > PM3_FIT_CHIP_PAIR) {
            hyp->chip_rate = true;
        }
    }

    hyp->phase = (int)best_phase;
    hyp->clk_fine = best_clk;
    hyp->nsym = cnt;
    hyp->snr_dd = 10.0 * log10((zmean * zmean) / zvar);
    hyp->eye = (rmean > 0.0) ? (rlow / rmean) : 0.0;
    hyp->mid = mid_sum / (double)cnt;
    hyp->mid_ratio = (rmean > 0.0) ? (hyp->mid / rmean) : 0.0;
    hyp->margin = 0.0;

    const double mid_limit = (hyp->tpl == PM3_TPL_FSK) ? PM3_FIT_MAX_MID_FSK : PM3_FIT_MAX_MID;
    if (hyp->mid_ratio > mid_limit) {
        return false;
    }

    // PSK only: the subcarrier has to actually be in the trace.
    if (hyp->tpl == PM3_TPL_PSK && rmean < (PM3_FIT_MIN_TONE_ENERGY * sqrt(best_clk))) {
        return false;
    }

    // FSK only: the two tone correlations have to actually separate.
    if (aux != NULL) {

        double asum = 0.0;
        size_t acnt = 0;

        for (double pos = best_phase; (pos + half) < (double)valid; pos += best_clk) {
            asum += aux[(size_t)(pos + 0.5)];
            acnt++;
        }

        if (acnt == 0) {
            return false;
        }
        const double amean = asum / (double)acnt;
        if (amean <= 0.0 || (rmean / amean) < PM3_FIT_MIN_TONE_SPLIT) {
            return false;
        }

        if (amean < (PM3_FIT_MIN_TONE_ENERGY * sqrt(best_clk))) {
            return false;
        }

        // The winning tone has to actually change.
        size_t hi_cnt = 0, lo_cnt = 0;

        for (double pos = best_phase; (pos + half) < (double)valid; pos += best_clk) {
            if (sgn[(size_t)(pos + 0.5)] >= 0.0) {
                hi_cnt++;
            } else {
                lo_cnt++;
            }
        }

        const size_t total = hi_cnt + lo_cnt;
        const size_t rarer = (hi_cnt < lo_cnt) ? hi_cnt : lo_cnt;
        if (total == 0 || ((double)rarer / (double)total) < PM3_FIT_MIN_TONE_BALANCE) {
            return false;
        }
    }

    return true;
}

static bool same_decode(const pm3_hyp_t *a, const pm3_hyp_t *b) {

    if (a->clk != b->clk || a->tpl != b->tpl) {
        return false;
    }
    if (a->tpl == PM3_TPL_PSK && a->fc != b->fc) {
        return false;
    }
    if (a->tpl == PM3_TPL_FSK && (a->fc_hi != b->fc_hi || a->fc_lo != b->fc_lo)) {
        return false;
    }
    return true;
}

static int cmp_hyp(const void *pa, const void *pb) {

    const pm3_hyp_t *a = (const pm3_hyp_t *)pa;
    const pm3_hyp_t *b = (const pm3_hyp_t *)pb;

    if (a->snr_dd > b->snr_dd) {
        return -1;
    }
    if (a->snr_dd < b->snr_dd) {
        return 1;
    }

    if (a->mod != b->mod) {
        return (a->mod < b->mod) ? -1 : 1;
    }
    if (a->enc != b->enc) {
        return (a->enc < b->enc) ? -1 : 1;
    }
    if (a->clk != b->clk) {
        return (a->clk < b->clk) ? -1 : 1;
    }
    if (a->q != b->q) {
        return (a->q < b->q) ? -1 : 1;
    }
    return 0;
}

static size_t enumerate(const pm3_fit_opts_t *opts, pm3_hyp_t *list) {

    size_t n = 0;

    for (size_t ci = 0; ci < ARRAYLEN(g_fit_clocks); ci++) {

        const int clk = g_fit_clocks[ci];
        if (opts->clk_only && clk != opts->clk_only) {
            continue;
        }

        for (size_t qi = 0; qi < ARRAYLEN(g_fit_q); qi++) {

            const int q = g_fit_q[qi];

            pm3_hyp_t h;

            if (opts->mod_mask == 0 || (opts->mod_mask & (1 << PM3_MOD_ASK))) {
                for (int enc = PM3_ENC_RAW; enc <= PM3_ENC_BIPHASE; enc++) {
                    memset(&h, 0, sizeof(h));
                    h.mod = PM3_MOD_ASK;
                    h.enc = (pm3_enc_t)enc;
                    h.tpl = (enc == PM3_ENC_RAW) ? PM3_TPL_FLAT : PM3_TPL_HALF;
                    h.clk = clk;
                    h.q = q;
                    if (list) {
                        list[n] = h;
                    }
                    n++;
                }
            }

            if (opts->mod_mask == 0 || (opts->mod_mask & (1 << PM3_MOD_NRZ))) {
                memset(&h, 0, sizeof(h));
                h.mod = PM3_MOD_NRZ;
                h.enc = PM3_ENC_RAW;
                h.tpl = PM3_TPL_FLAT;
                h.clk = clk;
                h.q = q;
                if (list) {
                    list[n] = h;
                }
                n++;
            }

            if (opts->mod_mask == 0 || (opts->mod_mask & (1 << PM3_MOD_PSK))) {
                for (size_t fi = 0; fi < ARRAYLEN(g_psk_fc); fi++) {
                    if (clk < g_psk_fc[fi] * 4) {
                        continue;
                    }
                    memset(&h, 0, sizeof(h));
                    h.mod = PM3_MOD_PSK;
                    h.enc = PM3_ENC_RAW;
                    h.tpl = PM3_TPL_PSK;
                    h.clk = clk;
                    h.q = q;
                    h.fc = g_psk_fc[fi];
                    if (list) {
                        list[n] = h;
                    }
                    n++;
                }
            }

            if (opts->mod_mask == 0 || (opts->mod_mask & (1 << PM3_MOD_FSK))) {
                for (size_t fi = 0; fi < ARRAYLEN(g_fsk_pairs); fi++) {

                    if (clk < g_fsk_pairs[fi][0] * PM3_FIT_FSK_MIN_CYCLES) {
                        continue;
                    }

                    memset(&h, 0, sizeof(h));
                    h.mod = PM3_MOD_FSK;
                    h.enc = PM3_ENC_RAW;
                    h.tpl = PM3_TPL_FSK;
                    h.clk = clk;
                    h.q = q;
                    h.fc_hi = g_fsk_pairs[fi][0];
                    h.fc_lo = g_fsk_pairs[fi][1];
                    if (list) {
                        list[n] = h;
                    }
                    n++;
                }
            }
        }
    }

    return n;
}

int pm3_fit_run(const double *sig, size_t len, const pm3_fit_opts_t *opts, pm3_fit_t *out) {

    if (sig == NULL || opts == NULL || out == NULL || len < 64) {
        return PM3_EINVARG;
    }

    memset(out, 0, sizeof(pm3_fit_t));

    const size_t nhyp = enumerate(opts, NULL);
    if (nhyp == 0) {
        return PM3_EINVARG;
    }

    const size_t longest = (size_t)g_fit_clocks[ARRAYLEN(g_fit_clocks) - 1];
    const size_t n = pm3_next_pow2(len + longest);
    if (n > PM3_DSP_MAX_FFT) {
        return PM3_EINVARG;
    }

    pm3_fft_plan_t *plan = pm3_fft_plan_create(n);
    pm3_cplx_t *sig_fft = calloc(n, sizeof(pm3_cplx_t));
    pm3_cplx_t *scratch = calloc(n, sizeof(pm3_cplx_t));
    double *corr = calloc(n, sizeof(double));
    double *corr_b = calloc(n, sizeof(double));
    double *stat = calloc(n, sizeof(double));
    double *zwork = calloc(n, sizeof(double));
    double *aux = calloc(n, sizeof(double));
    double *sgn = calloc(n, sizeof(double));
    double *agcbuf = calloc(n, sizeof(double));
    double *tpl = calloc(longest + 1, sizeof(double));
    pm3_hyp_t *list = calloc(nhyp, sizeof(pm3_hyp_t));

    if (plan == NULL || sig_fft == NULL || scratch == NULL || corr == NULL
            || corr_b == NULL || stat == NULL || zwork == NULL || aux == NULL || sgn == NULL
            || agcbuf == NULL || tpl == NULL || list == NULL) {
        pm3_fft_plan_destroy(plan);
        free(sig_fft);
        free(scratch);
        free(corr);
        free(corr_b);
        free(stat);
        free(zwork);
        free(aux);
        free(sgn);
        free(agcbuf);
        free(tpl);
        free(list);
        return PM3_EMALLOC;
    }

    pm3_signal_stats(sig, len, &out->stats);

    enumerate(opts, list);

    // FFT of the trace
    for (size_t i = 0; i < len; i++) {
        sig_fft[i].re = sig[i];
    }
    pm3_fft(plan, sig_fft, false);

    size_t kept = 0;

    for (size_t i = 0; i < nhyp; i++) {

        pm3_hyp_t *h = &list[i];
        const size_t tlen = (size_t)h->clk;
        const size_t valid = (len > tlen) ? (len - tlen) : 0;

        if (valid < tlen * PM3_FIT_MIN_SYMBOLS) {
            continue;
        }

        if (h->tpl == PM3_TPL_FSK) {

            if (build_template(h, tpl, tlen, 0) == false) {
                continue;
            }
            correlate(plan, sig_fft, tpl, tlen, scratch, corr);

            if (build_template(h, tpl, tlen, 1) == false) {
                continue;
            }
            correlate(plan, sig_fft, tpl, tlen, scratch, corr_b);

            for (size_t k = 0; k < valid; k++) {
                const double d = fabs(corr[k]) - fabs(corr_b[k]);
                stat[k] = fabs(d);
                aux[k] = fabs(corr[k]) + fabs(corr_b[k]);
                sgn[k] = d;
            }

        } else {

            if (build_template(h, tpl, tlen, 0) == false) {
                continue;
            }
            correlate(plan, sig_fft, tpl, tlen, scratch, corr);

            for (size_t k = 0; k < valid; k++) {
                stat[k] = fabs(corr[k]);
                sgn[k] = corr[k];
            }
        }

        const bool is_fsk = (h->tpl == PM3_TPL_FSK);
        if (score_hypothesis(h, stat, is_fsk ? aux : NULL, sgn, valid, zwork, agcbuf) == false) {
            continue;
        }

        list[kept++] = *h;
    }

    if (kept == 0) {
        pm3_fft_plan_destroy(plan);
        free(sig_fft);
        free(scratch);
        free(corr);
        free(corr_b);
        free(stat);
        free(zwork);
        free(aux);
        free(sgn);
        free(agcbuf);
        free(tpl);
        free(list);
        return PM3_ESOFT;
    }

    qsort(list, kept, sizeof(pm3_hyp_t), cmp_hyp);

    // Octave correction.
    for (bool moved = true; moved;) {

        moved = false;

        for (size_t j = 1; j < kept; j++) {

            bool candidate = (list[j].tpl == list[0].tpl
                              && list[j].mod == list[0].mod
                              && list[j].enc == list[0].enc);

            if (candidate == false
                    && list[0].tpl == PM3_TPL_FLAT
                    && list[j].tpl == PM3_TPL_HALF
                    && (list[0].mod == PM3_MOD_ASK || list[0].mod == PM3_MOD_NRZ)
                    && list[j].mod == PM3_MOD_ASK) {
                candidate = true;
            }

            if (candidate == false) {
                continue;
            }

            if (list[0].tpl != PM3_TPL_FLAT && list[0].tpl != PM3_TPL_HALF) {
                break;
            }

            if (list[0].chip_rate == false) {
                break;
            }

            const double ratio = (double)list[j].clk / (double)list[0].clk;
            if (fabs(ratio - 2.0) > 0.01) {
                continue;
            }

            const pm3_hyp_t winner = list[j];
            memmove(&list[1], &list[0], j * sizeof(pm3_hyp_t));
            list[0] = winner;
            out->promoted = true;
            break;
        }
    }

    // Structural override.
    if (out->stats.valid) {

        const double want_clk = out->stats.transition_coded
                                ? (2.0 * out->stats.chip)
                                : out->stats.chip;

        if (want_clk >= PM3_FIT_STRUCT_MIN_CLK) {

            for (size_t j = 0; j < kept; j++) {

                if (list[j].tpl != PM3_TPL_FLAT && list[j].tpl != PM3_TPL_HALF) {
                    continue;
                }

                const bool tpl_ok = out->stats.transition_coded
                                    ? (list[j].tpl == PM3_TPL_HALF)
                                    : (list[j].tpl == PM3_TPL_FLAT);
                if (tpl_ok == false) {
                    continue;
                }

                if (fabs((double)list[j].clk - want_clk) > (PM3_FIT_STRUCT_TOL * want_clk)) {
                    continue;
                }

                if (j > 0) {
                    const pm3_hyp_t winner = list[j];
                    memmove(&list[1], &list[0], j * sizeof(pm3_hyp_t));
                    list[0] = winner;
                    out->promoted = true;
                }
                break;
            }
        }
    }

    for (size_t i = 0; i < kept; i++) {
        list[i].margin = 0.0;
        for (size_t j = i + 1; j < kept; j++) {
            if (same_decode(&list[i], &list[j]) == false) {
                list[i].margin = list[i].snr_dd - list[j].snr_dd;
                break;
            }
        }
    }

    if (opts->keep_corr) {

        const pm3_hyp_t *best = &list[0];
        const size_t tlen = (size_t)best->clk;
        const size_t valid = len - tlen;

        if (best->tpl == PM3_TPL_FSK) {
            build_template(best, tpl, tlen, 0);
            correlate(plan, sig_fft, tpl, tlen, scratch, corr);
            build_template(best, tpl, tlen, 1);
            correlate(plan, sig_fft, tpl, tlen, scratch, corr_b);
            for (size_t k = 0; k < valid; k++) {
                stat[k] = fabs(fabs(corr[k]) - fabs(corr_b[k]));
            }
        } else {
            build_template(best, tpl, tlen, 0);
            correlate(plan, sig_fft, tpl, tlen, scratch, corr);
            for (size_t k = 0; k < valid; k++) {
                stat[k] = fabs(corr[k]);
                sgn[k] = corr[k];
            }
        }

        out->corr = calloc(valid, sizeof(double));
        if (out->corr != NULL) {
            memcpy(out->corr, stat, valid * sizeof(double));
            out->corr_len = valid;
        }
    }

    out->items = list;
    out->count = kept;

    pm3_fft_plan_destroy(plan);
    free(sig_fft);
    free(scratch);
    free(corr);
    free(corr_b);
    free(stat);
    free(zwork);
    free(aux);
    free(sgn);
    free(agcbuf);
    free(tpl);
    return PM3_SUCCESS;
}

void pm3_fit_free(pm3_fit_t *fit) {
    if (fit == NULL) {
        return;
    }
    free(fit->items);
    free(fit->corr);
    memset(fit, 0, sizeof(pm3_fit_t));
}

//-----------------------------------------------------------------------------
// Synthetic signal generator
//-----------------------------------------------------------------------------
static uint32_t rng_next(uint32_t *state) {
    uint32_t x = *state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *state = x;
    return x;
}

static double rng_uniform(uint32_t *state) {
    const uint32_t v = rng_next(state);
    return (double)v / 4294967296.0;
}

static double rng_gauss(uint32_t *state) {
    double u1 = rng_uniform(state);
    const double u2 = rng_uniform(state);
    if (u1 < 1e-12) {
        u1 = 1e-12;
    }
    return sqrt(-2.0 * log(u1)) * cos(2.0 * M_PI * u2);
}

int pm3_fit_generate(const pm3_gen_opts_t *opts, double *out, size_t len) {

    if (opts == NULL || out == NULL || len < 64 || opts->clk < 2.0) {
        return PM3_EINVARG;
    }

    uint32_t state = opts->seed ? opts->seed : 1;

    const size_t nbits = (size_t)((double)len / opts->clk) + 2;
    uint8_t *bits = calloc(nbits, sizeof(uint8_t));
    if (bits == NULL) {
        return PM3_EMALLOC;
    }
    for (size_t i = 0; i < nbits; i++) {
        bits[i] = rng_next(&state) & 1;
    }

    if (opts->repeat > 0) {
        for (size_t i = (size_t)opts->repeat; i < nbits; i++) {
            bits[i] = bits[i % (size_t)opts->repeat];
        }
    }

    double *edge = calloc(nbits + 1, sizeof(double));
    if (edge == NULL) {
        free(bits);
        return PM3_EMALLOC;
    }
    for (size_t i = 0; i <= nbits; i++) {
        edge[i] = ((double)i * opts->clk) + (opts->jitter ? (rng_gauss(&state) * opts->jitter) : 0.0);
    }

    int8_t *first = calloc(nbits, sizeof(int8_t));
    int8_t *second = calloc(nbits, sizeof(int8_t));
    if (first == NULL || second == NULL) {
        free(bits);
        free(edge);
        free(first);
        free(second);
        return PM3_EMALLOC;
    }

    {
        int8_t level = 1;
        for (size_t i = 0; i < nbits; i++) {
            level = (int8_t)(-level);       // boundary transition, always
            first[i] = level;
            if (bits[i]) {
                level = (int8_t)(-level);   // mid symbol transition, on a one
            }
            second[i] = level;
        }
    }

    for (size_t i = 0; i < len; i++) {

        size_t sym = (size_t)((double)i / opts->clk);
        if (sym >= nbits) {
            sym = nbits - 1;
        }
        while (sym + 1 < nbits && (double)i >= edge[sym + 1]) {
            sym++;
        }
        while (sym > 0 && (double)i < edge[sym]) {
            sym--;
        }

        const double span = edge[sym + 1] - edge[sym];
        const double frac = (span > 0.0) ? (((double)i - edge[sym]) / span) : 0.0;
        const int bit = bits[sym];

        double sym_level;

        switch (opts->enc) {
            case PM3_ENC_MANCHESTER: {
                sym_level = ((frac < 0.5) == (bit != 0)) ? 1.0 : -1.0;
                break;
            }
            case PM3_ENC_BIPHASE: {
                sym_level = (frac < 0.5) ? (double)first[sym] : (double)second[sym];
                break;
            }
            case PM3_ENC_RAW:
            default: {
                sym_level = bit ? 1.0 : -1.0;
                break;
            }
        }

        double v;

        switch (opts->mod) {
            case PM3_MOD_FSK: {
                const int fc = (sym_level > 0.0) ? opts->fc_hi : opts->fc_lo;
                v = sin(2.0 * M_PI * (double)i / (double)(fc ? fc : 8));
                break;
            }
            case PM3_MOD_PSK: {
                const int fc = opts->fc ? opts->fc : 4;
                v = sym_level * sin(2.0 * M_PI * (double)i / (double)fc);
                break;
            }
            case PM3_MOD_ASK:
            case PM3_MOD_NRZ:
            default: {
                v = sym_level;
                break;
            }
        }

        if (opts->envelope > 0.0) {
            v *= 1.0 + (opts->envelope * ((double)i / (double)len - 0.5));
        }

        if (opts->noise > 0.0) {
            v += rng_gauss(&state) * opts->noise;
        }

        if (opts->drift != 0.0) {
            v += opts->drift * ((double)i / (double)len);
        }

        if (opts->clip > 0.0) {
            if (v > opts->clip) {
                v = opts->clip;
            }

            if (v < -opts->clip) {
                v = -opts->clip;
            }
        }

        out[i] = v;
    }

    free(bits);
    free(edge);
    free(first);
    free(second);

    shape_for_q(out, len, opts->q ? opts->q : 8);
    pm3_remove_mean(out, len);
    return PM3_SUCCESS;
}
