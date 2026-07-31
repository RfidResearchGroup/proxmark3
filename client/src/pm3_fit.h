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

#ifndef PM3_FIT_H__
#define PM3_FIT_H__

#include "common.h"
#include "pm3_dsp.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PM3_FIT_MIN_SYMBOLS 64

typedef enum {
    PM3_MOD_ASK = 0,
    PM3_MOD_FSK,
    PM3_MOD_PSK,
    PM3_MOD_NRZ,
} pm3_mod_t;

typedef enum {
    PM3_ENC_RAW = 0,
    PM3_ENC_MANCHESTER,
    PM3_ENC_BIPHASE,
} pm3_enc_t;

typedef enum {
    PM3_TPL_FLAT = 0,       // one level held for the whole symbol
    PM3_TPL_HALF,           // half high, half low - a mid symbol transition
    PM3_TPL_PSK,            // subcarrier burst
    PM3_TPL_FSK,            // one of two tones, scored non coherently
} pm3_tpl_t;

typedef struct {

    pm3_mod_t mod;
    pm3_enc_t enc;
    pm3_tpl_t tpl;

    int clk;                // samples per symbol
    int q;                  // assumed antenna Q used to shape the template
    int fc_hi;              // FSK, the longer field clock ( pm3 `fchigh` )
    int fc_lo;              // FSK, the shorter field clock ( pm3 `fclow` )
    int fc;                 // PSK subcarrier period

    // results
    int phase;              // best symbol phase, 0 .. clk-1
    double clk_fine;        // refined clock, fractional - this is the useful one
    size_t nsym;            // decision instants the score was built from
    double snr_dd;          // decision directed SNR, dB
    double eye;             // min / mean at the decision instants, 0 .. 1
    double mid;             // mean at the mid symbol instants
    double mid_ratio;       // mid / mean at the decision instants
    bool chip_rate;         // decoded bits pair up 01/10 almost always, so
    double margin;          // dB to the next best genuinely different decode
} pm3_hyp_t;

typedef struct {
    int mod_mask;           // bitmask of (1 << pm3_mod_t), 0 means all
    int clk_only;           // restrict to this clock, 0 means all candidates
    bool keep_corr;         // hand back the rank 1 correlator output
} pm3_fit_opts_t;

typedef struct {
    pm3_hyp_t *items;       // ranked, best first
    size_t count;
    pm3_sigstat_t stats;    // structural facts measured from the waveform
    bool promoted;          // rank 1 was chosen on structural evidence rather
    double *corr;           // rank 1 decision statistic, when requested
    size_t corr_len;
} pm3_fit_t;

const char *pm3_mod_name(pm3_mod_t mod);
const char *pm3_enc_name(pm3_enc_t enc);

size_t pm3_fit_clocks(const int **clocks);
int pm3_fit_run(const double *sig, size_t len, const pm3_fit_opts_t *opts, pm3_fit_t *out);
void pm3_fit_free(pm3_fit_t *fit);

typedef struct {
    pm3_mod_t mod;
    pm3_enc_t enc;
    double clk;             // may be fractional
    int fc_hi;
    int fc_lo;
    int fc;
    double noise;
    double drift;
    double envelope;        // amplitude swing across the capture, 0 = none
    double jitter;
    double clip;            // 0 = no clipping
    int q;                  // antenna Q to shape with, 0 for the default
    int repeat;             // message length in bits, 0 for endless random data.
    uint32_t seed;
} pm3_gen_opts_t;

int pm3_fit_generate(const pm3_gen_opts_t *opts, double *out, size_t len);

#ifdef __cplusplus
}
#endif
#endif // PM3_FIT_H__
