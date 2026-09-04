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
// Host side DSP primitives;  FFT, windows, power spectrum, STFT
//-----------------------------------------------------------------------------

#ifndef PM3_DSP_H__
#define PM3_DSP_H__

#include <stdbool.h>
#include "common.h"
#include "graph.h"      // MAX_GRAPH_TRACE_LEN

#ifdef __cplusplus
extern "C" {
#endif

#define PM3_DSP_MAX_FFT     262144
#define PM3_DSP_DC_GUARD    2
#define PM3_DSP_MAX_RESAMPLE (MAX_GRAPH_TRACE_LEN * 32)
#define PM3_DSP_NYQUIST_CLK  2.5
#define PM3_DSP_ENVELOPE_SMOOTH 8
#define PM3_DSP_ENVELOPE_DEPTH 0.6

#define PM3_DSP_FLIP_FRAC 0.7

typedef enum {
    PM3_WIN_HANN = 0,
    PM3_WIN_HAMMING,
    PM3_WIN_BLACKMAN,
    PM3_WIN_RECT,
} pm3_window_t;

typedef struct {
    double re;
    double im;
} pm3_cplx_t;

typedef struct {
    size_t n;
    pm3_cplx_t *twiddle;    // n / 2 entries, exp(-2*pi*i*k/n)
    uint32_t *rev;          // n entries, bit reversal permutation
} pm3_fft_plan_t;

typedef struct {
    size_t n;               // transform length
    size_t nbins;           // n / 2 + 1, input is real
    double *mag;            // linear magnitude per bin
    double peak;            // largest magnitude found
    size_t peak_bin;        // ... and where
} pm3_spectrum_t;

typedef struct {
    size_t bin;             // integer bin the peak was found in
    double freq;            // cycles/sample, parabolic sub bin estimate
    double clk;             // samples/symbol, 1.0 / freq
    double mag_db;          // dB relative to the strongest bin in the spectrum
    double prominence;      // dB above the local noise floor
} pm3_peak_t;

typedef struct {
    size_t nframes;
    size_t nbins;
    size_t n;               // window length
    size_t hop;
    size_t *frame_start;    // nframes entries, offset of each frame
    double *peak_freq;      // nframes entries, cycles/sample of dominant bin
    double *peak_mag;       // nframes entries, magnitude of dominant bin
    double *frame_energy;   // nframes entries, total in band energy
    double *ridge;          // nframes * nbins, magnitude, row major
} pm3_stft_t;


#define PM3_DSP_MAX_PEAKS   16
#define PM3_DSP_NDELAYS     4

typedef enum {
    PM3_FAM_UNKNOWN = 0,
    PM3_FAM_ASK,
    PM3_FAM_FSK,
    PM3_FAM_PSK,
    PM3_FAM_NRZ,
    PM3_FAM_MANCHESTER,
} pm3_family_t;

typedef enum {
    PM3_CONF_NONE = 0,
    PM3_CONF_LOW,
    PM3_CONF_MEDIUM,
    PM3_CONF_HIGH,
} pm3_confidence_t;

typedef struct {

    size_t npeaks;
    pm3_peak_t peaks[PM3_DSP_MAX_PEAKS];
    bool have_sq;
    size_t nsq_peaks;
    pm3_peak_t sq_peaks[PM3_DSP_MAX_PEAKS];
    size_t ndelay;
    size_t delay[PM3_DSP_NDELAYS];
    pm3_peak_t delay_peak[PM3_DSP_NDELAYS];
    bool delay_valid[PM3_DSP_NDELAYS];

    pm3_family_t family;
    pm3_confidence_t confidence;

    double symbol_clk;      // best symbol rate estimate, samples/symbol
    bool have_symbol_clk;

    double carrier_clk;     // subcarrier / field clock, when one is present
    bool have_carrier;

    double fsk_clk_hi;      // the shorter of the two FSK field clocks
    double fsk_clk_lo;
    double fsk_ratio;

    bool transition_coded;
    double dc_ratio;        // low frequency energy relative to the peak
    double sym_prominence;  // prominence of the plain spectrum at symbol_clk
    double sq_prominence;   // prominence of the squaring line

    bool carrier_at_nyquist;
    double envelope_depth;  // 0.0 constant amplitude, 1.0 switched fully off
    bool needs_envelope;
} pm3_spec_analysis_t;

const char *pm3_family_name(pm3_family_t fam);
const char *pm3_confidence_name(pm3_confidence_t conf);

int pm3_analyse(const double *sig, size_t len, size_t n, pm3_window_t win, pm3_spec_analysis_t *out);

pm3_fft_plan_t *pm3_fft_plan_create(size_t n);
void pm3_fft_plan_destroy(pm3_fft_plan_t *plan);
void pm3_fft(const pm3_fft_plan_t *plan, pm3_cplx_t *data, bool inverse);

size_t pm3_next_pow2(size_t v);
bool pm3_window_from_str(const char *str, pm3_window_t *out);
const char *pm3_window_name(pm3_window_t win);
void pm3_apply_window(double *data, size_t len, pm3_window_t win);

double *pm3_extract(const int32_t *src, size_t len, size_t start, size_t count);
void pm3_remove_mean(double *data, size_t len);
double *pm3_envelope(const double *sig, size_t len, size_t smooth);

typedef struct {
    uint8_t *bits;
    size_t nbits;
    size_t nerrors;
    size_t phase;       // sample offset of the first chip centre
    double eye;         // mean distance from the threshold, 1.0 = fully open
} pm3_slice_t;

int pm3_ask_slice(const double *sig, size_t len, double clk, pm3_slice_t *out);
void pm3_slice_free(pm3_slice_t *out);
bool pm3_is_switched_carrier(const double *sig, size_t len);
double pm3_envelope_depth(const double *sig, size_t len);
void pm3_delay_multiply(const double *in, size_t len, size_t lag, double *out);
int pm3_spectrum(const double *sig, size_t len, size_t n, pm3_window_t win, pm3_spectrum_t *out);
void pm3_spectrum_free(pm3_spectrum_t *spec);
size_t pm3_find_peaks(const pm3_spectrum_t *spec, pm3_peak_t *peaks, size_t max_peaks);
int pm3_stft(const double *sig, size_t len, size_t n, size_t hop, pm3_window_t win, double anchor, pm3_stft_t *out);
void pm3_stft_free(pm3_stft_t *st);

typedef struct {
    bool valid;
    double chip;            // shortest repeated run length, samples
    double long_run;        // 95th percentile run length, samples
    double run_ratio;       // long_run / chip
    double short_fraction;  // runs no longer than 2.5 chips, as a fraction
    bool transition_coded;  // runs never much exceed two chips
    double period;          // autocorrelation repeat period, 0 if none
    double period_strength; // normalised autocorrelation at that lag
} pm3_sigstat_t;


int pm3_signal_stats(const double *sig, size_t len, pm3_sigstat_t *out);
double pm3_autocorr_period(const double *sig, size_t len, double *strength);
int pm3_psk_demod(const double *sig, size_t len, int fc, double clk,
                  uint8_t *bits, size_t *nbits, double *clk_out, int *phase_out,
                  double *score_out, uint8_t *abs_bits);

int pm3_ask_chips(const double *sig, size_t len, double chip, uint8_t *chips, size_t *nchips, double *chip_out, int *phase_out);
double *pm3_resample(const double *in, size_t len, double ratio, size_t *out_len);

#ifdef __cplusplus
}
#endif
#endif // PM3_DSP_H__
