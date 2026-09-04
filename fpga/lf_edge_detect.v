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

module lf_edge_detect(
    input clk,
    input [7:0] adc_d,
    input [7:0] lf_ed_threshold,
    input freeze,
    input sensitive,
    input slope_mode,
    input data_rdy,

    output [7:0] max,
    output [7:0] min,
    output [7:0] low_threshold,
    output [7:0] high_threshold,
    output [7:0] lowz_threshold,
    output [7:0] highz_threshold,
    output edge_state,
    output edge_toggle
);

min_max_tracker tracker(
    .clk       (clk),
    .adc_d     (adc_d),
    .threshold (lf_ed_threshold),
    .freeze    (freeze),
    .min       (min),
    .max       (max)
);

// auto-tune
assign high_threshold  = (max + min) / 2 + (max - min) / 4;
assign highz_threshold = (max + min) / 2 + (max - min) / 8;
assign lowz_threshold  = (max + min) / 2 - (max - min) / 8;
assign low_threshold   = (max + min) / 2 - (max - min) / 4;

// heuristic to see if it makes sense to try to detect an edge
//
// The gaps below are span/8, span/4 and span/8, so the default limits require a
// tracked span of more than 64 counts before any edge is reported.  That is fine
// for a settled signal and wrong for a recovering one: right after a tag answers,
// the reader's own frame arrives on an envelope ramping from 8 back up to 135,
// where the per bit dips ride on the ramp and the honest tracked span is small.
// The detector then switches itself off exactly when it is needed, which is what
// leaves a Proxmark simulating Hitag 2 deaf across the reader's password.
//
// `sensitive` relaxes the limits so a tight span still counts as workable.  It is
// opt in: on a settled signal the wider limits reject noise, and that is worth
// keeping as the default.
wire [7:0] gap_outer = sensitive ? 8'd2 : 8'd8;
wire [7:0] gap_inner = sensitive ? 8'd4 : 8'd16;

wire enabled =
    (high_threshold > highz_threshold)
    & (highz_threshold > lowz_threshold)
    & (lowz_threshold > low_threshold)
    & ((high_threshold - highz_threshold) > gap_outer)
    & ((highz_threshold - lowz_threshold) > gap_inner)
    & ((lowz_threshold - low_threshold) > gap_outer);

// Slope detection.
//
// Everything above slices against a level derived from the tracked min and max.
// That works on a settled signal and fails on a moving one: right after the tag
// answers, the reader's frame rides on an envelope ramping back up, so a fixed
// level is reached late or not at all.  Per the datasheet a '0' is 18..22 T0 and
// a '1' is 26..32, and t_stop is anything over 36 - so two merged '0' bits, at
// 36..44, cannot be told from a stop by duration.  The edge has to be produced
// here rather than inferred later.
//
// A gap is a sharp drop whatever the DC level is, so compare each sample against
// one from thirty two 1 MSa/s samples ago - 32 us, two thirds of the 48 us gap -
// and call the edge on the difference.  lf_ed_threshold sets how big a step
// counts, so it stays tunable from the ARM.
//
// The baseline has to be a decent fraction of the gap or the step is small and
// the usable threshold band with it: at 16 us, 18 worked and 14 was already
// noise, which is too tight to trust across rigs.  Widening it to 64 us, so the
// comparison spans the whole gap, was measured to gain nothing - same 29 bits of
// the reader's 32 - so 32 us stays and the delay line stays half the size.
reg [7:0] hist [0:31];
reg [4:0] hist_ptr = 0;

always @(posedge clk)
if (data_rdy)
begin
    hist[hist_ptr] <= adc_d;
    hist_ptr <= hist_ptr + 1;
end

wire [7:0] adc_delayed = hist[hist_ptr];   // the oldest entry, 32 samples back

// How big a step counts as an edge, in ADC counts over the 32 us baseline.
//
// Absolute.  Scaling it to the tracked span was tried twice and the tracker's
// span turns out not to be a usable reference: (max - min) >> 3 chatters - 1602
// edges, no decodable frame - while span/3 goes dead, no edges at all.  Those two
// bracket the working step of ~31, so the span is not stable between them; it is
// driven by our own load modulation as well as the reader's, which is exactly
// what makes it the wrong thing to normalise against.  min_max_tracker also
// starts at min=255, max=0, so any such expression needs an underflow guard.
//
// Swept against a Proxmark reader: 28 and below chatters, 29 loses a bit, 30..33
// authenticates, 34 degrades, 36 stops resolving frames.  The optimum does drift
// with coupling - 30, then 31..32, then 32..33 across rig changes today - so -t
// is the knob for a different setup.

wire falling_slope = (adc_delayed > adc_d) &&
                     (({1'b0, adc_delayed} - {1'b0, adc_d}) >= {1'b0, lf_ed_threshold});
wire rising_slope  = (adc_d > adc_delayed) &&
                     (({1'b0, adc_d} - {1'b0, adc_delayed}) >= {1'b0, lf_ed_threshold});

// Toggle the output with hysteresis
// Set to high if the ADC value is above the threshold
// Set to low if the ADC value is below the threshold
reg is_high = 0;
reg is_low = 0;
reg is_zero = 0;
reg trigger_enabled = 1;
reg output_edge = 0;
reg output_state;

// How far the signal has to travel before the state output flips.
//
// The default slices on high/low, which are +/- span/4 either side of the mean,
// so every bit has to traverse half the tracked span.  A reader's BPLM '0' bit
// only gives 14 T0 of field between its gaps, and on a run of them the envelope
// never climbs back above high_threshold - so the state never returns high, no
// new falling edge is produced, and two bits merge into one interval.  Measured
// against a Proxmark reader: the 32 bit password arrived as 29 bits with a single
// 38 T0 interval where two 20 T0 zeroes should have been.
//
// `sensitive` slices on the inner pair instead, +/- span/8, halving the travel
// needed.  Left as an option because the wider hysteresis is what rejects noise
// on a settled signal.
// Measured: an asymmetric pair - trigger on low_threshold, re-arm on lowz - was
// tried here and came out worse, 30 bits of the reader's 32 against 31 for the
// symmetric inner pair.  Keeping both slices on the inner thresholds.
// Where to slice, when `sensitive` is on.
//
// The default pair sits +/- span/4 either side of the mean, so every bit has to
// traverse half the tracked span.  A reader's BPLM '0' only gives 14 T0 of field
// between its gaps, and on a run of them the envelope never climbs back over
// high_threshold - the state never returns high, no new falling edge is produced
// and two bits merge into one interval.
//
// Measured alternatives, on the reader's 32 bit password: +/- span/8 gives 31
// bits, span/16 the same but less consistently, an asymmetric strict-trigger /
// easy-rearm pair 30, and biasing the band towards the top of the envelope 29.
wire [7:0] hi_slice = sensitive ? highz_threshold : high_threshold;
wire [7:0] lo_slice = sensitive ? lowz_threshold  : low_threshold;

always @(posedge clk)
begin
    is_high <= (adc_d >= hi_slice);
    is_low  <= (adc_d <= lo_slice);
    is_zero <= ((adc_d > lowz_threshold) & (adc_d < highz_threshold));
end

// all edges detection
always @(posedge clk)
if (enabled)
begin
    // To enable detecting two consecutive peaks at the same level
    // (low or high) we check whether or not we went back near 0 in-between.
    // This extra check is necessary to prevent from noise artifacts
    // around the threshold values.
    if (trigger_enabled & (is_high | is_low))
    begin
        output_edge <= ~output_edge;
        trigger_enabled <= 0;
    end
    else
        trigger_enabled <= trigger_enabled | is_zero;
end

// Measured: requiring the slope to hold across two consecutive 1 MSa/s samples
// was tried, to throw away the single sample noise that has the reader's 32 bit
// frame arriving as anything from 30 to 33 bits.  It does remove the extra edges
// - nothing over 32 after it - but delays the real ones enough to lose more than
// it saves, 1 authentication in 7 against 2 without.  Left undebounced.

// Return the slope output to idle high after a long flat stretch.
//
// The two slope rules below only ever move output_state on a slope, so it has no
// idle value: it keeps whatever the last edge left it at.  Left low - which is
// where a tag's answer tends to leave it - the next gap drives it low again, so
// there is no transition, no falling edge and no counter reset, and only the
// rising edge at the END of that gap re-arms it.  The frame's first bit is then
// never measured: `lf hitag sniff` logged the reader's first gap as a rising edge
// carrying ra=254, meaning the capture counter had not been reset for 254 T0.
//
// A gap is 4..10 T0 and a bit period at most 32, so the longest flat stretch
// inside a frame is about 28 T0; between frames it is at least t_EOF, 80 T0.
// 512 samples at 1 MSa/s is 64 T0, comfortably between the two.
reg [9:0] flat = 0;

always @(posedge clk)
if (data_rdy)
begin
    if (rising_slope | falling_slope)
        flat <= 0;
    else if (flat != 10'd1023)
        flat <= flat + 1;
end

// edge states
//
// Slope mode is not gated on `enabled`: that heuristic asks whether the tracked
// min/max span is wide enough to slice against, which is exactly the judgement
// slope detection does not need.
always @(posedge clk)
if (slope_mode)
begin
    if (rising_slope)
        output_state <= 1'd1;
    else if (falling_slope)
        output_state <= 1'd0;
    else if (flat == 10'd512)
        output_state <= 1'd1;
end
else if (enabled)
begin
    if (is_high)
        output_state <= 1'd1;
    else if (is_low)
        output_state <= 1'd0;
end

assign edge_state  = output_state;
assign edge_toggle = output_edge;

endmodule
