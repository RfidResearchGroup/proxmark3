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
//
// There are two modes:
// - lf_ed_toggle_mode == 0: the output is set low (resp. high) when a low
//   (resp. high) edge/peak is detected, with hysteresis
// - lf_ed_toggle_mode == 1: the output is toggling whenever an edge/peak
//   is detected.
//   That way you can detect two consecutive edges/peaks at the same level (L/H)
//
// Output:
// - ssp_frame (wired to TIOA1 on the arm) for the edge detection/state
// - ssp_clk: cross_lo

module lo_edge_detect(
    input pck0,
    input pck_divclk,
    input [7:0] adc_d,
    input cross_lo,
    input lf_field,
    input lf_ed_toggle_mode,
    input lf_weak_load,
    input lf_ed_hold_tracker,
    input lf_ed_sensitive,
    input lf_ed_slope,
    input [7:0] lf_ed_threshold,
    input ssp_dout,

    output ssp_frame,
    output ssp_clk,
    output adc_clk,
    output pwr_lo,
    output pwr_hi,
    output pwr_oe1,
    output pwr_oe2,
    output pwr_oe3,
    output pwr_oe4,
    output debug
);

wire tag_modulation = ssp_dout & !lf_field;
wire reader_modulation = !ssp_dout & lf_field & pck_divclk;

// No logic, straight through.
assign pwr_oe1 = 1'b0; // not used in LF mode

// Modulate on the same leg the working LF tag simulator uses.
//
// This used to hold pwr_oe3 off and modulate on pwr_oe2 and pwr_oe4 instead,
// which is not what lo_adc.v does - and lo_adc.v is the path behind the LF tag
// simulation that is known to swing a reader's ADC rail to rail from this coil:
//
//   lo_adc.v          oe2 = 0,  oe3 = mod & ~weak,  oe4 = mod & weak
//   lo_edge_detect.v  oe2 = mod & ~weak,  oe3 = 0,  oe4 = mod
//
// Measured against a genuine Paxton reader with a Proxmark simulating on top of
// it: the reader beeps at a continuous coil load toggle, so it can see this
// antenna modulating, and our Hitag 2 answer is emitted perfectly - 1184 samples
// a frame, no bails, the turnaround matching a genuine fob's 227 T0 to the
// carrier period - yet the reader never advances past START_AUTH.  Detectable
// but not decodable is what too shallow a load looks like on a short burst.
//
// The earlier note here claimed both legs together take our own envelope from
// ~148 counts to 0.  That figure was withdrawn as unsound - it assumed a DOUT
// toggle in a mode where it was not reaching the coil - and in any case what
// matters is the perturbation at the READER's antenna, not at ours.
// Modulation depth, measured against a genuine Paxton reader.
//
// Three load configurations were tried, judged both by how many of the reader's
// START_AUTH polls this simulator could still hear after its own answer, and by
// whether the reader ever advanced past START_AUTH:
//
//   oe2 + oe4         96 polls seen of 218    reader does not advance
//   oe3 alone        218 polls seen of 218    reader does not advance
//   oe2 + oe3 + oe4  103 polls seen of 218    reader does not advance
//
// So depth is not what the reader is rejecting - across a 2x range of load it
// behaves identically - but it matters a great deal to our own receive.  A
// heavier load pins the min/max tracker this same module feeds and leaves the
// simulator deaf for a while after every answer, which loses half the reader's
// polls and would lose its follow up command too: a real reader's t_WAIT2 can be
// as short as 90 T0, and Paxton's measures about 269.
//
// oe3 alone is the lightest of the three, and the leg lo_adc.v drives - but it is
// too light to be HEARD: with it a Proxmark reader 1 cm away got nothing at all
// from this simulator, RXFAIL no_signal=127 and not one block read, where
// oe2 + oe4 reads and writes reliably.  So the pair stays.
//
// That leaves our own post-answer deafness to solve the other way, by freezing
// the min/max tracker across our modulation rather than by modulating less - see
// lf_ed_hold_tracker below, which is what that input is for.
assign pwr_oe2 = tag_modulation & ~lf_weak_load;
assign pwr_oe4 = tag_modulation;
assign pwr_oe3 = 1'b0; // base antenna load = 33 Ohms

assign ssp_clk = cross_lo;
assign pwr_lo = reader_modulation;
assign pwr_hi = 1'b0;

// Hold the envelope follower across our own answer.
//
// Retriggerable: every carrier period in which we are modulating reloads the
// counter, so the follower stays held for the whole frame and is released a
// short time after the last transition.  pck0 is 24 MHz, so 8192 counts is
// about 340 us - longer than a 128 us half bit, short enough to be listening
// again well inside the reader's t_WAIT2.
reg [12:0] hold_cnt = 0;
always @(posedge pck0)
begin
    if (tag_modulation)
        hold_cnt <= 13'h1FFF;
    else if (hold_cnt != 0)
        hold_cnt <= hold_cnt - 1;
end

wire tracker_freeze = lf_ed_hold_tracker & (hold_cnt != 0);

// filter the ADC values
wire data_rdy;
wire [7:0] adc_filtered;
assign adc_clk = pck0;

lp20khz_1MSa_iir_filter adc_filter(
    .clk   (pck0),
    .adc_d (adc_d),
    .rdy   (data_rdy),
    .out   (adc_filtered)
);

// detect edges
wire [7:0] high_threshold, highz_threshold, lowz_threshold, low_threshold;
wire [7:0] max, min;
wire edge_state, edge_toggle;

// Measured: feeding the detector the unfiltered adc_d instead of adc_filtered
// was tried, on the grounds that lp20khz_1MSa_iir_filter cuts right at the 20 kHz
// a 6 T0 reader gap sits on and rounds it.  It produced an edge storm - 188043
// edges and not one decoded frame - so the filter stays.

lf_edge_detect lf_ed(
    .clk             (pck0),
    .adc_d           (adc_filtered),
    .lf_ed_threshold (lf_ed_threshold),
    .freeze          (tracker_freeze),
    .sensitive       (lf_ed_sensitive),
    .slope_mode      (lf_ed_slope),
    .data_rdy        (data_rdy),
    .max             (max),
    .min             (min),
    .high_threshold  (high_threshold),
    .highz_threshold (highz_threshold),
    .lowz_threshold  (lowz_threshold),
    .low_threshold   (low_threshold),
    .edge_state      (edge_state),
    .edge_toggle     (edge_toggle)
);

assign debug = lf_ed_toggle_mode ? edge_toggle : edge_state;

assign ssp_frame = lf_ed_toggle_mode ? edge_toggle : edge_state;

endmodule

