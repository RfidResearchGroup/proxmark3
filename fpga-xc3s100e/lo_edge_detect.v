//-----------------------------------------------------------------------------
// Copyright (C) 2014 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
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

//For ISE 10.1 PROJ,IDE auto include
//`include "lp20khz_1MSa_iir_filter.v"
//`include "lf_edge_detect.v"

module lo_edge_detect(
    input pck0, input pck_divclk,
    output pwr_lo, output pwr_hi,
    output pwr_oe1, output pwr_oe2, output pwr_oe3, output pwr_oe4,
    input [7:0] adc_d, output adc_clk,
    output ssp_frame, input ssp_dout, output ssp_clk,
    input cross_lo,
    output dbg,
    input lf_field,
    input lf_ed_toggle_mode, input [7:0] lf_ed_threshold
);

wire tag_modulation = ssp_dout & !lf_field;
wire reader_modulation = !ssp_dout & lf_field & pck_divclk;

// No logic, straight through.
assign pwr_oe1 = 1'b0;                      // not used in LF mode
assign pwr_oe3 = 1'b0;                      // base antenna load = 33 Ohms
// when modulating, add another 33 Ohms and 10k Ohms in parallel:
assign pwr_oe2 = tag_modulation;
assign pwr_oe4 = tag_modulation;

assign ssp_clk = cross_lo;
assign pwr_lo = reader_modulation;
assign pwr_hi = 1'b0;

// filter the ADC values
wire data_rdy;
wire [7:0] adc_filtered;
assign adc_clk = pck0;
lp20khz_1MSa_iir_filter adc_filter(pck0, adc_d, data_rdy, adc_filtered);

// detect edges
wire [7:0] high_threshold, highz_threshold, lowz_threshold, low_threshold;
wire [7:0] max, min;
wire edge_state, edge_toggle;
lf_edge_detect lf_ed(pck0, adc_filtered, lf_ed_threshold,
    max, min,
    high_threshold, highz_threshold, lowz_threshold, low_threshold,
    edge_state, edge_toggle);

assign dbg = lf_ed_toggle_mode ? edge_toggle : edge_state;

assign ssp_frame = lf_ed_toggle_mode ? edge_toggle : edge_state;

endmodule

