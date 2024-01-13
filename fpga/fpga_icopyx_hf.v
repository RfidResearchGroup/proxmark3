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
// The FPGA is responsible for interfacing between the A/D, the coil drivers,
// and the ARM. In the low-frequency modes it passes the data straight
// through, so that the ARM gets raw A/D samples over the SSP. In the high-
// frequency modes, the FPGA might perform some demodulation first, to
// reduce the amount of data that we must send to the ARM.
//-----------------------------------------------------------------------------

module fpga_hf(
    input spck,
    output miso,
    input mosi,
    input ncs,
    input pck0,
    input ck_1356meg,
    input ck_1356megb,
    output pwr_lo,
    output pwr_hi,
    output pwr_oe1,
    output pwr_oe2,
    output pwr_oe3,
    output pwr_oe4,
    input [7:0] adc_d,
    output adc_clk,
    output adc_noe,
    output ssp_frame,
    output ssp_din,
    input ssp_dout,
    output ssp_clk,
    input cross_hi,
    input cross_lo,
    output debug
);

//-----------------------------------------------------------------------------
// The SPI receiver. This sets up the configuration word, which the rest of
// the logic looks at to determine how to connect the A/D and the coil
// drivers (i.e., which section gets it). Also assign some symbolic names
// to the configuration bits, for use below.
//-----------------------------------------------------------------------------

// Receive 16bits of data from ARM here.
reg [15:0] shift_reg;
always @(posedge spck) if (~ncs) shift_reg <= {shift_reg[14:0], mosi};

reg [8:0] conf_word;
reg trace_enable;

// select module (outputs) based on major mode
wire [2:0] major_mode = conf_word[8:6];
// parameter to be passed to modules
wire [3:0] minor_mode = conf_word[3:0];

// configuring the HF reader
wire [1:0] subcarrier_frequency = conf_word[5:4];

// We switch modes between transmitting to the 13.56 MHz tag and receiving
// from it, which means that we must make sure that we can do so without
// glitching, or else we will glitch the transmitted carrier.
always @(posedge ncs)
begin
    // 4 bit command
    case (shift_reg[15:12])
        `FPGA_CMD_SET_CONFREG:  conf_word <= shift_reg[8:0];
        `FPGA_CMD_TRACE_ENABLE: trace_enable <= shift_reg[0];
    endcase
end

//-----------------------------------------------------------------------------
// And then we instantiate the modules corresponding to each of the FPGA's
// major modes, and use muxes to connect the outputs of the active mode to
// the output pins.
//-----------------------------------------------------------------------------

//   0 - HF reader
hi_reader hr(
    .ck_1356meg (ck_1356megb),
    .pwr_lo     (hr_pwr_lo),
    .pwr_hi     (hr_pwr_hi),
    .pwr_oe1    (hr_pwr_oe1),
    .pwr_oe2    (hr_pwr_oe2),
    .pwr_oe3    (hr_pwr_oe3),
    .pwr_oe4    (hr_pwr_oe4),
    .adc_d      (adc_d),
    .adc_clk    (hr_adc_clk),
    .ssp_frame  (hr_ssp_frame),
    .ssp_din    (hr_ssp_din),
    .ssp_dout   (ssp_dout),
    .ssp_clk    (hr_ssp_clk),
    .debug      (hr_debug),
    .subcarrier_frequency (subcarrier_frequency),
    .minor_mode (minor_mode)
);

//   1 - HF simulated tag
hi_simulate hs(
    .ck_1356meg (ck_1356meg),
    .pwr_lo     (hs_pwr_lo),
    .pwr_hi     (hs_pwr_hi),
    .pwr_oe1    (hs_pwr_oe1),
    .pwr_oe2    (hs_pwr_oe2),
    .pwr_oe3    (hs_pwr_oe3),
    .pwr_oe4    (hs_pwr_oe4),
    .adc_d      (adc_d),
    .adc_clk    (hs_adc_clk),
    .ssp_frame  (hs_ssp_frame),
    .ssp_din    (hs_ssp_din),
    .ssp_dout   (ssp_dout),
    .ssp_clk    (hs_ssp_clk),
    .debug      (hs_debug),
    .mod_type   (minor_mode)
);

//   2 - HF ISO14443-A
hi_iso14443a hisn(
    .ck_1356meg (ck_1356meg),
    .pwr_lo     (hisn_pwr_lo),
    .pwr_hi     (hisn_pwr_hi),
    .pwr_oe1    (hisn_pwr_oe1),
    .pwr_oe2    (hisn_pwr_oe2),
    .pwr_oe3    (hisn_pwr_oe3),
    .pwr_oe4    (hisn_pwr_oe4),
    .adc_d      (adc_d),
    .adc_clk    (hisn_adc_clk),
    .ssp_frame  (hisn_ssp_frame),
    .ssp_din    (hisn_ssp_din),
    .ssp_dout   (ssp_dout),
    .ssp_clk    (hisn_ssp_clk),
    .debug      (hisn_debug),
    .mod_type   (minor_mode)
);

//   3 - HF sniff
hi_sniffer he(
    .ck_1356meg  (ck_1356megb),
    .pwr_lo      (he_pwr_lo),
    .pwr_hi      (he_pwr_hi),
    .pwr_oe1     (he_pwr_oe1),
    .pwr_oe2     (he_pwr_oe2),
    .pwr_oe3     (he_pwr_oe3),
    .pwr_oe4     (he_pwr_oe4),
    .adc_d       (adc_d),
    .adc_clk     (he_adc_clk),
    .ssp_frame   (he_ssp_frame),
    .ssp_din     (he_ssp_din),
    .ssp_clk     (he_ssp_clk)
);

//   4 - HF ISO18092 FeliCa
hi_flite hfl(
    .ck_1356meg  (ck_1356megb),
    .pwr_lo      (hfl_pwr_lo),
    .pwr_hi      (hfl_pwr_hi),
    .pwr_oe1     (hfl_pwr_oe1),
    .pwr_oe2     (hfl_pwr_oe2),
    .pwr_oe3     (hfl_pwr_oe3),
    .pwr_oe4     (hfl_pwr_oe4),
    .adc_d       (adc_d),
    .adc_clk     (hfl_adc_clk),
    .ssp_frame   (hfl_ssp_frame),
    .ssp_din     (hfl_ssp_din),
    .ssp_dout    (ssp_dout),
    .ssp_clk     (hfl_ssp_clk),
    .debug       (hfl_debug),
    .mod_type    (minor_mode)
);

//   5 - HF get trace
hi_get_trace gt(
    .ck_1356megb  (ck_1356megb),
    .adc_d        (adc_d),
    .trace_enable (trace_enable),
    .major_mode   (major_mode),
    .ssp_frame    (gt_ssp_frame),
    .ssp_din      (gt_ssp_din),
    .ssp_clk      (gt_ssp_clk)
);

// Major modes:
//   x0 = HF reader
//   x1 = HF simulated tag
//   x2 = HF ISO14443-A
//   x3 = HF sniff
//   x4 = HF ISO18092 FeliCa
//   x5 = HF get trace
//   x6 = unused
//   x7 = FPGA_MAJOR_MODE_OFF

mux8 mux_ssp_clk   (.sel(major_mode), .y(ssp_clk  ), .x0(hr_ssp_clk   ), .x1(hs_ssp_clk  ), .x2(hisn_ssp_clk  ), .x3(he_ssp_clk  ), .x4(hfl_ssp_clk  ), .x5(gt_ssp_clk  ), .x6(1'b0), .x7(1'b0) );
mux8 mux_ssp_din   (.sel(major_mode), .y(ssp_din  ), .x0(hr_ssp_din   ), .x1(hs_ssp_din  ), .x2(hisn_ssp_din  ), .x3(he_ssp_din  ), .x4(hfl_ssp_din  ), .x5(gt_ssp_din  ), .x6(1'b0), .x7(1'b0) );
mux8 mux_ssp_frame (.sel(major_mode), .y(ssp_frame), .x0(hr_ssp_frame ), .x1(hs_ssp_frame), .x2(hisn_ssp_frame), .x3(he_ssp_frame), .x4(hfl_ssp_frame), .x5(gt_ssp_frame), .x6(1'b0), .x7(1'b0) );
mux8 mux_pwr_oe1   (.sel(major_mode), .y(pwr_oe1  ), .x0(hr_pwr_oe1   ), .x1(hs_pwr_oe1  ), .x2(hisn_pwr_oe1  ), .x3(he_pwr_oe1  ), .x4(hfl_pwr_oe1  ), .x5(1'b0        ), .x6(1'b0), .x7(1'b0) );
mux8 mux_pwr_oe2   (.sel(major_mode), .y(pwr_oe2  ), .x0(hr_pwr_oe2   ), .x1(hs_pwr_oe2  ), .x2(hisn_pwr_oe2  ), .x3(he_pwr_oe2  ), .x4(hfl_pwr_oe2  ), .x5(1'b0        ), .x6(1'b0), .x7(1'b0) );
mux8 mux_pwr_oe3   (.sel(major_mode), .y(pwr_oe3  ), .x0(hr_pwr_oe3   ), .x1(hs_pwr_oe3  ), .x2(hisn_pwr_oe3  ), .x3(he_pwr_oe3  ), .x4(hfl_pwr_oe3  ), .x5(1'b0        ), .x6(1'b0), .x7(1'b0) );
mux8 mux_pwr_oe4   (.sel(major_mode), .y(pwr_oe4  ), .x0(hr_pwr_oe4   ), .x1(hs_pwr_oe4  ), .x2(hisn_pwr_oe4  ), .x3(he_pwr_oe4  ), .x4(hfl_pwr_oe4  ), .x5(1'b0        ), .x6(1'b0), .x7(1'b0) );
mux8 mux_pwr_lo    (.sel(major_mode), .y(pwr_lo   ), .x0(hr_pwr_lo    ), .x1(hs_pwr_lo   ), .x2(hisn_pwr_lo   ), .x3(he_pwr_lo   ), .x4(hfl_pwr_lo   ), .x5(1'b0        ), .x6(1'b0), .x7(1'b0) );
mux8 mux_pwr_hi    (.sel(major_mode), .y(pwr_hi   ), .x0(hr_pwr_hi    ), .x1(hs_pwr_hi   ), .x2(hisn_pwr_hi   ), .x3(he_pwr_hi   ), .x4(hfl_pwr_hi   ), .x5(1'b0        ), .x6(1'b0), .x7(1'b0) );
mux8 mux_adc_clk   (.sel(major_mode), .y(adc_clk  ), .x0(hr_adc_clk   ), .x1(hs_adc_clk  ), .x2(hisn_adc_clk  ), .x3(he_adc_clk  ), .x4(hfl_adc_clk  ), .x5(1'b0        ), .x6(1'b0), .x7(1'b0) );
mux8 mux_dbg       (.sel(major_mode), .y(debug    ), .x0(hr_debug     ), .x1(hs_debug    ), .x2(hisn_debug    ), .x3(he_debug    ), .x4(hfl_debug    ), .x5(1'b0        ), .x6(1'b0), .x7(1'b0) );

// In all modes, let the ADC's outputs be enabled.
assign adc_noe = 1'b0;

endmodule
