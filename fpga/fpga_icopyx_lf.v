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

module fpga_lf(
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
    output debug,
    output PWR_LO_EN
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

reg [11:0] conf_word;

// select module (outputs) based on major mode
wire [2:0] major_mode = conf_word[8:6];
// parameter to be passed to modules
wire lf_field = conf_word[0];
wire lf_ed_toggle_mode = conf_word[1];
reg [7:0] lf_ed_threshold;

wire [7:0] pck_cnt;
wire pck_divclk;
reg [7:0] divisor;

clk_divider div_clk(
    .clk     (pck0),
    .divisor (divisor),
    .div_cnt (pck_cnt),
    .div_clk (pck_divclk)
);

// We switch modes between transmitting to the 13.56 MHz tag and receiving
// from it, which means that we must make sure that we can do so without
// glitching, or else we will glitch the transmitted carrier.
always @(posedge ncs)
begin
    // 4 bit command
    case (shift_reg[15:12])
        `FPGA_CMD_SET_CONFREG:
        begin
            // 12 bit data
            conf_word <= shift_reg[11:0];
            if (shift_reg[8:6] == `FPGA_MAJOR_MODE_LF_EDGE_DETECT)
            begin
                lf_ed_threshold <= 127;  // default threshold
            end
        end

        `FPGA_CMD_SET_DIVISOR:
            divisor <= shift_reg[7:0]; // 8bits

        `FPGA_CMD_SET_EDGE_DETECT_THRESHOLD:
            lf_ed_threshold <= shift_reg[7:0];  // 8 bits
    endcase
end

//-----------------------------------------------------------------------------
// And then we instantiate the modules corresponding to each of the FPGA's
// major modes, and use muxes to connect the outputs of the active mode to
// the output pins.
//-----------------------------------------------------------------------------

//   0 -- LF reader (generic)
lo_read lr(
    .pck0              (pck0),
    .pck_cnt           (pck_cnt),
    .pck_divclk        (pck_divclk),
    .pwr_lo            (lr_pwr_lo),
    .pwr_hi            (lr_pwr_hi),
    .pwr_oe1           (lr_pwr_oe1),
    .pwr_oe2           (lr_pwr_oe2),
    .pwr_oe3           (lr_pwr_oe3),
    .pwr_oe4           (lr_pwr_oe4),
    .adc_d             (adc_d),
    .adc_clk           (lr_adc_clk),
    .ssp_frame         (lr_ssp_frame),
    .ssp_din           (lr_ssp_din),
    .ssp_clk           (lr_ssp_clk),
    .debug             (lr_debug),
    .lf_field          (lf_field)
);

//   1 -- LF edge detect (generic)
lo_edge_detect le(
    .pck0              (pck0),
    .pck_divclk        (pck_divclk),
    .pwr_lo            (le_pwr_lo),
    .pwr_hi            (le_pwr_hi),
    .pwr_oe1           (le_pwr_oe1),
    .pwr_oe2           (le_pwr_oe2),
    .pwr_oe3           (le_pwr_oe3),
    .pwr_oe4           (le_pwr_oe4),
    .adc_d             (adc_d),
    .adc_clk           (le_adc_clk),
    .ssp_frame         (le_ssp_frame),
    .ssp_dout          (ssp_dout),
    .ssp_clk           (le_ssp_clk),
    .cross_lo          (cross_lo),
    .debug             (le_debug),
    .lf_field          (lf_field),
    .lf_ed_toggle_mode (lf_ed_toggle_mode),
    .lf_ed_threshold   (lf_ed_threshold)
);

//   2 -- LF passthrough
lo_passthru lp(
    .pck_divclk        (pck_divclk),
    .pwr_lo            (lp_pwr_lo),
    .pwr_hi            (lp_pwr_hi),
    .pwr_oe1           (lp_pwr_oe1),
    .pwr_oe2           (lp_pwr_oe2),
    .pwr_oe3           (lp_pwr_oe3),
    .pwr_oe4           (lp_pwr_oe4),
    .adc_clk           (lp_adc_clk),
    .ssp_din           (lp_ssp_din),
    .ssp_dout          (ssp_dout),
    .cross_lo          (cross_lo),
    .debug             (lp_debug)
);

//   3 -- LF ADC (read/write)
lo_adc la(
    .pck0              (pck0),
    .pwr_lo            (la_pwr_lo ),
    .pwr_hi            (la_pwr_hi ),
    .pwr_oe1           (la_pwr_oe1),
    .pwr_oe2           (la_pwr_oe2),
    .pwr_oe3           (la_pwr_oe3),
    .pwr_oe4           (la_pwr_oe4),
    .adc_d             (adc_d),
    .adc_clk           (la_adc_clk),
    .ssp_frame         (la_ssp_frame),
    .ssp_din           (la_ssp_din),
    .ssp_dout          (ssp_dout),
    .ssp_clk           (la_ssp_clk),
    .debug             (la_debug),
    .divisor           (divisor),
    .lf_field          (lf_field)
);

// Major modes:
//   x0 = LF reader (generic)
//   x1 = LF edge detect (generic)
//   x2 = LF passthrough
//   x3 = LF ADC (read/write)
//   x4 = SPARE
//   x5 = SPARE
//   x6 = SPARE
//   x7 = FPGA_MAJOR_MODE_OFF

mux8 mux_ssp_clk   (.sel(major_mode), .y(ssp_clk  ), .x0(lr_ssp_clk  ), .x1(le_ssp_clk  ), .x2(1'b0      ), .x3(la_ssp_clk  ), .x4(1'b0), .x5(1'b0), .x6(1'b0), .x7(1'b0) );
mux8 mux_ssp_din   (.sel(major_mode), .y(ssp_din  ), .x0(lr_ssp_din  ), .x1(1'b0        ), .x2(lp_ssp_din), .x3(la_ssp_din  ), .x4(1'b0), .x5(1'b0), .x6(1'b0), .x7(1'b0) );
mux8 mux_ssp_frame (.sel(major_mode), .y(ssp_frame), .x0(lr_ssp_frame), .x1(le_ssp_frame), .x2(1'b0      ), .x3(la_ssp_frame), .x4(1'b0), .x5(1'b0), .x6(1'b0), .x7(1'b0) );
mux8 mux_pwr_oe1   (.sel(major_mode), .y(pwr_oe1  ), .x0(lr_pwr_oe1  ), .x1(le_pwr_oe1  ), .x2(lp_pwr_oe1), .x3(la_pwr_oe1  ), .x4(1'b0), .x5(1'b0), .x6(1'b0), .x7(1'b0) );
mux8 mux_pwr_oe2   (.sel(major_mode), .y(pwr_oe2  ), .x0(lr_pwr_oe2  ), .x1(le_pwr_oe2  ), .x2(lp_pwr_oe2), .x3(la_pwr_oe2  ), .x4(1'b0), .x5(1'b0), .x6(1'b0), .x7(1'b0) );
mux8 mux_pwr_oe3   (.sel(major_mode), .y(pwr_oe3  ), .x0(lr_pwr_oe3  ), .x1(le_pwr_oe3  ), .x2(lp_pwr_oe3), .x3(la_pwr_oe3  ), .x4(1'b0), .x5(1'b0), .x6(1'b0), .x7(1'b0) );
mux8 mux_pwr_oe4   (.sel(major_mode), .y(pwr_oe4  ), .x0(lr_pwr_oe4  ), .x1(le_pwr_oe4  ), .x2(lp_pwr_oe4), .x3(la_pwr_oe4  ), .x4(1'b0), .x5(1'b0), .x6(1'b0), .x7(1'b0) );
mux8 mux_pwr_lo    (.sel(major_mode), .y(pwr_lo   ), .x0(lr_pwr_lo   ), .x1(le_pwr_lo   ), .x2(lp_pwr_lo ), .x3(la_pwr_lo   ), .x4(1'b0), .x5(1'b0), .x6(1'b1), .x7(1'b0) );
mux8 mux_pwr_hi    (.sel(major_mode), .y(pwr_hi   ), .x0(lr_pwr_hi   ), .x1(le_pwr_hi   ), .x2(lp_pwr_hi ), .x3(la_pwr_hi   ), .x4(1'b0), .x5(1'b0), .x6(1'b0), .x7(1'b0) );
mux8 mux_adc_clk   (.sel(major_mode), .y(adc_clk  ), .x0(lr_adc_clk  ), .x1(le_adc_clk  ), .x2(lp_adc_clk), .x3(la_adc_clk  ), .x4(1'b0), .x5(1'b0), .x6(1'b0), .x7(1'b0) );
mux8 mux_dbg       (.sel(major_mode), .y(debug    ), .x0(lr_debug    ), .x1(le_debug    ), .x2(lp_debug  ), .x3(la_debug    ), .x4(1'b0), .x5(1'b0), .x6(1'b0), .x7(1'b0) );
mux8 mux_ant       (.sel(major_mode), .y(PWR_LO_EN), .x0(1'b1        ), .x1(1'b1        ), .x2(1'b1      ), .x3(1'b1        ), .x4(1'b0), .x5(1'b0), .x6(1'b0), .x7(1'b0) );

// In all modes, let the ADC's outputs be enabled.
assign adc_noe = 1'b0;

endmodule
