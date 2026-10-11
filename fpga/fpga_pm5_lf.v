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
    //input ck_1356meg,
    input spck,
    input pck0,
    input ncs,
    input [7:0] adc_d,
    input cross_lo,
    input mosi,
    input ssp_dout,
    input ce,  // 复位输入，常态高

    output ssp_din,
    output ssp_frame,
    output ssp_clk,
    output adc_clk,
    output miso,
    output pwr_lo,
    output pwr_oe1,
    output pwr_oe2,
    output pwr_oe4,
    output dbg,
    output reg [11:0] pwm_duty = 12'h500
);

// In all modes, let the ADC's outputs be enabled.
//assign adc_noe = 1'b0;
assign miso = 1'bZ;

wire [2:0] major_mode;
assign major_mode = ce ? conf_word[8:6] : 3'b111;

//-----------------------------------------------------------------------------
// The SPI receiver. This sets up the configuration word, which the rest of
// the logic looks at to determine how to connect the A/D and the coil
// drivers (i.e., which section gets it). Also assign some symbolic names
// to the configuration bits, for use below.
//-----------------------------------------------------------------------------

// Receive 16bits of data from ARM here.
reg [15:0] shift_reg;

always @(posedge spck) begin
    if(~ncs & ce)
        shift_reg <= {shift_reg[14:0], mosi};
end

reg [7:0] lf_ed_threshold;

// adjustable frequency clock
wire [7:0] pck_cnt;
wire pck_divclk;
reg [7:0] divisor;
clk_divider div_clk(pck0, divisor, pck_cnt, pck_divclk);

reg [11:0] conf_word;

// We switch modes between transmitting to the 13.56 MHz tag and receiving
// from it, which means that we must make sure that we can do so without
// glitching, or else we will glitch the transmitted carrier.
always @(posedge ncs)
begin
    if(ce) begin
        // 4 bit command
        case (shift_reg[15:12])
            `FPGA_CMD_SET_CONFREG:
            begin
                // 12 bit data
                conf_word <= shift_reg[11:0];
                if (shift_reg[8:6] == `FPGA_MAJOR_MODE_LF_EDGE_DETECT) lf_ed_threshold <= 127;  // default threshold
            end

            `FPGA_CMD_SET_DIVISOR:
                divisor <= shift_reg[7:0]; // 8bits

            `FPGA_CMD_SET_EDGE_DETECT_THRESHOLD:
                lf_ed_threshold <= shift_reg[7:0];  // 8 bits
            `FPGA_CMD_SET_PWR_PWM_LOW_COUNT:pwm_duty <= shift_reg[11:0];
        endcase
    end
end

//-----------------------------------------------------------------------------
// And then we instantiate the modules corresponding to each of the FPGA's
// major modes, and use muxes to connect the outputs of the active mode to
// the output pins.
//-----------------------------------------------------------------------------

// ############################################################################

//   LF reader (generic)
lo_read lr(
    .pck0              (pck0),
    .pck_divclk        (pck_divclk),
    .pck_cnt           (pck_cnt),
    .adc_d             (adc_d),
    .lf_field          (conf_word[0]),

    .ssp_din           (mux0_ssp_din),
    .ssp_frame         (mux0_ssp_frame),
    .ssp_clk           (mux0_ssp_clk),
    .adc_clk           (mux0_adc_clk),
    .pwr_lo            (mux0_pwr_lo),
    .pwr_oe1           (mux0_pwr_oe1),
    .pwr_oe2           (mux0_pwr_oe2),
    .pwr_oe3           (mux0_pwr_oe3),
    .pwr_oe4           (mux0_pwr_oe4),
    .debug             (mux0_debug)
);

//   LF edge detect (generic)
lo_edge_detect le(
    .pck0              (pck0),
    .pck_divclk        (pck_divclk),
    .adc_d             (adc_d),
    .cross_lo          (cross_lo),
    .lf_field          (conf_word[0]),
    .lf_ed_toggle_mode (conf_word[1]),
    .lf_ed_threshold   (lf_ed_threshold),
    .ssp_dout          (ssp_dout),

    .ssp_frame         (mux1_ssp_frame),
    .ssp_clk           (mux1_ssp_clk),
    .adc_clk           (mux1_adc_clk),
    .pwr_lo            (mux1_pwr_lo),
    .pwr_oe1           (mux1_pwr_oe1),
    .pwr_oe2           (mux1_pwr_oe2),
    .pwr_oe3           (mux1_pwr_oe3),
    .pwr_oe4           (mux1_pwr_oe4),
    .debug             (mux1_debug)
);

//   LF passthrough
lo_passthru lp(
    .pck_divclk        (pck_divclk),
    .cross_lo          (cross_lo),
    .ssp_dout          (ssp_dout),

    .ssp_din           (mux2_ssp_din),
    .adc_clk           (mux2_adc_clk),
    .pwr_lo            (mux2_pwr_lo),
    .pwr_oe1           (mux2_pwr_oe1),
    .pwr_oe2           (mux2_pwr_oe2),
    .pwr_oe3           (mux2_pwr_oe3),
    .pwr_oe4           (mux2_pwr_oe4),
    .debug             (mux2_debug)
);

//   LF ADC (read/write)
lo_adc la(
    .pck0              (pck0),
    .adc_d             (adc_d),
    .divisor           (divisor),
    .lf_field          (conf_word[0]),
    .ssp_dout          (ssp_dout),

    .ssp_din           (mux3_ssp_din),
    .ssp_frame         (mux3_ssp_frame),
    .ssp_clk           (mux3_ssp_clk),
    .adc_clk           (mux3_adc_clk),
    .pwr_lo            (mux3_pwr_lo ),
    .pwr_oe1           (mux3_pwr_oe1),
    .pwr_oe2           (mux3_pwr_oe2),
    .pwr_oe3           (mux3_pwr_oe3),
    .pwr_oe4           (mux3_pwr_oe4),
    .debug             (mux3_debug)
);

assign mux6_pwr_lo = 1'b1;
//   7 -- SPARE

// These assignments must agree with the defines in fpgaloader.h
// Major modes Low Frequency
//   mux0 = LF reader (generic)
//   mux1 = LF edge detect (generic)
//   mux2 = LF passthrough
//   mux3 = LF ADC (read/write)
//   mux4 = SPARE
//   mux5 = SPARE
//   mux6 = SPARE
//   mux7 = FPGA_MAJOR_MODE_OFF

mux8 mux_ssp_clk (
    .sel    (major_mode),
    .y      (ssp_clk        ),
    .x0     (mux0_ssp_clk   ),
    .x1     (mux1_ssp_clk   ),
    .x2     (1'b0           ),
    .x3     (mux3_ssp_clk   ),
    .x4     (1'b0           ),
    .x5     (1'b0           ),
    .x6     (1'b0           ),
    .x7     (1'b0           )
);

mux8 mux_ssp_din (
    .sel    (major_mode),
    .y      (ssp_din        ),
    .x0     (mux0_ssp_din   ),
    .x1     (1'b0           ),
    .x2     (mux2_ssp_din   ),
    .x3     (mux3_ssp_din   ),
    .x4     (1'b0           ),
    .x5     (1'b0           ),
    .x6     (1'b0           ),
    .x7     (1'b0           )
);

mux8 mux_ssp_frame (
    .sel    (major_mode),
    .y      (ssp_frame      ),
    .x0     (mux0_ssp_frame ),
    .x1     (mux1_ssp_frame ),
    .x2     (1'b0           ),
    .x3     (mux3_ssp_frame ),
    .x4     (1'b0           ),
    .x5     (1'b0           ),
    .x6     (1'b0           ),
    .x7     (1'b0           )
);

mux8 mux_pwr_oe1 (
    .sel    (major_mode),
    .y      (pwr_oe1        ),
    .x0     (mux0_pwr_oe1   ),
    .x1     (mux1_pwr_oe1   ),
    .x2     (mux2_pwr_oe1   ),
    .x3     (mux3_pwr_oe1   ),
    .x4     (1'b0           ),
    .x5     (1'b0           ),
    .x6     (1'b0           ),
    .x7     (1'b0           )
);

mux8 mux_pwr_oe2 (
    .sel    (major_mode),
    .y      (pwr_oe2        ),
    .x0     (mux0_pwr_oe2   ),
    .x1     (mux1_pwr_oe2   ),
    .x2     (mux2_pwr_oe2   ),
    .x3     (mux3_pwr_oe2   ),
    .x4     (1'b0           ),
    .x5     (1'b0           ),
    .x6     (1'b0           ),
    .x7     (1'b0           )
);

mux8 mux_pwr_oe3 (
    .sel    (major_mode),
    .y      (pwr_oe3        ),
    .x0     (mux0_pwr_oe3   ),
    .x1     (mux1_pwr_oe3   ),
    .x2     (mux2_pwr_oe3   ),
    .x3     (mux3_pwr_oe3   ),
    .x4     (1'b0           ),
    .x5     (1'b0           ),
    .x6     (1'b0           ),
    .x7     (1'b0           )
);

mux8 mux_pwr_oe4 (
    .sel    (major_mode),
    .y      (pwr_oe4        ),
    .x0     (mux0_pwr_oe4   ),
    .x1     (mux1_pwr_oe4   ),
    .x2     (mux2_pwr_oe4   ),
    .x3     (mux3_pwr_oe4   ),
    .x4     (1'b0           ),
    .x5     (1'b0           ),
    .x6     (1'b0           ),
    .x7     (1'b0           )
);

mux8 mux_pwr_lo (
    .sel    (major_mode),
    .y      (pwr_lo         ),
    .x0     (mux0_pwr_lo    ),
    .x1     (mux1_pwr_lo    ),
    .x2     (mux2_pwr_lo    ),
    .x3     (mux3_pwr_lo    ),
    .x4     (1'b0           ),
    .x5     (1'b0           ),
    .x6     (mux6_pwr_lo    ),
    .x7     (1'b0           )
);

mux8 mux_adc_clk (
    .sel    (major_mode),
    .y      (adc_clk        ),
    .x0     (mux0_adc_clk   ),
    .x1     (mux1_adc_clk   ),
    .x2     (mux2_adc_clk   ),
    .x3     (mux3_adc_clk   ),
    .x4     (1'b0           ),
    .x5     (1'b0           ),
    .x6     (1'b0           ),
    .x7     (1'b0           )
);

mux8 mux_dbg (
    .sel    (major_mode),
    .y      (dbg            ),
    .x0     (mux0_debug     ),
    .x1     (mux1_debug     ),
    .x2     (mux2_debug     ),
    .x3     (mux3_debug     ),
    .x4     (1'b0           ),
    .x5     (1'b0           ),
    .x6     (1'b0           ),
    .x7     (1'b0           )
);
endmodule
