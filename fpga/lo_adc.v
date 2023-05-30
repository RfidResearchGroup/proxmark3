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
// The way that we connect things in low-frequency simulation mode. In this
// case just pass everything through to the ARM, which can bit-bang this
// (because it is so slow).
//
// Jonathan Westhues, April 2006
//-----------------------------------------------------------------------------

module lo_adc(
    input pck0,
    input [7:0] adc_d,
    input [7:0] divisor,
    input lf_field,
    input ssp_dout,

    output ssp_din,
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

reg [7:0] to_arm_shiftreg;
reg [7:0] pck_divider;
reg clk_state;

// Antenna logic, depending on "lf_field" (in arm defined as FPGA_LF_READER_FIELD)
wire tag_modulation = ssp_dout & !lf_field;
wire reader_modulation = !ssp_dout & lf_field & clk_state;

// always on (High Frequency outputs, unused)
assign pwr_oe1 = 1'b0;
assign pwr_hi  = 1'b0;

// low frequency outputs
assign pwr_lo  = reader_modulation;
assign pwr_oe2 = 1'b0;  // 33 Ohms
assign pwr_oe3 = tag_modulation; // base antenna load = 33 Ohms
assign pwr_oe4 = 1'b0;  // 10k Ohms

// Debug Output ADC clock
assign debug = adc_clk;

// ADC clock out of phase with antenna driver
assign adc_clk = ~clk_state;

// serialized SSP data is gated by clk_state to suppress unwanted signal
assign ssp_din = to_arm_shiftreg[7] && !clk_state;

// SSP clock always runs at 24MHz
assign ssp_clk = pck0;

// SSP frame is gated by clk_state and goes high when pck_divider=8..15
assign ssp_frame = (pck_divider[7:3] == 5'd1) && !clk_state;

// divide 24mhz down to 3mhz
always @(posedge pck0)
begin
    if (pck_divider == divisor[7:0])
    begin
        pck_divider <= 8'd0;
        clk_state = !clk_state;
    end
    else
    begin
        pck_divider <= pck_divider + 1;
    end
end

// this task also runs at pck0 frequency (24Mhz) and is used to serialize
// the ADC output which is then clocked into the ARM SSP.
always @(posedge pck0)
begin
    if ((pck_divider == 8'd7) && !clk_state)
        to_arm_shiftreg <= adc_d;
    else
    begin
        to_arm_shiftreg[7:1] <= to_arm_shiftreg[6:0];
        to_arm_shiftreg[0] <= 1'b0;
    end
end

endmodule
