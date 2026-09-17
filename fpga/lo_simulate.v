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

module lo_simulate(
    input pck0,
    input ck_1356meg,
    input ck_1356megb,
    input [7:0] adc_d,
    input [7:0] divisor,
    input cross_hi,
    input cross_lo,
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

// No logic, straight through.
assign pwr_oe3 = 1'b0;
assign pwr_oe1 = ssp_dout;
assign pwr_oe2 = ssp_dout;
assign pwr_oe4 = ssp_dout;
assign ssp_clk = cross_lo;
assign pwr_lo  = 1'b0;
assign pwr_hi  = 1'b0;
assign debug   = ssp_frame;

// Divide the clock to be used for the ADC
reg [7:0] pck_divider;
reg clk_state;

always @(posedge pck0)
begin
    if(pck_divider == divisor[7:0])
        begin
            pck_divider <= 8'd0;
            clk_state = !clk_state;
        end
    else
    begin
        pck_divider <= pck_divider + 1;
    end
end

assign adc_clk = ~clk_state;

// Toggle the output with hysteresis
//  Set to high if the ADC value is above 200
//  Set to low if the ADC value is below 64
reg is_high;
reg is_low;
reg output_state;

always @(posedge pck0)
begin
    if((pck_divider == 8'd7) && !clk_state) begin
        is_high = (adc_d >= 8'd191);
        is_low = (adc_d <= 8'd64);
    end
end

always @(posedge is_high or posedge is_low)
begin
    if(is_high)
        output_state <= 1'd1;
    else if(is_low)
        output_state <= 1'd0;
end

assign ssp_frame = output_state;

endmodule

