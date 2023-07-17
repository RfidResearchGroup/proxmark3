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
// For reading TI tags, we need to place the FPGA in pass through mode
// and pass everything through to the ARM

module lo_passthru(
    input pck_divclk,
    input cross_lo,
    input ssp_dout,

    output ssp_din,
    output adc_clk,
    output pwr_lo,
    output pwr_hi,
    output pwr_oe1,
    output pwr_oe2,
    output pwr_oe3,
    output pwr_oe4,
    output debug
);

// the antenna is modulated when ssp_dout = 1, when 0 the
// antenna drivers stop modulating and go into listen mode
assign ssp_din = cross_lo;
assign adc_clk = 1'b0;
assign pwr_lo  = pck_divclk && ssp_dout;
assign pwr_hi  = 1'b0;
assign pwr_oe1 = ssp_dout;
assign pwr_oe2 = ssp_dout;
assign pwr_oe3 = 1'b0;
assign pwr_oe4 = ssp_dout;
assign debug   = cross_lo;

endmodule
