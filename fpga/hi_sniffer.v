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

module hi_sniffer(
    input ck_1356meg,
    input [7:0] adc_d,

    output ssp_din,
    output reg ssp_frame,
    output ssp_clk,
    output adc_clk,
    output pwr_lo,
    output pwr_hi,
    output pwr_oe1,
    output pwr_oe2,
    output pwr_oe3,
    output pwr_oe4
);

// We are only snooping, all off.
assign pwr_hi  = 1'b0;
assign pwr_lo  = 1'b0;
assign pwr_oe1 = 1'b0;
assign pwr_oe2 = 1'b0;
assign pwr_oe3 = 1'b0;
assign pwr_oe4 = 1'b0;

//reg ssp_frame;
reg [7:0] adc_d_out = 8'd0;
reg [2:0] ssp_cnt   = 3'd0;

assign adc_clk =  ck_1356meg;
assign ssp_clk = ~ck_1356meg;
assign ssp_din = adc_d_out[0];

always @(posedge ssp_clk)
begin
    ssp_cnt <= ssp_cnt + 1;

    if(ssp_cnt[2:0] == 3'b000) // set frame length
    begin
        adc_d_out[7:0] <= adc_d;
        ssp_frame <= 1'b1;
    end
    else
    begin
        // shift value right one bit
        adc_d_out[7:0] <= {1'b0, adc_d_out[7:1]};
        ssp_frame <= 1'b0;
    end

end
endmodule
