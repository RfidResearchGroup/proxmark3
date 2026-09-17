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

module clk_divider(
    input clk,
    input [7:0] divisor,
    output [7:0] div_cnt,
    output div_clk
);

    reg [7:0] div_cnt_ = 0;
    reg div_clk_ = 0;
    assign div_cnt = div_cnt_;
    assign div_clk = div_clk_;

    always @(posedge clk)
    begin
        if(div_cnt == divisor) begin
            div_cnt_ <= 8'd0;
            div_clk_ = !div_clk_;
        end else
            div_cnt_ <= div_cnt_ + 1;
    end

endmodule

