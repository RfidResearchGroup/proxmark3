//-----------------------------------------------------------------------------
// Copyright (C) 2014 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
module clk_divider(input clk, input [7:0] divisor, output [7:0] div_cnt, output div_clk);

    reg [7:0] div_cnt_ = 0;
    reg div_clk_;
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

