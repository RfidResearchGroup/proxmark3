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

// 16 inputs to 1 output multiplexer
module mux16(
    input [3:0] sel,
    output reg y,
    input x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15
);

always @(*)
begin
    // y = x[sel];
    case (sel)
        4'd0:  y = x0;
        4'd1:  y = x1;
        4'd2:  y = x2;
        4'd3:  y = x3;
        4'd4:  y = x4;
        4'd5:  y = x5;
        4'd6:  y = x6;
        4'd7:  y = x7;
        4'd8:  y = x8;
        4'd9:  y = x9;
        4'd10: y = x10;
        4'd11: y = x11;
        4'd12: y = x12;
        4'd13: y = x13;
        4'd14: y = x14;
        4'd15: y = x15;
    endcase
end

endmodule
