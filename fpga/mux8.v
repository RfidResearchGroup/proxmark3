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

// 8 inputs to 1 output multiplexer
module mux8(
    input [2:0] sel,
    output reg y,
    input x0, x1, x2, x3, x4, x5, x6, x7
);

always @(*)
begin
    // y = x[sel];
    case (sel)
        3'd0: y = x0;
        3'd1: y = x1;
        3'd2: y = x2;
        3'd3: y = x3;
        3'd4: y = x4;
        3'd5: y = x5;
        3'd6: y = x6;
        3'd7: y = x7;
    endcase
end

endmodule
