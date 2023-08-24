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

// 1 input to 2 outputs multiplexer
module mux2_oneout(
    input [1:0] sel,
    input y,
    output reg x0,
    output reg x1
);

always @(*)
begin
    case (sel)
        1'b0: x1 = y;
        1'b1: x0 = y;
    endcase
end

endmodule
