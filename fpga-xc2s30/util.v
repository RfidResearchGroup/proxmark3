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
// General-purpose miscellany.
//

module mux8(sel, y, x0, x1, x2, x3, x4, x5, x6, x7);
    input [2:0] sel;
    input x0, x1, x2, x3, x4, x5, x6, x7;
    output y;
    reg y;

always @(x0 or x1 or x2 or x3 or x4 or x5 or x6 or x7 or sel)
begin
    case (sel)
        3'b000: y = x0;
        3'b001: y = x1;
        3'b010: y = x2;
        3'b011: y = x3;
        3'b100: y = x4;
        3'b101: y = x5;
        3'b110: y = x6;
        3'b111: y = x7;
    endcase
end

endmodule
