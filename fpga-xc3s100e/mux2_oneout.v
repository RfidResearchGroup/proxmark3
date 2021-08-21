//-----------------------------------------------------------------------------
// Two way MUX.
//
// kombi, 2020.05
//-----------------------------------------------------------------------------

module mux2_oneout(sel, y, x0, x1);
    input [1:0] sel;
    output x0, x1;
    input y;
    reg x0, x1;

always @(x0 or x1 or sel)
begin
    case (sel)
        1'b0: x1 = y;
        1'b1: x0 = y;
    endcase
end

endmodule
