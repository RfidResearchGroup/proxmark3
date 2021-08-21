//-----------------------------------------------------------------------------
// Two way MUX.
//
// kombi, 2020.05
//-----------------------------------------------------------------------------

module mux2_one(sel, y, x0, x1);
    input [1:0] sel;
    input x0, x1;
    output y;
    reg y;

always @(x0 or x1 or sel)
begin
    case (sel)
        1'b0: y = x1;
        1'b1: y = x0;
    endcase
end

endmodule
