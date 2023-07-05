//-----------------------------------------------------------------------------
// Two way MUX.
//
// kombi, 2020.05
//-----------------------------------------------------------------------------

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
