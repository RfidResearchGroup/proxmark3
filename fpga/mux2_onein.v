//-----------------------------------------------------------------------------
// Two way MUX.
//
// kombi, 2020.05
//-----------------------------------------------------------------------------

module mux2_one(
    input [1:0] sel,
    output reg y,
    input x0,
    input x1
);

always @(*)
begin
    case (sel)
        1'b0: y = x1;
        1'b1: y = x0;
    endcase
end

endmodule
