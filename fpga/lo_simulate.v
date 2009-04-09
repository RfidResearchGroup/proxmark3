//-----------------------------------------------------------------------------
// The way that we connect things in low-frequency simulation mode. In this
// case just pass everything through to the ARM, which can bit-bang this
// (because it is so slow).
//
// Jonathan Westhues, April 2006
//-----------------------------------------------------------------------------

module lo_simulate(
    pck0, ck_1356meg, ck_1356megb,
    pwr_lo, pwr_hi, pwr_oe1, pwr_oe2, pwr_oe3, pwr_oe4,
    adc_d, adc_clk,
    ssp_frame, ssp_din, ssp_dout, ssp_clk,
    cross_hi, cross_lo,
    dbg
);
    input pck0, ck_1356meg, ck_1356megb;
    output pwr_lo, pwr_hi, pwr_oe1, pwr_oe2, pwr_oe3, pwr_oe4;
    input [7:0] adc_d;
    output adc_clk;
    input ssp_dout;
    output ssp_frame, ssp_din, ssp_clk;
    input cross_hi, cross_lo;
    output dbg;

// No logic, straight through.
assign pwr_oe3 = 1'b0;
assign pwr_oe1 = ssp_dout;
assign pwr_oe2 = ssp_dout;
assign pwr_oe4 = ssp_dout;
assign ssp_clk = cross_lo;
assign pwr_lo = 1'b0;
assign adc_clk = 1'b0;
assign pwr_hi = 1'b0;
assign dbg = cross_lo;

endmodule
