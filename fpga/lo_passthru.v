//-----------------------------------------------------------------------------
// For reading TI tags, we need to place the FPGA in pass through mode
// and pass everything through to the ARM
//-----------------------------------------------------------------------------

module lo_passthru(
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
assign pwr_oe1 = 1'b1;
assign pwr_oe2 = 1'b1;
assign pwr_oe4 = 1'b1;
assign pwr_lo = 1'b0;
assign pwr_hi = 1'b0;
assign adc_clk = 1'b0;
assign ssp_din = cross_lo;
assign dbg = cross_lo;

endmodule
