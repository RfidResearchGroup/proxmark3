//-----------------------------------------------------------------------------
// For reading TI tags, we need to place the FPGA in pass through mode
// and pass everything through to the ARM
//-----------------------------------------------------------------------------
// iZsh <izsh at fail0verflow.com>, June 2014

module lo_passthru(
    input pck_divclk,
    output pwr_lo, output pwr_hi,
    output pwr_oe1, output pwr_oe2, output pwr_oe3, output pwr_oe4,
    output adc_clk,
    output ssp_din, input ssp_dout,
    input cross_lo,
    output dbg
);

// the antenna is modulated when ssp_dout = 1, when 0 the
// antenna drivers stop modulating and go into listen mode
assign pwr_oe3 = 1'b0;
assign pwr_oe1 = ssp_dout;
assign pwr_oe2 = ssp_dout;
assign pwr_oe4 = ssp_dout;
assign pwr_lo = pck_divclk && ssp_dout;
assign pwr_hi = 1'b0;
assign adc_clk = 1'b0;
assign ssp_din = cross_lo;
assign dbg = cross_lo;

endmodule
