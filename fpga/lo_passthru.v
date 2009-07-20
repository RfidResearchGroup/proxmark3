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
    dbg, divisor
);
    input pck0, ck_1356meg, ck_1356megb;
    output pwr_lo, pwr_hi, pwr_oe1, pwr_oe2, pwr_oe3, pwr_oe4;
    input [7:0] adc_d;
    output adc_clk;
    input ssp_dout;
    output ssp_frame, ssp_din, ssp_clk;
    input cross_hi, cross_lo;
    output dbg;
    input [7:0] divisor;

reg [7:0] pck_divider;
reg ant_lo;

// this task runs on the rising egde of pck0 clock (24Mhz) and creates ant_lo
// which is high for (divisor+1) pck0 cycles and low for the same duration
// ant_lo is therefore a 50% duty cycle clock signal with a frequency of
// 12Mhz/(divisor+1) which drives the antenna as well as the ADC clock adc_clk
always @(posedge pck0)
begin
	if(pck_divider == divisor[7:0])
		begin
			pck_divider <= 8'd0;
			ant_lo = !ant_lo;
		end
	else
	begin
		pck_divider <= pck_divider + 1;
	end
end

// the antenna is modulated when ssp_dout = 1, when 0 the
// antenna drivers stop modulating and go into listen mode
assign pwr_oe3 = 1'b0;
assign pwr_oe1 = ssp_dout;
assign pwr_oe2 = ssp_dout;
assign pwr_oe4 = ssp_dout;
assign pwr_lo = ant_lo && ssp_dout;
assign pwr_hi = 1'b0;
assign adc_clk = 1'b0;
assign ssp_din = cross_lo;
assign dbg = cross_lo;

endmodule
