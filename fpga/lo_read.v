//-----------------------------------------------------------------------------
// The way that we connect things in low-frequency read mode. In this case
// we are generating the 134 kHz or 125 kHz carrier, and running the
// unmodulated carrier at that frequency. The A/D samples at that same rate,
// and the result is serialized.
//
// Jonathan Westhues, April 2006
//-----------------------------------------------------------------------------

module lo_read(
    pck0, ck_1356meg, ck_1356megb,
    pwr_lo, pwr_hi, pwr_oe1, pwr_oe2, pwr_oe3, pwr_oe4,
    adc_d, adc_clk,
    ssp_frame, ssp_din, ssp_dout, ssp_clk,
    cross_hi, cross_lo,
    dbg,
    lo_is_125khz, divisor
);
    input pck0, ck_1356meg, ck_1356megb;
    output pwr_lo, pwr_hi, pwr_oe1, pwr_oe2, pwr_oe3, pwr_oe4;
    input [7:0] adc_d;
    output adc_clk;
    input ssp_dout;
    output ssp_frame, ssp_din, ssp_clk;
    input cross_hi, cross_lo;
    output dbg;
    input lo_is_125khz;
    input [7:0] divisor;

// The low-frequency RFID stuff. This is relatively simple, because most
// of the work happens on the ARM, and we just pass samples through. The
// PCK0 must be divided down to generate the A/D clock, and from there by
// a factor of 8 to generate the carrier (that we apply to the coil drivers).
//
// This is also where we decode the received synchronous serial port words,
// to determine how to drive the output enables.

// PCK0 will run at (PLL clock) / 4, or 24 MHz. That means that we can do
// 125 kHz by dividing by a further factor of (8*12*2), or ~134 kHz by
// dividing by a factor of (8*11*2) (for 136 kHz, ~2% error, tolerable).

reg [7:0] to_arm_shiftreg;
reg [7:0] pck_divider;
reg [6:0] ssp_divider;
reg ant_lo;

always @(posedge pck0)
begin
	if(pck_divider == 8'd0)
		begin
			pck_divider <= divisor[7:0];
			ant_lo = !ant_lo;
			if(ant_lo == 1'b0)
			begin
			    ssp_divider <= 7'b0011111;
				to_arm_shiftreg <= adc_d;
			end
		end
	else
	begin
		pck_divider <= pck_divider - 1;
		if(ssp_divider[6] == 1'b0)
		begin
			if (ssp_divider[1:0] == 1'b11) to_arm_shiftreg[7:1] <= to_arm_shiftreg[6:0];
			ssp_divider <= ssp_divider - 1;
		end
	end
end

assign ssp_din = to_arm_shiftreg[7];
assign ssp_clk = pck_divider[1];
assign ssp_frame = ~ssp_divider[5];
assign pwr_hi = 1'b0;
assign pwr_lo = ant_lo;
assign adc_clk = ~ant_lo;
assign dbg = adc_clk;
endmodule
