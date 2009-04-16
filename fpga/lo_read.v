//-----------------------------------------------------------------------------
// The way that we connect things in low-frequency read mode. In this case
// we are generating the unmodulated low frequency carrier.
// The A/D samples at that same rate and the result is serialized.
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
    input lo_is_125khz; // redundant signal, no longer used anywhere
    input [7:0] divisor;

reg [7:0] to_arm_shiftreg;
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

// this task also runs at pck0 frequency (24Mhz) and is used to serialize
// the ADC output which is then clocked into the ARM SSP.

// because ant_lo always transitions when pck_divider = 0 we use the
// pck_divider counter to sync our other signals off it
// we read the ADC value when pck_divider=7 and shift it out on counts 8..15
always @(posedge pck0)
begin
	if((pck_divider == 8'd7) && !ant_lo)
        to_arm_shiftreg <= adc_d;
    else
	begin
        to_arm_shiftreg[7:1] <= to_arm_shiftreg[6:0];
		// simulation showed a glitch occuring due to the LSB of the shifter
		// not being set as we shift bits out
		// this ensures the ssp_din remains low after a transfer and suppresses
		// the glitch that would occur when the last data shifted out ended in
		// a 1 bit and the next data shifted out started with a 0 bit
        to_arm_shiftreg[0] <= 1'b0;
	end
end

// ADC samples on falling edge of adc_clk, data available on the rising edge

// example of ssp transfer of binary value 1100101
// start of transfer is indicated by the rise of the ssp_frame signal
// ssp_din changes on the rising edge of the ssp_clk clock and is clocked into
// the ARM by the falling edge of ssp_clk
//             _______________________________
// ssp_frame__|                               |__
//             _______         ___     ___
// ssp_din  __|       |_______|   |___|   |______
//         _   _   _   _   _   _   _   _   _   _
// ssp_clk  |_| |_| |_| |_| |_| |_| |_| |_| |_| |_

// serialized SSP data is gated by ant_lo to suppress unwanted signal
assign ssp_din = to_arm_shiftreg[7] && !ant_lo;
// SSP clock always runs at 24Mhz
assign ssp_clk = pck0;
// SSP frame is gated by ant_lo and goes high when pck_divider=8..15
assign ssp_frame = (pck_divider[7:3] == 5'd1) && !ant_lo;
// unused signals tied low
assign pwr_hi = 1'b0;
assign pwr_oe1 = 1'b0;
assign pwr_oe2 = 1'b0;
assign pwr_oe3 = 1'b0;
assign pwr_oe4 = 1'b0;
// this is the antenna driver signal
assign pwr_lo = ant_lo;
// ADC clock out of phase with antenna driver
assign adc_clk = ~ant_lo;
// ADC clock also routed to debug pin
assign dbg = adc_clk;
endmodule
