//-----------------------------------------------------------------------------
// The way that we connect things in low-frequency read mode. In this case
// we are generating the unmodulated low frequency carrier.
// The A/D samples at that same rate and the result is serialized.
//
// Jonathan Westhues, April 2006
// iZsh <izsh at fail0verflow.com>, June 2014
//-----------------------------------------------------------------------------

module lo_read(
    input pck0, input [7:0] pck_cnt, input pck_divclk,
    output pwr_lo, output pwr_hi,
    output pwr_oe1, output pwr_oe2, output pwr_oe3, output pwr_oe4,
    input [7:0] adc_d, output adc_clk,
    output ssp_frame, output ssp_din, output ssp_clk,
    output dbg,
    input lf_field
);

reg [7:0] to_arm_shiftreg;

// this task also runs at pck0 frequency (24MHz) and is used to serialize
// the ADC output which is then clocked into the ARM SSP.

// because pck_divclk always transitions when pck_cnt = 0 we use the
// pck_div counter to sync our other signals off it
// we read the ADC value when pck_cnt=7 and shift it out on counts 8..15
always @(posedge pck0)
begin
    if((pck_cnt == 8'd7) && !pck_divclk)
        to_arm_shiftreg <= adc_d;
    else begin
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
assign ssp_din = to_arm_shiftreg[7] && !pck_divclk;
// SSP clock always runs at 24MHz
assign ssp_clk = pck0;
// SSP frame is gated by ant_lo and goes high when pck_divider=8..15
assign ssp_frame = (pck_cnt[7:3] == 5'd1) && !pck_divclk;
// unused signals tied low
assign pwr_hi = 1'b0;
assign pwr_oe1 = 1'b0;
assign pwr_oe2 = 1'b0;
assign pwr_oe3 = 1'b0;
assign pwr_oe4 = 1'b0;
// this is the antenna driver signal
assign pwr_lo = lf_field & pck_divclk;
// ADC clock out of phase with antenna driver
assign adc_clk = ~pck_divclk;
// ADC clock also routed to debug pin
assign dbg = adc_clk;
endmodule
