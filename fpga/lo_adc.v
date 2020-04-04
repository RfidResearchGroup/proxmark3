//-----------------------------------------------------------------------------
// The way that we connect things in low-frequency simulation mode. In this
// case just pass everything through to the ARM, which can bit-bang this
// (because it is so slow).
//
// Jonathan Westhues, April 2006
//-----------------------------------------------------------------------------

module lo_adc(
    pck0,
    pwr_lo, pwr_hi, pwr_oe1, pwr_oe2, pwr_oe3, pwr_oe4,
    adc_d, adc_clk,
    ssp_frame, ssp_din, ssp_dout, ssp_clk,
    dbg, divisor,
    lf_field
);
    input pck0;
    output pwr_lo, pwr_hi, pwr_oe1, pwr_oe2, pwr_oe3, pwr_oe4;
    input [7:0] adc_d;
    output adc_clk;
    input ssp_dout;
    output ssp_frame, ssp_din, ssp_clk;
    output dbg;
    input [7:0] divisor;
    input lf_field;

reg [7:0] to_arm_shiftreg;
reg [7:0] pck_divider;
reg clk_state;

// Antenna logic, depending on "lf_field" (in arm defined as FPGA_LF_READER_FIELD)
wire tag_modulation = ssp_dout & !lf_field;
wire reader_modulation = !ssp_dout & lf_field & clk_state;

// always on (High Frequency outputs, unused)
assign pwr_oe1 = 1'b0;
assign pwr_hi = 1'b0;

// low frequency outputs
assign pwr_lo = reader_modulation;
assign pwr_oe2 = 1'b0;  // 33 Ohms
assign pwr_oe3 = tag_modulation; // base antenna load = 33 Ohms
assign pwr_oe4 = 1'b0;  // 10k Ohms

// Debug Output ADC clock
assign dbg = adc_clk;

// ADC clock out of phase with antenna driver
assign adc_clk = ~clk_state;

// serialized SSP data is gated by clk_state to suppress unwanted signal
assign ssp_din = to_arm_shiftreg[7] && !clk_state;

// SSP clock always runs at 24MHz
assign ssp_clk = pck0;

// SSP frame is gated by clk_state and goes high when pck_divider=8..15
assign ssp_frame = (pck_divider[7:3] == 5'd1) && !clk_state;

// divide 24mhz down to 3mhz
always @(posedge pck0)
begin
    if (pck_divider == divisor[7:0])
  begin
        pck_divider <= 8'd0;
        clk_state = !clk_state;
  end
    else
    begin
        pck_divider <= pck_divider + 1;
    end
end

// this task also runs at pck0 frequency (24Mhz) and is used to serialize
// the ADC output which is then clocked into the ARM SSP.
always @(posedge pck0)
begin
    if ((pck_divider == 8'd7) && !clk_state)
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

endmodule
