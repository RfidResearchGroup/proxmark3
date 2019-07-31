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
    cross_hi, cross_lo,
    dbg, divisor,
    lo_is_125khz, lf_field
);
    input pck0;
    output pwr_lo, pwr_hi, pwr_oe1, pwr_oe2, pwr_oe3, pwr_oe4;
    input [7:0] adc_d;
    output adc_clk;
    input ssp_dout;
    output ssp_frame, ssp_din, ssp_clk;
    input cross_hi, cross_lo;
    output dbg;
    input [7:0] divisor;
    input lo_is_125khz; // redundant signal, no longer used anywhere
    input lf_field;

reg [7:0] to_arm_shiftreg;
reg [7:0] pck_divider;
reg clk_state;

// Antenna logic, depending on "lf_field" (in arm defined as FPGA_LF_READER_FIELD)
wire tag_modulation; 
assign tag_modulation = ssp_dout & !lf_field;
wire reader_modulation; 
assign reader_modulation = !ssp_dout & lf_field & clk_state;
assign pwr_oe1 = 1'b0; // not used in LF mode
assign pwr_oe2 = 1'b0; //tag_modulation;
assign pwr_oe3 = tag_modulation;
assign pwr_oe4 = 1'b0; //tag_modulation;
assign pwr_lo = reader_modulation;
assign pwr_hi = 1'b0;
assign dbg = adc_clk;

// ADC clock out of phase with antenna driver
assign adc_clk = ~clk_state;
// serialized SSP data is gated by clk_state to suppress unwanted signal
assign ssp_din = to_arm_shiftreg[7] && !clk_state;
// SSP clock always runs at 24Mhz
assign ssp_clk = pck0;
// SSP frame is gated by clk_state and goes high when pck_divider=8..15
assign ssp_frame = (pck_divider[7:3] == 5'd1) && !clk_state;

always @(posedge pck0)
begin
	if(pck_divider == divisor[7:0])
  begin
		pck_divider <= 8'd0;
		clk_state = !clk_state;
  end
	else
	begin
		pck_divider <= pck_divider + 1;
	end
end

always @(posedge pck0)
begin
	if((pck_divider == 8'd7) && !clk_state)
  begin
      to_arm_shiftreg <= adc_d;
  end
  else
	begin
    to_arm_shiftreg[7:1] <= to_arm_shiftreg[6:0];
    to_arm_shiftreg[0] <= 1'b0;
	end
end

endmodule
