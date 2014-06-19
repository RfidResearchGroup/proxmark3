//-----------------------------------------------------------------------------
// The way that we connect things in low-frequency simulation mode. In this
// case just pass everything through to the ARM, which can bit-bang this
// (because it is so slow).
//
// Jonathan Westhues, April 2006
//-----------------------------------------------------------------------------

module lo_edge_detect(
	input pck0, input [7:0] pck_cnt, input pck_divclk,
	output pwr_lo, output pwr_hi,
	output pwr_oe1, output pwr_oe2, output pwr_oe3, output pwr_oe4,
	input [7:0] adc_d, output adc_clk,
	output ssp_frame, input ssp_dout, output ssp_clk,
	input cross_lo,
	output dbg,
	input lf_field
);

wire tag_modulation = ssp_dout & !lf_field;
wire reader_modulation = !ssp_dout & lf_field & pck_divclk;

// No logic, straight through.
assign pwr_oe1 = 1'b0; // not used in LF mode
assign pwr_oe2 = tag_modulation;
assign pwr_oe3 = tag_modulation;
assign pwr_oe4 = tag_modulation;
assign ssp_clk = cross_lo;
assign pwr_lo = reader_modulation;
assign pwr_hi = 1'b0;
assign dbg = ssp_frame;

assign adc_clk = ~pck_divclk;

// Toggle the output with hysteresis
//  Set to high if the ADC value is above 200
//  Set to low if the ADC value is below 64
reg is_high;
reg is_low;
reg output_state;

always @(posedge pck0)
begin
	if((pck_cnt == 8'd7) && !pck_divclk) begin
		is_high = (adc_d >= 8'd190);
		is_low = (adc_d <= 8'd70);
	end
end

always @(posedge is_high or posedge is_low)
begin
	if(is_high)
		output_state <= 1'd1;
	else if(is_low)
		output_state <= 1'd0;
end

assign ssp_frame = output_state;

endmodule

