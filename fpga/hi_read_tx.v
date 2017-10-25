//-----------------------------------------------------------------------------
// The way that we connect things when transmitting a command to an ISO
// 15693 tag, using 100% modulation only for now.
//
// Jonathan Westhues, April 2006
//-----------------------------------------------------------------------------

module hi_read_tx(
    pck0, ck_1356meg, ck_1356megb,
    pwr_lo, pwr_hi, pwr_oe1, pwr_oe2, pwr_oe3, pwr_oe4,
    adc_d, adc_clk,
    ssp_frame, ssp_din, ssp_dout, ssp_clk,
    cross_hi, cross_lo,
    dbg,
    shallow_modulation
);
    input pck0, ck_1356meg, ck_1356megb;
    output pwr_lo, pwr_hi, pwr_oe1, pwr_oe2, pwr_oe3, pwr_oe4;
    input [7:0] adc_d;
    output adc_clk;
    input ssp_dout;
    output ssp_frame, ssp_din, ssp_clk;
    input cross_hi, cross_lo;
    output dbg;
    input shallow_modulation;

// low frequency outputs, not relevant
assign pwr_lo = 1'b0;
assign pwr_oe2 = 1'b0;
	
// The high-frequency stuff. For now, for testing, just bring out the carrier,
// and allow the ARM to modulate it over the SSP.
reg pwr_hi;
reg pwr_oe1;
reg pwr_oe3;
reg pwr_oe4;

always @(ck_1356megb or ssp_dout or shallow_modulation)
begin
    if(shallow_modulation)
    begin
        pwr_hi <= ck_1356megb;
        pwr_oe1 <= 1'b0;
        pwr_oe3 <= 1'b0;
        pwr_oe4 <= ~ssp_dout;
    end
    else
    begin
        pwr_hi <= ck_1356megb & ssp_dout;
        pwr_oe1 <= 1'b0;
        pwr_oe3 <= 1'b0;
        pwr_oe4 <= 1'b0;
    end
end


// Then just divide the 13.56 MHz clock down to produce appropriate clocks
// for the synchronous serial port.

reg [6:0] hi_div_by_128;

always @(posedge ck_1356meg)
    hi_div_by_128 <= hi_div_by_128 + 1;

assign ssp_clk = hi_div_by_128[6];

reg [2:0] hi_byte_div;

always @(negedge ssp_clk)
    hi_byte_div <= hi_byte_div + 1;

assign ssp_frame = (hi_byte_div == 3'b000);

// Implement a hysteresis to give out the received signal on
// ssp_din. Sample at fc.
assign adc_clk = ck_1356meg;

// ADC data appears on the rising edge, so sample it on the falling edge
reg after_hysteresis;
always @(negedge adc_clk)
begin
    if(& adc_d[7:0]) after_hysteresis <= 1'b1;
    else if(~(| adc_d[7:0])) after_hysteresis <= 1'b0;
end


assign ssp_din = after_hysteresis;

assign dbg = ssp_din;

endmodule
