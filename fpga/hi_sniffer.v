
module hi_sniffer(
    pck0, ck_1356meg, ck_1356megb,
    pwr_lo, pwr_hi, pwr_oe1, pwr_oe2, pwr_oe3, pwr_oe4,
    adc_d, adc_clk,
    ssp_frame, ssp_din, ssp_dout, ssp_clk,
    cross_hi, cross_lo,
    dbg,
    xcorr_is_848, snoop, xcorr_quarter_freq // not used.
);
    input pck0, ck_1356meg, ck_1356megb;
    output pwr_lo, pwr_hi, pwr_oe1, pwr_oe2, pwr_oe3, pwr_oe4;
    input [7:0] adc_d;
    output adc_clk;
    input ssp_dout;
    output ssp_frame, ssp_din, ssp_clk;
    input cross_hi, cross_lo;
    output dbg;
    input xcorr_is_848, snoop, xcorr_quarter_freq; // not used.

// We are only snooping, all off.
assign pwr_hi  = 1'b0;// ck_1356megb & (~snoop);
assign pwr_oe1 = 1'b0;
assign pwr_oe2 = 1'b0;
assign pwr_oe3 = 1'b0;
assign pwr_oe4 = 1'b0;

reg ssp_clk = 1'b0;
reg ssp_frame;
reg adc_clk;
reg [7:0] adc_d_out = 8'd0;
reg [7:0] ssp_cnt = 8'd0;
reg [7:0] pck_divider = 8'd0;
reg ant_lo = 1'b0;
reg bit_to_send = 1'b0;

always @(ck_1356meg, pck0) // should synthetisize to a mux..
  begin
    adc_clk = ck_1356meg;
    ssp_clk = ~ck_1356meg;
  end

reg [7:0] cnt_test = 8'd0; // test

always @(posedge pck0)
begin
    ant_lo <= 1'b0;
end

always @(posedge ssp_clk) // ~1356 (hf)
begin
  if(ssp_cnt[7:0] == 8'd255) // SSP counter for divides.
    ssp_cnt[7:0] <= 8'd0;
  else
    ssp_cnt <= ssp_cnt + 1;

      if((ssp_cnt[2:0] == 3'b000) && !ant_lo) // To set frame  length
        begin
          adc_d_out[7:0] = adc_d; // disable for test
          bit_to_send = adc_d_out[0];
          ssp_frame <= 1'b1;
        end
      else
        begin
          adc_d_out[6:0] = adc_d_out[7:1];
          adc_d_out[7] = 1'b0; // according to old lf_read.v comment prevents gliches if not set.
          bit_to_send = adc_d_out[0];
          ssp_frame <= 1'b0;
        end
end

assign ssp_din = bit_to_send && !ant_lo;//bit_to_send && !ant_lo; // && .. not needed i guess?

assign pwr_lo = ant_lo;
      

endmodule
