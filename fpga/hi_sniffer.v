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
assign pwr_hi  = 1'b0;
assign pwr_lo  = 1'b0;
assign pwr_oe1 = 1'b0;
assign pwr_oe2 = 1'b0;
assign pwr_oe3 = 1'b0;
assign pwr_oe4 = 1'b0;

reg ssp_frame;
reg [7:0] adc_d_out = 8'd0;
reg [2:0] ssp_cnt = 3'd0;

assign adc_clk = ck_1356meg;
assign ssp_clk = ~ck_1356meg;

always @(posedge ssp_clk)
begin
    if(ssp_cnt[2:0] == 3'd7)
        ssp_cnt[2:0] <= 3'd0;
    else
        ssp_cnt <= ssp_cnt + 1;

    if(ssp_cnt[2:0] == 3'b000) // set frame length
        begin
            adc_d_out[7:0] <= adc_d;
            ssp_frame <= 1'b1;
        end
    else
        begin
            adc_d_out[7:0] <= {1'b0, adc_d_out[7:1]};
            ssp_frame <= 1'b0;
        end

end

assign ssp_din = adc_d_out[0];

endmodule
