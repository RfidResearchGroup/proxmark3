// lnv42, Jan 2020
// reworked && integrated to RRG in Fev 2022
// HF FSK reader (used for iso15 sniffing/reading)

// output is the frequence divider from 13,56 MHz

// (eg. for iso 15 two subcarriers mode (423,75 khz && 484,28 khz): it return 32 or 28)
// (423,75k = 13.56M / 32 and 484.28k = 13,56M / 28)

module hi_read_fsk(
    ck_1356meg,
    pwr_lo, pwr_hi, pwr_oe1, pwr_oe2, pwr_oe3, pwr_oe4,
    adc_d, adc_clk,
    ssp_frame, ssp_din, ssp_clk,
    subcarrier_frequency, minor_mode
);

    input ck_1356meg;
    output pwr_lo, pwr_hi, pwr_oe1, pwr_oe2, pwr_oe3, pwr_oe4;
    input [7:0] adc_d;
    output adc_clk;
    output ssp_frame, ssp_din, ssp_clk;
    input [1:0]subcarrier_frequency;
    input [3:0] minor_mode;

assign adc_clk = ck_1356meg;  // input sample frequency is 13,56 MHz

assign power = subcarrier_frequency[0];

// Carrier is  on if power is on, else is 0
reg pwr_hi;
always @(ck_1356meg)
begin
    if (power == `FPGA_HF_FSK_READER_WITHPOWER)
        pwr_hi <= ck_1356meg;
    else
        pwr_hi <= 'b0;
end

reg [7:0] adc_cnt = 8'd0;
reg [7:0] out1 = 8'd0;
reg [7:0] old = 8'd0;
reg [7:0] edge_id = 8'd0;
reg edge_started = 1'd0;
// Count clock edge between two signal edges
always @(negedge adc_clk)
begin
    adc_cnt <= adc_cnt + 1'd1;

    if (& adc_d[7:5] && !(& old[7:5])) // up
    begin
        if (edge_started == 1'd0) // new edge starting
        begin
            if (edge_id <= adc_cnt)
                out1 <= adc_cnt - edge_id;
            else
                out1 <= adc_cnt + 9'h100 - edge_id;
            edge_id <= adc_cnt;
            edge_started = 1'd1;
        end
    end
    else
    begin
        edge_started = 1'd0;
        if (edge_id <= adc_cnt)
        begin
            if (adc_cnt - edge_id > 8'd40)
            begin
                out1 <= 8'd0;
            end
        end
        else
        begin
            if (adc_cnt + 9'h100 - edge_id > 8'd40)
            begin
                out1 <= 8'd0;
            end
        end
    end

    old <= adc_d;
end

// agregate out values (depending on selected output frequency)
reg [10:0] out_tmp = 11'd0;
reg [7:0] out = 8'd0;
always @(negedge adc_clk)
begin
    out_tmp <= out_tmp + out1;
    if (minor_mode == `FPGA_HF_FSK_READER_OUTPUT_848_KHZ && adc_cnt[0] == 1'd0)
    begin // average on 2 values
        out <= out_tmp[8:1];
        out_tmp <= 12'd0;
    end
    else if (minor_mode == `FPGA_HF_FSK_READER_OUTPUT_424_KHZ && adc_cnt[1:0] == 2'd0)
    begin // average on 4 values
        out <= out_tmp[9:2];
        out_tmp <= 12'd0;
    end
    else if (minor_mode == `FPGA_HF_FSK_READER_OUTPUT_212_KHZ && adc_cnt[2:0] == 3'd0)
    begin // average on 8 values
        out <= out_tmp[10:3];
        out_tmp <= 12'd0;
    end
    else // 1695_KHZ
        out <= out1;
end

// Set output (ssp) clock
(* clock_signal = "yes" *) reg ssp_clk;
always @(ck_1356meg)
begin
    if (minor_mode == `FPGA_HF_FSK_READER_OUTPUT_1695_KHZ)
        ssp_clk <= ~ck_1356meg;
    else if (minor_mode == `FPGA_HF_FSK_READER_OUTPUT_848_KHZ)
        ssp_clk <= ~adc_cnt[0];
    else if (minor_mode == `FPGA_HF_FSK_READER_OUTPUT_424_KHZ)
        ssp_clk <= ~adc_cnt[1];
    else                                           // 212 KHz
        ssp_clk <= ~adc_cnt[2];
end

// Transmit output
reg ssp_frame;
reg [7:0] ssp_out = 8'd0;
reg [2:0] ssp_cnt = 4'd0;
always @(posedge ssp_clk)
begin
    ssp_cnt <= ssp_cnt + 1'd1;
    if(ssp_cnt == 3'd15)
    begin
        ssp_out <= out;
        ssp_frame <= 1'b1;
    end
    else
    begin
        ssp_out <= {ssp_out[6:0], 1'b0};
        ssp_frame <= 1'b0;
    end
end

assign ssp_din = ssp_out[7];

// Unused.
assign pwr_oe4 = 1'b0;
assign pwr_oe1 = 1'b0;
assign pwr_oe3 = 1'b0;
assign pwr_lo = 1'b0;
assign pwr_oe2 = 1'b0;

endmodule

