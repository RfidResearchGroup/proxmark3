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

reg [4:0] adc_cnt = 5'd0;
always @(negedge adc_clk)
begin
    adc_cnt <= adc_cnt + 1'd1;
end

reg [7:0] out1 = 8'd0;
reg [7:0] out2 = 8'd0;

reg [7:0] avg = 8'd0;
reg [7:0] avg1 = 8'd0;
reg [7:0] avg2 = 8'd0;
reg [7:0] avg3 = 8'd0;
reg [7:0] avg4 = 8'd0;
reg [7:0] avg5 = 8'd0;
reg [7:0] avg6 = 8'd0;
reg [7:0] avg7 = 8'd0;
reg [7:0] avg8 = 8'd0;
reg [7:0] avg9 = 8'd0;
reg [7:0] avg10 = 8'd0;
reg [7:0] avg11 = 8'd0;
reg [7:0] avg12 = 8'd0;
reg [7:0] avg13 = 8'd0;
reg [7:0] avg14 = 8'd0;
reg [7:0] avg15 = 8'd0;
reg [7:0] avg16 = 8'd0;

reg [7:0] diff28 = 8'd0;
reg [7:0] diff32 = 8'd0;
   
reg [11:0] match32 = 12'd0;
reg [11:0] match28 = 12'd0;
   
always @(negedge adc_clk)
begin
    if (adc_cnt[0] == 1'b0) // every 4 clock
    begin
        avg = adc_d[7:1];
    end
    else
    begin
        avg = avg + adc_d[7:1];
        if (adc_cnt[0] == 1'b1)  // every 4 clock
        begin
            if (avg > avg14)
                diff28 = avg - avg14;
            else
                diff28 = avg14 - avg;

            if (avg > avg16)
                diff32 = avg - avg16;
            else
                diff32 = avg16 - avg;

            avg16 = avg15;
            avg15 = avg14;
            avg14 = avg13;
            avg13 = avg12;
            avg12 = avg11;
            avg11 = avg10;
            avg10 = avg9;
            avg9 = avg8;
            avg8 = avg7;
            avg7 = avg6;
            avg6 = avg5;
            avg5 = avg4;
            avg4 = avg3;
            avg3 = avg2;
            avg2 = avg1;
            avg1 = avg;

            if (adc_cnt[4:1] == 4'b0000) // every 32 clock (8*4)
            begin
                match28 = diff28;
                match32 = diff32;
            end
            else
            begin
                match28 = match28 + diff28;
                match32 = match32 + diff32;

                if (adc_cnt[4:1] == 4'b1111) // every 32 clock (8*4)
                begin
                    if (match28[11:3] > 10'b0 || match32[11:3] > 10'b0) // if not only noise
                    begin
                        if (match28 < match32)
                        begin
                            //if (match32 - match28 < 12'd24)
                              //out1 = out1; // out1 stay at is old value
                            //else
                            if (match32 - match28 > 12'd32)
                                out1 = 8'd28;
                            else if (match32 - match28 < 12'd16)
                                out1 = 8'd0;
                        end
                        else //if (match32 <= match28)
                        begin
                            //if (match28 - match32 < 12'd24)
                                //out1 = 8'd30; // out1 stay at is old value
                            //else
                            if (match28 - match32 > 12'd32)
                                out1 = 8'd32;
                            else if (match28 - match32 < 12'd16)
                                out1 = 8'd0;
                        end
                    end
                    else
                    begin
                        out1 = 8'd0;
                        //out2 = match32[8:1];
                    end
                    //out1 = match28[7:0];
                    //out2 = match32[7:0];
                    //out2 = 8'hFF;
                   
                    //out2 = out1;
                   
                end
            end
        end
    end
end   
   
/*
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
*/
// Other version of FSK reader, probably better but not working yet...
/*reg [7:0] out1 = 8'd0;
//reg [7:0] old = 8'd0;
reg [5:0] old1 = 4'd0;
reg [5:0] old2 = 4'd0;
//reg [7:0] edge_id = 8'd0;
//reg edge_started = 1'd0;
reg [5:0] edge_cnt = 6'd0;
reg [3:0] last_values = 4'd0;

// Count clock edge between two signal edges
always @(negedge adc_clk)
begin
    edge_cnt <= edge_cnt + 1'd1;

    last_values[3:1] <= last_values[2:0];
//    last_values[0] <= (& adc_d[7:5]); // adc_d >= 192

    last_values[0] <= (adc_d[7:2] > old1 && old1 > old2);


    //out1[7:4] <= out1[3:0];
    //out1[3:0] <= last_values;
    //out1 <= 8'd28;
    //out1 <= out1+1;

    if (edge_cnt > 6'd22 || out1 == 8'd0)
    begin
        if ((last_values[3:2] == 2'b0) && (last_values[1:0] == 2'b11)) // edge start detected
        begin // 2 not high (low or mid) values followed by 2 high values
            out1 <= edge_cnt;
            edge_cnt <= 6'd0;
        end
        else if (edge_cnt > 6'd44) // average(32, 2*28) == 44 : ideal value for iso15 FSK
        begin // /!\ MIN FREQ SUPPORTED = 13MHz/44 ~= 308kHz /!\
            out1 <= 8'd0;
            edge_cnt <= 6'd0;
        end
    end

    old2 <= old1;
    old1 <= adc_d[7:2];

    /*if (last_values[0])
        out1 <= 8'h7F;
    else if (last_values[1])
        out1 <= 8'hFF;
    else
        out1 <= 8'h0;

   /*

    if (& adc_d[7:5] && !(& old[7:5])) // up
    begin
        if (edge_started == 1'd0) // new edge starting
        begin
            //if (edge_id <= edge_cnt)
            //    out1 <= edge_cnt - edge_id;
            //else
            //    out1 <= edge_cnt + (9'h100 - edge_id);
            out1 <= edge_cnt;
            //edge_id <= edge_cnt;
            edge_started = 1'd1;
            edge_cnt <= 8'd0;
        end
    end
    else
    begin
        edge_started = 1'd0;
        if (edge_cnt > 8'd80)
        begin
            out1 <= 8'd0;
            //edge_id <= 8'd0;
            edge_cnt <= 8'd0;
        end
*//*        if (edge_id <= edge_cnt) // NO EDGE
        begin
            if (edge_cnt - edge_id > 8'd40)
            begin
                out1 <= 8'd0;
                edge_id <= 8'd0;
                edge_cnt <= 8'd0;
            end
        end
        else
        begin
            if (edge_cnt + (9'h100 - edge_id) > 8'd40) // NO EDGE
            begin
                out1 <= 8'd0;
                edge_id <= 8'd0;
                edge_cnt <= 8'd0;
            end
        end*//*
    //end

    //old <= adc_d;
end*/

// agregate out values (depending on selected output frequency)
/*reg [10:0] out_tmp = 11'd0;
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

//    if (adc_cnt > 8'd192 && edge_id < 8'd64) // WUT ?
//    begin
//        out <= 8'd0;
//        out_tmp <= 11'd0;
//    end
end
*/
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
reg [379:0] megatmpout = 380'd0;
   
reg ssp_frame;
reg [7:0] ssp_out = 8'd0;
reg [3:0] ssp_cnt = 4'd0;
always @(posedge ssp_clk)
begin
    ssp_cnt <= ssp_cnt + 1'd1;
    if (ssp_cnt[2:0] == 3'd7)
    begin
        ssp_out = {2'b0, megatmpout[379:378], megatmpout[378], megatmpout[378], 2'b0};
        megatmpout[379:2] = megatmpout[377:0];
        megatmpout[1:0] = out2[5:4];
        out2 = out1;

        ssp_frame <= 1'b1;
    end
    else
    begin
        ssp_out = {ssp_out[6:0], 1'b0};
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

