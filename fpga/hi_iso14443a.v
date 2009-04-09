//-----------------------------------------------------------------------------
// ISO14443-A support for the Proxmark III
// Gerhard de Koning Gans, April 2008
//-----------------------------------------------------------------------------

module hi_iso14443a(
    pck0, ck_1356meg, ck_1356megb,
    pwr_lo, pwr_hi, pwr_oe1, pwr_oe2, pwr_oe3, pwr_oe4,
    adc_d, adc_clk,
    ssp_frame, ssp_din, ssp_dout, ssp_clk,
    cross_hi, cross_lo,
    dbg,
    mod_type
);
    input pck0, ck_1356meg, ck_1356megb;
    output pwr_lo, pwr_hi, pwr_oe1, pwr_oe2, pwr_oe3, pwr_oe4;
    input [7:0] adc_d;
    output adc_clk;
    input ssp_dout;
    output ssp_frame, ssp_din, ssp_clk;
    input cross_hi, cross_lo;
    output dbg;
    input [2:0] mod_type;

reg ssp_clk;
reg ssp_frame;

reg fc_div_2;
always @(posedge ck_1356meg)
    fc_div_2 = ~fc_div_2;

wire adc_clk;
assign adc_clk = ck_1356meg;

reg after_hysteresis, after_hysteresis_prev1, after_hysteresis_prev2, after_hysteresis_prev3;
reg [11:0] has_been_low_for;
reg [8:0] saw_deep_modulation;
reg [2:0] deep_counter;
reg deep_modulation;
always @(negedge adc_clk)
begin
	if(& adc_d[7:6]) after_hysteresis <= 1'b1;
    else if(~(| adc_d[7:4])) after_hysteresis <= 1'b0;
	
	if(~(| adc_d[7:0]))
	begin
		if(deep_counter == 3'd7)
		begin
			deep_modulation <= 1'b1;
			saw_deep_modulation <= 8'd0;
		end
		else
			deep_counter <= deep_counter + 1;
	end
	else
	begin
		deep_counter <= 3'd0;
		if(saw_deep_modulation == 8'd255)
			deep_modulation <= 1'b0;
		else
			saw_deep_modulation <= saw_deep_modulation + 1;
	end
	
	if(after_hysteresis)
    begin
        has_been_low_for <= 7'b0;
    end
    else
    begin
        if(has_been_low_for == 12'd4095)
        begin
            has_been_low_for <= 12'd0;
            after_hysteresis <= 1'b1;
        end
        else
            has_been_low_for <= has_been_low_for + 1;
    end
end

// Report every 4 subcarrier cycles
// 64 periods of carrier frequency => 6-bit counter [negedge_cnt]
reg [5:0] negedge_cnt;
reg bit1, bit2, bit3;
reg [3:0] count_ones;
reg [3:0] count_zeros;
wire [7:0] avg;
reg [7:0] lavg;
reg signed [12:0] step1;
reg signed [12:0] step2;
reg [7:0] stepsize;
reg curbit;
reg [12:0] average;
wire signed [9:0] dif;

// A register to send the results to the arm
reg signed [7:0] to_arm;

assign avg[7:0] = average[11:4];
assign dif = lavg - avg;

reg bit_to_arm;
reg fdt_indicator, fdt_elapsed;
reg [10:0] fdt_counter;
reg [47:0] mod_sig_buf;
wire mod_sig_buf_empty;
reg [5:0] mod_sig_ptr;
reg [3:0] mod_sig_flip;
reg mod_sig, mod_sig_coil;
reg temp_buffer_reset;
reg sendbit;

assign mod_sig_buf_empty = ~(|mod_sig_buf[47:0]);
reg [2:0] ssp_frame_counter;

// ADC data appears on the rising edge, so sample it on the falling edge
always @(negedge adc_clk)
begin

	// last bit = 0 then fdt = 1172, in case of 0x26 (7-bit command, LSB first!)
	// last bit = 1 then fdt = 1236, in case of 0x52 (7-bit command, LSB first!)
	if(fdt_counter == 11'd740) fdt_indicator = 1'b1;
	
	if(fdt_counter == 11'd1148)
	begin
		if(fdt_elapsed)
		begin
			if(negedge_cnt[3:0] == mod_sig_flip[3:0]) mod_sig_coil <= mod_sig;
		end
		else
		begin
			mod_sig_flip[3:0] <= negedge_cnt[3:0];
			mod_sig_coil <= mod_sig;
			fdt_elapsed = 1'b1;
			fdt_indicator = 1'b0;

			if(~(| mod_sig_ptr[5:0])) mod_sig_ptr <= 6'b001001;
			else temp_buffer_reset = 1'b1; // fix position of the buffer pointer
		end
	end
	else
	begin
		fdt_counter <= fdt_counter + 1;
	end
	
	if(& negedge_cnt[3:0])
	begin
		// When there is a dip in the signal and not in reader mode
		if(~after_hysteresis && mod_sig_buf_empty && ~((mod_type == 3'b100) || (mod_type == 3'b011) || (mod_type == 3'b010))) // last condition to prevent reset
		begin
			fdt_counter <= 11'd0;
			fdt_elapsed = 1'b0;
			fdt_indicator = 1'b0;
			temp_buffer_reset = 1'b0;
			mod_sig_ptr <= 6'b000000;
		end
		
		lavg <= avg;
		
		if(stepsize<16) stepsize = 8'd16;

		if(dif>0)
		begin
			step1 = dif*3;
			step2 = stepsize*2; // 3:2
			if(step1>step2)
			begin
				curbit = 1'b0;
				stepsize = dif;
			end
		end
		else
		begin
			step1 = dif*3;
			step1 = -step1;
			step2 = stepsize*2;
			if(step1>step2)
			begin
				curbit = 1'b1;
				stepsize = -dif;
			end
		end
		
		if(curbit)
		begin
			count_zeros <= 4'd0;
			if(& count_ones[3:2])
			begin
				curbit = 1'b0; // suppressed signal
				stepsize = 8'd24; // just a fine number
			end
			else
			begin
				count_ones <= count_ones + 1;
			end
		end
		else
		begin
			count_ones <= 4'd0;
			if(& count_zeros[3:0])
			begin
				stepsize = 8'd24;
			end
			else
			begin
				count_zeros <= count_zeros + 1;
			end
		end
		
		// What do we communicate to the ARM
		if(mod_type == 3'b001) sendbit = after_hysteresis;
		else if(mod_type == 3'b010)
		begin
			if(fdt_counter > 11'd772) sendbit = mod_sig_coil;
			else sendbit = fdt_indicator;
		end
		else if(mod_type == 3'b011) sendbit = curbit;
		else sendbit = 1'b0;

	end

	if(~(| negedge_cnt[3:0])) average <= adc_d;
	else average <= average + adc_d;

	if(negedge_cnt == 7'd63)
    begin
		if(deep_modulation)
		begin
			to_arm <= {after_hysteresis_prev1,after_hysteresis_prev2,after_hysteresis_prev3,after_hysteresis,1'b0,1'b0,1'b0,1'b0};
		end
		else
		begin
			to_arm <= {after_hysteresis_prev1,after_hysteresis_prev2,after_hysteresis_prev3,after_hysteresis,bit1,bit2,bit3,curbit};
		end

        negedge_cnt <= 0;
	
		end
    else
    begin
        negedge_cnt <= negedge_cnt + 1;
    end

    if(negedge_cnt == 6'd15)
	begin
        after_hysteresis_prev1 <= after_hysteresis;
		bit1 <= curbit;
	end
    if(negedge_cnt == 6'd31)
	begin
        after_hysteresis_prev2 <= after_hysteresis;
		bit2 <= curbit;
	end
    if(negedge_cnt == 6'd47)
	begin
        after_hysteresis_prev3 <= after_hysteresis;
		bit3 <= curbit;
	end
	

	if(mod_type != 3'b000)
	begin
		if(negedge_cnt[3:0] == 4'b1000)
		begin
			// The modulation signal of the tag
			mod_sig_buf[47:0] <= {mod_sig_buf[46:1], ssp_dout, 1'b0};
			if((ssp_dout || (| mod_sig_ptr[5:0])) && ~fdt_elapsed)
				if(mod_sig_ptr == 6'b101110)
				begin
					mod_sig_ptr <= 6'b000000;
				end
				else mod_sig_ptr <= mod_sig_ptr + 1;
			else if(fdt_elapsed && ~temp_buffer_reset)
			begin
				if(ssp_dout) temp_buffer_reset = 1'b1;
				if(mod_sig_ptr == 6'b000010) mod_sig_ptr <= 6'b001001;
				else mod_sig_ptr <= mod_sig_ptr - 1;
			end
			else
			begin
				// side effect: when ptr = 1 it will cancel the first 1 of every block of ones
				if(~mod_sig_buf[mod_sig_ptr-1] && ~mod_sig_buf[mod_sig_ptr+1]) mod_sig = 1'b0;
				else mod_sig = mod_sig_buf[mod_sig_ptr] & fdt_elapsed; // & fdt_elapsed  was for direct relay to oe4
			end
		end
	end
	
	// SSP Clock and data
	if(mod_type == 3'b000)
	begin
		if(negedge_cnt[2:0] == 3'b100)
			ssp_clk <= 1'b0;
			
		if(negedge_cnt[2:0] == 3'b000)
		begin
			ssp_clk <= 1'b1;
			// Don't shift if we just loaded new data, obviously.
			if(negedge_cnt != 7'd0)
			begin
				to_arm[7:1] <= to_arm[6:0];
			end
		end

		if(negedge_cnt[5:4] == 2'b00)
			ssp_frame = 1'b1;
		else
			ssp_frame = 1'b0;
		
		bit_to_arm = to_arm[7];
	end
	else
	begin
		if(negedge_cnt[3:0] == 4'b1000) ssp_clk <= 1'b0;

		if(negedge_cnt[3:0] == 4'b0111)
		begin
			if(ssp_frame_counter == 3'd7) ssp_frame_counter <= 3'd0;
			else ssp_frame_counter <= ssp_frame_counter + 1;
		end

		if(negedge_cnt[3:0] == 4'b0000)
		begin
			ssp_clk <= 1'b1;
		end
		
		ssp_frame = (ssp_frame_counter == 3'd7);
	
		bit_to_arm = sendbit;
	end
	
end

assign ssp_din = bit_to_arm;

// Modulating carrier frequency is fc/16
wire modulating_carrier;
assign modulating_carrier = (mod_sig_coil & negedge_cnt[3] & (mod_type == 3'b010));
assign pwr_hi = (ck_1356megb & (((mod_type == 3'b100) & ~mod_sig_coil) || (mod_type == 3'b011)));

// This one is all LF, so doesn't matter
//assign pwr_oe2 = modulating_carrier;
assign pwr_oe2 = 1'b0;

// Toggle only one of these, since we are already producing much deeper
// modulation than a real tag would.
//assign pwr_oe1 = modulating_carrier;
assign pwr_oe1 = 1'b0;
assign pwr_oe4 = modulating_carrier;
//assign pwr_oe4 = 1'b0;

// This one is always on, so that we can watch the carrier.
//assign pwr_oe3 = modulating_carrier;
assign pwr_oe3 = 1'b0;


assign dbg = negedge_cnt[3];

// Unused.
assign pwr_lo = 1'b0;

endmodule
