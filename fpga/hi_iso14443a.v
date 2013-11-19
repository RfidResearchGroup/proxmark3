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
	if(& adc_d[7:6]) after_hysteresis <= 1'b1;			// if adc_d >= 196 
    else if(~(| adc_d[7:4])) after_hysteresis <= 1'b0;  // if adc_d <= 15
	
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
// wire [7:0] avg;
// reg [7:0] lavg;
// reg signed [12:0] step1;
// reg signed [12:0] step2;
// reg [7:0] stepsize;
reg [7:0] rx_mod_edge_threshold;
reg curbit;
// reg [12:0] average;
// wire signed [9:0] dif;

// storage for two previous samples:
reg [7:0] adc_d_1;
reg [7:0] adc_d_2;
reg [7:0] adc_d_3;
reg [7:0] adc_d_4;

// the filtered signal (filter performs noise reduction and edge detection)
// (gaussian derivative)
wire signed [10:0] adc_d_filtered;
assign adc_d_filtered = (adc_d_4 << 1) + adc_d_3 - adc_d_1 - (adc_d << 1);

// Registers to store steepest edges detected:
reg [7:0] rx_mod_falling_edge_max;
reg [7:0] rx_mod_rising_edge_max;

// A register to send the results to the arm
reg signed [7:0] to_arm;


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
	// ------------------------------------------------------------------------------------------------------------------------------------------------------------------
	// relevant for TAGSIM_MOD only. Timing of Tag's answer to a command received from a reader
	// ISO14443-3 specifies:
	// fdt = 1172, if last bit was 0.
	// fdt = 1236, if last bit was 1.
	// the FPGA takes care for the 1172 delay. To achieve the additional 1236-1172=64 ticks delay, the ARM must send an additional correction bit (before the start bit).
	// The correction bit will be coded as 00010000, i.e. it adds 4 bits to the transmission stream, causing the required delay.
	if(fdt_counter == 11'd740) fdt_indicator = 1'b1; 	// fdt_indicator is true for 740 <= fdt_counter <= 1148. Ready to buffer data. (?) 
														// Shouldn' this be 1236 - 720 = 516? (The mod_sig_buf can buffer 46 data bits, 
														// i.e. a maximum delay of 46 * 16 = 720 adc_clk ticks)
	
	if(fdt_counter == 11'd1148) // additional 16 (+ eventual n*128) adc_clk_ticks delay will be added by the mod_sig_buf below
								// the remaining 8 ticks delay comes from the 8 ticks timing difference between reseting fdt_counter and the mod_sig_buf clock.
	begin
		if(fdt_elapsed)
		begin
			if(negedge_cnt[3:0] == mod_sig_flip[3:0]) mod_sig_coil <= mod_sig; // start modulating (if mod_sig is already set) 
		end
		else
		begin
			mod_sig_flip[3:0] <= negedge_cnt[3:0];		// exact timing of modulation
			mod_sig_coil <= mod_sig;					// modulate (if mod_sig is already set)
			fdt_elapsed = 1'b1;
			fdt_indicator = 1'b0;

			if(~(| mod_sig_ptr[5:0])) mod_sig_ptr <= 6'b001001;  	// didn't receive a 1 yet. Delay next 1 by n*128 ticks.
			else temp_buffer_reset = 1'b1; 							// else fix the buffer size at current position
		end
	end
	else
	begin
		fdt_counter <= fdt_counter + 1; // Count until 1148
	end
	
	
	//-------------------------------------------------------------------------------------------------------------------------------------------
	// Relevant for READER_LISTEN only
	// look for steepest falling and rising edges:
	if (adc_d_filtered > 0)
		begin
		if (adc_d_filtered > rx_mod_falling_edge_max)
			rx_mod_falling_edge_max <= adc_d_filtered;
		end
	else
		begin
		if (-adc_d_filtered > rx_mod_rising_edge_max)
			rx_mod_rising_edge_max <= -adc_d_filtered;
		end
		
	// store previous samples for filtering and edge detection:
	adc_d_4 <= adc_d_3;
	adc_d_3 <= adc_d_2;
	adc_d_2 <= adc_d_1;
	adc_d_1 <= adc_d;

		

	if(& negedge_cnt[3:0])  // == 0xf == 15
	begin
		// Relevant for TAGSIM_MOD only (timing Tag's answer. See above)
		// When there is a dip in the signal and not in (READER_MOD, READER_LISTEN, TAGSIM_MOD)
		if(~after_hysteresis && mod_sig_buf_empty && ~((mod_type == 3'b100) || (mod_type == 3'b011) || (mod_type == 3'b010))) // last condition to prevent reset
		begin
			fdt_counter <= 11'd0;
			fdt_elapsed = 1'b0;
			fdt_indicator = 1'b0;
			temp_buffer_reset = 1'b0;
			mod_sig_ptr <= 6'b000000;
		end
		
		// Relevant for READER_LISTEN only
		// detect modulation signal: if modulating, there must be a falling and a rising edge ... and vice versa
		if (rx_mod_falling_edge_max > 6 && rx_mod_rising_edge_max > 6)
				curbit = 1'b1;	// modulation
			else
				curbit = 1'b0;	// no modulation
				
		// prepare next edge detection:
		rx_mod_rising_edge_max <= 0;
		rx_mod_falling_edge_max <= 0;
	
	
		// What do we communicate to the ARM
		if(mod_type == 3'b001) sendbit = after_hysteresis;		// TAGSIM_LISTEN
		else if(mod_type == 3'b010)								// TAGSIM_MOD
		begin
			if(fdt_counter > 11'd772) sendbit = mod_sig_coil;
			else sendbit = fdt_indicator;
		end
		else if(mod_type == 3'b011) sendbit = curbit;			// READER_LISTEN
		else sendbit = 1'b0;									// READER_MOD, SNIFFER

	end

	//------------------------------------------------------------------------------------------------------------------------------------------
	// Relevant for SNIFFER mode only. Prepare communication to ARM.
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
	
	//--------------------------------------------------------------------------------------------------------------------------------------------------------------
	// Relevant in TAGSIM_MOD only. Delay-Line to buffer data and send it at the correct time
	// Note: Data in READER_MOD is fed through this delay line as well.
	if(mod_type != 3'b000)			// != SNIFFER
	begin
		if(negedge_cnt[3:0] == 4'b1000) // == 0x8
		begin
			// The modulation signal of the tag. The delay line is only relevant for TAGSIM_MOD, but used in other modes as well.
			// Note: this means that even in READER_MOD, there will be an arbitrary delay depending on the time of a previous reset of fdt_counter and the time and
			// content of the next bit to be transmitted.
			mod_sig_buf[47:0] <= {mod_sig_buf[46:1], ssp_dout, 1'b0};  			// shift in new data starting at mod_sig_buf[1]. mod_sig_buf[0] = 0 always.
			if((ssp_dout || (| mod_sig_ptr[5:0])) && ~fdt_elapsed)				// buffer a 1 (and all subsequent data) until fdt_counter = 1148 adc_clk ticks.
				if(mod_sig_ptr == 6'b101110)									// buffer overflow at 46 - this would mean data loss
				begin
					mod_sig_ptr <= 6'b000000;
				end
				else mod_sig_ptr <= mod_sig_ptr + 1;							// increase buffer (= increase delay by 16 adc_clk ticks). ptr always points to first 1.
			else if(fdt_elapsed && ~temp_buffer_reset)							
			// fdt_elapsed. If we didn't receive a 1 yet, ptr will be at 9 and not yet fixed. Otherwise temp_buffer_reset will be 1 already.
			begin
				// wait for the next 1 after fdt_elapsed before fixing the delay and starting modulation. This ensures that the response can only happen
				// at intervals of 8 * 16 = 128 adc_clk ticks intervals (as defined in ISO14443-3)
				if(ssp_dout) temp_buffer_reset = 1'b1;							
				if(mod_sig_ptr == 6'b000010) mod_sig_ptr <= 6'b001001;			// still nothing received, need to go for the next interval
				else mod_sig_ptr <= mod_sig_ptr - 1;							// decrease buffer.
			end
			else
			// mod_sig_ptr and therefore the delay is now fixed until fdt_counter is reset (this can happen in SNIFFER and TAGSIM_LISTEN mode only. Note that SNIFFER
			// mode (3'b000) is the default and is active in FPGA_MAJOR_MODE_OFF if no other minor mode is explicitly requested.
			begin
				// don't modulate with the correction bit (which is sent as 00010000, all other bits will come with at least 2 consecutive 1s)
				// side effect: when ptr = 1 it will cancel the first 1 of every block of ones. Note: this would only be the case if we received a 1 just before fdt_elapsed.
				if(~mod_sig_buf[mod_sig_ptr-1] && ~mod_sig_buf[mod_sig_ptr+1]) mod_sig = 1'b0;
				// finally, do the modulation:
				else mod_sig = mod_sig_buf[mod_sig_ptr] & fdt_elapsed;
			end
		end
	end
	
	//-----------------------------------------------------------------------------------------------------------------------------------------------------------------------
	// Communication to ARM (SSP Clock and data)
	// SNIFFER mode (ssp_clk = adc_clk / 8, ssp_frame clock = adc_clk / 64)):
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
	//-----------------------------------------------------------------------------------------------------------------------------------------------------------------------
	// Communication to ARM (SSP Clock and data)
	// all other modes (ssp_clk = adc_clk / 16, ssp_frame clock = adc_clk / 128):
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


// Modulating carrier (adc_clk/16, for TAGSIM_MOD only). Will be 0 for other modes.
wire modulating_carrier;
assign modulating_carrier = (mod_sig_coil & negedge_cnt[3] & (mod_type == 3'b010));					// in TAGSIM_MOD only. Otherwise always 0.

// for READER_MOD only: drop carrier for mod_sig_coil==1 (pause), READER_LISTEN: carrier always on, others: carrier always off
assign pwr_hi = (ck_1356megb & (((mod_type == 3'b100) & ~mod_sig_coil) || (mod_type == 3'b011)));	


// Enable HF antenna drivers:
assign pwr_oe1 = 1'b0;
assign pwr_oe3 = 1'b0;

// TAGSIM_MOD: short circuit antenna with different resistances (modulated by modulating_carrier)
// for pwr_oe4 = 1 (tristate): antenna load = 10k || 33			= 32,9 Ohms
// for pwr_oe4 = 0 (active):   antenna load = 10k || 33 || 33  	= 16,5 Ohms
assign pwr_oe4 = modulating_carrier;

// This is all LF, so doesn't matter.
assign pwr_oe2 = 1'b0;
assign pwr_lo = 1'b0;


assign dbg = negedge_cnt[3];

endmodule
