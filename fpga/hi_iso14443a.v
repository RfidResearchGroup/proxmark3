//-----------------------------------------------------------------------------
// ISO14443-A support for the Proxmark III
// Gerhard de Koning Gans, April 2008
//-----------------------------------------------------------------------------

// constants for the different modes:
`define SNIFFER			3'b000
`define TAGSIM_LISTEN	3'b001
`define TAGSIM_MOD		3'b010
`define READER_LISTEN	3'b011
`define READER_MOD		3'b100

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

wire adc_clk;
assign adc_clk = ck_1356meg;

reg after_hysteresis, pre_after_hysteresis, after_hysteresis_prev1, after_hysteresis_prev2, after_hysteresis_prev3, after_hysteresis_prev4;
reg [11:0] has_been_low_for;
reg [8:0] saw_deep_modulation;
reg [2:0] deep_counter;
reg deep_modulation;

always @(negedge adc_clk)
begin
	if(& adc_d[7:6]) after_hysteresis <= 1'b1;			// adc_d >= 196 (U >= 3,28V) -> after_hysteris = 1
    else if(~(| adc_d[7:4])) after_hysteresis <= 1'b0;  // if adc_d <= 15 (U <= 1,13V) -> after_hysteresis = 0

	pre_after_hysteresis <= after_hysteresis;
	
	if(~(| adc_d[7:0]))									// if adc_d == 0 (U <= 0,94V)
	begin
		if(deep_counter == 3'd7)						// adc_d == 0 for 7 adc_clk ticks -> deep_modulation (by reader)
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
		if(saw_deep_modulation == 8'd255)				// adc_d != 0 for 255 adc_clk ticks -> deep_modulation is over, now waiting for tag's response
			deep_modulation <= 1'b0;
		else
			saw_deep_modulation <= saw_deep_modulation + 1;
	end
	
	if(after_hysteresis)
    begin
        has_been_low_for <= 12'd0;
    end
    else
    begin
        if(has_been_low_for == 12'd4095)
        begin
            has_been_low_for <= 12'd0;
            after_hysteresis <= 1'b1;					// reset after_hysteresis to 1 if it had been 0 for 4096 cycles (no field)
        end
        else
		begin
            has_been_low_for <= has_been_low_for + 1;
		end	
    end
end



// Report every 4 subcarrier cycles
// 128 periods of carrier frequency => 7-bit counter [negedge_cnt]
reg [6:0] negedge_cnt;
reg bit1, bit2, bit3, bit4;
reg curbit;

// storage for four previous samples:
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

// A register to send 8 Bit results to the arm
reg [7:0] to_arm;


reg bit_to_arm;
reg fdt_indicator, fdt_elapsed;
reg [10:0] fdt_counter;
//reg [47:0] mod_sig_buf;
reg [31:0] mod_sig_buf;
//reg [5:0] mod_sig_ptr;
reg [4:0] mod_sig_ptr;
reg [3:0] mod_sig_flip;
reg mod_sig, mod_sig_coil;
reg temp_buffer_reset;
reg sendbit;
reg [3:0] sub_carrier_cnt;
reg[3:0] reader_falling_edge_time;

// ADC data appears on the rising edge, so sample it on the falling edge
always @(negedge adc_clk)
begin
	// ------------------------------------------------------------------------------------------------------------------------------------------------------------------
	// relevant for TAGSIM_MOD only. Timing of Tag's answer relative to a command received from a reader
	// ISO14443-3 specifies:
	// fdt = 1172, if last bit was 0.
	// fdt = 1236, if last bit was 1.
	// the FPGA takes care for the 1172 delay. To achieve the additional 1236-1172=64 ticks delay, the ARM must send an additional correction bit (before the start bit).
	// The correction bit will be coded as 00010000, i.e. it adds 4 bits to the transmission stream, causing the required delay.
	if(fdt_counter == 11'd547) fdt_indicator <= 1'b1; 	// The ARM must not send earlier to prevent mod_sig_buf overflow.
														// The mod_sig_buf can buffer 29 excess data bits, i.e. a maximum delay of 29 * 16 = 464 adc_clk ticks. fdt_indicator
														// could appear at ssp_din after 1 tick, 16 ticks for the transfer, 128 ticks until response is sended.
														// 1148 - 464 - 1 - 128 - 8 = 547
	
	if ((mod_type == `TAGSIM_MOD) || (mod_type == `TAGSIM_LISTEN))
	begin
		if(fdt_counter == 11'd1148) // the RF part delays the rising edge by approx 5 adc_clk_ticks, the ADC needs 3 clk_ticks for A/D conversion,
									// 16 ticks delay by mod_sig_buf
									// 1172 - 5 - 3 - 16 = 1148.
		begin
			if(fdt_elapsed)
			begin
				if(negedge_cnt[3:0] == mod_sig_flip) mod_sig_coil <= mod_sig; // start modulating (if mod_sig is already set)
				sub_carrier_cnt[3:0] <= sub_carrier_cnt[3:0] + 1;
			end
			else
			begin
				mod_sig_flip <= negedge_cnt[3:0];			// start modulation at this time
				sub_carrier_cnt[3:0] <= 0;					// subcarrier phase in sync with start of modulation
				mod_sig_coil <= mod_sig;					// assign signal to coil
				fdt_elapsed = 1'b1;
				if(~(| mod_sig_ptr[4:0])) mod_sig_ptr <= 5'd9;  // if mod_sig_ptr == 0 -> didn't receive a 1 yet. Delay next 1 by n*128 ticks.
				else temp_buffer_reset = 1'b1; 					// else fix the buffer size at current position
			end
		end
		else
		begin
			fdt_counter <= fdt_counter + 1; // Count until 1155
		end
	end
	else // other modes: don't use the delay line.
	begin
		mod_sig_coil <= ssp_dout;
	end	
	
	
	//-------------------------------------------------------------------------------------------------------------------------------------------
	// Relevant for READER_LISTEN only
	// look for steepest falling and rising edges:

	if(negedge_cnt[3:0] == 4'd1)					// reset modulation detector. Save current edge.
	begin
		if (adc_d_filtered > 0)
		begin
			rx_mod_falling_edge_max <= adc_d_filtered;
			rx_mod_rising_edge_max <= 0;
		end	
		else
		begin
			rx_mod_falling_edge_max <= 0;
			rx_mod_rising_edge_max <= -adc_d_filtered;
		end
	end
	else											// detect modulation
	begin
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
	end

	// detect modulation signal: if modulating, there must be a falling and a rising edge
	if (rx_mod_falling_edge_max > 6 && rx_mod_rising_edge_max > 6)
			curbit <= 1'b1;	// modulation
		else
			curbit <= 1'b0;	// no modulation
			
	
	// store previous samples for filtering and edge detection:
	adc_d_4 <= adc_d_3;
	adc_d_3 <= adc_d_2;
	adc_d_2 <= adc_d_1;
	adc_d_1 <= adc_d;


	// Relevant for TAGSIM_MOD only (timing the Tag's answer. See above)
	// When we see end of a modulation and we are emulating a Tag, start fdt_counter.
	// Reset fdt_counter when modulation is detected.
	if(~after_hysteresis /* && mod_sig_buf_empty */ && mod_type == `TAGSIM_LISTEN)
	begin
		fdt_counter <= 11'd0;
		fdt_elapsed = 1'b0;
		fdt_indicator <= 1'b0;
		temp_buffer_reset = 1'b0;
		mod_sig_ptr <= 5'b00000;
		mod_sig = 1'b0;
	end	


	if(negedge_cnt[3:0] == 4'd1)
	begin
		// What do we communicate to the ARM
		if(mod_type == `TAGSIM_LISTEN) 
			sendbit = after_hysteresis;
		else if(mod_type == `TAGSIM_MOD)
			/* if(fdt_counter > 11'd772) sendbit = mod_sig_coil; // huh?
			else */ 
			sendbit = fdt_indicator;
		else if (mod_type == `READER_LISTEN)
			sendbit = curbit;
		else
			sendbit = 1'b0;
	end



	// check timing of a falling edge in reader signal
	if (pre_after_hysteresis && ~after_hysteresis)
		reader_falling_edge_time[3:0] <= negedge_cnt[3:0];
	else
		reader_falling_edge_time[3:0] <= 4'd8;



	// sync clock to external reader's clock:
	if (negedge_cnt[3:0] == 4'd13 && (mod_type == `SNIFFER || mod_type == `TAGSIM_MOD || mod_type == `TAGSIM_LISTEN))
	begin
		// adjust clock if necessary:
		if (reader_falling_edge_time < 4'd8 && reader_falling_edge_time > 4'd1)
		begin
			negedge_cnt <= negedge_cnt;				// freeze time
		end	
		else if (reader_falling_edge_time == 4'd8)
		begin
			negedge_cnt <= negedge_cnt + 1;			// the desired state. Advance as usual;
		end
		else
		begin
			negedge_cnt[3:0] <= 4'd15;				// time warp
		end
		reader_falling_edge_time <= 4'd8;			// only once per detected rising edge
	end
	


	//------------------------------------------------------------------------------------------------------------------------------------------
	// Prepare 8 Bits to communicate to ARM
	if (negedge_cnt == 7'd63)
	begin
		if (mod_type == `SNIFFER)
		begin
			if(deep_modulation) // a reader is sending (or there's no field at all)
			begin
				to_arm <= {after_hysteresis_prev1,after_hysteresis_prev2,after_hysteresis_prev3,after_hysteresis_prev4,1'b0,1'b0,1'b0,1'b0};
			end
			else
			begin
				to_arm <= {after_hysteresis_prev1,after_hysteresis_prev2,after_hysteresis_prev3,after_hysteresis_prev4,bit1,bit2,bit3,bit4};
			end			
			negedge_cnt <= 0;
		end
		else
		begin
			negedge_cnt <= negedge_cnt + 1;
		end
	end	
	else if(negedge_cnt == 7'd127)
	begin
		if (mod_type == `TAGSIM_MOD)
		begin
			to_arm[7:0] <= {mod_sig_ptr[4:0], mod_sig_flip[3:1]};
			negedge_cnt <= 0;
		end
		else
		begin
			to_arm[7:0] <= 8'd0;
			negedge_cnt <= negedge_cnt + 1;
		end
	end
	else
	begin
		negedge_cnt <= negedge_cnt + 1;
	end

	
    if(negedge_cnt == 7'd1)
	begin
        after_hysteresis_prev1 <= after_hysteresis;
		bit1 <= curbit;
	end
    if(negedge_cnt == 7'd17)
	begin
        after_hysteresis_prev2 <= after_hysteresis;
		bit2 <= curbit;
	end
    if(negedge_cnt == 7'd33)
	begin
        after_hysteresis_prev3 <= after_hysteresis;
		bit3 <= curbit;
	end
    if(negedge_cnt == 7'd47)
	begin
        after_hysteresis_prev4 <= after_hysteresis;
		bit4 <= curbit;
	end
	
	//--------------------------------------------------------------------------------------------------------------------------------------------------------------
	// Relevant in TAGSIM_MOD only. Delay-Line to buffer data and send it at the correct time
	if(negedge_cnt[3:0] == 4'd0) 	// at rising edge of ssp_clk - ssp_dout changes at the falling edge.
	begin
		mod_sig_buf[31:0] <= {mod_sig_buf[30:1], ssp_dout, 1'b0};  			// shift in new data starting at mod_sig_buf[1]. mod_sig_buf[0] = 0 always.
		// asign the delayed signal to mod_sig, but don't modulate with the correction bit (which is sent as 00010000, all other bits will come with at least 2 consecutive 1s)
		// side effect: when ptr = 1 it will cancel the first 1 of every block of ones. Note: this would only be the case if we received a 1 just before fdt_elapsed.
		if((ssp_dout || (| mod_sig_ptr[4:0])) && ~fdt_elapsed)				// buffer a 1 (and all subsequent data) until fdt_counter = 1148 adc_clk ticks.
			//if(mod_sig_ptr == 6'b101110)									// buffer overflow at 46 - this would mean data loss
			//begin
			//	mod_sig_ptr <= 6'b000000;
			//end
			if (mod_sig_ptr == 5'd30) mod_sig_ptr <= 5'd0;
			else mod_sig_ptr <= mod_sig_ptr + 1;							// increase buffer (= increase delay by 16 adc_clk ticks). ptr always points to first 1.
		else if(fdt_elapsed && ~temp_buffer_reset)							
		// fdt_elapsed. If we didn't receive a 1 yet, ptr will be at 9 and not yet fixed. Otherwise temp_buffer_reset will be 1 already.
		begin
			// wait for the next 1 after fdt_elapsed before fixing the delay and starting modulation. This ensures that the response can only happen
			// at intervals of 8 * 16 = 128 adc_clk ticks intervals (as defined in ISO14443-3)
			if(ssp_dout) temp_buffer_reset = 1'b1;							
			if(mod_sig_ptr == 5'd2) mod_sig_ptr <= 5'd9;					// still nothing received, need to go for the next interval
			else mod_sig_ptr <= mod_sig_ptr - 1;							// decrease buffer.
		end
		else
		begin
			if(~mod_sig_buf[mod_sig_ptr-1] && ~mod_sig_buf[mod_sig_ptr+1]) mod_sig = 1'b0;
			// finally, assign the delayed signal:
			else mod_sig = mod_sig_buf[mod_sig_ptr];
		end
	end
	
	//-----------------------------------------------------------------------------------------------------------------------------------------------------------------------
	// Communication to ARM (SSP Clock and data)
	// SNIFFER mode (ssp_clk = adc_clk / 8, ssp_frame clock = adc_clk / 64)):
	if(mod_type == `SNIFFER)
	begin
		if(negedge_cnt[2:0] == 3'b100)
			ssp_clk <= 1'b0;
			
		if(negedge_cnt[2:0] == 3'b000)
		begin
			ssp_clk <= 1'b1;
			// Don't shift if we just loaded new data, obviously.
			if(negedge_cnt[5:0] != 6'd0)
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
			// if(ssp_frame_counter == 3'd7) ssp_frame_counter <= 3'd0;
			// else ssp_frame_counter <= ssp_frame_counter + 1;
			if (negedge_cnt[6:4] == 3'b000) ssp_frame = 1'b1;
			else ssp_frame = 1'b0;
		end
		// ssp_frame = (ssp_frame_counter == 3'd7);

		if(negedge_cnt[3:0] == 4'b0000)
		begin
			ssp_clk <= 1'b1;
			// Don't shift if we just loaded new data, obviously.
			if(negedge_cnt[6:0] != 7'd0)
			begin
				to_arm[7:1] <= to_arm[6:0];
			end
		end
		
		if (mod_type == `TAGSIM_MOD && fdt_elapsed && temp_buffer_reset)
			// transmit timing information
			bit_to_arm = to_arm[7];
		else
			// transmit data or fdt_indicator
			bit_to_arm = sendbit;
		end
	
end	//always @(negedge adc_clk)

assign ssp_din = bit_to_arm;


// Subcarrier (adc_clk/16, for TAGSIM_MOD only).
wire sub_carrier;
assign sub_carrier = ~sub_carrier_cnt[3];

// in READER_MOD: drop carrier for mod_sig_coil==1 (pause); in READER_LISTEN: carrier always on; in other modes: carrier always off
assign pwr_hi = (ck_1356megb & (((mod_type == `READER_MOD) & ~mod_sig_coil) || (mod_type == `READER_LISTEN)));	


// Enable HF antenna drivers:
assign pwr_oe1 = 1'b0;
assign pwr_oe3 = 1'b0;

// TAGSIM_MOD: short circuit antenna with different resistances (modulated by sub_carrier modulated by mod_sig_coil)
// for pwr_oe4 = 1 (tristate): antenna load = 10k || 33			= 32,9 Ohms
// for pwr_oe4 = 0 (active):   antenna load = 10k || 33 || 33  	= 16,5 Ohms
assign pwr_oe4 = ~(mod_sig_coil & sub_carrier & (mod_type == `TAGSIM_MOD));

// This is all LF, so doesn't matter.
assign pwr_oe2 = 1'b0;
assign pwr_lo = 1'b0;


assign dbg = negedge_cnt[3];

endmodule
