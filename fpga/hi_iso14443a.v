//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------
// ISO14443-A support for the Proxmark III

module hi_iso14443a(
    input ck_1356meg,
    input [7:0] adc_d,
    input [3:0] mod_type,
    input ssp_dout,

    output ssp_din,
    output reg ssp_frame,
    output reg ssp_clk,
    output adc_clk,
    output pwr_lo,
    output pwr_hi,
    output pwr_oe1,
    output pwr_oe2,
    output pwr_oe3,
    output pwr_oe4,
    output debug
);

assign adc_clk = ck_1356meg;

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Reader -> PM3:
// detecting and shaping the reader's signal. Reader will modulate the carrier by 100% (signal is either on or off). Use a
// hysteresis (Schmitt Trigger) to avoid false triggers during slowly increasing or decreasing carrier amplitudes
reg after_hysteresis;
reg [11:0] has_been_low_for;

always @(negedge adc_clk)
begin
    if(adc_d >= 16) after_hysteresis <= 1'b1;           // U >= 1,14V   -> after_hysteresis = 1
    else if(adc_d < 8) after_hysteresis <= 1'b0;        // U <  1,04V   -> after_hysteresis = 0
    // Note: was >= 3,53V and <= 1,19V. The new trigger values allow more reliable detection of the first bit
    // (it might not reach 3,53V due to the high time constant of the high pass filter in the analogue RF part).
    // In addition, the new values are more in line with ISO14443-2: "The PICC shall detect the ”End of Pause” after the field exceeds
    // 5% of H_INITIAL and before it exceeds 60% of H_INITIAL." Depending on the signal strength, 60% might well be less than 3,53V.


    // detecting a loss of reader's field (adc_d < 192 for 4096 clock cycles). If this is the case,
    // set the detected reader signal (after_hysteresis) to '1' (unmodulated)
    if(adc_d >= 192)
    begin
        has_been_low_for <= 12'd0;
    end
    else
    begin
        if(has_been_low_for == 12'd4095)
        begin
            has_been_low_for <= 12'd0;
            after_hysteresis <= 1'b1;
        end
        else
        begin
            has_been_low_for <= has_been_low_for + 1;
        end
    end

end

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Reader -> PM3
// detect when a reader is active (modulating). We assume that the reader is active, if we see the carrier off for at least 8
// carrier cycles. We assume that the reader is inactive, if the carrier stayed high for at least 256 carrier cycles.
reg deep_modulation;
reg [2:0] deep_counter;
reg [8:0] saw_deep_modulation;

always @(negedge adc_clk)
begin
    if(~(| adc_d[7:0]))                                 // if adc_d == 0 (U <= 0,94V)
    begin
        if(deep_counter == 3'd7)                        // adc_d == 0 for 8 adc_clk ticks -> deep_modulation (by reader)
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
        if(saw_deep_modulation == 8'd255)               // adc_d != 0 for 256 adc_clk ticks -> deep_modulation is over, probably waiting for tag's response
            deep_modulation <= 1'b0;
        else
            saw_deep_modulation <= saw_deep_modulation + 1;
    end
end

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Tag -> PM3
// filter the input for a tag's signal. The filter box needs the 4 previous input values and is a gaussian derivative filter
// for noise reduction and edge detection.
// store 4 previous samples:
reg [7:0] input_prev_4, input_prev_3, input_prev_2, input_prev_1;

always @(negedge adc_clk)
begin
    input_prev_4 <= input_prev_3;
    input_prev_3 <= input_prev_2;
    input_prev_2 <= input_prev_1;
    input_prev_1 <= adc_d;
end

// adc_d_filtered = 2*input_prev4 + 1*input_prev3 + 0*input_prev2 - 1*input_prev1 - 2*input
//                  = (2*input_prev4 + input_prev3) - (2*input + input_prev1)
wire [8:0] input_prev_4_times_2 = input_prev_4 << 1;
wire [8:0] adc_d_times_2        = adc_d << 1;

wire [9:0] tmp1 = input_prev_4_times_2 + input_prev_3;
wire [9:0] tmp2 = adc_d_times_2 + input_prev_1;

// convert intermediate signals to signed and calculate the filter output
wire signed [10:0] adc_d_filtered = {1'b0, tmp1} - {1'b0, tmp2};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// internal FPGA timing. Maximum required period is 128 carrier clock cycles for a full 8 Bit transfer to ARM. (i.e. we need a
// 7 bit counter). Adjust its frequency to external reader's clock when simulating a tag or sniffing.
reg pre_after_hysteresis;
reg [3:0] reader_falling_edge_time;
reg [6:0] negedge_cnt;

always @(negedge adc_clk)
begin
    // detect a reader signal's falling edge and remember its timing:
    pre_after_hysteresis <= after_hysteresis;
    if (pre_after_hysteresis && ~after_hysteresis)
    begin
        reader_falling_edge_time[3:0] <= negedge_cnt[3:0];
    end

    // adjust internal timer counter if necessary:
    if (negedge_cnt[3:0] == 4'd13 && (mod_type == `FPGA_HF_ISO14443A_SNIFFER || mod_type == `FPGA_HF_ISO14443A_TAGSIM_LISTEN) && deep_modulation)
    begin
        if (reader_falling_edge_time == 4'd1)           // reader signal changes right after sampling. Better sample earlier next time.
        begin
            negedge_cnt <= negedge_cnt + 2;             // time warp
        end
        else if (reader_falling_edge_time == 4'd0)      // reader signal changes right before sampling. Better sample later next time.
        begin
            negedge_cnt <= negedge_cnt;                 // freeze time
        end
        else
        begin
            negedge_cnt <= negedge_cnt + 1;             // Continue as usual
        end
        reader_falling_edge_time[3:0] <= 4'd8;          // adjust only once per detected edge
    end
    else if (negedge_cnt == 7'd127)                     // normal operation: count from 0 to 127
    begin
        negedge_cnt <= 0;
    end
    else
    begin
        negedge_cnt <= negedge_cnt + 1;
    end
end

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Tag -> PM3:
// determine best possible time for starting/resetting the modulation detector.
reg [3:0] mod_detect_reset_time;

always @(negedge adc_clk)
begin
    if (mod_type == `FPGA_HF_ISO14443A_READER_LISTEN)
    // (our) reader signal changes at negedge_cnt[3:0]=9, tag response expected to start n*16+4 ticks later, further delayed by
    // 3 ticks ADC conversion. The maximum filter output (edge detected) will be detected after subcarrier zero crossing (+7 ticks).
    // To allow some timing variances, we want to have the maximum filter outputs well within the detection window, i.e.
    // at mod_detect_reset_time+4 and mod_detect_reset_time+12  (-4 ticks).
    // 9 + 4 + 3 + 7 - 4  = 19.    19 mod 16 = 3
    begin
        mod_detect_reset_time <= 4'd4;
    end
    else
    if (mod_type == `FPGA_HF_ISO14443A_SNIFFER)
    begin
        // detect a rising edge of reader's signal and sync modulation detector to the tag's answer:
        if (~pre_after_hysteresis && after_hysteresis && deep_modulation)
        // reader signal rising edge detected at negedge_cnt[3:0]. This signal had been delayed
        // 9 ticks by the RF part + 3 ticks by the A/D converter + 1 tick to assign to after_hysteresis.
        // Then the same as above.
        // - 9 - 3 - 1 + 4 + 3 + 7 - 4 = -3
        begin
            mod_detect_reset_time <= negedge_cnt[3:0] - 4'd3;
        end
    end
end

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Tag -> PM3:
// modulation detector. Looks for the steepest falling and rising edges within a 16 clock period. If there is both a significant
// falling and rising edge (in any order), a modulation is detected.
reg signed [10:0] rx_mod_falling_edge_max;
reg signed [10:0] rx_mod_rising_edge_max;
reg curbit;

`ifdef PM3ICOPYX
`define EDGE_DETECT_THRESHOLD   3
`else
`define EDGE_DETECT_THRESHOLD   7
`endif
`define EDGE_DETECT_THRESHOLDHIGH   20

always @(negedge adc_clk)
begin
    if(negedge_cnt[3:0] == mod_detect_reset_time)
    begin
        if (mod_type == `FPGA_HF_ISO14443A_SNIFFER)
        begin
            // detect modulation signal: if modulating, there must have been a falling AND a rising edge
            if ((rx_mod_falling_edge_max > `EDGE_DETECT_THRESHOLDHIGH) && (rx_mod_rising_edge_max < -`EDGE_DETECT_THRESHOLDHIGH))
                curbit <= 1'b1; // modulation
            else
                curbit <= 1'b0; // no modulation
        end
        else
        begin
            // detect modulation signal: if modulating, there must have been a falling AND a rising edge
            if ((rx_mod_falling_edge_max > `EDGE_DETECT_THRESHOLD) && (rx_mod_rising_edge_max < -`EDGE_DETECT_THRESHOLD))
                curbit <= 1'b1; // modulation
            else
                curbit <= 1'b0; // no modulation
        end
        // reset modulation detector
        rx_mod_rising_edge_max <= 0;
        rx_mod_falling_edge_max <= 0;
    end
    else // look for steepest edges (slopes)
    begin
        if (adc_d_filtered > 0)
        begin
            if (adc_d_filtered > rx_mod_falling_edge_max)
                rx_mod_falling_edge_max <= adc_d_filtered;
        end
        else
        begin
            if (adc_d_filtered < rx_mod_rising_edge_max)
                rx_mod_rising_edge_max <= adc_d_filtered;
        end
    end

end

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Tag+Reader -> PM3
// sample 4 bits reader data and 4 bits tag data for sniffing
reg [3:0] reader_data;
reg [3:0] tag_data;

always @(negedge adc_clk)
begin
    if(negedge_cnt[3:0] == 4'd0)
    begin
        reader_data[3:0] <= {reader_data[2:0], after_hysteresis};
        tag_data[3:0] <= {tag_data[2:0], curbit};
    end
end

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// PM3 -> Reader:
// a delay line to ensure that we send the (emulated) tag's answer at the correct time according to ISO14443-3
reg [31:0] mod_sig_buf;
reg [4:0] mod_sig_ptr;
reg mod_sig;

always @(negedge adc_clk)
begin
    if(negedge_cnt[3:0] == 4'd0)    // sample data at rising edge of ssp_clk - ssp_dout changes at the falling edge.
    begin
        mod_sig_buf[31:2] <= mod_sig_buf[30:1];             // shift
        if (~ssp_dout && ~mod_sig_buf[1])
            mod_sig_buf[1] <= 1'b0;                         // delete the correction bit (a single 1 preceded and succeeded by 0)
        else
            mod_sig_buf[1] <= mod_sig_buf[0];
        mod_sig_buf[0] <= ssp_dout;                         // add new data to the delay line

        mod_sig = mod_sig_buf[mod_sig_ptr];                 // the delayed signal.
    end
end

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// PM3 -> Reader, internal timing:
// a timer for the 1172 cycles fdt (Frame Delay Time). Start the timer with a rising edge of the reader's signal.
// set fdt_elapsed when we no longer need to delay data. Set fdt_indicator when we can start sending data.
// Note: the FPGA only takes care for the 1172 delay. To achieve an additional 1236-1172=64 ticks delay, the ARM must send
// a correction bit (before the start bit). The correction bit will be coded as 00010000, i.e. it adds 4 bits to the
// transmission stream, causing the required additional delay.
reg [10:0] fdt_counter;
reg fdt_indicator, fdt_elapsed;
reg [3:0] mod_sig_flip;
reg [3:0] sub_carrier_cnt;

// we want to achieve a delay of 1172. The RF part already has delayed the reader signals's rising edge
// by 9 ticks, the ADC took 3 ticks and there is always a delay of 32 ticks by the mod_sig_buf. Therefore need to
// count to 1172 - 9 - 3 - 32 = 1128
`define FDT_COUNT 11'd1128

// The ARM must not send too early, otherwise the mod_sig_buf will overflow, therefore signal that we are ready
// with fdt_indicator. The mod_sig_buf can buffer 29 excess data bits, i.e. a maximum delay of 29 * 16 = 464 adc_clk ticks.
// fdt_indicator is assigned to sendbit after at least 1 tick, the transfer to ARM needs minimum 8 ticks. Response from
// ARM could appear at ssp_dout 8 ticks later.
// 1128 - 464 - 1 - 8 - 8 = 647
`define FDT_INDICATOR_COUNT 11'd647
// Note: worst case, assignment to sendbit takes 15 ticks more, and transfer to ARM needs 7*16 = 112 ticks more.
//       When the ARM's response then appears, the fdt_count is already 647 + 15 + 112 = 774, which still allows the ARM a possible
//       response window of 1128 - 774 = 354 ticks.

// reset on a pause in listen mode. I.e. the counter starts when the pause is over:
assign fdt_reset = ~after_hysteresis && mod_type == `FPGA_HF_ISO14443A_TAGSIM_LISTEN;

always @(negedge adc_clk)
begin
    if (fdt_reset)
    begin
        fdt_counter <= 11'd0;
        fdt_elapsed <= 1'b0;
        fdt_indicator <= 1'b0;
    end
    else
    begin
        if(fdt_counter == `FDT_COUNT)
        begin
            if(~fdt_elapsed)                            // just reached fdt.
            begin
                mod_sig_flip <= negedge_cnt[3:0];       // start modulation at this time
                sub_carrier_cnt <= 4'd0;                // subcarrier phase in sync with start of modulation
                fdt_elapsed <= 1'b1;
            end
            else
            begin
                sub_carrier_cnt <= sub_carrier_cnt + 1;
            end
        end
        else
        begin
            fdt_counter <= fdt_counter + 1;
        end
    end

    if(fdt_counter == `FDT_INDICATOR_COUNT) fdt_indicator <= 1'b1;
end

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// PM3 -> Reader or Tag
// assign a modulation signal to the antenna. This signal is either a delayed signal (to achieve fdt when sending to a reader)
// or undelayed when sending to a tag
reg mod_sig_coil;

always @(negedge adc_clk)
begin
    if (mod_type == `FPGA_HF_ISO14443A_TAGSIM_MOD)           // need to take care of proper fdt timing
    begin
        if(fdt_counter == `FDT_COUNT)
        begin
            if(fdt_elapsed)
            begin
                if(negedge_cnt[3:0] == mod_sig_flip) mod_sig_coil <= mod_sig;
            end
            else
            begin
                mod_sig_coil <= mod_sig;    // just reached fdt. Immediately assign signal to coil
            end
        end
    end
    else                                    // other modes: don't delay
    begin
        mod_sig_coil <= ssp_dout;
    end
end

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// PM3 -> Reader
// determine the required delay in the mod_sig_buf (set mod_sig_ptr).
reg temp_buffer_reset;

always @(negedge adc_clk)
begin
    if(fdt_reset)
    begin
        mod_sig_ptr <= 5'd0;
        temp_buffer_reset = 1'b0;
    end
    else
    begin
        if(fdt_counter == `FDT_COUNT && ~fdt_elapsed)                           // if we just reached fdt
            if(~(| mod_sig_ptr[4:0]))
                mod_sig_ptr <= 5'd8;                                            // ... but didn't buffer a 1 yet, delay next 1 by n*128 ticks.
            else
                temp_buffer_reset = 1'b1;                                       // else no need for further delays.

        if(negedge_cnt[3:0] == 4'd0)                                            // at rising edge of ssp_clk - ssp_dout changes at the falling edge.
        begin
            if((ssp_dout || (| mod_sig_ptr[4:0])) && ~fdt_elapsed)              // buffer a 1 (and all subsequent data) until fdt is reached.
                if (mod_sig_ptr == 5'd31)
                    mod_sig_ptr <= 5'd0;                                        // buffer overflow - data loss.
                else
                    mod_sig_ptr <= mod_sig_ptr + 1;                             // increase buffer (= increase delay by 16 adc_clk ticks). mod_sig_ptr always points ahead of first 1.
            else if(fdt_elapsed && ~temp_buffer_reset)
            begin
                // wait for the next 1 after fdt_elapsed before fixing the delay and starting modulation. This ensures that the response can only happen
                // at intervals of 8 * 16 = 128 adc_clk ticks (as defined in ISO14443-3)
                if(ssp_dout)
                    temp_buffer_reset = 1'b1;
                if(mod_sig_ptr == 5'd1)
                    mod_sig_ptr <= 5'd8;                                        // still nothing received, need to go for the next interval
                else
                    mod_sig_ptr <= mod_sig_ptr - 1;                             // decrease buffer.
            end
        end
    end
end

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// FPGA -> ARM communication:
// buffer 8 bits data to be sent to ARM. Shift them out bit by bit.
reg [7:0] to_arm;

always @(negedge adc_clk)
begin
    if (negedge_cnt[5:0] == 6'd63)                          // fill the buffer
    begin
        if (mod_type == `FPGA_HF_ISO14443A_SNIFFER)
        begin
            if(deep_modulation)                             // a reader is sending (or there's no field at all)
            begin
                to_arm <= {reader_data[3:0], 4'b0000};      // don't send tag data
            end
            else
            begin
                to_arm <= {reader_data[3:0], tag_data[3:0]};
            end
        end
        else
        begin
            to_arm[7:0] <= {mod_sig_ptr[4:0], mod_sig_flip[3:1]}; // feedback timing information
        end
    end

    if(negedge_cnt[2:0] == 3'b000 && mod_type == `FPGA_HF_ISO14443A_SNIFFER)    // shift at double speed
    begin
        // Don't shift if we just loaded new data, obviously.
        if(negedge_cnt[5:0] != 6'd0)
        begin
            to_arm[7:1] <= to_arm[6:0];
        end
    end

    if(negedge_cnt[3:0] == 4'b0000 && mod_type != `FPGA_HF_ISO14443A_SNIFFER)
    begin
        // Don't shift if we just loaded new data, obviously.
        if(negedge_cnt[6:0] != 7'd0)
        begin
            to_arm[7:1] <= to_arm[6:0];
        end
    end
end

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// FPGA <-> ARM communication:
// generate a ssp clock and ssp frame signal for the synchronous transfer from/to the ARM

always @(negedge adc_clk)
begin
    if(mod_type == `FPGA_HF_ISO14443A_SNIFFER)
    // FPGA_HF_ISO14443A_SNIFFER mode (ssp_clk = adc_clk / 8, ssp_frame clock = adc_clk / 64)):
    begin
        if(negedge_cnt[2:0] == 3'd0)
            ssp_clk <= 1'b1;
        if(negedge_cnt[2:0] == 3'd4)
            ssp_clk <= 1'b0;

        if(negedge_cnt[5:0] == 6'd0)    // ssp_frame rising edge indicates start of frame
            ssp_frame <= 1'b1;
        if(negedge_cnt[5:0] == 6'd8)
            ssp_frame <= 1'b0;
    end
    else
    // all other modes (ssp_clk = adc_clk / 16, ssp_frame clock = adc_clk / 128):
    begin
        if(negedge_cnt[3:0] == 4'd0)
            ssp_clk <= 1'b1;
        if(negedge_cnt[3:0] == 4'd8)
            ssp_clk <= 1'b0;

        if(negedge_cnt[6:0] == 7'd7)    // ssp_frame rising edge indicates start of frame, sampled on falling edge of ssp_clk
            ssp_frame <= 1'b1;
        if(negedge_cnt[6:0] == 7'd23)
            ssp_frame <= 1'b0;
    end
end

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// FPGA -> ARM communication:
// select the data to be sent to ARM
reg bit_to_arm;
reg sendbit;

always @(negedge adc_clk)
begin
    if(negedge_cnt[3:0] == 4'd0)
    begin
        // What do we communicate to the ARM
        if(mod_type == `FPGA_HF_ISO14443A_TAGSIM_LISTEN)
            sendbit = after_hysteresis;
        else if(mod_type == `FPGA_HF_ISO14443A_TAGSIM_MOD)
            /* if(fdt_counter > 11'd772) sendbit = mod_sig_coil; // huh?
            else */
            sendbit = fdt_indicator;
        else if (mod_type == `FPGA_HF_ISO14443A_READER_LISTEN)
            sendbit = curbit;
        else
            sendbit = 1'b0;
    end

    if(mod_type == `FPGA_HF_ISO14443A_SNIFFER)
        // send sampled reader and tag data:
        bit_to_arm = to_arm[7];
    else if (mod_type == `FPGA_HF_ISO14443A_TAGSIM_MOD && fdt_elapsed && temp_buffer_reset)
        // send timing information:
        bit_to_arm = to_arm[7];
    else
        // send data or fdt_indicator
        bit_to_arm = sendbit;
end

assign ssp_din = bit_to_arm;

// Subcarrier (adc_clk/16, for FPGA_HF_ISO14443A_TAGSIM_MOD only).
wire sub_carrier;
assign sub_carrier = ~sub_carrier_cnt[3];

// in FPGA_HF_ISO14443A_READER_MOD: drop carrier for mod_sig_coil == 1 (pause);
// in FPGA_HF_ISO14443A_READER_LISTEN: carrier always on; in other modes: carrier always off
assign pwr_hi = (ck_1356meg & (((mod_type == `FPGA_HF_ISO14443A_READER_MOD) & ~mod_sig_coil) || (mod_type == `FPGA_HF_ISO14443A_READER_LISTEN)));

// Enable HF antenna drivers:
assign pwr_oe1 = 1'b0;
assign pwr_oe3 = 1'b0;

// FPGA_HF_ISO14443A_TAGSIM_MOD: short circuit antenna with different resistances (modulated by sub_carrier modulated by mod_sig_coil)
// for pwr_oe4 = 1 (tristate): antenna load = 10k || 33         = 32,9 Ohms
// for pwr_oe4 = 0 (active):   antenna load = 10k || 33 || 33   = 16,5 Ohms
assign pwr_oe4 = mod_sig_coil & sub_carrier & (mod_type == `FPGA_HF_ISO14443A_TAGSIM_MOD);

// This is all LF, so doesn't matter.
assign pwr_oe2 = 1'b0;
assign pwr_lo = 1'b0;

assign debug = negedge_cnt[3];

endmodule
