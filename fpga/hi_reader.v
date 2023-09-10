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
// with optional support for iso15 2sc mode slected with compiler define WITH_HF_15

module hi_reader(
    input ck_1356meg,
    input [7:0] adc_d,
    input [1:0] subcarrier_frequency,
    input [3:0] minor_mode,
    input ssp_dout,

    output ssp_din,
    output reg ssp_frame,
    output reg ssp_clk,
    output adc_clk,
    output pwr_lo,
    output reg pwr_hi,
    output reg pwr_oe1,
    output pwr_oe2,
    output pwr_oe3,
    output reg pwr_oe4,
    output debug
);

assign adc_clk = ck_1356meg;  // sample frequency is 13,56 MHz

// When we're a reader, we just need to do the BPSK demod; but when we're an
// eavesdropper, we also need to pick out the commands sent by the reader,
// using AM. Do this the same way that we do it for the simulated tag.
reg after_hysteresis, after_hysteresis_prev, after_hysteresis_prev_prev;
reg [11:0] has_been_low_for;
always @(negedge adc_clk)
begin
    if (& adc_d[7:0]) after_hysteresis <= 1'b1;
    else if (~(| adc_d[7:0])) after_hysteresis <= 1'b0;

    if (after_hysteresis)
    begin
        has_been_low_for <= 12'd0;
    end
    else
    begin
        if (has_been_low_for == 12'd4095)
        begin
            has_been_low_for <= 12'd0;
            after_hysteresis <= 1'b1;
        end
        else
            has_been_low_for <= has_been_low_for + 1;
    end
end

// Let us report a correlation every 64 samples. I.e.
// one Q/I pair after 4 subcarrier cycles for the 848kHz subcarrier,
// one Q/I pair after 2 subcarrier cycles for the 424kHz subcarriers,
// one Q/I pair for each subcarrier cyle for the 212kHz subcarrier.
// We need a 6-bit counter for the timing.
reg [5:0] corr_i_cnt;
always @(negedge adc_clk)
    corr_i_cnt <= corr_i_cnt + 1;

`ifdef WITH_HF_15
reg [1:0] fskout = 2'd0;
reg last0 = 1'b0;

reg [7:0] avg = 8'd0;
reg [127:0] avg128 = 128'd0;
reg [7:0] diff16 = 8'd0;
reg [7:0] diff28 = 8'd0;
reg [7:0] diff32 = 8'd0;

reg [11:0] match16 = 12'd0;
reg [11:0] match32 = 12'd0;
reg [11:0] match28 = 12'd0;

always @(negedge adc_clk)
begin
    if (corr_i_cnt[0] == 1'b0) // every 2 clock
        avg = adc_d[7:1];
    else
    begin
        avg = avg + adc_d[7:1];
        if (corr_i_cnt[0] == 1'b1)  // every 2 clock
        begin
            if (avg > avg128[63:56])
                diff16 = avg - avg128[63:56];
            else
                diff16 = avg128[63:56] - avg;

            if (avg > avg128[111:104])
                diff28 = avg - avg128[111:104];
            else
                diff28 = avg128[111:104] - avg;

            if (avg > avg128[127:120])
                diff32 = avg - avg128[127:120];
            else
                diff32 = avg128[127:120] - avg;

            avg128[127:8] = avg128[119:0];
            avg128[7:0] = avg;

            if (corr_i_cnt[4:1] == 4'b0000) // every 32 clock (8*4)
            begin
                match16 = diff16;
                match28 = diff28;
                match32 = diff32;
            end
            else
            begin
                match16 = match16 + diff16;
                match28 = match28 + diff28;
                match32 = match32 + diff32;

                if (corr_i_cnt[4:1] == 4'b1111) // every 32 clock (8*4)
                begin
                    last0 = (fskout == 2'b0);
                    if (match16 < 12'd64 && last0)
                        fskout = 2'b00; // not yet started
                    else if  ((match16 | match28 | match32) == 12'b0)
                        fskout = 2'b00; // signal likely ended
                    else if (((match16 <= match28 + 12'd16) && (match16 <= match32+ 12'd16)) ||
                            (match28 <= 12'd16 && match32 <= 12'd16))
                    begin
                        if (!last0)
                            fskout = 2'b11; // 16 match better than 28 or 32 but already started
                    end
                    else
                    begin
                        if (match28 < match32)
                        begin
                            diff28 = match32 - match28;
                            diff16 = match16 - match28;
                            if (diff28*2 > diff16)
                                fskout = 2'b01;
                            else if (!last0)
                            begin
                                fskout = 2'b01;
                            end
                        end
                        else //if (match32 <= match28)
                        begin
                            diff32 = match28 - match32;
                            diff16 = match16 - match32;
                            if (diff32*2 > diff16)
                                fskout = 2'b10;
                            else if (!last0)
                            begin
                                fskout = 2'b10;
                            end
                        end
                    end
                end
            end
        end
    end
end
`endif

// A couple of registers in which to accumulate the correlations. From the 64 samples
// we would add at most 32 times the difference between unmodulated and modulated signal. It should
// be safe to assume that a tag will not be able to modulate the carrier signal by more than 25%.
// 32 * 255 * 0,25 = 2040, which can be held in 11 bits. Add 1 bit for sign.
// Temporary we might need more bits. For the 212kHz subcarrier we could possible add 32 times the
// maximum signal value before a first subtraction would occur. 32 * 255 = 8160 can be held in 13 bits.
// Add one bit for sign -> need 14 bit registers but final result will fit into 12 bits.
reg signed [13:0] corr_i_accum;
reg signed [13:0] corr_q_accum;
// we will report maximum 8 significant bits
reg signed [7:0] corr_i_out;
reg signed [7:0] corr_q_out;

// the amplitude of the subcarrier is sqrt(ci^2 + cq^2).
// approximate by amplitude = max(|ci|,|cq|) + 1/2*min(|ci|,|cq|)
reg [13:0] corr_amplitude, abs_ci, abs_cq, max_ci_cq;
reg [12:0] min_ci_cq_2; // min_ci_cq / 2

always @(*)
begin
    if (corr_i_accum[13] == 1'b0)
        abs_ci <= corr_i_accum;
    else
        abs_ci <= -corr_i_accum;

    if (corr_q_accum[13] == 1'b0)
        abs_cq <= corr_q_accum;
    else
        abs_cq <= -corr_q_accum;

    if (abs_ci > abs_cq)
    begin
        max_ci_cq <= abs_ci;
        min_ci_cq_2 <= abs_cq / 2;
    end
    else
    begin
        max_ci_cq <= abs_cq;
        min_ci_cq_2 <= abs_ci / 2;
    end

    corr_amplitude <= max_ci_cq + min_ci_cq_2;

end

// The subcarrier reference signals
reg subcarrier_I;
reg subcarrier_Q;

always @(*)
begin
    if (subcarrier_frequency == `FPGA_HF_READER_SUBCARRIER_848_KHZ)
    begin
        subcarrier_I = ~corr_i_cnt[3];
        subcarrier_Q = ~(corr_i_cnt[3] ^ corr_i_cnt[2]);
    end
    else if (subcarrier_frequency == `FPGA_HF_READER_SUBCARRIER_212_KHZ)
    begin
        subcarrier_I = ~corr_i_cnt[5];
        subcarrier_Q = ~(corr_i_cnt[5] ^ corr_i_cnt[4]);
    end
    else
    begin // 424 kHz
        subcarrier_I = ~corr_i_cnt[4];
        subcarrier_Q = ~(corr_i_cnt[4] ^ corr_i_cnt[3]);
    end
end

// ADC data appears on the rising edge, so sample it on the falling edge
always @(negedge adc_clk)
begin
    // These are the correlators: we correlate against in-phase and quadrature
    // versions of our reference signal, and keep the (signed) results or the
    // resulting amplitude to send out later over the SSP.
    if (corr_i_cnt == 6'd0)
    begin
        if (minor_mode == `FPGA_HF_READER_MODE_SNIFF_AMPLITUDE)
        begin
`ifdef WITH_HF_15
            if (subcarrier_frequency == `FPGA_HF_READER_2SUBCARRIERS_424_484_KHZ)
            begin
                // send amplitude + 2 bits fsk (2sc) signal + 2 bits reader signal
                corr_i_out <= corr_amplitude[13:6];
                corr_q_out <= {corr_amplitude[5:2], fskout, after_hysteresis_prev_prev, after_hysteresis_prev};
            end
            else
`endif
            begin
                // send amplitude plus 2 bits reader signal
                corr_i_out <= corr_amplitude[13:6];
                corr_q_out <= {corr_amplitude[5:0], after_hysteresis_prev_prev, after_hysteresis_prev};
            end
        end
        else if (minor_mode == `FPGA_HF_READER_MODE_SNIFF_IQ)
        begin
            // Send 7 most significant bits of in phase tag signal (signed), plus 1 bit reader signal
            if (corr_i_accum[13:11] == 3'b000 || corr_i_accum[13:11] == 3'b111)
                corr_i_out <= {corr_i_accum[11:5], after_hysteresis_prev_prev};
            else // truncate to maximum value
                if (corr_i_accum[13] == 1'b0)
                    corr_i_out <= {7'b0111111, after_hysteresis_prev_prev};
                else
                    corr_i_out <= {7'b1000000, after_hysteresis_prev_prev};

            // Send 7 most significant bits of quadrature phase tag signal (signed), plus 1 bit reader signal
            if (corr_q_accum[13:11] == 3'b000 || corr_q_accum[13:11] == 3'b111)
                corr_q_out <= {corr_q_accum[11:5], after_hysteresis_prev};
            else // truncate to maximum value
                if (corr_q_accum[13] == 1'b0)
                    corr_q_out <= {7'b0111111, after_hysteresis_prev};
                else
                    corr_q_out <= {7'b1000000, after_hysteresis_prev};
        end
        else if (minor_mode == `FPGA_HF_READER_MODE_RECEIVE_AMPLITUDE)
        begin
`ifdef WITH_HF_15
            if (subcarrier_frequency == `FPGA_HF_READER_2SUBCARRIERS_424_484_KHZ)
            begin
                // send 2 bits fsk (2sc) signal + amplitude
                corr_i_out <= {fskout, corr_amplitude[13:8]};
                corr_q_out <= corr_amplitude[7:0];
            end
            else
`endif
            begin
                // send amplitude
                corr_i_out <= {2'b00, corr_amplitude[13:8]};
                corr_q_out <= corr_amplitude[7:0];
            end
        end
        else if (minor_mode == `FPGA_HF_READER_MODE_RECEIVE_IQ)
        begin
            // Send 8 bits of in phase tag signal
            if (corr_i_accum[13:11] == 3'b000 || corr_i_accum[13:11] == 3'b111)
                corr_i_out <= corr_i_accum[11:4];
            else // truncate to maximum value
                if (corr_i_accum[13] == 1'b0)
                    corr_i_out <= 8'b01111111;
                else
                    corr_i_out <= 8'b10000000;

            // Send 8 bits of quadrature phase tag signal
            if (corr_q_accum[13:11] == 3'b000 || corr_q_accum[13:11] == 3'b111)
                corr_q_out <= corr_q_accum[11:4];
            else // truncate to maximum value
                if (corr_q_accum[13] == 1'b0)
                    corr_q_out <= 8'b01111111;
                else
                    corr_q_out <= 8'b10000000;
        end

        // for each Q/I pair report two reader signal samples when sniffing. Store the 1st.
        after_hysteresis_prev_prev <= after_hysteresis;

        // Initialize next correlation.
        // Both I and Q reference signals are high when corr_i_nct == 0. Therefore need to accumulate.
        corr_i_accum <= $signed({1'b0, adc_d});
        corr_q_accum <= $signed({1'b0, adc_d});
    end
    else
    begin
        if (subcarrier_I)
            corr_i_accum <= corr_i_accum + $signed({1'b0, adc_d});
        else
            corr_i_accum <= corr_i_accum - $signed({1'b0, adc_d});

        if (subcarrier_Q)
            corr_q_accum <= corr_q_accum + $signed({1'b0, adc_d});
        else
            corr_q_accum <= corr_q_accum - $signed({1'b0, adc_d});
    end

    // for each Q/I pair report two reader signal samples when sniffing. Store the 2nd.
    if (corr_i_cnt == 6'd32)
        after_hysteresis_prev <= after_hysteresis;

    // Then the result from last time is serialized and send out to the ARM.
    // We get one report each cycle, and each report is 16 bits, so the
    // ssp_clk should be the adc_clk divided by 64/16 = 4.
    // ssp_clk frequency = 13,56MHz / 4 = 3.39MHz

    if (corr_i_cnt[1:0] == 2'b00)
    begin
        // Don't shift if we just loaded new data, obviously.
        if (corr_i_cnt != 6'd0)
        begin
            corr_i_out[7:0] <= {corr_i_out[6:0], corr_q_out[7]};
            corr_q_out[7:1] <= corr_q_out[6:0];
        end
    end

end

// ssp clock and frame signal for communication to and from ARM
//                _____       _____       _____       _
// ssp_clk       |     |_____|     |_____|     |_____|
//                   _____
// ssp_frame     ___|     |____________________________
//                ___________ ___________ ___________ _
// ssp_d_in      X___________X___________X___________X_
//
// corr_i_cnt    0  1  2  3  4  5  6  7  8  9 10 11 12 ...
//
always @(negedge adc_clk)
begin
    if (corr_i_cnt[1:0] == 2'b00)
        ssp_clk <= 1'b1;

    if (corr_i_cnt[1:0] == 2'b10)
        ssp_clk <= 1'b0;

    // set ssp_frame signal for corr_i_cnt = 1..3
    // (send one frame with 16 Bits)
    if (corr_i_cnt == 6'd1)
        ssp_frame <= 1'b1;

    if (corr_i_cnt == 6'd3)
        ssp_frame <= 1'b0;
end

assign ssp_din = corr_i_out[7];

// a jamming signal
reg jam_signal;
reg [3:0] jam_counter;

always @(negedge adc_clk)
begin
    if (corr_i_cnt == 6'd0)
    begin
        jam_counter <= jam_counter + 1;
        jam_signal <= jam_counter[1] ^ jam_counter[3];
    end
end

always @(*)
begin
    pwr_oe1 = 1'b0;
    pwr_oe4 = 1'b0;

    if (minor_mode == `FPGA_HF_READER_MODE_SEND_SHALLOW_MOD)
    begin
        pwr_hi  = ck_1356meg;
        pwr_oe4 = ssp_dout;
    end
    else if (minor_mode == `FPGA_HF_READER_MODE_SEND_SHALLOW_MOD_RDV4)
    begin
        pwr_hi  = ck_1356meg;
        pwr_oe1 = ssp_dout;
    end
    else if (minor_mode == `FPGA_HF_READER_MODE_SEND_FULL_MOD)
    begin
        pwr_hi  = ck_1356meg & ~ssp_dout;
        pwr_oe4 = 1'b0;
    end
    else if (minor_mode == `FPGA_HF_READER_MODE_SEND_JAM)
    begin
        pwr_hi  = ck_1356meg & jam_signal;
        pwr_oe4 = 1'b0;
    end
    else if (minor_mode == `FPGA_HF_READER_MODE_SNIFF_IQ
          || minor_mode == `FPGA_HF_READER_MODE_SNIFF_AMPLITUDE
          || minor_mode == `FPGA_HF_READER_MODE_SNIFF_PHASE)
    begin // all off
        pwr_hi  = 1'b0;
        pwr_oe4 = 1'b0;
    end
    else // receiving from tag
    begin
        pwr_hi  = ck_1356meg;
        pwr_oe4 = 1'b0;
    end
end

// unused
assign pwr_oe2 = 1'b0;
assign pwr_oe3 = 1'b0;
assign pwr_lo  = 1'b0;

// Debug Output
assign debug = corr_i_cnt[3];

endmodule
