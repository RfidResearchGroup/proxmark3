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
// ISO14443-A sniffer for the Proxmark5 at 106, 212, 424 and 848 kbit/s
//
// Built only into the PM5 14a sniffer image (PM5_SNIFF14A, `make -C fpga
// fpga_pm5_sniff14a`), which `hf 14a sniff` loads into the FPGA's SRAM. Derived
// from common/hi_iso14443a.v, SNIFFER minor mode only:
//  - reader: pauses relative to the idle level of the full 10-bit samples
//  - tag at 106 kbit/s: I/Q correlation against the fc/16 subcarrier
//  - tag at 212 / 424 / 848 kbit/s: BPSK against the preamble's phase
// The ARM sets the bit rates after a PPS (rate_tag / rate_rdr). With link16 each
// byte to the ARM comes with an edge side byte (16-bit words).
//-----------------------------------------------------------------------------

`ifdef PM5_SNIFF14A

module pm5_hi_iso14443a(
    input ck_1356meg,
    input [9:0] adc_d10,                // all 10 ADC bits
    input [1:0] rate_tag,               // bit rates: 0 = 106, 1 = 212, 2 = 424, 3 = 848 kbit/s
    input [1:0] rate_rdr,
    input link16,                       // 16-bit words to the ARM: the byte and an edge side byte
    input [3:0] mod_type,
    input hf14a_sel,                    // the HF ISO14443A major mode is selected
    input [10:0] edge_detect_threshold,
    input [10:0] edge_detect_threshold_high,

    output ssp_din,
    output reg ssp_frame,
    output reg ssp_clk,
    output adc_clk,
    output debug
);

// The PM5's ADC is inverting (for HF).
assign adc_clk = ~ck_1356meg;

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Reader -> PM3: pauses relative to the signal itself
// The stock detectors need a pause to drive the ADC to its rail, which stops beyond ~3 cm. Here a pause is the 10-bit sample
// above the idle level by more than half the highest pause seen (at least edge_detect_threshold * 8) for 15 samples in a row;
// a tag's subcarrier stays under a quarter of that and swings within 8 samples. Once a pause has clipped, a pause must sit at
// the rail for 20 samples instead (a clipping tag reaches it too, for at most 14). A pause ends when the sample falls below
// the idle level, but lasts at least 36 samples: the ARM samples it every 16 and takes 2 or 3 slots as a pause.
// A frame's first pause (the reader quiet) may also pass 15 samples above the floor, with no sample more than 32 under the
// idle level in the last 63 (a tag's overshoot rises within 9 samples of its last swing down) and, within 16 blocks of tag
// subcarrier, 4 times the floor (reader pauses are 390 - 580 over idle from contact to 4.4 cm). A first pause learns the
// peak and the clip flag from its frame; if no second pause follows (every frame has two) the old ones come back.
reg [9:0] rd_x;
reg [9:0] rd_base = 10'd448;    // idle level of the AC coupled input, slewed 1 code per 64 samples while the reader is quiet
reg [9:0] rd_peak = 10'd0;      // highest pause excursion since the reader's frame began
reg [3:0] rd_run;               // samples in a row above the threshold
reg [3:0] rd_runf = 4'd0;       // samples in a row above the floor
reg [4:0] rd_rr;                // samples in a row at the rail
reg rd_clip = 1'b0;             // a pause has clipped since the reader's frame began
reg [5:0] rd_qb = 6'd63;        // samples since the input was last more than 32 under the idle level, up to 63
reg [4:0] iq_tq = 5'd16;        // blocks since the tag detector last saw subcarrier, up to 16 (below)
reg [9:0] rd_peak_o;            // rd_peak, rd_clip before this frame's first pause
reg rd_clip_o;
reg rd_one = 1'b0;              // this frame has one pause so far
reg [5:0] rd_w;                 // samples since the pause began
reg rd_ah = 1'b1;
reg rd_dm = 1'b0;
reg rd_sniff;
reg [8:0] rd_quiet;
reg [5:0] rd_tick;
wire signed [10:0] rd_exc = $signed({1'b0, rd_x}) - $signed({1'b0, rd_base});
wire [9:0] rd_floor = {1'b0, edge_detect_threshold[5:0], 3'b000};
wire rd_above_f = ~rd_exc[10] && (rd_exc[9:0] > rd_floor);
// above max(peak / 2, floor): above both (no max to compute; the same for the quarter and eighth below)
wire rd_above = rd_above_f && (rd_exc[9:0] > {1'b0, rd_peak[9:1]});
wire rd_below = rd_exc[10];
wire rd_rail = &rd_x[9:2];
wire rd_near = (rd_exc[10:6] == 5'b00000 || rd_exc[10:6] == 5'b11111);   // within 64 codes of the idle level
wire rd_above_f4 = ~rd_exc[10] && ({1'b0, rd_exc[9:5]} >= edge_detect_threshold[5:0]);    // 4 times the floor
wire rd_first = ~rd_dm && (&rd_qb) && (iq_tq[4] || rd_above_f4) && rd_above_f && rd_runf == 4'd14;   // a frame's first pause
// A reader frame begins >= 1172 fc after a card's answer, never right after the card's subcarrier swung up from under the
// idle level, while the card's overshoot after a burst always comes right after such a swing. So outside a reader frame no
// pause begins (nor is a tag slot blanked for one) within 255 samples of two such swings within 32 samples (one per
// subcarrier cycle). A swing is a rise of more than 24 in one sample from more than 32 under the idle level.
reg [9:0] rd_xp;                // the last sample
reg rd_dp = 1'b0;               // it was more than 32 under the idle level
reg [5:0] rd_qs = 6'd63;        // samples since the input swung up from there, up to 63 (a swing: a run of such rises)
reg [7:0] rd_qo = 8'd255;       // samples since a swing came within 32 of the last one, up to 255
reg rd_swq = 1'b0;
wire signed [10:0] rd_dx = $signed({1'b0, rd_x}) - $signed({1'b0, rd_xp});
wire rd_swing = rd_dp && ~rd_dx[10] && (|rd_dx[9:5] || (&rd_dx[4:3] && |rd_dx[2:0]));   // rose more than 24
wire rd_sw0 = rd_swing && ~rd_swq;
wire rd_sg = rd_dm || (&rd_qo);
wire rd_start106 = rd_sg && (rd_first || (rd_clip ? (rd_rail && rd_rr == 5'd19) : (rd_above && rd_run == 4'd14)));
reg rd_qwin;
// The idle level follows the carrier only within 64 codes; a steady carrier (64 samples all within 32 codes of the first,
// off the rails) more than 32 codes from it moves it there at once. Not within 16 blocks of tag subcarrier: inside a long
// answer a 1 then a 0 leaves 128 samples at the answer's level, not the carrier's.
reg [9:0] rd_cx;                // the window's first sample
reg rd_cwin;                    // all samples so far within 32 codes of it
wire signed [10:0] rd_cd = $signed({1'b0, rd_x}) - $signed({1'b0, rd_cx});
wire rd_cnear = (rd_cd[10:5] == 6'd0) || (rd_cd[10:5] == 6'h3F);           // -32 .. +31
wire rd_cfar = ~((rd_exc[10:5] == 6'd0) || (rd_exc[10:5] == 6'h3F));       // the base more than 32 off
wire rd_cmid = (rd_cx[9:6] != 4'd0) && (rd_cx[9:6] != 4'hF);               // not at a rail (64 .. 959)
wire rd_tag;                    // a clipping tag modulated within the last 256 samples (below): no pause can begin
// At the PPS rates pauses are shorter and weaker than the 106 ones the peak was learned from. 212: 12 samples above a
// quarter of the peak, clipped or not; pauses are held off while an answer is decoded (rd_hb_busy) and while a clipping
// tag dips (rd_tag).
wire rd_hbr = (rate_rdr != 2'd0);
// 848: a byte to the ARM every 32 samples (the same format: 4 reader slots of 8 samples, 2 tag bits)
wire rate848 = (rate_rdr == 2'd3) || (rate_tag == 2'd3);
wire rd_hb_busy;                // a PPS rate answer is being decoded (below): the reader may not send
wire rd_above4 = rd_above_f && (rd_exc[9:0] > {2'b00, rd_peak[9:2]});
reg [3:0] rd_run4;              // samples in a row above a quarter of the peak
// 848: a frame's later pauses sag under a run of them. Inside a reader frame (rd_dm) the card cannot send, so there 3
// samples above an eighth of the peak start a pause (narrow bumps further off), 5 samples after the rise as with 6 in a
// row above a quarter, which the first pause still needs.
wire rd_above8 = rd_above_f && (rd_exc[9:0] > {3'b000, rd_peak[9:3]});
reg [3:0] rd_run8;              // samples in a row above an eighth of the peak
reg [3:0] rd_s8 = 4'd15;        // samples since the input last rose above an eighth (15: long ago)
reg rd_b8 = 1'b0;               // and it stayed there 3 samples: a bump, not a ripple
reg rd_f106 = 1'b0;             // a 106 pause since the reader was last quiet (below): no bump rule
// 848 at contact: a frame's first two pauses merge at the rail with a dip of 1 - 4 samples between them. Inside a frame
// whose pauses clip, a return to the rail after at least 10 samples there and at most 6 off it, above a quarter of the
// peak all the while, is a start, 5 samples on (as with 6 in a row). No 106 pause dips so.
reg rd_rail_q = 1'b0;
reg [2:0] rd_dipn = 3'd0;       // samples off the rail in this dip, up to 6
reg rd_dipok = 1'b0;            // this dip can be the gap between two pauses
reg rd_rdip = 1'b0;             // back at the rail after such a dip
wire rd_start_dip = rate848 && rd_clip && rd_dm && rd_rdip && rd_rr == 5'd4;
wire rd_dip_back = rd_rail && ~rd_rail_q && rd_dipok;
wire rd_start848 = (rd_above4 && rd_run4 == 4'd5) || (rd_dm && ~rd_f106 && rd_s8 == 4'd5 && rd_b8) || rd_start_dip;
// 424: narrow pauses, above an eighth of the peak: 12 samples for a frame's first pause, after 32 quiet samples (a
// clipping card's half cycles sit at the top for 8), and 8 inside a frame (the card's dips still hold pauses off)
wire rd_start424 = (rate_rdr != 2'd2) ? (rd_above4 && rd_run4 == 4'd11)
                                      : rd_above8 && (rd_dm ? rd_run8 == 4'd7 : (rd_run8 == 4'd11 && rd_qb[5]));
wire rd_start = ~rd_tag && ~rd_hb_busy && (rd_hbr ? (rate848 ? rd_start848 : rd_start424)
                                                  : rd_start106);
wire rd_fp = rd_ah && rd_start && ~rd_dm && ~rd_hbr;  // a 106 frame's first pause begins: learn the peak and the flag again
// the modes the ARM sets between two sniffs have minor mode 0 too: a new sniff is a new selection of the 14a major mode
wire rd_in_sniff = hf14a_sel && (mod_type == `FPGA_HF_ISO14443A_SNIFFER);
// a pause ends below the idle level after at least rd_wmin samples, after rd_wcap whatever the level (424: pause starts
// can be 32 samples apart; 848: 8 sample slots)
wire [5:0] rd_wmin = rate848 ? 6'd7 : (rate_rdr == 2'd2) ? 6'd16 : 6'd35;
wire [5:0] rd_wcap = rate848 ? 6'd10 : (rate_rdr == 2'd2) ? 6'd20 : 6'd63;
// A 106 pause at a PPS rate (the reader starting over with a REQA / WUPA, or the field going off) has to reach the ARM's
// 106 decoders whole: one still above half the peak when the short hold would end is held as at 106 (848 pauses stay
// above half for at most 13 samples, a 106 one for 44). Until the reader is quiet again the bump rule is off.
reg rd_lp = 1'b0;               // this pause is a 106 one
reg rd_hd = 1'b0;               // this pause has been under half the peak since it began
wire rd_lpn = rd_lp || (rd_hbr && rd_w == rd_wcap && rd_above && ~rd_hd);
wire [5:0] rd_wmin_e = rd_lpn ? 6'd35 : rd_wmin;
wire [5:0] rd_wcap_e = rd_lpn ? 6'd63 : rd_wcap;
// not if it comes back to the rail after a dip (merged 848 pauses at contact) or falls under half the peak within 20
// samples (106 pauses stay above half for 34+)
wire rd_cancel106 = ~rd_ah && rd_lp && rate848 && rd_w < 6'd20 && ((rd_clip && rd_dip_back) || ~rd_above);
wire [3:0] rd_uh_n = rd_w[3:0] + 4'd7;                        // rd_w - 9, the samples since w = 10 (1 .. 10)
wire [15:0] rd_uh_t = 16'h7FFF >> ~rd_uh_n;                   // rd_uh_n ones (a constant shifted: LUTs, no carry chain)
wire [9:0] rd_unhold = rd_uh_t[9:0];                          // they go back to carrier
wire rd_lp_set = ~rd_ah && rd_lpn && ~rd_lp;                  // this pause is found to be a 106 one now (at w = 10)
wire [15:0] rd_wmask = (|rd_w[5:4] || &rd_w[3:0]) ? 16'hFFFF : (16'hFFFF >> ~rd_w[3:0]);   // its samples so far

always @(negedge adc_clk)
begin
    rd_x <= adc_d10;                    // registered: the ADC outputs change late in this clock's cycle
    rd_tick <= rd_tick + 1'b1;
    rd_run <= ~rd_above ? 4'd0 : (rd_run == 4'd15) ? 4'd15 : rd_run + 1'b1;
    rd_runf <= ~rd_above_f ? 4'd0 : (rd_runf == 4'd15) ? 4'd15 : rd_runf + 1'b1;
    rd_qb <= (rd_below && ~&rd_exc[9:5]) ? 6'd0 : (&rd_qb) ? rd_qb : rd_qb + 1'b1;
    rd_xp <= rd_x;
    rd_dp <= rd_below && ~&rd_exc[9:5];
    rd_swq <= rd_swing;
    rd_qs <= rd_sw0 ? 6'd0 : (&rd_qs) ? rd_qs : rd_qs + 1'b1;
    rd_qo <= (rd_sw0 && ~rd_qs[5]) ? 8'd0 : (&rd_qo) ? rd_qo : rd_qo + 1'b1;
    rd_run4 <= ~rd_above4 ? 4'd0 : (rd_run4 == 4'd15) ? 4'd15 : rd_run4 + 1'b1;
    rd_run8 <= ~rd_above8 ? 4'd0 : (rd_run8 == 4'd15) ? 4'd15 : rd_run8 + 1'b1;
    if (rd_above8 && rd_run8 == 4'd0)
    begin
        rd_s8 <= 4'd1;
        rd_b8 <= 1'b0;
    end
    else
    begin
        if (rd_s8 != 4'd15)
            rd_s8 <= rd_s8 + 1'b1;
        if (rd_above8 && rd_run8 == 4'd2)
            rd_b8 <= 1'b1;
    end
    rd_rr <= ~rd_rail ? 5'd0 : (rd_rr == 5'd31) ? 5'd31 : rd_rr + 1'b1;
    rd_rail_q <= rd_rail;
    if (rd_rail_q && ~rd_rail)
    begin
        rd_dipok <= (rd_rr >= 5'd10) && rd_above4;      // left the rail
        rd_dipn <= 3'd1;
        rd_rdip <= 1'b0;
    end
    else if (~rd_rail)
    begin
        if (rd_dipn != 3'd6)
            rd_dipn <= rd_dipn + 1'b1;
        if (rd_dipn == 3'd6 || ~rd_above4)
            rd_dipok <= 1'b0;
    end
    else if (~rd_rail_q)
    begin
        rd_rdip <= rd_dipok;                            // back at the rail
        rd_dipok <= 1'b0;
    end
    else if (rd_rr == 5'd4)
        rd_rdip <= 1'b0;                                // taken (or not) 5 samples on
    if (rd_ah)
    begin
        if (rd_start)
        begin
            rd_ah <= 1'b0;
            rd_w <= 6'd0;
            rd_lp <= 1'b0;
            rd_hd <= ~rd_above;
        end
    end
    else
    begin
        if (rd_w != 6'd63)
            rd_w <= rd_w + 1'b1;
        if (~rd_above)
            rd_hd <= 1'b1;
        if (rd_lpn)
        begin
            rd_lp <= 1'b1;
            rd_f106 <= 1'b1;
        end
        // a pause ends after 64 samples whatever the level, so a wrong idle level cannot hold "reader active" for good
        if ((rd_below && rd_w >= rd_wmin_e) || rd_w == rd_wcap_e)
            rd_ah <= 1'b1;
        // merged 848 pauses at contact stay above half the peak through the hold and were held as a 106 one: the hold
        // ends where they come back to the rail (the pause shown 10 long, rd_hist), and the dip rule starts the next one
        if (rd_cancel106)
        begin
            rd_ah <= 1'b1;
            rd_lp <= 1'b0;
            rd_f106 <= 1'b0;
        end
    end

    // reader active: a pause within the last 256 samples
    if (~rd_ah)
    begin
        rd_dm <= 1'b1;
        rd_quiet <= 9'd0;
    end
    else if (rd_quiet == 9'd255)
    begin
        rd_dm <= 1'b0;
        rd_f106 <= 1'b0;
    end
    else
        rd_quiet <= rd_quiet + 1'b1;

    // the idle level follows the carrier only while nothing happens: one step per 64 samples, and only after 64 samples
    // all within 64 codes of it (a clipping tag's swings walked it away, so pauses could no longer end)
    if (rd_tick == 6'd0)
        rd_qwin <= 1'b1;
    else if (~rd_near)
        rd_qwin <= 1'b0;
    if (rd_tick == 6'd0)
    begin
        rd_cx <= rd_x;
        rd_cwin <= 1'b1;
    end
    else if (~rd_cnear)
        rd_cwin <= 1'b0;
    if (rd_tick == 6'd0 && rd_cwin && rd_cnear && rd_cfar && rd_cmid && iq_tq[4])
        rd_base <= rd_x;                                    // steady carrier, the base far off: there at once
    else if (~rd_dm && rd_tick == 6'd0 && rd_qwin && rd_near && rd_exc != 11'sd0)
        rd_base <= rd_base + {{9{rd_exc[10]}}, 1'b1};      // -1 / +1 (one adder)

    rd_sniff <= rd_in_sniff;
    if (rd_in_sniff && ~rd_sniff)
    begin
        // each sniff starts over (last, so it wins over the updates above)
        rd_peak <= 10'd0;
        rd_clip <= 1'b0;
        rd_ah <= 1'b1;
        rd_dm <= 1'b0;
        rd_quiet <= 9'd0;
        rd_base <= 10'd448;
        rd_one <= 1'b0;
        rd_f106 <= 1'b0;
    end
    else
    begin
        if (rd_fp)
        begin
            rd_peak_o <= rd_peak;
            rd_clip_o <= rd_clip;
            rd_peak <= 10'd0;
            rd_clip <= 1'b0;
            rd_one <= 1'b1;
        end
        else if (rd_one && rd_ah && rd_start)
            rd_one <= 1'b0;                     // a second pause: a reader frame
        else if (rd_one && rd_ah && rd_quiet == 9'd255)
        begin
            rd_peak <= rd_peak_o;               // one pause, then quiet: no frame, the old state back
            rd_clip <= rd_clip_o;
            rd_one <= 1'b0;
        end
        if (~rd_ah && ~rd_exc[10] && rd_exc[9:0] > rd_peak)
            rd_peak <= rd_exc[9:0];
        if (~rd_ah && rd_rail && rd_rr == 5'd31)
            rd_clip <= 1'b1;                    // sat at the rail 32 samples (3.2 cm pauses touch it for ~6)
    end
end

// the reader signal the sniffer uses
wire rdr_ah = rd_ah;
wire rdr_dm = rd_dm;

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// internal FPGA timing. Maximum required period is 128 carrier clock cycles for a full 8 Bit transfer to ARM. (i.e. we need a
// 7 bit counter). Adjust its frequency to external reader's clock when simulating a tag or sniffing.
reg pre_after_hysteresis;
reg [3:0] reader_falling_edge_time;
reg [6:0] negedge_cnt;

always @(negedge adc_clk)
begin
    // detect a reader signal's falling edge and remember its timing:
    pre_after_hysteresis <= rdr_ah;
    if (pre_after_hysteresis && ~rdr_ah)
    begin
        reader_falling_edge_time[3:0] <= negedge_cnt[3:0];
    end

    // adjust internal timer counter if necessary:
    if (negedge_cnt[3:0] == 4'd13 && (mod_type == `FPGA_HF_ISO14443A_SNIFFER || mod_type == `FPGA_HF_ISO14443A_TAGSIM_LISTEN) && rdr_dm
            && ~rate848)                                // 848: its one sample nudges would eat the 8 sample slots' margin
    begin
        if (reader_falling_edge_time == 4'd1)           // reader signal changes right after sampling. Better sample earlier next time.
        begin
            negedge_cnt <= negedge_cnt + 2'd2;             // time warp
        end
        else if (reader_falling_edge_time == 4'd0)      // reader signal changes right before sampling. Better sample later next time.
        begin
            negedge_cnt <= negedge_cnt;                 // freeze time
        end
        else
        begin
            negedge_cnt <= negedge_cnt + 1'b1;             // Continue as usual
        end
        reader_falling_edge_time[3:0] <= 4'd8;          // adjust only once per detected edge
    end
    else if (negedge_cnt == 7'd127)                     // normal operation: count from 0 to 127
    begin
        negedge_cnt <= 0;
    end
    else
    begin
        negedge_cnt <= negedge_cnt + 1'b1;
    end
end

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Tag -> PM3: I/Q detector
// Correlate the 10-bit samples against an 847.5 kHz (fc/16) square wave in phase and in quadrature, in 16-sample blocks
// aligned to negedge_cnt[3:0], so that each block is one 16 tick slot of the ARM's tag nibbles. The tag's subcarrier phase
// is arbitrary, so the amplitude is taken from both (|I| + |Q|, below). The block sums cancel any DC level and anything slow
// (the aliased carrier, the baseline recovery after a reader pause). Time warps of negedge_cnt only happen while the reader
// is active, where tag bits are not used. The sample and its slot are registered first (the ADC outputs change late in the
// clock's cycle); this costs one slot of latency.
reg [9:0] iq_adc;
reg [3:0] iq_ph;
always @(negedge adc_clk)
begin
    iq_adc <= adc_d10;
    iq_ph <= negedge_cnt[3:0];
end

wire [14:0] iq_x  = {5'd0, iq_adc};
wire iq_ni = iq_ph[3];                  // - for slots 8..15
wire iq_nq = iq_ph[3] ^ iq_ph[2];       // - for 4..11

reg signed [14:0] iq_acc_i, iq_acc_q;   // block being summed
reg signed [14:0] iq_blk_i, iq_blk_q;   // last complete block

// the block that completes with this sample, and the 32 sample window over it and the previous block; -x as ~x + 1,
// the 1 in the adder's carry (one carry chain, not two)
wire signed [14:0] iq_cur_i = iq_acc_i + (iq_x ^ {15{iq_ni}}) + {14'd0, iq_ni};
wire signed [14:0] iq_cur_q = iq_acc_q + (iq_x ^ {15{iq_nq}}) + {14'd0, iq_nq};
wire signed [15:0] iq_w_i = iq_cur_i + iq_blk_i;
wire signed [15:0] iq_w_q = iq_cur_q + iq_blk_q;
// |I| + |Q|, ones' complement abs (1 LSB low for negative values): little logic, and flat over phase for the square-ish
// subcarrier the front end delivers
wire [15:0] iq_abs_i = iq_w_i ^ {16{iq_w_i[15]}};
wire [15:0] iq_abs_q = iq_w_q ^ {16{iq_w_q[15]}};
wire [16:0] iq_mag = iq_abs_i + iq_abs_q;
wire [16:0] iq_floor = {9'd0, edge_detect_threshold_high[5:0], 2'b00};

// The coupling sets the subcarrier level over a wide range, and the AC coupled front end leaves a tail after each modulated
// half bit, so no fixed threshold fits every placement: each slot is judged one slot later, against 5/8 of the answer's
// peak since the reader last sent, including the next slot. The peak follows a long answer down: each slot marked
// modulated without a new peak takes 1/512 (at least 1) off it.
reg [16:0] iq_peak;
reg [16:0] iq_mag_1;
reg iq_deep_1;
wire [16:0] iq_pk_a = (iq_mag_1 > iq_peak) ? iq_mag_1 : iq_peak;
wire [16:0] iq_pk = (iq_mag > iq_pk_a) ? iq_mag : iq_pk_a;
// At contact the tag itself clips and no magnitude threshold fits every answer, but a clipping tag's subcarrier dips into
// the bottom eighth (< 128) once per cycle, one dip per slot while it modulates, and its overshoot never does. So once the
// tag clips, a slot is modulated if it holds the centre of such a dip.
wire iq_low = ~|rd_x[9:7];
reg iq_low_q;
reg [3:0] iq_tw;                // samples in the current dip
wire iq_dip_end = ~iq_low && iq_low_q;
wire [3:0] iq_back = iq_tw - {1'b0, iq_tw[3:1]};

// The tag clips when it dips there every cycle: 4 dips each ending within 24 samples of the last, the reader quiet (a field
// step dips once, an unclipped tag off centre 2 - 3 times a burst). Decided per answer: cleared while the reader sends.
reg [4:0] iq_rail_gap;
reg [1:0] iq_rail_n;
reg iq_tclip = 1'b0;
// only dips that reach under 104 count (a shallow one starts the count over)
wire iq_deep_x = (rd_x < 10'd104);
reg iq_dip_deep = 1'b0;         // the current dip reached under 104
// Both decisions lag 4 slots: the flag is only set until an answer's 5th modulated slot is decided, so it applies to the
// answer from its first slot.
reg [2:0] iq_ans = 3'd0;        // slots of this answer marked modulated by either decision, up to 5 (4 enables the hole fill)
wire iq_ans5 = iq_ans[2] & iq_ans[0];
// counted from the answer's own first slot: 16 blocks without one start it over, so does a slot 4 times as strong as any
// since the reader's frame (a card's processing noise before its answer)
wire iq_jump = ({2'b00, iq_mag_1} > {iq_peak, 2'b00});

// At contact the tag's overshoot after a burst sits at the rail as long as a clipped reader pause must. A reader may not
// send within ~1172 fc of a tag's last modulation, so no pause begins, and no slot is blanked for one, within 256 samples
// of a deep dip ending within 24 samples of the last one.
reg [7:0] rd_hold = 8'd255;
assign rd_tag = (rd_hold != 8'd255);
// both dips deep (under 104): the swing after a reader pause bottoms out near 128 at 1.6 - 3.2 cm
reg iq_last_deep = 1'b0;        // the dip before this one reached under 104

always @(negedge adc_clk)
begin
    iq_low_q <= iq_low;
    iq_tw <= ~iq_low ? 4'd0 : (iq_tw == 4'd15) ? 4'd15 : iq_tw + 1'b1;
    iq_dip_deep <= iq_low && (iq_dip_deep || iq_deep_x);
    if (iq_dip_end)
    begin
        iq_rail_gap <= 5'd0;
        iq_last_deep <= iq_dip_deep;
    end
    else if (iq_rail_gap != 5'd31)
        iq_rail_gap <= iq_rail_gap + 1'b1;
    if (rd_in_sniff && ~rd_sniff)
        rd_hold <= 8'd255;
    // at the PPS rates the swing after a reader pause reaches the rail too: while the reader sends those dips are its
    // own (848: 16 apart; 424: 27 or more), and only dips under 20 apart, a card's, count (none at 848)
    else if (iq_dip_end && iq_dip_deep && iq_last_deep
             && ((rd_hbr && rdr_dm) ? (~rate848 && iq_rail_gap < 5'd20) : (iq_rail_gap < 5'd24)))
        rd_hold <= 8'd0;
    else if (rd_tag)
        rd_hold <= rd_hold + 1'b1;
    if (rdr_dm || (rd_in_sniff && ~rd_sniff))
    begin
        iq_tclip <= 1'b0;
        iq_rail_n <= 2'd0;
    end
    else if (iq_dip_end)
    begin
        if (~iq_dip_deep)
            iq_rail_n <= 2'd0;
        else if (iq_rail_gap < 5'd24)
        begin
            if (iq_rail_n == 2'd3 && ~iq_ans5)
                iq_tclip <= 1'b1;
            else
                iq_rail_n <= iq_rail_n + 1'b1;
        end
        else
            iq_rail_n <= 2'd1;
    end
end

wire [16:0] iq_thr_p = {1'b0, iq_pk[16:1]} + {3'd0, iq_pk[16:3]};

// Centres of dips, per block, aligned with the I/Q blocks. At the end of a dip its centre lies half its width back: in
// this block, or (early in it) in the last one, whose flag is still to be used (the slot decision lags a slot behind).
// Only the first dip of a burst goes by its centre; a dip within 24 samples of the last goes to the slot after (with the
// centres at a slot boundary, a sample of jitter put two in one slot and none in the next).
reg iq_rl_nxt, iq_rl_cur, iq_rl_blk;
reg [2:0] iq_dl = 3'd4;         // slot of the last dip from this one: 0 next, 1 this, 2 last, 3 the one before, 4 none
wire iq_chain = (iq_rail_gap < 5'd24) && (iq_dl != 3'd4);
wire [1:0] iq_tgt = iq_chain ? ((iq_dl == 3'd0) ? 2'd0 : iq_dl[1:0] - 1'b1) : (iq_back > iq_ph) ? 2'd2 : 2'd1;
wire iq_m_nxt = iq_dip_end && (iq_tgt == 2'd0);
wire iq_m_cur = iq_dip_end && (iq_tgt == 2'd1);
wire iq_m_blk = iq_dip_end && (iq_tgt == 2'd2);
// No answer can begin within ~900 samples of the reader going quiet: for 16 blocks after that the tag slots are blank and
// the strongest block is learned; until the reader sends again a slot also has to be above twice that (a card's periodic
// noise after a SELECT passed the floor alone).
reg [16:0] iq_quiet = 17'd0;
reg [4:0] iq_qw = 5'd16;        // blocks since the reader was last active, up to 16: the learning window
wire iq_thr_lo = ~|iq_thr_p[16:8] && (iq_thr_p[7:0] < iq_floor[7:0]);  // (the floor has 8 bits)
wire [16:0] iq_thr_f = iq_thr_lo ? iq_floor : iq_thr_p;
wire iq_thr_qt = (iq_thr_f < {iq_quiet[15:0], 1'b0});
wire [16:0] iq_thr = iq_thr_qt ? {iq_quiet[15:0], 1'b0} : iq_thr_f;
wire iq_by_pk = ~iq_thr_lo && ~iq_thr_qt;   // the threshold is 5/8 of the peak (an answer's, not noise under the quiet rule)

// A tag clipping this hard dips to the rail for 3 slots of a modulated half bit, then swings and decays without dipping:
// of two modulated halves in a row (a 0 then a 1) the second has no dip. So a modulated slot (by its dip) continues into
// the next one when that and the one after both hold a sample in the bottom quarter.
reg iq_lo_cur, iq_lo_blk;
wire iq_lo = ~|rd_x[9:8];
reg iqbit;
reg [3:0] iq_sr_mag, iq_sr_dip;

// A reader pause only counts as one (and sets rdr_dm, which blanks the tag bits) some samples in; its first slots would
// read as modulation and sync the ARM's tag decoder. So any slot whose window saw a sample above the pause threshold is
// blanked; for clipped pauses 20 samples at the rail, and the two blocks before too. So is a frame's first pause (rd_fp).
reg iq_rd_cur, iq_rd_blk, iq_rd_blk_1;
wire iq_rd_src = ~rd_tag && rd_sg && (rd_clip ? (rd_rail && rd_rr >= 5'd19) : rd_above);
wire iq_rd_back = (iq_rd_src & rd_clip) | rd_fp;
// this block's slot, by magnitude and by dip
wire iq_on_ok = ~iq_deep_1 && iq_qw[4] && ~iq_rd_blk && ~iq_rd_blk_1;
wire iq_on_mag = iq_on_ok && (iq_mag_1 > iq_thr);
wire iq_on_dip = iq_on_ok && (iq_rl_blk | iq_m_blk | (iq_sr_dip[0] && iq_lo_blk && (iq_lo_cur | iq_lo)));
wire iq_fill = iq_ans[2] && iq_by_pk;

always @(negedge adc_clk)
begin
    if (iq_ph == 4'd15)
    begin
        iq_rl_nxt <= 1'b0;
        iq_rl_cur <= iq_rl_nxt | iq_m_nxt;
        iq_rl_blk <= iq_rl_cur | iq_m_cur;
    end
    else
    begin
        if (iq_m_nxt)
            iq_rl_nxt <= 1'b1;
        if (iq_m_cur)
            iq_rl_cur <= 1'b1;
        if (iq_m_blk)
            iq_rl_blk <= 1'b1;
    end
    if (iq_dip_end)
        iq_dl <= {1'b0, iq_tgt} + (iq_ph == 4'd15);
    else if (iq_ph == 4'd15 && iq_dl != 3'd4)
        iq_dl <= iq_dl + 1'b1;

    if (iq_ph == 4'd15)
    begin
        iq_lo_cur <= 1'b0;
        iq_lo_blk <= iq_lo_cur | iq_lo;
    end
    else if (iq_lo)
        iq_lo_cur <= 1'b1;

    if (iq_ph == 4'd15)
    begin
        iq_rd_cur <= 1'b0;
        iq_rd_blk <= iq_rd_cur | iq_rd_src | rd_fp;
        iq_rd_blk_1 <= iq_rd_blk | iq_rd_back;
    end
    else if (iq_rd_src | rd_fp)
    begin
        iq_rd_cur <= 1'b1;
        if (iq_rd_back)
        begin
            iq_rd_blk <= 1'b1;
            iq_rd_blk_1 <= 1'b1;
        end
    end

    if (iq_ph == 4'd15)
    begin
        iq_blk_i <= iq_cur_i;
        iq_blk_q <= iq_cur_q;
        iq_mag_1 <= iq_mag;
        iq_deep_1 <= rdr_dm;
        // both decisions go through 4 more slots, so the answer's own clip decision (made ~3 slots into its start bit)
        // also applies to its first slots
        iq_sr_mag <= {iq_sr_mag[2:0], iq_on_mag};
        iq_sr_dip <= {iq_sr_dip[2:0], iq_on_dip};
        iq_tq <= (iq_on_mag || iq_on_dip) ? 5'd0 : iq_tq[4] ? iq_tq : iq_tq + 1'b1;
        // a half bit is 3 - 5 slots: in an answer (4 modulated slots, the threshold on its peak) a clear slot between two
        // set ones is a lost one
        iqbit <= iq_tclip ? (iq_sr_dip[3] | (iq_fill & iqbit & iq_sr_dip[2]))
                          : (iq_sr_mag[3] | (iq_fill & iqbit & iq_sr_mag[2]));   // taken by tag_data one slot later
        // iq_ans + ~iq_ans5 (up to 5) as LUT equations: a 3 bit carry chain mapped larger
        if (iq_deep_1 || (iq_tq[4] && ~(iq_on_mag || iq_on_dip)))
            iq_ans <= 3'd0;
        else if (iq_on_mag || iq_on_dip)
            iq_ans <= (iq_tq[4] || iq_jump) ? 3'd1
                                            : {iq_ans[2] | (iq_ans[1] & iq_ans[0]), iq_ans[1] ^ (iq_ans[0] & ~iq_ans[2]),
                                               ~iq_ans[0] | iq_ans[2]};
        if (iq_deep_1)
            iq_peak <= 17'd0;                                // the reader is sending: next answer starts over
        else if (iq_mag_1 > iq_peak)
            iq_peak <= iq_mag_1;
        else if (iq_on_mag)
            iq_peak <= iq_peak - {9'd0, iq_peak[16:10], 1'b1};
        if (iq_deep_1)
        begin
            iq_quiet <= 17'd0;
            iq_qw <= 5'd0;
        end
        else
        begin
            if (~iq_qw[4])
                iq_qw <= iq_qw + 1'b1;
            if (~iq_qw[4] && iq_mag_1 > iq_quiet)
                iq_quiet <= iq_mag_1;
        end
    end
    if (iq_ph == 4'd0)
    begin
        iq_acc_i <= iq_x;                   // slot 0: + in both
        iq_acc_q <= iq_x;
    end
    else
    begin
        iq_acc_i <= iq_cur_i;
        iq_acc_q <= iq_cur_q;
    end
end

wire sniff_tag_bit = iqbit;

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Tag -> PM3 at 212 / 424 kbit/s (rate_tag 1 / 2): BPSK on the fc/16 subcarrier, NRZ-L, 4 blocks per bit at 212, 2 at 424
// (hb_last). An answer is 8 bits of unmodulated subcarrier (its phase is the reference, logic 1), a start bit (0), bytes LSB
// first with odd parity except the last, one bit of 0, then no subcarrier. After 4 blocks with subcarrier, I and Q of the
// next 4 are summed: sI, sQ are their signs. Per block, sI * I + sQ * Q has the sign of the projection on the reference for
// any reference phase (|cos| + |sin| > 0), no multiplier needed. The first block below 0 starts the start bit; each bit is
// the sign of the sum over its blocks. The answer ends after 2 blocks under half the preamble's amplitude. Bits go to the ARM
// in the tag nibble, {valid, bit, valid, bit} per byte, preamble and start bit left out.
reg [1:0] hb_st = 2'd0;                     // 0 idle, 1 reference, 2 waiting for the start bit, 3 bits
reg [1:0] hb_n;
reg signed [16:0] hb_ai, hb_aq;
reg hb_si, hb_sq;                           // the reference's I, Q are negative
reg [16:0] hb_lvl;
reg hb_lost;
reg signed [17:0] hb_grp;
reg [1:0] hb_gn;
reg hb_go;                                  // the start bit's group is done
reg [1:0] hb_cnt;                           // bits since to_arm was loaded
reg hb_b1, hb_b2;
reg [14:0] hb_age;                          // blocks since the lock: the reader pause hold-off ends after 16384
// A real answer's start bit comes 24 blocks after the reference (the preamble is 32 blocks, the lock takes 8). A card
// processing a command can modulate the field with a random phase, so a phase flip within 12 blocks is no preamble.
reg [3:0] hb_w;                             // blocks in state 2

wire hb_on = rd_in_sniff && (rate_tag != 2'd0);
wire [1:0] hb_last = (rate_tag == 2'd2) ? 2'd1 : 2'd3;   // last block of a bit: 4 blocks per bit at 212, 2 at 424
wire signed [15:0] hb_i = {iq_cur_i[14], iq_cur_i};
wire signed [15:0] hb_q = {iq_cur_q[14], iq_cur_q};
wire [16:0] hb_amp = (hb_i ^ {16{hb_i[15]}}) + (hb_q ^ {16{hb_q[15]}});
wire signed [16:0] hb_p = (hb_si ? -hb_i : hb_i) + (hb_sq ? -hb_q : hb_q);
wire signed [17:0] hb_sum = hb_grp + hb_p;
wire signed [16:0] hb_ri = hb_ai + iq_cur_i;
wire signed [16:0] hb_rq = hb_aq + iq_cur_q;
wire [17:0] hb_ramp = (hb_ri ^ {17{hb_ri[16]}}) + (hb_rq ^ {17{hb_rq[16]}});
// the lock starts on the 106 I/Q detector's floor per block (its 2-block window: th x 2 per block)
wire hb_present = hb_amp > ((hb_st == 2'd0) ? {10'd0, edge_detect_threshold_high[5:0], 1'b0} : hb_lvl);
// a reference under the floor is no preamble (a lock on processing noise whose phases cancelled), and 4 blocks in a row 4
// times as strong lock again
wire hb_weak = (hb_lvl[16:6] == 11'd0) && (hb_lvl[5:0] < edge_detect_threshold_high[5:0]);
wire hb_strong = ({3'b000, hb_amp} > {hb_lvl, 3'b000});
reg [1:0] hb_j = 2'd0;                      // blocks in a row hb_strong
// 848 kbit/s (rate_tag 3): one subcarrier cycle per bit, so a block decides a bit only when it sits on the bit. After the
// lock the projection on the reference is kept over a sliding 16 sample window (constant in the preamble, ramping from +A
// to -A across a flip): the start bit is where it passes -A/2 (12 blocks after the reference at least, as above), each bit
// its sign 4 samples later and every 16 after that, present while above A/4; at the end the window empties within one
// decision.
wire hb848 = (rate_tag == 2'd3);
// the window's sum as a running total's rise over 16 samples, in 14 bits (|sum| <= 8 x 1023 across a reference change):
// an upset of the total or the ring is gone 16 samples later
reg [13:0] hp_ring [0:15];                  // hp_T 16 samples ago, by block phase
reg [13:0] hp_T = 14'd0;                    // the weighted samples' running total (wraps)
reg signed [14:0] hp_A;                     // the preamble's
reg [3:0] hp_sc;                            // samples to the next bit decision
wire hp_wi = ~iq_ph[3] ^ hb_si;             // the reference's I weight here is +1
wire hp_wq = ~(iq_ph[3] ^ iq_ph[2]) ^ hb_sq;
wire signed [10:0] hp_s = (hp_wi && hp_wq) ? $signed({1'b0, iq_adc}) : (~hp_wi && ~hp_wq) ? -$signed({1'b0, iq_adc}) : 11'sd0;
wire [13:0] hp_Tn = hp_T + {{3{hp_s[10]}}, hp_s};
wire [13:0] hp_d = hp_Tn - hp_ring[iq_ph];
wire signed [14:0] hp_next = {hp_d[13], hp_d};   // the last 16 weighted samples' sum
// |P| > A/4 in one carry chain: |P| = (P ^ sign) + sign, and x + 1 > t is the carry of x + ~t + 1
wire [15:0] hp_pd = {1'b0, hp_next ^ {15{hp_next[14]}}} + {1'b0, ~{2'b00, hp_A[14:2]}} + {15'd0, hp_next[14]};
wire hp_pres = hp_pd[15];
wire signed [15:0] hp_lo = hp_next + $signed({2'b00, hp_A[14:1]});   // P < -A/2: its sign
wire hp_dec = hb848 && (hb_st == 2'd3) && (hp_sc == 4'd0);   // a bit decision (the first one: the start bit)
wire hb_push = hb_on && ~rdr_dm && hb_go
               && (hb848 ? hp_dec : ((iq_ph == 4'd15) && (hb_st == 2'd3) && (hb_gn == hb_last)));
wire hb_bit = hb848 ? ~hp_next[14] : (~hb_sum[17] && (hb_sum != 18'sd0));

always @(negedge adc_clk)
begin
    if (rate848 ? (negedge_cnt[4:0] == 5'd31) : (negedge_cnt[5:0] == 6'd63))
    begin
        hb_cnt <= hb_push ? 2'd1 : 2'd0;    // taken into to_arm on this edge (848: a bit decided on it goes in the next)
        if (hb_push)
            hb_b1 <= hb_bit;
    end
    else if (hb_push)
    begin
        if (hb_cnt == 2'd0)
            hb_b1 <= hb_bit;
        else
            hb_b2 <= hb_bit;
        if (hb_cnt != 2'd2)
            hb_cnt <= hb_cnt + 1'b1;
    end
    if (hb848)
    begin
        hp_ring[iq_ph] <= hp_Tn;
        hp_T <= hp_Tn;
    end
    if (~hb_st[1])
        hb_age <= 15'd0;
    else if (iq_ph == 4'd15 && ~hb_age[14])
        hb_age <= hb_age + 1'b1;

    if (~hb_on || rdr_dm || (rd_in_sniff && ~rd_sniff))
    begin
        hb_st <= 2'd0;
        hb_n <= 2'd0;
        hb_lost <= 1'b0;
        hb_j <= 2'd0;
    end
    else
    begin
        if (hb848 && hb_st == 2'd2 && hb_w != 4'd0 && hp_lo[15])
        begin
            if (hb_w < 4'd12)
            begin
                hb_st <= 2'd0;                  // no preamble: the phase flipped within 12 blocks
                hb_n <= 2'd0;
            end
            else
            begin
                hb_st <= 2'd3;                  // the start bit: decided 4 samples on, the window then inside it
                hp_sc <= 4'd4;
                hb_go <= 1'b0;
                hb_lost <= 1'b0;
            end
        end
        if (hb848 && hb_st == 2'd3)
        begin
            if (hp_sc != 4'd0)
                hp_sc <= hp_sc - 1'b1;
            else
            begin
                hp_sc <= 4'd15;
                hb_go <= 1'b1;
                hb_lost <= ~hp_pres;
                if (~hp_pres && hb_lost)
                begin
                    hb_st <= 2'd0;              // the answer is over
                    hb_n <= 2'd0;
                end
            end
        end
    if (iq_ph == 4'd15)
    begin
        case (hb_st)
        2'd0:
            if (~hb_present)
                hb_n <= 2'd0;
            else if (hb_n == 2'd3)
            begin
                hb_st <= 2'd1;
                hb_n <= 2'd0;
                hb_ai <= 17'sd0;
                hb_aq <= 17'sd0;
            end
            else
                hb_n <= hb_n + 1'b1;
        2'd1:
        begin
            hb_ai <= hb_ri;
            hb_aq <= hb_rq;
            hb_n <= hb_n + 1'b1;
            if (hb_n == 2'd3)
            begin
                hb_si <= hb_ri[16];
                hb_sq <= hb_rq[16];
                hb_lvl <= hb_ramp[17:1] >> 2;   // 4 blocks: half a block's amplitude
                hb_st <= 2'd2;
                hb_w <= 4'd0;
                hp_A <= 15'sd0;                 // 848: the preamble's projection, its highest so far
            end
        end
        2'd2:
        begin
            if (hb_w != 4'd15)
                hb_w <= hb_w + 1'b1;
            if (hb_w == 4'd0 && hb_weak)
            begin
                hb_st <= 2'd0;                  // a reference under the floor: no preamble
                hb_n <= 2'd0;
            end
            else if (hb848)
            begin
                if (hp_next > hp_A)
                    hp_A <= hp_next;            // (the start bit is decided per sample, from the first block on)
            end
            else if (hb_p[16] && hb_w < 4'd12)
            begin
                hb_st <= 2'd0;                  // no preamble: the phase flipped within 12 blocks
                hb_n <= 2'd0;
            end
            else if (hb_p[16])
            begin
                hb_st <= 2'd3;
                hb_grp <= {hb_p[16], hb_p};
                hb_gn <= 2'd1;
                hb_go <= 1'b0;
            end
        end
        2'd3:
            if (hb848)
                ;                               // decided per sample
            else if (hb_gn == hb_last)
            begin
                hb_go <= 1'b1;
                hb_grp <= 18'sd0;
                hb_gn <= 2'd0;
            end
            else
            begin
                hb_grp <= hb_sum;
                hb_gn <= hb_gn + 1'b1;
            end
        endcase
        if (hb_st[1] && hb_strong)
        begin
            hb_j <= hb_j + 1'b1;
            if (hb_j == 2'd3)
            begin
                hb_st <= 2'd0;                  // the next block starts the reference (its sums cleared there)
                hb_n <= 2'd3;
            end
        end
        else
            hb_j <= 2'd0;
        // the answer is over (last, so it wins over the above; 848: per sample, above, once in its bits). Before the start
        // bit also at 848: a lock on an answer's fading tail would wait there through the gap, holding reader pauses off
        if (hb_st[1] && (~hb848 || hb_st == 2'd2))
        begin
            hb_lost <= ~hb_present;
            if (~hb_present && hb_lost)
            begin
                hb_st <= 2'd0;
                hb_n <= 2'd0;
            end
        end
    end
    end
end

wire [3:0] hb_nib = {hb_cnt != 2'd0, hb_b1, hb_cnt[1], hb_b2};
// No reader pause can begin once an answer's preamble has locked (the subcarrier's phase flips cross a cold pause
// threshold). A real pause qualifies long before a lock and resets this; bounded beyond the longest frame (256 bytes =
// 9216 blocks), and not for a lock too faint to fake a pause (a subcarrier swings at most hb_lvl / 4 from the base, under
// peak / 16 here).
wire hb_faint = (hb_lvl[16:8] == 9'd0) && (hb_lvl[7:0] < rd_peak[9:2]);
assign rd_hb_busy = hb_on && hb_st[1] && ~hb_age[14] && ~hb_faint;

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Tag+Reader -> PM3
// sample 4 bits reader data and 4 bits tag data for sniffing
reg [3:0] reader_data;
reg [3:0] tag_data;

// At 212 / 424 a frame's pauses start on a grid, all at one phase of the 16 sample reader slots, and where that phase is
// the sampling instant a sample of jitter moved single pauses a slot. So the reader level is delayed by a tap, set at each
// frame's first pause to put the pause starts mid-slot (the reader was quiet before it: changing the tap cannot glitch),
// with 16 samples of room for the later pauses, which come out of a saturated front end later and later: inside a frame
// the tap follows them, a start that would show e samples off its point moving it by e. A later start shortens the delay,
// which cannot show a start that was not there; a longer one is taken only where the level it switches to is not a pause
// under carrier. At 848 the later pauses jump around within a few samples: a fixed window instead (rd_e8 below), the first
// pause with 8 samples more delay for the merged pause rewrite.
reg [31:0] rd_hist = 32'hFFFFFFFF;          // rdr_ah, 1 .. 32 samples ago
reg [4:0] rd_dly = 5'd0;
reg rd_lvl_q;
// 848 sends pause starts, not the level: a slot reads pause when a delayed start came since the last slot sample (pause
// starts are at least 2 slots apart, so a carrier slot always lies between them). A 106 pause (rd_lp) shows as its level:
// the ARM's 106 decoders take it from pairs of slots.
reg [17:0] rd_lph = 18'd0;                  // rd_lp, 1 .. 18 samples ago (the 848 tap is at most 17)
reg rd_lvl_dq = 1'b1;
reg rd_s848 = 1'b0;                         // a delayed start since the last slot sample
wire rd_lvl_d = rd_hist[rd_dly];
// the early move below (2 more delay) shows 2 samples of history again: no pause start counts in them
reg [1:0] rd_rep = 2'd0;
wire rd_ev848 = rd_lvl_dq && ~rd_lvl_d && ~|rd_rep;
wire rdr_lvl = rd_hbr ? (rate848 ? ~(rd_s848 || rd_ev848 || (~rd_lvl_d && rd_lph[rd_dly])) : rd_lvl_d) : rdr_ah;
// where this start would show with the tap as it is: (cnt + 1 + tap) mod 16 against 7
wire [3:0] rd_ph = negedge_cnt[3:0] + 4'd1 + rd_dly[3:0];
wire [3:0] rd_e16 = rd_ph - 4'd7;
wire signed [5:0] rd_e = $signed({{2{rd_e16[3]}}, rd_e16});
// 848: the first pause shows 6 before the 8 sample instant, so a slot takes the starts from 1 early to 6 late; once one is
// 3 - 5 late the window moves 2 later for the rest of the frame
wire [2:0] rd_e8 = rd_ph[2:0] - 3'd2;
reg rd_late = 1'b0;
// weak frames' pauses are bumps under the rail at the window's early end, where a baseline wander shows them early: after
// a pause that did not reach the rail the window moves 2 earlier for the rest of the frame instead (-3 .. +4)
reg rd_early = 1'b0;
reg rd_fclip = 1'b0;            // at the rail since the last pause start (its tail, or this one's rise)
wire signed [6:0] rd_dly_t = $signed({2'b00, rd_dly}) - rd_e;
wire rd_dly_ok = (rd_dly_t >= 7'sd1) && (rd_dly_t <= 7'sd31)
                 && ~(rd_e < 6'sd0 && rd_hist[rd_dly] && ~rd_hist[rd_dly_t[4:0]]);

always @(negedge adc_clk)
begin
    rd_hist <= {rd_hist[30:0], rdr_ah} | {22'd0, rd_cancel106 ? rd_unhold : 10'd0};
    // a 106 pause is found so 10 samples in: it shows as level from its start (those samples are still in the tap);
    // merged 848 pauses taken for one (rd_cancel106) are not one after all
    rd_lph <= rd_cancel106 ? ({rd_lph[16:0], 1'b0} & ~{{2{|rd_w[5:4] || &rd_w[3:0]}}, rd_wmask})
                           : ({rd_lph[16:0], rd_lp} | (rd_lp_set ? 18'h007FF : 18'd0));
    rd_lvl_dq <= rd_lvl_d;
    rd_rep <= {rd_rep[0], 1'b0};
    if (negedge_cnt[2:0] == 3'd0)
        rd_s848 <= 1'b0;                    // taken by reader_data on this edge
    else if (rd_ev848)
        rd_s848 <= 1'b1;
    rd_lvl_q <= rdr_ah;
    if (rd_hbr && rd_lvl_q && ~rdr_ah)
        rd_fclip <= 1'b0;               // a pause starts: whether it clips is found from here on
    else if (rd_rail)
        rd_fclip <= 1'b1;
    if (rd_hbr && rd_lvl_q && ~rdr_ah)
    begin
        if (~rdr_dm)
        begin
            rd_dly <= rate848 ? {2'b01, 3'd1 - negedge_cnt[2:0]} : {1'b1, 4'd6 - negedge_cnt[3:0]};
            rd_late <= 1'b0;
            rd_early <= 1'b0;
        end
        else if (rate848)
        begin
            if (~rd_late && ~rd_early && ~rd_fclip)
            begin
                rd_dly <= rd_dly + 5'd2;
                rd_early <= 1'b1;
                rd_rep <= 2'b11;
            end
            else if (~rd_late && ~rd_early && rd_e8 >= 3'd3 && rd_e8 <= 3'd5)
            begin
                rd_dly <= rd_dly - 5'd2;
                rd_late <= 1'b1;
            end
        end
        else if (rd_dly_ok)
            rd_dly <= rd_dly_t[4:0];
    end
end

always @(negedge adc_clk)
begin
    if (rate848 ? (negedge_cnt[2:0] == 3'd0) : (negedge_cnt[3:0] == 4'd0))
        reader_data[3:0] <= {reader_data[2:0], rdr_lvl};
    if(negedge_cnt[3:0] == 4'd0)
        tag_data[3:0] <= {tag_data[2:0], sniff_tag_bit};
end

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// FPGA -> ARM communication:
// buffer 8 bits data to be sent to ARM. Shift them out bit by bit.
reg [7:0] to_arm;

always @(negedge adc_clk)
begin
    if (rate848 ? (negedge_cnt[4:0] == 5'd31) : (negedge_cnt[5:0] == 6'd63))   // fill the buffer (848: every 32)
    begin
        if (mod_type == `FPGA_HF_ISO14443A_SNIFFER)
        begin
            if(rdr_dm)                                      // a reader is sending (or there's no field at all)
            begin
                to_arm <= {reader_data[3:0], 4'b0000};      // don't send tag data
            end
            else
            begin
                to_arm <= {reader_data[3:0], hb_on ? hb_nib : tag_data[3:0]};
            end
        end
    end

    if(rate848 && negedge_cnt[1:0] == 2'b00 && mod_type == `FPGA_HF_ISO14443A_SNIFFER)    // 848: shift at 4x
    begin
        if(negedge_cnt[4:0] != 5'd0)
            to_arm[7:1] <= to_arm[6:0];
    end
    else if(~rate848 && negedge_cnt[2:0] == 3'b000 && mod_type == `FPGA_HF_ISO14443A_SNIFFER)    // shift at double speed
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
// Edge timestamps: with link16 the sniffer sends one 16-bit word per byte period (64 samples): the byte above and a side
// byte with one edge event and its age, so the ARM can time 106 frames to the sample; idle words carry a 5-bit sequence
// number. 848 (a byte per 32 samples): the word is two bytes, the period's first half and the second.
wire [7:0] arm_byte = rdr_dm ? {reader_data[3:0], 4'b0000}
                             : {reader_data[3:0], hb_on ? hb_nib : tag_data[3:0]};
reg [15:0] to_arm16 = 16'd0;
reg [7:0] arm_byte_a = 8'd0;    // 848: the byte of the word's first half
reg [4:0] ed_seq = 5'd1;        // word number mod 32 (word 0 is the power-up one)

// The side byte: one event per word, its age in samples to the word's load edge (so a time warp after the edge moves it
// with the word: the ARM puts an event of age a in word N at 64 N + 63 - a):
//   0aaaaaaa  a reader pause's lead (the rd_above rise) once rd_start takes the pause; age 1..127
//   10aaaaaa  a tag answer's onset (DE32 below), the decision's age - 3
//   110wwwww  a clean pause's width - 24 (lead to its last rd_above sample; rd_rr under 12 all through the hold)
//   111sssss  idle, s = the word number mod 32 (the ARM checks for lost words)
// a frame's first lead > another lead > the onset > the width > idle; the others wait, their ages counting; one whose age
// no longer fits is dropped (never sent wrong). Events at 106 only: at 212 / 424 the words are idle.
wire ed_106 = (rate_rdr == 2'd0) && (rate_tag == 2'd0);
reg ed_above_q = 1'b0;
reg ed_ah_q = 1'b1;
reg [7:0] ed_lage = 8'd255;     // samples since the last rd_above rise (saturating)
reg ed_lval = 1'b0;             // a rise was seen
reg ed_pf = 1'b0, ed_pl = 1'b0; // pending leads: a frame's first (rdr_dm low), another
reg [7:0] ed_pf_age = 8'd0, ed_pl_age = 8'd0;
reg ed_pz = 1'b0;               // a taken pause is followed (taken .. hold end): its width and whether it sat at the rail
reg [7:0] ed_pc = 8'd0;         // samples since its lead (saturating)
reg [7:0] ed_pw = 8'd0;
reg ed_wv = 1'b0, ed_dirty = 1'b0;
reg ed_rw = 1'b0;               // pending width
reg [4:0] ed_rw_w = 5'd0;
reg ed_pt = 1'b0;               // pending onset
reg [6:0] ed_pt_age = 7'd0;
wire ed_fall = ~rd_above && ed_above_q;
wire [7:0] ed_wnow = ed_fall ? ed_pc : ed_pw;
wire ed_dnow = ed_dirty || (rd_rr >= 5'd12);

// DE32, the tag onset: x = rd_x[9:2]; a(j) = |x(j) - x(j-8)| (ones' complement); m(j) = a(j) + .. + a(j-5). Armed after
// 192 samples in a row with m under T0 = max(10, iq_quiet / 4); then the first j, from 24 after the arming sample on, with
// 2 m(j-32) >= m(j) decides: an onset (the ARM: j - 39) when m was over T0 within the last 8 samples, a noise blip
// otherwise; none by 80 after the arming: a timeout. Reset while the reader sends or the quiet is not learned.
reg [7:0] ed_x1 = 0, ed_x2 = 0, ed_x3 = 0, ed_x4 = 0, ed_x5 = 0, ed_x6 = 0, ed_x7 = 0, ed_x8 = 0;
wire signed [8:0] ed_d = $signed({1'b0, rd_x[9:2]}) - $signed({1'b0, ed_x8});
wire [7:0] ed_a = ed_d[8] ? ~ed_d[7:0] : ed_d[7:0];
reg [7:0] ed_a1 = 0, ed_a2 = 0, ed_a3 = 0, ed_a4 = 0, ed_a5 = 0, ed_a6 = 0;
reg [10:0] ed_m = 11'd0;        // m(j), j = this row - 2
reg [10:0] ed_mline [0:31];     // m 32 samples back, read one ahead (a block RAM)
reg [4:0] ed_mc = 5'd0;
reg [10:0] ed_mt = 11'd0;       // m(j - 32)
reg [5:0] ed_up = 6'd0;         // samples since configuration, to 50 (the lines filled)
reg ed_st = 1'b0;
reg [7:0] ed_q = 8'd0;
reg [6:0] ed_ta = 7'd0;         // samples since the arming one
reg [3:0] ed_h = 4'd0;          // samples since m was last over T0, down from 8
wire ed_qbig = |iq_quiet[16:13];
wire [10:0] ed_q4 = iq_quiet[12:2];
wire [10:0] ed_t0 = ed_qbig ? 11'd2047 : (ed_q4 > 11'd10) ? ed_q4 : 11'd10;
wire ed_ge = (ed_m >= ed_t0);
wire [3:0] ed_hn = ed_ge ? 4'd8 : (ed_h != 4'd0) ? ed_h - 1'b1 : 4'd0;
wire ed_cross = ({ed_mt, 1'b0} >= {1'b0, ed_m});
wire ed_run = ~rdr_dm && iq_qw[4] && (ed_up == 6'd50);

always @(negedge adc_clk)
begin
    if (rate848 && negedge_cnt[5:0] == 6'd31)
        arm_byte_a <= arm_byte;

    // DE32's lines and sums (free running)
    {ed_x8, ed_x7, ed_x6, ed_x5, ed_x4, ed_x3, ed_x2, ed_x1} <= {ed_x7, ed_x6, ed_x5, ed_x4, ed_x3, ed_x2, ed_x1, rd_x[9:2]};
    {ed_a6, ed_a5, ed_a4, ed_a3, ed_a2, ed_a1} <= {ed_a5, ed_a4, ed_a3, ed_a2, ed_a1, ed_a};
    ed_m <= ed_m + {3'd0, ed_a} - {3'd0, ed_a6};
    ed_mline[ed_mc] <= ed_m;
    ed_mt <= ed_mline[ed_mc + 1'b1];
    ed_mc <= ed_mc + 1'b1;
    if (ed_up != 6'd50)
        ed_up <= ed_up + 1'b1;

    // leads and pauses
    ed_above_q <= rd_above;
    ed_ah_q <= rd_ah;
    if (rd_above && ~ed_above_q)
    begin
        ed_lage <= 8'd1;
        ed_lval <= 1'b1;
    end
    else if (ed_lage != 8'd255)
        ed_lage <= ed_lage + 1'b1;
    if (ed_pf && ed_pf_age != 8'd255)
        ed_pf_age <= ed_pf_age + 1'b1;
    if (ed_pl && ed_pl_age != 8'd255)
        ed_pl_age <= ed_pl_age + 1'b1;
    if (ed_pt && ed_pt_age != 7'd127)
        ed_pt_age <= ed_pt_age + 1'b1;
    if (ed_pc != 8'd255)
        ed_pc <= ed_pc + 1'b1;
    if (ed_pz)
    begin
        if (ed_fall)                            // the pause's last rd_above sample so far
        begin
            ed_pw <= ed_pc;
            ed_wv <= 1'b1;
        end
        if (rd_rr >= 5'd12)
            ed_dirty <= 1'b1;
        if (rd_ah && ~ed_ah_q)                  // the hold ended
        begin
            ed_pz <= 1'b0;
            if (~ed_dnow && (ed_wv || ed_fall) && ed_wnow >= 8'd24 && ed_wnow <= 8'd48)
            begin
                ed_rw <= 1'b1;
                ed_rw_w <= ed_wnow[4:0] - 5'd24;
            end
        end
    end
    if (rd_ah && rd_start && ed_lval)           // a pause taken: its lead goes out, its width is followed
    begin
        if (rdr_dm)
        begin
            ed_pl <= 1'b1;
            ed_pl_age <= ed_lage + 2'd2;
        end
        else
        begin
            ed_pf <= 1'b1;
            ed_pf_age <= ed_lage + 2'd2;
        end
        ed_pz <= 1'b1;
        ed_pc <= ed_lage + 1'b1;
        ed_wv <= 1'b0;
        ed_dirty <= (rd_rr >= 5'd12);
    end

    // DE32's state machine
    if (~ed_run)
    begin
        ed_st <= 1'b0;
        ed_q <= 8'd0;
        ed_h <= 4'd0;
        if (rdr_dm || ~iq_qw[4])
            ed_pt <= 1'b0;
    end
    else
    begin
        ed_h <= ed_hn;
        if (~ed_st)
        begin
            if (~ed_ge)
                ed_q <= (ed_q == 8'd255) ? ed_q : ed_q + 1'b1;
            else if (ed_q >= 8'd192)
            begin
                ed_st <= 1'b1;
                ed_ta <= 7'd1;
            end
            else
                ed_q <= 8'd0;
        end
        else
        begin
            if (ed_ta != 7'd127)
                ed_ta <= ed_ta + 1'b1;
            if (ed_ta >= 7'd24)
            begin
                if (ed_cross)
                begin
                    ed_st <= 1'b0;
                    if (ed_hn != 4'd0)          // an answer: m over T0 within the last 8
                    begin
                        ed_q <= 8'd0;
                        ed_pt <= 1'b1;
                        ed_pt_age <= 7'd0;
                    end
                end
                else if (ed_ta >= 7'd80)
                begin
                    ed_st <= 1'b0;
                    ed_q <= 8'd0;
                end
            end
        end
    end

    if (negedge_cnt[5:0] == 6'd63)
    begin
        ed_seq <= ed_seq + 1'b1;
        if (rate848)
            to_arm16 <= {arm_byte_a, arm_byte};
        else if (ed_106 && ed_pf && ed_pf_age <= 8'd127)
        begin
            to_arm16 <= {arm_byte, 1'b0, ed_pf_age[6:0]};
            ed_pf <= 1'b0;
        end
        else if (ed_106 && ed_pl && ed_pl_age <= 8'd127)
        begin
            to_arm16 <= {arm_byte, 1'b0, ed_pl_age[6:0]};
            ed_pl <= 1'b0;
        end
        else if (ed_106 && ed_pt && ed_pt_age <= 7'd63 && ~rdr_dm && iq_qw[4])
        begin
            to_arm16 <= {arm_byte, 2'b10, ed_pt_age[5:0]};
            ed_pt <= 1'b0;
        end
        else if (ed_106 && ed_rw)
        begin
            to_arm16 <= {arm_byte, 3'b110, ed_rw_w};
            ed_rw <= 1'b0;
        end
        else
            to_arm16 <= {arm_byte, 3'b111, ed_seq};
        // too old to send: dropped
        if (ed_pf && ed_pf_age > 8'd127) ed_pf <= 1'b0;
        if (ed_pl && ed_pl_age > 8'd127) ed_pl <= 1'b0;
        if (ed_pt && ed_pt_age > 7'd63) ed_pt <= 1'b0;
    end
    else if (negedge_cnt[1:0] == 2'b00 && negedge_cnt[5:0] != 6'd0)
        to_arm16[15:1] <= to_arm16[14:0];
end

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// FPGA <-> ARM communication:
// generate a ssp clock and ssp frame signal for the synchronous transfer from/to the ARM (TI mode frames)
localparam FRAME_SET_848 = 5'd28;
localparam FRAME_CLR_848 = 5'd0;
localparam FRAME_SET_8B  = 6'd56;
localparam FRAME_CLR_8B  = 6'd0;
localparam FRAME_SET_16B = 7'd112;
localparam FRAME_CLR_16B = 7'd0;

always @(negedge adc_clk)
begin
    if(mod_type == `FPGA_HF_ISO14443A_SNIFFER && link16)
    // 16-bit words: ssp_clk = adc_clk / 4, a frame per 64 samples. It falls at count 3 of each 4, not 2: a time warp
    // (+2 at negedge_cnt[3:0] == 13) skips a count 2 mod 4, which then held no edge
    begin
        if(negedge_cnt[1:0] == 2'd0)
            ssp_clk <= 1'b1;
        if(negedge_cnt[1:0] == 2'd3)
            ssp_clk <= 1'b0;
        if(negedge_cnt[5:0] == 6'd60)
            ssp_frame <= 1'b1;
        if(negedge_cnt[5:0] == 6'd0)
            ssp_frame <= 1'b0;
    end
    else
    if(mod_type == `FPGA_HF_ISO14443A_SNIFFER && rate848)
    // 848 kbit/s sniffing: ssp_clk = adc_clk / 4, ssp_frame clock = adc_clk / 32
    begin
        if(negedge_cnt[1:0] == 2'd0)
            ssp_clk <= 1'b1;
        if(negedge_cnt[1:0] == 2'd2)
            ssp_clk <= 1'b0;
        if(negedge_cnt[4:0] == FRAME_SET_848)
            ssp_frame <= 1'b1;
        if(negedge_cnt[4:0] == FRAME_CLR_848)
            ssp_frame <= 1'b0;
    end
    else if(mod_type == `FPGA_HF_ISO14443A_SNIFFER)
    // FPGA_HF_ISO14443A_SNIFFER mode (ssp_clk = adc_clk / 8, ssp_frame clock = adc_clk / 64)):
    begin
        if(negedge_cnt[2:0] == 3'd0) // High level for 4 cycles
            ssp_clk <= 1'b1;
        if(negedge_cnt[2:0] == 3'd4)// Low level for 4 cycles
            ssp_clk <= 1'b0;

        // ssp_frame rising edge indicates start of frame (TI mode: when the last ssp_clk of the byte rises)
        if(negedge_cnt[5:0] == FRAME_SET_8B)
            ssp_frame <= 1'b1;
        if(negedge_cnt[5:0] == FRAME_CLR_8B)
            ssp_frame <= 1'b0;
    end
    else
    // all other modes (ssp_clk = adc_clk / 16, ssp_frame clock = adc_clk / 128):
    begin
        if(negedge_cnt[3:0] == 4'd0) // High level for 8 cycles (rising edge at cycle 0 or 16)
            ssp_clk <= 1'b1;
        if(negedge_cnt[3:0] == 4'd8) // Low level for 8 cycles (falling edge at cycle 8)
            ssp_clk <= 1'b0;

        if(negedge_cnt[6:0] == FRAME_SET_16B) // ssp_frame rising edge indicates start of frame, sampled on falling edge of ssp_clk
            ssp_frame <= 1'b1;
        if(negedge_cnt[6:0] == FRAME_CLR_16B)
            ssp_frame <= 1'b0;
    end
end

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// FPGA -> ARM communication:
// select the data to be sent to ARM
reg bit_to_arm;

always @(negedge adc_clk)
begin

    if(mod_type == `FPGA_HF_ISO14443A_SNIFFER)
        // send sampled reader and tag data:
        bit_to_arm = link16 ? to_arm16[15] : to_arm[7];
    else
        bit_to_arm = 1'b0;                  // the sniffer image has no other 14a mode
end

assign ssp_din = bit_to_arm;

assign debug = negedge_cnt[3];

endmodule

`endif
