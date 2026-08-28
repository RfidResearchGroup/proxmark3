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

/*
  This code demodulates and modulates signal as described in ISO/IEC 18092.
  That includes packets used for Felica, NFC Tag 3, etc. (which do overlap)
  simple envelope following algorithm is used (modification of fail0verflow LF one)
  is used to combat some nasty aliasing effect with testing phone (envelope looked like sine wave)

  Speeds supported:  only 212 kbps (fc/64) for now.  Todo: 414 kbps
  though for reader, the selection has to come from ARM. modulation waits for market sprocket -doesn't really mean anything

   mod_type: bits 210:
      bit 2 : reader drive/power on/off
      bit 1 : speed bit, 0 : 212, 1 :424
      bit 0 : listen or modulate
*/

module hi_flite(
    input ck_1356meg,
    input [7:0] adc_d,
    input [3:0] mod_type,
    input ssp_dout,

    output reg ssp_din,
    output reg ssp_frame,
    output reg ssp_clk,
    output adc_clk,
    output reg pwr_lo,
    output reg pwr_hi,
    output reg pwr_oe1,
    output reg pwr_oe2,
    output reg pwr_oe3,
    output reg pwr_oe4,
    output debug
);

assign debug = 0;

wire power  = mod_type[2];
wire speed  = mod_type[1];
wire disabl = mod_type[0];
// Signal probe: stream how much the envelope is actually moving instead of
// demodulated bits, so reading distance can be measured rather than guessed.
wire probe  = mod_type[3];

// 512x64/fc  -wait before ts0, 32768 ticks
// tslot: 256*64/fc
assign adc_clk = ck_1356meg;

// Initial envelope guess, only used until the first edges are seen.
`define imin 70     // (13'd256)
`define imax 180    // (-13'd256)
`define ithrmin 91  // -13'd8
`define ithrmax 160 //  13'd8

// Narrowest hysteresis band the threshold generator will produce. An
// unmodulated carrier collapses curmin onto curmax, and without a floor the
// band would collapse with it, so every ADC noise count would look like an
// edge. This floor is also the sensitivity limit: a tag whose modulation is
// smaller than the band can never arm the edge detector, so it sets the
// reading distance.
//
// Measured on a RDV4 with the reader field on: the raw carrier ripples 4..6
// counts peak to peak, about +/- 1 after the lowpass above. +/- 4 keeps a 4x
// noise margin while halving the smallest tag modulation we can still see
// compared to sizing the floor against the unfiltered ripple.
`define minhalfband 8

// Recovery watchdog, counting samples since the demodulator was last in a
// known-good idle state (the desync in the stable branch below).
//
// Nothing else in this module can put the hysteresis band back onto the signal
// once it has drifted off it, and there are two ways to get there. The band can
// end up somewhere the signal never visits, which makes the stable branch -
// the only place thresholds are recomputed and the only place a desync can
// happen - permanently unreachable. Or try_sync can latch on with the band
// mis-positioned, where edges of one polarity keep clearing tsinceedge so the
// desync never fires either. Both freeze the slicer, and both survive the
// field being switched off between commands, because these are FPGA registers
// and only a bitstream reload clears them. The symptom is that the first
// command after the client starts works and everything after it fails on a
// signal that is plainly strong enough.
//
// 2^18 samples is 19.3 ms. The longest legal FeliCa frame, 255 bytes plus
// preamble and sync, is 9.9 ms, so this cannot fire part way through a reply.
// During quiet it fires harmlessly and keeps the band centred on the carrier.
`define stalebit 18


// Bit decisions to ignore right after the edge detector arms. try_sync is
// armed part way through a bit, so its first accumulation covers only part of
// a half-bit and the decision that follows is meaningless. Acting on it can
// latch `zero` inverted, which decodes the entire frame with the wrong
// polarity and loses the sync word. The preamble is 48 bits, so skipping the
// first couple of decisions costs nothing and lets the real preamble-to-sync
// transition be the one that locks polarity.
`define syncguard 2

`define min_bitdelay_212 8
//minimum values and corresponding thresholds
reg [8:0] curmin=`imin;
reg [8:0] curminthres=`ithrmin;
reg [8:0] curmaxthres=`ithrmax;
reg [8:0] curmax=`imax;

// Hysteresis band, derived from the tracked envelope rather than from fixed
// levels. The old code blended curmin/curmax with fixed weights, but clamped
// curmin to <= `imin and curmax to >= `imax, so the thresholds could never
// leave ~91/160 no matter where the signal actually sat. A tag whose envelope
// lives inside that window - which is the normal case for a reader field, the
// peak detector idles near 112 and a tag swings it by about +/-20 - never
// crossed a threshold at all and demodulated as a constant.
//
// The band is now centred on the tracked envelope and set to 3/16 of its span.
// The old 0.8125/0.1875 blend worked out to 5/16, which on a real card leaves
// only about 1.6x margin between the threshold and the modulation peaks and
// bit-slips often; 3/16 roughly doubles that margin.
wire [8:0] span     = (curmax > curmin) ? (curmax - curmin) : 9'd0;
wire [9:0] envsum   = {1'b0, curmax} + {1'b0, curmin};
wire [8:0] centre   = envsum[9:1];
// 3/16 of the tracked span, floored. Keep the intermediate wide: span reaches
// 255 and 3 * 255 needs 10 bits, a 9 bit intermediate silently wraps and hands
// back a far too narrow band exactly when the envelope is widest.
wire [11:0] scaledspan = ({3'd0, span} << 1) + {3'd0, span};
wire [8:0] rawhalf  = scaledspan[11:4];
wire [8:0] halfband = (rawhalf < `minhalfband) ? `minhalfband : rawhalf;
wire [8:0] lothres  = (centre > halfband) ? (centre - halfband) : 9'd0;
// where to put the band when re-centring on the level actually present
wire [9:0] rc_hisum = {2'd0, adc_d} + `minhalfband;
wire [8:0] rc_hi    = (rc_hisum > 10'd255) ? 9'd255 : rc_hisum[8:0];
wire [8:0] rc_lo    = (adc_d > `minhalfband) ? ({1'b0, adc_d} - `minhalfband) : 9'd0;
wire [9:0] hisum    = {1'b0, centre} + {1'b0, halfband};
wire [8:0] hithres  = (hisum > 10'd255) ? 9'd255 : hisum[8:0];

//signal state, 1-not modulated, 0 -modulated
reg after_hysteresis = 1'b1;

//state machine for envelope tracking
// Keep this out of block RAM. The project synthesises with -fsm_style bram, and
// once this got large enough for XST to recognise it as a state machine it put
// the state ROM in a block RAM - the xc2s30 has six and the design already uses
// all of them, so the build failed to fit with nothing but a MAP error to say
// so. It is two bits; LUTs are the right home for it.
(* fsm_extract = "no" *)
reg [1:0] state = 1'd0;

//lower edge detected, trying to  detect first bit of SYNC (b24d, 1011001001001101)
reg try_sync = 1'b0;

//detected first sync bit, phase frozen
reg did_sync=0;

//samples since the last known-good idle, see `stalebit
reg [`stalebit:0] stale = 0;

//decisions still to skip before did_sync may latch, see `syncguard
reg [1:0] guard = 2'd0;

`define bithalf_212 32 // half-bit length for 212 kbit
`define bitmlen_212 63 // bit transition edge

`define bithalf_424 16 // half-bit length for 212 kbit
`define bitmlen_424 31 // bit transition edge

wire [7:0] bithalf = speed ? `bithalf_424 : `bithalf_212;
wire [7:0] bitmlen = speed ? `bitmlen_424 : `bitmlen_212;

// curbit_raw is decided in the bit-phase domain, which is aligned to the tag's
// edges by try_sync and so drifts against ssp_cnt. curbit is that decision
// re-timed into the ssp domain: the SSC latches ssp_din when ssp_clk rises at
// ssp_cnt[5:0] == 0, so updating half an ssp bit away from that keeps the ARM
// from ever sampling a bit while it is changing. Both run at 64 carrier
// periods per bit, so this is a re-time and not a resample - no bit is
// duplicated or dropped.
reg curbit_raw = 1'b0;
reg curbit = 1'b0;

reg [7:0] fccount = 8'd0; // in-bit tick counter. Counts carrier cycles from the first lower edge detected, reset on every manchester bit detected

reg [7:0] tsinceedge = 8'd0;// ticks from last edge,  desync if the valye is too large

reg zero = 1'b0; // Manchester first halfbit low second high corresponds to this value. It has been known to change. SYNC is used to set it

//ssp clock and current values
//ssp counter for transfer and framing
reg [8:0] ssp_cnt = 9'd0;

always @(posedge adc_clk)
    ssp_cnt <= (ssp_cnt + 1);

always @(negedge adc_clk)
    if (ssp_cnt[5:0] == 6'd32)
        curbit <= curbit_raw;

`ifdef WITH_FELICA_PROBE
// Signal probe: min and max of the envelope over each ssp byte window (512
// carrier periods, 8 bit periods), reported in alternating bytes - min, max,
// min, max. That gives both the carrier level and the tag modulation depth,
// which are different questions: the level says whether the front end is
// running out of ADC range, the depth says whether the tag is in range at all.
// Measured on a RDV4: idle ripples 4..6 counts, an ordinary card on the
// antenna swings about 70, a strongly coupled one over 200.
reg [7:0] pmin = 8'hff;
reg [7:0] pmax = 8'd0;
reg [7:0] pout = 8'd0;
reg       ptog = 1'b0;
reg [7:0] probe_sr = 8'd0;

always @(negedge adc_clk)
begin
    if (ssp_cnt[8:0] == 9'd0)
    begin
        pout <= ptog ? pmax : pmin;
        ptog <= ~ptog;
        pmin <= adc_d;
        pmax <= adc_d;
    end
    else
    begin
        if (adc_d < pmin) pmin <= adc_d;
        if (adc_d > pmax) pmax <= adc_d;
    end
end


`endif

//maybe change it so that ARM sends preamble as well.
//then: ready bits sent to ARM, 8 bits sent from ARM (all ones), then preamble (all zeros, presumably) - which starts modulation

always @(negedge adc_clk)
begin
    //count fc/64 - transfer bits to ARM at the rate they are received
    if( ((~speed) && (ssp_cnt[5:0] == 6'b000000) ) || (speed && (ssp_cnt[4:0] == 5'b00000)) )
    begin
        ssp_clk <= 1'b1;
        //send current bit (detected in SNIFF mode or the one being modulated in MOD mode, 0 otherwise)
`ifdef WITH_FELICA_PROBE
        if (probe)
        begin
            // one 8 bit reading per ssp byte, LSB first so the ARM reads it verbatim
            if (ssp_cnt[8:6] == 3'd0)
            begin
                ssp_din  <= pout[0];
                probe_sr <= {1'b0, pout[7:1]};
            end
            else
            begin
                ssp_din  <= probe_sr[0];
                probe_sr <= {1'b0, probe_sr[7:1]};
            end
        end
        else
`endif
        begin
            ssp_din <= curbit;
        end
    end
    if( ( (~speed) && (ssp_cnt[5:0] == 6'b100000)) ||(speed && ssp_cnt[4:0] == 5'b10000))
        ssp_clk <= 1'b0;
    //create frame pulses. TBH, I still don't know what they do exactly, but they are crucial for ARM->FPGA transfer. If the frame is in the beginning of the byte, transfer slows to a crawl for some reason
    // took me a day to figure THAT out.
    if(( (~speed) && (ssp_cnt[8:0] == 9'd31)) || (speed && ssp_cnt[7:0] == 8'd15))
    begin
        ssp_frame <= 1'b1;
    end
    if(( (~speed) && (ssp_cnt[8:0] == 9'b1011111)) || (speed &&ssp_cnt[7:0] == 8'b101111) )
    begin
        ssp_frame <= 1'b0;
    end
end

// Matched-filter accumulators. acc integrates the envelope over the half-bit
// in progress, h1 holds the completed first half.
//
// The top 6 ADC bits are enough and the xc2s30 has no room for more: 32 samples
// of 6 bits needs 11 bits of accumulator against 13 for the full 8. Resolution
// is not the limit here - a 70 count tag swing is 17 counts at 6 bits, times 32
// samples is a difference of ~560, against a noise floor of about 6 after the
// same averaging. Two extra bits would buy nothing and cost slices the device
// does not have.
wire [5:0] samp = adc_d[7:2];
reg [11:0] acc = 12'd0;
reg [11:0] h1  = 12'd0;
wire [11:0] h2 = acc + {6'd0, samp};
wire firsthalfhigh = (h1 > h2);

// which half was the larger on the previous bit, ie the previous bit value
// before polarity is known. A change in it is a Manchester bit transition.
reg prv_s = 1'b0;

// set TAGSIM__MODULATE on ARM if we want to write... (frame would get lost if done mid-frame...)
// start sending over 1s on ssp->arm when we start sending preamble
// reg sending = 1'b0;  // are we actively modulating?
reg [11:0] bit_counts = 12'd0; // for timeslots. only support ts=0 for now, at 212 speed  -512 fullbits from end of frame. One hopes.   might remove those?

//we need some way to flush bit_counts triggers on mod_type changes don't compile
reg dlay;
always @(negedge adc_clk) // every data ping?
begin
    // Watchdog clock, see `stalebit. It runs first so that the three places
    // that clear it below - a clean desync, a successful Manchester lock, and
    // the watchdog firing itself - all override it.
    stale <= stale + 1;

    //envelope follow code...
  ////////////
    if (fccount == bitmlen)
    begin
        if ((~try_sync) && (adc_d < curminthres) && disabl )
        begin
            fccount <= 1;
        end
        else
        begin
            fccount <= 0;
        end
        dlay <= ssp_dout;
        if (bit_counts > 768) // should be over ts0 now, without ARM interference... stop counting...
        begin
            bit_counts <= 0;
        end
        else
            if (power)
                bit_counts <= 0;
            else
                bit_counts <= bit_counts + 1;
    end
    else
    begin
        if((~try_sync) && (adc_d < curminthres) && disabl)
        begin
            fccount <= 1;
        end
        else
        begin
            fccount <= fccount + 1;
        end
    end

    // rising edge
    if (adc_d > curmaxthres)
    begin
        case (state)
        0:  begin
                curmax <= adc_d;
                state <= 2;
            end
        1:  begin
                curminthres <= lothres;
                curmaxthres <= hithres;
                curmax <= adc_d;
                state <= 2;
            end
        2:  begin
                if (adc_d > curmax)
                    curmax <= adc_d;
                end
        default:
            begin
            end
        endcase
        after_hysteresis <= 1'b1;
        if(try_sync)
            tsinceedge <= 0;
    end
    else if (adc_d<curminthres) //falling edge
    begin
        case (state)
        0:  begin
                curmin <= adc_d;
                state <= 1;
            end
        1:  begin
                if (adc_d<curmin)
                    curmin <= adc_d;
            end
        2:  begin
                curminthres <= lothres;
                curmaxthres <= hithres;
                curmin <= adc_d;
                state <= 1;
            end
        default:
            begin
            end
        endcase
        after_hysteresis <= 0;
        if (~try_sync ) //begin modulation, lower edge...
        begin
            try_sync <= 1;
            fccount <= 1;
            did_sync <= 0;
            guard <= `syncguard;
            // A frame is starting: give it the full watchdog interval. Doing
            // this only on did_sync below is not enough, because did_sync stays
            // latched between frames unless a desync clears it, so during a
            // long exchange - `hf felica dump` walking a card's nodes - the
            // watchdog clock keeps running across frames and eventually fires
            // in the middle of one. try_sync arming is the one event that
            // happens at the start of every frame.
            stale <= 0;
            curbit_raw <= 0;
            acc <= 0;
            tsinceedge <= 0;
        end
        else
        begin
            tsinceedge <= 0;
        end
    end
    else //stable state, low or high
    begin
        curminthres <= lothres;
        curmaxthres <= hithres;
        state <= 0;

        if (try_sync )
        begin
            if (tsinceedge >= (128))
            begin
                //we might need to start counting... assuming ARM wants to reply to the frame.
                bit_counts <= 1;// i think? 128 is about 2 bits passed... but 1 also works
                try_sync <= 0;
                did_sync <= 0;//desync
                stale <= 0;   //this is the known-good state the watchdog looks for
                // Re-centre the envelope on the carrier level that is actually
                // there. Resetting to the compile-time constants instead threw
                // away the only measurement we had and, when the real level sat
                // inside `ithrmin..`ithrmax, guaranteed the next frame could not
                // produce a single edge.
                curmin <= adc_d;
                curmax <= adc_d;
                curminthres <= lothres;
                curmaxthres <= hithres;
                tsinceedge <= 0;
                after_hysteresis <= 1'b1;
                curbit_raw <= 0;
                acc <= 0;
            end
            else
                tsinceedge <= (tsinceedge + 1);
        end
    end

    if (try_sync && tsinceedge < 128)
    begin
        // Matched-filter bit detector. Each Manchester bit is two half-bits of
        // opposite level, so integrating the raw ADC over each half and taking
        // the larger recovers the bit without ever consulting a threshold.
        //
        // The old detector counted comparator trips instead: +1 per sample
        // above curmaxthres, -1 below curminthres, and inside the dead band it
        // just repeated the previous crossing direction. That made every bit
        // depend on where the hysteresis band happened to sit, which is what
        // made a mispositioned band rail the output to a constant, a clipped
        // envelope mis-slice, and a weak tag undetectable. It also threw away
        // amplitude, so it gained nothing from the 32x oversampling.
        //
        // Integrating 32 samples per half instead averages the noise down by
        // sqrt(32) and cancels any offset common to both halves, which is what
        // slew and clipping asymmetry look like. Thresholds still drive the bit
        // phase and the desync below, they just no longer decide bit values.
        if (fccount == bithalf)
        begin
            h1  <= acc;      // first half: samples 0..31
            acc <= {6'd0, samp};    // second half starts here, sample 32
        end
        else if (fccount == bitmlen)
        begin
            // h2 is acc plus this sample, so both halves are 32 samples and
            // neither is biased by an extra sample of carrier.
            if (guard != 2'd0)
                guard <= guard - 2'd1;

            // A bit value change flips which half is the larger. The preamble
            // is 48 identical bits, so the first flip is the preamble meeting
            // the sync word, whose first bit is a 1. Lock polarity there.
            if ((~did_sync) && (guard == 2'd0) && (firsthalfhigh != prv_s))
            begin
                did_sync <= 1'b1;
                zero <= ~firsthalfhigh;
                curbit_raw <= 1;
                // A Manchester lock means the demodulator is working, so hold
                // the watchdog off for the frame that is now starting. Without
                // this it eventually fires part way through a reply and clears
                // try_sync and did_sync mid-frame, slipping every bit after
                // that point. It is deterministic rather than rare: the delay
                // from field-on to reply barely varies, so the watchdog phase
                // lines up with the reply on attempt after attempt.
                stale <= 0;
            end
            else
                curbit_raw <= firsthalfhigh ? (~zero) : zero;

            prv_s <= firsthalfhigh;
            acc <= 0;
        end
        else
            acc <= acc + {6'd0, samp};
    end

    // Watchdog, see `stalebit. Put the band back on the signal directly, since
    // nothing above is able to any more.
    if (stale[`stalebit])
    begin
        curmin <= adc_d;
        curmax <= adc_d;
        curminthres <= rc_lo;
        curmaxthres <= rc_hi;
        try_sync <= 1'b0;
        did_sync <= 1'b0;
        curbit_raw <= 1'b0;
        after_hysteresis <= 1'b1;
        tsinceedge <= 0;
        state <= 0;
        stale <= 0;
    end
//  sending <= 0;
end

//put modulation here to maintain the correct clock. Seems that some readers are sensitive to that

wire mod = ((fccount >= bithalf) ^ dlay) & (~disabl);

always @(ck_1356meg or ssp_dout or power or disabl or mod)
begin
    if (power)
    begin
        pwr_hi  <= ck_1356meg;
        pwr_lo  <= 1'b0;
        pwr_oe1 <= 1'b0;//mod;
        pwr_oe2 <= 1'b0;//mod;
        pwr_oe3 <= 1'b0;//mod;
        pwr_oe4 <= mod;//1'b0;
    end
    else
    begin
        pwr_hi  <= 1'b0;
        pwr_lo  <= 1'b0;
        pwr_oe1 <= 1'b0;
        pwr_oe2 <= 1'b0;
        pwr_oe3 <= 1'b0;
        pwr_oe4 <= mod;
    end
end

endmodule
