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

// 512x64/fc  -wait before ts0, 32768 ticks
// tslot: 256*64/fc
assign adc_clk = ck_1356meg;

///heuristic values for initial thresholds. seem to work OK
`define imin 70     // (13'd256)
`define imax 180    // (-13'd256)
`define ithrmin 91  // -13'd8
`define ithrmax 160 //  13'd8

`define min_bitdelay_212 8
//minimum values and corresponding thresholds
reg [8:0] curmin=`imin;
reg [8:0] curminthres=`ithrmin;
reg [8:0] curmaxthres=`ithrmax;
reg [8:0] curmax=`imax;

//signal state, 1-not modulated, 0 -modulated
reg after_hysteresis = 1'b1;

//state machine for envelope tracking
reg [1:0] state = 1'd0;

//lower edge detected, trying to  detect first bit of SYNC (b24d, 1011001001001101)
reg try_sync = 1'b0;

//detected first sync bit, phase frozen
reg did_sync=0;

`define bithalf_212 32 // half-bit length for 212 kbit
`define bitmlen_212 63 // bit transition edge

`define bithalf_424 16 // half-bit length for 212 kbit
`define bitmlen_424 31 // bit transition edge

wire [7:0] bithalf = speed ? `bithalf_424 : `bithalf_212;
wire [7:0] bitmlen = speed ? `bitmlen_424 : `bitmlen_212;

reg curbit = 1'b0;

reg [7:0] fccount = 8'd0; // in-bit tick counter. Counts carrier cycles from the first lower edge detected, reset on every manchester bit detected

reg [7:0] tsinceedge = 8'd0;// ticks from last edge,  desync if the valye is too large

reg zero = 1'b0; // Manchester first halfbit low second high corresponds to this value. It has been known to change. SYNC is used to set it

//ssp clock and current values
//ssp counter for transfer and framing
reg [8:0] ssp_cnt = 9'd0;

always @(posedge adc_clk)
    ssp_cnt <= (ssp_cnt + 1);

//maybe change it so that ARM sends preamble as well.
//then: ready bits sent to ARM, 8 bits sent from ARM (all ones), then preamble (all zeros, presumably) - which starts modulation

always @(negedge adc_clk)
begin
    //count fc/64 - transfer bits to ARM at the rate they are received
    if( ((~speed) && (ssp_cnt[5:0] == 6'b000000) ) || (speed && (ssp_cnt[4:0] == 5'b00000)) )
    begin
        ssp_clk <= 1'b1;
        //send current bit (detected in SNIFF mode or the one being modulated in MOD mode, 0 otherwise)
        ssp_din <= curbit;
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

//previous signal value, mostly to detect SYNC
reg prv = 1'b1;

// for simple error correction in mod/demod detection, use maximum of modded/demodded in given interval. Maybe 1 bit is extra? but better safe than sorry.
reg[7:0] mid = 8'd128;

// set TAGSIM__MODULATE on ARM if we want to write... (frame would get lost if done mid-frame...)
// start sending over 1s on ssp->arm when we start sending preamble
// reg sending = 1'b0;  // are we actively modulating?
reg [11:0] bit_counts = 12'd0; // for timeslots. only support ts=0 for now, at 212 speed  -512 fullbits from end of frame. One hopes.   might remove those?

//we need some way to flush bit_counts triggers on mod_type changes don't compile
reg dlay;
always @(negedge adc_clk) // every data ping?
begin
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
                curmax <= adc_d > `imax? adc_d : `imax;
                state <= 2;
            end
        1:  begin
                curminthres <= ((curmin >> 1) + (curmin >> 2) + (curmin >> 4) + (curmax >> 3) + (curmax >> 4)); //threshold: 0.1875 max + 0.8125 min
                curmaxthres <= ((curmax >> 1) + (curmax >> 2) + (curmax >> 4) + (curmin >> 3) + (curmin >> 4));
                curmax <= adc_d > 155 ? adc_d : 155; // to hopefully prevent overflow from spikes going up to 255
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
                curmin <= adc_d<`imin? adc_d :`imin;
                state <= 1;
            end
        1:  begin
                if (adc_d<curmin)
                    curmin <= adc_d;
            end
        2:  begin
                curminthres <= ( (curmin >> 1) + (curmin >> 2) + (curmin >> 4) + (curmax >> 3) + (curmax >> 4));
                curmaxthres <= ( (curmax >> 1) + (curmax >> 2) + (curmax >> 4) + (curmin >> 3) + (curmin >> 4));
                curmin <= adc_d < `imin ? adc_d : `imin;
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
            curbit <= 0;
            mid <= 8'd127;
            tsinceedge <= 0;
            prv <= 1;
        end
        else
        begin
            tsinceedge <= 0;
        end
    end
    else //stable state, low or high
    begin
        curminthres <= ( (curmin >> 1) + (curmin >> 2) + (curmin >> 4) + (curmax >> 3) + (curmax >> 4));
        curmaxthres <= ( (curmax >> 1) + (curmax >> 2) + (curmax >> 4) + (curmin >> 3) + (curmin >> 4));
        state <= 0;

        if (try_sync )
        begin
            if (tsinceedge >= (128))
            begin
                //we might need to start counting... assuming ARM wants to reply to the frame.
                bit_counts <= 1;// i think? 128 is about 2 bits passed... but 1 also works
                try_sync <= 0;
                did_sync <= 0;//desync
                curmin <= `imin; //reset envelope
                curmax <= `imax;
                curminthres <= `ithrmin;
                curmaxthres <= `ithrmax;
                prv <= 1;
                tsinceedge <= 0;
                after_hysteresis <= 1'b1;
                curbit <= 0;
                mid <= 8'd128;
            end
            else
                tsinceedge <= (tsinceedge + 1);
        end
    end

    if (try_sync && tsinceedge < 128)
    begin
        //detect bits in their middle ssp sampling is in sync, so it would sample all bits in order
        if (fccount == bithalf)
        begin
            if ((~did_sync) && ((prv == 1 && (mid > 128))||(prv == 0 && (mid <= 128))))
            begin
                //sync the Zero, and set curbit roperly
                did_sync <= 1'b1;
                zero <= ~prv;// 1-prv
                curbit <= 1;
            end
            else
                curbit <= (mid > 128) ? (~zero) : zero;

            prv <= (mid > 128) ? 1 : 0;

            if (adc_d > curmaxthres)
                mid <= 8'd129;
            else if (adc_d < curminthres)
                mid <= 8'd127;
            else 
            begin
                if (after_hysteresis)
                begin
                    mid <= 8'd129;
                end
                else
                begin
                    mid <= 8'd127;
                end
            end
        end
        else
        begin
            if (fccount==bitmlen)
            begin
                // fccount <= 0;
                prv <= (mid > 128) ? 1 : 0;
                mid <= 128;
            end
            else
            begin
                // minimum-maximum calc
                if(adc_d > curmaxthres)
                    mid <= mid + 1;
                else if (adc_d < curminthres)
                    mid <= mid - 1;
                else
                    begin
                        if (after_hysteresis)
                        begin
                            mid <= mid + 1;
                        end
                        else
                        begin
                            mid <= mid - 1;
                        end
                    end
            end
        end
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
