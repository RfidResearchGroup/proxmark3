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
//
// Pretend to be an ISO 14443 tag. We will do this by alternately short-
// circuiting and open-circuiting the antenna coil, with the tri-state
// pins.
//
// We communicate over the SSP, as a bitstream (i.e., might as well be
// unframed, though we still generate the word sync signal). The output
// (ARM -> FPGA) tells us whether to modulate or not. The input (FPGA
// -> ARM) is us using the A/D as a fancy comparator; this is with
// (software-added) hysteresis, to undo the high-pass filter.
//
// At this point only Type A is implemented. This means that we are using a
// bit rate of 106 kbit/s, or fc/128. Oversample by 4, which ought to make
// things practical for the ARM (fc/32, 423.8 kbits/s, ~50 kbytes/s)
//
// Jonathan Westhues, October 2006
//-----------------------------------------------------------------------------

module hi_simulate(
    input ck_1356meg,
    input [7:0] adc_d,
    input [3:0] mod_type,
    input ssp_dout,

    output reg ssp_din,
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

// Power amp goes between LOW and tri-state, so pwr_hi (and pwr_lo) can
// always be low.
assign pwr_hi = 1'b0;        // HF antenna connected to GND
assign pwr_lo = 1'b0;        // LF antenna connected to GND

// This one is all LF, so doesn't matter
assign pwr_oe2 = 1'b0;

assign adc_clk = ck_1356meg;
assign debug = ssp_frame;

// The comparator with hysteresis on the output from the peak detector.
reg after_hysteresis;
reg [11:0] has_been_low_for;

always @(negedge adc_clk)
begin
    if (& adc_d[7:5]) after_hysteresis <= 1'b1;           // if (adc_d >= 224)
    else if (~(| adc_d[7:5])) after_hysteresis <= 1'b0;   // if (adc_d <= 31)

    if (adc_d >= 224)
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
        begin
            has_been_low_for <= has_been_low_for + 1;
        end
    end
end

// Divide 13.56 MHz to produce various frequencies for SSP_CLK
// and modulation.
reg [8:0] ssp_clk_divider;

always @(negedge adc_clk)
    ssp_clk_divider <= (ssp_clk_divider + 1);

always @(negedge adc_clk)
begin
    if (mod_type == `FPGA_HF_SIMULATOR_MODULATE_424K_8BIT)
        // Get bit every at 53KHz (every 8th carrier bit of 424kHz)
        ssp_clk <= ~ssp_clk_divider[7];
    else if (mod_type == `FPGA_HF_SIMULATOR_MODULATE_212K)
        // Get next bit at 212kHz
        ssp_clk <= ~ssp_clk_divider[5];
    else
        // Get next bit at 424kHz
        ssp_clk <= ~ssp_clk_divider[4];
end

// Produce the byte framing signal; the phase of this signal
// is arbitrary, because it's just a bit stream in this module.
always @(negedge adc_clk)
begin
    if (mod_type == `FPGA_HF_SIMULATOR_MODULATE_212K)
    begin
        if (ssp_clk_divider[8:5] == 4'd1)
            ssp_frame <= 1'b1;
        if (ssp_clk_divider[8:5] == 4'd5)
            ssp_frame <= 1'b0;
    end
    else
    begin
        if (ssp_clk_divider[7:4] == 4'd1)
            ssp_frame <= 1'b1;
        if (ssp_clk_divider[7:4] == 4'd5)
            ssp_frame <= 1'b0;
    end
end

// Synchronize up the after-hysteresis signal, to produce DIN.
always @(posedge ssp_clk)
    ssp_din = after_hysteresis;

// Modulating carrier frequency is fc/64 (212kHz) to fc/16 (848kHz). Reuse ssp_clk divider for that.
reg modulating_carrier;
always @(*)
    if(mod_type == `FPGA_HF_SIMULATOR_NO_MODULATION)
        modulating_carrier <= 1'b0;                          // no modulation
    else if(mod_type == `FPGA_HF_SIMULATOR_MODULATE_BPSK)
        modulating_carrier <= ssp_dout ^ ssp_clk_divider[3]; // XOR means BPSK
    else if(mod_type == `FPGA_HF_SIMULATOR_MODULATE_212K)
        modulating_carrier <= ssp_dout & ssp_clk_divider[5]; // switch 212kHz subcarrier on/off
    else if(mod_type == `FPGA_HF_SIMULATOR_MODULATE_424K || mod_type == `FPGA_HF_SIMULATOR_MODULATE_424K_8BIT)
        modulating_carrier <= ssp_dout & ssp_clk_divider[4]; // switch 424kHz modulation on/off
    else
        modulating_carrier <= 1'b0;                          // yet unused

// Load modulation. Toggle only one of these, since we are already producing much deeper
// modulation than a real tag would.
assign pwr_oe1 = 1'b0;                  // 33 Ohms Load
assign pwr_oe4 = modulating_carrier;    // 33 Ohms Load
// This one is always on, so that we can watch the carrier.
assign pwr_oe3 = 1'b0;                  // 10k Load

endmodule
