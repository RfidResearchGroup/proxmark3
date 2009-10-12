//-----------------------------------------------------------------------------
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

// Power amp goes between LOW and tri-state, so pwr_hi (and pwr_lo) can
// always be low.
assign pwr_hi = 1'b0;
assign pwr_lo = 1'b0;

// The comparator with hysteresis on the output from the peak detector.
reg after_hysteresis;
assign adc_clk = ck_1356meg;

always @(negedge adc_clk)
begin
    if(& adc_d[7:5]) after_hysteresis = 1'b1;
    else if(~(| adc_d[7:5])) after_hysteresis = 1'b0;
end

// Divide 13.56 MHz by 32 to produce the SSP_CLK
// The register is bigger to allow higher division factors of up to /128
reg [6:0] ssp_clk_divider;
always @(posedge adc_clk)
    ssp_clk_divider <= (ssp_clk_divider + 1);
assign ssp_clk = ssp_clk_divider[4];

// Divide SSP_CLK by 8 to produce the byte framing signal; the phase of
// this is arbitrary, because it's just a bitstream.
// One nasty issue, though: I can't make it work with both rx and tx at
// once. The phase wrt ssp_clk must be changed. TODO to find out why
// that is and make a better fix.
reg [2:0] ssp_frame_divider_to_arm;
always @(posedge ssp_clk)
    ssp_frame_divider_to_arm <= (ssp_frame_divider_to_arm + 1);
reg [2:0] ssp_frame_divider_from_arm;
always @(negedge ssp_clk)
    ssp_frame_divider_from_arm <= (ssp_frame_divider_from_arm + 1);

reg ssp_frame;
always @(ssp_frame_divider_to_arm or ssp_frame_divider_from_arm or mod_type)
    if(mod_type == 3'b000) // not modulating, so listening, to ARM
        ssp_frame = (ssp_frame_divider_to_arm == 3'b000);
    else
        ssp_frame = (ssp_frame_divider_from_arm == 3'b000);

// Synchronize up the after-hysteresis signal, to produce DIN.
reg ssp_din;
always @(posedge ssp_clk)
    ssp_din = after_hysteresis;

// Modulating carrier frequency is fc/16, reuse ssp_clk divider for that
reg modulating_carrier;
always @(mod_type or ssp_clk or ssp_dout)
    if(mod_type == 3'b000)
        modulating_carrier <= 1'b0;                          // no modulation
    else if(mod_type == 3'b001)
        modulating_carrier <= ssp_dout ^ ssp_clk_divider[3]; // XOR means BPSK
    else if(mod_type == 3'b010)
        modulating_carrier <= ssp_dout & ssp_clk_divider[5]; // switch 212kHz subcarrier on/off
    else
        modulating_carrier <= 1'b0;                           // yet unused

// This one is all LF, so doesn't matter
assign pwr_oe2 = modulating_carrier;

// Toggle only one of these, since we are already producing much deeper
// modulation than a real tag would.
assign pwr_oe1 = modulating_carrier;
assign pwr_oe4 = modulating_carrier;

// This one is always on, so that we can watch the carrier.
assign pwr_oe3 = 1'b0;

assign dbg = after_hysteresis;

endmodule
