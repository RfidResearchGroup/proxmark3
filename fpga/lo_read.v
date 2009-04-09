//-----------------------------------------------------------------------------
// The way that we connect things in low-frequency read mode. In this case
// we are generating the 134 kHz or 125 kHz carrier, and running the 
// unmodulated carrier at that frequency. The A/D samples at that same rate,
// and the result is serialized.
//
// Jonathan Westhues, April 2006
//-----------------------------------------------------------------------------

module lo_read(
    pck0, ck_1356meg, ck_1356megb,
    pwr_lo, pwr_hi, pwr_oe1, pwr_oe2, pwr_oe3, pwr_oe4,
    adc_d, adc_clk,
    ssp_frame, ssp_din, ssp_dout, ssp_clk,
    cross_hi, cross_lo,
    dbg,
    lo_is_125khz
);
    input pck0, ck_1356meg, ck_1356megb;
    output pwr_lo, pwr_hi, pwr_oe1, pwr_oe2, pwr_oe3, pwr_oe4;
    input [7:0] adc_d;
    output adc_clk;
    input ssp_dout;
    output ssp_frame, ssp_din, ssp_clk;
    input cross_hi, cross_lo;
    output dbg;
    input lo_is_125khz;

// The low-frequency RFID stuff. This is relatively simple, because most
// of the work happens on the ARM, and we just pass samples through. The
// PCK0 must be divided down to generate the A/D clock, and from there by
// a factor of 8 to generate the carrier (that we apply to the coil drivers).
//
// This is also where we decode the received synchronous serial port words,
// to determine how to drive the output enables.

// PCK0 will run at (PLL clock) / 4, or 24 MHz. That means that we can do
// 125 kHz by dividing by a further factor of (8*12*2), or ~134 kHz by
// dividing by a factor of (8*11*2) (for 136 kHz, ~2% error, tolerable).

reg [3:0] pck_divider;
reg clk_lo;

always @(posedge pck0)
begin
    if(lo_is_125khz)
    begin
        if(pck_divider == 4'd11)
        begin
            pck_divider <= 4'd0;
            clk_lo = !clk_lo;
        end
        else
            pck_divider <= pck_divider + 1;
    end
    else
    begin
        if(pck_divider == 4'd10)
        begin
            pck_divider <= 4'd0;
            clk_lo = !clk_lo;
        end
        else
            pck_divider <= pck_divider + 1;
    end
end

reg [2:0] carrier_divider_lo;

always @(posedge clk_lo)
begin
    carrier_divider_lo <= carrier_divider_lo + 1;
end

assign pwr_lo = carrier_divider_lo[2];

// This serializes the values returned from the A/D, and sends them out
// over the SSP.

reg [7:0] to_arm_shiftreg;

always @(posedge clk_lo)
begin
    if(carrier_divider_lo == 3'b000)
        to_arm_shiftreg <= adc_d;
    else
        to_arm_shiftreg[7:1] <= to_arm_shiftreg[6:0];
end

assign ssp_clk = clk_lo;
assign ssp_frame = (carrier_divider_lo == 3'b001);
assign ssp_din = to_arm_shiftreg[7];

// The ADC converts on the falling edge, and our serializer loads when
// carrier_divider_lo == 3'b000.
assign adc_clk = ~carrier_divider_lo[2];

assign pwr_hi = 1'b0;

assign dbg = adc_clk;

endmodule
