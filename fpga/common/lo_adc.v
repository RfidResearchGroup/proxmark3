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
// The way that we connect things in low-frequency simulation mode. In this
// case just pass everything through to the ARM, which can bit-bang this
// (because it is so slow).
//
// Jonathan Westhues, April 2006
//-----------------------------------------------------------------------------

module lo_adc(
    input pck0,
    input [7:0] adc_d,
    input [7:0] divisor,
    input lf_field,
    input lf_weak_load,
    input ssp_dout,

    output ssp_din,
    output reg ssp_frame,
    output ssp_clk,
    output adc_clk,
    output pwr_lo,
    output pwr_hi,
    output pwr_oe1,
    output pwr_oe2,
    output pwr_oe3,
    output pwr_oe4,
    output debug
);

reg [7:0] to_arm_shiftreg;
reg [7:0] pck_divider;
reg clk_state;

// Antenna logic, depending on "lf_field" (in arm defined as FPGA_LF_READER_FIELD)
wire tag_modulation = ssp_dout & !lf_field;
wire reader_modulation = !ssp_dout & lf_field & clk_state;

// always on (High Frequency outputs, unused)
assign pwr_oe1 = 1'b0;
assign pwr_hi  = 1'b0;

// low frequency outputs
assign pwr_lo  = reader_modulation;
assign pwr_oe2 = 1'b0;  // 33 Ohms
// lf_weak_load moves the modulation from the 33 Ohm leg to the 10k one, so the
// depth measured here matches what lo_edge_detect does in the same mode.
assign pwr_oe3 = tag_modulation & ~lf_weak_load; // base antenna load = 33 Ohms
assign pwr_oe4 = tag_modulation & lf_weak_load;  // 10k Ohms

// Debug Output ADC clock
assign debug = adc_clk;

// ADC clock out of phase with antenna driver
`ifdef PM5
// Since the PM5's ADC sampling occurs on the rising edge,
// whereas the falling edge of the field signal causes a rapid voltage rise—making it unsuitable for sampling
// the phase was adjusted to align them.
assign adc_clk = clk_state;
`else
assign adc_clk = ~clk_state;
`endif

// serialized SSP data is gated by clk_state to suppress unwanted signal
assign ssp_din = to_arm_shiftreg[7] && !clk_state;

// SSP clock always runs at 24MHz
assign ssp_clk = pck0;

// ssp_frame window: TI = 1-cycle pulse (at divider 7), SSP = spans the entire data window (dividers 8–15).
// Note: The 'always' block below reads the value of pck_divider *before* it toggles for the current cycle,
// so SET is triggered at the window start minus 1, and CLR is triggered at the window end.
`ifdef WITH_TIMODE
  `define LO_ADC_FRAME_SET  8'd6
  `define LO_ADC_FRAME_CLR  8'd7
`else
  `define LO_ADC_FRAME_SET  8'd7
  `define LO_ADC_FRAME_CLR  8'd15
`endif

// Frame signal generation.
always @(posedge pck0)
begin
  if ((pck_divider == `LO_ADC_FRAME_SET) && !clk_state)
      ssp_frame <= 1'b1;
  if ((pck_divider == `LO_ADC_FRAME_CLR) && !clk_state)
      ssp_frame <= 1'b0;
end

// divide 24mhz down to 3mhz
always @(posedge pck0) // SSPCLK rising edge
begin
    if (pck_divider == divisor[7:0])
    begin
        // Resets to zero upon reaching the frequency division factor; effectively, the value 95 corresponds to 125 kHz, meaning it executes 96 times (counting from 0 to 95) and resets on the 96th iteration.
        // After resetting, the cycle count becomes 0 and does not increment.
        pck_divider <= 8'd0;
        // Toggle clk upon reaching the frequency division factor; the value 95 (corresponding to 125 kHz) actually implies operation at a frequency of 250 kHz.
        clk_state = !clk_state;
    end
    else
    begin
        pck_divider <= pck_divider + 1'd1; // Increments by 1 on each rising edge of sspclk.
    end
end

// this task also runs at pck0 frequency (24Mhz) and is used to serialize
// the ADC output which is then clocked into the ARM SSP.
always @(posedge pck0)
begin

    // For PM5: Since adc_clk = ~clk_state, the ADC receives a rising edge when clk_state is 0.
    // Note: Because the PM5 ADC samples on the rising edge, this causes hardware sampling to occur the moment the field is turned off (when voltage rises rapidly); therefore, a modification was made here.
    // The adc_clk is now set to be in-phase with clk_state (since pwrlo is based on clk_state, this aligns the phases).
    // Consequently, when clk_state is 0, the ADC receives a falling edge; sampling the output of the 9280 on the falling edge is safe, so this approach was adopted.
    // ADC sampling completes when pck_divider == 8'd7; one cycle later, the 'else' condition takes effect.
    // Shift transmission begins at 8'd8, but since the data payload is only 8 bits, zeros are transmitted continuously after the actual data is sent—a point easily misunderstood.
    // In reality, the active sequence spans pck_divider values from 0 to 7 (sampling), to 8 (transmission start), and finally to 16 (transmission end).

    if ((pck_divider == 8'd7) && !clk_state)
        to_arm_shiftreg <= adc_d;
    else
    begin
        to_arm_shiftreg[7:1] <= to_arm_shiftreg[6:0];
        to_arm_shiftreg[0] <= 1'b0;
    end
end

endmodule
