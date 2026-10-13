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
// The FPGA is responsible for interfacing between the A/D, the coil drivers,
// and the ARM. In the low-frequency modes it passes the data straight
// through, so that the ARM gets raw A/D samples over the SSP. In the high-
// frequency modes, the FPGA might perform some demodulation first, to
// reduce the amount of data that we must send to the ARM.
//-----------------------------------------------------------------------------


module fpga_hf(
    input ck_1356meg,
    input spck,
    //input pck0,
    input ncs,
    input [7:0] adc_d,
    //input cross_hi, 
    //input cross_lo,
    input mosi,
    input ssp_dout,
    input ce,  // 复位输入，常态高
  
    output ssp_din,
    output ssp_frame,
    output ssp_clk,
    output adc_clk, 
    //output adc_noe,
    output miso,
    output pwr_lo, 
    output pwr_hi,
    output pwr_oe1, 
    output pwr_oe2, 
    //output pwr_oe3, 
    output pwr_oe4,
    output dbg,
    output reg [11:0] pwm_duty = 12'h800
);


// In all modes, let the ADC's outputs be enabled.
//assign adc_noe = 1'b0;
assign miso = 1'bZ;
wire cross_hi = 1'b0;

wire [2:0] major_mode;
assign major_mode = ce ? conf_word[8:6] : 3'b111;

//-----------------------------------------------------------------------------
// The SPI receiver. This sets up the configuration word, which the rest of
// the logic looks at to determine how to connect the A/D and the coil
// drivers (i.e., which section gets it). Also assign some symbolic names
// to the configuration bits, for use below.
//-----------------------------------------------------------------------------

// Receive 16bits of data from ARM here.
reg [15:0] shift_reg;

//always @(posedge spck) if (~ncs) shift_reg <= {shift_reg[14:0], mosi};
always @(posedge spck) begin
    if(~ncs & ce)
        shift_reg <= {shift_reg[14:0], mosi};
end

reg trace_enable;

reg [5:0] hf_edge_detect_threshold = 6'd7;
reg [5:0] hf_edge_detect_threshold_high = 6'd20;

reg [8:0] conf_word;

initial
begin
    hf_edge_detect_threshold <= 7;
    hf_edge_detect_threshold_high <= 20;
end

// We switch modes between transmitting to the 13.56 MHz tag and receiving
// from it, which means that we must make sure that we can do so without
// glitching, or else we will glitch the transmitted carrier.
always @(posedge ncs)
begin
    if(ce) begin
        // 4 bit command
        case (shift_reg[15:12])
            `FPGA_CMD_SET_CONFREG:  conf_word <= shift_reg[8:0];
            `FPGA_CMD_TRACE_ENABLE: trace_enable <= shift_reg[0];
            `FPGA_CMD_SET_EDGE_DETECT_THRESHOLD:
            begin
                hf_edge_detect_threshold <= shift_reg[5:0];
                hf_edge_detect_threshold_high <= shift_reg[11:6];
            end
            `FPGA_CMD_SET_PWR_PWM_LOW_COUNT:pwm_duty <= shift_reg[11:0];
        endcase
    end
end
//-----------------------------------------------------------------------------
// And then we instantiate the modules corresponding to each of the FPGA's
// major modes, and use muxes to connect the outputs of the active mode to
// the output pins.
//-----------------------------------------------------------------------------

//   HF reader
hi_reader hr(
    .ck_1356meg (ck_1356meg),
    .adc_d      (adc_d),
    .subcarrier_frequency (conf_word[5:4]),
    .minor_mode (conf_word[3:0]),
    .ssp_dout   (ssp_dout),

    .ssp_din    (mux0_ssp_din),
    .ssp_frame  (mux0_ssp_frame),
    .ssp_clk    (mux0_ssp_clk),
    .adc_clk    (mux0_adc_clk),
    .pwr_lo     (mux0_pwr_lo),
    .pwr_hi     (mux0_pwr_hi),
    .pwr_oe1    (mux0_pwr_oe1),
    .pwr_oe2    (mux0_pwr_oe2),
    .pwr_oe3    (mux0_pwr_oe3),
    .pwr_oe4    (mux0_pwr_oe4),
    .debug      (mux0_debug)
);

//   HF simulated tag
hi_simulate hs(
    .ck_1356meg (ck_1356meg),
    .adc_d      (adc_d),
    .mod_type   (conf_word[3:0]),
    .ssp_dout   (ssp_dout),

    .ssp_din    (mux1_ssp_din),
    .ssp_frame  (mux1_ssp_frame),
    .ssp_clk    (mux1_ssp_clk),
    .adc_clk    (mux1_adc_clk),
    .pwr_lo     (mux1_pwr_lo),
    .pwr_hi     (mux1_pwr_hi),
    .pwr_oe1    (mux1_pwr_oe1),
    .pwr_oe2    (mux1_pwr_oe2),
    .pwr_oe3    (mux1_pwr_oe3),
    .pwr_oe4    (mux1_pwr_oe4),
    .debug      (mux1_debug)
);

//   HF ISO14443-A
hi_iso14443a hisn(
    .ck_1356meg (ck_1356meg),
    .adc_d      (adc_d),
    .mod_type   (conf_word[3:0]),
    .ssp_dout   (ssp_dout),

    .ssp_din    (mux2_ssp_din),
    .ssp_frame  (mux2_ssp_frame),
    .ssp_clk    (mux2_ssp_clk),
    .adc_clk    (mux2_adc_clk),
    .pwr_lo     (mux2_pwr_lo),
    .pwr_hi     (mux2_pwr_hi),
    .pwr_oe1    (mux2_pwr_oe1),
    .pwr_oe2    (mux2_pwr_oe2),
    .pwr_oe3    (mux2_pwr_oe3),
    .pwr_oe4    (mux2_pwr_oe4),
    .debug      (mux2_debug),
    .edge_detect_threshold ({5'b00000, hf_edge_detect_threshold}),
    .edge_detect_threshold_high ({5'b00000, hf_edge_detect_threshold_high})
);

//   HF sniff
hi_sniffer he(
    .ck_1356meg  (ck_1356meg),
    .adc_d       (adc_d),

    .ssp_din     (mux3_ssp_din),
    .ssp_frame   (mux3_ssp_frame),
    .ssp_clk     (mux3_ssp_clk),
    .adc_clk     (mux3_adc_clk),
    .pwr_lo      (mux3_pwr_lo),
    .pwr_hi      (mux3_pwr_hi),
    .pwr_oe1     (mux3_pwr_oe1),
    .pwr_oe2     (mux3_pwr_oe2),
    .pwr_oe3     (mux3_pwr_oe3),
    .pwr_oe4     (mux3_pwr_oe4)
);

//   HF ISO18092 FeliCa
hi_flite hfl(
    .ck_1356meg  (ck_1356meg),
    .adc_d       (adc_d),
    .mod_type    (conf_word[3:0]),
    .ssp_dout    (ssp_dout),

    .ssp_din     (mux4_ssp_din),
    .ssp_frame   (mux4_ssp_frame),
    .ssp_clk     (mux4_ssp_clk),
    .adc_clk     (mux4_adc_clk),
    .pwr_lo      (mux4_pwr_lo),
    .pwr_hi      (mux4_pwr_hi),
    .pwr_oe1     (mux4_pwr_oe1),
    .pwr_oe2     (mux4_pwr_oe2),
    .pwr_oe3     (mux4_pwr_oe3),
    .pwr_oe4     (mux4_pwr_oe4),
    .debug       (mux4_debug)
);

//   HF get trace

hi_get_trace gt(
    .ck_1356megb  (ck_1356meg),
    .adc_d        (adc_d),
    .trace_enable (trace_enable),
    .major_mode   (major_mode),
    .ssp_din      (mux5_ssp_din),
    .ssp_frame    (mux5_ssp_frame),
    .ssp_clk      (mux5_ssp_clk)
);

// These assignments must agree with the defines in fpgaloader.h

// Major modes High Frequency
//   mux0 = HF reader
//   mux1 = HF simulated tag
//   mux2 = HF ISO14443-A
//   mux3 = HF sniff
//   mux4 = HF ISO18092 FeliCa
//   mux5 = HF get trace
//   mux6 = unused
//   mux7 = FPGA_MAJOR_MODE_OFF

mux8 mux_ssp_clk (
    .sel    (major_mode),
    .y      (ssp_clk        ),
    .x0     (mux0_ssp_clk   ),
    .x1     (mux1_ssp_clk   ),
    .x2     (mux2_ssp_clk   ),
    .x3     (mux3_ssp_clk   ),
    .x4     (mux4_ssp_clk   ),
    .x5     (mux5_ssp_clk   ),
    .x6     (1'b0           ),
    .x7     (1'b0           )
);

mux8 mux_ssp_din (
    .sel    (major_mode),
    .y      (ssp_din        ),
    .x0     (mux0_ssp_din   ),
    .x1     (mux1_ssp_din   ),
    .x2     (mux2_ssp_din   ),
    .x3     (mux3_ssp_din   ),
    .x4     (mux4_ssp_din   ),
    .x5     (mux5_ssp_din   ),
    .x6     (1'b0           ),
    .x7     (1'b0           )
);

mux8 mux_ssp_frame (
    .sel    (major_mode),
    .y      (ssp_frame      ),
    .x0     (mux0_ssp_frame ),
    .x1     (mux1_ssp_frame ),
    .x2     (mux2_ssp_frame ),
    .x3     (mux3_ssp_frame ),
    .x4     (mux4_ssp_frame ),
    .x5     (mux5_ssp_frame ),
    .x6     (1'b0           ),
    .x7     (1'b0           )
);

mux8 mux_pwr_oe1 (
    .sel    (major_mode),
    .y      (pwr_oe1        ),
    .x0     (mux0_pwr_oe1   ),
    .x1     (mux1_pwr_oe1   ),
    .x2     (mux2_pwr_oe1   ),
    .x3     (mux3_pwr_oe1   ),
    .x4     (mux4_pwr_oe1   ),
    .x5     (1'b0           ),
    .x6     (1'b0           ),
    .x7     (1'b0           )
);

mux8 mux_pwr_oe2 (
    .sel    (major_mode),
    .y      (pwr_oe2        ),
    .x0     (mux0_pwr_oe2   ),
    .x1     (mux1_pwr_oe2   ),
    .x2     (mux2_pwr_oe2   ),
    .x3     (mux3_pwr_oe2   ),
    .x4     (mux4_pwr_oe2   ),
    .x5     (1'b0           ),
    .x6     (1'b0           ),
    .x7     (1'b0           )
);

mux8 mux_pwr_oe3 (
    .sel    (major_mode),
    .y      (pwr_oe3        ),
    .x0     (mux0_pwr_oe3   ),
    .x1     (mux1_pwr_oe3   ),
    .x2     (mux2_pwr_oe3   ),
    .x3     (mux3_pwr_oe3   ),
    .x4     (mux4_pwr_oe3   ),
    .x5     (1'b0           ),
    .x6     (1'b0           ),
    .x7     (1'b0           )
);

mux8 mux_pwr_oe4 (
    .sel    (major_mode),
    .y      (pwr_oe4        ),
    .x0     (mux0_pwr_oe4   ),
    .x1     (mux1_pwr_oe4   ),
    .x2     (mux2_pwr_oe4   ),
    .x3     (mux3_pwr_oe4   ),
    .x4     (mux4_pwr_oe4   ),
    .x5     (1'b0           ),
    .x6     (1'b0           ),
    .x7     (1'b0           )
);

mux8 mux_pwr_lo (
    .sel    (major_mode),
    .y      (pwr_lo         ),
    .x0     (mux0_pwr_lo    ),
    .x1     (mux1_pwr_lo    ),
    .x2     (mux2_pwr_lo    ),
    .x3     (mux3_pwr_lo    ),
    .x4     (mux4_pwr_lo    ),
    .x5     (1'b0           ),
    .x6     (1'b0           ),
    .x7     (1'b0           )
);

mux8 mux_pwr_hi (
    .sel    (major_mode),
    .y      (pwr_hi      ),
    .x0     (mux0_pwr_hi    ),
    .x1     (mux1_pwr_hi    ),
    .x2     (mux2_pwr_hi    ),
    .x3     (mux3_pwr_hi    ),
    .x4     (mux4_pwr_hi    ),
    .x5     (1'b0           ),
    .x6     (1'b0           ),
    .x7     (1'b0           )
);

mux8 mux_adc_clk (
    .sel    (major_mode),
    .y      (adc_clk        ),
    .x0     (mux0_adc_clk   ),
    .x1     (mux1_adc_clk   ),
    .x2     (mux2_adc_clk   ),
    .x3     (mux3_adc_clk   ),
    .x4     (mux4_adc_clk   ),
    .x5     (1'b0           ),
    .x6     (1'b0           ),
    .x7     (1'b0           )
);

mux8 mux_dbg (
    .sel    (major_mode),
    .y      (dbg            ),
    .x0     (mux0_debug     ),
    .x1     (mux1_debug     ),
    .x2     (mux2_debug     ),
    .x3     (1'b0           ),
    .x4     (mux4_debug     ),
    .x5     (1'b0           ),
    .x6     (1'b0           ),
    .x7     (1'b0           )
);
endmodule
