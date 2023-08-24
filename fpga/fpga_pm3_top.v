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

// These defines are for reference only, they are passed by the Makefile so do not uncomment them here
// Proxmark3 RDV4 target
//`define PM3RDV4
// Proxmark3 generic target
//`define PM3GENERIC
// iCopy-X with XC3S100E
//`define PM3ICOPYX

// Pass desired defines to compiler to enable required modules
// WITH_LF  enables Low Frequency mode when defined else HF is enabled
//`define WITH_LF
// WITH_LF0 enables module reader
//`define WITH_LF0
// WITH_LF1 enables module edge detect
//`define WITH_LF1
// WITH_LF2 enables module passthrough
//`define WITH_LF2
// WITH_LF3 enables module ADC
//`define WITH_LF3

// WITH_HF0 enables module HF reader
//`define WITH_HF0
// WITH_HF1 enables module simulated tag
//`define WITH_HF1
// WITH_HF2 enables module ISO14443-A
//`define WITH_HF2
// WITH_HF3 enables module sniff
//`define WITH_HF3
// WITH_HF4 enables module ISO18092 FeliCa
//`define WITH_HF4
// WITH_HF5 enables module get trace
//`define WITH_HF5

//`ifdef WITH_LF  `include "clk_divider.v"    `endif
//`ifdef WITH_LF0 `include "lo_read.v"        `endif
//`ifdef WITH_LF1 `include "lo_edge_detect.v" `endif
//`ifdef WITH_LF2 `include "lo_passthru.v"    `endif
//`ifdef WITH_LF3 `include "lo_adc.v"         `endif
//
//`ifdef WITH_HF0 `include "hi_reader.v"      `endif
//`ifdef WITH_HF1 `include "hi_simulate.v"    `endif
//`ifdef WITH_HF2 `include "hi_iso14443a.v"   `endif
//`ifdef WITH_HF3 `include "hi_sniffer.v"     `endif
//`ifdef WITH_HF4 `include "hi_flite.v"       `endif
//`ifdef WITH_HF5 `include "hi_get_trace.v"   `endif

module fpga_top(
    input ck_1356meg,
    input ck_1356megb,
    input spck,
    input pck0,
    input ncs,
    input [7:0] adc_d,
    input cross_hi,
    input cross_lo,
    input mosi,
    input ssp_dout,

    output ssp_din,
    output ssp_frame,
    output ssp_clk,
    output adc_clk,
    output adc_noe,
    output miso,
    output pwr_lo,
    output pwr_hi,
    output pwr_oe1,
    output pwr_oe2,
    output pwr_oe3,
    output pwr_oe4,
    output dbg
);

// In all modes, let the ADC's outputs be enabled.
assign adc_noe = 1'b0;

//-----------------------------------------------------------------------------
// The SPI receiver. This sets up the configuration word, which the rest of
// the logic looks at to determine how to connect the A/D and the coil
// drivers (i.e., which section gets it). Also assign some symbolic names
// to the configuration bits, for use below.
//-----------------------------------------------------------------------------

// Receive 16bits of data from ARM here.
reg [15:0] shift_reg;
always @(posedge spck) if (~ncs) shift_reg <= {shift_reg[14:0], mosi};

reg trace_enable;

reg [7:0] lf_ed_threshold;

// adjustable frequency clock
wire [7:0] pck_cnt;
wire pck_divclk;
reg [7:0] divisor;
clk_divider div_clk(pck0, divisor, pck_cnt, pck_divclk);

`ifdef WITH_LF
reg [11:0] conf_word;
`else
reg [8:0] conf_word;
`endif

// We switch modes between transmitting to the 13.56 MHz tag and receiving
// from it, which means that we must make sure that we can do so without
// glitching, or else we will glitch the transmitted carrier.
always @(posedge ncs)
begin
    // 4 bit command
    case (shift_reg[15:12])
`ifdef WITH_LF
        `FPGA_CMD_SET_CONFREG:
        begin
            // 12 bit data
            conf_word <= shift_reg[11:0];
            if (shift_reg[8:6] == `FPGA_MAJOR_MODE_LF_EDGE_DETECT) lf_ed_threshold <= 127;  // default threshold
        end

        `FPGA_CMD_SET_DIVISOR:
            divisor <= shift_reg[7:0]; // 8bits

        `FPGA_CMD_SET_EDGE_DETECT_THRESHOLD:
            lf_ed_threshold <= shift_reg[7:0];  // 8 bits
`else
        `FPGA_CMD_SET_CONFREG:  conf_word <= shift_reg[8:0];
        `FPGA_CMD_TRACE_ENABLE: trace_enable <= shift_reg[0];
`endif
    endcase
end

//-----------------------------------------------------------------------------
// And then we instantiate the modules corresponding to each of the FPGA's
// major modes, and use muxes to connect the outputs of the active mode to
// the output pins.
//-----------------------------------------------------------------------------

// ############################################################################
// # Enable Low Frequency Modules
`ifdef WITH_LF

//   LF reader (generic)
`ifdef WITH_LF0
lo_read lr(
    .pck0              (pck0),
    .pck_divclk        (pck_divclk),
    .pck_cnt           (pck_cnt),
    .adc_d             (adc_d),
    .lf_field          (conf_word[0]),

    .ssp_din           (mux0_ssp_din),
    .ssp_frame         (mux0_ssp_frame),
    .ssp_clk           (mux0_ssp_clk),
    .adc_clk           (mux0_adc_clk),
    .pwr_lo            (mux0_pwr_lo),
    .pwr_hi            (mux0_pwr_hi),
    .pwr_oe1           (mux0_pwr_oe1),
    .pwr_oe2           (mux0_pwr_oe2),
    .pwr_oe3           (mux0_pwr_oe3),
    .pwr_oe4           (mux0_pwr_oe4),
    .debug             (mux0_debug)
);
`endif

//   LF edge detect (generic)
`ifdef WITH_LF1
lo_edge_detect le(
    .pck0              (pck0),
    .pck_divclk        (pck_divclk),
    .adc_d             (adc_d),
    .cross_lo          (cross_lo),
    .lf_field          (conf_word[0]),
    .lf_ed_toggle_mode (conf_word[1]),
    .lf_ed_threshold   (lf_ed_threshold),
    .ssp_dout          (ssp_dout),

    .ssp_frame         (mux1_ssp_frame),
    .ssp_clk           (mux1_ssp_clk),
    .adc_clk           (mux1_adc_clk),
    .pwr_lo            (mux1_pwr_lo),
    .pwr_hi            (mux1_pwr_hi),
    .pwr_oe1           (mux1_pwr_oe1),
    .pwr_oe2           (mux1_pwr_oe2),
    .pwr_oe3           (mux1_pwr_oe3),
    .pwr_oe4           (mux1_pwr_oe4),
    .debug             (mux1_debug)
);
`endif

//   LF passthrough
`ifdef WITH_LF2
lo_passthru lp(
    .pck_divclk        (pck_divclk),
    .cross_lo          (cross_lo),
    .ssp_dout          (ssp_dout),

    .ssp_din           (mux2_ssp_din),
    .adc_clk           (mux2_adc_clk),
    .pwr_lo            (mux2_pwr_lo),
    .pwr_hi            (mux2_pwr_hi),
    .pwr_oe1           (mux2_pwr_oe1),
    .pwr_oe2           (mux2_pwr_oe2),
    .pwr_oe3           (mux2_pwr_oe3),
    .pwr_oe4           (mux2_pwr_oe4),
    .debug             (mux2_debug)
);
`endif

//   LF ADC (read/write)
`ifdef WITH_LF3
lo_adc la(
    .pck0              (pck0),
    .adc_d             (adc_d),
    .divisor           (divisor),
    .lf_field          (conf_word[0]),
    .ssp_dout          (ssp_dout),

    .ssp_din           (mux3_ssp_din),
    .ssp_frame         (mux3_ssp_frame),
    .ssp_clk           (mux3_ssp_clk),
    .adc_clk           (mux3_adc_clk),
    .pwr_lo            (mux3_pwr_lo ),
    .pwr_hi            (mux3_pwr_hi ),
    .pwr_oe1           (mux3_pwr_oe1),
    .pwr_oe2           (mux3_pwr_oe2),
    .pwr_oe3           (mux3_pwr_oe3),
    .pwr_oe4           (mux3_pwr_oe4),
    .debug             (mux3_debug)
);
`endif // WITH_LF3

assign mux6_pwr_lo = 1'b1;
//   7 -- SPARE

`else // if WITH_LF not defined
// ############################################################################
// # Enable High Frequency Modules

//   HF reader
`ifdef WITH_HF0
hi_reader hr(
    .ck_1356meg (ck_1356megb),
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
`endif // WITH_HF0

//   HF simulated tag
`ifdef WITH_HF1
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
`endif // WITH_HF1

//   HF ISO14443-A
`ifdef WITH_HF2
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
    .debug      (mux2_debug)
);
`endif // WITH_HF2

//   HF sniff
`ifdef WITH_HF3
hi_sniffer he(
    .ck_1356meg  (ck_1356megb),
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
`endif //WITH_HF3

//   HF ISO18092 FeliCa
`ifdef WITH_HF4
hi_flite hfl(
    .ck_1356meg  (ck_1356megb),
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
`endif // WITH_HF4

//   HF get trace
`ifdef WITH_HF5
hi_get_trace gt(
    .ck_1356megb  (ck_1356megb),
    .adc_d        (adc_d),
    .trace_enable (trace_enable),
    .major_mode   (conf_word[8:6]),
    .ssp_din      (mux5_ssp_din),
    .ssp_frame    (mux5_ssp_frame),
    .ssp_clk      (mux5_ssp_clk)
);
`endif // WITH_HF5

`endif // WITH_LF

// These assignments must agree with the defines in fpgaloader.h
// Major modes Low Frequency
//   mux0 = LF reader (generic)
//   mux1 = LF edge detect (generic)
//   mux2 = LF passthrough
//   mux3 = LF ADC (read/write)
//   mux4 = SPARE
//   mux5 = SPARE
//   mux6 = SPARE
//   mux7 = FPGA_MAJOR_MODE_OFF

// Major modes High Frequency
//   mux0 = HF reader
//   mux1 = HF simulated tag
//   mux2 = HF ISO14443-A
//   mux3 = HF sniff
//   mux4 = HF ISO18092 FeliCa
//   mux5 = HF get trace
//   mux6 = unused
//   mux7 = FPGA_MAJOR_MODE_OFF

mux8 mux_ssp_clk   (.sel(conf_word[8:6]), .y(ssp_clk  ), .x0(mux0_ssp_clk  ), .x1(mux1_ssp_clk  ), .x2(mux2_ssp_clk  ), .x3(mux3_ssp_clk  ), .x4(mux4_ssp_clk  ), .x5(mux5_ssp_clk  ), .x6(mux6_ssp_clk  ), .x7(mux7_ssp_clk  ) );
mux8 mux_ssp_din   (.sel(conf_word[8:6]), .y(ssp_din  ), .x0(mux0_ssp_din  ), .x1(mux1_ssp_din  ), .x2(mux2_ssp_din  ), .x3(mux3_ssp_din  ), .x4(mux4_ssp_din  ), .x5(mux5_ssp_din  ), .x6(mux6_ssp_din  ), .x7(mux7_ssp_din  ) );
mux8 mux_ssp_frame (.sel(conf_word[8:6]), .y(ssp_frame), .x0(mux0_ssp_frame), .x1(mux1_ssp_frame), .x2(mux2_ssp_frame), .x3(mux3_ssp_frame), .x4(mux4_ssp_frame), .x5(mux5_ssp_frame), .x6(mux6_ssp_frame), .x7(mux7_ssp_frame) );
mux8 mux_pwr_oe1   (.sel(conf_word[8:6]), .y(pwr_oe1  ), .x0(mux0_pwr_oe1  ), .x1(mux1_pwr_oe1  ), .x2(mux2_pwr_oe1  ), .x3(mux3_pwr_oe1  ), .x4(mux4_pwr_oe1  ), .x5(mux5_pwr_oe1  ), .x6(mux6_pwr_oe1  ), .x7(mux7_pwr_oe1  ) );
mux8 mux_pwr_oe2   (.sel(conf_word[8:6]), .y(pwr_oe2  ), .x0(mux0_pwr_oe2  ), .x1(mux1_pwr_oe2  ), .x2(mux2_pwr_oe2  ), .x3(mux3_pwr_oe2  ), .x4(mux4_pwr_oe2  ), .x5(mux5_pwr_oe2  ), .x6(mux6_pwr_oe2  ), .x7(mux7_pwr_oe2  ) );
mux8 mux_pwr_oe3   (.sel(conf_word[8:6]), .y(pwr_oe3  ), .x0(mux0_pwr_oe3  ), .x1(mux1_pwr_oe3  ), .x2(mux2_pwr_oe3  ), .x3(mux3_pwr_oe3  ), .x4(mux4_pwr_oe3  ), .x5(mux5_pwr_oe3  ), .x6(mux6_pwr_oe3  ), .x7(mux7_pwr_oe3  ) );
mux8 mux_pwr_oe4   (.sel(conf_word[8:6]), .y(pwr_oe4  ), .x0(mux0_pwr_oe4  ), .x1(mux1_pwr_oe4  ), .x2(mux2_pwr_oe4  ), .x3(mux3_pwr_oe4  ), .x4(mux4_pwr_oe4  ), .x5(mux5_pwr_oe4  ), .x6(mux6_pwr_oe4  ), .x7(mux7_pwr_oe4  ) );
mux8 mux_pwr_lo    (.sel(conf_word[8:6]), .y(pwr_lo   ), .x0(mux0_pwr_lo   ), .x1(mux1_pwr_lo   ), .x2(mux2_pwr_lo   ), .x3(mux3_pwr_lo   ), .x4(mux4_pwr_lo   ), .x5(mux5_pwr_lo   ), .x6(mux6_pwr_lo   ), .x7(mux7_pwr_lo   ) );
mux8 mux_pwr_hi    (.sel(conf_word[8:6]), .y(pwr_hi   ), .x0(mux0_pwr_hi   ), .x1(mux1_pwr_hi   ), .x2(mux2_pwr_hi   ), .x3(mux3_pwr_hi   ), .x4(mux4_pwr_hi   ), .x5(mux5_pwr_hi   ), .x6(mux6_pwr_hi   ), .x7(mux7_pwr_hi   ) );
mux8 mux_adc_clk   (.sel(conf_word[8:6]), .y(adc_clk  ), .x0(mux0_adc_clk  ), .x1(mux1_adc_clk  ), .x2(mux2_adc_clk  ), .x3(mux3_adc_clk  ), .x4(mux4_adc_clk  ), .x5(mux5_adc_clk  ), .x6(mux6_adc_clk  ), .x7(mux7_adc_clk  ) );
mux8 mux_dbg       (.sel(conf_word[8:6]), .y(dbg      ), .x0(mux0_debug    ), .x1(mux1_debug    ), .x2(mux2_debug    ), .x3(mux3_debug    ), .x4(mux4_debug    ), .x5(mux5_debug    ), .x6(mux6_debug    ), .x7(mux7_debug    ) );

endmodule
