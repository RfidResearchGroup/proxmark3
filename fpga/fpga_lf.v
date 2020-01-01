//-----------------------------------------------------------------------------
// Jonathan Westhues, March 2006
// iZsh <izsh at fail0verflow.com>, June 2014
// Piwi, Feb 2019
// Anon, 2019
//-----------------------------------------------------------------------------
// Defining commands, modes and options. This must be aligned to the definitions in fpgaloader.h
// Note: the definitions here are without shifts

// Commands:
`define FPGA_CMD_SET_CONFREG                        1
`define FPGA_CMD_SET_DIVISOR                        2
`define FPGA_CMD_SET_EDGE_DETECT_THRESHOLD          3

// Major modes:
`define FPGA_MAJOR_MODE_LF_READER                   0
`define FPGA_MAJOR_MODE_LF_EDGE_DETECT              1
`define FPGA_MAJOR_MODE_LF_PASSTHRU                 2
`define FPGA_MAJOR_MODE_LF_ADC                      3

// Options for LF_ADC
`define FPGA_LF_ADC_READER_FIELD                    1

// Options for LF_EDGE_DETECT
`define FPGA_LF_EDGE_DETECT_READER_FIELD            1
`define FPGA_LF_EDGE_DETECT_TOGGLE_MODE             2

`include "lo_read.v"
`include "lo_passthru.v"
`include "lo_edge_detect.v"
`include "lo_adc.v"
`include "util.v"
`include "clk_divider.v"

module fpga_lf(
    input spck, output miso, input mosi, input ncs,
    input pck0, input ck_1356meg, input ck_1356megb,
    output pwr_lo, output pwr_hi,
    output pwr_oe1, output pwr_oe2, output pwr_oe3, output pwr_oe4,
    input [7:0] adc_d, output adc_clk, output adc_noe,
    output ssp_frame, output ssp_din, input ssp_dout, output ssp_clk,
    input cross_hi, input cross_lo,
    output dbg
);

//-----------------------------------------------------------------------------
// The SPI receiver. This sets up the configuration word, which the rest of
// the logic looks at to determine how to connect the A/D and the coil
// drivers (i.e., which section gets it). Also assign some symbolic names
// to the configuration bits, for use below.
//-----------------------------------------------------------------------------

reg [15:0] shift_reg;
reg [7:0] divisor;
reg [8:0] conf_word;

// threshold edge detect
reg [7:0] lf_ed_threshold;

always @(posedge ncs)
begin
    case (shift_reg[15:12])
        `FPGA_CMD_SET_CONFREG:
        begin
            conf_word <= shift_reg[8:0];
            if (shift_reg[8:6] == `FPGA_MAJOR_MODE_LF_EDGE_DETECT)
            begin
                lf_ed_threshold <= 127;              // default threshold
            end
        end
        `FPGA_CMD_SET_DIVISOR:
             divisor <= shift_reg[7:0];
        `FPGA_CMD_SET_EDGE_DETECT_THRESHOLD:
             lf_ed_threshold <= shift_reg[7:0];
    endcase
end

//
always @(posedge spck)
begin
    if (~ncs)
    begin
        shift_reg[15:1] <= shift_reg[14:0];
        shift_reg[0] <= mosi;
    end
end

wire [2:0] major_mode = conf_word[8:6];

// For the low-frequency configuration:
wire lf_field = conf_word[0];
wire lf_ed_toggle_mode = conf_word[1]; // for lo_edge_detect

//-----------------------------------------------------------------------------
// And then we instantiate the modules corresponding to each of the FPGA's
// major modes, and use muxes to connect the outputs of the active mode to
// the output pins.
//-----------------------------------------------------------------------------
wire [7:0] pck_cnt;
wire pck_divclk;
clk_divider div_clk(pck0, divisor, pck_cnt, pck_divclk);

lo_read lr(
    pck0, pck_cnt, pck_divclk,
    lr_pwr_lo, lr_pwr_hi, lr_pwr_oe1, lr_pwr_oe2, lr_pwr_oe3, lr_pwr_oe4,
    adc_d, lr_adc_clk,
    lr_ssp_frame, lr_ssp_din, lr_ssp_clk,
    lr_dbg, lf_field
);

lo_passthru lp(
    pck_divclk,
    lp_pwr_lo, lp_pwr_hi, lp_pwr_oe1, lp_pwr_oe2, lp_pwr_oe3, lp_pwr_oe4,
    lp_adc_clk,
    lp_ssp_din, ssp_dout,
    cross_lo,
    lp_dbg
);

lo_edge_detect le(
    pck0, pck_divclk,
    le_pwr_lo, le_pwr_hi, le_pwr_oe1, le_pwr_oe2, le_pwr_oe3, le_pwr_oe4,
    adc_d, le_adc_clk,
    le_ssp_frame, ssp_dout, le_ssp_clk,
    cross_lo,
    le_dbg,
    lf_field,
    lf_ed_toggle_mode, lf_ed_threshold
);

lo_adc la(
    pck0,
    la_pwr_lo, la_pwr_hi, la_pwr_oe1, la_pwr_oe2, la_pwr_oe3, la_pwr_oe4,
    adc_d, la_adc_clk,
    la_ssp_frame, la_ssp_din, ssp_dout, la_ssp_clk,
    la_dbg, divisor,
    lf_field
);

// Major modes:
//   000 --  LF reader (generic)
//   001 --  LF edge detect (generic)
//   010 --  LF passthrough
//   011 --  LF ADC (read/write)
//   110 --  FPGA_MAJOR_MODE_OFF_LF (rdv40 specific)
//   111 --  FPGA_MAJOR_MODE_OFF
//                                           000           001           010          011           100   101   110   111
mux8 mux_ssp_clk     (major_mode, ssp_clk,   lr_ssp_clk,   le_ssp_clk,   1'b0,        la_ssp_clk,   1'b0, 1'b0, 1'b0, 1'b0);
mux8 mux_ssp_din     (major_mode, ssp_din,   lr_ssp_din,   1'b0,         lp_ssp_din,  la_ssp_din,   1'b0, 1'b0, 1'b0, 1'b0);
mux8 mux_ssp_frame   (major_mode, ssp_frame, lr_ssp_frame, le_ssp_frame, 1'b0,        la_ssp_frame, 1'b0, 1'b0, 1'b0, 1'b0);
mux8 mux_pwr_oe1     (major_mode, pwr_oe1,   lr_pwr_oe1,   le_pwr_oe1,   lp_pwr_oe1,  la_pwr_oe1,   1'b0, 1'b0, 1'b0, 1'b0);
mux8 mux_pwr_oe2     (major_mode, pwr_oe2,   lr_pwr_oe2,   le_pwr_oe2,   lp_pwr_oe2,  la_pwr_oe2,   1'b0, 1'b0, 1'b0, 1'b0);
mux8 mux_pwr_oe3     (major_mode, pwr_oe3,   lr_pwr_oe3,   le_pwr_oe3,   lp_pwr_oe3,  la_pwr_oe3,   1'b0, 1'b0, 1'b0, 1'b0);
mux8 mux_pwr_oe4     (major_mode, pwr_oe4,   lr_pwr_oe4,   le_pwr_oe4,   lp_pwr_oe4,  la_pwr_oe4,   1'b0, 1'b0, 1'b0, 1'b0);
mux8 mux_pwr_lo      (major_mode, pwr_lo,    lr_pwr_lo,    le_pwr_lo,    lp_pwr_lo,   la_pwr_lo,    1'b0, 1'b0, 1'b1, 1'b0);
mux8 mux_pwr_hi      (major_mode, pwr_hi,    lr_pwr_hi,    le_pwr_hi,    lp_pwr_hi,   la_pwr_hi,    1'b0, 1'b0, 1'b0, 1'b0);
mux8 mux_adc_clk     (major_mode, adc_clk,   lr_adc_clk,   le_adc_clk,   lp_adc_clk,  la_adc_clk,   1'b0, 1'b0, 1'b0, 1'b0);
mux8 mux_dbg         (major_mode, dbg,       lr_dbg,       le_dbg,       lp_dbg,      la_dbg,       1'b0, 1'b0, 1'b0, 1'b0);

// In all modes, let the ADC's outputs be enabled.
assign adc_noe = 1'b0;

endmodule
