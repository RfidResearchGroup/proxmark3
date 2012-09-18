//-----------------------------------------------------------------------------
// The FPGA is responsible for interfacing between the A/D, the coil drivers,
// and the ARM. In the low-frequency modes it passes the data straight
// through, so that the ARM gets raw A/D samples over the SSP. In the high-
// frequency modes, the FPGA might perform some demodulation first, to
// reduce the amount of data that we must send to the ARM.
//
// I am not really an FPGA/ASIC designer, so I am sure that a lot of this
// could be improved.
//
// Jonathan Westhues, March 2006
// Added ISO14443-A support by Gerhard de Koning Gans, April 2008
//-----------------------------------------------------------------------------

`include "lo_read.v"
`include "lo_passthru.v"
`include "lo_edge_detect.v"
`include "hi_read_tx.v"
`include "hi_read_rx_xcorr.v"
`include "hi_simulate.v"
`include "hi_iso14443a.v"
`include "util.v"

module fpga(
	spcki, miso, mosi, ncs,
	pck0i, ck_1356meg, ck_1356megb,
	pwr_lo, pwr_hi, pwr_oe1, pwr_oe2, pwr_oe3, pwr_oe4,
	adc_d, adc_clk, adc_noe,
	ssp_frame, ssp_din, ssp_dout, ssp_clk,
	cross_hi, cross_lo,
	dbg
);
	input spcki, mosi, ncs;
	output miso;
	input pck0i, ck_1356meg, ck_1356megb;
	output pwr_lo, pwr_hi, pwr_oe1, pwr_oe2, pwr_oe3, pwr_oe4;
	input [7:0] adc_d;
	output adc_clk, adc_noe;
	input ssp_dout;
	output ssp_frame, ssp_din, ssp_clk;
	input cross_hi, cross_lo;
	output dbg;

//assign pck0 = pck0i;
	IBUFG #(.IOSTANDARD("DEFAULT") ) pck0b(
		.O(pck0),
		.I(pck0i)
	);
//assign spck = spcki;
	IBUFG #(.IOSTANDARD("DEFAULT") ) spckb(
		.O(spck),
		.I(spcki)
	);
//-----------------------------------------------------------------------------
// The SPI receiver. This sets up the configuration word, which the rest of
// the logic looks at to determine how to connect the A/D and the coil
// drivers (i.e., which section gets it). Also assign some symbolic names
// to the configuration bits, for use below.
//-----------------------------------------------------------------------------

reg [15:0] shift_reg;
reg [7:0] divisor;
reg [7:0] conf_word;

// We switch modes between transmitting to the 13.56 MHz tag and receiving
// from it, which means that we must make sure that we can do so without
// glitching, or else we will glitch the transmitted carrier.
always @(posedge ncs)
begin
	case(shift_reg[15:12])
		4'b0001: conf_word <= shift_reg[7:0];
		4'b0010: divisor <= shift_reg[7:0];
	endcase
end

always @(posedge spck)
begin
	if(~ncs)
	begin
		shift_reg[15:1] <= shift_reg[14:0];
		shift_reg[0] <= mosi;
	end
end

wire [2:0] major_mode;
assign major_mode = conf_word[7:5];

// For the low-frequency configuration:
wire lo_is_125khz;
assign lo_is_125khz = conf_word[3];

// For the high-frequency transmit configuration: modulation depth, either
// 100% (just quite driving antenna, steady LOW), or shallower (tri-state
// some fraction of the buffers)
wire hi_read_tx_shallow_modulation;
assign hi_read_tx_shallow_modulation = conf_word[0];

// For the high-frequency receive correlator: frequency against which to
// correlate.
wire hi_read_rx_xcorr_848;
assign hi_read_rx_xcorr_848 = conf_word[0];
// and whether to drive the coil (reader) or just short it (snooper)
wire hi_read_rx_xcorr_snoop;
assign hi_read_rx_xcorr_snoop = conf_word[1];

// Divide the expected subcarrier frequency for hi_read_rx_xcorr by 4
wire hi_read_rx_xcorr_quarter;
assign hi_read_rx_xcorr_quarter = conf_word[2];

// For the high-frequency simulated tag: what kind of modulation to use.
wire [2:0] hi_simulate_mod_type;
assign hi_simulate_mod_type = conf_word[2:0];

// For the high-frequency simulated tag: what kind of modulation to use.
wire lf_field;
assign lf_field = conf_word[0];

//-----------------------------------------------------------------------------
// And then we instantiate the modules corresponding to each of the FPGA's
// major modes, and use muxes to connect the outputs of the active mode to
// the output pins.
//-----------------------------------------------------------------------------

lo_read lr(
	pck0, ck_1356meg, ck_1356megb,
	lr_pwr_lo, lr_pwr_hi, lr_pwr_oe1, lr_pwr_oe2, lr_pwr_oe3, lr_pwr_oe4,
	adc_d, lr_adc_clk,
	lr_ssp_frame, lr_ssp_din, ssp_dout, lr_ssp_clk,
	cross_hi, cross_lo,
	lr_dbg,
	lo_is_125khz, divisor
);

lo_passthru lp(
	pck0, ck_1356meg, ck_1356megb,
	lp_pwr_lo, lp_pwr_hi, lp_pwr_oe1, lp_pwr_oe2, lp_pwr_oe3, lp_pwr_oe4,
	adc_d, lp_adc_clk,
	lp_ssp_frame, lp_ssp_din, ssp_dout, lp_ssp_clk,
	cross_hi, cross_lo,
	lp_dbg, divisor
);

lo_edge_detect ls(
	pck0, ck_1356meg, ck_1356megb,
	ls_pwr_lo, ls_pwr_hi, ls_pwr_oe1, ls_pwr_oe2, ls_pwr_oe3, ls_pwr_oe4,
	adc_d, ls_adc_clk,
	ls_ssp_frame, ls_ssp_din, ssp_dout, ls_ssp_clk,
	cross_hi, cross_lo,
	ls_dbg, divisor,
	lf_field
);

hi_read_tx ht(
	pck0, ck_1356meg, ck_1356megb,
	ht_pwr_lo, ht_pwr_hi, ht_pwr_oe1, ht_pwr_oe2, ht_pwr_oe3, ht_pwr_oe4,
	adc_d, ht_adc_clk,
	ht_ssp_frame, ht_ssp_din, ssp_dout, ht_ssp_clk,
	cross_hi, cross_lo,
	ht_dbg,
	hi_read_tx_shallow_modulation
);

hi_read_rx_xcorr hrxc(
	pck0, ck_1356meg, ck_1356megb,
	hrxc_pwr_lo, hrxc_pwr_hi, hrxc_pwr_oe1, hrxc_pwr_oe2, hrxc_pwr_oe3,	hrxc_pwr_oe4,
	adc_d, hrxc_adc_clk,
	hrxc_ssp_frame, hrxc_ssp_din, ssp_dout, hrxc_ssp_clk,
	cross_hi, cross_lo,
	hrxc_dbg,
	hi_read_rx_xcorr_848, hi_read_rx_xcorr_snoop, hi_read_rx_xcorr_quarter
);

hi_simulate hs(
	pck0, ck_1356meg, ck_1356megb,
	hs_pwr_lo, hs_pwr_hi, hs_pwr_oe1, hs_pwr_oe2, hs_pwr_oe3, hs_pwr_oe4,
	adc_d, hs_adc_clk,
	hs_ssp_frame, hs_ssp_din, ssp_dout, hs_ssp_clk,
	cross_hi, cross_lo,
	hs_dbg,
	hi_simulate_mod_type
);

hi_iso14443a hisn(
	pck0, ck_1356meg, ck_1356megb,
	hisn_pwr_lo, hisn_pwr_hi, hisn_pwr_oe1, hisn_pwr_oe2, hisn_pwr_oe3,	hisn_pwr_oe4,
	adc_d, hisn_adc_clk,
	hisn_ssp_frame, hisn_ssp_din, ssp_dout, hisn_ssp_clk,
	cross_hi, cross_lo,
	hisn_dbg,
	hi_simulate_mod_type
);

// Major modes:
//   000 --  LF reader (generic)
//   001 --  LF simulated tag (generic)
//   010 --  HF reader, transmitting to tag; modulation depth selectable
//   011 --  HF reader, receiving from tag, correlating as it goes; frequency selectable
//   100 --  HF simulated tag
//   101 --  HF ISO14443-A
//   110 --  LF passthrough
//   111 --  everything off

mux8 mux_ssp_clk		(major_mode, ssp_clk,   lr_ssp_clk,   ls_ssp_clk,   ht_ssp_clk,   hrxc_ssp_clk,   hs_ssp_clk,   hisn_ssp_clk,   lp_ssp_clk,   1'b0);
mux8 mux_ssp_din		(major_mode, ssp_din,   lr_ssp_din,   ls_ssp_din,   ht_ssp_din,   hrxc_ssp_din,   hs_ssp_din,   hisn_ssp_din,   lp_ssp_din,   1'b0);
mux8 mux_ssp_frame	(major_mode, ssp_frame, lr_ssp_frame, ls_ssp_frame, ht_ssp_frame, hrxc_ssp_frame, hs_ssp_frame, hisn_ssp_frame, lp_ssp_frame, 1'b0);
mux8 mux_pwr_oe1		(major_mode, pwr_oe1,   lr_pwr_oe1,   ls_pwr_oe1,   ht_pwr_oe1,   hrxc_pwr_oe1,   hs_pwr_oe1,   hisn_pwr_oe1,   lp_pwr_oe1,   1'b0);
mux8 mux_pwr_oe2		(major_mode, pwr_oe2,   lr_pwr_oe2,   ls_pwr_oe2,   ht_pwr_oe2,   hrxc_pwr_oe2,   hs_pwr_oe2,   hisn_pwr_oe2,   lp_pwr_oe2,   1'b0);
mux8 mux_pwr_oe3		(major_mode, pwr_oe3,   lr_pwr_oe3,   ls_pwr_oe3,   ht_pwr_oe3,   hrxc_pwr_oe3,   hs_pwr_oe3,   hisn_pwr_oe3,   lp_pwr_oe3,   1'b0);
mux8 mux_pwr_oe4		(major_mode, pwr_oe4,   lr_pwr_oe4,   ls_pwr_oe4,   ht_pwr_oe4,   hrxc_pwr_oe4,   hs_pwr_oe4,   hisn_pwr_oe4,   lp_pwr_oe4,   1'b0);
mux8 mux_pwr_lo			(major_mode, pwr_lo,    lr_pwr_lo,    ls_pwr_lo,    ht_pwr_lo,    hrxc_pwr_lo,    hs_pwr_lo,    hisn_pwr_lo,    lp_pwr_lo,    1'b0);
mux8 mux_pwr_hi			(major_mode, pwr_hi,    lr_pwr_hi,    ls_pwr_hi,    ht_pwr_hi,    hrxc_pwr_hi,    hs_pwr_hi,    hisn_pwr_hi,    lp_pwr_hi,    1'b0);
mux8 mux_adc_clk		(major_mode, adc_clk,   lr_adc_clk,   ls_adc_clk,   ht_adc_clk,   hrxc_adc_clk,   hs_adc_clk,   hisn_adc_clk,   lp_adc_clk,   1'b0);
mux8 mux_dbg				(major_mode, dbg,       lr_dbg,       ls_dbg,       ht_dbg,       hrxc_dbg,       hs_dbg,       hisn_dbg,       lp_dbg,       1'b0);

// In all modes, let the ADC's outputs be enabled.
assign adc_noe = 1'b0;

endmodule
