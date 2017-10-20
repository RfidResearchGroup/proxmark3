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
// iZsh <izsh at fail0verflow.com>, June 2014
// Satsuoni <>, October 2017 , added FeliCa support.
//-----------------------------------------------------------------------------

`include "hi_flite.v"
`include "util.v"
`include "hi_sniffer.v"

module fpga_nfc(
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
reg [7:0] conf_word;

// We switch modes between transmitting to the 13.56 MHz tag and receiving
// from it, which means that we must make sure that we can do so without
// glitching, or else we will glitch the transmitted carrier.
always @(posedge ncs)
begin
	case(shift_reg[15:12])
		4'b0001: conf_word <= shift_reg[7:0];		// FPGA_CMD_SET_CONFREG
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

// For the high-frequency transmit configuration: modulation depth, either
// 100% (just quite driving antenna, steady LOW), or shallower (tri-state
// some fraction of the buffers)
//wire hi_read_tx_shallow_modulation = conf_word[0];

// For the high-frequency receive correlator: frequency against which to
// correlate.
wire hi_read_rx_xcorr_848 = conf_word[0];
// and whether to drive the coil (reader) or just short it (snooper)
wire hi_read_rx_xcorr_snoop = conf_word[1];
// divide subcarrier frequency by 4
wire hi_read_rx_xcorr_quarter = conf_word[2];

// For the high-frequency simulated tag: what kind of modulation to use.
wire [2:0] hi_simulate_mod_type = conf_word[2:0];

//-----------------------------------------------------------------------------
// And then we instantiate the modules corresponding to each of the FPGA's
// major modes, and use muxes to connect the outputs of the active mode to
// the output pins.
//-----------------------------------------------------------------------------
hi_sniffer he(
       pck0, ck_1356meg, ck_1356megb,
       he_pwr_lo, he_pwr_hi, he_pwr_oe1, he_pwr_oe2, he_pwr_oe3,       he_pwr_oe4,
       adc_d, he_adc_clk,
       he_ssp_frame, he_ssp_din, ssp_dout, he_ssp_clk,
       cross_hi, cross_lo,
       he_dbg,
       hi_read_rx_xcorr_848, hi_read_rx_xcorr_snoop, hi_read_rx_xcorr_quarter
);


hi_flite hfl(
       pck0, ck_1356meg, ck_1356megb,
       hfl_pwr_lo, hfl_pwr_hi, hfl_pwr_oe1, hfl_pwr_oe2, hfl_pwr_oe3,       hfl_pwr_oe4,
       adc_d, hfl_adc_clk,
       hfl_ssp_frame, hfl_ssp_din, ssp_dout, hfl_ssp_clk,
       cross_hi, cross_lo,
       hfl_dbg,
       hi_simulate_mod_type
);

// Major modes:
// no major modes here for now, except NFC demod/sim. Maybe I should remove mux at some point, unless I can think of more modes
//   000 --  
//   001 --  
//   010 --  
//   011 --  
//   100 -- 
//   101 --  HF NFC demod, just to copy it for now
//   111 --  everything off

mux8 mux_ssp_clk		(major_mode, ssp_clk,   1'b0,   1'b0,   1'b0,   1'b0,  he_ssp_clk,   hfl_ssp_clk, 1'b0, 1'b0);
mux8 mux_ssp_din		(major_mode, ssp_din,   1'b0,   1'b0,   1'b0,   1'b0,   he_ssp_din,   hfl_ssp_din, 1'b0, 1'b0);
mux8 mux_ssp_frame		(major_mode, ssp_frame, 1'b0,   1'b0,   1'b0,   1'b0,   he_ssp_frame, hfl_ssp_frame, 1'b0, 1'b0);
mux8 mux_pwr_oe1		(major_mode, pwr_oe1,   1'b0,   1'b0,   1'b0,   1'b0,   he_pwr_oe1,   hfl_pwr_oe1, 1'b0, 1'b0);
mux8 mux_pwr_oe2		(major_mode, pwr_oe2,   1'b0,   1'b0,   1'b0,   1'b0,   he_pwr_oe2,   hfl_pwr_oe2, 1'b0, 1'b0);
mux8 mux_pwr_oe3		(major_mode, pwr_oe3,   1'b0,   1'b0,   1'b0,   1'b0,   he_pwr_oe3,   hfl_pwr_oe3, 1'b0, 1'b0);
mux8 mux_pwr_oe4		(major_mode, pwr_oe4,   1'b0,   1'b0,   1'b0,   1'b0,   he_pwr_oe4,   hfl_pwr_oe4, 1'b0, 1'b0);
mux8 mux_pwr_lo			(major_mode, pwr_lo,    1'b0,   1'b0,   1'b0,   1'b0,   he_pwr_lo,    hfl_pwr_lo, 1'b0, 1'b0);
mux8 mux_pwr_hi			(major_mode, pwr_hi,    1'b0,   1'b0,   1'b0,   1'b0,   he_pwr_hi,    hfl_pwr_hi, 1'b0, 1'b0);
mux8 mux_adc_clk		(major_mode, adc_clk,   1'b0,   1'b0,   1'b0,   1'b0,   he_adc_clk,   hfl_adc_clk, 1'b0, 1'b0);
mux8 mux_dbg			(major_mode, dbg,       1'b0,   1'b0,   1'b0,   1'b0,  hfl_dbg,       hfl_dbg, 1'b0, 1'b0);

// In all modes, let the ADC's outputs be enabled.
assign adc_noe = 1'b0;

endmodule
