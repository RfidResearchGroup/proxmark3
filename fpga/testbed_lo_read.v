`include "lo_read_org.v"
`include "lo_read.v"
/*
	pck0			- input main 24Mhz clock (PLL / 4)
	[7:0] adc_d		- input data from A/D converter
	lo_is_125khz	- input freq selector (1=125Khz, 0=136Khz)

	pwr_lo			- output to coil drivers (ssp_clk / 8)
	adc_clk			- output A/D clock signal
	ssp_frame		- output SSS frame indicator (goes high while the 8 bits are shifted)
	ssp_din			- output SSP data to ARM (shifts 8 bit A/D value serially to ARM MSB first)
	ssp_clk			- output SSP clock signal 1Mhz/1.09Mhz (pck0 / 2*(11+lo_is_125khz) )

	ck_1356meg		- input unused
	ck_1356megb		- input unused
	ssp_dout		- input unused
	cross_hi		- input unused
	cross_lo		- input unused

	pwr_hi			- output unused, tied low
	pwr_oe1			- output unused, undefined
	pwr_oe2			- output unused, undefined
	pwr_oe3			- output unused, undefined
	pwr_oe4			- output unused, undefined
	dbg				- output alias for adc_clk
*/

module testbed_lo_read;
	reg  pck0;
	reg  [7:0] adc_d;
	reg  lo_is_125khz;
	reg [15:0] divisor;

	wire pwr_lo;
	wire adc_clk;
	wire ck_1356meg;
	wire ck_1356megb;
	wire ssp_frame;
	wire ssp_din;
	wire ssp_clk;
	wire ssp_dout;
	wire pwr_hi;
	wire pwr_oe1;
	wire pwr_oe2;
	wire pwr_oe3;
	wire pwr_oe4;
	wire cross_lo;
	wire cross_hi;
	wire dbg;

	lo_read_org #(5,10) dut1(
	.pck0(pck0),
	.ck_1356meg(ack_1356meg),
	.ck_1356megb(ack_1356megb),
	.pwr_lo(apwr_lo),
	.pwr_hi(apwr_hi),
	.pwr_oe1(apwr_oe1),
	.pwr_oe2(apwr_oe2),
	.pwr_oe3(apwr_oe3),
	.pwr_oe4(apwr_oe4),
	.adc_d(adc_d),
	.adc_clk(adc_clk),
	.ssp_frame(assp_frame),
	.ssp_din(assp_din),
	.ssp_dout(assp_dout),
	.ssp_clk(assp_clk),
	.cross_hi(across_hi),
	.cross_lo(across_lo),
	.dbg(adbg),
	.lo_is_125khz(lo_is_125khz)
	);

	lo_read #(5,10) dut2(
	.pck0(pck0),
	.ck_1356meg(bck_1356meg),
	.ck_1356megb(bck_1356megb),
	.pwr_lo(bpwr_lo),
	.pwr_hi(bpwr_hi),
	.pwr_oe1(bpwr_oe1),
	.pwr_oe2(bpwr_oe2),
	.pwr_oe3(bpwr_oe3),
	.pwr_oe4(bpwr_oe4),
	.adc_d(adc_d),
	.adc_clk(badc_clk),
	.ssp_frame(bssp_frame),
	.ssp_din(bssp_din),
	.ssp_dout(bssp_dout),
	.ssp_clk(bssp_clk),
	.cross_hi(bcross_hi),
	.cross_lo(bcross_lo),
	.dbg(bdbg),
	.lo_is_125khz(lo_is_125khz),
	.divisor(divisor)
	);

	integer idx, i, adc_val=8;

	// main clock
	always #5 pck0 = !pck0;

	task crank_dut;
	begin
		@(posedge adc_clk) ;
		adc_d = adc_val;
		adc_val = (adc_val *2) + 53;
	end
	endtask

	initial begin

		// init inputs
		pck0 = 0;
		adc_d = 0;
		lo_is_125khz = 1;
		divisor=255;  //min 19, 95=125Khz, max 255

		// simulate 4 A/D cycles at 125Khz
		for (i = 0 ;  i < 8 ;  i = i + 1) begin
			crank_dut;
		end
		$finish;
	end
endmodule // main
