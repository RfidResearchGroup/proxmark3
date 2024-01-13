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

`include "lo_read.v"
/*
    pck0            - input main 24MHz clock (PLL / 4)
    [7:0] adc_d     - input data from A/D converter
    lo_is_125khz    - input freq selector (1=125kHz, 0=136kHz)

    pwr_lo          - output to coil drivers (ssp_clk / 8)
    adc_clk         - output A/D clock signal
    ssp_frame       - output SSS frame indicator (goes high while the 8 bits are shifted)
    ssp_din         - output SSP data to ARM (shifts 8 bit A/D value serially to ARM MSB first)
    ssp_clk         - output SSP clock signal 1MHz/1.09MHz (pck0 / 2*(11+lo_is_125khz) )

    ck_1356meg      - input unused
    ck_1356megb     - input unused
    ssp_dout        - input unused
    cross_hi        - input unused
    cross_lo        - input unused

    pwr_hi          - output unused, tied low
    pwr_oe1         - output unused, undefined
    pwr_oe2         - output unused, undefined
    pwr_oe3         - output unused, undefined
    pwr_oe4         - output unused, undefined
    dbg             - output alias for adc_clk
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
    reg ssp_dout;
    wire pwr_hi;
    wire pwr_oe1;
    wire pwr_oe2;
    wire pwr_oe3;
    wire pwr_oe4;
    wire cross_lo;
    wire cross_hi;
    wire dbg;

    lo_read #(5,10) dut(
    .pck0(pck0),
    .ck_1356meg(ck_1356meg),
    .ck_1356megb(ck_1356megb),
    .pwr_lo(pwr_lo),
    .pwr_hi(pwr_hi),
    .pwr_oe1(pwr_oe1),
    .pwr_oe2(pwr_oe2),
    .pwr_oe3(pwr_oe3),
    .pwr_oe4(pwr_oe4),
    .adc_d(adc_d),
    .adc_clk(adc_clk),
    .ssp_frame(ssp_frame),
    .ssp_din(ssp_din),
    .ssp_dout(ssp_dout),
    .ssp_clk(ssp_clk),
    .cross_hi(cross_hi),
    .cross_lo(cross_lo),
    .dbg(dbg),
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
        ssp_dout = 0;
        lo_is_125khz = 1;
        divisor = 255;  //min 16, 95=125kHz, max 255

        // simulate 4 A/D cycles at 125kHz
        for (i = 0 ;  i < 8 ;  i = i + 1) begin
            crank_dut;
        end
        $finish;
    end
endmodule // main
