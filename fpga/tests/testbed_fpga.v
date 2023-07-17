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

`include "fpga.v"

module testbed_fpga;
    reg spck, mosi, ncs;
    wire miso;
    reg pck0i, ck_1356meg, ck_1356megb;
    wire pwr_lo, pwr_hi, pwr_oe1, pwr_oe2, pwr_oe3, pwr_oe4;
    reg [7:0] adc_d;
    wire adc_clk, adc_noe;
    reg ssp_dout;
    wire ssp_frame, ssp_din, ssp_clk;

    fpga dut(
        spck, miso, mosi, ncs,
        pck0i, ck_1356meg, ck_1356megb,
        pwr_lo, pwr_hi, pwr_oe1, pwr_oe2, pwr_oe3, pwr_oe4,
        adc_d, adc_clk, adc_noe,
        ssp_frame, ssp_din, ssp_dout, ssp_clk
    );

    integer i;

    initial begin

        // init inputs
        #5 ncs=1;
        #5 spck = 1;
        #5 mosi = 1;

        #50 ncs=0;
        for (i = 0 ;  i < 8 ;  i = i + 1) begin
            #5 mosi = $random;
            #5 spck = 0;
            #5 spck = 1;
        end
        #5 ncs=1;

        #50 ncs=0;
        for (i = 0 ;  i < 8 ;  i = i + 1) begin
            #5 mosi = $random;
            #5 spck = 0;
            #5 spck = 1;
        end
        #5 ncs=1;

        #50 mosi=1;
        $finish;
    end

endmodule // main
