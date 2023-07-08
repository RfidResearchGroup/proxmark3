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
// Butterworth low pass IIR filter
// input: 8bit ADC signal, 1MS/s
// output: 8bit value, Fc=20khz
//
// coef: (using http://www-users.cs.york.ac.uk/~fisher/mkfilter/trad.html)
// Recurrence relation:
// y[n] = (  1 * x[n- 2])
//      + (  2 * x[n- 1])
//      + (  1 * x[n- 0])

//      + ( -0.8371816513 * y[n- 2])
//      + (  1.8226949252 * y[n- 1])
//
// therefore:
// a = [1,2,1]
// b = [-0.8371816513, 1.8226949252]
// b is approximated to b = [-0xd6/0x100, 0x1d3 / 0x100] (for optimization)
// gain = 2.761139367e2
//
// See details about its design see
// https://fail0verflow.com/blog/2014/proxmark3-fpga-iir-filter.html

module lp20khz_1MSa_iir_filter(
    input clk,
    input [7:0] adc_d,
    output rdy,
    output [7:0] out
);

    // clk is 24MHz, the IIR filter is designed for 1MS/s
    // hence we need to divide it by 24
    // using a shift register takes less area than a counter
    reg [23:0] cnt = 1;
    assign rdy = cnt[0];
    always @(posedge clk)
        cnt <= {cnt[22:0], cnt[23]};

    reg [7:0] x0 = 0;
    reg [7:0] x1 = 0;
    reg [16:0] y0 = 0;
    reg [16:0] y1 = 0;

    always @(posedge clk)
    begin
        if (rdy)
        begin
            x0 <= x1;
            x1 <= adc_d;
            y0 <= y1;
            y1 <=
                // center the signal:
                // input range is [0; 255]
                // We want "128" to be at the center of the 17bit register
                // (128+z)*gain = 17bit center
                // z = (1<<16)/gain - 128 = 109
                // We could use 9bit x registers for that, but that would be
                // a waste, let's just add the constant during the computation
                // (x0+109) + 2*(x1+109) + (x2+109) = x0 + 2*x1 + x2 + 436
                x0 + {x1, 1'b0} + adc_d + 436
                // we want "- y0 * 0xd6 / 0x100" using only shift and add
                // 0xd6 == 0b11010110
                // so *0xd6/0x100 is equivalent to
                // ((x << 1) + (x << 2) + (x << 4) + (x << 6) + (x << 7)) >> 8
                // which is also equivalent to
                // (x >> 7) + (x >> 6) + (x >> 4) + (x >> 2) + (x >> 1)
                - ((y0 >> 7) + (y0 >> 6) + (y0 >> 4) + (y0 >> 2) + (y0 >> 1)) // - y0 * 0xd6 / 0x100
                // we want "+ y1 * 0x1d3 / 0x100"
                // 0x1d3 == 0b111010011
                // so this is equivalent to
                // ((x << 0) + (x << 1) + (x << 4) + (x << 6) + (x << 7) + (x << 8)) >> 8
                // which is also equivalent to
                // (x >> 8) + (x >> 7) + (x >> 4) + (x >> 2) + (x >> 1) + (x >> 0)
                + ((y1 >> 8) + (y1 >> 7) + (y1 >> 4) + (y1 >> 2) + (y1 >> 1) + y1);
        end
    end

    // output: reduce to 8bit
    assign out = y1[16:9];

endmodule
