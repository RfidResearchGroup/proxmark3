//-----------------------------------------------------------------------------
// Copyright (C) 2014 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// track min and max peak values (envelope follower)
//
// NB: the min value (resp. max value) is updated only when the next high peak
// (resp. low peak) is reached/detected, since you can't know it isn't a
// local minima (resp. maxima) until then.
// This also means the peaks are detected with an unpredictable delay.
// This algorithm therefore can't be used directly for realtime peak detections,
// but it can be used as a simple envelope follower.
module min_max_tracker(input clk, input [7:0] adc_d, input [7:0] threshold,
    output [7:0] min, output [7:0] max);

    reg [7:0] min_val = 255;
    reg [7:0] max_val = 0;
    reg [7:0] cur_min_val = 255;
    reg [7:0] cur_max_val = 0;
    reg [1:0] state = 0;

    always @(posedge clk)
    begin
        case (state)
        0: // initialize
            begin
                if (cur_max_val >= ({1'b0, adc_d} + threshold))
                    state <= 2;
                else if (adc_d >= ({1'b0, cur_min_val} + threshold))
                    state <= 1;
                if (cur_max_val <= adc_d)
                    cur_max_val <= adc_d;
                else if (adc_d <= cur_min_val)
                    cur_min_val <= adc_d;
            end
        1: // high phase
            begin
                if (cur_max_val <= adc_d)
                    cur_max_val <= adc_d;
                else if (({1'b0, adc_d} + threshold) <= cur_max_val) begin
                    state <= 2;
                    cur_min_val <= adc_d;
                    max_val <= cur_max_val;
                end
            end
        2: // low phase
            begin
                if (adc_d <= cur_min_val)
                    cur_min_val <= adc_d;
                else if (adc_d >= ({1'b0, cur_min_val} + threshold)) begin
                    state <= 1;
                    cur_max_val <= adc_d;
                    min_val <= cur_min_val;
                end
            end
        endcase
    end

    assign min = min_val;
    assign max = max_val;

endmodule
