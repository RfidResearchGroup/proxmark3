//-----------------------------------------------------------------------------
// Copyright (C) 2014 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// input clk is 24MHz
`include "min_max_tracker.v"

module lf_edge_detect(input clk, input [7:0] adc_d, input [7:0] lf_ed_threshold,
    output [7:0] max, output [7:0] min,
    output [7:0] high_threshold, output [7:0] highz_threshold,
    output [7:0] lowz_threshold, output [7:0] low_threshold,
    output edge_state, output edge_toggle);

    min_max_tracker tracker(clk, adc_d, lf_ed_threshold, min, max);

    // auto-tune
    assign high_threshold = (max + min) / 2 + (max - min) / 4;
    assign highz_threshold = (max + min) / 2 + (max - min) / 8;
    assign lowz_threshold = (max + min) / 2 - (max - min) / 8;
    assign low_threshold = (max + min) / 2 - (max - min) / 4;

    // heuristic to see if it makes sense to try to detect an edge
    wire enabled =
        (high_threshold > highz_threshold)
        & (highz_threshold > lowz_threshold)
        & (lowz_threshold > low_threshold)
        & ((high_threshold - highz_threshold) > 8)
        & ((highz_threshold - lowz_threshold) > 16)
        & ((lowz_threshold - low_threshold) > 8);

    // Toggle the output with hysteresis
    // Set to high if the ADC value is above the threshold
    // Set to low if the ADC value is below the threshold
    reg is_high = 0;
    reg is_low = 0;
    reg is_zero = 0;
    reg trigger_enabled = 1;
    reg output_edge = 0;
    reg output_state;

    always @(posedge clk)
    begin
        is_high <= (adc_d >= high_threshold);
        is_low <= (adc_d <= low_threshold);
        is_zero <= ((adc_d > lowz_threshold) & (adc_d < highz_threshold));
    end

    // all edges detection
    always @(posedge clk)
    if (enabled) begin
        // To enable detecting two consecutive peaks at the same level
        // (low or high) we check whether or not we went back near 0 in-between.
        // This extra check is necessary to prevent from noise artifacts
        // around the threshold values.
        if (trigger_enabled & (is_high | is_low)) begin
            output_edge <= ~output_edge;
            trigger_enabled <= 0;
        end else
            trigger_enabled <= trigger_enabled | is_zero;
    end

    // edge states
    always @(posedge clk)
    if (enabled) begin
        if (is_high)
            output_state <= 1'd1;
        else if (is_low)
            output_state <= 1'd0;
    end

    assign edge_state = output_state;
    assign edge_toggle = output_edge;

endmodule
