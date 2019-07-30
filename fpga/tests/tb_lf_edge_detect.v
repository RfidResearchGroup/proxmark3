//-----------------------------------------------------------------------------
// Copyright (C) 2014 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// testbench for lf_edge_detect
`include "lf_edge_detect.v"

`define FIN "tb_tmp/data.filtered.gold"
`define FOUT_MIN "tb_tmp/data.min"
`define FOUT_MAX "tb_tmp/data.max"
`define FOUT_STATE "tb_tmp/data.state"
`define FOUT_TOGGLE "tb_tmp/data.toggle"
`define FOUT_HIGH "tb_tmp/data.high"
`define FOUT_HIGHZ "tb_tmp/data.highz"
`define FOUT_LOWZ "tb_tmp/data.lowz"
`define FOUT_LOW "tb_tmp/data.low"

module lf_edge_detect_tb;

    integer fin, fout_state, fout_toggle;
    integer fout_high, fout_highz, fout_lowz, fout_low, fout_min, fout_max;
    integer r;

    reg clk = 0;
    reg [7:0] adc_d;
    wire adc_clk;
    wire data_rdy;
    wire edge_state;
    wire edge_toggle;

    wire [7:0] high_threshold;
    wire [7:0] highz_threshold;
    wire [7:0] lowz_threshold;
    wire [7:0] low_threshold;
    wire [7:0] max;
    wire [7:0] min;

    initial
    begin
        clk = 0;
        fin = $fopen(`FIN, "r");
        if (!fin) begin
            $display("ERROR: can't open the data file");
            $finish;
        end
        fout_min = $fopen(`FOUT_MIN, "w+");
        fout_max = $fopen(`FOUT_MAX, "w+");
        fout_state = $fopen(`FOUT_STATE, "w+");
        fout_toggle = $fopen(`FOUT_TOGGLE, "w+");
        fout_high = $fopen(`FOUT_HIGH, "w+");
        fout_highz = $fopen(`FOUT_HIGHZ, "w+");
        fout_lowz = $fopen(`FOUT_LOWZ, "w+");
        fout_low = $fopen(`FOUT_LOW, "w+");
        if (!$feof(fin))
            adc_d = $fgetc(fin); // read the first value
    end

    always
        # 1 clk = !clk;

    // input
    initial
    begin
        while (!$feof(fin)) begin
            @(negedge clk) adc_d <= $fgetc(fin);
        end

        if ($feof(fin))
        begin
            # 3 $fclose(fin);
            $fclose(fout_state);
            $fclose(fout_toggle);
            $fclose(fout_high);
            $fclose(fout_highz);
            $fclose(fout_lowz);
            $fclose(fout_low);
            $fclose(fout_min);
            $fclose(fout_max);
            $finish;
        end
    end

    initial
    begin
        // $monitor("%d\t S: %b, E: %b", $time, edge_state, edge_toggle);
    end

    // output
    always @(negedge clk)
    if ($time > 2) begin
        r = $fputc(min, fout_min);
        r = $fputc(max, fout_max);
        r = $fputc(edge_state, fout_state);
        r = $fputc(edge_toggle, fout_toggle);
        r = $fputc(high_threshold, fout_high);
        r = $fputc(highz_threshold, fout_highz);
        r = $fputc(lowz_threshold, fout_lowz);
        r = $fputc(low_threshold, fout_low);
    end

    // module to test
    lf_edge_detect detect(clk, adc_d, 8'd127,
        max, min,
        high_threshold, highz_threshold,
        lowz_threshold, low_threshold,
        edge_state, edge_toggle);

endmodule
