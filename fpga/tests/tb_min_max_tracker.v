//-----------------------------------------------------------------------------
// Copyright (C) 2014 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// testbench for min_max_tracker
`include "min_max_tracker.v"

`define FIN "tb_tmp/data.filtered.gold"
`define FOUT_MIN "tb_tmp/data.min"
`define FOUT_MAX "tb_tmp/data.max"

module min_max_tracker_tb;

    integer fin;
    integer fout_min, fout_max;
    integer r;

    reg clk;
    reg [7:0] adc_d;
    wire [7:0] min;
    wire [7:0] max;

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
            $fclose(fout_min);
            $fclose(fout_max);
            $finish;
        end
    end

    initial
    begin
        // $monitor("%d\t min: %x, max: %x", $time, min, max);
    end

    // output
    always @(negedge clk)
    if ($time > 2) begin
        r = $fputc(min, fout_min);
        r = $fputc(max, fout_max);
    end

    // module to test
    min_max_tracker tracker(clk, adc_d, 8'd127, min, max);

endmodule
