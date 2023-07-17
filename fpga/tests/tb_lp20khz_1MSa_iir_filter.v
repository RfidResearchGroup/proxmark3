//-----------------------------------------------------------------------------
// Copyright (C) 2014 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// testbench for lp20khz_1MSa_iir_filter
`include "lp20khz_1MSa_iir_filter.v"

`define FIN "tb_tmp/data.in"
`define FOUT "tb_tmp/data.filtered"

module lp20khz_1MSa_iir_filter_tb;

    integer fin, fout, r;

    reg clk;
    reg [7:0] adc_d;
    wire data_rdy;
    wire [7:0] adc_filtered;

    initial
    begin
        clk = 0;
        fin = $fopen(`FIN, "r");
        if (!fin) begin
            $display("ERROR: can't open the data file");
            $finish;
        end
        fout = $fopen(`FOUT, "w+");
        if (!$feof(fin))
            adc_d = $fgetc(fin); // read the first value
    end

    always
        # 1 clk = !clk;

    always @(posedge clk)
        if (data_rdy) begin
            if ($time > 1)
                r = $fputc(adc_filtered, fout);
            if (!$feof(fin))
                adc_d <= $fgetc(fin);
            else begin
                $fclose(fin);
                $fclose(fout);
                $finish;
            end
        end

    // module to test
    lp20khz_1MSa_iir_filter filter(clk, adc_d, data_rdy, adc_filtered);

endmodule
