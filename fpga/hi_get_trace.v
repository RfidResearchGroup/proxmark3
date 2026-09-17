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

module hi_get_trace(
    input ck_1356megb,
    input [7:0] adc_d,
    input trace_enable,
    input [2:0] major_mode,

    output ssp_din,
    output reg ssp_frame,
    output reg ssp_clk
);

// clock divider
reg [6:0] clock_cnt;
always @(negedge ck_1356megb)
begin
    clock_cnt <= clock_cnt + 1;
end

// sample at 13,56MHz / 8. The highest signal frequency (subcarrier) is 848,5kHz, i.e. in this case we oversample by a factor of 2
reg [2:0] sample_clock;
always @(negedge ck_1356megb)
begin
    if (sample_clock == 3'd7)
        sample_clock <= 3'd0;
    else
        sample_clock <= sample_clock + 1;
end


reg [11:0] addr;
reg [11:0] start_addr;
reg [2:0] previous_major_mode;
reg write_enable1;
reg write_enable2;
always @(negedge ck_1356megb)
begin
    previous_major_mode <= major_mode;
    if (major_mode == `FPGA_MAJOR_MODE_HF_GET_TRACE)
    begin
        write_enable1 <= 1'b0;
        write_enable2 <= 1'b0;
        if (previous_major_mode != `FPGA_MAJOR_MODE_HF_GET_TRACE) // just switched into GET_TRACE mode
            addr <= start_addr;
        if (clock_cnt == 7'd0)
        begin
            if (addr == 12'd3071)
                addr <= 12'd0;
            else
                addr <= addr + 1;
        end
    end
    else if (major_mode != `FPGA_MAJOR_MODE_OFF)
    begin
        if (trace_enable)
        begin
            if (addr[11] == 1'b0)
            begin
                write_enable1 <= 1'b1;
                write_enable2 <= 1'b0;
            end
            else
            begin
                write_enable1 <= 1'b0;
                write_enable2 <= 1'b1;
            end
            if (sample_clock == 3'b000)
            begin
                if (addr == 12'd3071)
                begin
                    addr <= 12'd0;
                    write_enable1 <= 1'b1;
                    write_enable2 <= 1'b0;
                end
                else
                begin
                    addr <= addr + 1;
                end
            end
        end
        else
        begin
            write_enable1 <= 1'b0;
            write_enable2 <= 1'b0;
            start_addr <= addr;
        end
    end
    else // major_mode == `FPGA_MAJOR_MODE_OFF
    begin
        write_enable1 <= 1'b0;
        write_enable2 <= 1'b0;
        if (previous_major_mode != `FPGA_MAJOR_MODE_OFF && previous_major_mode != `FPGA_MAJOR_MODE_HF_GET_TRACE) // just switched off
        begin
            start_addr <= addr;
        end
    end
end

// (2+1)k RAM
reg [7:0] D_out1, D_out2;
reg [7:0] ram1 [2047:0]; // 2048  u8
reg [7:0] ram2 [1023:0]; // 1024  u8

always @(negedge ck_1356megb)
begin
    if (write_enable1)
    begin
        ram1[addr[10:0]] <= adc_d;
        D_out1 <= adc_d;
    end
    else
        D_out1 <= ram1[addr[10:0]];
    if (write_enable2)
    begin
        ram2[addr[9:0]] <= adc_d;
        D_out2 <= adc_d;
    end
    else
        D_out2 <= ram2[addr[9:0]];
end

reg [7:0] shift_out;

always @(negedge ck_1356megb)
begin
    if (clock_cnt[3:0] == 4'd0)        // update shift register every 16 clock cycles
    begin
        if (clock_cnt[6:4] == 3'd0)    // either load new value
        begin
            if (addr[11] == 1'b0)
                shift_out <= D_out1;
            else
                shift_out <= D_out2;
        end
        else
        begin
            // or shift left
            shift_out[7:1] <= shift_out[6:0];
        end
    end

    ssp_clk <= ~clock_cnt[3];       // ssp_clk frequency = 13,56MHz / 16 = 847,5 kHz

    if (clock_cnt[6:4] == 3'b000)    // set ssp_frame for 0...31
        ssp_frame <= 1'b1;
    else
        ssp_frame <= 1'b0;

end

assign ssp_din = shift_out[7];

endmodule
