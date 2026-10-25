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


module fpga_top (
    input ck_1356meg,
    input ck_1356meg_b,        // B is for close range wiring
    input spi_sck,
    input pck0,
    input spi_ncs,
    input [9:0] adc_d,
    input cross_lo,
    input spi_mosi,
    input ssp_dout,
    input module_sel,         // module select: 1 = HF, 0 = LF
    
    output ssp_din,
    output ssp_frame,
    output ssp_clk,
    output adc_clk,
    output spi_miso,
    output pwr_lo,
    output pwr_hi,
    output pwr_oe1,
    output pwr_oe2,
    output pwr_oe4,
    output dbg1,
    output dbg2,
    output dbgled,

    output clk_gate,         // gates the external 13.56 MHz clock
    output pwr_pwm,          // boost converter PWM, sets the driver supply voltage
    output pan_en,           // analog supply enable
    output pdp_en            // boost converter enable
);
    
    wire ce_lf = ~module_sel; // enable, active high; a low level holds the module in reset
    wire ce_hf = module_sel;  // enable, active high; a low level holds the module in reset
    //-----------------------------------------GATE-------------------------
    // Synchronise the gate enable into the input clock domain against metastability
    reg gate_en_sync1, gate_en_sync2;
    always @(posedge ck_1356meg) begin
        gate_en_sync1 <= gate_en;
        gate_en_sync2 <= gate_en_sync1;
    end
    
    assign clk_gate = ~gate_en_sync2; // inverted, the external gate is active low
    //-----------------------------------------PWM--------------------------
    
    // CLKOUT is 200 MHz: 4096 steps at 5 ns keep the resolution, at a 20.48 us
    // period. 400 MHz does not close the 12 bit carry chain at 2.5 ns.
    Gowin_rPLL pwr_pwm_pll(
        .clkout(pwr_pwm_pll_clko), //output clkout
        .clkin(ck_1356meg) //input clkin
    );

    wire [11:0] pwm_duty_lf;   // PWM duty from the LF module
    wire [11:0] pwm_duty_hf;   // PWM duty from the HF module

    wire [11:0] pwm_duty;      // low-level count of the 4096-step PWM period
    reg [11:0] pwm_cnt= 12'h0;

    // pwm_duty is from the SPI clock domain; resample it into the PWM domain
    // so a duty update is never sampled mid transition.
    reg [11:0] pwm_duty_meta, pwm_duty_sync;
    always @(posedge pwr_pwm_pll_clko) begin
        pwm_duty_meta <= pwm_duty;
        pwm_duty_sync <= pwm_duty_meta;
    end

    // Register the output; the bare comparator glitches on every count edge.
    reg pwr_pwm_r;
    always @(posedge pwr_pwm_pll_clko) begin
        pwm_cnt   <= pwm_cnt + 1'b1;  // counter
        pwr_pwm_r <= (pwm_cnt > pwm_duty_sync);  // PWM output
    end
    assign pwr_pwm = pwr_pwm_r;

    assign pan_en = 1'b1;
    assign pdp_en = 1'b1;

    assign pwr_hi = 1'bZ;  // PWRHI is replaced by the external gate; the two are wired in parallel, so float it
    assign dbgled = 1'b1;
    assign dbg2   = 1'bZ;  // not used

`ifdef PM5_SNIFF14A
    // 14a sniffer image: no LF side; the boost PWM follows the HF module's duty whichever side is selected
    wire ssp_din_lf = 1'b0, ssp_frame_lf = 1'b0, ssp_clk_lf = 1'b0, adc_clk_lf = 1'b0, miso_lf = 1'b0;
    wire pwr_lo_lf = 1'b0, pwr_oe1_lf = 1'b0, pwr_oe2_lf = 1'b0, pwr_oe4_lf = 1'b0, dbg_lf = 1'b0;
    assign pwm_duty_lf = pwm_duty_hf;
`else
    fpga_lf uut_lf (
        .pck0(pck0),

        .spck(spi_sck),
        .ncs(spi_ncs),

        .adc_d(adc_d[9:2]),
        .cross_lo(cross_lo),
        .mosi(spi_mosi),
        .ssp_dout(ssp_dout),
        .ce(ce_lf),
        
        .ssp_din(ssp_din_lf),
        .ssp_frame(ssp_frame_lf),
        .ssp_clk(ssp_clk_lf),
        .adc_clk(adc_clk_lf),
        .miso(miso_lf),
        .pwr_lo(pwr_lo_lf),
        .pwr_oe1(pwr_oe1_lf),
        .pwr_oe2(pwr_oe2_lf),
        .pwr_oe4(pwr_oe4_lf),
        .dbg(dbg_lf),

        .pwm_duty(pwm_duty_lf)
    );
`endif

    fpga_hf uut_hf (
        .ck_1356meg(ck_1356meg),

        .spck(spi_sck),
        .ncs(spi_ncs),

`ifdef PM5_SNIFF14A
        .adc_d10(adc_d),
`endif
        .adc_d(adc_d[9:2]),
        .mosi(spi_mosi),
        .ssp_dout(ssp_dout),
        .ce(ce_hf),
        
        .ssp_din(ssp_din_hf),
        .ssp_frame(ssp_frame_hf),
        .ssp_clk(ssp_clk_hf),
        .adc_clk(adc_clk_hf),
        .miso(miso_hf),
        .pwr_lo(pwr_lo_hf),
        .pwr_hi(gate_en),
        .pwr_oe1(pwr_oe1_hf),
        .pwr_oe2(pwr_oe2_hf),
        .pwr_oe4(pwr_oe4_hf),
        .dbg(dbg_hf),

        .pwm_duty(pwm_duty_hf)
    );

    assign ssp_din   = ~module_sel ? ssp_din_lf   : ssp_din_hf;
    assign ssp_frame = ~module_sel ? ssp_frame_lf : ssp_frame_hf;
    assign ssp_clk   = ~module_sel ? ssp_clk_lf   : ssp_clk_hf;
    assign adc_clk   = ~module_sel ? adc_clk_lf   : adc_clk_hf;
    assign spi_miso  = ~module_sel ? miso_lf      : miso_hf;
    assign pwr_lo    = ~module_sel ? pwr_lo_lf    : pwr_lo_hf;
    //assign pwr_hi    = ~module_sel ? pwr_hi_lf    : pwr_hi_hf;
    assign pwr_oe1   = ~module_sel ? pwr_oe1_lf   : pwr_oe1_hf;
    assign pwr_oe2   = ~module_sel ? pwr_oe2_lf   : pwr_oe2_hf;
    assign pwr_oe4   = ~module_sel ? pwr_oe4_lf   : pwr_oe4_hf;
    assign dbg1      = ~module_sel ? dbg_lf       : dbg_hf;
    assign pwm_duty  = ~module_sel ? pwm_duty_lf  : pwm_duty_hf;

endmodule