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
// The FPGA is responsible for interfacing between the A/D, the coil drivers,
// and the ARM. In the low-frequency modes it passes the data straight
// through, so that the ARM gets raw A/D samples over the SSP. In the high-
// frequency modes, the FPGA might perform some demodulation first, to
// reduce the amount of data that we must send to the ARM.
//-----------------------------------------------------------------------------

module fpga_top(
    input spck,
    output miso,
    input mosi,
    input ncs,
    input pck0,
    input ck_1356meg,
    input ck_1356megb,
    output pwr_lo,
    output pwr_hi,
    output pwr_oe1,
    output pwr_oe2,
    output pwr_oe3,
    output pwr_oe4,
    input [7:0] adc_d,
    output adc_clk,
    output adc_noe,
    output ssp_frame,
    output ssp_din,
    input ssp_dout,
    output ssp_clk,
    input cross_hi,
    input cross_lo,
    output dbg,
    output PWR_LO_EN,
    input FPGA_SWITCH
    );


fpga_hf hfmod(
    hfspck, hfmiso, hfmosi, hfncs,
    hfpck0, hfck_1356meg, hfck_1356megb,
    hfpwr_lo, hfpwr_hi,
    hfpwr_oe1, hfpwr_oe2, hfpwr_oe3, hfpwr_oe4,
    adc_d, hfadc_clk, hfadc_noe,
    hfssp_frame, hfssp_din, hfssp_dout, hfssp_clk,
    hfcross_hi, hfcross_lo,
    hfdebug
);

fpga_lf lfmod(
    lfspck, lfmiso, lfmosi, lfncs,
    lfpck0, lfck_1356meg, lfck_1356megb,
    lfpwr_lo, lfpwr_hi,
    lfpwr_oe1, lfpwr_oe2, lfpwr_oe3, lfpwr_oe4,
    adc_d, lfadc_clk, lfadc_noe,
    lfssp_frame, lfssp_din, lfssp_dout, lfssp_clk,
    lfcross_hi, lfcross_lo,
    lfdebug,
    lfPWR_LO_EN
);

mux2_oneout         mux_spck_all                (FPGA_SWITCH, spck,         hfspck,         lfspck);
mux2_one            mux_miso_all                (FPGA_SWITCH, miso,         hfmiso,         lfmiso);
mux2_oneout         mux_mosi_all                (FPGA_SWITCH, mosi,         hfmosi,         lfmosi);
mux2_oneout         mux_ncs_all                 (FPGA_SWITCH, ncs,          hfncs,          lfncs);
mux2_oneout         mux_pck0_all                (FPGA_SWITCH, pck0,         hfpck0,         lfpck0);
mux2_oneout         mux_ck_1356meg_all          (FPGA_SWITCH, ck_1356meg,   hfck_1356meg,   lfck_1356meg);
mux2_oneout         mux_ck_1356megb_all         (FPGA_SWITCH, ck_1356megb,  hfck_1356megb,  lfck_1356megb);
mux2_one            mux_pwr_lo_all              (FPGA_SWITCH, pwr_lo,       hfpwr_lo,       lfpwr_lo);
mux2_one            mux_pwr_hi_all              (FPGA_SWITCH, pwr_hi,       hfpwr_hi,       lfpwr_hi);
mux2_one            mux_pwr_oe1_all             (FPGA_SWITCH, pwr_oe1,      hfpwr_oe1,      lfpwr_oe1);
mux2_one            mux_pwr_oe2_all             (FPGA_SWITCH, pwr_oe2,      hfpwr_oe2,      lfpwr_oe2);
mux2_one            mux_pwr_oe3_all             (FPGA_SWITCH, pwr_oe3,      hfpwr_oe3,      lfpwr_oe3);
mux2_one            mux_pwr_oe4_all             (FPGA_SWITCH, pwr_oe4,      hfpwr_oe4,      lfpwr_oe4);
mux2_one            mux_adc_clk_all             (FPGA_SWITCH, adc_clk,      hfadc_clk,      lfadc_clk);
mux2_one            mux_adc_noe_all             (FPGA_SWITCH, adc_noe,      adc_noe,        lfadc_noe);
mux2_one            mux_ssp_frame_all           (FPGA_SWITCH, ssp_frame,    hfssp_frame,    lfssp_frame);
mux2_one            mux_ssp_din_all             (FPGA_SWITCH, ssp_din,      hfssp_din,      lfssp_din);
mux2_oneout         mux_ssp_dout_all            (FPGA_SWITCH, ssp_dout,     hfssp_dout,     lfssp_dout);
mux2_one            mux_ssp_clk_all             (FPGA_SWITCH, ssp_clk,      hfssp_clk,      lfssp_clk);
mux2_oneout         mux_cross_hi_all            (FPGA_SWITCH, cross_hi,     hfcross_hi,     lfcross_hi);
mux2_oneout         mux_cross_lo_all            (FPGA_SWITCH, cross_lo,     hfcross_lo,     lfcross_lo);
mux2_one            mux_dbg_all                 (FPGA_SWITCH, dbg,          hfdebug,        lfdebug);
mux2_one            mux_PWR_LO_EN_all           (FPGA_SWITCH, PWR_LO_EN,    1'b0,           lfPWR_LO_EN);

endmodule
