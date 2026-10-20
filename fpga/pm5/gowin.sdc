//Copyright (C)2014-2026 GOWIN Semiconductor Corporation.
//All rights reserved.
//File Title: Timing Constraints file
//Tool Version: V1.9.9 (64-bit) 
//Created Time: 2026-04-20 17:50:38
create_clock -name CLK_SPI -period 250 -waveform {0 125} [get_ports {spi_sck}]
create_clock -name CLK_NCS -period 1000 -waveform {0 500} [get_ports {spi_ncs}]
create_clock -name clk24 -period 41.667 -waveform {0 20.834} [get_ports {pck0}]
create_clock -name clk1356 -period 73.746 -waveform {0 36.873} [get_ports {ck_1356meg}]
create_clock -name pwr_pwm_clk -period 5 [get_nets {pwr_pwm_pll_clko}]
set_clock_groups -asynchronous -group [get_clocks {clk1356}] -group [get_clocks {clk24}] -group [get_clocks {CLK_SPI}] -group [get_clocks {CLK_NCS}]
report_timing -setup -from_clock [get_clocks {clk1356}] -to [get_ports {pwr_hi}]
