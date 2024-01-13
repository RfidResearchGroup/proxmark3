#------------------------------------------------------------------------------
# Run the simulation testbench in ModelSim: recompile both Verilog source
# files, then start the simulation, add a lot of signals to the waveform
# viewer, and run. I should (TODO) fix the absolute paths at some point.
#
# Jonathan Westhues, Mar 2006
#------------------------------------------------------------------------------

vlog -work work -O0 C:/depot/proximity/mark3/fpga/fpga.v
vlog -work work -O0 C:/depot/proximity/mark3/fpga/fpga_tb.v

vsim work.fpga_tb

add wave sim:/fpga_tb/adc_clk
add wave sim:/fpga_tb/adc_d
add wave sim:/fpga_tb/pwr_lo
add wave sim:/fpga_tb/ssp_clk
add wave sim:/fpga_tb/ssp_frame
add wave sim:/fpga_tb/ssp_din
add wave sim:/fpga_tb/ssp_dout

add wave sim:/fpga_tb/dut/clk_lo
add wave sim:/fpga_tb/dut/pck_divider
add wave sim:/fpga_tb/dut/carrier_divider_lo
add wave sim:/fpga_tb/dut/conf_word

run 30000
