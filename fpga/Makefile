include ../common/Makefile.common

all: fpga.ngc fpga.ngd fpga.ncd fpga-placed.ncd fpga.bit
clean:
	$(DELETE) fpga.bgn  fpga.drc  fpga.ncd           fpga.ngd            fpga_par.xrpt    fpga-placed.pad      fpga-placed.par       fpga-placed.xpi   fpga_usage.xml  xlnx_auto_0.ise  xst.srp
	$(DELETE) fpga.map  fpga.ngc           fpga_ngdbuild.xrpt  fpga.pcf         fpga-placed_pad.csv  fpga-placed.ptwx      fpga.rbt          xlnx_auto_0_xdb
	$(DELETE) fpga.bld  fpga.mrp  fpga.ngc_xst.xrpt  fpga.ngm            fpga-placed.ncd  fpga-placed_pad.txt  fpga-placed.unroutes  fpga_summary.xml  netlist.lst     xst

fpga.ngc: fpga.v fpga.ucf xst.scr util.v lo_edge_detect.v lo_read.v lo_passthru.v hi_simulate.v hi_read_tx.v hi_read_rx_xcorr.v hi_iso14443a.v
	$(DELETE) fpga.ngc
	$(XILINX_TOOLS_PREFIX)xst -ifn xst.scr

fpga.ngd: fpga.ngc
	$(DELETE) fpga.ngd
	$(XILINX_TOOLS_PREFIX)ngdbuild -aul -p xc2s30-5-vq100 -nt timestamp -uc fpga.ucf fpga.ngc fpga.ngd

fpga.ncd: fpga.ngd
	$(DELETE) fpga.ncd
	$(XILINX_TOOLS_PREFIX)map -p xc2s30-5-vq100 fpga.ngd

fpga-placed.ncd: fpga.ncd
	$(DELETE) fpga-placed.ncd
	$(XILINX_TOOLS_PREFIX)par fpga.ncd fpga-placed.ncd

fpga.bit: fpga-placed.ncd
	$(DELETE) fpga.bit fpga.drc fpga.rbt
	$(XILINX_TOOLS_PREFIX)bitgen fpga-placed.ncd fpga.bit


.PHONY: all clean help
help:
	@echo Multi-OS Makefile, you are running on $(DETECTED_OS)
	@echo Possible targets:
	@echo +	all   - Make fpga.bit, the FPGA bitstream 
	@echo +	clean - Clean intermediate files, does not clean fpga.bit
	
