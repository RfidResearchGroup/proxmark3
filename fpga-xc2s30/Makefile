#
# FPGA Makefile
#
RMDIR = rm -rf
# rmdir only if dir is empty, tolerate failure
RMDIR_SOFT = -rmdir
#
all: fpga_lf.bit fpga_hf.bit fpga_felica.bit
clean:
	$(Q)$(RM) *.bgn *.drc *.ncd *.ngd *_par.xrpt *-placed.* *-placed_pad.* *_usage.xml xst_hf.srp xst_lf.srp xst_felica.srp
	$(Q)$(RM) *.map *.ngc *.xrpt *.pcf *.rbt *.bld *.mrp *.ngm *.unroutes *_summary.xml netlist.lst
	$(Q)$(RMDIR) *_auto_* xst

#fpga_hf.ngc: fpga_hf.v fpga.ucf xst_hf.scr util.v hi_simulate.v hi_reader.v hi_iso14443a.v hi_sniffer.v hi_flite.v hi_get_trace.v
fpga_hf.ngc: fpga_hf.v fpga.ucf xst_hf.scr util.v hi_simulate.v hi_reader.v hi_iso14443a.v hi_sniffer.v hi_get_trace.v
	$(Q)$(RM) $@
	$(info [-] XST $@)
	$(Q)$(XILINX_TOOLS_PREFIX)xst -ifn xst_hf.scr

fpga_felica.ngc: fpga_felica.v fpga.ucf xst_felica.scr util.v hi_simulate.v hi_reader.v hi_sniffer.v hi_flite.v hi_get_trace.v
	$(Q)$(RM) $@
	$(info [-] XST $@)
	$(Q)$(XILINX_TOOLS_PREFIX)xst -ifn xst_felica.scr

fpga_lf.ngc: fpga_lf.v fpga.ucf xst_lf.scr util.v clk_divider.v lo_edge_detect.v lo_read.v lo_passthru.v lp20khz_1MSa_iir_filter.v min_max_tracker.v lf_edge_detect.v
	$(Q)$(RM) $@
	$(info [-] XST $@)
	$(Q)$(XILINX_TOOLS_PREFIX)xst -ifn xst_lf.scr

%.ngd: %.ngc
	$(Q)$(RM) $@
	$(info [-] NGD $@)
	$(Q)$(XILINX_TOOLS_PREFIX)ngdbuild -aul -p xc2s30-5-vq100 -nt timestamp -uc fpga.ucf $< $@

%.ncd: %.ngd
	$(Q)$(RM) $@
	$(info [-] MAP $@)
	$(Q)$(XILINX_TOOLS_PREFIX)map -p xc2s30-5-vq100 $<

%-placed.ncd: %.ncd
	$(Q)$(RM) $@
	$(info [-] PAR $@)
	$(Q)$(XILINX_TOOLS_PREFIX)par $< $@

%.bit: %-placed.ncd
	$(Q)$(RM) $@ $*.drc $*.rbt
	$(info [=] BITGEN $@)
	$(Q)$(XILINX_TOOLS_PREFIX)bitgen $< $@

.PHONY: all clean help
help:
	@echo Possible targets:
	@echo +	all   - Make fpga.bit, the FPGA bitstream
	@echo +	clean - Clean intermediate files, does not clean fpga.bit

