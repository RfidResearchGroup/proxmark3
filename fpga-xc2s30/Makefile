#
# FPGA Makefile
#
FPGA_TYPE = xc2s30-5-vq100
RMDIR = rm -rf
# rmdir only if dir is empty, tolerate failure
RMDIR_SOFT = -rmdir
#
all: fpga_lf.bit fpga_hf.bit fpga_felica.bit fpga_hf_15.bit
clean:
	$(Q)$(RM) *.bgn *.drc *.ncd *.ngd *_par.xrpt *-placed.* *-placed_pad.* *_usage.xml *.srp *.scr
	$(Q)$(RM) *.map *.ngc *.xrpt *.pcf *.rbt *.bld *.mrp *.ngm *.unroutes *_summary.xml netlist.lst
	$(Q)$(RMDIR) *_auto_* xst

%.scr:
	$(Q)$(RM) $@
	$(Q)echo run -ifn $*.v -ifmt Verilog -ofn $*.ngc -ofmt NGC -p $(FPGA_TYPE) -top $* -opt_mode area -opt_level 2 -resource_sharing yes -fsm_style bram -fsm_encoding compact> $@

%.ngc: %.scr
	$(Q)$(RM) $@
	$(info [-] XST $@)
	$(Q)$(XILINX_TOOLS_PREFIX)xst -ifn $<

%.ngd: %.ngc
	$(Q)$(RM) $@
	$(info [-] NGD $@)
	$(Q)$(XILINX_TOOLS_PREFIX)ngdbuild -aul -p $(FPGA_TYPE) -nt timestamp -uc fpga.ucf $< $@

%.ncd: %.ngd
	$(Q)$(RM) $@
	$(info [-] MAP $@)
	$(Q)$(XILINX_TOOLS_PREFIX)map -p $(FPGA_TYPE) $<

%-placed.ncd: %.ncd
	$(Q)$(RM) $@
	$(info [-] PAR $@)
	$(Q)$(XILINX_TOOLS_PREFIX)par $< $@

%.bit: %-placed.ncd
	$(Q)$(RM) $@ $*.drc $*.rbt
	$(info [=] BITGEN $@)
	$(Q)$(XILINX_TOOLS_PREFIX)bitgen -w $< $@

.PHONY: all clean help
help:
	@echo Possible targets:
	@echo +	all   - Make fpga.bit, the FPGA bitstream
	@echo +	clean - Clean intermediate files, does not clean fpga.bit

