#
# FPGA build dispatcher.
#
# Each requested target is routed to the implementation of the platform that
# owns it:
#   proxmark3_fpga.mk   Xilinx ISE        - PM3, PM3-ULT, iCopy-X
#   proxmark5_fpga.mk   yosys/nextpnr     - PM5
#
#   make            - every PM3 image
#   make pm3        - same
#   make pm5        - the PM5 bitstream
#   make <target>   - routed by name, e.g. fpga_pm3_hf, fpga_pm3_ult_lf, fpga_pm5
#   make clean      - both platforms
#   make help       - both target lists
#
# Both platform files are also usable directly, which is how the recursive
# builds call them:
#   make -C fpga -f proxmark5_fpga.mk all

include common_src.mk

PM3_MK = proxmark3_fpga.mk
PM5_MK = proxmark5_fpga.mk

PLATFORMS = pm3 pm5

# Everything that is not a dispatcher builtin is forwarded to a platform file.
GOALS = $(filter-out $(PLATFORMS) all clean help,$(MAKECMDGOALS))

# PM5 owns the fpga_pm5* targets, everything else is PM3.
mk_for = $(if $(filter fpga_pm5%,$1),$(PM5_MK),$(PM3_MK))

.PHONY: all pm3 pm5 clean help $(GOALS)

ifneq ($(GOALS),)

$(GOALS):
	$(Q)$(MAKE) --no-print-directory -f $(call mk_for,$@) $@

all pm3 pm5 clean help: ;

else

all: pm3

pm3:
	$(Q)$(MAKE) --no-print-directory -f $(PM3_MK) all

pm5:
	$(Q)$(MAKE) --no-print-directory -f $(PM5_MK) all

clean:
	$(Q)$(MAKE) --no-print-directory -f $(PM3_MK) clean
	$(Q)$(MAKE) --no-print-directory -f $(PM5_MK) clean

help:
	@echo "################################################################"
	@echo "#   FPGA build dispatcher"
	@echo "#"
	@echo "#   make           - every PM3 image (Xilinx ISE)"
	@echo "#   make pm5       - the PM5 bitstream (yosys/nextpnr-himbaechel)"
	@echo "#   make <target>  - routed by name, e.g. fpga_pm3_hf, fpga_pm5"
	@echo "#   make clean     - both platforms"
	@echo "################################################################"
	$(Q)$(MAKE) --no-print-directory -f $(PM3_MK) help
	$(Q)$(MAKE) --no-print-directory -f $(PM5_MK) help

endif
