#
# FPGA Makefile for all targets
#
# The top part of this Makefile is used to define custom options for a number of compilation targets
# To define an additional target simply look at the other defined targets and add a new TARGET entry with a unique number and the custom options required

XILINX_TOOLS_PREFIX=

# Copy update (only when destination is older or missing)
CP = cp -u

# Make directory, no error if already existing
MKDIR = mkdir -p

# Remove recursive, force
RMDIR = rm -rf

# Path to make
MAKE = make

# Custom prefix for build directories, each target is built into its own separate directory name formed by combining the PREFIX and TARGET names.
# This way the source is not polluted with build files and the build directories are left behind after compilation so logs and reports can be
# examined or can be easily deleted with "make clean"
PREFIX = __

# Options to be passed to XST
XST_OPTS_BASE  = run
XST_OPTS_BASE += -ifn xst.prj
XST_OPTS_BASE += -ifmt mixed
XST_OPTS_BASE += -ofmt NGC
XST_OPTS_BASE += -lso xst.lso
XST_OPTS_BASE += -top fpga_top
XST_OPTS_BASE += -resource_sharing yes

# Optimizations for speed (default)
XST_OPTS_SPEED  = -opt_mode Speed
XST_OPTS_SPEED += -opt_level 1
XST_OPTS_SPEED += -fsm_style lut
XST_OPTS_SPEED += -fsm_encoding auto

# Optimization for reduced space
XST_OPTS_AREA  = -opt_mode area
XST_OPTS_AREA += -opt_level 2
XST_OPTS_AREA += -fsm_style bram
XST_OPTS_AREA += -fsm_encoding compact

# Types of selective module compilation:
# WITH_LF  Enables selection of LF modules (and disables all HF)

# To enable these modules WITH_LF _MUST_ be defined
# WITH_LF0 enable LF reader (generic)
# WITH_LF1 enable LF edge detect (generic)
# WITH_LF2 enable LF passthrough
# WITH_LF3 enable LF ADC (read/write)

# To enable these modules WITH_LF _MUST_NOT_ be defined
# WITH_HF0 enable HF reader (see also WITH_HF_15 below)
# WITH_HF_15 select "iso15 2sc mode" extensions instead of original
# WITH_HF1 enable HF simulated tag
# WITH_HF2 enable HF ISO14443-A
# WITH_HF3 enable sniff
# WITH_HF4 enable HF ISO18092 FeliCa
# WITH_HF5 enable HF get trace

# RDV40/Generic - Enable LF and all the LF modules
TARGET1_OPTIONS = -define \{WITH_LF WITH_LF0 WITH_LF1 WITH_LF2 WITH_LF3\}
# RDV40/Generic - Enable all HF modules except Felica
TARGET2_OPTIONS = -define \{WITH_HF0 WITH_HF1 WITH_HF2 WITH_HF3 WITH_HF5\}
# RDV40/Generic - Enable all HF modules except Felica and ISO14443, select HF_15 instead of HF
TARGET3_OPTIONS = -define \{WITH_HF0 WITH_HF1 WITH_HF3 WITH_HF5 WITH_HF_15\}
# RDV40/Generic - Enable all HF modules except ISO14443
TARGET4_OPTIONS = -define \{WITH_HF0 WITH_HF1 WITH_HF3 WITH_HF4 WITH_HF5\}
# ICOPYX
TARGET5_OPTIONS = -define {PM3ICOPYX} -rtlview Yes

# Here we list the target names
TARGET1_NAME = fpga_pm3_lf
TARGET2_NAME = fpga_pm3_hf
TARGET3_NAME = fpga_pm3_hf_15
TARGET4_NAME = fpga_pm3_felica
TARGET5_NAME = fpga_icopyx_hf

# Targets can be compiled for different FPGA flavours
TARGET1_FPGA = xc2s30-5-vq100
TARGET2_FPGA = $(TARGET1_FPGA)
TARGET3_FPGA = $(TARGET1_FPGA)
TARGET4_FPGA = $(TARGET1_FPGA)
TARGET5_FPGA = xc3s100e-4-vq100

# Assemble the final XST options for each target
TARGET1_XST_OPTS = $(XST_OPTS_BASE) $(XST_OPTS_AREA)  -p $(TARGET1_FPGA) -ofn $(TARGET1_NAME) $(TARGET1_OPTIONS)
TARGET2_XST_OPTS = $(XST_OPTS_BASE) $(XST_OPTS_AREA)  -p $(TARGET2_FPGA) -ofn $(TARGET2_NAME) $(TARGET2_OPTIONS)
TARGET3_XST_OPTS = $(XST_OPTS_BASE) $(XST_OPTS_AREA)  -p $(TARGET3_FPGA) -ofn $(TARGET3_NAME) $(TARGET3_OPTIONS)
TARGET4_XST_OPTS = $(XST_OPTS_BASE) $(XST_OPTS_AREA)  -p $(TARGET4_FPGA) -ofn $(TARGET4_NAME) $(TARGET4_OPTIONS)
TARGET5_XST_OPTS = $(XST_OPTS_BASE) $(XST_OPTS_SPEED) -p $(TARGET5_FPGA) -ofn $(TARGET5_NAME) $(TARGET5_OPTIONS)

# these files are common for all targets
TARGET_COMMON_FILES  = define.v
TARGET_COMMON_FILES += mux8.v
TARGET_COMMON_FILES += clk_divider.v
TARGET_COMMON_FILES += lp20khz_1MSa_iir_filter.v
TARGET_COMMON_FILES += min_max_tracker.v
TARGET_COMMON_FILES += hi_flite.v
TARGET_COMMON_FILES += hi_get_trace.v
TARGET_COMMON_FILES += hi_iso14443a.v
TARGET_COMMON_FILES += hi_reader.v
TARGET_COMMON_FILES += hi_simulate.v
TARGET_COMMON_FILES += hi_sniffer.v
TARGET_COMMON_FILES += lf_edge_detect.v
TARGET_COMMON_FILES += lo_adc.v
TARGET_COMMON_FILES += lo_edge_detect.v
TARGET_COMMON_FILES += lo_passthru.v
TARGET_COMMON_FILES += lo_read.v

# Add the files that are unique per target and all the common files
TARGET1_FILES = $(TARGET_COMMON_FILES) fpga_pm3_top.v
TARGET2_FILES = $(TARGET1_FILES)
TARGET3_FILES = $(TARGET1_FILES)
TARGET4_FILES = $(TARGET1_FILES)
TARGET5_FILES = $(TARGET_COMMON_FILES) mux2_onein.v mux2_oneout.v fpga_icopyx_hf.v fpga_icopyx_lf.v fpga_icopyx_top.v

# List of all valid target FPGA images to build
TARGETS = $(TARGET1_NAME) $(TARGET2_NAME) $(TARGET3_NAME) $(TARGET4_NAME) $(TARGET5_NAME)

#  Verbosity type for ISE tools ise|xflow|silent
VERBOSITY = -intstyle silent
# Echo (Q=) or not echo (Q=@) build commands to the terminal
Q=@

# Pass the custom variables to the lower make rules
$(TARGET1_NAME).bit: TARGET_FPGA = $(TARGET1_FPGA)
$(TARGET1_NAME).bit: TARGET_FILES = $(TARGET1_FILES)
$(TARGET1_NAME).bit: TARGET_XST_OPTS = $(TARGET1_XST_OPTS)

$(TARGET2_NAME).bit: TARGET_FPGA = $(TARGET2_FPGA)
$(TARGET2_NAME).bit: TARGET_FILES = $(TARGET2_FILES)
$(TARGET2_NAME).bit: TARGET_XST_OPTS = $(TARGET2_XST_OPTS)

$(TARGET3_NAME).bit: TARGET_FPGA = $(TARGET3_FPGA)
$(TARGET3_NAME).bit: TARGET_FILES = $(TARGET3_FILES)
$(TARGET3_NAME).bit: TARGET_XST_OPTS = $(TARGET3_XST_OPTS)

$(TARGET4_NAME).bit: TARGET_FPGA = $(TARGET4_FPGA)
$(TARGET4_NAME).bit: TARGET_FILES = $(TARGET4_FILES)
$(TARGET4_NAME).bit: TARGET_XST_OPTS = $(TARGET4_XST_OPTS)

$(TARGET5_NAME).bit: TARGET_FPGA = $(TARGET5_FPGA)
$(TARGET5_NAME).bit: TARGET_FILES = $(TARGET5_FILES)
$(TARGET5_NAME).bit: TARGET_XST_OPTS = $(TARGET5_XST_OPTS)

$(TARGETS):
	$(Q)$(MKDIR) $(PREFIX)build_$@
	$(Q)$(MAKE) -C $(PREFIX)build_$@ -f ../Makefile $(notdir $@).bit

work:
	$(Q)$(RM) xst.prj
	$(Q)for item in $(TARGET_FILES); do echo verilog work ../$$item>>xst.prj; done
	$(Q)echo work> xst.lso

%.xst: work
	$(Q)$(RM) $@
	$(Q)echo $(TARGET_XST_OPTS)> $@

%.ngc: %.xst
	$(Q)$(RM) $@
	$(info [-] XST $@)
	$(Q)$(XILINX_TOOLS_PREFIX)xst $(VERBOSITY) -ifn $<

%.ngd: %.ngc
	$(Q)$(RM) $@
	$(info [-] NGD $@)
	$(Q)$(XILINX_TOOLS_PREFIX)ngdbuild $(VERBOSITY) -quiet -p $(TARGET_FPGA) -nt timestamp -uc ../$(TARGET_FPGA).ucf $< $@

%_map.ncd: %.ngd
	$(Q)$(RM) $@
	$(info [-] MAP $@)
	$(Q)$(XILINX_TOOLS_PREFIX)map $(VERBOSITY) -p $(TARGET_FPGA) -o $*_map $*

%.ncd: %_map.ncd
	$(Q)$(RM) $@
	$(info [-] PAR $@)
	$(Q)$(XILINX_TOOLS_PREFIX)par $(VERBOSITY) -w $< $@

%.bit: %.ncd
	# Hacky hack, make empty files for icopyx
	if echo "$@" | grep -qi "icopyx"; then \
		truncate -s0 ../fpga_icopyx_lf.bit; \
		truncate -s0 ../fpga_icopyx_hf_15.bit; \
		truncate -s0 ../fpga_icopyx_felica.bit; \
	fi
	$(Q)$(RM) $@ $*.drc $*.rbt
	$(info [=] BITGEN $@)
	$(Q)$(XILINX_TOOLS_PREFIX)bitgen $(VERBOSITY) -w $* $@
	$(Q)$(CP) $@ ..

# Build all targets
all: $(TARGETS)

# ALWAYS have some hardcoded text after $(PREFIX) to avoid rm -rf * or rm -rf /* situations if PREFIX is incorrectly set to empty "" or just "/"
clean:
	$(Q)$(RMDIR) $(PREFIX)build_*
	$(info [-] Build files deleted)

.DEFAULT:
	@if [ "$@" != "all" ] && [ ! "$(filter $@,$(TARGETS))" ]; then \
		make help; \
	else \
		make all; \
	fi

.PHONY: all help clean

help:
	@echo "################################################################"
	@echo "#"
	@echo "#   <target> - Builds only one of the above listed targets"
	@echo "#   all      - Builds the FPGA bitstreams for all targets"
	@echo "#   clean    - Keeps .bit files but cleans intermediate build files for all targets"
	@echo "#"
	@echo "#"
	@echo "# Valid targets are:"
	@echo "#   $(TARGETS)"
	@echo "#"
	@echo "################################################################"

