#
# Shared definitions for the FPGA build files.
#
# Source layout:
#   common/   HDL shared by every platform
#   pm3/      Xilinx PM3 / PM3-ULT top level and pin constraints
#   icopyx/   Xilinx iCopy-X top level and pin constraints
#   pm5/      Gowin PM5 top level, PLL, yosys script and pin constraints
#
# Included by proxmark3_fpga.mk and proxmark5_fpga.mk.

COMMON_DIR = common
PM3_DIR    = pm3
ICOPYX_DIR = icopyx
PM5_DIR    = pm5

# Prefix of the per target build directories, gitignored as fpga/__build*
PREFIX = __

# Copy update (only when destination is older or missing)
CP = cp -u

# Make directory, no error if already existing
MKDIR = mkdir -p

# Remove recursive, force
RMDIR = rm -rf

# Path to make
MAKE = make

# Echo (Q=) or not echo (Q=@) build commands to the terminal
Q =

# HDL shared by every target, in synthesis order
COMMON_HDL  = $(COMMON_DIR)/define.v
COMMON_HDL += $(COMMON_DIR)/mux8.v
COMMON_HDL += $(COMMON_DIR)/clk_divider.v
COMMON_HDL += $(COMMON_DIR)/lp20khz_1MSa_iir_filter.v
COMMON_HDL += $(COMMON_DIR)/min_max_tracker.v
COMMON_HDL += $(COMMON_DIR)/hi_flite.v
COMMON_HDL += $(COMMON_DIR)/hi_get_trace.v
COMMON_HDL += $(COMMON_DIR)/hi_iso14443a.v
COMMON_HDL += $(COMMON_DIR)/hi_reader.v
COMMON_HDL += $(COMMON_DIR)/hi_simulate.v
COMMON_HDL += $(COMMON_DIR)/hi_sniffer.v
COMMON_HDL += $(COMMON_DIR)/lf_edge_detect.v
COMMON_HDL += $(COMMON_DIR)/lo_adc.v
COMMON_HDL += $(COMMON_DIR)/lo_edge_detect.v
COMMON_HDL += $(COMMON_DIR)/lo_passthru.v
COMMON_HDL += $(COMMON_DIR)/lo_read.v

# HDL of the PM5 (Gowin) bitstream, in synthesis order. One image covers both
# halves; the board selects LF or HF with the module_sel pin.
PM5_HDL  = $(COMMON_HDL)
PM5_HDL += $(PM5_DIR)/gowin_rpll.v
PM5_HDL += $(PM5_DIR)/pm5_hi_iso14443a.v
PM5_HDL += $(PM5_DIR)/fpga_pm5_hf.v
PM5_HDL += $(PM5_DIR)/fpga_pm5_lf.v
PM5_HDL += $(PM5_DIR)/fpga_pm5_top.v

# Strips the build date/time out of a generated Xilinx bitstream, so that
# rebuilding without a source change produces a byte identical file.
# Xilinx specific: not applicable to the Gowin bitstream.
STRIP_DATE_TIME = $(COMMON_DIR)/strip_date_time_from_binary.py
