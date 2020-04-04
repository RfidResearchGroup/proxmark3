#-----------------------------------------------------------------------------
# Copyright (C) 2014 iZsh <izsh at fail0verflow.com>
#
# This code is licensed to you under the terms of the GNU GPL, version 2 or,
# at your option, any later version. See the LICENSE.txt file for the text of
# the license.
#-----------------------------------------------------------------------------
MKDIR = mkdir -p
TEST_OUTDIR = tb_tmp

TB_SOURCES = \
	tb_lp20khz_1MSa_iir_filter.v \
	tb_min_max_tracker.v \
	tb_lf_edge_detect.v

TBS = $(TB_SOURCES:.v=.vvp)

TB_DATA = \
	pcf7931_write1byte_1MSA_data \
	pcf7931_read_1MSA_data

all: $(TBS) tests

%.vvp: %.v
	iverilog -I .. -o $@ $<

clean:
	rm -rf *.vvp $(TEST_OUTDIR)

tests: tb_lp20khz_1MSa_iir_filter tb_min_max_tracker tb_lf_edge_detect

tb_lp20khz_1MSa_iir_filter: tb_lp20khz_1MSa_iir_filter.vvp | test_dir
	@printf "Testing $@\n"
	@for d in $(TB_DATA); do \
		$(call run_test,$@.vvp,$$d,in); \
		$(call check_golden,$$d,filtered); \
	done; \
	rm -f $(TEST_OUTDIR)/data.*

tb_min_max_tracker: tb_min_max_tracker.vvp | test_dir
	@printf "Testing $@\n"
	@for d in $(TB_DATA); do \
		$(call run_test,$@.vvp,$$d,in filtered.gold); \
		$(call check_golden,$$d,min); \
		$(call check_golden,$$d,max); \
	done; \
	rm -f $(TEST_OUTDIR)/data.*

tb_lf_edge_detect: tb_lf_edge_detect.vvp | test_dir
	@printf "Testing $@\n"
	@for d in $(TB_DATA); do \
		$(call run_test,$@.vvp,$$d,in filtered.gold); \
		$(call check_golden,$$d,min); \
		$(call check_golden,$$d,max); \
		$(call check_golden,$$d,state); \
		$(call check_golden,$$d,toggle); \
		$(call check_golden,$$d,high); \
		$(call check_golden,$$d,highz); \
		$(call check_golden,$$d,lowz); \
		$(call check_golden,$$d,low); \
	done; \
	rm -f $(TEST_OUTDIR)/data.*

test_dir:
	@if [ ! -d $(TEST_OUTDIR) ] ; then $(MKDIR) $(TEST_OUTDIR) ; fi

.PHONY: all clean

# $(1) = basename
# $(2) = extension to check
check_golden = \
	printf "        Checking $(1).$(2)... "; \
	mv $(TEST_OUTDIR)/data.$(2) $(TEST_OUTDIR)/$(1).$(2); \
	if cmp -s tb_data/$(1).$(2).gold $(TEST_OUTDIR)/$(1).$(2); then \
		printf "OK\n"; \
	else \
		printf "ERROR\n"; \
	fi

# $(1) = vvp file
# $(2) = data basename
# $(3) = data extensions to copy
run_test = \
	env echo "    With $(2)... "; \
	cp tb_data/$(2).time $(TEST_OUTDIR); \
	for e in $(3); do cp tb_data/$(2).$$e $(TEST_OUTDIR)/data.$$e; done; \
	./$(1)
