MYSRCPATHS =
MYINCLUDES = -I../../common_fpga
MYCFLAGS = -std=c99 -D_ISOC99_SOURCE
MYDEFS =
MYSRCS =
MYLIBS =

ZLIBPATH = ../../common/zlib
MYINCLUDES += -I$(ZLIBPATH)
MYLIBS += $(OBJDIR)/libz.a

BINS = fpga_compress

ROOT_DIR:=$(dir $(realpath $(lastword $(MAKEFILE_LIST))))

include ../../Makefile.host

fpga_compress: $(OBJDIR)/fpga_compress.o $(MYOBJS)
$(OBJDIR)/libz.a:
	$(info [*] MAKE zlib)
	$(Q)$(MAKE) --no-print-directory -C $(ZLIBPATH) OBJDIR=$(ROOT_DIR)$(OBJDIR) BINDIR=$(ROOT_DIR)$(OBJDIR) all
