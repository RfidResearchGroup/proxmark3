MYSRCPATHS =
MYINCLUDES = -I../../common_fpga
MYCFLAGS = -std=c99 -D_ISOC99_SOURCE
MYDEFS =
MYSRCS =
MYLIBS =

MYSRCPATHS += ../../common/lz4
MYINCLUDES += -I../../common/lz4
MYSRCS += lz4hc.c lz4.c
MYCFLAGS += -DLZ4_MEMORY_USAGE=20  -Wno-redundant-decls -Wno-old-style-definition -Wno-missing-prototypes -Wno-missing-declarations

BINS = fpga_compress

ROOT_DIR:=$(dir $(realpath $(lastword $(MAKEFILE_LIST))))

include ../../Makefile.host

fpga_compress: $(OBJDIR)/fpga_compress.o $(MYOBJS)

tarbin: $(BINS)
	$(info [=] TAR ../proxmark3-$(platform)-bin.tar)
	$(Q)$(TAR) $(TARFLAGS) ../../proxmark3-$(platform)-bin.tar $(BINS:%=fpga_compress/%) $(WINBINS:%=fpga_compress/%)
