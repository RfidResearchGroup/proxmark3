ifeq ($(PLTNAME),)
    -include ../../Makefile.platform
    -include ../../.Makefile.options.cache
    ifneq ($(PLATFORM), $(CACHED_PLATFORM))
        $(error platform definitions have been changed, please "make clean" at the root of the project)
    endif
endif

MYSRCPATHS =
MYINCLUDES = -I../../common_fpga
MYCFLAGS = -std=c99 -D_ISOC99_SOURCE
ifeq ($(PLATFORM),PM3ICOPYX)
  MYDEFS = -DXC3
else
  MYDEFS =
endif
MYSRCS =
MYLIBS =

MYSRCPATHS += ../../common/lz4
MYINCLUDES += -I../../common/lz4
MYSRCS += lz4hc.c lz4.c
MYCFLAGS += -DLZ4_MEMORY_USAGE=20  -Wno-redundant-decls -Wno-old-style-definition -Wno-missing-prototypes -Wno-missing-declarations

BINS = fpga_compress

include ../../Makefile.host

fpga_compress: $(OBJDIR)/fpga_compress.o $(MYOBJS)

tarbin: $(BINS)
	$(info [=] TAR ../proxmark3-$(platform)-bin.tar)
	$(Q)$(TAR) $(TARFLAGS) ../../proxmark3-$(platform)-bin.tar $(BINS:%=fpga_compress/%) $(WINBINS:%=fpga_compress/%)
